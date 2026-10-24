#!/usr/bin/env python3
"""Foundation utilities for the Ghost Data Still Exists audit agent.

This module deliberately keeps inference separate from I/O.  Later features will
add identity resolution and evidence reconstruction, while this layer protects
the submission contract from malformed input or output.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = REPOSITORY_ROOT / "dataset"
REQUIRED_REQUEST_COLUMNS = (
    "case_id",
    "email",
    "requested_at",
    "reported_status",
    "reported_at",
    "audit_at",
    "request_text",
)
OUTPUT_COLUMNS = ("case_id", "deletion_status", "steps_json")
VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
STEP_FIELDS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}


class ContractError(ValueError):
    """Raised when participant-facing input or generated output violates the contract."""


@dataclass(frozen=True)
class AuditCase:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime
    request_text: str


@dataclass(frozen=True)
class OutputRow:
    case_id: str
    deletion_status: str
    steps: list[dict[str, Any]]


def parse_timestamp(value: str, *, field_name: str, case_id: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError(f"{case_id}: invalid {field_name} timestamp: {value!r}") from error


def load_requests(path: Path) -> list[AuditCase]:
    """Load and validate a request CSV without reading any non-dataset source."""
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != REQUIRED_REQUEST_COLUMNS:
            raise ContractError(
                f"{path}: expected request columns {REQUIRED_REQUEST_COLUMNS}, got {reader.fieldnames}"
            )
        cases: list[AuditCase] = []
        case_ids: set[str] = set()
        for row_number, row in enumerate(reader, start=2):
            case_id = row["case_id"].strip()
            if not case_id:
                raise ContractError(f"{path}:{row_number}: missing case_id")
            if case_id in case_ids:
                raise ContractError(f"{path}:{row_number}: duplicate case_id {case_id!r}")
            case_ids.add(case_id)
            cases.append(
                AuditCase(
                    case_id=case_id,
                    email=row["email"].strip(),
                    requested_at=parse_timestamp(row["requested_at"], field_name="requested_at", case_id=case_id),
                    reported_status=row["reported_status"].strip(),
                    reported_at=parse_timestamp(row["reported_at"], field_name="reported_at", case_id=case_id),
                    audit_at=parse_timestamp(row["audit_at"], field_name="audit_at", case_id=case_id),
                    request_text=row["request_text"],
                )
            )
    return sorted(cases, key=lambda case: case.case_id)


def validate_steps(status: str, steps: list[dict[str, Any]], *, case_id: str) -> None:
    if status == "NOT_APPLICABLE":
        if steps:
            raise ContractError(f"{case_id}: NOT_APPLICABLE must use an empty steps array")
        return
    if not steps:
        raise ContractError(f"{case_id}: {status} requires at least one step")

    previous_phase = -1
    for expected_number, step in enumerate(steps, start=1):
        if set(step) != STEP_FIELDS:
            raise ContractError(f"{case_id}: step {expected_number} must contain exactly {sorted(STEP_FIELDS)}")
        if step["step_no"] != expected_number:
            raise ContractError(f"{case_id}: step numbers must start at 1 and be consecutive")
        phase = step["phase"]
        if phase not in PHASE_ORDER:
            raise ContractError(f"{case_id}: invalid phase {phase!r}")
        if PHASE_ORDER[phase] < previous_phase:
            raise ContractError(f"{case_id}: phases must be FINDING, REMEDIATION, VERIFICATION")
        previous_phase = PHASE_ORDER[phase]
        if not all(isinstance(step[field], str) and step[field] for field in ("system_id", "resource_id", "operation", "state")):
            raise ContractError(f"{case_id}: step {expected_number} has an empty required string field")


def validate_output_rows(cases: Iterable[AuditCase], rows: Iterable[OutputRow]) -> list[OutputRow]:
    expected_case_ids = [case.case_id for case in cases]
    materialized = list(rows)
    actual_case_ids = [row.case_id for row in materialized]
    if actual_case_ids != expected_case_ids:
        raise ContractError("output case IDs must exactly match input case IDs in ascending order")
    for row in materialized:
        if row.deletion_status not in VALID_STATUSES:
            raise ContractError(f"{row.case_id}: invalid deletion status {row.deletion_status!r}")
        validate_steps(row.deletion_status, row.steps, case_id=row.case_id)
    return materialized


def read_output_rows(path: Path) -> list[OutputRow]:
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != OUTPUT_COLUMNS:
            raise ContractError(f"{path}: output header must be {OUTPUT_COLUMNS}")
        rows: list[OutputRow] = []
        for row_number, row in enumerate(reader, start=2):
            try:
                steps = json.loads(row["steps_json"])
            except json.JSONDecodeError as error:
                raise ContractError(f"{path}:{row_number}: invalid steps_json") from error
            if not isinstance(steps, list):
                raise ContractError(f"{path}:{row_number}: steps_json must be a JSON array")
            rows.append(OutputRow(row["case_id"], row["deletion_status"], steps))
    return rows


def compare_outputs(expected_path: Path, actual_path: Path) -> list[str]:
    """Return semantic row differences; JSON object-key order does not matter."""
    expected = read_output_rows(expected_path)
    actual = read_output_rows(actual_path)
    differences: list[str] = []
    if len(expected) != len(actual):
        differences.append(f"row count differs: expected {len(expected)}, got {len(actual)}")
    for index, (want, got) in enumerate(zip(expected, actual), start=1):
        if want != got:
            differences.append(f"row {index} differs for expected case {want.case_id!r}")
    return differences


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Ghost Data Still Exists inputs and outputs.")
    parser.add_argument("--requests", type=Path, default=DATASET_ROOT / "deletion_requests.csv")
    parser.add_argument("--validate-output", type=Path, metavar="PATH")
    parser.add_argument("--compare-sample", type=Path, metavar="PATH", help="compare PATH with dataset/sample_output.csv")
    args = parser.parse_args()

    try:
        cases = load_requests(args.requests)
        if args.validate_output:
            validate_output_rows(cases, read_output_rows(args.validate_output))
        if args.compare_sample:
            differences = compare_outputs(DATASET_ROOT / "sample_output.csv", args.compare_sample)
            if differences:
                print("Sample comparison failed:", *differences, sep="\n- ", file=sys.stderr)
                return 1
        print(f"Validated {len(cases)} request(s) from {args.requests}")
        if args.validate_output:
            print(f"Validated output contract: {args.validate_output}")
        if args.compare_sample:
            print("Sample output matches.")
        return 0
    except (OSError, ContractError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
