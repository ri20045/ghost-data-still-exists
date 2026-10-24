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
from collections import defaultdict
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
IDENTITY_COLUMNS = ("user_id", "name", "email", "phone", "email_hash", "updated_at")
AUDIT_COLUMNS = ("audit_id", "user_id", "event_time", "field_name", "old_value", "new_value")
IDENTITY_FIELDS = ("name", "email", "phone", "email_hash")


class ContractError(ValueError):
    """Raised when participant-facing input or generated output violates the contract."""


class AmbiguousIdentityError(ContractError):
    """Raised when an identifier maps to more than one stable user ID."""


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


@dataclass(frozen=True)
class IdentityChange:
    audit_id: str
    event_time: datetime
    field_name: str
    old_value: str
    new_value: str


@dataclass(frozen=True)
class ResolvedIdentity:
    """A subject and all identifiers relevant at the requested audit cutoff."""

    user_id: str
    values_at_audit: dict[str, str]
    historical_values: dict[str, tuple[str, ...]]

    @property
    def all_identifiers(self) -> tuple[str, ...]:
        values = set(self.values_at_audit.values())
        for aliases in self.historical_values.values():
            values.update(aliases)
        return tuple(sorted(value for value in values if value))


class IdentityResolver:
    def __init__(self, snapshots: dict[str, dict[str, str]], changes: dict[str, list[IdentityChange]]):
        self._snapshots = snapshots
        self._changes = changes
        self._email_index: dict[str, set[str]] = defaultdict(set)
        for user_id, snapshot in snapshots.items():
            self._add_email(user_id, snapshot["email"])
        for user_id, events in changes.items():
            for event in events:
                if event.field_name == "email":
                    self._add_email(user_id, event.old_value)
                    self._add_email(user_id, event.new_value)

    def _add_email(self, user_id: str, email: str) -> None:
        normalized = email.strip().casefold()
        if normalized:
            self._email_index[normalized].add(user_id)

    def resolve(self, email: str, audit_at: datetime) -> ResolvedIdentity:
        candidates = self._email_index.get(email.strip().casefold(), set())
        if not candidates:
            raise ContractError(f"no identity found for request email {email!r}")
        if len(candidates) != 1:
            raise AmbiguousIdentityError(f"request email {email!r} maps to multiple users")
        user_id = next(iter(candidates))
        values = {field: self._snapshots[user_id][field] for field in IDENTITY_FIELDS}
        historical: dict[str, set[str]] = {field: {value} if value else set() for field, value in values.items()}
        for event in reversed(self._changes.get(user_id, [])):
            if event.event_time > audit_at:
                # Rewind the current snapshot to the state that existed at audit_at.
                values[event.field_name] = event.old_value
                historical[event.field_name].add(event.old_value)
            else:
                # Both sides were valid identifiers before the audit cutoff.
                historical[event.field_name].update((event.old_value, event.new_value))
        return ResolvedIdentity(
            user_id=user_id,
            values_at_audit=values,
            historical_values={field: tuple(sorted(value for value in aliases if value)) for field, aliases in historical.items()},
        )


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


def load_identity_resolver(identities_path: Path, audit_log_path: Path) -> IdentityResolver:
    """Load the participant-facing identity snapshot and its identifier history."""
    snapshots: dict[str, dict[str, str]] = {}
    with identities_path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != IDENTITY_COLUMNS:
            raise ContractError(f"{identities_path}: expected identity columns {IDENTITY_COLUMNS}")
        for row_number, row in enumerate(reader, start=2):
            user_id = row["user_id"].strip()
            if not user_id or user_id in snapshots:
                raise ContractError(f"{identities_path}:{row_number}: missing or duplicate user_id")
            parse_timestamp(row["updated_at"], field_name="updated_at", case_id=user_id)
            snapshots[user_id] = {field: row[field].strip() for field in IDENTITY_FIELDS}

    changes: dict[str, list[IdentityChange]] = defaultdict(list)
    with audit_log_path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != AUDIT_COLUMNS:
            raise ContractError(f"{audit_log_path}: expected audit columns {AUDIT_COLUMNS}")
        audit_ids: set[str] = set()
        for row_number, row in enumerate(reader, start=2):
            audit_id = row["audit_id"].strip()
            user_id = row["user_id"].strip()
            field_name = row["field_name"].strip()
            if not audit_id or audit_id in audit_ids or user_id not in snapshots or field_name not in IDENTITY_FIELDS:
                raise ContractError(f"{audit_log_path}:{row_number}: invalid identity audit row")
            audit_ids.add(audit_id)
            changes[user_id].append(
                IdentityChange(
                    audit_id=audit_id,
                    event_time=parse_timestamp(row["event_time"], field_name="event_time", case_id=audit_id),
                    field_name=field_name,
                    old_value=row["old_value"].strip(),
                    new_value=row["new_value"].strip(),
                )
            )
    for events in changes.values():
        events.sort(key=lambda event: (event.event_time, event.audit_id))
    return IdentityResolver(snapshots, dict(changes))


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
    parser.add_argument("--resolve-case", metavar="CASE_ID", help="print a case's stable user ID and alias counts")
    args = parser.parse_args()

    try:
        cases = load_requests(args.requests)
        if args.resolve_case:
            case = next((item for item in cases if item.case_id == args.resolve_case), None)
            if case is None:
                raise ContractError(f"case not found: {args.resolve_case}")
            resolver = load_identity_resolver(DATASET_ROOT / "user_identities.csv", DATASET_ROOT / "user_audit_log.csv")
            identity = resolver.resolve(case.email, case.audit_at)
            alias_count = sum(len(values) for values in identity.historical_values.values())
            print(f"Resolved {case.case_id} to {identity.user_id} with {alias_count} identifier values at or before audit_at.")
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
