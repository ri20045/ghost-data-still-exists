#!/usr/bin/env python3
"""Compare a candidate output with participant-provided expected rows."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

CODE_ROOT = Path(__file__).resolve().parents[1] / "code"
sys.path.insert(0, str(CODE_ROOT))

from main import OutputRow, read_output_rows  # noqa: E402


def evaluate_rows(expected: list[OutputRow], actual: list[OutputRow]) -> dict[str, Any]:
    """Return status, step, field, and sequence metrics aligned by case and step."""
    expected_by_id = {row.case_id: row for row in expected}
    actual_by_id: dict[str, list[OutputRow]] = defaultdict(list)
    for row in actual:
        actual_by_id[row.case_id].append(row)

    correct_statuses = 0
    exact_sequences = 0
    expected_steps = 0
    correct_steps = 0
    expected_fields = 0
    correct_fields = 0

    for expected_row in expected:
        candidates = actual_by_id.get(expected_row.case_id, [])
        actual_row = candidates[0] if len(candidates) == 1 else None
        if actual_row is not None and actual_row.deletion_status == expected_row.deletion_status:
            correct_statuses += 1
        if actual_row is not None and actual_row.steps == expected_row.steps:
            exact_sequences += 1

        actual_steps = actual_row.steps if actual_row is not None else []
        step_count = max(len(expected_row.steps), len(actual_steps))
        expected_steps += step_count
        for index in range(step_count):
            expected_step = expected_row.steps[index] if index < len(expected_row.steps) else {}
            actual_step = actual_steps[index] if index < len(actual_steps) else {}
            fields = set(expected_step) | set(actual_step)
            expected_fields += len(fields)
            if expected_step == actual_step and expected_step:
                correct_steps += 1
            correct_fields += sum(
                expected_step.get(field) == actual_step.get(field)
                and field in expected_step
                and field in actual_step
                for field in fields
            )

    def metric(correct: int, total: int) -> dict[str, int | float | None]:
        return {
            "correct": correct,
            "total": total,
            "accuracy": correct / total if total else None,
        }

    expected_ids = set(expected_by_id)
    return {
        "case_count": len(expected),
        "case_status_accuracy": metric(correct_statuses, len(expected)),
        "step_accuracy": metric(correct_steps, expected_steps),
        "field_accuracy": metric(correct_fields, expected_fields),
        "sequence_accuracy": metric(exact_sequences, len(expected)),
        "missing_case_ids": sorted(expected_ids - set(actual_by_id)),
        "duplicate_case_ids": sorted(
            case_id for case_id, rows in actual_by_id.items() if len(rows) != 1
        ),
        "unexpected_case_ids": sorted(set(actual_by_id) - expected_ids),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "prediction",
        type=Path,
        help="candidate CSV to compare with dataset/sample_output.csv",
    )
    parser.add_argument(
        "--expected",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "dataset" / "sample_output.csv",
        help="participant-provided expected CSV (defaults to the public sample answers)",
    )
    args = parser.parse_args()

    try:
        result = evaluate_rows(
            read_output_rows(args.expected),
            read_output_rows(args.prediction),
        )
    except (OSError, ValueError) as error:
        print(f"Evaluation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
