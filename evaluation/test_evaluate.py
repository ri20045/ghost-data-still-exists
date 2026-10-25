import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "code"))

from main import OutputRow  # noqa: E402
from evaluate import evaluate_rows  # noqa: E402


def make_step(resource_id: str) -> dict[str, object]:
    return {
        "step_no": 1,
        "phase": "VERIFICATION",
        "system_id": "account_service",
        "resource_id": resource_id,
        "operation": "VERIFY_RECORD_ABSENT",
        "state": "ABSENT",
        "evidence_id": "evidence_01",
    }


class EvaluationTests(unittest.TestCase):
    def test_exact_rows_score_full_accuracy(self):
        expected = [
            OutputRow("case_1", "COMPLETE", [make_step("account_001")]),
            OutputRow("case_2", "NOT_APPLICABLE", []),
        ]

        metrics = evaluate_rows(expected, expected)

        self.assertEqual(1.0, metrics["case_status_accuracy"]["accuracy"])
        self.assertEqual(1.0, metrics["step_accuracy"]["accuracy"])
        self.assertEqual(1.0, metrics["field_accuracy"]["accuracy"])
        self.assertEqual(1.0, metrics["sequence_accuracy"]["accuracy"])

    def test_wrong_status_and_missing_step_are_counted_as_errors(self):
        expected = [OutputRow("case_1", "COMPLETE", [make_step("account_001")])]
        actual = [OutputRow("case_1", "INCOMPLETE", [])]

        metrics = evaluate_rows(expected, actual)

        self.assertEqual(0.0, metrics["case_status_accuracy"]["accuracy"])
        self.assertEqual(0.0, metrics["step_accuracy"]["accuracy"])
        self.assertEqual(0.0, metrics["field_accuracy"]["accuracy"])
        self.assertEqual(0.0, metrics["sequence_accuracy"]["accuracy"])

    def test_missing_duplicate_and_unexpected_cases_are_reported(self):
        expected = [
            OutputRow("case_1", "NOT_APPLICABLE", []),
            OutputRow("case_2", "NOT_APPLICABLE", []),
        ]
        actual = [
            OutputRow("case_1", "NOT_APPLICABLE", []),
            OutputRow("case_1", "NOT_APPLICABLE", []),
            OutputRow("case_3", "NOT_APPLICABLE", []),
        ]

        metrics = evaluate_rows(expected, actual)

        self.assertEqual(["case_2"], metrics["missing_case_ids"])
        self.assertEqual(["case_1"], metrics["duplicate_case_ids"])
        self.assertEqual(["case_3"], metrics["unexpected_case_ids"])
        self.assertEqual(0.0, metrics["case_status_accuracy"]["accuracy"])


if __name__ == "__main__":
    unittest.main()
