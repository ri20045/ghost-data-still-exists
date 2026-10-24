import unittest
from pathlib import Path

from main import (
    ContractError,
    OutputRow,
    load_evidence_index,
    load_activity_index,
    load_deletion_rules,
    load_identity_resolver,
    load_requests,
    investigate_case,
    validate_output_rows,
    validate_steps,
)


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"


class ContractTests(unittest.TestCase):
    def test_loads_and_sorts_all_evaluation_requests(self):
        cases = load_requests(DATASET / "deletion_requests.csv")
        self.assertEqual(518, len(cases))
        self.assertEqual(sorted(case.case_id for case in cases), [case.case_id for case in cases])

    def test_not_applicable_requires_no_steps(self):
        validate_steps("NOT_APPLICABLE", [], case_id="case_test")
        with self.assertRaises(ContractError):
            validate_steps("NOT_APPLICABLE", [{"step_no": 1}], case_id="case_test")

    def test_rejects_non_consecutive_step_numbers(self):
        with self.assertRaises(ContractError):
            validate_steps(
                "COMPLETE",
                [{"step_no": 2, "phase": "VERIFICATION", "system_id": "a", "resource_id": "b", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_1"}],
                case_id="case_test",
            )

    def test_rejects_output_case_mismatch(self):
        cases = load_requests(DATASET / "sample_deletion_requests.csv")
        with self.assertRaises(ContractError):
            validate_output_rows(cases, [OutputRow("wrong", "NOT_APPLICABLE", [])])

    def test_resolves_current_and_historical_request_emails(self):
        resolver = load_identity_resolver(
            DATASET / "user_identities.csv", DATASET / "user_audit_log.csv"
        )
        for case in load_requests(DATASET / "sample_deletion_requests.csv"):
            identity = resolver.resolve(case.email, case.audit_at)
            self.assertTrue(identity.user_id.startswith("user_"))
            self.assertIn(case.email, identity.all_identifiers)

    def test_rewinds_snapshot_for_changes_after_audit_cutoff(self):
        resolver = load_identity_resolver(
            DATASET / "user_identities.csv", DATASET / "user_audit_log.csv"
        )
        cases = load_requests(DATASET / "sample_deletion_requests.csv")
        case = next(item for item in cases if item.case_id == "case_10")
        identity = resolver.resolve(case.email, case.audit_at)
        self.assertIn(case.email, identity.historical_values["email"])

    def test_indexes_all_manifest_evidence_and_honors_audit_cutoff(self):
        index = load_evidence_index(DATASET / "evidence_files.csv")
        self.assertEqual(94, len(index.files))
        earliest_capture = min(item.captured_at for item in index.files)
        self.assertEqual([], index.search(["user_01"], earliest_capture.replace(year=2020)))

    def test_evidence_search_uses_identity_values_not_manifest_metadata(self):
        resolver = load_identity_resolver(
            DATASET / "user_identities.csv", DATASET / "user_audit_log.csv"
        )
        case = load_requests(DATASET / "sample_deletion_requests.csv")[0]
        identity = resolver.resolve(case.email, case.audit_at)
        matches = load_evidence_index(DATASET / "evidence_files.csv").search(
            identity.all_identifiers, case.audit_at
        )
        self.assertTrue(all(item.captured_at <= case.audit_at for item in matches))

    def test_loads_activity_and_policy_contracts(self):
        self.assertEqual(4011, len(load_activity_index(DATASET / "system_activity.csv").events))
        self.assertEqual(15, len(load_deletion_rules(DATASET / "deletion_rules.csv")))

    def test_investigation_only_reports_resources_found_in_evidence_content(self):
        case = next(item for item in load_requests(DATASET / "sample_deletion_requests.csv") if item.case_id == "case_05")
        identity = load_identity_resolver(DATASET / "user_identities.csv", DATASET / "user_audit_log.csv").resolve(case.email, case.audit_at)
        investigation = investigate_case(
            case, identity, load_evidence_index(DATASET / "evidence_files.csv"),
            load_activity_index(DATASET / "system_activity.csv"),
        )
        self.assertTrue(investigation.resources)
        self.assertTrue(all(item.evidence_ids for item in investigation.resources))
        self.assertEqual(["account_005"], [item.resource_id for item in investigation.resources])


if __name__ == "__main__":
    unittest.main()
