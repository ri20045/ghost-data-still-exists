import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

from main import (
    ActivityEvent,
    ActivityIndex,
    AuditCase,
    ContractError,
    DeletionRule,
    EvidenceFile,
    EvidenceIndex,
    OutputRow,
    ResolvedIdentity,
    ResourceObservation,
    load_evidence_index,
    load_activity_index,
    load_deletion_rules,
    load_identity_resolver,
    load_requests,
    investigate_case,
    orchestrate_case,
    plan_investigation,
    reconstruct_resource_states,
    request_authorizes_deletion,
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

    def test_recognizes_clear_multilingual_deletion_requests(self):
        requests = (
            "Please delete my account.",
            "Je demande la suppression définitive du compte.",
            "Solicito la eliminación permanente de mi cuenta.",
            "Solicito a exclusão permanente da conta.",
            "이 계정의 영구 삭제를 요청합니다.",
            "このアカウントの完全な削除を依頼します。",
        )
        for request_text in requests:
            with self.subTest(request_text=request_text):
                self.assertTrue(request_authorizes_deletion(request_text))

    def test_recognizes_ambiguous_deletion_audits_and_scoped_deletion(self):
        requests = (
            "I deleted my account. Could you verify that my profile is gone?",
            "Please inspect whether my account and analytics data have already been removed.",
            "Please remove my profile, but keep invoices required by policy.",
        )
        for request_text in requests:
            with self.subTest(request_text=request_text):
                self.assertTrue(request_authorizes_deletion(request_text))

    def test_rejects_non_deletion_requests_and_explicit_denials(self):
        requests = (
            "The mobile number on my profile is out of date. Please replace it with the new one and leave the account active.",
            "Please stop the promotional emails. I still need the account and my order history, so I am not asking for deletion.",
            "I'd like to download my account information in a portable format. Please keep the account as it is.",
            "I can't access my profile and need help resetting the login. Do not close the account.",
            "My surname is misspelled on the account. Can you correct it without removing any of my records?",
            "Please remove me from marketing lists only. I still want receipts and service messages for this account.",
            "Can you tell me what personal information you hold about me? This is an information request, not a request to erase it.",
            "Could you send me a copy of the information held on my account? I still use it, so please don't delete or change anything.",
            "I do not want you to delete my account; please keep it active.",
            "Je ne demande pas la suppression de mon compte.",
            "No solicito la eliminación de mi cuenta.",
            "削除を依頼していません。",
        )
        for request_text in requests:
            with self.subTest(request_text=request_text):
                self.assertFalse(request_authorizes_deletion(request_text))

    def test_public_sample_requests_remain_authorized(self):
        sample_cases = load_requests(DATASET / "sample_deletion_requests.csv")
        for case in sample_cases:
            with self.subTest(case_id=case.case_id):
                self.assertTrue(request_authorizes_deletion(case.request_text))

    def test_orchestrates_non_deletion_without_resolving_or_investigating(self):
        case = AuditCase(
            case_id="case_fixture",
            email="person@example.test",
            requested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            reported_status="COMPLETE",
            reported_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            audit_at=datetime(2026, 1, 3, tzinfo=timezone.utc),
            request_text="Please send me an export of my account information.",
        )
        resolver = Mock()
        evidence_index = Mock()
        activity_index = Mock()

        result = orchestrate_case(case, resolver, evidence_index, activity_index, [])

        self.assertEqual(OutputRow("case_fixture", "NOT_APPLICABLE", []), result)
        resolver.resolve.assert_not_called()
        evidence_index.search.assert_not_called()
        activity_index.for_resource.assert_not_called()

    def test_orchestrates_evidence_backed_incomplete_case_in_contract_order(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        case = AuditCase(
            case_id="case_fixture",
            email="person@example.test",
            requested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            reported_status="COMPLETE",
            reported_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            audit_at=audit_at,
            request_text="Please delete my account.",
        )
        resolver = Mock()
        resolver.resolve.return_value = ResolvedIdentity(
            user_id="user_fixture",
            values_at_audit={
                "name": "Example Person",
                "email": "person@example.test",
                "phone": "+10000000000",
                "email_hash": "fixture-hash",
            },
            historical_values={},
        )
        evidence_index = EvidenceIndex(
            [
                EvidenceFile(
                    file_id="evidence_fixture",
                    path=Path("fixture.sql"),
                    origin="test_fixture",
                    captured_at=audit_at,
                    text="INSERT INTO customer_profiles VALUES ('account_001', 'person@example.test', 'ACTIVE');",
                )
            ]
        )
        activity_index = ActivityIndex([])
        rules = [DeletionRule("rule_fixture", "USER_PROFILE", "Always", "DELETE")]

        result = orchestrate_case(case, resolver, evidence_index, activity_index, rules)

        self.assertEqual("INCOMPLETE", result.deletion_status)
        self.assertEqual(
            ["FINDING", "REMEDIATION", "VERIFICATION"],
            [step["phase"] for step in result.steps],
        )
        self.assertEqual(
            ["REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"],
            [step["operation"] for step in result.steps],
        )
        self.assertEqual([1, 2, 3], [step["step_no"] for step in result.steps])
        self.assertEqual("evidence_fixture", result.steps[0]["evidence_id"])
        self.assertEqual("PRESENT", result.steps[0]["state"])
        self.assertEqual(["", ""], [step["evidence_id"] for step in result.steps[1:]])
        validate_output_rows([case], [result])
        resolver.resolve.assert_called_once_with(case.email, case.audit_at)

    def test_reconstructs_explicit_absence_without_claiming_case_complete(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        case = AuditCase(
            case_id="case_fixture",
            email="person@example.test",
            requested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            reported_status="PARTIALLY_COMPLETE",
            reported_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            audit_at=audit_at,
            request_text="Please delete my account.",
        )
        resolver = Mock()
        resolver.resolve.return_value = ResolvedIdentity(
            user_id="user_fixture",
            values_at_audit={"name": "", "email": case.email, "phone": "", "email_hash": ""},
            historical_values={},
        )
        evidence_index = EvidenceIndex(
            [
                EvidenceFile(
                    file_id="evidence_absent",
                    path=Path("lookup.log"),
                    origin="test_fixture",
                    captured_at=audit_at,
                    text=(
                        "event=profile_lookup_completed resource_id=account_001 "
                        "rows=0 http_status=404 lookup_key=person@example.test"
                    ),
                )
            ]
        )
        activity_index = ActivityIndex([])
        investigation = investigate_case(
            case,
            resolver.resolve.return_value,
            evidence_index,
            activity_index,
        )

        self.assertEqual("ABSENT", investigation.resources[0].observed_state)
        self.assertEqual(("evidence_absent",), investigation.resources[0].state_evidence_ids)
        with self.assertRaisesRegex(ContractError, "completion evaluation is not implemented"):
            orchestrate_case(case, resolver, evidence_index, activity_index, [])

    def test_present_evidence_wins_over_an_absence_claim_from_another_snapshot(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        case = AuditCase(
            case_id="case_fixture",
            email="person@example.test",
            requested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            reported_status="COMPLETE",
            reported_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            audit_at=audit_at,
            request_text="Please delete my account.",
        )
        resolver = Mock()
        resolver.resolve.return_value = ResolvedIdentity(
            user_id="user_fixture",
            values_at_audit={"name": "", "email": case.email, "phone": "", "email_hash": ""},
            historical_values={},
        )
        evidence_index = EvidenceIndex(
            [
                EvidenceFile(
                    file_id="evidence_absent",
                    path=Path("lookup.log"),
                    origin="test_fixture",
                    captured_at=audit_at,
                    text=(
                        "event=profile_lookup_completed resource_id=account_001 "
                        "rows=0 http_status=404 lookup_key=person@example.test"
                    ),
                ),
                EvidenceFile(
                    file_id="evidence_present",
                    path=Path("snapshot.sql"),
                    origin="test_fixture",
                    captured_at=audit_at,
                    text="INSERT INTO customer_profiles VALUES ('account_001', 'person@example.test', 'ACTIVE');",
                ),
            ]
        )
        investigation = investigate_case(
            case, resolver.resolve.return_value, evidence_index, ActivityIndex([])
        )

        self.assertEqual("PRESENT", investigation.resources[0].observed_state)
        self.assertEqual(("evidence_present",), investigation.resources[0].state_evidence_ids)

    def test_reconstructs_json_record_states_and_active_restore_risks(self):
        json_evidence = EvidenceFile(
            file_id="evidence_json",
            path=Path("snapshot.json"),
            origin="test_fixture",
            captured_at=datetime(2026, 1, 3, tzinfo=timezone.utc),
            text='{"resource_id":"account_001","record_state":"ABSENT"}',
        )
        json_resource = ResourceObservation(
            "account_001", ("evidence_json",), (), None, "UNKNOWN", ()
        )
        json_states = reconstruct_resource_states(
            [json_resource], EvidenceIndex([json_evidence])
        )
        self.assertEqual("ABSENT", json_states[0].observed_state)

        case = AuditCase(
            case_id="case_fixture",
            email="person@example.test",
            requested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            reported_status="COMPLETE",
            reported_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            audit_at=datetime(2026, 1, 3, tzinfo=timezone.utc),
            request_text="Please delete my account.",
        )
        resolver = Mock()
        resolver.resolve.return_value = ResolvedIdentity(
            user_id="user_fixture",
            values_at_audit={"name": "", "email": case.email, "phone": "", "email_hash": ""},
            historical_values={},
        )
        evidence_index = EvidenceIndex(
            [
                EvidenceFile(
                    file_id="evidence_flow",
                    path=Path("flow.log"),
                    origin="test_fixture",
                    captured_at=case.audit_at,
                    text=(
                        "resource_id=data_flow_001 result=ACTIVE "
                        "subject_reference=person@example.test"
                    ),
                ),
                EvidenceFile(
                    file_id="evidence_backup",
                    path=Path("backup.log"),
                    origin="test_fixture",
                    captured_at=case.audit_at,
                    text=(
                        "resource_id=backup_001 restore_status=available "
                        "customer_email=person@example.test"
                    ),
                ),
            ]
        )

        result = orchestrate_case(case, resolver, evidence_index, ActivityIndex([]), [])

        self.assertEqual(
            ["REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"],
            [step["operation"] for step in result.steps if step["phase"] == "FINDING"],
        )
        self.assertTrue(all(step["evidence_id"] for step in result.steps[:2]))

    def test_orchestration_rejects_deletion_without_evidence_for_a_finding(self):
        case = AuditCase(
            case_id="case_fixture",
            email="person@example.test",
            requested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            reported_status="NOT_STARTED",
            reported_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            audit_at=datetime(2026, 1, 3, tzinfo=timezone.utc),
            request_text="Please delete my account.",
        )
        resolver = Mock()
        resolver.resolve.return_value = ResolvedIdentity(
            user_id="user_fixture",
            values_at_audit={
                "name": "Example Person",
                "email": "person@example.test",
                "phone": "+10000000000",
                "email_hash": "fixture-hash",
            },
            historical_values={},
        )
        evidence_index = EvidenceIndex(
            [
                EvidenceFile(
                    file_id="evidence_claim_only",
                    path=Path("audit.log"),
                    origin="test_fixture",
                    captured_at=case.audit_at,
                    text=(
                        "event=deletion_operation_completed result=SUCCESS "
                        "resource_id=account_001 email=person@example.test"
                    ),
                )
            ]
        )
        activity_index = ActivityIndex(
            [
                ActivityEvent(
                    activity_id="activity_fixture",
                    event_time=case.audit_at,
                    event_type="DELETE_RECORD",
                    source_system="deletion_worker",
                    target_system="account_service",
                    resource_id="account_001",
                    reported_result="SUCCESS",
                    details="Policy action completed.",
                )
            ]
        )

        with self.assertRaisesRegex(ContractError, "no evidence-backed resource state"):
            orchestrate_case(case, resolver, evidence_index, activity_index, [])

    def test_plans_ordered_policy_actions_for_evidence_proven_record(self):
        case = next(item for item in load_requests(DATASET / "sample_deletion_requests.csv") if item.case_id == "case_05")
        identity = load_identity_resolver(DATASET / "user_identities.csv", DATASET / "user_audit_log.csv").resolve(case.email, case.audit_at)
        investigation = investigate_case(case, identity, load_evidence_index(DATASET / "evidence_files.csv"), load_activity_index(DATASET / "system_activity.csv"))
        plan = plan_investigation(case, investigation, load_deletion_rules(DATASET / "deletion_rules.csv"))
        self.assertEqual("INCOMPLETE", plan.deletion_status)
        self.assertEqual(["REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"], [step["operation"] for step in plan.steps])
        self.assertEqual([1, 2, 3], [step["step_no"] for step in plan.steps])


if __name__ == "__main__":
    unittest.main()
