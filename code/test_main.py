import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from main import (
    ActivityEvent,
    ActivityIndex,
    AuditCase,
    CaseInvestigation,
    CaseCoverageDiagnostic,
    ContractError,
    DeletionRule,
    diagnose_case_coverage,
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
    def test_coverage_diagnostic_separates_blocked_cases_from_errors(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        cases = [
            AuditCase(
                case_id=f"case_{index}",
                email=f"person{index}@example.test",
                requested_at=audit_at,
                reported_status="COMPLETE",
                reported_at=audit_at,
                audit_at=audit_at,
                request_text="Please delete my account.",
            )
            for index in range(1, 5)
        ]
        expected = (
            OutputRow("case_1", "COMPLETE", [{"step_no": 1}]),
            ContractError("case_2: retention cutoff is unknown for audit_record_002"),
            ContractError("case_3: no deletion rule for category USER_PROFILE"),
            OutputRow("case_4", "NOT_APPLICABLE", []),
        )
        evidence_index = EvidenceIndex(
            [
                EvidenceFile(
                    "evidence_retention_row",
                    Path("audit.sql"),
                    "test_fixture",
                    audit_at,
                    "resource_id=audit_record_002",
                )
            ]
        )
        with patch("main.orchestrate_case", side_effect=expected):
            diagnostics = diagnose_case_coverage(
                cases, Mock(), evidence_index, ActivityIndex([]), []
            )

        self.assertEqual(
            (
                CaseCoverageDiagnostic("case_1", "COMPLETE"),
                CaseCoverageDiagnostic(
                    "case_2",
                    "BLOCKED",
                    "retention cutoff is unknown for audit_record_002",
                    "UNKNOWN_RETENTION_CUTOFF",
                    "audit_record_002",
                    ("evidence_retention_row",),
                    "RESOURCE_EVIDENCE_WITHOUT_AUDIT_METADATA",
                    "Evidence references the resource but does not establish an audit-record cutoff.",
                ),
                CaseCoverageDiagnostic(
                    "case_3",
                    "ERROR",
                    "case_3: no deletion rule for category USER_PROFILE",
                    "PROCESSING_ERROR",
                ),
                CaseCoverageDiagnostic("case_4", "NOT_APPLICABLE"),
            ),
            diagnostics,
        )

    def test_coverage_diagnostic_distinguishes_partial_support_evidence(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        cases = [
            AuditCase(
                case_id=f"case_{index}",
                email=f"person{index}@example.test",
                requested_at=audit_at,
                reported_status="COMPLETE",
                reported_at=audit_at,
                audit_at=audit_at,
                request_text="Please delete my account.",
            )
            for index in range(1, 3)
        ]
        evidence_index = EvidenceIndex(
            [
                EvidenceFile(
                    "evidence_support_readback",
                    Path("support.log"),
                    "test_fixture",
                    audit_at,
                    "2026-01-03T00:00:00Z service=support_platform "
                    "event=support_ticket_read_completed resource_id=support_001 "
                    "requester_name=null requester_email=null requester_phone=null",
                )
            ]
        )
        with patch(
            "main.orchestrate_case",
            side_effect=[
                ContractError("case_1: resource support_001 state is unknown"),
                ContractError("case_2: resource export_002 state is unknown"),
            ],
        ):
            diagnostics = diagnose_case_coverage(
                cases, Mock(), evidence_index, ActivityIndex([]), []
            )

        self.assertEqual(["BLOCKED", "BLOCKED"], [item.outcome for item in diagnostics])
        self.assertEqual(
            ["PARTIAL_SUPPORT_READBACK", "NO_RESOURCE_EVIDENCE"],
            [item.evidence_assessment for item in diagnostics],
        )
        self.assertIn("omits message content", diagnostics[0].evidence_note)
        self.assertIn("No participant-facing evidence", diagnostics[1].evidence_note)

    def test_coverage_diagnostic_distinguishes_missing_retention_cutoff_evidence(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        cases = [
            AuditCase(
                case_id=f"case_{index}",
                email=f"person{index}@example.test",
                requested_at=audit_at,
                reported_status="COMPLETE",
                reported_at=audit_at,
                audit_at=audit_at,
                request_text="Please delete my account.",
            )
            for index in range(1, 4)
        ]
        evidence_index = EvidenceIndex(
            [
                EvidenceFile(
                    "evidence_audit_record",
                    Path("audit.json"),
                    "test_fixture",
                    audit_at,
                    '{"resource_id":"audit_record_001","event_code":"SUBJECT_REQUEST_AUDITED"}',
                ),
                EvidenceFile(
                    "evidence_resource_only",
                    Path("audit.json"),
                    "test_fixture",
                    audit_at,
                    '{"resource_id":"audit_record_002","source":"security_service"}',
                ),
            ]
        )
        with patch(
            "main.orchestrate_case",
            side_effect=[
                ContractError("case_1: retention cutoff is unknown for audit_record_001"),
                ContractError("case_2: retention cutoff is unknown for audit_record_002"),
                ContractError("case_3: retention cutoff is unknown for audit_record_003"),
            ],
        ):
            diagnostics = diagnose_case_coverage(
                cases, Mock(), evidence_index, ActivityIndex([]), []
            )

        self.assertEqual(
            [
                "AUDIT_RECORD_WITHOUT_CUTOFF",
                "RESOURCE_EVIDENCE_WITHOUT_AUDIT_METADATA",
                "NO_AUDIT_RECORD_EVIDENCE",
            ],
            [item.evidence_assessment for item in diagnostics],
        )
        self.assertTrue(
            all(item.outcome == "BLOCKED" for item in diagnostics)
        )

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

    def test_stable_user_reference_matching_uses_exact_ids(self):
        captured_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        index = EvidenceIndex(
            [
                EvidenceFile(
                    "evidence_neighbor",
                    Path("lookup.log"),
                    "test_fixture",
                    captured_at,
                    "resource_id=audit_record_001 subject_reference=user_437",
                )
            ]
        )

        self.assertEqual([], index.search(["user_43"], captured_at))
        self.assertEqual(["evidence_neighbor"], [
            item.file_id for item in index.search(["user_437"], captured_at)
        ])

    def test_activity_identity_link_discovers_resource_but_evidence_proves_state(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        case = AuditCase(
            "case_activity_link",
            "person@example.test",
            audit_at,
            "COMPLETE",
            audit_at,
            audit_at,
            "Please delete my account.",
        )
        identity = ResolvedIdentity(
            "user_001",
            {"name": "Example Person", "email": case.email, "phone": "", "email_hash": ""},
            {},
        )
        activity = ActivityIndex(
            [
                ActivityEvent(
                    "activity_link",
                    audit_at,
                    "SEARCH_LOOKUP",
                    "search_service",
                    "search_service",
                    "search_001",
                    "SUCCESS",
                    "subject_email=person@example.test",
                )
            ]
        )
        evidence = EvidenceIndex(
            [
                EvidenceFile(
                    "evidence_resource",
                    Path("search.json"),
                    "test_fixture",
                    audit_at,
                    '{"resource_id":"search_001","result":"FOUND"}',
                )
            ]
        )
        investigation = investigate_case(case, identity, evidence, activity)

        self.assertEqual(["search_001"], [item.resource_id for item in investigation.resources])
        self.assertEqual("PRESENT", investigation.resources[0].observed_state)
        self.assertEqual(("evidence_resource",), investigation.resources[0].state_evidence_ids)
        self.assertIn("activity_link", investigation.resources[0].activity_ids)
        result = plan_investigation(
            case,
            investigation,
            [DeletionRule("rule_search", "SEARCH_INDEX_ENTRY", "Always", "DELETE")],
        )
        self.assertEqual("INCOMPLETE", result.deletion_status)
        self.assertEqual("evidence_resource", result.steps[0]["evidence_id"])

    def test_activity_link_without_pre_cutoff_evidence_does_not_prove_state(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        case = AuditCase(
            "case_activity_only",
            "person@example.test",
            audit_at,
            "COMPLETE",
            audit_at,
            audit_at,
            "Please delete my account.",
        )
        identity = ResolvedIdentity(
            "user_001",
            {"name": "", "email": case.email, "phone": "", "email_hash": ""},
            {},
        )
        activity = ActivityIndex(
            [
                ActivityEvent(
                    "activity_only",
                    audit_at,
                    "SEARCH_LOOKUP",
                    "search_service",
                    "search_service",
                    "search_001",
                    "NOT_FOUND",
                    "subject_email=person@example.test",
                )
            ]
        )
        future_evidence = EvidenceIndex(
            [
                EvidenceFile(
                    "evidence_future",
                    Path("search.json"),
                    "test_fixture",
                    datetime(2026, 1, 4, tzinfo=timezone.utc),
                    '{"resource_id":"search_001","result":"ABSENT"}',
                )
            ]
        )

        investigation = investigate_case(case, identity, future_evidence, activity)

        self.assertEqual((), investigation.resources[0].evidence_ids)
        self.assertEqual((), investigation.resources[0].state_evidence_ids)
        self.assertEqual("UNKNOWN", investigation.resources[0].observed_state)
        with self.assertRaisesRegex(ContractError, "state is unknown"):
            plan_investigation(
                case,
                investigation,
                [DeletionRule("rule_search", "SEARCH_INDEX_ENTRY", "Always", "DELETE")],
            )

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

    def test_reconstructs_explicit_absence_and_emits_evidence_backed_completion(self):
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
        result = orchestrate_case(
            case,
            resolver,
            evidence_index,
            activity_index,
            [DeletionRule("rule_fixture", "USER_PROFILE", "Always", "DELETE")],
        )
        self.assertEqual("COMPLETE", result.deletion_status)
        self.assertEqual("VERIFY_RECORD_ABSENT", result.steps[0]["operation"])
        self.assertEqual("evidence_absent", result.steps[0]["evidence_id"])
        validate_output_rows([case], [result])

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

    def test_reconstructs_nested_json_records_and_export_jobs(self):
        captured_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        evidence = EvidenceFile(
            "evidence_structured",
            Path("snapshot.json"),
            "test_fixture",
            captured_at,
            (
                '{"records":['
                '{"resource_id":"export_001","owner_email":"person@example.test",'
                '"download_available":true},'
                '{"resource_id":"account_001","status_code":404,"profile":null},'
                '{"resource_id":"data_flow_001","enabled":true},'
                '{"resource_id":"analytics_001","profile":{"email":"person@example.test",'
                '"phone":null}},'
                '{"resource_id":"audit_record_001","subject_reference":"user_001",'
                '"event_code":"ACCOUNT_DELETION_RECORDED",'
                '"retention_until":"2030-12-31T23:59:59Z"}]}'
            ),
        )
        resource_ids = [
            "export_001",
            "account_001",
            "data_flow_001",
            "analytics_001",
            "audit_record_001",
        ]
        resources = reconstruct_resource_states(
            [
                ResourceObservation(resource_id, ("evidence_structured",), (), None, "UNKNOWN", ())
                for resource_id in resource_ids
            ],
            EvidenceIndex([evidence]),
        )

        self.assertEqual(
            ["PRESENT", "ABSENT", "ACTIVE", "PRESENT", "PRESENT"],
            [resource.observed_state for resource in resources],
        )
        self.assertEqual(
            datetime(2030, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            resources[-1].retention_until,
        )

    def test_reconstructs_pipe_delimited_resource_statuses(self):
        evidence = EvidenceFile(
            "evidence_inventory",
            Path("inventory.txt"),
            "test_fixture",
            datetime(2026, 1, 3, tzinfo=timezone.utc),
            (
                "- 2026-01-03T00:00:00Z | account_service | account_001 "
                "| USER_PROFILE | NOT_FOUND | lookup\n"
                "- 2026-01-03T00:00:00Z | search_service | search_001 "
                "| SEARCH_INDEX_ENTRY | FOUND | match\n"
                "- 2026-01-03T00:00:00Z | integration_service | data_flow_001 "
                "| DATA_FLOW | ACTIVE | enabled"
            ),
        )
        resources = reconstruct_resource_states(
            [
                ResourceObservation("account_001", ("evidence_inventory",), (), None, "UNKNOWN", ()),
                ResourceObservation("search_001", ("evidence_inventory",), (), None, "UNKNOWN", ()),
                ResourceObservation("data_flow_001", ("evidence_inventory",), (), None, "UNKNOWN", ()),
            ],
            EvidenceIndex([evidence]),
        )

        self.assertEqual(
            ["ABSENT", "PRESENT", "ACTIVE"],
            [resource.observed_state for resource in resources],
        )

    def test_reconstructs_json_records_embedded_in_timestamped_logs(self):
        evidence = EvidenceFile(
            "evidence_json_log",
            Path("structured.log"),
            "test_fixture",
            datetime(2026, 1, 3, tzinfo=timezone.utc),
            (
                '2026-01-03T00:00:00Z {"resource_id":"search_001","result":"hit"}\n'
                '2026-01-03T00:00:01Z {"resource_id":"analytics_001",'
                '"matched_value":"person@example.test","direct_identifiers":"1"}\n'
                '2026-01-03T00:00:02Z {"resource_id":"support_001",'
                '"message_text":"[REDACTED]"}\n'
                '2026-01-03T00:00:03Z {"resource_id":"data_flow_001",'
                '"enabled":"true","scheduler_registered":"true"}\n'
                '2026-01-03T00:00:04Z {"resource_id":"backup_001",'
                '"restore_allowed":"false"}\n'
                '2026-01-03T00:00:05Z {"resource_id":"export_001",'
                '"available":"true"}\n'
                '2026-01-03T00:00:06Z {"resource_id":"account_002",'
                '"event":"profile_lookup_completed","rows":"0","http_status":"404"}\n'
                '2026-01-03T00:00:07Z {"resource_id":"account_003",'
                '"event":"profile_lookup_completed","rows":"1","http_status":"200"}\n'
                '2026-01-03T00:00:08Z {"resource_id":"search_002",'
                '"event":"index_query_completed","total_hits":0}\n'
                '2026-01-03T00:00:09Z {"resource_id":"search_003",'
                '"event":"index_query_completed","total_hits":2}'
            ),
        )
        resource_ids = (
            "search_001",
            "analytics_001",
            "support_001",
            "data_flow_001",
            "backup_001",
            "export_001",
            "account_002",
            "account_003",
            "search_002",
            "search_003",
        )
        resources = reconstruct_resource_states(
            [
                ResourceObservation(resource_id, ("evidence_json_log",), (), None, "UNKNOWN", ())
                for resource_id in resource_ids
            ],
            EvidenceIndex([evidence]),
        )

        self.assertEqual(
            [
                "PRESENT",
                "PRESENT",
                "REDACTED",
                "ACTIVE",
                "BLOCKED",
                "PRESENT",
                "ABSENT",
                "PRESENT",
                "ABSENT",
                "PRESENT",
            ],
            [resource.observed_state for resource in resources],
        )

    def test_reconstructs_search_state_from_text_hit_counts(self):
        evidence = EvidenceFile(
            "evidence_search_counts",
            Path("search.log"),
            "test_fixture",
            datetime(2026, 1, 3, tzinfo=timezone.utc),
            (
                '2026-01-03T00:00:00Z resource_id=search_010 total_hits="0"\n'
                '2026-01-03T00:00:01Z resource_id=search_011 total_hits="3"'
            ),
        )
        resources = reconstruct_resource_states(
            [
                ResourceObservation(resource_id, ("evidence_search_counts",), (), None, "UNKNOWN", ())
                for resource_id in ("search_010", "search_011")
            ],
            EvidenceIndex([evidence]),
        )

        self.assertEqual(
            ["ABSENT", "PRESENT"],
            [resource.observed_state for resource in resources],
        )

    def test_reconstructs_escaped_quoted_key_value_log_fields(self):
        evidence = EvidenceFile(
            "evidence_escaped_log",
            Path("runtime.log"),
            "test_fixture",
            datetime(2026, 1, 3, tzinfo=timezone.utc),
            (
                '2026-01-03T00:00:00Z message="resource_id=\\"account_001\\" '
                'rows=\\"0\\" http_status=\\"404\\" correlation_key=\\"person@example.test\\""\n'
                '2026-01-03T00:00:01Z message="resource_id=\\"data_flow_001\\" '
                'enabled=\\"true\\" scheduler_registered=\\"true\\""\n'
                '2026-01-03T00:00:02Z message="resource_id=\\"support_001\\" '
                'message_text=\\"[REDACTED]\\""\n'
                '2026-01-03T00:00:03Z message="resource_id=\\"search_001\\" '
                'event=\\"index_query_completed\\" result=\\"hit\\""\n'
                '2026-01-03T00:00:04Z message="resource_id=\\"export_001\\" '
                'event=\\"export_download_check_completed\\" available=\\"true\\""'
            ),
        )
        resources = reconstruct_resource_states(
            [
                ResourceObservation(resource_id, ("evidence_escaped_log",), (), None, "UNKNOWN", ())
                for resource_id in (
                    "account_001",
                    "data_flow_001",
                    "support_001",
                    "search_001",
                    "export_001",
                )
            ],
            EvidenceIndex([evidence]),
        )

        self.assertEqual(
            ["ABSENT", "ACTIVE", "REDACTED", "PRESENT", "PRESENT"],
            [resource.observed_state for resource in resources],
        )

    def test_reconstructs_sql_backup_restore_flags(self):
        captured_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        evidence = EvidenceFile(
            "evidence_sql_flags",
            Path("inventory.sql"),
            "test_fixture",
            captured_at,
            (
                "INSERT INTO backup_restore_entries VALUES "
                "('backup_001', NULL, 'person@example.test', 'archive/backup_001', '1', "
                "'2026-01-03T00:00:00Z');\n"
                "INSERT INTO backup_restore_entries VALUES "
                "('backup_002', NULL, 'person@example.test', 'archive/backup_002', '0', "
                "'2026-01-03T00:00:00Z');"
            ),
        )
        resources = reconstruct_resource_states(
            [
                ResourceObservation("backup_001", ("evidence_sql_flags",), (), None, "UNKNOWN", ()),
                ResourceObservation("backup_002", ("evidence_sql_flags",), (), None, "UNKNOWN", ()),
            ],
            EvidenceIndex([evidence]),
        )

        self.assertEqual(["RESTORABLE", "BLOCKED"], [
            resource.observed_state for resource in resources
        ])

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

        with self.assertRaisesRegex(ContractError, "state is unknown"):
            orchestrate_case(
                case,
                resolver,
                evidence_index,
                activity_index,
                [DeletionRule("rule_fixture", "USER_PROFILE", "Always", "DELETE")],
            )

    def test_policy_completion_preserves_redacted_tombstone_and_retained_audit_record(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        evidence = EvidenceFile(
            "evidence_policy",
            Path("policy.json"),
            "test_fixture",
            audit_at,
            (
                '{"records":['
                '{"resource_id":"tombstone_001","subject_reference":"user_001",'
                '"name":null,"email":null,"phone":null,"email_hash":null,'
                '"account_status":"DELETED"},'
                '{"resource_id":"audit_record_001","subject_reference":"user_001",'
                '"event_name":"ACCOUNT_DELETION_RECORDED",'
                '"retention_until":"2030-12-31T23:59:59Z"}]}'
            ),
        )
        resources = reconstruct_resource_states(
            [
                ResourceObservation("tombstone_001", ("evidence_policy",), (), None, "UNKNOWN", ()),
                ResourceObservation("audit_record_001", ("evidence_policy",), (), None, "UNKNOWN", ()),
            ],
            EvidenceIndex([evidence]),
        )
        case = AuditCase(
            "case_policy",
            "person@example.test",
            audit_at,
            "COMPLETE",
            audit_at,
            audit_at,
            "Please delete my account.",
        )
        investigation = CaseInvestigation("case_policy", ("evidence_policy",), resources)
        rules = [
            DeletionRule("rule_retained", "SECURITY_AUDIT_LOG", "Within retention", "RETAIN"),
            DeletionRule("rule_tombstone", "ACCOUNT_TOMBSTONE", "Stable reference", "REDACT"),
        ]

        result = plan_investigation(case, investigation, rules)

        self.assertEqual("REDACTED", resources[0].observed_state)
        self.assertEqual("PRESENT", resources[1].observed_state)
        self.assertEqual(datetime(2030, 12, 31, 23, 59, 59, tzinfo=timezone.utc), resources[1].retention_until)
        self.assertEqual("COMPLETE", result.deletion_status)
        self.assertEqual(
            ["VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED"],
            [step["operation"] for step in result.steps],
        )
        self.assertTrue(all(step["evidence_id"] == "evidence_policy" for step in result.steps))

    def test_identifiable_tombstone_is_redacted_instead_of_deleted(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        evidence = EvidenceFile(
            "evidence_tombstone",
            Path("snapshot.sql"),
            "test_fixture",
            audit_at,
            (
                "INSERT INTO records VALUES('tombstone_001','identity_service',"
                "'deleted_customer_references','{\"resource_id\":\"tombstone_001\","
                "\"subject_reference\":\"user_001\",\"name\":\"Fixture Person\","
                "\"email\":\"person@example.test\",\"phone\":null,\"email_hash\":null,"
                "\"account_status\":\"DELETED\"}','2026-01-03T00:00:00Z');"
            ),
        )
        resources = reconstruct_resource_states(
            [ResourceObservation("tombstone_001", ("evidence_tombstone",), (), None, "UNKNOWN", ())],
            EvidenceIndex([evidence]),
        )
        case = AuditCase(
            "case_tombstone",
            "person@example.test",
            audit_at,
            "COMPLETE",
            audit_at,
            audit_at,
            "Please delete my account.",
        )
        result = plan_investigation(
            case,
            CaseInvestigation("case_tombstone", ("evidence_tombstone",), resources),
            [DeletionRule("rule_tombstone", "ACCOUNT_TOMBSTONE", "Stable reference", "REDACT")],
        )

        self.assertEqual("PRESENT", resources[0].observed_state)
        self.assertEqual("INCOMPLETE", result.deletion_status)
        self.assertEqual(
            ["REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"],
            [step["operation"] for step in result.steps],
        )
        self.assertEqual("evidence_tombstone", result.steps[0]["evidence_id"])
        self.assertEqual(["", ""], [step["evidence_id"] for step in result.steps[1:]])

    def test_orchestration_finds_a_redacted_tombstone_by_stable_user_reference(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        case = AuditCase(
            "case_tombstone",
            "person@example.test",
            audit_at,
            "COMPLETE",
            audit_at,
            audit_at,
            "Please delete my account.",
        )
        resolver = Mock()
        resolver.resolve.return_value = ResolvedIdentity(
            "user_001",
            {"name": "", "email": case.email, "phone": "", "email_hash": ""},
            {},
        )
        evidence_index = EvidenceIndex(
            [
                EvidenceFile(
                    "evidence_tombstone",
                    Path("snapshot.json"),
                    "test_fixture",
                    audit_at,
                    '{"resource_id":"tombstone_001","subject_reference":"user_001",'
                    '"name":null,"email":null,"phone":null,"email_hash":null,'
                    '"account_status":"DELETED"}',
                )
            ]
        )

        result = orchestrate_case(
            case,
            resolver,
            evidence_index,
            ActivityIndex([]),
            [DeletionRule("rule_tombstone", "ACCOUNT_TOMBSTONE", "Stable reference", "REDACT")],
        )

        self.assertEqual("COMPLETE", result.deletion_status)
        self.assertEqual("VERIFY_RECORD_REDACTED", result.steps[0]["operation"])
        self.assertEqual("evidence_tombstone", result.steps[0]["evidence_id"])

    def test_anonymized_analytics_record_is_verified_without_remediation(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        evidence = EvidenceFile(
            "evidence_analytics",
            Path("analytics.json"),
            "test_fixture",
            audit_at,
            '{"resource_id":"analytics_001","record_type":"ANALYTICS_PROFILE",'
            '"result":"ANONYMIZED","subject_reference":""}',
        )
        resources = reconstruct_resource_states(
            [ResourceObservation("analytics_001", ("evidence_analytics",), (), None, "UNKNOWN", ())],
            EvidenceIndex([evidence]),
        )
        case = AuditCase(
            "case_analytics",
            "person@example.test",
            audit_at,
            "COMPLETE",
            audit_at,
            audit_at,
            "Please delete my account.",
        )

        result = plan_investigation(
            case,
            CaseInvestigation("case_analytics", ("evidence_analytics",), resources),
            [DeletionRule("rule_analytics", "ANALYTICS_PROFILE", "Still attributable", "ANONYMIZE")],
        )

        self.assertEqual("ANONYMIZED", resources[0].observed_state)
        self.assertEqual("COMPLETE", result.deletion_status)
        self.assertEqual("VERIFY_RECORD_ANONYMIZED", result.steps[0]["operation"])

    def test_support_message_redaction_and_analytics_attribution_follow_policy(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        evidence = EvidenceFile(
            "evidence_policy_records",
            Path("policy_records.json"),
            "test_fixture",
            audit_at,
            (
                '{"records":['
                '{"resource_id":"support_001","message_text":'
                '"Please contact person@example.test about the shared order."},'
                '{"resource_id":"support_002","message_text":"[REDACTED]"},'
                '{"resource_id":"analytics_001","user_id":"user_001",'
                '"record_type":"ANALYTICS_PROFILE"}]}'
            ),
        )
        resources = reconstruct_resource_states(
            [
                ResourceObservation(resource_id, ("evidence_policy_records",), (), None, "UNKNOWN", ())
                for resource_id in ("support_001", "support_002", "analytics_001")
            ],
            EvidenceIndex([evidence]),
        )
        case = AuditCase(
            "case_policy_records",
            "person@example.test",
            audit_at,
            "COMPLETE",
            audit_at,
            audit_at,
            "Please delete my account.",
        )
        rules = [
            DeletionRule("rule_support", "SUPPORT_MESSAGE", "Shared context", "REDACT"),
            DeletionRule("rule_analytics", "ANALYTICS_PROFILE", "Still attributable", "ANONYMIZE"),
        ]

        self.assertEqual(["PRESENT", "REDACTED", "PRESENT"], [
            resource.observed_state for resource in resources
        ])
        support_redacted = plan_investigation(
            case,
            CaseInvestigation(
                "case_policy_records", ("evidence_policy_records",), (resources[1],)
            ),
            rules,
        )
        analytics_identifiable = plan_investigation(
            case,
            CaseInvestigation(
                "case_policy_records", ("evidence_policy_records",), (resources[2],)
            ),
            rules,
        )
        self.assertEqual("COMPLETE", support_redacted.deletion_status)
        self.assertEqual("VERIFY_RECORD_REDACTED", support_redacted.steps[0]["operation"])
        self.assertEqual("INCOMPLETE", analytics_identifiable.deletion_status)
        self.assertEqual("ANONYMIZE_RECORD", analytics_identifiable.steps[1]["operation"])

    def test_policy_retention_requires_a_known_cutoff_and_active_legal_hold(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        case = AuditCase(
            "case_retention",
            "person@example.test",
            audit_at,
            "COMPLETE",
            audit_at,
            audit_at,
            "Please delete my account.",
        )
        evidence = EvidenceFile(
            "evidence_retention",
            Path("retention.json"),
            "test_fixture",
            audit_at,
            '{"resource_id":"audit_record_001","subject_reference":"user_001",'
            '"event_name":"ACCOUNT_DELETION_RECORDED",'
            '"retention_until":"2030-12-31T23:59:59Z"}',
        )
        resources = reconstruct_resource_states(
            [ResourceObservation("audit_record_001", ("evidence_retention",), (), None, "UNKNOWN", ())],
            EvidenceIndex([evidence]),
        )
        result = plan_investigation(
            case,
            CaseInvestigation("case_retention", ("evidence_retention",), resources),
            [DeletionRule("rule_audit", "SECURITY_AUDIT_LOG", "Within retention", "RETAIN")],
        )
        self.assertEqual("COMPLETE", result.deletion_status)
        self.assertEqual("VERIFY_RECORD_PRESENT", result.steps[0]["operation"])

        expired_retention = ResourceObservation(
            "audit_record_003",
            ("evidence_retention",),
            (),
            None,
            "PRESENT",
            ("evidence_retention",),
            datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        )
        expired_result = plan_investigation(
            case,
            CaseInvestigation("case_retention", ("evidence_retention",), (expired_retention,)),
            [DeletionRule("rule_audit", "SECURITY_AUDIT_LOG", "Within retention", "RETAIN")],
        )
        self.assertEqual("INCOMPLETE", expired_result.deletion_status)
        self.assertEqual("DELETE_RECORD", expired_result.steps[1]["operation"])

        no_cutoff = ResourceObservation(
            "audit_record_002", ("evidence_retention",), (), None, "PRESENT", ("evidence_retention",)
        )
        with self.assertRaisesRegex(ContractError, "retention cutoff is unknown"):
            plan_investigation(
                case,
                CaseInvestigation("case_retention", ("evidence_retention",), (no_cutoff,)),
                [DeletionRule("rule_audit", "SECURITY_AUDIT_LOG", "Within retention", "RETAIN")],
            )

    def test_reconstructs_retention_cutoff_from_sql_table_schema(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        evidence = EvidenceFile(
            "evidence_sql_retention",
            Path("inventory.sql"),
            "test_fixture",
            audit_at,
            (
                "CREATE TABLE security_audit_records ("
                "resource_id TEXT PRIMARY KEY, subject_reference TEXT NOT NULL, "
                "event_code TEXT NOT NULL, retention_until TEXT NOT NULL, "
                "updated_at TEXT NOT NULL);\n"
                "INSERT INTO security_audit_records VALUES "
                "('audit_record_001', 'user_001', 'ACCOUNT_DELETION_RECORDED', "
                "'2030-12-31T23:59:59Z', '2026-01-02T00:00:00Z');\n"
                "INSERT INTO security_audit_records VALUES "
                "('audit_record_002', 'user_002', 'ACCOUNT_DELETION_RECORDED', "
                "NULL, '2026-01-02T00:00:00Z');"
            ),
        )
        resources = reconstruct_resource_states(
            [
                ResourceObservation(resource_id, ("evidence_sql_retention",), (), None, "UNKNOWN", ())
                for resource_id in ("audit_record_001", "audit_record_002")
            ],
            EvidenceIndex([evidence]),
        )

        self.assertEqual(
            datetime(2030, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            resources[0].retention_until,
        )
        self.assertEqual("PRESENT", resources[0].observed_state)
        self.assertIsNone(resources[1].retention_until)
        self.assertEqual("PRESENT", resources[1].observed_state)

        case = AuditCase(
            "case_sql_retention",
            "person@example.test",
            audit_at,
            "COMPLETE",
            audit_at,
            audit_at,
            "Please delete my account.",
        )
        rules = [DeletionRule("rule_audit", "SECURITY_AUDIT_LOG", "Within retention", "RETAIN")]
        complete = plan_investigation(
            case,
            CaseInvestigation("case_sql_retention", ("evidence_sql_retention",), (resources[0],)),
            rules,
        )
        self.assertEqual("COMPLETE", complete.deletion_status)
        with self.assertRaisesRegex(ContractError, "retention cutoff is unknown"):
            plan_investigation(
                case,
                CaseInvestigation("case_sql_retention", ("evidence_sql_retention",), (resources[1],)),
                rules,
            )

    def test_blocked_backup_is_verified_as_retained_and_not_recommended_for_deletion(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        case = AuditCase(
            "case_backup",
            "person@example.test",
            audit_at,
            "COMPLETE",
            audit_at,
            audit_at,
            "Please delete my account.",
        )
        observation = ResourceObservation(
            "backup_001", ("evidence_backup",), (), None, "BLOCKED", ("evidence_backup",)
        )

        result = plan_investigation(
            case,
            CaseInvestigation("case_backup", ("evidence_backup",), (observation,)),
            [DeletionRule("rule_backup", "BACKUP_ARCHIVE", "Restore can be blocked", "RETAIN")],
        )

        self.assertEqual("COMPLETE", result.deletion_status)
        self.assertEqual("VERIFY_RESTORE_BLOCKED", result.steps[0]["operation"])

    def test_active_legal_hold_is_retained_and_unknown_hold_status_blocks_completion(self):
        audit_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        case = AuditCase(
            "case_hold",
            "person@example.test",
            audit_at,
            "COMPLETE",
            audit_at,
            audit_at,
            "Please delete my account.",
        )
        evidence = EvidenceFile(
            "evidence_hold",
            Path("hold.json"),
            "test_fixture",
            audit_at,
            '{"resource_id":"legal_hold_001","subject_reference":"user_001",'
            '"record_type":"LEGAL_HOLD_RECORD","hold_status":"ACTIVE"}',
        )
        resources = reconstruct_resource_states(
            [ResourceObservation("legal_hold_001", ("evidence_hold",), (), None, "UNKNOWN", ())],
            EvidenceIndex([evidence]),
        )
        rules = [
            DeletionRule("rule_hold", "LEGAL_HOLD_RECORD", "Active hold", "RETAIN")
        ]
        result = plan_investigation(
            case,
            CaseInvestigation("case_hold", ("evidence_hold",), resources),
            rules,
        )
        self.assertTrue(resources[0].policy_active)
        self.assertEqual("VERIFY_RECORD_PRESENT", result.steps[0]["operation"])

        unknown_hold = EvidenceFile(
            "evidence_hold_unknown",
            Path("hold_unknown.json"),
            "test_fixture",
            audit_at,
            '{"resource_id":"legal_hold_002","subject_reference":"user_001",'
            '"record_type":"LEGAL_HOLD_RECORD","result":"FOUND"}',
        )
        unknown_resources = reconstruct_resource_states(
            [
                ResourceObservation(
                    "legal_hold_002", ("evidence_hold_unknown",), (), None, "UNKNOWN", ()
                )
            ],
            EvidenceIndex([unknown_hold]),
        )
        with self.assertRaisesRegex(ContractError, "legal-hold status is unknown"):
            plan_investigation(
                case,
                CaseInvestigation("case_hold", ("evidence_hold_unknown",), unknown_resources),
                rules,
            )

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
