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
import re
import subprocess
import sys
import unicodedata
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
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
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
EVIDENCE_COLUMNS = ("file_id", "file_path", "origin", "captured_at")
ACTIVITY_COLUMNS = (
    "activity_id", "event_time", "event_type", "source_system", "target_system",
    "resource_id", "reported_result", "details",
)
RULE_COLUMNS = ("rule_id", "data_category", "condition", "required_action")
TEXT_EVIDENCE_SUFFIXES = {".log", ".sql", ".txt"}
# These are the resource namespaces represented by the participant-facing activity
# stream and policy artifacts.  Deliberately exclude identity values such as user_05.
RESOURCE_ID_PATTERN = re.compile(
    r"\b(?:account|analytics|audit_record|backup|data_flow|export|legal_hold|search|support|tombstone)_\d+\b"
)
DELETION_MARKERS = (
    "delete", "deleted", "deleting", "deletion", "erase", "erased", "erasing", "erasure",
    "remove my", "remove any", "remove all", "remove the account", "remove this account",
    "remove records", "remove the profile", "remove profile", "remove the rest",
    "remove that search result", "remove the search result", "remove personal",
    "close my account", "close the account", "close this account", "closed my account",
    "closed this account", "account deletion", "deletion request", "suppression", "supprimer",
    "supresión", "eliminación", "eliminacion", "eliminar", "borrar", "exclusão", "exclusao",
    "excluir", "apagamento", "apagar", "deletar", "삭제", "削除", "消去",
)
NEGATED_DELETION_PATTERNS = (
    r"\bnot\s+(?:a\s+)?request\s+to\s+(?:delete|erase|remove|close)\b",
    r"\bnot\s+(?:asking|requesting)\s+(?:for\s+(?:a\s+)?(?:deletion|erasure)|to\s+(?:delete|erase|remove|close))\b",
    r"\b(?:do\s+not|don['’]t|never)\s+(?:delete|erase|remove|close)\b",
    r"\b(?:do\s+not|don['’]t|never)\s+(?:want|need|wish)\s+(?:(?:you\s+)?to\s+)?(?:any\s+|a\s+)?(?:delete|erase|remove|close|deletion|erasure)\b",
    r"\bwithout\s+(?:deleting|erasing|removing|closing)\b",
    r"\bremove\s+me\s+from\s+(?:the\s+)?(?:marketing|promotional|mailing)\s+lists?\b",
    r"\bnot\s+(?:a\s+)?(?:deletion|erasure)\s+request\b",
    r"\bno\s+(?:solicito|pido|quiero)\s+(?:la\s+)?(?:eliminaci[oó]n|supresi[oó]n|borrar|eliminar)\b",
    r"\b(?:n[aã]o\s+(?:estou\s+)?(?:pedindo|solicito)|n[aã]o\s+quero)\s+(?:a\s+)?(?:exclus[aã]o|elimina[cç][aã]o|apagar|excluir)\b",
    r"\bpas\s+(?:une\s+demande\s+de|de\s+demande\s+de)\s+(?:suppression|effacement)\b",
    r"\bne\s+demande\s+pas\s+(?:la\s+)?(?:suppression|effacement)\b",
    r"\bne\s+(?:veux|souhaite)\s+pas\s+(?:supprimer|effacer)\b",
    r"削除(?:を依頼していません|の依頼ではありません|しないで)",
    r"削除(?:를 요청하지 않습니다| 요청이 아닙니다|하지 마세요)",
)
DELETION_AUDIT_ACTIONS = (
    "check", "confirm", "verify", "audit", "inspect", "review", "investigate",
    "tell me whether", "let me know whether",
)
DELETION_AUDIT_STATES = (
    "gone", "removed", "deleted", "erased", "no longer exists", "does not exist",
    "doesn't exist", "fully removed",
)
DELETION_AUDIT_SUBJECTS = ("account", "profile", "personal data", "analytics data", "records")
PREFIX_TO_CATEGORY = {
    "account": "USER_PROFILE",
    "analytics": "ANALYTICS_PROFILE",
    "audit_record": "SECURITY_AUDIT_LOG",
    "backup": "BACKUP_ARCHIVE",
    "data_flow": "DATA_FLOW",
    "export": "USER_EXPORT",
    "legal_hold": "LEGAL_HOLD_RECORD",
    "search": "SEARCH_INDEX_ENTRY",
    "support": "SUPPORT_MESSAGE",
    "tombstone": "ACCOUNT_TOMBSTONE",
}
PREFIX_TO_SYSTEM = {
    "account": "account_service", "analytics": "analytics_platform", "audit_record": "security_service",
    "backup": "backup_service", "data_flow": "integration_service", "export": "export_service",
    "legal_hold": "legal_service",
    "search": "search_service", "support": "support_platform", "tombstone": "identity_service",
}


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
class CaseCoverageDiagnostic:
    case_id: str
    outcome: str
    reason: str = ""
    reason_code: str = ""
    resource_id: str = ""
    evidence_ids: tuple[str, ...] = ()


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


@dataclass(frozen=True)
class EvidenceFile:
    file_id: str
    path: Path
    origin: str
    captured_at: datetime
    text: str


class EvidenceIndex:
    """Searchable evidence whose contents, not manifest rows, establish case links."""

    def __init__(self, files: list[EvidenceFile]):
        self.files = tuple(sorted(files, key=lambda item: (item.captured_at, item.file_id)))
        by_resource: dict[str, list[EvidenceFile]] = defaultdict(list)
        for evidence in self.files:
            for resource_id in _resource_ids_in_evidence(evidence):
                by_resource[resource_id].append(evidence)
        self._by_resource = {
            resource_id: tuple(items) for resource_id, items in by_resource.items()
        }

    def search(self, identifiers: Iterable[str], audit_at: datetime) -> list[EvidenceFile]:
        needles = {value.casefold() for value in identifiers if value.strip()}
        if not needles:
            return []
        return [
            evidence
            for evidence in self.files
            if evidence.captured_at <= audit_at
            and evidence.text
            and any(_identifier_in_text(evidence.text, needle) for needle in needles)
        ]

    def for_resource(self, resource_id: str, audit_at: datetime) -> list[EvidenceFile]:
        return [
            evidence
            for evidence in self._by_resource.get(resource_id, ())
            if evidence.captured_at <= audit_at
        ]


@dataclass(frozen=True)
class ActivityEvent:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass(frozen=True)
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


@dataclass(frozen=True)
class ResourceObservation:
    resource_id: str
    evidence_ids: tuple[str, ...]
    activity_ids: tuple[str, ...]
    latest_activity_claim: str | None
    observed_state: str
    state_evidence_ids: tuple[str, ...]
    retention_until: datetime | None = None
    policy_active: bool | None = None


@dataclass(frozen=True)
class CaseInvestigation:
    case_id: str
    evidence_ids: tuple[str, ...]
    resources: tuple[ResourceObservation, ...]


class ActivityIndex:
    def __init__(self, events: list[ActivityEvent]):
        self.events = tuple(sorted(events, key=lambda event: (event.event_time, event.activity_id)))
        self._by_resource: dict[str, list[ActivityEvent]] = defaultdict(list)
        for event in self.events:
            self._by_resource[event.resource_id].append(event)

    def for_resource(self, resource_id: str, audit_at: datetime) -> list[ActivityEvent]:
        return [event for event in self._by_resource.get(resource_id, []) if event.event_time <= audit_at]

    def linked_to_identifiers(
        self, identifiers: Iterable[str], audit_at: datetime
    ) -> list[ActivityEvent]:
        needles = tuple(value for value in identifiers if value.strip())
        return [
            event
            for event in self.events
            if event.event_time <= audit_at
            and any(_identifier_in_text(event.details, needle.casefold()) for needle in needles)
        ]


def _resource_ids_in_evidence(evidence: EvidenceFile) -> set[str]:
    if evidence.path.suffix.casefold() == ".json":
        try:
            document = json.loads(evidence.text)
        except json.JSONDecodeError as error:
            raise ContractError(f"{evidence.path}: invalid JSON evidence") from error

        resource_ids: set[str] = set()

        def collect(value: Any) -> None:
            if isinstance(value, dict):
                resource_id = value.get("resource_id")
                if isinstance(resource_id, str) and RESOURCE_ID_PATTERN.fullmatch(resource_id):
                    resource_ids.add(resource_id)
                for child in value.values():
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        collect(document)
        return resource_ids
    return set(RESOURCE_ID_PATTERN.findall(evidence.text))


def linked_resource_ids(evidence: EvidenceFile, identifiers: Iterable[str]) -> set[str]:
    """Find resources in the same evidence record or line as a subject identifier."""
    needles = {value.casefold() for value in identifiers if value.strip()}
    if not needles:
        return set()
    if evidence.path.suffix.casefold() == ".json":
        try:
            document = json.loads(evidence.text)
        except json.JSONDecodeError as error:
            raise ContractError(f"{evidence.path}: invalid JSON evidence") from error
        found: set[str] = set()

        def visit(value: Any) -> None:
            if isinstance(value, dict):
                serialized = json.dumps(value, ensure_ascii=False).casefold()
                if any(_identifier_in_text(serialized, needle) for needle in needles):
                    resource_id = value.get("resource_id")
                    if isinstance(resource_id, str) and RESOURCE_ID_PATTERN.fullmatch(resource_id):
                        found.add(resource_id)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(document)
        return found
    return {
        resource_id
        for line in evidence.text.splitlines()
        if any(_identifier_in_text(line, needle) for needle in needles)
        for resource_id in RESOURCE_ID_PATTERN.findall(line)
    }


def _identifier_in_text(text: str, identifier: str) -> bool:
    if not identifier:
        return False
    return re.search(
        rf"(?<![\w]){re.escape(identifier)}(?![\w])", text, re.IGNORECASE
    ) is not None


def _resource_state_from_result(result: str, resource_id: str) -> str:
    normalized = result.casefold()
    if normalized in {"not_found", "notfound", "miss", "absent"}:
        return "ABSENT"
    if normalized in {"redacted", "anonymized", "blocked"}:
        if normalized == "blocked" and resource_id.startswith("backup_"):
            return "BLOCKED"
        return normalized.upper()
    if normalized in {"active", "enabled"}:
        if resource_id.startswith("data_flow_"):
            return "ACTIVE"
        if resource_id.startswith("backup_"):
            return "RESTORABLE"
        return "PRESENT"
    if normalized in {"disabled", "inactive"} and resource_id.startswith("data_flow_"):
        return "INACTIVE"
    if normalized in {"restorable", "allowed", "available"} and resource_id.startswith("backup_"):
        return "RESTORABLE"
    if normalized in {"found", "identifiable", "hit", "present"}:
        if resource_id.startswith("data_flow_"):
            return "ACTIVE"
        if resource_id.startswith("backup_"):
            return "RESTORABLE"
        return "PRESENT"
    return "UNKNOWN"


def _resource_state_from_text(text: str, resource_id: str, *, sql_statement: bool = False) -> str:
    normalized = text.replace('\\"', '"').casefold()
    if resource_id.startswith("data_flow_"):
        if re.search(
            r"\b(?:state|status|flow_state)\s*[:=]\s*[\"']?active\b"
            r"|\b(?:enabled|scheduler_registered)\s*=\s*[\"']?true\b",
            normalized,
        ):
            return "ACTIVE"
        if re.search(
            r"\b(?:state|status|flow_state)\s*[:=]\s*[\"']?(?:disabled|inactive)\b"
            r"|\b(?:enabled|scheduler_registered)\s*=\s*[\"']?false\b",
            normalized,
        ):
            return "INACTIVE"
    if resource_id.startswith("backup_"):
        if re.search(
            r"\b(?:can_restore|restore_enabled)\s*=\s*[\"']?true\b"
            r"|\brestore_allowed\s*=\s*[\"']?(?:true|1)(?:\b|[\"'])"
            r"|\b(?:restore_access|restore_state|restore_status)\s*[:=]\s*[\"']?"
            r"(?:allowed|available|enabled|restorable)\b",
            normalized,
        ):
            return "RESTORABLE"
        if re.search(
            r"\b(?:can_restore|restore_enabled)\s*=\s*[\"']?false\b"
            r"|\brestore_allowed\s*=\s*[\"']?(?:false|0)(?:\b|[\"'])"
            r"|\b(?:restore_access|restore_state|restore_status)\s*[:=]\s*[\"']?"
            r"(?:blocked|disabled|denied)\b",
            normalized,
        ):
            return "BLOCKED"
    result = re.search(r"\bresult\s*[=:]\s*[\"']?([a-z_]+)", normalized)
    if result and _resource_state_from_result(result.group(1), resource_id) == "ABSENT":
        return "ABSENT"
    if re.search(
        r"\brows\s*=\s*[\"']?0[\"']?\b|\bhttp_status\s*=\s*[\"']?404[\"']?\b",
        normalized,
    ):
        return "ABSENT"
    if (
        resource_id.startswith("support_")
        and re.search(r"\bmessage_text\s*[=:]\s*[\"']\[redacted\][\"']", normalized)
    ):
        return "REDACTED"
    if (
        resource_id.startswith("export_")
        and re.search(r"\b(?:available|download_available)\s*=\s*[\"']?true\b", normalized)
    ):
        return "PRESENT"
    if not resource_id.startswith(("data_flow_", "backup_")) and _text_has_direct_identifier(normalized):
        return "PRESENT"
    if result:
        state = _resource_state_from_result(result.group(1), resource_id)
        if state != "UNKNOWN" and not (
            resource_id.startswith("tombstone_") and state == "REDACTED"
        ):
            return state
    if re.search(
        r"\brows\s*=\s*[\"']?[1-9]\d*[\"']?\b|\bhttp_status\s*=\s*[\"']?2\d\d[\"']?\b",
        normalized,
    ):
        return "PRESENT"
    if resource_id.startswith("tombstone_"):
        stable_reference = re.search(
            r"\bsubject_reference\s*[=:]\s*[\"']?user_\d+\b", normalized
        )
        deleted = re.search(
            r"\baccount_status\s*[=:]\s*[\"']?deleted\b", normalized
        )
        redacted_fields = (
            re.search(r"\b(?:name|full_name)\s*[=:]\s*(?:null|none|[\"']{2}|\[redacted\])", normalized),
            re.search(r"\bemail\s*[=:]\s*(?:null|none|[\"']{2}|\[redacted\])", normalized),
            re.search(r"\bphone\s*[=:]\s*(?:null|none|[\"']{2}|\[redacted\])", normalized),
            re.search(r"\bemail_hash\s*[=:]\s*(?:null|none|[\"']{2}|\[redacted\])", normalized),
        )
        if stable_reference and deleted and all(redacted_fields):
            return "REDACTED"
        if any(
            re.search(rf"\b{field}\s*[=:]\s*[\"']?[^,;\s\"']+", normalized)
            and not redacted
            for field, redacted in zip(
                ("name", "email", "phone", "email_hash"), redacted_fields
            )
        ):
            return "PRESENT"
        return "UNKNOWN"
    row_state = re.search(
        r"\|\s*(not_found|identifiable|anonymized|redacted|active|inactive|"
        r"found|absent|present|restorable|blocked)\s*\|",
        normalized,
    )
    if row_state:
        state = _resource_state_from_result(row_state.group(1), resource_id)
        if state != "UNKNOWN":
            return state
    if sql_statement:
        values = _sql_values_from_line(text)
        if values and values[0] == resource_id:
            if resource_id.startswith("backup_") and "backup_restore_entries" in normalized:
                if len(values) > 4 and values[4] in {"1", "true"}:
                    return "RESTORABLE"
                if len(values) > 4 and values[4] in {"0", "false"}:
                    return "BLOCKED"
            if resource_id.startswith("data_flow_") and "connector_subscriptions" in normalized:
                if len(values) > 4 and values[4] in {"1", "true"}:
                    return "ACTIVE"
                if len(values) > 4 and values[4] in {"0", "false"}:
                    return "INACTIVE"
    if sql_statement and re.search(r"^\s*insert\s+into\b", normalized):
        return "PRESENT"
    if re.search(r"\b(?:record_state|resource_state)\s*[:=]\s*[\"']?present\b", normalized):
        return "PRESENT"
    return "UNKNOWN"


def _text_has_direct_identifier(text: str) -> bool:
    matched_value = re.search(
        r"\bmatched_value\s*[=:]\s*(?:\"([^\"]*)\"|'([^']*)'|([^,\s|]+))",
        text,
        re.IGNORECASE,
    )
    if matched_value:
        value = next((part for part in matched_value.groups() if part is not None), "").strip()
        return value.casefold() not in {"", "null", "none", "n/a", "[redacted]"}
    event = re.search(r"\bevent\s*[=:]\s*[\"']?([\w-]+)", text, re.IGNORECASE)
    if not event or not re.search(
        r"(?:read|lookup|fetch|query|search|scan).*(?:completed|complete|hit|matched|found)$",
        event.group(1),
        re.IGNORECASE,
    ):
        return False
    field = (
        r"(?:email|email_address|owner_email|customer_email|requester_email|"
        r"subject_email|contact_email|phone|phone_number|owner_phone|customer_phone|"
        r"requester_phone|name|full_name|display_name|requester_name|email_hash)"
    )
    matches = re.finditer(
        rf"\b{field}\s*[=:]\s*(?:\"([^\"]*)\"|'([^']*)'|([^,\s|]+))",
        text,
        re.IGNORECASE,
    )
    for match in matches:
        value = next((part for part in match.groups() if part is not None), "").strip()
        if value.casefold() not in {"", "null", "none", "n/a", "[redacted]"}:
            return True
    return False


def _sql_values_from_line(line: str) -> list[str] | None:
    insert = re.search(r"\bVALUES\s*\(", line, re.IGNORECASE)
    if not insert:
        return None

    values: list[str] = []
    token: list[str] = []
    quoted = False
    index = insert.end()
    while index < len(line):
        character = line[index]
        if character == "'":
            if quoted and index + 1 < len(line) and line[index + 1] == "'":
                token.append("'")
                index += 2
                continue
            quoted = not quoted
        elif not quoted and character in ",)":
            values.append("".join(token).strip())
            token.clear()
            if character == ")":
                break
        else:
            token.append(character)
        index += 1

    return values


def _json_record_from_sql_line(line: str, resource_id: str) -> dict[str, Any] | None:
    values = _sql_values_from_line(line)
    if values is None:
        return None
    for value in values:
        try:
            record = json.loads(value)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and record.get("resource_id") == resource_id:
            return record
    return None


def _records_in_evidence(evidence: EvidenceFile, resource_id: str) -> list[dict[str, Any]]:
    if evidence.path.suffix.casefold() == ".json":
        try:
            document = json.loads(evidence.text)
        except json.JSONDecodeError as error:
            raise ContractError(f"{evidence.path}: invalid JSON evidence") from error
        records: list[dict[str, Any]] = []

        def visit(value: Any) -> None:
            if isinstance(value, dict):
                if value.get("resource_id") == resource_id:
                    records.append(value)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(document)
        return records
    if evidence.path.suffix.casefold() == ".sql":
        return [
            record
            for line in evidence.text.splitlines()
            if resource_id.casefold() in line.casefold()
            if (record := _json_record_from_sql_line(line, resource_id)) is not None
        ]
    records = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("resource_id") == resource_id:
                records.append(value)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for line in evidence.text.splitlines():
        object_start = line.find("{")
        if object_start < 0 or resource_id.casefold() not in line.casefold():
            continue
        try:
            structured_record = json.loads(line[object_start:])
        except json.JSONDecodeError:
            continue
        visit(structured_record)
    return records


def _resource_state_from_json_record(record: dict[str, Any], resource_id: str) -> str:
    direct_identifier_fields = (
        "email", "email_hash", "phone", "name", "full_name",
        "requester_email", "requester_phone", "requester_name",
        "owner_email", "owner_phone", "customer_email", "customer_phone",
        "subject_email", "contact_email", "email_address", "phone_number",
        "display_name",
    )

    def has_identifier(value: Any) -> bool:
        if isinstance(value, dict):
            if any(value.get(key) not in (None, "") for key in direct_identifier_fields):
                return True
            return any(has_identifier(child) for child in value.values())
        if isinstance(value, list):
            return any(has_identifier(child) for child in value)
        return False

    subject_reference = record.get("subject_reference")
    if resource_id.startswith("tombstone_"):
        if (
            re.fullmatch(r"user_\d+", str(subject_reference or ""))
            and record.get("account_status") == "DELETED"
            and all(
                field in record and record[field] in (None, "")
                for field in ("name", "email", "phone", "email_hash")
            )
        ):
            return "REDACTED"
        if has_identifier(record):
            return "PRESENT"
        return "UNKNOWN"
    if resource_id.startswith("data_flow_"):
        enabled = record.get("enabled", record.get("scheduler_registered"))
        if enabled is True or isinstance(enabled, str) and enabled.casefold() == "true":
            return "ACTIVE"
        if enabled is False or isinstance(enabled, str) and enabled.casefold() == "false":
            return "INACTIVE"
    if resource_id.startswith("backup_"):
        restore_allowed = record.get(
            "restore_allowed", record.get("can_restore", record.get("restore_enabled"))
        )
        if restore_allowed is True or isinstance(restore_allowed, str) and restore_allowed.casefold() in {"true", "1"}:
            return "RESTORABLE"
        if restore_allowed is False or isinstance(restore_allowed, str) and restore_allowed.casefold() in {"false", "0"}:
            return "BLOCKED"
    if resource_id.startswith("export_"):
        available = record.get("available", record.get("download_available"))
        if available is True or isinstance(available, str) and available.casefold() == "true":
            return "PRESENT"
    if record.get("status_code") == 404:
        return "ABSENT"
    if has_identifier(record):
        return "PRESENT"
    message_text = record.get("message_text")
    if resource_id.startswith("support_") and isinstance(message_text, str):
        if message_text.strip().casefold() == "[redacted]":
            return "REDACTED"
        if message_text.strip():
            return "PRESENT"
    if record.get("customer_reference") not in (None, "") or record.get("user_id") not in (None, ""):
        return "PRESENT"
    matched_value = record.get("matched_value")
    if isinstance(matched_value, str) and matched_value.strip():
        return "PRESENT"
    direct_identifiers = record.get("direct_identifiers")
    if direct_identifiers is True or isinstance(direct_identifiers, str) and direct_identifiers.casefold() in {"1", "true"}:
        return "PRESENT"
    if isinstance(record.get("profile"), dict) and record.get("status_code") == 200:
        return "PRESENT"
    if (
        resource_id.startswith("audit_record_")
        and re.fullmatch(r"user_\d+", str(subject_reference or ""))
        and (record.get("event_name") or record.get("event_code"))
        and record.get("retention_until")
    ):
        return "PRESENT"
    if resource_id.startswith("legal_hold_") and any(
        record.get(key) is not None
        for key in ("hold_status", "hold_state", "hold_active", "active")
    ):
        return "PRESENT"
    for key in ("record_state", "resource_state", "result"):
        value = record.get(key)
        if isinstance(value, str):
            state = _resource_state_from_result(value, resource_id)
            if state != "UNKNOWN":
                return state
    row_count = record.get("rows", record.get("row_count"))
    if row_count == 0:
        return "ABSENT"
    if isinstance(row_count, int) and row_count > 0:
        return "PRESENT"
    return "UNKNOWN"


def _resource_state_in_evidence(evidence: EvidenceFile, resource_id: str) -> str:
    records = _records_in_evidence(evidence, resource_id)
    states = [_resource_state_from_json_record(record, resource_id) for record in records]
    if evidence.path.suffix.casefold() not in {".json", ".sql"}:
        for line in evidence.text.splitlines():
            if resource_id.casefold() in line.casefold():
                states.append(
                    _resource_state_from_text(
                        line,
                        resource_id,
                        sql_statement=evidence.path.suffix.casefold() == ".sql",
                    )
                )
    elif evidence.path.suffix.casefold() == ".sql" and not records:
        for line in evidence.text.splitlines():
            if resource_id.casefold() in line.casefold():
                states.append(_resource_state_from_text(line, resource_id, sql_statement=True))

    known_states = [state for state in states if state != "UNKNOWN"]
    if resource_id.startswith("data_flow_"):
        if "ACTIVE" in known_states:
            return "ACTIVE"
        if known_states and all(state == "INACTIVE" for state in known_states):
            return "INACTIVE"
        return "UNKNOWN"
    if resource_id.startswith("backup_"):
        if "RESTORABLE" in known_states:
            return "RESTORABLE"
        if known_states and all(state == "BLOCKED" for state in known_states):
            return "BLOCKED"
        return "UNKNOWN"
    if "PRESENT" in known_states:
        return "PRESENT"
    if known_states and all(state == "ABSENT" for state in known_states):
        return "ABSENT"
    if "REDACTED" in known_states:
        return "REDACTED"
    if "ANONYMIZED" in known_states:
        return "ANONYMIZED"
    if "BLOCKED" in known_states:
        return "BLOCKED"
    return "UNKNOWN"


def _policy_metadata_from_record(record: dict[str, Any], resource_id: str) -> tuple[datetime | None, bool | None]:
    retention_value = record.get("retention_until")
    retention_until = None
    if isinstance(retention_value, str) and retention_value:
        retention_until = parse_timestamp(
            retention_value, field_name="retention_until", case_id=resource_id
        )

    active_value: Any = None
    if resource_id.startswith("legal_hold_"):
        active_value = record.get(
            "active",
            record.get(
                "hold_active",
                record.get("hold_status", record.get("hold_state", record.get("result"))),
            ),
        )
    if isinstance(active_value, bool):
        policy_active = active_value
    elif isinstance(active_value, str) and active_value.casefold() in {"active", "true", "open"}:
        policy_active = True
    elif isinstance(active_value, str) and active_value.casefold() in {
        "inactive", "false", "closed", "released",
    }:
        policy_active = False
    else:
        policy_active = None
    return retention_until, policy_active


def _policy_metadata_from_text(text: str, resource_id: str) -> tuple[datetime | None, bool | None]:
    retention_match = re.search(
        r"\bretention_until\s*[=:]\s*[\"']?"
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
        text,
        re.IGNORECASE,
    )
    retention_until = (
        parse_timestamp(
            retention_match.group(1), field_name="retention_until", case_id=resource_id
        )
        if retention_match
        else None
    )
    policy_active = None
    if resource_id.startswith("legal_hold_"):
        active_match = re.search(
            r"\b(?:active|hold_active|hold_status|hold_state|result)\s*[=:]\s*[\"']?"
            r"(active|inactive|true|false|open|closed|released)\b",
            text,
            re.IGNORECASE,
        )
        if active_match:
            policy_active = active_match.group(1).casefold() in {"active", "true", "open"}
    return retention_until, policy_active


def _policy_metadata_from_sql(text: str, resource_id: str) -> list[datetime]:
    table_name = "security_audit_records"
    table_definition = re.search(
        rf"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"`\[]?{table_name}[\"`\]]?"
        r"\s*\((.*?)\)\s*;",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if not table_definition:
        return []

    columns: list[str] = []
    for definition in table_definition.group(1).split(","):
        column = re.match(r'\s*(?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|(\w+))', definition)
        if column:
            columns.append(next(value for value in column.groups() if value is not None))
    if not {"resource_id", "retention_until"}.issubset(columns):
        return []

    metadata = []
    for line in text.splitlines():
        insert = re.search(
            rf"\bINSERT\s+INTO\s+[\"`\[]?{table_name}[\"`\]]?"
            r"\s*(?:\(([^)]*)\))?\s+VALUES\s*\(",
            line,
            re.IGNORECASE,
        )
        if not insert:
            continue
        insert_columns = (
            [column.strip().strip('"`[]') for column in insert.group(1).split(",")]
            if insert.group(1)
            else columns
        )
        values = _sql_values_from_line(line)
        if values is None or len(insert_columns) != len(values):
            continue
        row = dict(zip(insert_columns, values))
        retention_value = row.get("retention_until", "").strip()
        if (
            row.get("resource_id") != resource_id
            or retention_value.casefold() in {"", "null", "none"}
        ):
            continue
        retention_until = parse_timestamp(
            retention_value,
            field_name="retention_until",
            case_id=resource_id,
        )
        metadata.append(retention_until)
    return metadata


def reconstruct_resource_states(
    resources: Iterable[ResourceObservation], evidence_index: EvidenceIndex
) -> tuple[ResourceObservation, ...]:
    """Infer only resource states explicitly supported by linked evidence."""
    evidence_by_id = {evidence.file_id: evidence for evidence in evidence_index.files}
    reconstructed: list[ResourceObservation] = []
    for resource in resources:
        evidence_states = [
            (evidence_id, _resource_state_in_evidence(evidence_by_id[evidence_id], resource.resource_id))
            for evidence_id in resource.evidence_ids
            if evidence_id in evidence_by_id
        ]
        states = {state for _, state in evidence_states}
        if resource.resource_id.startswith("data_flow_") and "ACTIVE" in states:
            state = "ACTIVE"
        elif resource.resource_id.startswith("data_flow_") and states and states <= {"INACTIVE"}:
            state = "INACTIVE"
        elif resource.resource_id.startswith("backup_") and "RESTORABLE" in states:
            state = "RESTORABLE"
        elif resource.resource_id.startswith("backup_") and states and states <= {"BLOCKED"}:
            state = "BLOCKED"
        elif resource.resource_id.startswith(("data_flow_", "backup_")):
            state = "UNKNOWN"
        elif "PRESENT" in states:
            state = "PRESENT"
        elif states == {"ABSENT"}:
            state = "ABSENT"
        elif states == {"REDACTED"}:
            state = "REDACTED"
        elif states == {"ANONYMIZED"}:
            state = "ANONYMIZED"
        elif states == {"BLOCKED"}:
            state = "BLOCKED"
        else:
            state = "UNKNOWN"
        state_evidence_ids = tuple(
            evidence_id for evidence_id, evidence_state in evidence_states if evidence_state == state
        )
        metadata: list[tuple[datetime, datetime | None, bool | None]] = []
        for evidence_id in resource.evidence_ids:
            evidence = evidence_by_id.get(evidence_id)
            if evidence is None:
                continue
            metadata.extend(
                (
                    evidence.captured_at,
                    *_policy_metadata_from_record(record, resource.resource_id),
                )
                for record in _records_in_evidence(evidence, resource.resource_id)
            )
            if evidence.path.suffix.casefold() != ".json":
                for line in evidence.text.splitlines():
                    if resource.resource_id.casefold() not in line.casefold():
                        continue
                    retention_until, policy_active = _policy_metadata_from_text(
                        line, resource.resource_id
                    )
                    if retention_until is not None or policy_active is not None:
                        metadata.append((evidence.captured_at, retention_until, policy_active))
            if evidence.path.suffix.casefold() == ".sql":
                metadata.extend(
                    (evidence.captured_at, retention_until, None)
                    for retention_until in _policy_metadata_from_sql(
                        evidence.text, resource.resource_id
                    )
                )
        latest_metadata_at = max((item[0] for item in metadata), default=None)
        latest_metadata = [
            item for item in metadata
            if item[0] == latest_metadata_at and (item[1] is not None or item[2] is not None)
        ]
        retention_values = {item[1] for item in latest_metadata if item[1] is not None}
        active_values = {item[2] for item in latest_metadata if item[2] is not None}
        if len(retention_values) > 1 or len(active_values) > 1:
            raise ContractError(
                f"{resource.resource_id}: conflicting policy-condition evidence"
            )
        reconstructed.append(
            ResourceObservation(
                resource.resource_id,
                resource.evidence_ids,
                resource.activity_ids,
                resource.latest_activity_claim,
                state,
                state_evidence_ids,
                next(iter(retention_values), None),
                next(iter(active_values), None),
            )
        )
    return tuple(reconstructed)


def investigate_case(
    case: AuditCase,
    identity: ResolvedIdentity,
    evidence_index: EvidenceIndex,
    activity_index: ActivityIndex,
) -> CaseInvestigation:
    """Collect evidence-grounded candidate resources; activity is retained as an untrusted claim."""
    identifiers = (*identity.all_identifiers, identity.user_id)
    evidence = evidence_index.search(identifiers, case.audit_at)
    resource_evidence: dict[str, set[str]] = defaultdict(set)
    resource_activity: dict[str, set[str]] = defaultdict(set)
    for item in evidence:
        for resource_id in linked_resource_ids(item, identifiers):
            resource_evidence[resource_id].add(item.file_id)

    for event in activity_index.linked_to_identifiers(identifiers, case.audit_at):
        if not RESOURCE_ID_PATTERN.fullmatch(event.resource_id):
            continue
        resource_activity[event.resource_id].add(event.activity_id)
        for item in evidence_index.for_resource(event.resource_id, case.audit_at):
            resource_evidence[event.resource_id].add(item.file_id)

    observations: list[ResourceObservation] = []
    for resource_id in sorted(resource_evidence.keys() | resource_activity.keys()):
        events = activity_index.for_resource(resource_id, case.audit_at)
        latest_claim = None
        if events:
            latest = events[-1]
            latest_claim = f"{latest.event_type}:{latest.reported_result}"
        evidence_ids = tuple(sorted(resource_evidence[resource_id]))
        observations.append(
            ResourceObservation(
                resource_id=resource_id,
                evidence_ids=evidence_ids,
                activity_ids=tuple(sorted({
                    *(event.activity_id for event in events),
                    *resource_activity.get(resource_id, set()),
                })),
                latest_activity_claim=latest_claim,
                observed_state="UNKNOWN",
                state_evidence_ids=(),
            )
        )
    resource_observations = tuple(observations)
    return CaseInvestigation(
        case_id=case.case_id,
        evidence_ids=tuple(item.file_id for item in evidence),
        resources=reconstruct_resource_states(resource_observations, evidence_index),
    )


def request_authorizes_deletion(request_text: str) -> bool:
    """Recognize deletion requests and deletion audits without treating denials as consent."""
    normalized = unicodedata.normalize("NFKC", request_text).casefold()
    for pattern in NEGATED_DELETION_PATTERNS:
        normalized = re.sub(pattern, " ", normalized)

    if any(marker in normalized for marker in DELETION_MARKERS):
        return True
    return (
        any(action in normalized for action in DELETION_AUDIT_ACTIONS)
        and any(state in normalized for state in DELETION_AUDIT_STATES)
        and any(subject in normalized for subject in DELETION_AUDIT_SUBJECTS)
    )


def orchestrate_case(
    case: AuditCase,
    identity_resolver: IdentityResolver,
    evidence_index: EvidenceIndex,
    activity_index: ActivityIndex,
    rules: Iterable[DeletionRule],
) -> OutputRow:
    """Build one case result from intent, resolved identity, evidence, and policy."""
    if not request_authorizes_deletion(case.request_text):
        return OutputRow(case.case_id, "NOT_APPLICABLE", [])

    identity = identity_resolver.resolve(case.email, case.audit_at)
    investigation = investigate_case(case, identity, evidence_index, activity_index)
    return plan_investigation(case, investigation, rules)


def _missing_evidence_reason(error: ContractError) -> tuple[str, str] | None:
    message = str(error)
    normalized = message.casefold()
    if "no identity found for request email" in normalized:
        return "NO_IDENTITY", "no matching participant-facing identity record"
    if "no evidence-backed resources establish" in normalized:
        return "NO_LINKED_RESOURCE", "no linked evidence establishes a resource state"
    if "has no evidence for its reconstructed state" in normalized:
        return "NO_STATE_EVIDENCE", message.split(": ", 1)[-1]
    if "retention cutoff is unknown" in normalized:
        return "UNKNOWN_RETENTION_CUTOFF", message.split(": ", 1)[-1]
    if "legal-hold status is unknown" in normalized:
        return "UNKNOWN_LEGAL_HOLD", message.split(": ", 1)[-1]
    if "not evidenced as present" in normalized:
        return "REQUIRED_RECORD_NOT_EVIDENCED", message.split(": ", 1)[-1]
    if "state is unknown" in normalized:
        return "UNKNOWN_RESOURCE_STATE", message.split(": ", 1)[-1]
    return None


def diagnose_case_coverage(
    cases: Iterable[AuditCase],
    identity_resolver: IdentityResolver,
    evidence_index: EvidenceIndex,
    activity_index: ActivityIndex,
    rules: Iterable[DeletionRule],
) -> tuple[CaseCoverageDiagnostic, ...]:
    """Summarize case outcomes without writing predictions or suppressing errors."""
    rules_list = list(rules)
    diagnostics = []
    for case in cases:
        try:
            result = orchestrate_case(
                case, identity_resolver, evidence_index, activity_index, rules_list
            )
        except ContractError as error:
            blocked_reason = _missing_evidence_reason(error)
            if blocked_reason is not None:
                outcome = "BLOCKED"
                reason_code, reason = blocked_reason
            elif "maps to multiple users" in str(error).casefold():
                outcome = "ERROR"
                reason = "request identifier maps to multiple identity records"
                reason_code = "AMBIGUOUS_IDENTITY"
            else:
                outcome = "ERROR"
                reason = str(error)
                reason_code = "PROCESSING_ERROR"
            resource_match = RESOURCE_ID_PATTERN.search(str(error))
            resource_id = resource_match.group(0) if resource_match else ""
            evidence_ids = (
                tuple(
                    sorted({
                        evidence.file_id
                        for evidence in evidence_index.for_resource(resource_id, case.audit_at)
                    })
                )
                if resource_id
                else ()
            )
            diagnostics.append(
                CaseCoverageDiagnostic(
                    case.case_id,
                    outcome,
                    reason,
                    reason_code,
                    resource_id,
                    evidence_ids,
                )
            )
        else:
            diagnostics.append(
                CaseCoverageDiagnostic(case.case_id, result.deletion_status)
            )
    return tuple(diagnostics)


def make_step(
    phase: str, system_id: str, resource_id: str, operation: str, state: str, evidence_id: str
) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def resource_prefix(resource_id: str) -> str:
    if resource_id.startswith("audit_record_"):
        return "audit_record"
    if resource_id.startswith("data_flow_"):
        return "data_flow"
    if resource_id.startswith("legal_hold_"):
        return "legal_hold"
    return resource_id.split("_", 1)[0]


def plan_investigation(
    case: AuditCase, investigation: CaseInvestigation, rules: Iterable[DeletionRule]
) -> OutputRow:
    """Apply deletion policy to reconstructed states and emit a complete or incomplete row."""
    if not request_authorizes_deletion(case.request_text):
        return OutputRow(case.case_id, "NOT_APPLICABLE", [])

    rules_by_category = {rule.data_category: rule for rule in rules}
    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    future_verifications: list[dict[str, Any]] = []
    current_verifications: list[dict[str, Any]] = []
    if not investigation.resources:
        raise ContractError(
            f"{case.case_id}: no evidence-backed resources establish the required deletion state"
        )

    def evidence_for(observation: ResourceObservation) -> str:
        if not observation.state_evidence_ids:
            raise ContractError(
                f"{case.case_id}: {observation.resource_id} has no evidence for its reconstructed state"
            )
        return observation.state_evidence_ids[0]

    def record_steps(
        observation: ResourceObservation,
        *,
        finding_operation: str,
        remediation_operation: str,
        remediation_state: str,
        verification_operation: str,
        verification_state: str,
    ) -> None:
        prefix = resource_prefix(observation.resource_id)
        system_id = PREFIX_TO_SYSTEM[prefix]
        findings.append(
            make_step(
                "FINDING", system_id, observation.resource_id, finding_operation, "PRESENT",
                evidence_for(observation),
            )
        )
        remediations.append(
            make_step(
                "REMEDIATION", system_id, observation.resource_id, remediation_operation,
                remediation_state, "",
            )
        )
        future_verifications.append(
            make_step(
                "VERIFICATION", system_id, observation.resource_id, verification_operation,
                verification_state, "",
            )
        )

    for observation in investigation.resources:
        prefix = resource_prefix(observation.resource_id)
        if prefix not in PREFIX_TO_CATEGORY or prefix not in PREFIX_TO_SYSTEM:
            raise ContractError(
                f"{case.case_id}: no policy mapping for resource {observation.resource_id}"
            )
        category = PREFIX_TO_CATEGORY[prefix]
        system_id = PREFIX_TO_SYSTEM[prefix]
        state = observation.observed_state
        if prefix == "data_flow":
            if state == "ACTIVE":
                findings.append(
                    make_step(
                        "FINDING", system_id, observation.resource_id, "REPORT_ACTIVE_DATA_FLOW",
                        "ACTIVE", evidence_for(observation),
                    )
                )
                remediations.append(
                    make_step(
                        "REMEDIATION", system_id, observation.resource_id, "DISABLE_DATA_FLOW",
                        "DISABLED", "",
                    )
                )
                future_verifications.append(
                    make_step(
                        "VERIFICATION", system_id, observation.resource_id,
                        "VERIFY_DATA_FLOW_DISABLED", "DISABLED", "",
                    )
                )
            elif state == "INACTIVE":
                current_verifications.append(
                    make_step(
                        "VERIFICATION", system_id, observation.resource_id,
                        "VERIFY_DATA_FLOW_DISABLED", "DISABLED", evidence_for(observation),
                    )
                )
            else:
                raise ContractError(
                    f"{case.case_id}: data-flow state is unknown for {observation.resource_id}"
                )
            continue

        if prefix == "backup":
            if state == "RESTORABLE":
                findings.append(
                    make_step(
                        "FINDING", system_id, observation.resource_id, "REPORT_RESTORE_RISK",
                        "ACTIVE", evidence_for(observation),
                    )
                )
                remediations.append(
                    make_step(
                        "REMEDIATION", system_id, observation.resource_id, "BLOCK_RESTORE",
                        "BLOCKED", "",
                    )
                )
                future_verifications.append(
                    make_step(
                        "VERIFICATION", system_id, observation.resource_id,
                        "VERIFY_RESTORE_BLOCKED", "BLOCKED", "",
                    )
                )
            elif state == "BLOCKED":
                current_verifications.append(
                    make_step(
                        "VERIFICATION", system_id, observation.resource_id,
                        "VERIFY_RESTORE_BLOCKED", "BLOCKED", evidence_for(observation),
                    )
                )
            else:
                raise ContractError(
                    f"{case.case_id}: backup restore state is unknown for {observation.resource_id}"
                )
            continue

        rule = rules_by_category.get(category)
        if rule is None:
            raise ContractError(f"{case.case_id}: no deletion rule for category {category}")
        action = rule.required_action
        if category == "SECURITY_AUDIT_LOG":
            if observation.retention_until is None:
                raise ContractError(
                    f"{case.case_id}: retention cutoff is unknown for {observation.resource_id}"
                )
            action = "RETAIN" if case.audit_at <= observation.retention_until else "DELETE"
        elif category == "LEGAL_HOLD_RECORD":
            if observation.policy_active is None:
                raise ContractError(
                    f"{case.case_id}: legal-hold status is unknown for {observation.resource_id}"
                )
            action = "RETAIN" if observation.policy_active else "DELETE"

        if action == "DELETE":
            if state == "ABSENT":
                current_verifications.append(
                    make_step(
                        "VERIFICATION", system_id, observation.resource_id,
                        "VERIFY_RECORD_ABSENT", "ABSENT", evidence_for(observation),
                    )
                )
            elif state in {"PRESENT", "REDACTED", "ANONYMIZED"}:
                record_steps(
                    observation,
                    finding_operation="REPORT_REMAINING_RECORD",
                    remediation_operation="DELETE_RECORD",
                    remediation_state="ABSENT",
                    verification_operation="VERIFY_RECORD_ABSENT",
                    verification_state="ABSENT",
                )
            else:
                raise ContractError(
                    f"{case.case_id}: state is unknown for required deletion {observation.resource_id}"
                )
        elif action == "REDACT":
            if state == "REDACTED":
                current_verifications.append(
                    make_step(
                        "VERIFICATION", system_id, observation.resource_id,
                        "VERIFY_RECORD_REDACTED", "REDACTED", evidence_for(observation),
                    )
                )
            elif state == "ABSENT":
                current_verifications.append(
                    make_step(
                        "VERIFICATION", system_id, observation.resource_id,
                        "VERIFY_RECORD_ABSENT", "ABSENT", evidence_for(observation),
                    )
                )
            elif state in {"PRESENT", "ANONYMIZED"}:
                record_steps(
                    observation,
                    finding_operation="REPORT_EXPOSED_PII",
                    remediation_operation="REDACT_RECORD",
                    remediation_state="REDACTED",
                    verification_operation="VERIFY_RECORD_REDACTED",
                    verification_state="REDACTED",
                )
            else:
                raise ContractError(
                    f"{case.case_id}: redaction state is unknown for {observation.resource_id}"
                )
        elif action == "ANONYMIZE":
            if state == "ANONYMIZED":
                current_verifications.append(
                    make_step(
                        "VERIFICATION", system_id, observation.resource_id,
                        "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", evidence_for(observation),
                    )
                )
            elif state == "ABSENT":
                current_verifications.append(
                    make_step(
                        "VERIFICATION", system_id, observation.resource_id,
                        "VERIFY_RECORD_ABSENT", "ABSENT", evidence_for(observation),
                    )
                )
            elif state in {"PRESENT", "REDACTED"}:
                record_steps(
                    observation,
                    finding_operation="REPORT_EXPOSED_PII",
                    remediation_operation="ANONYMIZE_RECORD",
                    remediation_state="ANONYMIZED",
                    verification_operation="VERIFY_RECORD_ANONYMIZED",
                    verification_state="ANONYMIZED",
                )
            else:
                raise ContractError(
                    f"{case.case_id}: anonymization state is unknown for {observation.resource_id}"
                )
        elif action == "RETAIN":
            if state in {"PRESENT", "REDACTED", "ANONYMIZED"}:
                current_verifications.append(
                    make_step(
                        "VERIFICATION", system_id, observation.resource_id,
                        "VERIFY_RECORD_PRESENT", "PRESENT", evidence_for(observation),
                    )
                )
            else:
                raise ContractError(
                    f"{case.case_id}: required retained record is not evidenced as present: "
                    f"{observation.resource_id}"
                )
        else:
            raise ContractError(
                f"{case.case_id}: unsupported required action {action!r} for {category}"
            )

    if findings:
        steps = findings + remediations + future_verifications
        status = "INCOMPLETE"
    else:
        steps = current_verifications
        status = "COMPLETE"
    steps.sort(key=lambda step: (
        PHASE_ORDER[step["phase"]], OPERATION_ORDER[step["operation"]], step["system_id"], step["resource_id"]
    ))
    for step_no, step in enumerate(steps, start=1):
        step["step_no"] = step_no
    return OutputRow(case.case_id, status, steps)


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


def extract_evidence_text(path: Path) -> str:
    """Extract deterministic searchable text; image interpretation remains a later feature."""
    suffix = path.suffix.casefold()
    if suffix in TEXT_EVIDENCE_SUFFIXES:
        return path.read_text(encoding="utf-8", errors="replace")
    if suffix == ".json":
        try:
            return json.dumps(json.loads(path.read_text(encoding="utf-8")), ensure_ascii=False, sort_keys=True)
        except json.JSONDecodeError as error:
            raise ContractError(f"{path}: invalid JSON evidence") from error
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError:
            # Keep this dependency-free for clean challenge runs.  PDFs with compressed
            # streams may yield no strings and are then deferred for visual analysis.
            return subprocess.run(
                ["strings", "-a", str(path)], check=True, text=True, capture_output=True
            ).stdout
        else:
            try:
                return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)
            except Exception as error:  # pypdf exposes several format-specific exception classes.
                raise ContractError(f"{path}: unable to extract PDF text") from error
    if suffix == ".png":
        # PNGs need visual/OCR interpretation, deliberately deferred to the evidence-state feature.
        return ""
    raise ContractError(f"{path}: unsupported evidence type {suffix!r}")


def load_evidence_index(manifest_path: Path, dataset_root: Path = DATASET_ROOT) -> EvidenceIndex:
    """Load only manifest-declared evidence and verify every path stays within dataset/evidence."""
    evidence_root = (dataset_root / "evidence").resolve()
    files: list[EvidenceFile] = []
    with manifest_path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != EVIDENCE_COLUMNS:
            raise ContractError(f"{manifest_path}: expected evidence columns {EVIDENCE_COLUMNS}")
        file_ids: set[str] = set()
        for row_number, row in enumerate(reader, start=2):
            file_id = row["file_id"].strip()
            relative_path = Path(row["file_path"])
            resolved_path = (dataset_root / relative_path).resolve()
            if not file_id or file_id in file_ids:
                raise ContractError(f"{manifest_path}:{row_number}: missing or duplicate file_id")
            if evidence_root not in resolved_path.parents or not resolved_path.is_file():
                raise ContractError(f"{manifest_path}:{row_number}: invalid evidence path")
            file_ids.add(file_id)
            files.append(
                EvidenceFile(
                    file_id=file_id,
                    path=resolved_path,
                    origin=row["origin"].strip(),
                    captured_at=parse_timestamp(row["captured_at"], field_name="captured_at", case_id=file_id),
                    text=extract_evidence_text(resolved_path),
                )
            )
    return EvidenceIndex(files)


def load_activity_index(path: Path) -> ActivityIndex:
    events: list[ActivityEvent] = []
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != ACTIVITY_COLUMNS:
            raise ContractError(f"{path}: expected activity columns {ACTIVITY_COLUMNS}")
        activity_ids: set[str] = set()
        for row_number, row in enumerate(reader, start=2):
            activity_id = row["activity_id"].strip()
            if not activity_id or activity_id in activity_ids or not row["resource_id"].strip():
                raise ContractError(f"{path}:{row_number}: invalid activity row")
            activity_ids.add(activity_id)
            events.append(
                ActivityEvent(
                    activity_id=activity_id,
                    event_time=parse_timestamp(row["event_time"], field_name="event_time", case_id=activity_id),
                    event_type=row["event_type"].strip(),
                    source_system=row["source_system"].strip(),
                    target_system=row["target_system"].strip(),
                    resource_id=row["resource_id"].strip(),
                    reported_result=row["reported_result"].strip(),
                    details=row["details"],
                )
            )
    return ActivityIndex(events)


def load_deletion_rules(path: Path) -> list[DeletionRule]:
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != RULE_COLUMNS:
            raise ContractError(f"{path}: expected rule columns {RULE_COLUMNS}")
        rules = [DeletionRule(**row) for row in reader]
    if not rules or len({rule.rule_id for rule in rules}) != len(rules):
        raise ContractError(f"{path}: deletion rules must have unique IDs")
    return rules


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
    parser.add_argument("--inspect-evidence", metavar="CASE_ID", help="count text evidence linked to a resolved case at audit_at")
    parser.add_argument("--investigate-case", metavar="CASE_ID", help="list evidence-grounded resource candidates and activity claims")
    parser.add_argument("--plan-case", metavar="CASE_ID", help="build a policy-based plan for an investigated case")
    parser.add_argument(
        "--diagnose-coverage",
        action="store_true",
        help="summarize resolved, non-deletion, and evidence-blocked cases without writing output",
    )
    args = parser.parse_args()

    try:
        cases = load_requests(args.requests)
        selected_case_id = args.resolve_case or args.inspect_evidence or args.investigate_case or args.plan_case
        if selected_case_id:
            case = next((item for item in cases if item.case_id == selected_case_id), None)
            if case is None:
                raise ContractError(f"case not found: {selected_case_id}")
            resolver = load_identity_resolver(DATASET_ROOT / "user_identities.csv", DATASET_ROOT / "user_audit_log.csv")
            identity = resolver.resolve(case.email, case.audit_at)
            if args.resolve_case:
                alias_count = sum(len(values) for values in identity.historical_values.values())
                print(f"Resolved {case.case_id} to {identity.user_id} with {alias_count} identifier values at or before audit_at.")
            if args.inspect_evidence:
                matches = load_evidence_index(DATASET_ROOT / "evidence_files.csv").search(identity.all_identifiers, case.audit_at)
                print(f"Found {len(matches)} text-evidence item(s) for {case.case_id} at or before audit_at.")
            if args.investigate_case:
                investigation = investigate_case(
                    case,
                    identity,
                    load_evidence_index(DATASET_ROOT / "evidence_files.csv"),
                    load_activity_index(DATASET_ROOT / "system_activity.csv"),
                )
                print(
                    f"Investigated {case.case_id}: {len(investigation.evidence_ids)} evidence item(s), "
                    f"{len(investigation.resources)} evidence-grounded resource candidate(s)."
                )
            if args.plan_case:
                investigation = investigate_case(
                    case,
                    identity,
                    load_evidence_index(DATASET_ROOT / "evidence_files.csv"),
                    load_activity_index(DATASET_ROOT / "system_activity.csv"),
                )
                plan = plan_investigation(case, investigation, load_deletion_rules(DATASET_ROOT / "deletion_rules.csv"))
                print(f"Planned {plan.case_id}: {plan.deletion_status} with {len(plan.steps)} ordered step(s).")
        if args.diagnose_coverage:
            diagnostics = diagnose_case_coverage(
                cases,
                load_identity_resolver(DATASET_ROOT / "user_identities.csv", DATASET_ROOT / "user_audit_log.csv"),
                load_evidence_index(DATASET_ROOT / "evidence_files.csv"),
                load_activity_index(DATASET_ROOT / "system_activity.csv"),
                load_deletion_rules(DATASET_ROOT / "deletion_rules.csv"),
            )
            counts = {
                outcome: sum(item.outcome == outcome for item in diagnostics)
                for outcome in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE", "BLOCKED", "ERROR")
            }
            print(f"Coverage diagnostic for {len(diagnostics)} request(s):")
            for outcome, count in counts.items():
                print(f"  {outcome}: {count}")
            for outcome in ("BLOCKED", "ERROR"):
                groups: dict[str, list[CaseCoverageDiagnostic]] = defaultdict(list)
                for item in diagnostics:
                    if item.outcome == outcome:
                        groups[item.reason_code].append(item)
                for reason_code, entries in sorted(groups.items()):
                    print(f"{outcome} {reason_code} ({len(entries)} case(s)):")
                    for item in entries:
                        resources = f" resource={item.resource_id}" if item.resource_id else ""
                        evidence = (
                            ",".join(item.evidence_ids) if item.evidence_ids else "none"
                        )
                        print(
                            f"  {item.case_id}:{resources} evidence={evidence} "
                            f"reason={item.reason}"
                        )
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
