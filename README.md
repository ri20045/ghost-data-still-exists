# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists

Build an AI agent that audits whether a user's personal data was actually deleted.

A deletion workflow may report **Complete** while data still exists in databases, logs, support attachments, exports, search indexes, archives, or backups. Sync and restore processes may also bring deleted data back.

For each request, the agent must first determine whether deletion was actually requested. It then returns `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`, reports any remaining data or recreation risk, and produces the ordered remediation and verification steps required to finish an authorized deletion safely.

Read [`problem_statement.md`](./problem_statement.md) for the complete challenge contract.

Request intent is determined with deterministic multilingual rules. The classifier recognizes deletion and deletion-audit wording while excluding requests for access, correction, export, marketing opt-out, and explicit instructions not to delete.

Single-case orchestration correlates resources through direct identity matches and identity-linked activity references. Activity can identify a resource to inspect, but only resource-specific participant evidence captured by `audit_at` can establish its state. The planner applies the supplied delete/redact/anonymize/retain rules and emits verification for discovered resources that meet policy. Tombstones are correlated by their stable `user_id`; retention cutoffs, active legal holds, and blocked backup restores are checked explicitly. Unknown state or policy conditions prevent a completion decision. Batch row planning now validates the complete ordered result and fails without returning partial rows if any case is unresolved; CSV writing is not implemented yet.

Evidence-state reconstruction also reads nested JSON records and export-job fields, including explicit profile lookup status codes, and recognizes the status column in pipe-delimited inventory records. These formats are interpreted conservatively: identity-linked activity remains a discovery lead, and missing or conflicting state evidence is not treated as proof of deletion.

Timestamped log lines that contain a complete JSON object are also parsed as structured resource evidence. Explicit hit results, direct-identifier scan matches, redacted messages, and enabled/disabled flow or restore flags are recognized; absent or unparseable fields remain unknown.

Quoted key-value log messages are normalized before state checks, including escaped quotes embedded in an outer message field. This allows explicit 404/zero-row lookups, search hits, redaction markers, active-flow flags, and available exports to be reconstructed without treating a missing field as evidence.

Embedded JSON lookup records may encode row counts and HTTP status codes as strings; explicit `"rows":"0"` or HTTP 404 now establishes absence, while a positive row count establishes presence.

Search evidence can also establish an index entry's state through an explicit `total_hits` count, whether it appears in a structured record or a log line. A positive count means the entry is present; zero means absent.

For SQL snapshots that define `security_audit_records`, retention cutoffs are read from the `retention_until` column using that table's declared schema and matching resource row. Audit events from other tables or text that only reports an audit record as found do not establish a retention cutoff. The public sample's audit rows that omit this value therefore remain unresolved.

The public sample has a source inconsistency: `sample_output.csv` cites `account_001` and `account_002` in `evidence_54` for its first two cases, but the participant-facing evidence file does not contain those resource IDs. The implementation does not use sample answers to fabricate evidence; clarify or correct this discrepancy before relying on full-dataset completion results.

---

## Quick Start

Clone the repository and move into the project directory:

```bash
git clone https://github.com/interviewstreet/hackerrank-orchestrate-october26.git
cd hackerrank-orchestrate-october26
```

Start your AI coding tool from the **repository root** so it automatically reads [`AGENTS.md`](./AGENTS.md) and logs your session turns to `log.txt` in the root directory.

Build your solution in `code/main.py`, or use another language and document its setup and run command clearly in your README.

Your solution must:

- Read the input files from `dataset/`
- Generate one prediction row for every request in `dataset/deletion_requests.csv`
- Write the final predictions to `output.csv` in the repository root

Run the starter Python entry point with:

```bash
python3 code/main.py
```

At the foundation stage, this command validates the 518-request input contract.
Use the following during development to validate a generated output or compare a
sample prediction with the provided sample answer:

```bash
python3 code/main.py --validate-output output.csv
python3 code/main.py --requests dataset/sample_deletion_requests.csv --compare-sample path/to/sample_prediction.csv
python3 code/main.py --inspect-evidence case_33
python3 code/main.py --investigate-case case_05
python3 code/main.py --plan-case case_05
python3 code/main.py --diagnose-coverage
python3 code/main.py --requests dataset/sample_deletion_requests.csv --diagnose-coverage
python3 -m unittest discover -s code -p 'test_*.py'
```

`--diagnose-coverage` summarizes cases that can be planned, are not deletion requests, are blocked by missing identity/evidence, or encounter a separate processing error. Blocked/error cases are grouped by root cause; where an unresolved resource ID is known, the report includes that ID and the participant-facing evidence file IDs captured by `audit_at`. Unknown-state cases distinguish no resource evidence from evidence without a usable state signal, and flag support readbacks that show null requester fields but omit the message content needed to verify redaction. Unknown-retention cases distinguish an audit record lacking its required cutoff from resource-only evidence or no resource evidence, and state what participant-facing evidence is needed to resolve each case. A displayed evidence ID is a lead for review, not a claim that it proves the required state. The diagnostic does not create or modify `output.csv`.

`--require-resolved-coverage` can be combined with `--diagnose-coverage` to enforce fail-closed output eligibility. `BLOCKED` and `ERROR` are internal diagnostic outcomes, not deletion statuses allowed by the CSV contract; if any request has either outcome, the command exits with an error instead of allowing an incomplete or fabricated output. Without that flag, coverage diagnosis remains informational and exits normally.

The blank template at `dataset/output.csv` is provided as a reference. Your final generated file for submission must be the root-level `output.csv`.


## Dataset

All participant-facing files are in `dataset/`:

| File | Contents |
| --- | --- |
| `deletion_requests.csv` | 518 requests |
| `sample_deletion_requests.csv` | 32 sample requests |
| `sample_output.csv` | Correct sample answers |
| `user_identities.csv` | Current user identities |
| `user_audit_log.csv` | Historical identity changes |
| `system_activity.csv` | Activity across services and data processes |
| `deletion_rules.csv` | Required treatment for each data category |
| `evidence_files.csv` | Manifest of supplied evidence files |
| `output.csv` | Blank output template |

Evidence is stored under `dataset/evidence/` and may include PDFs, images, logs, JSON, plain text, or SQL snapshot exports. SQL captures may contain a primary database, regional replicas, a reporting replica, or a failover replica so replication drift can be investigated directly. The `.sql` files are readable as text and executable with SQLite.

Only `deletion_requests.csv` requires answers. The other files provide evidence and context.

---

## Output

Create `output.csv` with these columns in this exact order:

```text
case_id,deletion_status,steps_json
```

Produce exactly one row per request. `deletion_status` is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`. `steps_json` is an ordered JSON array containing findings, remediation actions, and verification checks. Use an empty array (`[]`) for `NOT_APPLICABLE`. Evidence references may be a `file_id`, `activity_id`, or `audit_id`. Determine the resource state at `audit_at` from the available evidence; reported workflow statuses and operation results are claims. Use `dataset/sample_output.csv` as the format reference.

The final file must contain 518 data rows sorted by `case_id` (plus the header row). The grader parses `steps_json` as JSON, so object-key order and whitespace do not matter; array order does. Order findings, remediation, and verification in that phase order. Within a phase, follow the operation order in the problem statement, then sort by `system_id` and `resource_id`.

---

## Evaluation

`output.csv` will be compared with hidden canonical answers. Scoring considers:

- deletion assessment accuracy;
- current and historical identity resolution;
- discovery of remaining data and recreation risks;
- correct policy application and evidence references; and
- completeness and ordering of remediation and verification steps.

Your `code.zip` must include:

```text
code/evaluation/evaluation_report.md
code/evaluation/usage_report.md
```

- `evaluation_report.md` must cover case, row, field, and sequence accuracy, at least three additional evaluation cases created by you, failures found, and improvements made.
- `usage_report.md` must cover the final full-dataset run, including model providers and names, model calls, input and output tokens, total and average tokens per request, and estimated total and per-request cost. Include per-model and overall totals when using multiple models.

**Important:** Place `evaluation_report.md` and `usage_report.md` inside `code/evaluation/` (matching `code/evaluation/main.py` in this starter layout), write your complete evaluation metrics, custom evaluation test cases, and token/cost breakdowns directly inside those Markdown files, and keep prompts in source code or Markdown files. Automated code evaluation ignores raw data files (`.csv`, `.tsv`, `.json`, `.jsonl`, `.sql`, `.log`), so content stored only in those formats will not be visible to the code judge or AI interviewer.

---

## Chat Transcript

This repository includes [`AGENTS.md`](./AGENTS.md), which instructs compatible AI coding tools to append conversation summaries to `log.txt` in the repository root:

| Platform | Path |
| --- | --- |
| macOS / Linux | `<repo root>/log.txt` |
| Windows | `<repo root>\log.txt` |

- Always launch your AI coding agent from the repository root (or explicitly ask it to read `./AGENTS.md` first) so every turn is logged to `log.txt` with the required `User Prompt`, `Agent Response Summary`, `Actions`, and `Context` sections.
- Upload `log.txt` directly as your `chat_transcript` submission on HackerRank.
- Do not include API keys, tokens, credentials, or secrets in prompts, code, configuration, or `log.txt`.

---

## Packaging `code.zip` and Submission

| Item | Description |
| --- | --- |
| `code.zip` | Runnable solution, prompts, configuration, `README.md`, and `evaluation/` reports |
| `output.csv` | One answer row for each of the 518 requests in `dataset/deletion_requests.csv` |
| `chat_transcript` | The root `log.txt` file generated by your coding agent |
| AI interview | Live explanation of your architecture, approach, and evaluation |

You may use any programming language, model, framework, or retrieval approach. Include clear setup and execution instructions in `README.md` inside `code.zip`.

To package `code.zip` from the repository root without bundling the dataset:

**macOS / Linux:**

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

**Windows (PowerShell):**

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

When packaging `code.zip`:

- Keep your evaluation reports in `code/evaluation/` so they are bundled automatically with `code` (or add `evaluation` to the archive command above if you placed them in a top-level `evaluation/` directory).
- Do **not** include `dataset/`, virtual environments (`.venv`, `venv`, `node_modules`), or build caches (`__pycache__`). On Windows, keep `.venv` at the repository root (outside `code/`) and remove any `code/__pycache__` folders before running `Compress-Archive`.
- Do **not** include nested archives (`.zip`, `.tar`, `.gz`, `.tgz`, `.7z`, `.rar`) inside `code.zip` — submissions containing nested archive files will be rejected.

Before submitting, confirm that:

- `output.csv` has the exact header `case_id,deletion_status,steps_json` and contains all 518 data rows sorted by `case_id`;
- every `steps_json` value is a valid JSON array with consecutive step numbers starting at `1`;
- findings cite valid evidence IDs, and `COMPLETE` verification steps cite evidence proving the current state;
- proposed remediation and future verification steps use an empty `evidence_id` (`""`);
- `code.zip` includes your runnable code, `README.md`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`;
- `log.txt` follows the `AGENTS.md` turn format and is uploaded to the `chat_transcript` slot; and
- no API keys, credentials, real personal data, or sensitive configuration values are included.
