# Evaluation report

## Full-dataset metrics

Final accuracy metrics are **not available**. No valid prediction CSV has been generated: the fail-closed batch planner currently stops because 201 of the 518 requests remain blocked by insufficient evidence. Reporting accuracy against hidden answers would be unsupported, and the public sample contains a documented evidence discrepancy. The prediction status, step, field, and sequence metrics therefore remain **N/A**, not zero.

The current run's diagnostic coverage was:

| Outcome | Cases |
| --- | ---: |
| COMPLETE | 76 |
| INCOMPLETE | 231 |
| NOT_APPLICABLE | 10 |
| BLOCKED | 201 |
| ERROR | 0 |

The outcomes are a coverage diagnostic, not a scoring report. `BLOCKED` is not an allowed output status and is never converted to one.

## Metrics supported by the evaluation tool

Run `python3 evaluation/evaluate.py <candidate.csv>` to compare a candidate with participant-provided `dataset/sample_output.csv`, or provide another participant-provided expected CSV with `--expected`.

The tool reports:

- Case-level deletion-status accuracy.
- Step-level exact-match accuracy, aligned by case and step position.
- Field-level accuracy over compared step fields.
- Sequence accuracy for each case's complete ordered `steps_json` array.
- Missing, duplicate, and unexpected case IDs.

No accuracy values are claimed here because no final dataset output is available to evaluate.

## Additional participant-created evaluation cases

These synthetic deletion-audit cases are implemented in `code/test_main.py`; they do not use organizer-only labels or real dataset subjects.

1. **Non-deletion export request:** an account export request returns NOT_APPLICABLE with no steps, without resolving identity or investigating resources (`test_orchestrates_non_deletion_without_resolving_or_investigating`).
2. **Evidence-backed remaining profile:** a deletion request with a present profile produces an INCOMPLETE row with finding, deletion remediation, and verification in required phase order (`test_orchestrates_evidence_backed_incomplete_case_in_contract_order`).
3. **Explicitly absent profile:** a resource-specific 404/zero-row lookup supports an evidence-cited COMPLETE verification (`test_reconstructs_explicit_absence_and_emits_evidence_backed_completion`).

The evaluator itself also has synthetic tests for exact-match metrics, a wrong status with a missing step, and missing/duplicate/unexpected case IDs (`evaluation/test_evaluate.py`).

## Failures found and improvements made

- **Unresolved evidence:** 201 requests remain blocked; the planner now aborts the entire batch rather than inventing COMPLETE or INCOMPLETE outcomes.
- **No valid final CSV:** `--generate-output` is implemented, but it exits without writing while unresolved cases remain.
- **Evaluation readiness:** added a deterministic evaluator for status, step, field, sequence, and case-ID metrics, plus focused tests for exact, incorrect, and malformed-case-set scenarios.
- **Public sample inconsistency:** the README records that sample answers cite resources absent from the cited participant-facing evidence. This discrepancy remains unresolved and was not papered over.
