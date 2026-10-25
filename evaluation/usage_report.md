# Model and token usage report

## Final full-dataset run

The final full-dataset run has **not completed**. `python3 code/main.py --generate-output output.csv` currently aborts because 201 cases are blocked by missing or insufficient evidence. No output CSV was produced, so there is no completed final run to report model usage for.

## Application usage

The solution code is deterministic Python and makes no model-provider calls.

| Provider / model | Calls | Input tokens | Output tokens | Estimated cost |
| --- | ---: | ---: | ---: | ---: |
| None (no model integration) | 0 | 0 | 0 | $0.00 |

Application model-token totals and cost are zero because no model is called. Average model tokens per request: 0.

## Final-run accounting status

Full-dataset request-level usage and final-run totals are **not applicable / unavailable** until a complete output-producing run succeeds. This report does not estimate coding-assistant session usage or claim that an incomplete diagnostic is the final run.
