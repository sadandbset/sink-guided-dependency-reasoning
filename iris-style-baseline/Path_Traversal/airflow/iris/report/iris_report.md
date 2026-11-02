# Augur IRIS Report

Generated at: `2026-10-21T12:31:27.727966+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 631 | 269 | 0 | 54 | 2337 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 2 | 0 | 2 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `airflow/utils/serve_logs.py:108` `py/augur/airflow/pass1-path-traversal`: Untrusted request-derived data flows into a filesystem access path. \[Pass 1: path traversal\]
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `airflow/utils/serve_logs.py:109` `py/augur/airflow/pass1-path-traversal`: Untrusted request-derived data flows into a filesystem access path. \[Pass 1: path traversal\]
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
