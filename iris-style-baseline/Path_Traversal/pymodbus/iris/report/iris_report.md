# Augur IRIS Report

Generated at: `2026-10-23T02:54:50.321227+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 3 | 8 | 0 | 1 | 22 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 2 | 0 | 2 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `pymodbus/server/simulator/http_server.py:264` `py/augur/pymodbus/pass1-path-traversal`: Untrusted data from an HTTP request path (source: request.path in pymodbus/server/simulator/http_server.py) flows to a file access API without path validation (Pass 1: path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `pymodbus/server/simulator/http_server.py:265` `py/augur/pymodbus/pass1-path-traversal`: Untrusted data from an HTTP request path (source: request.path in pymodbus/server/simulator/http_server.py) flows to a file access API without path validation (Pass 1: path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
