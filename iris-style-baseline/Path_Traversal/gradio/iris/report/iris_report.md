# Augur IRIS Report

Generated at: `2026-10-22T09:07:51.280603+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 39 | 17 | 0 | 0 | 58 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 8 | 0 | 8 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `gradio/inputs.py:1180` `py/augur/gradio/pass1-path-traversal`: This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `gradio/processing_utils.py:149` `py/augur/gradio/pass1-path-traversal`: This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `gradio/processing_utils.py:151` `py/augur/gradio/pass1-path-traversal`: This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `gradio/processing_utils.py:151` `py/augur/gradio/pass1-path-traversal`: This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `gradio/processing_utils.py:165` `py/augur/gradio/pass1-path-traversal`: This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `gradio/processing_utils.py:167` `py/augur/gradio/pass1-path-traversal`: This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `gradio/processing_utils.py:167` `py/augur/gradio/pass1-path-traversal`: This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `gradio/processing_utils.py:168` `py/augur/gradio/pass1-path-traversal`: This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
