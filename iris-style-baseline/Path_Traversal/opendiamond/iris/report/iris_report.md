# Augur IRIS Report

Generated at: `2026-10-22T14:20:44.507461+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 137 | 38 | 1 | 70 | 129 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 6 | 0 | 6 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `opendiamond/dataretriever/diamond_store.py:137` `py/augur/opendiamond/pass1-path-traversal`: User-controlled path data flows from [this untrusted input](1) into a file-access API and may traverse outside the intended directory.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `opendiamond/dataretriever/mixer_store.py:266` `py/augur/opendiamond/pass1-path-traversal`: User-controlled path data flows from [this untrusted input](1) into a file-access API and may traverse outside the intended directory.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `opendiamond/dataretriever/test_store.py:296` `py/augur/opendiamond/pass1-path-traversal`: User-controlled path data flows from [this untrusted input](1) into a file-access API and may traverse outside the intended directory.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `opendiamond/dataretriever/video_store.py:104` `py/augur/opendiamond/pass1-path-traversal`: User-controlled path data flows from [this untrusted input](1) into a file-access API and may traverse outside the intended directory.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `opendiamond/dataretriever/video_store.py:162` `py/augur/opendiamond/pass1-path-traversal`: User-controlled path data flows from [this untrusted input](1) into a file-access API and may traverse outside the intended directory.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `opendiamond/dataretriever/yfcc100m_mysql_store.py:128` `py/augur/opendiamond/pass1-path-traversal`: User-controlled path data flows from [this untrusted input](1) into a file-access API and may traverse outside the intended directory.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
