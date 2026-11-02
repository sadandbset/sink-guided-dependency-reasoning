# Augur IRIS Report

Generated at: `2026-10-23T00:38:19.341031+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 562 | 25 | 0 | 0 | 80 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 2 | 0 | 2 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `src/pretalx/common/mixins/forms.py:450` `py/augur/pretalx/pass1-path-traversal`: Pass 1 (CWE-22/23/36/073): attacker-controlled input flows into a filesystem access or file-response sink; the path is not contained by an allowed root before the file access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pretalx/common/views.py:56` `py/augur/pretalx/pass1-path-traversal`: Pass 1 (CWE-22/23/36/073): attacker-controlled input flows into a filesystem access or file-response sink; the path is not contained by an allowed root before the file access.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
