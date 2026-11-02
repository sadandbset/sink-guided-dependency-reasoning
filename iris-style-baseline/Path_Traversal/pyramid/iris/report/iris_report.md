# Augur IRIS Report

Generated at: `2026-10-23T05:17:24.569641+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 153 | 51 | 2 | 7 | 102 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 5 | 0 | 5 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `src/pyramid/i18n.py:193` `py/augur/pyramid/pass1-path-traversal`: Pass 1 (CWE-22/23/36/073): attacker-controlled request data reaches a filesystem access or file-response sink (open/listdir/metadata/pkg_resources/FileResponse) without the path being contained by an allowed root.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyramid/i18n.py:198` `py/augur/pyramid/pass1-path-traversal`: Pass 1 (CWE-22/23/36/073): attacker-controlled request data reaches a filesystem access or file-response sink (open/listdir/metadata/pkg_resources/FileResponse) without the path being contained by an allowed root.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyramid/i18n.py:200` `py/augur/pyramid/pass1-path-traversal`: Pass 1 (CWE-22/23/36/073): attacker-controlled request data reaches a filesystem access or file-response sink (open/listdir/metadata/pkg_resources/FileResponse) without the path being contained by an allowed root.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyramid/i18n.py:202` `py/augur/pyramid/pass1-path-traversal`: Pass 1 (CWE-22/23/36/073): attacker-controlled request data reaches a filesystem access or file-response sink (open/listdir/metadata/pkg_resources/FileResponse) without the path being contained by an allowed root.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyramid/i18n.py:203` `py/augur/pyramid/pass1-path-traversal`: Pass 1 (CWE-22/23/36/073): attacker-controlled request data reaches a filesystem access or file-response sink (open/listdir/metadata/pkg_resources/FileResponse) without the path being contained by an allowed root.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
