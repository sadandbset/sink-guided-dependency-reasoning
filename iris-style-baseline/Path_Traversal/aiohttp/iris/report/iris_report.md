# Augur IRIS Report

Generated at: `2026-10-21T09:39:34.621707+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 27 | 17 | 4 | 10 | 135 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 4 | 0 | 0 | 4 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

No unresolved candidates.

## Filtered as Likely False Positives

- `pass1` `aiohttp/web_urldispatcher.py:657` `py/augur/aiohttp/pass1-path-traversal`: Tainted request-derived path data flows into a filesystem access. If this path is not protected by the StaticResource canonicalize-then-contain guard (resolve + relative_to) or the anchor rejection, an attacker may traverse outside the intended base directory (CWE-022/023/036/073).
Tainted request-derived path data flows into a filesystem access. If this path is not protected by the StaticResource canonicalize-then-contain guard (resolve + relative_to) or the anchor rejection, an attacker may traverse outside the intended base directory (CWE-022/023/036/073).
  - Reason: path traversal guard heuristic: `reject|deny|block.*\.\.`
- `pass1` `aiohttp/web_urldispatcher.py:667` `py/augur/aiohttp/pass1-path-traversal`: Tainted request-derived path data flows into a filesystem access. If this path is not protected by the StaticResource canonicalize-then-contain guard (resolve + relative_to) or the anchor rejection, an attacker may traverse outside the intended base directory (CWE-022/023/036/073).
Tainted request-derived path data flows into a filesystem access. If this path is not protected by the StaticResource canonicalize-then-contain guard (resolve + relative_to) or the anchor rejection, an attacker may traverse outside the intended base directory (CWE-022/023/036/073).
  - Reason: path traversal guard heuristic: `reject|deny|block.*\.\.`
- `pass1` `aiohttp/web_urldispatcher.py:668` `py/augur/aiohttp/pass1-path-traversal`: Tainted request-derived path data flows into a filesystem access. If this path is not protected by the StaticResource canonicalize-then-contain guard (resolve + relative_to) or the anchor rejection, an attacker may traverse outside the intended base directory (CWE-022/023/036/073).
Tainted request-derived path data flows into a filesystem access. If this path is not protected by the StaticResource canonicalize-then-contain guard (resolve + relative_to) or the anchor rejection, an attacker may traverse outside the intended base directory (CWE-022/023/036/073).
  - Reason: path traversal guard heuristic: `reject|deny|block.*\.\.`
- `pass1` `aiohttp/web_urldispatcher.py:683` `py/augur/aiohttp/pass1-path-traversal`: Tainted request-derived path data flows into a filesystem access. If this path is not protected by the StaticResource canonicalize-then-contain guard (resolve + relative_to) or the anchor rejection, an attacker may traverse outside the intended base directory (CWE-022/023/036/073).
Tainted request-derived path data flows into a filesystem access. If this path is not protected by the StaticResource canonicalize-then-contain guard (resolve + relative_to) or the anchor rejection, an attacker may traverse outside the intended base directory (CWE-022/023/036/073).
  - Reason: path traversal guard heuristic: `reject|deny|block.*\.\.`
