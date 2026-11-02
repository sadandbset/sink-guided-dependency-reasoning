# Augur IRIS Report

Generated at: `2026-10-22T02:04:59.858525+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 195 | 183 | 19 | 209 | 163 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 28 | 0 | 28 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `copyparty/httpcli.py:783` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:1519` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:1531` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:1561` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:1584` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:1496` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:1607` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:1512` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:1517` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:1513` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:1514` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:2337` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:2233` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:2254` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:2255` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:2281` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:2610` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:2615` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:3876` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/httpcli.py:3878` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/szip.py:250` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/szip.py:259` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/util.py:1221` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/util.py:1211` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/util.py:1548` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/util.py:1962` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/util.py:1963` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `copyparty/util.py:1965` `py/augur/copyparty/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
