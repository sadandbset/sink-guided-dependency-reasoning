# Augur IRIS Report

Generated at: `2026-10-23T02:27:00.546529+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 87 | 223 | 15 | 275 | 150 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 14 | 0 | 14 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `src/pyload/core/api/__init__.py:536` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/core/api/__init__.py:952` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/webui/app/blueprints/app_blueprint.py:36` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/webui/app/blueprints/app_blueprint.py:165` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/webui/app/blueprints/app_blueprint.py:259` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/webui/app/blueprints/app_blueprint.py:267` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/webui/app/blueprints/app_blueprint.py:300` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/webui/app/blueprints/app_blueprint.py:268` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/webui/app/blueprints/app_blueprint.py:306` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/webui/app/blueprints/app_blueprint.py:308` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/webui/app/blueprints/app_blueprint.py:289` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/webui/app/blueprints/cnl_blueprint.py:97` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/webui/app/helpers.py:86` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/pyload/webui/app/blueprints/json_blueprint.py:157` `py/augur/pyload/pass1-path-traversal`: Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
Untrusted request data flows into this filesystem path operation; verify the guard chain (purge.name/parse.name barriers, safepath component weakness, werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies on this channel before treating it as path traversal.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
