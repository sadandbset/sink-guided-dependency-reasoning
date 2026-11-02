# Augur Phase 1 Step 3 - Label Statistics

- **Project**: Flask-Cors (flask-cors_vuln snapshot, `flask_cors/version.py` = 3.0.8)
- **Pass**: 1 - Path Traversal (CWE-022, CWE-023, CWE-036, CWE-073)
- **LLM model**: `glm-5.3` (Claude Code agent harness; single deterministic labeling pass)
- **Generated**: 2026-10-22T03:30:00Z
- **Run ID**: `flask-cors-path-traversal-pass1-20261022`
- **Schema**: validated PASS against `augur-0.3.0/assets/labels_schema.json` (jsonschema, on-disk artifact re-validated after write)

## Input candidates and batching

| Input | Data rows | Labeled | Duplicates removed | Excluded |
| --- | --- | --- | --- | --- |
| `extraction/sources.csv` | 46 | 46 | 0 | 0 |
| `extraction/sinks.csv` | 21 | 21 | 0 | 0 |
| **Total** | **67** | **67** | **0** | **0** |

Batch policy (CSV row order, stable sizes, per WORKFLOW.md 4.4.4):

| Batch | Scope | Samples |
| --- | --- | --- |
| batch-01 | sources.csv rows 1-16 (flask_cors/core.py) | 16 |
| batch-02 | sources.csv rows 17-32 (flask_cors/core.py) | 16 |
| batch-03 | sources.csv rows 33-46 (core.py tail, decorator.py, extension.py) | 14 |
| batch-04 | sinks.csv rows 1-10 (examples import-path hacks, docs/conf.py) | 10 |
| batch-05 | sinks.csv rows 11-21 (setup.py open/join/dirname, view_based_example.py) | 11 |

Re-ask threshold 0.55: **0 entries below threshold** (minimum confidence 0.65), 0 re-asks, 0 entries left `candidate`/`unknown` for role assignment.

Dedup note: no exact duplicate rows exist. The two `os.path.dirname` rows per examples file are the inner/outer calls of `os.path.dirname(os.path.dirname(os.path.abspath(__file__)))` on one source line - distinct AST nodes. Rows sharing a line in `core.py` (245: `request.headers` vs `request.method`; 176: `request_headers` vs `request_method`) are distinct nodes. `tests/` (18 files) and `flask-cors-db/` were already excluded at extraction time (Step 2 path filters).

## Label counts by role x classification

| role | tp | fp | candidate | unknown | total |
| --- | --- | --- | --- | --- | --- |
| source | 8 | 0 | 0 | 0 | 8 |
| sink | 0 | 3 | 0 | 0 | 3 |
| sanitizer | 0 | 0 | 0 | 0 | 0 |
| summary | 0 | 0 | 4 | 0 | 4 |
| none | 0 | 52 | 0 | 0 | 52 |
| **total** | **8** | **55** | **4** | **0** | **67** |

## Source labels by extraction family

| CSV family (flowKind) | rows | labeled source | labeled none |
| --- | --- | --- | --- |
| request_attr (request.path / request.headers / request.method) | 5 | 5 (`src-023`, `src-024`, `src-037`, `src-045`, `src-046`) | 0 |
| request_header (Origin / ACL-Request-Method / ACL-Request-Headers reads) | 3 | 3 (`src-011`, `src-014`, `src-016`) | 0 |
| response_header (resp.headers.get) | 1 | 0 | 1 |
| request_value_param (internal helper params carrying request values) | 6 | 0 | 6 |
| wrapper_param (response-object wrapper params) | 2 | 0 | 2 |
| config_param (operator-trust option entry points) | 7 | 0 | 7 |
| config_field (options/app_config dict reads) | 22 | 0 | 22 |

Only `request.path` (`src-045`/`src-046`, extension.py:178/:180) is path-shaped. Header/method sources (`src-011`, `src-014`, `src-016`, `src-023`, `src-024`, `src-037`) are genuinely attacker-controlled but non-path-shaped; retained at 0.65-0.85 confidence for conservative recall. All 29 config-family rows are operator-trust (developer kwargs / `app.config` CORS_* / `DEFAULT_OPTIONS`) - not attacker input.

## Sink labels by extraction family

| CSV family (flowKind) | rows | role=sink | role=summary | role=none |
| --- | --- | --- | --- | --- |
| file_open (builtin open, setup.py:15/:18/:29) | 3 | 3 | 0 | 0 |
| path_join (os.path.join, setup.py:15/:18) | 2 | 0 | 2 | 0 |
| path_part (os.path.dirname; setup.py x2, examples x6) | 8 | 0 | 2 (setup.py) | 6 (examples) |
| path_canon (os.path.abspath; examples x3, docs x1) | 4 | 0 | 0 | 4 |
| import_path_insert (sys.path.insert; examples x3, docs x1) | 4 | 0 | 0 | 4 |

Dangerous path argument index: `open` = argument 0 (all 3 rows); `sys.path.insert` = argument 1. The 3 `open()` rows are real file-read API calls labeled `role=sink, classification=fp` - their path arguments are literal/`__file__`-derived constants inside the setuptools packaging script, unreachable from any untrusted source.

## Distribution by file

| File | entries | source | sink | summary | none |
| --- | --- | --- | --- | --- | --- |
| flask_cors/core.py | 34 | 5 | 0 | 0 | 29 |
| flask_cors/extension.py | 9 | 2 | 0 | 0 | 7 |
| flask_cors/decorator.py | 3 | 1 | 0 | 0 | 2 |
| setup.py | 7 | 0 | 3 | 4 | 0 |
| examples/app_based_example.py | 4 | 0 | 0 | 0 | 4 |
| examples/blueprints_based_example.py | 4 | 0 | 0 | 0 | 4 |
| examples/view_based_example.py | 4 | 0 | 0 | 0 | 4 |
| docs/conf.py | 2 | 0 | 0 | 0 | 2 |

Note: zero labels of any kind fall inside the `flask_cors` package's runtime logic as sinks or summaries - the package performs no filesystem access (grep-verified: no `open`/`os.path`/`pathlib`/`shutil`/`io` calls in any module).

## Flow kind mapping (CSV -> schema)

`request_attr` -> `field` (5), `request_header`/`response_header`/`config_field` -> `return` (26), `request_value_param`/`wrapper_param`/`config_param` -> `param` (15), sink families -> `argument` (21). CSV `argIndex` -1 mapped to schema `arg_index` null (5 request_attr rows).

## Quality checks (WORKFLOW.md 4.4.6)

1. **Schema validation**: PASS (labels.json validates against assets/labels_schema.json).
2. **Sink coverage for pass 1**: at least one sink exists - 3 `open()` rows (setup.py). Documented caveat: no sink exists inside the `flask_cors` package itself; the only file-access API in the entire snapshot is `builtin open()` in the packaging script with constant paths.
3. **Duplicates removed**: 0 (no exact duplicates existed; see dedup note).
4. **Argument index bounds**: all `flow_kind=argument` entries carry integer arg_index 0/1 matching the real parameter positions (`open(path, mode)` arg 0; `sys.path.insert(idx, path)` arg 1); param-position indices match the function definitions (e.g. `get_cors_headers(options, request_headers, request_method)` args 1/2).

## Sanitizers: 0 entries

No sanitizer labels were emitted. flask_cors contains no path-validation code at all (no base-dir containment, no `..` rejection, no realpath/normpath/basename guard) because it performs zero filesystem access - there is nothing to sanitize. `os.path.abspath` in examples/docs is canonicalization *without* base-dir containment on constant inputs, and `os.path.dirname` is component extraction - neither qualifies as a proven Pass 1 sanitizer (function name alone is not evidence).

## End-to-end flow statement

**No source-to-sink path traversal flow exists anywhere in this snapshot**: the 8 labeled sources (Flask request proxy boundary) all terminate in regex matching, logging, and CORS response-header construction inside a package with zero filesystem APIs, while the 3 labeled sinks (`setup.py` open) are fed only by constant literal paths in a packaging-time script. Any Phase 2 Pass 1 alert on this codebase would be a false positive by construction.
