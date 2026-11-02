# Phase 1 Review - pymodbus / Pass 1 (Path Traversal, CWE-022/023/036/073)

Augur Phase 1 Step 3 checkpoint payload (advisory human review gate). Scope: LLM candidate labeling of all 34 candidates (12 sources.csv + 22 sinks.csv rows) against the real pymodbus_vuln source tree. Output: `labels.json` (schema-valid), `labels_raw_pass1.json`, `label_stats.md`.

## 1. Label counts by pass and role

| Pass | Focus | source | sink | sanitizer | summary | none | total |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Path Traversal | 3 | 8 | 0 | 1 | 22 | 34 |

Classifications: tp 12, fp 22, candidate 0, unknown 0. All 34 CSV rows processed (0 skipped); model glm-5.3, 3 batches (12/9/13); no entry below the 0.55 re-ask threshold.

## 2. Top high-risk sink APIs

| Sink | Location | Dangerous arg | Input controllability | Note |
| --- | --- | --- | --- | --- |
| K11 `open(file)` | pymodbus/server/simulator/http_server.py:264 | 0 | full - derived from `request.path[1:]` via join (S05→K10) | file read of unvalidated joined path; try/except is 404 error handling, not sanitization |
| K12 `web.FileResponse(file)` | http_server.py:265 | 0 | full - same path as K11 | file response; aiohttp-internal open untraceable (external lib) |
| K06 `open(json_file)` | http_server.py:130 | 0 | constructor param (operator config) | valid sink model; no untrusted source labeled to reach it |
| K03 `open(file)` / K04 `shutil.copyfile` | examples/contrib/explain.py:141/:168 | 0 / 1 | function param (local tool boundary) | valid sink models; local operator provenance |
| K13 `logging.FileHandler` | pymodbus/logging.py:57 | 0 | param (app logging config) | alert requires embedding app to forward user input into log config |
| K16 `open(modbus_config_path)` | pymodbus/repl/server/main.py:173 | 0 | typer CLI option (operator) | valid sink model; operator provenance |
| K21 `ssl load_cert_chain` | pymodbus/transport/transport.py:132 | 0 (certfile), 1 (keyfile) | operator TLS config | valid sink model; no untrusted source reaches it |

## 3. Top broad source APIs

| Source | Location | Boundary | Downstream use |
| --- | --- | --- | --- |
| S05 `request.path` | http_server.py:260 (handle_html_static) | aiohttp request path (client-controlled, percent-decoded) | → join → open/FileResponse (the only request-reachable file flow) |
| S06 `request.path` | http_server.py:271 (handle_html) | aiohttp request path | dict-key only (template selection); no file access |
| S07 `request.path` | http_server.py:287 (handle_json) | aiohttp request path | dict-key only; POST form drives register actions, no file access |

## 4. Sanitizer list

**Empty - no sanitizer labeled.** No normpath/abspath/realpath/relative_to/startswith/basename/`'..'`-rejection exists anywhere on the static-file path in the DB. The only input filter is the aiohttp route regex `{tail:[a-z0-9.]*}` (http_server.py:172); its effectiveness depends on external-library router semantics and is recorded as manual-review point R1 rather than asserted as a sanitizer (rubric: sanitizers require concrete evidence).

## 5. Unresolved / low-confidence items (manual review points)

**R1 (primary): aiohttp route-matching semantics vs. `request.path` (affects S05→K10→K11/K12 exploitability, not the labels).**
The handler reads `request.path` (decoded) directly instead of `request.match_info['tail']`. The route `/​{tail:[a-z0-9.]*}` is registered at http_server.py:172. Analysis of both plausible semantics:
- If aiohttp matches dynamic routes against the **raw (percent-encoded) path with an anchored whole-path pattern** (documented aiohttp behavior: dynamic routes match the entire path; `%` is not in `[a-z0-9.]`), then the matched raw path contains only `[a-z0-9./]` characters, its decoding is identity, and `page = request.path[1:]` cannot contain `/`, `\` or `%2e%2e%2f` - the join stays inside `web_path` and the flow is **not exploitable** (a bare `..` joins to a directory → `IsADirectoryError` → 404).
- If any aiohttp version matches a **decoded** path or a non-anchored pattern, encoded traversal sequences could reach `page` and escape `web_path` (no other defense exists in the handler).
aiohttp is outside the CodeQL database (not importable for verification during this run either), so this cannot be decided from DB code. Reviewer action: confirm the aiohttp version pinned by the deployment and its `DynamicResource` matching (raw vs decoded, fullmatch vs prefix). The labels (source=tp, sinks=tp) are correct under either semantics; this point governs the *finding* verdict in Phase 2 triage.

**R2: `handle_html`/`handle_json` KeyError (S06/S07).** An attacker-controlled `page_type` that is not a `generator_html` key raises KeyError → aiohttp 500. Not a path-traversal issue (information leak/DoS at most); noted because the source labels are kept.

**R3: `os.path.join` stdlib taint modeling (K10).** The summary label guarantees arg→result propagation even if the local CodeQL Python taint library lacks an `os.path.join` model. If the installed pack already models it, the summary is redundant but harmless.

**R4: `logging.FileHandler` (K13) reachability.** No in-repo caller passes `log_file_name` (grep-verified). Any alert requires an embedding application to forward attacker input into `pymodbus_apply_logging_config`; judgment left to Phase 2 alert triage.

## 6. Review of the ten labeling questions (per task contract)

1. **Source trust boundary**: only the three `request.path` reads are untrusted HTTP boundaries. Internal params (`json_file`, `log_file`, `custom_actions_module`, `log_file_name`, explain `file`) and CLI args (parse_args/typer) are operator/embedding-app inputs - a bare parameter is not a source; no privilege differential exists (no setuid/service-wrapper evidence).
2. **Path transformations**: the only request-derived path flow is `request.path[1:]` → `os.path.join` → `open`/`FileResponse`, fully tracked in real code (http_server.py:260-265); aiohttp performs single percent-decoding of `request.path` upstream (external); no double-decode, no object conversion on the path.
3. **Real file access**: sinks are actual open/FileResponse/copyfile/FileHandler/load_cert_chain call sites. `os.path.join`/`Path.joinpath` sites with constants or internal operands were **not** counted as dangerous file access (K07/K08/K14/K17); the tainted join (K10) is a summary, not a sink.
4. **Traversal forms**: `../`, absolute paths and separator variants would all escape `web_path` at the join (no in-code defense). Whether any such form can reach the handler is exactly R1. Backslash variants would additionally matter on Windows.
5. **Root containment checks**: none exist (no `relative_to`, no containment, no fixed-filename map, no allowlist beyond the external route regex).
6. **Sanitizer function-name traps**: no normpath/basename/startswith/blacklist code exists at all, so no function was "assumed" to sanitize; the route regex is not asserted as a sanitizer (external semantics, R1).
7. **Symlinks**: no symlink handling code anywhere on the flow; `web_path` is the package directory (attacker would first need a separator-capable path, R1). TOCTOU: single-shot open in try/except; no exists()-then-open window on attacker paths. Not applicable / nothing found.
8. **Authorized access**: operator reading own `json_file`/`log_file_name`/`modbus_config_path`/explain `file` is intended use, not a vulnerability; serving the fixed web assets is the console's intended function.
9. **Tests/constants/generated code**: no test files in the candidate set (extraction excluded `%/test/%`); constant-path rows (K07/K08/K09/K14/K15/K17) and the NamedTemporaryFile operand (K05) rejected; no DB-directory files involved.
10. **Complete vs. local flows**: only S05→K10→K11/K12 is a complete untrusted-source→dangerous-path-argument flow. Remaining sink labels (K03/K04/K06/K13/K16/K21) model valid dangerous APIs whose labeled inputs are trusted boundaries; the CLI/param→file flows are local wrapper flows without an attacker entry.

## 7. Quality checks (WORKFLOW 4.4.6)

- [x] labels.json schema-validated against `assets/labels_schema.json` (validation run recorded below).
- [x] Pass 1 has ≥ 1 sink (8) and ≥ 1 source (3).
- [x] Obvious duplicates handled (0 exact duplicate rows; S10/S11/S12, S05/S06/S07 grouped for library generation; recorded in labels_raw_pass1.json).
- [x] Argument indices verified against real signatures (correction: K10 argIndex 0→1; constructor param indices count `self` as 0, consistent with the CSV).

## 8. Process integrity statement

- Labeling basis: real source code at each CSV row's file/line anchor plus supporting greps (callers of `pymodbus_apply_logging_config`/`annotate_pymodbus_logs`, consumers of `self.log_file`, web/ directory listing) - no invented evidence.
- Ground-truth-looking artifacts in the source tree (VULNERABILITY_AUDIT_REPORT.md, path_traversal_sinks.csv, Chinese audit reports), CVE advisories and patch diffs were NOT read.
- No modification of source code, CodeQL database, Augur files, or Phase 1 extraction CSVs.
- An attempt to verify aiohttp router semantics by downloading and inspecting the aiohttp wheel was partially blocked by tool availability during the run (wheel downloaded; source inspection blocked by intermittent Bash-classifier outages). This is honestly reflected as unresolved point R1 rather than an asserted conclusion.

## 9. Decision requested

Approve the Pass 1 label set for Phase 2 library generation, with R1 (aiohttp route-matching semantics) carried forward as the decisive triage input for the S05→K11/K12 finding, or request label changes.
