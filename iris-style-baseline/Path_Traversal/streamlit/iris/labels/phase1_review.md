# Phase 1 Step 3 — LLM Candidate Labeling Review (Pass 1: Path Traversal)

**Checkpoint artifact (advisory human review gate, WORKFLOW 4.5).** Scope: Pass 1 only — Path Traversal, CWE-22 / CWE-23 / CWE-36 / CWE-73. No Phase 2 work was started.

## 1. Run facts

| Item | Value |
| --- | --- |
| Project / version | streamlit 1.11.0 (`lib/setup.py`) |
| Source root | `dataset/codeql_databases/path_traversal_dbs/streamlit_vuln` (read-only) |
| LLM model | **glm-5.3** (assistant model, Claude Code CLI) — in-session labeling; **no external LLM API calls** |
| Batches | **4** (17 request-boundary sources; 7 env/CLI sources; 8 serving sinks; 25 internal sinks) |
| Candidates processed | **57 / 57** (24 sources + 33 sinks, 100%; see `labels_raw_pass1.json` for per-candidate raw decisions) |
| Output | `labels/labels.json` (schema-valid), `labels/labels_raw_pass1.json`, `labels/label_stats.md`, this file |
| References loaded | `references/python.md`, `references/patterns.md`; **no framework reference matches** — Augur 0.3.0 has no `references/tornado.md`, so Tornado source/sink shapes come from repository evidence (detection.json) |

Constraint compliance: ground truth, patch diffs, and CVE advisories were **not** consulted; source code, CodeQL DB, Augur files, and the Phase 1 CSVs were **not modified**; no CodeQL query was executed in this step.

## 2. Headline finding

**One confirmed complete source→sink path-traversal flow exists in this database:**

`ComponentRequestHandler.get(path)` (`lib/streamlit/components/v1/components.py:310`, route `/component/(.*)`, `server.py:391-395`)
→ `parts = path.split("/")`; `parts[0]` must match a registered component (`components.py:311-317`)
→ `filename = "/".join(parts[1:])` (`components.py:319`)
→ `abspath = os.path.join(component_root, filename)` (`components.py:320`)
→ `open(abspath, "rb")` (`components.py:325`, label `sink-009`, tp, conf 0.97)
→ `self.write(contents)` (`components.py:333`) — file contents returned to the requester.

- **Validation present:** none on `filename`. No `basename`/`normpath`/`realpath`, no `startswith`/`relative_to` containment, no fixed-name mapping, no whitelist. The registry lookup (`components.py:436-443`) validates only `parts[0]`.
- **Escapes:** raw `../` segments are captured directly by the `(.*)` regex; percent-encoded `%2e%2e%2f` additionally decode because Tornado unquotes regex capture groups; a `filename` beginning with `/` (or a drive letter on Windows) makes `os.path.join` return an absolute path, bypassing `component_root` entirely. Multiple sequential `../` give arbitrary depth.
- **Reachability:** the route is unauthenticated, GET (no XSRF), and `set_default_headers` (components.py:351-353) permits cross-origin reads when CORS is disabled or in development mode. Precondition: the app must have registered at least one component with a filesystem `path` (via `declare_component(path=...)`); with no registered components the handler 404s.
- **Intended-function check (question 8):** serving files *under* `component_root` is the feature; reading files *outside* that root is not an authorized use — this is a vulnerability, not intended behavior.

## 3. Review questions (as posed for this pass)

1. **Real untrusted input boundaries?** Confirmed for: `/component/(.*)` route capture (src-012, tp 0.97), multipart POST body + headers on `/upload_file` (src-007/009, tp), static-route path (src-016, tp — sink side lives in the tornado library), multipart `filename` (src-022, tp). `os.getenv`/`os.environ.get` rows (src-001..006) and the click CLI `target` (src-021) are local operator boundaries, not network boundaries → `none`/fp (CLI kept at 0.7 confidence due to a Windows backslash edge, see Q4). Internal wrapper form params and response-hook params are not sources.
2. **Decoding/normalization/join/object conversion before file access?** The component flow is fully traceable step by step in real code (split → registry lookup → join → open; components.py:310-325). `unquote_plus` (routes.py:130) applies only to the `title` query argument and feeds a response header, not a path. No double-decode chain reaches a file API in-repo.
3. **Sinks are actual file operations?** Yes for all 30 `role=sink` entries (open / tokenize.open / os.remove / os.makedirs / os.stat / shutil.rmtree / tempfile.mkdtemp / bind_unix_socket / render / Path.glob). `Path(...)`, `join()`, and string concatenation were never counted as sinks (extraction policy, detection.json). `MediaFileHandler` was correctly **not** a sink — it serves from `InMemoryFileManager` (routes.py:173-205).
4. **Traversal variants?** For src-012/sink-009: `../` (raw and percent-encoded via capture unquoting), absolute paths (leading `/` resets `os.path.join`), drive letters on Windows, arbitrary repetition — all escape `component_root`; nothing blocks them. Windows edge noted on cli.py:75/196: `path.strip("/").rsplit("/", 1)[-1]` does not split backslashes, so a crafted URL could smuggle `..\` into the temp-dir join on Windows (sink-014, candidate 0.60).
5. **Real containment checks before file access?** None on the component route (Q2). For the static route, containment exists but in tornado library code outside the DB (`validate_absolute_path` abspath/realpath root check) — recorded as unverifiable in-repo on src-016. The page-name allowlist (routes.py:67-81) only rewrites known page names to `index.html`; other paths defer to the superclass.
6. **Do normpath/resolve/basename/startswith/blacklist neutralize here?** Not applicable on the component flow — none are present. Elsewhere: `clean_filename` (string_util.py:64-78) genuinely strips to `[-\w.]` and rejects `..` — but it sanitizes a *Content-Disposition filename*, not a filesystem path. `os.path.basename` (cli.py:196) is forward-slash-only (Windows caveat). `_is_valid_session_id` (upload_file_request_handler.py:50-52) validates session membership, not paths. No candidate was labeled `sanitizer` because none of these is an extracted candidate on a filesystem path.
7. **Symlinks / TOCTOU?** No symlink-following policy code exists in `lib/streamlit` for these flows (`os.path.realpath` is absent from the component and static-route paths). The component traversal does not rely on symlinks, so its absence is not a mitigation. TOCTOU-adjacent `os.path.exists/isdir` guards exist (cli.py:203, file_util.py:75, memo_decorator.py:126) but guard fixed internal paths. Recorded as **not applicable** — no symlink-dependent bypass found.
8. **Authorized file serving?** `/component/` serving files under a component root is the feature; escaping the root is not authorized (headline finding). `/assets/` and `/(.*)` static serving is the intended framework feature with framework-side containment; `/media/` serves in-memory files. Uploads are intentionally in-memory.
9. **Tests / constants / unreachable code / DB-generated files?** Extraction scope already excluded `lib/tests/`, `e2e/`, `scripts/`, generated proto, and the nested `streamlit-db` directory (detection.json `extraction_policy`); no test-file candidates reached labeling. Compile-time constant paths (`os.devnull`, `/etc/machine-id`, `/var/lib/dbus/machine-id`) → `role=none`, fp, conf 0.95.
10. **Complete flows vs partial wrappers?** One complete untrusted-source→dangerous-path flow (src-012 → sink-009). The element API sinks (st.image/st.audio/st.video opens, sink-010/011/015) are real sinks but their source side lives in app scripts outside this DB → `candidate`. The upload boundary (src-022 filename) terminates in memory inside the framework; its continuation into app scripts needs Phase 2 modeling. cli.py:75 is a local-CLI partial flow (candidate, Windows edge).

## 4. Sanitizer summary

Zero `sanitizer` entries (none of the extracted candidates is a barrier). For the record, real neutralizers observed in source but **not candidates**: `string_util.clean_filename` (header filenames only), `UploadFileRequestHandler._is_valid_session_id`, the page-name allowlist in `StaticFileHandler.parse_url_path`, and tornado's library-side `StaticFileHandler.validate_absolute_path` (out of DB). `MySanitizers.qll` must still be generated with an empty/`none()` fallback per WORKFLOW 5.2.3.

## 5. Dedup and exclusion record

- **Exact duplicates:** none in either CSV (all rows differ in file:line).
- **Near-duplicates retained intentionally:** `open` argument 0 ×17 sites, `os.remove` ×4, `os.stat` ×2, `glob` receiver ×2, `self.get_argument` ×2 — per-site classification differs, so entries are per-site; Step 4 must dedupe signatures when rendering `.qll`.
- **Excluded via `role=none` (16):** 6 env reads, CLI `target`, 3 response-hook path params, `check_origin` origin, multipart `content_type`/`body`, and 3 constant-path opens (devnull, machine-id ×2) — each with a code-anchored rationale.
- **Never extracted (documented, not labeled):** MediaFileHandler disk access (none — in-memory), tornado library internals (out of DB), archive extraction (absent from the codebase), `os.path.exists/isdir` pure checks, path-construction nodes.

## 6. Human review points (classification = candidate, 10 entries)

| ID | Site | Open question |
| --- | --- | --- |
| src-008 | stats.py:116 Accept header | keep as source (recall) or drop (comparison-only use)? |
| src-010 | routes.py:129 `title` arg | boundary real; header-only consumer; clean_filename is a barrier there |
| src-011 | routes.py:298 `hash` arg | in-memory cache key only |
| src-018 | server.py:774 WS payload | requires Phase 2 BackMsg/widget-state modeling to be useful |
| src-019/020 | `_require_arg` sessionId/widgetId | modeled as sources to skip dict modeling — confirm acceptable |
| sink-010/011/015 | st.image/st.audio/st.video opens | exploitability depends on app scripts (out of DB) |
| sink-014 | cli.py:75 download write | operator-trusted CLI, but Windows `rsplit('/')` backslash edge |

## 7. Recommendations for Phase 2 (not started)

1. Generate `MySources/MySinks/MySanitizers/MySummaries.qll` from these labels; dedupe signatures; keep `isBarrier` empty with `none()` fallback.
2. Add summary steps for the wrappers identified in detection.json: `open_python_file`, `streamlit_read`/`streamlit_write`, `_require_arg` (or keep the source modeling used here), and `parse_body_arguments` → `args`/`files` dict entries; model BackMsg `rerun_script` → widget-state deserialization if recall on the WebSocket channel is wanted.
3. Expected top alert: `src-012 → sink-009` (components.py:310 → 325). The `st.image`/`st.media` sinks can only fire with app-script-side sources, which are outside this DB.
4. Note for Step 6 filtering: the static-route source (src-016) defers to tornado's `validate_absolute_path`; alerts on it should be triaged against the installed tornado version's containment behavior rather than treated as in-repo confirmed.
