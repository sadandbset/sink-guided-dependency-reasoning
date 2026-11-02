# Phase 1 Review (Human Review Gate — advisory) — xmpp-http-upload, Pass 1: Path Traversal

Augur 0.3.0, Phase 1 Step 3 output for review before Phase 2 (library generation, taint queries).
Artifacts: `labels/labels.json` (schema-valid, 32 entries), `labels/labels_raw_pass1.json` (3 batches, verbatim candidate rows), `labels/label_stats.md`.
Model: `glm-5.3` (in-session labeling; 3 batches: 4 sources / 14 + 14 sinks; 32/32 candidates processed).

## 1. Label counts by pass and role

| Role | Count |
| --- | --- |
| source | 4 |
| sink | 7 |
| sanitizer | **0** (deliberate — §4) |
| summary | 8 |
| none | 13 |

Classification: tp 19, fp 13, candidate/unknown 0. Lowest confidence: 0.65 (sink-020 `unlink`, sink-026 `stat`) — all above the 0.55 re-ask threshold.

## 2. Top high-risk sink APIs (in exploitability order)

| Entry | API | Route | Why |
| --- | --- | --- | --- |
| sink-028 | `flask.send_file(str(data_file))` — xhu.py:228 | GET `/<path:path>` — **unauthenticated** | framework file-read-into-response; arg 0 = `<route-path>.data`; traversal via `../` reads files outside `DATA_ROOT` (limited to `*.data` names) |
| sink-013 | `metadata_file.open("r")` — xhu.py:57 | HEAD/GET — **unauthenticated** | file read of `<route-path>.meta` outside `DATA_ROOT` under the same broken guard |
| sink-026 | `data_file.stat()` — xhu.py:197 | HEAD — **unauthenticated** | existence/size oracle on `<route-path>.data` outside `DATA_ROOT` |
| sink-019 | `at.open("xb")` — xhu.py:76 | PUT — HMAC-gated | exclusive-create write of `<route-path>.data`; path signed by SECRET_KEY holder |
| sink-023 | `dest_path.parent.mkdir(parents=True)` — xhu.py:137 | PUT — HMAC-gated | recursive directory creation outside `DATA_ROOT` via `../` (not suffix-constrained) |
| sink-024 | `metadata_file.open("x")` — xhu.py:144 | PUT — HMAC-gated | exclusive-create write of `<route-path>.meta` |
| sink-020 | `at.unlink()` — xhu.py:80 | PUT — HMAC-gated, error path only | rollback deletion of `<route-path>.data` |

**Flow narrative (complete, source-to-sink):** request URL → Werkzeug `path` converter (percent-decodes, captures the full remainder incl. slashes as a relative string) → handler parameter `path` (put_file :105 / head_file :190 / get_file :215) → `sanitized_join(path, Path(DATA_ROOT))` (:107 / :64) → `(root / path).absolute()` (:43, no normalization) → lexical `startswith` guard (:44, **always passes for converter input**) → `get_paths` `'<base>.data'/'.meta'` (:50/:51) → the sink APIs above. On GET/HEAD nothing authenticates the caller; only PUT checks an HMAC over `"{path} {length}"` (:118–130).

## 3. Top broad source APIs

All 4 labeled sources are genuine request-boundary reads, but **none reaches a path sink in this codebase**:

- `flask.request.args.get("v")` (:118) → only `hmac.compare_digest` (:125) — verification-key input.
- `flask.request.headers.get("Content-Length")` (:119) → int → HMAC input (:120) + stream-copy length (:142).
- `flask.request.headers.get("Content-Type")` (:132) → `.meta` JSON (:147) → response headers (pass-10 adjacent).
- `flask.request.stream` (:142) → body **content** written by `stream_file` (:92–101) — never a path.

**The real path source (the route parameter) is missing from the CSV** — see §6, the top review point.

## 4. Sanitizer list — empty, and why that is correct

The only guard, `sanitized_join` (xhu.py:42–46), is **not a proven neutralization**:

1. `pathlib.Path.absolute()` performs no `..` normalization and no symlink resolution (CPython semantics; `resolve()` is the normalizing API and is never called).
2. The Werkzeug `path` converter regex `[^/].*?` guarantees a *relative* string, so `(root / path)` is a textual join whose `str()` always begins with `str(root) + "/"` — the guard is satisfied by every converter-supplied path, including `a/../../etc/passwd`-style inputs, and the OS resolves the `..` segments at the later `open`/`stat`/`mkdir`/`send_file`.
3. There is no `normpath`, no `realpath`, no `basename`, no explicit `..` rejection, no allowlist anywhere in `xhu.py`.

Labeling `sanitized_join` a barrier would suppress the genuine flow; it is labeled `summary` (param 0 → return) instead. **Step-6 warning:** the pipeline’s generic “explicit `startswith` guard → FP” heuristic must not fire on this project’s findings.

## 5. Answers to the ten mandated review questions

1. **Sources genuinely untrusted?** Yes for all 4 CSV rows (query string / headers / raw body — all attacker-controlled, URL-decoded by the framework). No internal function parameter was auto-promoted to source: `get_info`/`sanitized_join`/`write_file`/`load_metadata` parameter rows are `summary`/`none`, not `source`.
2. **Decode/join/conversion chain traceable?** Yes — every step is a concrete cited line: Werkzeug decode (framework, invisible to the DB but documented) → `path` param → `sanitized_join` :107/:64 → `(root/path).absolute()` :43 → `get_paths` `+ ".data"/".meta"` :50/:51 → `.open/.stat/.mkdir/.unlink/send_file`. No multipart, no archive, no object conversion exists.
3. **Sinks are actual file access?** Only the 7 `sink` rows are real file read/write/delete/mkdir/stat/file-response calls. `Path(...)`, `os.path.join`, the `/` join, `.absolute()` are pure path wrappers → labeled `summary`/`none`, never sinks. `flask.make_response` (response wrapper) was correctly not extracted.
4. **Can the path escape the declared root?** **Yes, via `../`**: the guard compares the un-normalized joined string (§4). Absolute paths are impossible from the converter (regex forbids a leading `/`; `//x` does not match the rule). On POSIX a backslash is an ordinary filename character (no separator confusion, no escape). Double decoding: the app itself never decodes; Werkzeug/WSGI decode once — `%2e%2e%2f` arrives as `../` in the handler. Escape is therefore possible and the read/write targets resolve outside `DATA_ROOT`.
5. **Real, pre-access root check?** A check exists and runs before the file access (`sanitized_join` is called before every use), but it is *ineffective* for converter-supplied paths (§4) — not a valid containment, so it is not a sanitizer label.
6. **Could normpath/resolve/basename/startswith/replace/blacklist block it here?** None of normpath/resolve/basename/blacklist exist in the code. The one present mechanism (`startswith` after `.absolute()`) fails for the reasons in §4 — function name (“sanitized_”) and shape (“prefix check”) do not make a sanitizer in this concrete implementation.
7. **Symlinks / TOCTOU?** No symlink creation, no `resolve()`/`is_symlink()`; the check-then-use window exists (check in `sanitized_join`, use at :76/:137/:144/:197/:228) and a symlink planted under `DATA_ROOT` pointing outside would be followed (the guard is lexical). However the app only creates regular files/dirs — planting a symlink requires independent filesystem write access. **Recorded as not applicable via the app alone** (defense-in-depth note only).
8. **Is the access user-authorized by design?** The service intentionally serves stored files over GET/HEAD (XMPP HTTP upload protocol), but the *declared* boundary is `DATA_ROOT` plus the textual `.data`/`.meta` suffixes. Traversal with `../` reads/writes outside that declared boundary — not an authorized access pattern. PUT additionally requires an HMAC over the exact path (so a traversal PUT needs the key holder to have signed that exact traversal path); GET/HEAD have **no** such gate.
9. **Tests / constants / generated code?** No test tree exists in the project. The 4 `setup.py` rows are packaging constants → `none`/fp. `config.example.py` contributes no candidates. The CodeQL DB directory (inside the source tree) was excluded by the extraction filter and never explored.
10. **Complete flow or local wrapper fragment?** The dominant flow is **complete** from a truly untrusted source (route parameter) to dangerous file-API path positions — but the source end is missing from the CSV (§6). The CSV’s 4 sources have no path flow. The sink-side labels carry the internal chain via the 8 `summary` edges (sanitized_join, get_info, get_paths, `Path` ctor, Div join), so Phase 2 will connect once the route-param source is modeled.

## 6. Unresolved / low-confidence items and human review points

1. **[Blocker for Phase 2 recall] Route-parameter sources missing from `sources.csv`.** Verified root cause: `sources.ql` `flaskRouteHandler` casts `Function.getADecorator()` to `Attribute`; for `@app.route("/<path:path>", methods=[...])` the API returns the decorator **Call** node (verified by read-only diagnostics in `iris/diagnostics/`: `instanceof Call` true, `instanceof Attribute` false; fix pattern `dec.(Call).getFunc().(Attribute).getName() = "route"` verified to match all four handlers). **Action:** add put_file/head_file/get_file `path` parameters (xhu.py:105/:190/:215) to `MySources.qll` (pass 1), or re-run extraction with the fixed predicate. Without this, `Pass1_PathTraversal.ql` produces zero alerts.
2. **Phase-2 flow-modeling risks** (checked, not blockers): stdlib boundaries the taint query must cross — `pathlib.Path(arg0) -> result` (covered by the sink-009/sink-010 summary edge), `Path.parent` (sink-023 receiver; no candidate row exists — add a manual summary in `MySummaries.qll` if the pass query misses the mkdir flow), `str(data_file)` at :228, and the `@contextlib.contextmanager` generator `write_file` invoked at :141 (sink-018 review note).
3. **Exploitability scoping (recorded, no action):** read-side traversal is limited to `*.data`/`*.meta` file names; PUT-side traversal requires an HMAC over the exact traversal path; `mkdir` is not suffix-constrained. These constraints are stated in the sink rationales so Step-6 triage does not over- or under-report.
4. **Lowest-confidence labels:** sink-020 (`unlink`, 0.65 — error-path only) and sink-026 (`stat`, 0.65 — metadata oracle, not content read). Both are genuine filesystem accesses on unconfined paths; confirm the project wants them as alert points (recommended: keep, severity low).

## 7. Phase 2 hand-off summary

- `MySources.qll` (pass 1): the 4 labeled request sources **plus the route-param modeling from §6.1**.
- `MySinks.qll` (pass 1): 7 entries — `flask.send_file` (arg 0), `pathlib.Path.open` (receiver; call sites :57/:76/:144), `.unlink` (receiver), `.mkdir` (receiver), `.stat` (receiver).
- `MySanitizers.qll`: empty — keep the `isBarrier` predicate with `none()` fallback; do **not** model `sanitized_join`/`startswith` as barriers.
- `MySummaries.qll`: 8 entries — `sanitized_join` arg0→return, `get_info` param0→returns, `get_paths` param0→returns, `pathlib.Path` arg0→result, `Path.__truediv__` right-operand→result.

## 8. Independence statement

No PyVul ground truth, CVE advisories, fix commits or patch diffs were consulted. The pre-existing audit artifacts in the source-tree root (`VULNERABILITY_AUDIT_REPORT.md`, `path_traversal_sinks.csv`, `漏洞审查报告.md`, `第一步筛选报告.md`) were **not opened** (only listed, to be explicitly avoided). Labeling relied on `xhu.py`, `setup.py`, `config.example.py`, the Phase-1 CSVs and `exploration/detection.json`, and the Augur references (`WORKFLOW.md`, `references/patterns.md`, `references/python.md`, `references/flask.md`, `assets/labels_schema.json`). Read-only diagnostics (`codeql query run` + `bqrs decode`, CLI 2.25.1) were run to verify the §6.1 root cause; no source, database, Augur file, or Phase-1 CSV was modified.

**Status: Phase 1 Step 3 complete; stopping here per the task contract — Phase 2 is not started.**
