# Phase 1 Step 3 Review — LLM Candidate Labeling (Pass 1: Path Traversal)

Project: aiohttp 4.0.0a2.dev0 (`aiohttp_vuln` source tree)
Pass: 1 (CWE-022 / CWE-023 / CWE-036 / CWE-073, Path Traversal)
Model: glm-5.3 (Claude Code CLI agent, single session, no external LLM API calls)
Generated: 2026-10-21
Artifacts: `labels/labels.json` (schema-VALID against `augur-0.3.0/assets/labels_schema.json`, jsonschema 4.26.0 Draft 2020-12), `labels/labels_raw_pass1.json`, `labels/label_stats.md`

---

## 1. Label counts by pass and role

Candidates processed: **108 source rows + 85 sink rows = 193** (all rows from Phase 1 Step 2 CSVs; programmatic coverage assertion: every row matched exactly one decision, no row skipped, none invented). Deduplication: **0 exact duplicate (file, line, callable, node) pairs**; same-line pairs such as `request.headers.get` + `request.headers` are distinct AST node shapes and were retained separately. Exclusions: 135 rows labeled `none/fp` with a per-row exclusion basis recorded in `labels_raw_pass1.json`.

| role | tp | candidate | fp | total |
| --- | --- | --- | --- | --- |
| source | 21 | 6 | 77 (as none) | 108 |
| sink | 9 | 6 | 2 (+58 as none) | 85 |
| sanitizer | 3 | 1 | 0 | 4 |
| summary | 5 | 5 | 0 | 10 |
| **non-none total** | **38** | **18** | **2** | **58** |

Labeling was done in 6 file-group batches (B1 static-resource core 74 rows, B2 request/multipart/wire 23, B3 routing/middleware/response 33, B4 client-side file persistence 24, B5 build & dev tooling 24, B6 examples 15), each batch verified against the real source at the candidate's file:line.

## 2. Top high-risk sink APIs (request-reachable)

The single concentrated attack surface is the static-file pipeline. End-to-end verified flow (every step read in the real code):

```
socket bytes (web_protocol.py:358 data_received)
  -> http_parser.py:556 request-line split -> URL.build (http_parser.py:589)
  -> request.rel_url.raw_path            [SOURCE, web_urldispatcher.py:616]
  -> _unquote_path(remainder)            [DECODE, web_urldispatcher.py:625 — exactly ONE percent-decode]
  -> match_info['filename']              [SOURCE, web_urldispatcher.py:635 — attacker controls the full post-prefix remainder]
  -> Path(rel_url)                       [web_urldispatcher.py:637]
  -> self._directory.joinpath(filename)  [web_urldispatcher.py:643 — tainted arg joins the base dir]
  -> .resolve()                          [web_urldispatcher.py:643 — canonicalization BEFORE the guard]
  -> filename.anchor check               [GUARD, :638 — HTTPForbidden on drive/UNC anchors]
  -> filepath.relative_to(self._directory) [GUARD, :645 — ValueError -> HTTPNotFound; default follow_symlinks=False]
  -> is_dir / is_file                    [SINK, :657/:667]
  -> FileResponse(filepath)              [SINK, :668]
  -> stat / .gz-sibling stat             [SINK, web_fileresponse.py:141/:136]
  -> filepath.open('rb')                 [SINK, web_fileresponse.py:288 — via run_in_executor]
  -> loop.sendfile / chunked read        [SINK, web_fileresponse.py:93]
  -> iterdir (show_index only)           [SINK, web_urldispatcher.py:683]
```

Highest-confidence sinks: `web_fileresponse.py:288 filepath.open` (0.90), `web_urldispatcher.py:668 FileResponse(filepath)` (0.90), `web_fileresponse.py:46 FileResponse.__init__ path` param (0.85), `web_fileresponse.py:141 stat` (0.85), `web_urldispatcher.py:683 iterdir` (0.75).

## 3. Top source APIs (broad)

- `request.match_info['filename']` (web_urldispatcher.py:635, conf 0.95) — **the** routed filename; attacker controls the entire URL remainder after the static prefix, after exactly one percent-decode (`%2f`→`/`, `%2e%2e`→`..` become literal at this point).
- `request.rel_url.raw_path` chains (web_urldispatcher.py:616/:997, web_middlewares.py:86-109, conf 0.8-0.9) — raw request path in router and path-normalization middleware.
- `line.split(' ', maxsplit=2)` request-line path (http_parser.py:556, conf 0.9) — the wire entry, feeding `URL.build`.
- Multipart filename family (multipart.py:532/:541/:552/:553, web_request.py:724/:745, conf 0.7-0.9) — Content-Disposition `filename` of uploads.
- Lower-tier candidates (kept for review, not confirmed): raw wire/body params (`feed_data`, `data_received`, conf 0.45-0.6) and the NETRC env read (helpers.py:197, conf 0.55).

## 4. Sanitizer list

| sanitizer | location | verdict |
| --- | --- | --- |
| `filepath.relative_to(self._directory)` after `.joinpath(filename).resolve()` | web_urldispatcher.py:643-645 | **tp, 0.90** — canonicalize-then-contain; raises `ValueError`→`HTTPNotFound` when the resolved path escapes the base; enforced before any file access; active in the default configuration (`follow_symlinks=False`) |
| `if filename.anchor: raise HTTPForbidden` | web_urldispatcher.py:638 | **tp, 0.80** — rejects drive/UNC-anchored request filenames (`D:\path`, `\\machine\c$`) before the join; incomplete alone (empty anchor for relative `../`), sound in combination with resolve+relative_to |
| `Path(name).name` (guess_filename) | helpers.py:360 | **tp, 0.85** — basename-only extraction; strips all directory components from the client-supplied upload filename guess |
| url_for containment `relative_to` | web_urldispatcher.py:579 | candidate, 0.55 — same guard shape on the application-input (url_for) path, not request data |

Deliberately **not** labeled sanitizer: `resolve()` at web_urldispatcher.py:643 (labeled summary/tp) — it canonicalizes (which *enables* the containment guard) but preserves taint; a barrier there would incorrectly sever the source→sink flow. Likewise `os.path.expanduser` (web_urldispatcher.py:536) is applied only to the operator-configured base directory, never to the request filename (negative evidence: `~/` cannot be expanded via a request).

## 5. Resolved / low-confidence items (human-review queue, 18 entries)

1. **NETRC env → netrc read** (helpers.py:197 source + :218 sink, conf 0.55) — CWE-73 shape, but requires local env control; operator trust. Recommend confirm as out-of-remote-threat-model or keep as candidate signature.
2. **CookieJar.save/load + open** (cookiejar.py:105/107/110/112, conf 0.6) — genuine file read/write APIs with path params; in-tree paths are operator config. Note `pickle.load` inside `load()` is pass-6 material.
3. **Wire/body param sources** (http_parser.py:288/786/935, web_protocol.py:358, conf 0.45-0.6) — genuine network boundaries but noisy as pass-1 source anchors; recommend promoting only the request-line split (already tp).
4. **Summary-step candidates**: `request.clone(rel_url=path)` re-binding in normalize_path_middleware (web_middlewares.py:22), `Path(rel_url)` (web_urldispatcher.py:637 is tp; helpers.py:200 env variant 0.5), `with_name` .gz-sibling derivation (web_fileresponse.py:134), url_for `joinpath` (web_urldispatcher.py:577), `StaticResource._handle` request-carrier (web_urldispatcher.py:634).
5. **create_unix_server** (web_runner.py:156, conf 0.5) — genuine fs-object creation at arg 1; operator config in-tree.

No `unknown` classifications were needed: every candidate could be decided from the source code.

## 6. Explicit answers to the review checklist

1. **Real untrusted sources?** Yes — `match_info['filename']`, `rel_url.raw_path`, request-line path, multipart Content-Disposition filename are genuine request-boundary values. 77 source rows were rejected: internal `request`-carrier params (not automatic sources), headers/cookies with no path consumer, CLI argv (operator-local), boolean env flags, example echo handlers.
2. **Path from URL decode/normalize/join to file API traceable?** Yes — the full chain in §2 was verified line-by-line: one percent-decode (:625), `Path()` (:637), `joinpath` (:643), `resolve()` (:643), then stat/open/sendfile in FileResponse.
3. **Sinks are real file access?** Yes — open (:288), stat (:141/:136), sendfile (:93), iterdir (:683), FileResponse ctor. `Path()`, `joinpath`, `with_name`, and string handling alone were NOT counted as sinks (labeled summary/none); DNS `resolve` name-collision rows and pre-opened file-object reads were rejected.
4. **Can `../`/absolute/drive/double-decode escape the base?** By construction the attacker can *supply* all of these (single decode turns `%2e%2e%2f` into `../`; backslashes are separators on Windows). Whether they escape is decided by the guard chain — see §7. Double-decode is impossible: exactly one `_unquote_path` pass exists between wire and filename (verified).
5. **Real containment executed before file access?** Yes — anchor check (:638) + resolve+`relative_to` (:643-645) run before is_dir/is_file/FileResponse. With `follow_symlinks=False` (the default) this is a sound canonicalize-then-contain.
6. **Do the named sanitizers actually block?** `relative_to` after full `resolve()`: yes (both sides canonical; `..` collapsed; ValueError on escape). `anchor`: yes for drive/UNC forms only. `resolve()` alone: not a sanitizer (taint-preserving). Blacklists/`startswith`: none present (and `startswith` guards are absent from this pipeline entirely).
7. **Symlinks / TOCTOU?** `follow_symlinks=True` (non-default operator opt-in) disables the containment check entirely — documented residual-risk configuration. A TOCTOU window exists between the :645 check and FileResponse's re-stat (:141) / re-open (:288); a symlink swap in the served directory within that window could bypass containment — recorded as an evidence note, not separately labelable. No symlink-following issue under the default configuration.
8. **Authorized file serving ≠ vulnerability?** Correct — the static-route feature is intentional authorized access; the labels record the pipeline as *guarded by default*, and no finding claims the default configuration is traversable.
9. **Tests / constants / unreachable code?** `tests/` was already excluded at extraction; examples/tools rows were retained per the extraction contract and labeled `none/fp` (literal `__file__`-derived paths, argv[0], fixed repo dirs). No database-directory generated files were encountered.
10. **Complete untrusted-source→dangerous-path flow vs local wrapper flow?** The complete flow exists (§2) — source (match_info['filename']) to real file APIs. The url_for branch (:577-588) is the local/application-input variant and was labeled accordingly (sink/fp with the trust difference documented). The multipart filename is a source with **no in-tree path sink** (content goes to an auto-named `TemporaryFile`, web_request.py:726) — its risk is deferred to downstream applications.

## 7. Overall pass-1 assessment (for Phase 2 planning)

The static-file pipeline implements the textbook defense (canonicalize-then-contain) in its default configuration. Residual items worth Phase-2 attention:

- `follow_symlinks=True` opt-out disables containment (operator decision, not a default vuln).
- TOCTOU between the containment check and FileResponse's re-stat/re-open.
- Multipart `FileField.filename` as an exported untrusted value (downstream-app recall).
- NETRC env path and CookieJar path params as CWE-73-shaped signatures (local trust).

The generated query (Phase 2) should anchor sources at the `match_info`/`raw_path`/request-line/multipart-filename nodes, sinks at the FileResponse/stat/open/sendfile/iterdir nodes, model `_unquote_path`, `Path()`, `joinpath`, `resolve`, and `request.clone(rel_url=...)` as taint steps (MySummaries), and use the `relative_to` containment + `anchor` guard as barriers (MySanitizers) — the anchor guard and the default-config relative_to check are the tp sanitizers to wire into `isBarrier`.

**Status: Step 3 complete. Stopping here per task contract — Phase 2 (Step 4 library generation) is NOT started.**

Constraints honored: no PyVul ground truth (`VULNERABILITY_AUDIT_REPORT.md`, `path_traversal_sinks.csv`), no patch diffs, no CVE advisories consulted; source tree, CodeQL database, Augur installation, and Phase 1 CSVs unmodified; outputs written only under `iris/labels/` (plus the labeling driver script `build_labels_pass1.py` in the workspace root for reproducibility).
