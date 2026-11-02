# Phase 1 Review - Pass 1 (Path Traversal) - starlette

Human review gate summary (Augur WORKFLOW.md 4.5). This checkpoint ends Phase 1; Phase 2 (library generation, taint queries) was NOT started.

## 1. Label counts by pass and role

| role | count |
| --- | --- |
| source | 138 |
| sink | 19 |
| sanitizer | 1 |
| summary | 10 |
| none | 21 |

Total unique entries: 189 (from 189 candidate rows: 142 sources.csv + 47 sinks.csv, 0 duplicates). Classifications: tp 147, fp 32, candidate 10, unknown 0. Model: glm-5.3, 7 module-grouped batches, labels.json validated locally against assets/labels_schema.json.

## 2. Top high-risk sink APIs (sink/tp)

- **p1-k-016** `__init__` at starlette/responses.py:288 - arg_index 1, confidence 0.85
- **p1-k-017** `run_sync` at starlette/responses.py:335 - arg_index 1, confidence 0.80
- **p1-k-018** `open_file` at starlette/responses.py:353 - arg_index 0, confidence 0.95
- **p1-k-038** `stat` at starlette/staticfiles.py:177 - arg_index 0, confidence 0.85
- **p1-k-040** `FileResponse` at starlette/staticfiles.py:192 - arg_index 0, confidence 0.90

These five form the serving chain of the only complete untrusted-source-to-file-API flow in this tree: `scope['path']` (source, staticfiles.py:111) -> get_path normpath/join -> get_response -> run_sync(lookup_path) -> os.path.join(directory, path) -> realpath -> commonprefix check -> os.stat -> FileResponse(full_path) -> re-stat -> **anyio.open_file(self.path, mode='rb')** (responses.py:353).

## 3. Top broad source APIs

- `scope['path']` subscript reads (http_path family, 11 entries) - the request path; primary: starlette/staticfiles.py:111 (confidence 0.97).
- ASGI entry-point `scope` parameters (35 entries, confidence 0.90) - externally reachable, carry all HTTP input; broad by design for conservative recall.
- `match.groupdict()` / `matched_params.pop('path')` / `scope.get('path_params')` (route_var family, 9 entries) - routed path variables that applications may feed into file APIs.
- multipart filename chain (formparsers.py:194/206/209 + decode boundaries) - genuinely attacker-controlled, but NO in-tree path sink (incomplete flow, review point 10).
- Header/wire/query/method reads (~40 entries) - genuine untrusted input with low direct pass-1 relevance (kept for recall).

## 4. Sanitizer list

- **p1-k-037** `os.path.commonprefix` at starlette/staticfiles.py:172 - candidate, confidence 0.45

The only sanitizer-shaped candidate. Verdict: **partial, not reliable** in this specific implementation (review point 6 - cannot be accepted by function name):

1. `os.path.commonprefix` is a pure CHARACTER-prefix comparison, not path-component-aware: a sibling directory sharing a textual prefix (base `/static` vs sibling `/static-evil`, request `../static-evil/x`) passes `commonprefix([full_path, directory]) == directory` and escapes the declared root (staticfiles.py:170-175).
2. The guard is not applied AT ALL on the `follow_symlink=True` branch (staticfiles.py:167-168 uses `abspath` only) - with that opt-in option the request path is never containment-checked before stat/open.
3. TOCTOU: check at staticfiles.py:170-177 vs re-stat/open in FileResponse.__call__ (responses.py:335/353, executed later in a thread) - a symlink swap between check and use escapes the root.

Phase 2 recommendation: do NOT emit this as a hard `isBarrier` (it would also suppress the genuine bypass flow); keep it documented, or restrict modeling to the default follow_symlink=False branch. **Human review required.**

`normpath` in get_path (staticfiles.py:111) is deliberately NOT labeled a sanitizer: it collapses `..`/`.` components but the collapsed result can remain an upward-relative path (`a/../..` -> `..`) that escapes when joined onto the base; it is labeled summary (taint-preserving). Similarly `realpath`/`abspath` are taint-preserving summaries, not barriers.

## 5. Summary (flow-step) entries

- p1-s-116 `get_path` at starlette/staticfiles.py:106 (tp/summary, conf 0.90)
- p1-k-024 `normpath` at starlette/staticfiles.py:111 (tp/summary, conf 0.80)
- p1-k-025 `join` at starlette/staticfiles.py:111 (tp/summary, conf 0.85)
- p1-k-027 `run_sync` at starlette/staticfiles.py:121 (tp/summary, conf 0.90)
- p1-k-028 `join` at starlette/staticfiles.py:136 (tp/summary, conf 0.80)
- p1-k-029 `run_sync` at starlette/staticfiles.py:137 (tp/summary, conf 0.85)
- p1-k-030 `run_sync` at starlette/staticfiles.py:150 (fp/summary, conf 0.80)
- p1-k-033 `join` at starlette/staticfiles.py:166 (tp/summary, conf 0.85)
- p1-k-034 `abspath` at starlette/staticfiles.py:168 (tp/summary, conf 0.75)
- p1-k-035 `realpath` at starlette/staticfiles.py:170 (tp/summary, conf 0.80)

These model the propagation CodeQL cannot follow automatically: the starred `os.path.join(*scope['path'].split('/'))` unpack, join/normpath/realpath/abspath transforms, and the `anyio.to_thread.run_sync(callback, arg)` thread offload (argument 1 -> callback parameter, callback return -> run_sync return).

## 6. Unresolved / low-confidence items (human review points)

- **p1-s-013** starlette/datastructures.py:34 - role source, candidate, conf 0.55 - root_path / app_root_path read: server- and mount-derived value, only indirectly request-influenced (Mount.matches builds root_path from matched_path, routing.py:398-402); trust level uncertain - not clearly attacker-controlled, kept as candidate for human review (review point 1).
- **p1-s-061** starlette/requests.py:105 - role source, candidate, conf 0.55 - root_path / app_root_path read: server- and mount-derived value, only indirectly request-influenced (Mount.matches builds root_path from matched_path, routing.py:398-402); trust level uncertain - not clearly attacker-controlled, kept as candidate for human review (review point 1).
- **p1-s-101** starlette/routing.py:398 - role source, candidate, conf 0.55 - root_path / app_root_path read: server- and mount-derived value, only indirectly request-influenced (Mount.matches builds root_path from matched_path, routing.py:398-402); trust level uncertain - not clearly attacker-controlled, kept as candidate for human review (review point 1).
- **p1-s-138** starlette/middleware/wsgi.py:24 - role source, candidate, conf 0.55 - root_path / app_root_path read: server- and mount-derived value, only indirectly request-influenced (Mount.matches builds root_path from matched_path, routing.py:398-402); trust level uncertain - not clearly attacker-controlled, kept as candidate for human review (review point 1).
- **p1-k-037** starlette/staticfiles.py:172 - role sanitizer, candidate, conf 0.45 - THE base-directory containment guard on the default (follow_symlink=False) branch: realpath(joined_path) then os.path.commonprefix([full_path, directory]) != directory -> skip the directory (staticfiles.py:170-175)
- **p1-k-039** starlette/staticfiles.py:184 - role source, candidate, conf 0.60 - full_path parameter of file_response: the post-containment-check resolved path
- **p1-k-044** starlette/templating.py:93 - role sink, candidate, conf 0.55 - Template-name-to-file-load boundary: env.get_template(name) loads a template file by joining the name onto the loader directory (inside jinja2, outside the database)
- **p1-k-045** starlette/templating.py:94 - role sink, candidate, conf 0.55 - Template-name-to-file-load boundary: env.get_template(name) loads a template file by joining the name onto the loader directory (inside jinja2, outside the database)
- **p1-k-046** starlette/templating.py:98 - role sink, candidate, conf 0.55 - Template-name-to-file-load boundary: env.get_template(name) loads a template file by joining the name onto the loader directory (inside jinja2, outside the database)
- **p1-k-047** starlette/templating.py:112 - role sink, candidate, conf 0.55 - Template-name-to-file-load boundary: env.get_template(name) loads a template file by joining the name onto the loader directory (inside jinja2, outside the database)

Plus the sub-threshold sanitizer entry p1-k-037 (commonprefix at starlette/staticfiles.py:172, conf 0.45) analyzed in section 4.

## 7. Review-question triage (task points 1-10)

1. **Source trust**: only genuine untrusted boundaries were labeled source/tp: ASGI scope reads (path/method/headers/query/path_params), the ASGI scope parameters of externally reachable entry points, multipart Content-Disposition filename, wire messages, decode boundaries. Internal function parameters were NOT auto-labeled: staticfiles get_path scope -> summary; get_response/lookup_path path params -> secondary source with documented provenance; root_path reads -> candidate (uncertain trust). os.environ, lifespan scope, test client -> none/fp.
2. **Traceability**: every step of the StaticFiles flow was verified in real code (staticfiles.py:102->111->121->166->170-177->192; responses.py:335/353); decode position (server-side, single) verified via testclient.py:240/258; thread indirection needs summary steps (run_sync).
3. **Sink reality**: only actual file access was labeled sink/tp: anyio.open_file (responses.py:353), os.stat (staticfiles.py:177, responses.py:335), FileResponse construction/init (staticfiles.py:192, responses.py:288). join/normpath/realpath/abspath are summaries, not sinks; UploadFile ops/SpooledTemporaryFile/file.read are none (auto-named file / receiver-only).
4. **Escape potential**: `../` is collapsed by normpath but survives as upward-relative path; the containment is the flawed commonprefix (sibling-prefix bypass, review section 4); absolute paths cannot survive the '/'-split + join('') - a leading '/' becomes an empty component; Windows backslash components survive the '/'-split as one component and normpath converts separators (mixed-separator concern recorded in detection.json); single percent-decode only (no double-decode boundary in-tree).
5. **Root containment**: real check exists ONLY on the follow_symlink=False default branch (realpath + commonprefix, staticfiles.py:170-175) and it is character-prefix based (bypassable); fixed filename mappings exist for 'index.html'/'404.html'; no relative_to()/component-aware check anywhere.
6. **Sanitizer effectiveness**: normpath/realpath/abspath do not block escape here (taint-preserving; labeled summary); commonprefix is partial (labeled sanitizer/candidate 0.45). No basename/startswith/blacklist guards exist in the tree.
7. **Symlinks**: follow_symlink defaults False (realpath branch); True branch skips the containment check entirely (staticfiles.py:167-168); TOCTOU window between check and open (responses.py:353). All three recorded as evidence.
8. **Authorized access**: StaticFiles serving is the intended function; the file_response full_path param is labeled candidate precisely because under default config with non-colliding directories it is the operator-chosen in-root file. The vulnerability interest is the bypass paths, not the normal serving.
9. **Tests/constants/generated code**: tests/ and starlette-db/ excluded at extraction; testclient.py rows labeled none/fp; fixed literals ('index.html', '404.html') -> fp; operator config (Config env_file, packages, Jinja2Templates directory) -> fp.
10. **Complete flow vs partial**: one COMPLETE untrusted-source-to-file-API flow exists (scope['path'] -> anyio.open_file via StaticFiles/lookup_path). Partial/local flows: multipart filename (no in-tree sink), WSGI PATH_INFO (sink outside tree), template names (sink inside jinja2, outside DB) - all flagged accordingly.

## 8. Decision

Output artifacts: labels/labels.json (schema-valid), labels/labels_raw_pass1.json, labels/label_stats.md, labels/phase1_review.md. Stopping here per the task contract - no Phase 2 work (MySources/MySinks/MySanitizers/MySummaries generation, taint query execution) was started.

