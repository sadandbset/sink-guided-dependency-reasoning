# Label Statistics - Pass 1 (Path Traversal)

- Project: starlette 0.26.1 (`starlette_vuln` source tree)
- Language: python; Framework: starlette (the audit target IS the framework)
- Labeling model: **glm-5.3** (Claude Code CLI agent session, 2026-10-23, single session, no external LLM API calls, no temperature sampling)
- Run id: `starlette-pathtraversal-pass1-step3-20261023`
- Generated: 2026-10-23T12:33:36+00:00

## Row accounting

| Input | Rows |
| --- | --- |
| extraction/sources.csv | 142 |
| extraction/sinks.csv | 47 |
| **total candidate rows** | **189** |
| unique label entries | 189 |

Dedupe: 0 duplicate candidate nodes. Cross-CSV key check `(file, line, callable, arg_index)` found no overlap - the apparent `staticfiles.py:113` overlap is two DIFFERENT parameters (scope arg 2 in sources.csv vs path arg 1 in sinks.csv), so both rows were labeled separately. Within-CSV duplicates: 0 in sources.csv, 0 in sinks.csv.

## Batches (module-grouped, processed sequentially in one session)

| # | Scope | source rows | sink rows |
| --- | --- | --- | --- |
| 1 | starlette/staticfiles.py + starlette/responses.py (StaticFiles serving pipeline and FileResponse) | 14 | 26 |
| 2 | starlette/config.py + starlette/templating.py (env-file read, jinja2 template loading) | 2 | 10 |
| 3 | starlette/formparsers.py + starlette/datastructures.py (multipart/form parsing, UploadFile) | 25 | 11 |
| 4 | starlette/routing.py (Router, Route/WebSocketRoute/Mount/Host matching and dispatch) | 36 | 0 |
| 5 | starlette/requests.py + starlette/endpoints.py + starlette/websockets.py (request/websocket objects and endpoints) | 32 | 0 |
| 6 | starlette/middleware/* (base, cors, errors, exceptions, gzip, trustedhost, wsgi) | 29 | 0 |
| 7 | starlette/applications.py + starlette/testclient.py (Starlette app entry, test client) | 4 | 0 |
| | **total** | **142** | **47** |

## Label counts by role

| role | count |
| --- | --- |
| source | 138 |
| sink | 19 |
| sanitizer | 1 |
| summary | 10 |
| none | 21 |

## Label counts by classification

| classification | count |
| --- | --- |
| tp | 147 |
| fp | 32 |
| candidate | 10 |
| unknown | 0 |

Classification semantics used here: `tp` = the candidate genuinely plays the labeled role in an attacker-reachable flow (for sources: genuinely attacker-controlled boundary value, with provenance verified in code); `fp` = the candidate was extracted but does not play the role in any attacker-reachable flow in this codebase (operator input, response direction, test machinery, auto-named temp files, fixed literals); `candidate` = cannot be fully confirmed either way from this tree (human review point); `unknown` = none.

## Confidence distribution

| band | count |
| --- | --- |
| high (>=0.8) | 175 |
| medium (0.55-0.79) | 13 |
| low (<0.55) | 1 |

Low-confidence entries (below the 0.55 re-ask threshold):

- p1-k-037 starlette/staticfiles.py:172 (sanitizer/candidate, conf 0.45)

No external LLM re-asks were performed (single labeling session); the sub-threshold entry was resolved by a second direct source-reading pass instead.

## Entries by module and role

| module | source | sink | sanitizer | summary | none |
| --- | --- | --- | --- | --- | --- |
| applications.py | 1 | 0 | 0 | 0 | 0 |
| base.py | 1 | 0 | 0 | 0 | 0 |
| config.py | 0 | 4 | 0 | 0 | 1 |
| cors.py | 8 | 0 | 0 | 0 | 0 |
| datastructures.py | 8 | 0 | 0 | 0 | 8 |
| endpoints.py | 11 | 0 | 0 | 0 | 0 |
| errors.py | 4 | 0 | 0 | 0 | 0 |
| exceptions.py | 3 | 0 | 0 | 0 | 0 |
| formparsers.py | 17 | 0 | 0 | 0 | 3 |
| gzip.py | 3 | 0 | 0 | 0 | 1 |
| requests.py | 17 | 0 | 0 | 0 | 0 |
| responses.py | 3 | 3 | 0 | 0 | 1 |
| routing.py | 35 | 0 | 0 | 0 | 1 |
| staticfiles.py | 13 | 6 | 1 | 10 | 3 |
| templating.py | 1 | 6 | 0 | 0 | 0 |
| testclient.py | 0 | 0 | 0 | 0 | 3 |
| trustedhost.py | 2 | 0 | 0 | 0 | 0 |
| websockets.py | 4 | 0 | 0 | 0 | 0 |
| wsgi.py | 7 | 0 | 0 | 0 | 0 |

## Exclusion and none/fp rationale summary

- tests/ (32 files) and starlette-db/ were already excluded at extraction (Step 2).
- `starlette/testclient.py` rows (3): test machinery - the TestClient builds the ASGI scope from test code; labeled none/fp (review point 9). The unquote rows double as evidence that `scope['path']` is the percent-decoded request path.
- `starlette/config.py:16` os.environ: operator/local-process trust level; Config values are config lookups, never file paths (review point 1).
- `starlette/routing.py:668` lifespan scope: application lifecycle events, not request data.
- `starlette/middleware/gzip.py:86` Content-Length: response-direction header write/delete.
- UploadFile write/read/seek/close + SpooledTemporaryFile (11 entries): auto-named temp file, attacker controls content only, never the path (review point 3).
- config.py file APIs (4 entries): real file read, but the path is the operator-configured `env_file` (review points 1/8).
- staticfiles.py bootstrap checks (isdir/isfile/stat on self.directory, package dirs): operator input, construction/first-request time.
- staticfiles.py:150/154 ('404.html'): fixed filename mapping (review point 5).

## CSV flowKind -> schema signature.flow_kind mapping

| CSV flowKind / node shape | schema flow_kind | arg_index |
| --- | --- | --- |
| `param` (function parameters) | `param` | CSV argIndex |
| container subscript/attribute reads (`http_path`, `http_request`, `http_header` subscripts, `multipart_field`/`multipart_filename` subscripts, `env`) | `field` | null |
| call results (`url_decode`, `route_var` get/groupdict/pop, `http_header` get/getlist, `http_wire` receive/message.get, `parse_options_header`) | `return` | null |
| `UploadFile()` constructor (multipart filename field) | `field` | null |
| file-object method calls (write/read/seek/close) | `receiver` | null |
| wrapper calls without a path argument (run_in_threadpool, SpooledTemporaryFile) | `unknown` | null |
| sink call-site path arguments (open, stat, join, run_sync, FileResponse ctor, ...) | `argument` | CSV argIndex (dangerous path argument index) |
| sink definition-side params (`file_api_def`) | `param` | CSV argIndex |

