# Pass 1 (Path Traversal) Label Statistics

- Project: aiohttp 4.0.0a2.dev0 (`aiohttp_vuln` tree)
- Model: glm-5.3 (Claude Code CLI agent, single session, no external LLM API)
- Generated: 2026-10-21T09:11:14.714881+00:00
- Candidates: 108 source rows + 85 sink rows = 193 total; all labeled, 0 skipped, 0 exact duplicates

## Role x classification (combined)

| role | classification | count |
| --- | --- | --- |
| none | fp | 135 |
| sanitizer | candidate | 1 |
| sanitizer | tp | 3 |
| sink | candidate | 6 |
| sink | fp | 2 |
| sink | tp | 9 |
| source | candidate | 6 |
| source | tp | 21 |
| summary | candidate | 5 |
| summary | tp | 5 |

## Source candidates (108 rows)

| role | classification | count |
| --- | --- | --- |
| none | fp | 77 |
| source | candidate | 6 |
| source | tp | 21 |
| summary | candidate | 2 |
| summary | tp | 2 |

## Sink candidates (85 rows)

| role | classification | count |
| --- | --- | --- |
| none | fp | 58 |
| sanitizer | candidate | 1 |
| sanitizer | tp | 3 |
| sink | candidate | 6 |
| sink | fp | 2 |
| sink | tp | 9 |
| summary | candidate | 3 |
| summary | tp | 3 |

## Batches

| batch | description | source rows | sink rows |
| --- | --- | --- | --- |
| B1 | Static-resource core (web_urldispatcher.py, web_fileresponse.py) | 34 | 40 |
| B2 | Request / multipart / wire input (web_request.py, multipart.py, http_parser.py, web_protocol.py) | 22 | 1 |
| B3 | Routing / middleware / response plumbing (web_app.py, web_middlewares.py, web_response.py, web_ws.py, web_log.py, web.py, web_runner.py) | 29 | 4 |
| B4 | Client-side file persistence (cookiejar.py, helpers.py, payload.py, connector.py) | 6 | 18 |
| B5 | Build & dev tooling (setup.py, tools/*, requirements/*) | 6 | 18 |
| B6 | Examples (examples/*) | 11 | 4 |

## Confirmed entries (role != none)

- `p1-src-009` source/candidate conf=0.55 — helpers.py:197 get
- `p1-src-010` source/candidate conf=0.55 — helpers.py:197 environ
- `p1-src-012` source/candidate conf=0.60 — http_parser.py:288 feed_data
- `p1-src-013` source/tp conf=0.90 — http_parser.py:556 split
- `p1-src-016` source/candidate conf=0.55 — http_parser.py:786 feed_data
- `p1-src-017` source/candidate conf=0.45 — http_parser.py:935 feed_data
- `p1-src-018` source/tp conf=0.85 — multipart.py:532 content_disposition_filename
- `p1-src-019` source/tp conf=0.90 — multipart.py:541 content_disposition_filename
- `p1-src-020` source/tp conf=0.70 — multipart.py:552 filename
- `p1-src-021` source/tp conf=0.70 — multipart.py:553 filename
- `p1-src-046` summary/candidate conf=0.55 — web_middlewares.py:22 _check_request_resolves
- `p1-src-049` source/tp conf=0.85 — web_middlewares.py:86 raw_path
- `p1-src-050` source/tp conf=0.85 — web_middlewares.py:87 raw_path
- `p1-src-051` source/tp conf=0.80 — web_middlewares.py:91 raw_path
- `p1-src-052` source/tp conf=0.80 — web_middlewares.py:95 path
- `p1-src-053` source/tp conf=0.80 — web_middlewares.py:97 path
- `p1-src-054` source/tp conf=0.80 — web_middlewares.py:109 raw_path
- `p1-src-058` source/candidate conf=0.60 — web_protocol.py:358 data_received
- `p1-src-066` source/tp conf=0.85 — web_request.py:724 filename
- `p1-src-067` source/tp conf=0.85 — web_request.py:745 filename
- `p1-src-083` source/tp conf=0.80 — web_urldispatcher.py:350 raw_path
- `p1-src-084` source/tp conf=0.80 — web_urldispatcher.py:350 rel_url
- `p1-src-085` summary/tp conf=0.80 — web_urldispatcher.py:472 _unquote_path
- `p1-src-087` source/tp conf=0.90 — web_urldispatcher.py:616 raw_path
- `p1-src-088` source/tp conf=0.90 — web_urldispatcher.py:616 rel_url
- `p1-src-089` summary/tp conf=0.85 — web_urldispatcher.py:625 _unquote_path
- `p1-src-090` summary/candidate conf=0.55 — web_urldispatcher.py:634 _handle
- `p1-src-091` source/tp conf=0.95 — web_urldispatcher.py:635 match_info
- `p1-src-092` source/tp conf=0.90 — web_urldispatcher.py:635 match_info
- `p1-src-101` source/tp conf=0.80 — web_urldispatcher.py:997 raw_path
- `p1-src-102` source/tp conf=0.80 — web_urldispatcher.py:997 rel_url
- `p1-sink-012` sink/candidate conf=0.60 — cookiejar.py:105 save
- `p1-sink-014` sink/candidate conf=0.60 — cookiejar.py:107 open
- `p1-sink-015` sink/candidate conf=0.60 — cookiejar.py:110 load
- `p1-sink-017` sink/candidate conf=0.60 — cookiejar.py:112 open
- `p1-sink-023` summary/candidate conf=0.50 — helpers.py:200 Path
- `p1-sink-025` sink/candidate conf=0.55 — helpers.py:218 netrc
- `p1-sink-027` sanitizer/tp conf=0.85 — helpers.py:360 Path
- `p1-sink-041` sink/tp conf=0.85 — web_fileresponse.py:46 __init__
- `p1-sink-046` sink/tp conf=0.70 — web_fileresponse.py:93 sendfile
- `p1-sink-047` summary/candidate conf=0.50 — web_fileresponse.py:134 with_name
- `p1-sink-048` sink/tp conf=0.70 — web_fileresponse.py:136 stat
- `p1-sink-049` sink/tp conf=0.85 — web_fileresponse.py:141 stat
- `p1-sink-050` sink/tp conf=0.90 — web_fileresponse.py:288 open
- `p1-sink-054` sink/candidate conf=0.50 — web_runner.py:156 create_unix_server
- `p1-sink-062` summary/candidate conf=0.50 — web_urldispatcher.py:577 joinpath
- `p1-sink-063` sanitizer/candidate conf=0.55 — web_urldispatcher.py:579 relative_to
- `p1-sink-064` sink/fp conf=0.60 — web_urldispatcher.py:584 is_file
- `p1-sink-065` sink/fp conf=0.70 — web_urldispatcher.py:587 open
- `p1-sink-067` summary/tp conf=0.70 — web_urldispatcher.py:637 Path
- `p1-sink-068` sanitizer/tp conf=0.80 — web_urldispatcher.py:638 anchor
- `p1-sink-069` summary/tp conf=0.60 — web_urldispatcher.py:643 resolve
- `p1-sink-070` summary/tp conf=0.70 — web_urldispatcher.py:643 joinpath
- `p1-sink-071` sanitizer/tp conf=0.90 — web_urldispatcher.py:645 relative_to
- `p1-sink-072` sink/tp conf=0.70 — web_urldispatcher.py:657 is_dir
- `p1-sink-073` sink/tp conf=0.70 — web_urldispatcher.py:667 is_file
- `p1-sink-074` sink/tp conf=0.90 — web_urldispatcher.py:668 FileResponse
- `p1-sink-077` sink/tp conf=0.75 — web_urldispatcher.py:683 iterdir

## Human-review queue (18 entries: classification candidate/unknown or confidence < 0.55)

- `p1-src-009` source/candidate conf=0.55 — helpers.py:197 get — NETRC environment variable controls a file-read location: netrc_env -> Path(netrc_env) at helpers.py:200 -> netrc.netrc(str(netrc_path)) at helpers.py:218. Genu...
- `p1-src-010` source/candidate conf=0.55 — helpers.py:197 environ — os.environ attribute read backing the NETRC .get() at the same line; same trust analysis as the paired get() row.
- `p1-src-012` source/candidate conf=0.60 — http_parser.py:288 feed_data — feed_data(data) of HttpRequestParser receives the raw request bytes off the socket: the ultimate network input boundary, upstream of the request-line path extra...
- `p1-src-016` source/candidate conf=0.55 — http_parser.py:786 feed_data — HttpPayloadParser.feed_data(chunk): request body bytes, i.e. the carrier of multipart/form-data content whose Content-Disposition carries the untrusted filename...
- `p1-src-017` source/candidate conf=0.45 — http_parser.py:935 feed_data — DeflateBuffer.feed_data(chunk): decompressed body bytes. Same wire-content trust analysis as the payload-parser row, one decompression step deeper; indirect for...
- `p1-src-046` summary/candidate conf=0.55 — web_middlewares.py:22 _check_request_resolves — _check_request_resolves(request, path) re-binds a derived path onto a cloned request (alt_request = request.clone(rel_url=path)) and re-resolves it against the ...
- `p1-src-058` source/candidate conf=0.60 — web_protocol.py:358 data_received — RequestHandler.data_received(data): the raw socket-bytes callback of the server protocol (asyncio BaseProtocol) - the ultimate network boundary feeding the requ...
- `p1-src-090` summary/candidate conf=0.55 — web_urldispatcher.py:634 _handle — StaticResource._handle is the framework handler entry: the injected request carries match_info['filename'] (the source at :635). The precise source is the match...
- `p1-sink-012` sink/candidate conf=0.60 — cookiejar.py:105 save — CookieJar.save(file_path) is a genuine file-write API whose path parameter is opened for writing (file_path.open(mode='wb') at :107) and pickled into. In-tree t...
- `p1-sink-014` sink/candidate conf=0.60 — cookiejar.py:107 open — file_path.open(mode='wb') - the actual cookie-store write. Path parameter of the enclosing save() is operator/application-supplied; kept as a sink signature wit...
- `p1-sink-015` sink/candidate conf=0.60 — cookiejar.py:110 load — CookieJar.load(file_path): file-read API whose path parameter is opened at :112 and pickled back in (pickle.load inside - unsafe deserialization shape, pass 6 m...
- `p1-sink-017` sink/candidate conf=0.60 — cookiejar.py:112 open — file_path.open(mode='rb') - the actual cookie-store read; same trust analysis as CookieJar.load.
- `p1-sink-023` summary/candidate conf=0.50 — helpers.py:200 Path — Path(netrc_env) converts the NETRC environment string into a Path object that is then read by netrc.netrc(str(netrc_path)) at :218. Taint-preserving str->Path c...
- `p1-sink-025` sink/candidate conf=0.55 — helpers.py:218 netrc — netrc.netrc(str(netrc_path)) performs the actual file read of the NETRC-designated path (netrc opens and parses the file). The path is environment-controlled (N...
- `p1-sink-047` summary/candidate conf=0.50 — web_fileresponse.py:134 with_name — filepath.with_name(filepath.name + '.gz') derives the gzip sibling path from the serving path: taint-preserving receiver->result derivation feeding the stat at ...
- `p1-sink-054` sink/candidate conf=0.50 — web_runner.py:156 create_unix_server — loop.create_unix_server(server, self._path) creates a unix listening socket at a filesystem path (arg 1). Genuine filesystem-object-creation API; in-tree the pa...
- `p1-sink-062` summary/candidate conf=0.50 — web_urldispatcher.py:577 joinpath — url_for: joinpath(filename) joins a caller-supplied filename into the base directory - the same shape as the request-side join at :643 but fed by application co...
- `p1-sink-063` sanitizer/candidate conf=0.55 — web_urldispatcher.py:579 relative_to — url_for: filepath.relative_to(self._directory) applies the same canonicalize-then-contain guard as :645, but on the application-supplied url_for path (append_ve...

## Schema validation

- jsonschema 4.26.0 (Draft 2020-12) against `C:\Users\lzh\Desktop\github\PyVul-main\iris_tools\augur-0.3.0\assets\labels_schema.json`: **VALID**
- arg_index bound check: OK (no negative or missing argument indices)
