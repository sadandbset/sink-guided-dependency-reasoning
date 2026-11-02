# Pass 1 Label Statistics (Path Traversal)

- Run: `django-pathtraversal-pass1-step3-20261022`
- Model: glm-5.3 (Claude Code CLI agent session; deterministic batch labeling, no sampling temperature)
- Generated: 2026-10-22T01:59:24.512682+00:00
- Schema: `assets/labels_schema.json` (draft 2020-12) - validated OK

## 1. Candidate intake and dedup

| input | CSV rows | unique candidates |
| --- | --- | --- |
| sources.csv | 225 | 211 |
| sinks.csv   | 588 | 527 |
| **total** | **813** | **738** |

Dedup rule: rows identical in (node, kind, callable, flowKind, receiver, moduleHint, argIndex, file, line) but differing only in `matchKind` (ast/api double-match of the same call node) were merged; 5 exact ast/ast duplicate rows per CSV were likewise collapsed. All 738 unique candidates were labeled - no candidate was silently dropped; exclusions are expressed as `role=none / classification=fp` decisions with rationale.

## 2. Label counts

### By role (all 738 entries)

| role | sources | sinks | total |
| --- | --- | --- | --- |
| source | 194 | 0 | 194 |
| sink | 0 | 98 | 98 |
| sanitizer | 0 | 19 | 19 |
| summary | 3 | 24 | 27 |
| none | 14 | 386 | 400 |

### By classification

| classification | count |
| --- | --- |
| tp | 243 |
| candidate | 39 |
| fp | 456 |
| unknown | 0 |

### Confidence distribution

| bucket | count |
| --- | --- |
| >=0.85 | 298 |
| 0.70-0.84 | 402 |
| 0.55-0.69 | 38 |
| <0.55 | 0 |

No entry is below 0.55; per WORKFLOW.md 4.4.4 no re-ask batch was needed. Low-confidence (0.55-0.69) entries are all `classification=candidate` and routed to human review (see phase1_review.md).

## 3. Source candidates by CSV flow family

| flow family | labeled | decision |
| --- | --- | --- |
| cli_param | 3 | none:3 |
| cli_url | 1 | none:1 |
| env | 9 | none:9 |
| http_cookie | 7 | source:7 |
| http_files | 3 | source:3 |
| http_form | 54 | source:54 |
| http_meta | 51 | source:51 |
| http_path | 39 | source:39 |
| http_query | 29 | source:29 |
| http_query_raw | 1 | source:1 |
| http_url_decode | 2 | none:1, summary:1 |
| multipart_filename | 2 | source:1, summary:1 |
| route_param | 8 | source:8 |
| session_key | 1 | source:1 |
| upload_name | 1 | summary:1 |

- Kept as **source/tp (195)**: request.path/path_info (39), request.META (51), request.GET (29), request.POST (54), request.FILES (3), request.COOKIES (7), WSGI environ extraction (1), route params (6: static serve, staticfiles serve, admindocs x4), multipart Content-Disposition filename (1), session-key constructor param (1); set_language GET/POST/META rows are counted in the families above.
- Rejected as **none/fp (14)**: 9 `os.environ.get` rows (deployer-controlled env: DJANGO_SETTINGS_MODULE, DJANGO_COLORS, PATH/PATHEXT, PYTHONSTARTUP, RUN_MAIN, COMP_WORDS) and 5 CLI rows (TemplateCommand handle/handle_template/download - operator-invoked django-admin, no remote boundary).
- 3 **summary** rows on the upload-name boundary chain: RFC2231 `unquote` (multipartparser:687), `UploadedFile._set_name` (uploadedfile:39), `FileUploadHandler.new_file` (uploadhandler:93).

## 4. Sanitizers (19 entries)

| id | location | callable | class | conf |
| --- | --- | --- | --- | --- |
| snk-0035 | django/utils/archive.py:167 | target_filename | candidate | 0.60 |
| snk-0046 | django/utils/archive.py:212 | target_filename | candidate | 0.60 |
| snk-0059 | django/template/backends/base.py:77 | safe_join | tp | 0.85 |
| snk-0217 | django/db/models/fields/files.py:308 | validate_file_name | tp | 0.85 |
| snk-0220 | django/template/loaders/filesystem.py:36 | safe_join | tp | 0.85 |
| snk-0223 | django/contrib/staticfiles/finders.py:121 | safe_join | tp | 0.85 |
| snk-0346 | django/http/multipartparser.py:208 | sanitize_file_name | tp | 0.80 |
| snk-0376 | django/views/static.py:36 | safe_join | tp | 0.85 |
| snk-0396 | django/core/files/storage.py:63 | get_valid_filename | tp | 0.80 |
| snk-0398 | django/core/files/storage.py:71 | PurePath | tp | 0.80 |
| snk-0399 | django/core/files/storage.py:73 | validate_file_name | tp | 0.85 |
| snk-0404 | django/core/files/storage.py:106 | PurePath | tp | 0.80 |
| snk-0429 | django/core/files/storage.py:330 | safe_join | tp | 0.85 |
| snk-0490 | django/core/files/uploadedfile.py:43 | basename | tp | 0.75 |
| snk-0492 | django/core/files/uploadedfile.py:51 | validate_file_name | tp | 0.85 |
| snk-0500 | django/core/files/utils.py:9 | basename | tp | 0.80 |
| snk-0501 | django/core/files/utils.py:16 | PurePosixPath | tp | 0.80 |
| snk-0502 | django/core/files/utils.py:21 | basename | tp | 0.80 |
| snk-0511 | django/contrib/admindocs/views.py:332 | safe_join | tp | 0.85 |

Guard families: `safe_join` x6 (static serve, staticfiles finders, storage.path, template loader, template backends base, admindocs); `validate_file_name` x3 (storage get_available_name, uploadedfile._set_name, FileField.generate_filename); `PurePath/PurePosixPath` '..'-part guards x3; `os.path.basename` guards x3; `get_valid_filename`; `sanitize_file_name`; archive `target_filename` x2 (candidate - prefix-check weakness).

Inline guards with no candidate row (documented in rationales / phase1_review.md): session `VALID_KEY_CHARS` subset check, cache-key md5 hexdigest, JavaScriptCatalog package allowlist, `TemplateCommand.validate_name` isidentifier.

## 5. Summary steps (27 entries)

- src-0117 `unquote` django/http/multipartparser.py:687 [tp/0.70]
- src-0192 `_set_name` django/core/files/uploadedfile.py:39 [tp/0.70]
- src-0193 `new_file` django/core/files/uploadhandler.py:93 [tp/0.75]
- snk-0020 `extract` django/utils/archive.py:45 [candidate/0.60]
- snk-0022 `extract` django/utils/archive.py:51 [candidate/0.55]
- snk-0062 `open` django/core/files/base.py:108 [candidate/0.60]
- snk-0143 `fromfile` django/contrib/gis/geos/factory.py:4 [candidate/0.60]
- snk-0154 `join` django/contrib/sessions/backends/file.py:55 [tp/0.80]
- snk-0157 `load` django/contrib/sessions/backends/file.py:75 [candidate/0.60]
- snk-0159 `save` django/contrib/sessions/backends/file.py:111 [candidate/0.60]
- snk-0167 `delete` django/contrib/sessions/backends/file.py:175 [candidate/0.60]
- snk-0205 `_get_file` django/db/models/fields/files.py:41 [candidate/0.60]
- snk-0206 `open` django/db/models/fields/files.py:44 [candidate/0.55]
- snk-0207 `open` django/db/models/fields/files.py:44 [candidate/0.55]
- snk-0208 `path` django/db/models/fields/files.py:58 [candidate/0.60]
- snk-0210 `open` django/db/models/fields/files.py:72 [candidate/0.55]
- snk-0211 `open` django/db/models/fields/files.py:75 [candidate/0.55]
- snk-0212 `open` django/db/models/fields/files.py:75 [candidate/0.55]
- snk-0213 `open` django/db/models/fields/files.py:77 [candidate/0.55]
- snk-0214 `save` django/db/models/fields/files.py:88 [candidate/0.65]
- snk-0215 `delete` django/db/models/fields/files.py:106 [candidate/0.65]
- snk-0222 `find_location` django/contrib/staticfiles/finders.py:111 [tp/0.75]
- snk-0230 `path` django/contrib/staticfiles/finders.py:230 [tp/0.70]
- snk-0329 `attach_file` django/core/mail/message.py:340 [candidate/0.60]
- snk-0373 `serve` django/views/static.py:19 [tp/0.75]
- snk-0516 `find` django/contrib/staticfiles/views.py:33 [tp/0.75]
- snk-0518 `serve` django/contrib/staticfiles/views.py:39 [candidate/0.65]

Two shapes: (a) arg->return path builders needed so route/request taint reaches the file APIs (finders.find, find_location, storage.path call-sites, _key_to_file join); (b) object-field steps where the carried name/key crosses method boundaries (UploadedFile._set_name, new_file, File/FieldFile open/save/delete, session load/save/delete).

## 6. Sinks

- **sink/tp (26 call-site rows):** static serve open+FileResponse (views/static.py:50), admindocs template read (views.py:334), FileSystemStorage open/os.open/makedirs/file_move_safe/rmdir/remove (storage.py), upload move fallback (move.py:48/56/58/80), session file open/os.open/move/unlink (sessions file.py:78/126/164/181), file-cache open/file_move_safe/remove (filebased.py:34/55/63/85/93).
- **sink/candidate (37 entries):** archive extraction writes (utils/archive.py:183/221 + makedirs + archive opens), CLI --template extraction (templates.py:313), template loader/dummy backend reads, mail attach_file read, gis fromfile, File/Image reopen by carried name, ManifestStaticFilesStorage open.
- **sink/fp (56):** real file APIs whose path argument is provably constant/config/CLI-derived (management commands, debug templates, mail file backend, sqlite test DBs, migrations writer, collectstatic, ...).
- All remaining 386 sink candidates are `none/fp`: path utilities (join/normpath/abspath/split/splitext/basename/Path()), metadata checks (exists/isdir/stat/scandir/walk/listdir), permission ops (chmod/utime/copystat/copymode) and pure wrappers - none of them is a file read/write/delete/extract/serve.

## 7. Batches

| batch | description | candidates |
| --- | --- | --- |
| 1 | Source batch 1: request-path / WSGI / route-param boundaries | 48 |
| 2 | Source batch 2: form / query / multipart request data boundaries | 86 |
| 3 | Source batch 3: header (META) and cookie boundaries | 58 |
| 4 | Source batch 4: upload filename, session key, env and CLI param candidates | 19 |
| 5 | Sink batch 5: static-serving flow (views/static, staticfiles views/finders/storage) | 71 |
| 6 | Sink batch 6: admindocs/template loaders/mail/gis/forms/debug and config paths | 97 |
| 7 | Sink batch 7: core/files storage family + FieldFile + multipart/response | 85 |
| 8 | Sink batch 8: session file backend + file-based cache backend | 43 |
| 9 | Sink batch 9: archive extraction + management TemplateCommand (CLI) | 77 |
| 10 | Sink batch 10: remaining management-command / CLI / config sink candidates | 154 |

## 8. Machine-checkable quality gates (WORKFLOW.md 4.4.6)

- Schema validation: **pass** (draft 2020-12, `additionalProperties: false` respected).
- Pass 1 has at least one sink: **yes** (98 sink entries, 26 tp call-site rows).
- Duplicates removed: **yes** (738 unique of 813 CSV rows).
- Argument index bounds: every `flow_kind=argument` entry carries an integer `arg_index >= 0` (enforced by schema); receiver-style calls use `flow_kind=receiver` with arg_index null; param/return/field flows carry arg_index only where the extraction captured one.
