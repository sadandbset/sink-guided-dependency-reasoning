# Pass 1 Label Statistics — Path Traversal (Zope)

- Experiment workspace: `iris_manual/Path_Traversal/Zope/iris`
- Source tree: `dataset/codeql_databases/path_traversal_dbs/Zope_vuln/src` (Zope 5.2.dev0)
- Labeling LLM (real model used): **glm-5.3** (this session's model; labeling performed by direct
  review of the real source code, no ground truth / patches / CVE material consulted)
- Generated: 2026-10-24 (UTC)
- Pass: 1 — Path Traversal — CWE-22, CWE-23, CWE-36, CWE-73
- Schema validation: `labels.json` **PASSES** local Augur `assets/labels_schema.json`
  (jsonschema 4.26.0, draft 2020-12 validator)

## Batch policy

| item | value |
| --- | --- |
| batch size | 32 |
| batch count | 12 (11 × 32 + 1 × 24) |
| total candidates processed | 376 (315 source rows + 61 sink rows) |
| candidates dropped | 0 — no candidate was excluded outright; env/CLI/config families were labeled `none`/`fp` instead |
| re-ask threshold | 0.55 |
| re-asks performed | 0 (no entry below threshold; minimum confidence observed = 0.60) |
| exact duplicate rows removed | 0 (dedup key: nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context) |

## Role counts

| role | count |
| --- | --- |
| source | 270 |
| sink | 61 |
| none | 45 |
| sanitizer | 0 |
| summary | 0 |

## Classification counts

| classification | count |
| --- | --- |
| tp | 265 |
| fp | 102 |
| candidate | 9 |
| unknown | 0 |

## Source candidates by family (315 CSV rows)

| family | rows | role | class | conf. | note |
| --- | ---: | --- | --- | --- | --- |
| request_subscript | 84 | source | tp | 0.85 | REQUEST[...] merged namespaces (BODY/BODY/URL/id) |
| request_header | 38 | source | tp | 0.85 | environ[HTTP_*] via get_header; not path-shaped |
| http_request_param | 33 | source | tp | 0.90 | published entries / WebDAV verb handlers / dav__init |
| request_lookup_get | 33 | source | tp | 0.85 | REQUEST.get merged lookup (per-key trust varies) |
| wsgi_environ_subscript | 22 | source | tp | 0.85 | raw environ subscripts (HTTP_* attacker-controlled) |
| zmi_form_param | 18 | source | tp | 0.85–0.90 | mapply-marshalled manage_* params; import 'file' & export 'id' reach FS joins |
| wsgi_environ_get | 16 | source | tp | 0.85 | environ.get + get_env alias |
| config_path_param | 16 | none | fp | 0.90 | ZCML/config-time paths, developer boundary |
| env_config | 12 | none | fp | 0.95 | os.environ operator/deployment config |
| cli_argv_param | 12 | none | fp | 0.95 | console utility path params, operator boundary |
| cli_argv | 5 | none | fp | 0.95 | sys.argv subscripts, operator boundary |
| request_form | 5 | source | tp | 0.90 | REQUEST.form (Cache.py:518→restrictedTraverse observed) |
| route_path_param | 5 | source | candidate | 0.70 | ZODB object-tree traversal; FS reach only via bridges |
| wsgi_environ | 4 | source | tp | 0.90 | request.environ attribute reads |
| url_traversal_segment | 3 | source | tp | 0.80–0.85 | 2× NullResource name (ZODB id); 1× DirectoryResource.get name (FS join, unfiltered in-repo) |
| multipart_filename | 3 | source | tp | 0.90 | FieldStorage filename; cookId basename downstream |
| wsgi_environ_param | 2 | source | tp | 0.95 | publish_module environ + HTTPRequest.__init__ environ |
| request_form_get | 2 | source | tp | 0.90 | REQUEST.form.get (PropertyManager) |
| request_body_stdin_param | 1 | source | tp | 0.90 | HTTPRequest.__init__ stdin body stream |
| xmlrpc_request_args | 1 | source | tp | 0.90 | xmlrpc.parse_input → mapply |

## Sink candidates by family (61 CSV rows)

| family | rows | role | class | conf. | note |
| --- | ---: | --- | --- | --- | --- |
| fs_metadata | 34 | sink | fp (32) / candidate (2) | 0.70–0.95 | candidates: resource.py:156/:157 (URL-derived ++resource++ join); ObjectManager.py:645 guarded by split (:639-641), Windows ntpath edge + TOCTOU noted |
| fs_open | 11 | sink | fp (10) / candidate (1) | 0.65–0.95 | candidate: ObjectManager.py:622 export write under CONFIG.clienthome with request id |
| fs_copy | 8 | sink | fp | 0.95 | copyzopeskel CLI (operator boundary) |
| fs_listdir | 3 | sink | fp | 0.90 | fixed import dirs / startup product discovery |
| fs_open_fileio | 1 | sink | fp | 0.85 | ImageFile.py:121 filestream_iterator — path fixed at ZCML registration |
| external_import_file | 1 | sink | fp | 0.65 | ObjectManager.py:679 importFile — guarded, TOCTOU/Windows notes |
| fs_create_dir | 1 | sink | fp | 0.95 | copyzopeskel CLI makedirs |
| external_resource_factory | 1 | sink | candidate | 0.70 | resource.py:170 factory(name, filename) over URL-derived join |
| fs_delete | 1 | sink | fp | 0.95 | userfolder.py:309 fixed inituser removal |

## Candidate entries retained for manual review (9)

| id | location | role | conf. | issue |
| --- | --- | --- | --- | --- |
| p1-src-287 | ZPublisher/BaseRequest.py:353 | source | 0.70 | object-tree traversal param; FS reachability depends on external zope.traversing dispatch |
| p1-src-288 | ZPublisher/HTTPRequest.py:253 | source | 0.70 | physicalPathFromURL URL param (same caveat) |
| p1-src-289 | ZPublisher/HTTPRequest.py:1161 | source | 0.70 | resolve_url url param (same caveat) |
| p1-src-290 | OFS/Traversable.py:152 | source | 0.70 | unrestrictedTraverse path param (same caveat) |
| p1-src-291 | OFS/Traversable.py:362 | source | 0.70 | restrictedTraverse path param (same caveat) |
| p1-snk-318 | Products/Five/browser/resource.py:157 | sink | 0.75 | isdir(join(path, name)) with URL-derived name; '..' would resolve true |
| p1-snk-343 | OFS/ObjectManager.py:622 | sink | 0.65 | clienthome export join; slash-containing ids pass checkValidId (compound precondition) |
| p1-snk-369 | Products/Five/browser/resource.py:156 | sink | 0.75 | isfile(join(path, name)) with URL-derived name |
| p1-snk-375 | Products/Five/browser/resource.py:170 | sink | 0.70 | external factory(name, filename) performs the actual read |

Note: the related `url_traversal_segment` source for the ++resource++ bridge is
`p1-src-294` (`Products/Five/browser/resource.py:153`, DirectoryResource.get name,
source/tp/0.85) — labeled tp as an untrusted boundary; the in-repo unfiltered join is
recorded on the sink side above.

## Confidence distribution

| confidence | entries |
| --- | --- |
| 0.60 | 2 |
| 0.65 | 2 |
| 0.70 | 7 |
| 0.75 | 2 |
| 0.80 | 3 |
| 0.85 | 213 |
| 0.90 | 89 |
| 0.95 | 58 |

## Quality checks (WORKFLOW.md 4.4.6)

1. **Schema validation**: PASS (local `assets/labels_schema.json`).
2. **Pass 1 has ≥1 sink**: yes — 61 sink entries.
3. **Duplicates removed**: 0 exact-duplicate rows found in either CSV.
4. **Argument index bounds**: all 61 `flow_kind=argument` entries carry an integer
   `arg_index ≥ 0` (0 or 1, matching the extracted call argument positions); source
   `param` entries use the CSV parameter index (0/1/2) or `null` where not applicable;
   CSV `-1` values mapped to `null`.
5. **flow_kind normalization**: CSV flow families mapped to the schema enum —
   parameter rows → `param` (90), field/attribute/subscript reads → `field` (217),
   call-return reads → `return` (8), sink call arguments → `argument` (61).

## Sanitizer / summary roles: none assigned — rationale

No row in `sources.csv` / `sinks.csv` is a proven neutralizer or framework-glue taint
step for Pass 1. The real guard layer in this codebase consists of propagation-layer
nodes that the extraction queries deliberately did **not** emit as candidates
(see `exploration/detection.json` → `propagation_and_validation_nodes`):

- `OFS/ObjectManager.py:639-641` — `os.path.split` dirname rejection in `manage_importObject`
- `OFS/ObjectManager.py:84-115` — `checkValidId` (rejects `.`, `..`, control/angle chars;
  **does not** reject `/` or embedded `..` components — flagged for Phase 2)
- `App/Extensions.py:92-95` and `:47-54` — getPath split guard and `_getPath` join-collapse paranoia
- `OFS/Image.py:1002-1010` — `cookId` basename extraction over `/`, `\`, `:`
- `webdav/NullResource.py:129-138/:181-185` — lock checks + `_verifyObjectPaste` before object creation

These are documented in `labels/phase1_review.md` as the Phase 2 `MySanitizers.qll`
input inventory; they were not invented as candidate entries to keep `labels.json`
faithful to the extracted candidate set.

## Exclusion / none-labeling rationale

No candidate was silently dropped. Candidates on non-attacker boundaries were labeled
`none` with classification `fp` and an explicit rationale:

- `env_config` (12 rows): `os.environ` reads are operator/deployment configuration
  (INSTANCE_HOME/CLIENT_HOME bootstrap, ZOPE_DTML_REQUEST_AUTOQUOTE,
  DONT_GZIP_MAJOR_MIME_TYPES) — no request boundary flows into these values.
- `cli_argv` / `cli_argv_param` (17 rows): console utilities (zconsole, copyzopeskel,
  mkwsgiinstance, serve) run at the operator CLI boundary, not the HTTP boundary.
- `config_path_param` (16 rows): ZCML-registration-time path parameters
  (ImageFile/PageTemplateFile/ClassicHTMLFile/ResourceFactory/Directory/Extensions
  lookups) — developer boundary, not per-request input.

Config/CLI **sinks** were correspondingly labeled `fp` (operator/developer boundary;
no request-derived component reaches the path argument — verified in source).
