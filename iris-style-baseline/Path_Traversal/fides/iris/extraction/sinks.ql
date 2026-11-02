/**
 * @name fides CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the fides
 *   CodeQL database (ethyca-fides on main after 2.15.0, creation sha
 *   1212eadf - the fides webserver + CLI itself is the audit target):
 *   the static-file serving channel (FileResponse(ui_file) at
 *   src/fides/api/main.py:180 with ui_file.is_file() guard read at :170
 *   and the path resolution chain match_route main.py:163 /
 *   get_path_to_admin_ui_file main.py:167 -> ui.py:42
 *   package_path / ADMIN_UI_DIRECTORY / path - pathlib __truediv__ whose
 *   absolute-path/lexical-'..' semantics are documented in
 *   detection.json; FileResponse(index) at ui.py:50 for the root route;
 *   the lexical containment check path_is_in_ui_directory
 *   `ui_directory in path.parents` at ui.py:141 - captured as the
 *   .parents attribute row - and the .relative_to display-path
 *   derivation at ui.py:88; the UI route-map discovery
 *   ui_path.glob of "**" (recursive) plus "*.html" at ui.py:82 over
 *   Path(ui_directory).exists() ui.py:71); builtin open(...) (the local
 *   DSR upload write f"fides_uploads/{file_key}" with server-generated
 *   file_key at api/tasks/storage.py:184-:187 after os.makedirs at :182,
 *   packaged notice-yaml reads consent_util.py:511/:560 via load_file,
 *   packaged SaaS template reads saas_util.py:27/:34/:50/:75/:381, the
 *   CLI BigQuery keyfile read cli/utils.py:361, config reads/writes
 *   config/create.py:197, config/helpers.py:92, config/utils.py:18/:24,
 *   manifest write core/pull.py:19, credentials write/read
 *   core/utils.py:161/:181); pathlib member file access
 *   (yaml_path.open("r") db/samples.py:93 over iterdir-walked packaged
 *   samples; Path(os.path.join(DSR_DIRECTORY,
 *   "assets/back.svg")).read_text() dsr_report_builder.py:150; Path ctors
 *   ui.py:27/:70, dsr_report_builder.py:17/:150, get_email_template.py
 *   :22/:24 with .parent/.resolve propagation); directory creation
 *   (os.makedirs storage.py:182, os.mkdir config/create.py:215, bare
 *   makedirs core/deploy.py:160); the os.path propagation/validation
 *   family in all three import styles (qualified os.path.<member>:
 *   helpers.py:33/:34/:42/:43, connector_registry_service.py:75,
 *   dsr_report_builder.py:150, storage.py:181, create.py:221; the
 *   `from os import path` style path.dirname/path.abspath/path.join
 *   db/database.py:29-:31; the from-imported bare names join/dirname
 *   app_setup.py:51/:56, join/dirname/exists core/deploy.py:19-:23/:159,
 *   isfile core/utils.py:87); directory listings (os.listdir
 *   connector_registry_service.py:73 and
 *   saas_request/override_implementations/__init__.py:9,
 *   .iterdir() samples.py:89); globbing (glob.glob core/utils.py:92 over
 *   the CLI manifests_dir, ui_path.glob ui.py:82); zipfile (in-memory
 *   only: ZipFile(BytesIO(file), "r") saas_config_endpoints.py:378 -
 *   the request zip upload boundary; zipfile.ZipFile(zipped_csvs, "w")
 *   storage.py:84 and zipfile.ZipFile(self.baos, "w")
 *   dsr_report_builder.py:41 with the .writestr member-name writes
 *   storage.py:90 f"{key}.csv" and dsr_report_builder.py:83
 *   f"{filename}" - archive ENTRY NAMES derived from graph dataset
 *   keys, relevant because the produced zips are downloaded and
 *   extracted elsewhere; the zip_file.read(info) entry read
 *   connector_registry_service.py:191 of the uploaded zip - NO
 *   extractall/extract anywhere, nothing is written to the filesystem
 *   from archive entries); external-library manifest/config IO
 *   (manifests.write_manifest core/dataset.py:327 and
 *   core/annotate_dataset.py:163 - fideslang manifest writes;
 *   ingest_manifests core/annotate_dataset.py:109, core/parse.py:20,
 *   load_yaml_into_dict core/pull.py:38 - fideslang manifest reads;
 *   toml.load config/__init__.py:201 and core/utils.py:182 - config and
 *   credentials reads); and definition rows for the tool's own
 *   path-taking APIs (load_file, get_config_from_file,
 *   update_config_file, get_config, replace_config_value,
 *   create_config_file, generate_config_docs, load_yaml_as_string,
 *   load_config, load_as_string, load_datasets, encode_file_contents,
 *   load_default_notices_on_startup,
 *   load_default_experience_configs_on_startup, upload_to_local,
 *   get_path_to_admin_ui_file, generate_route_file_map, match_route,
 *   path_is_in_ui_directory, write_manifest_file, get_manifest_list,
 *   write_credentials_file, read_credentials_file,
 *   handle_bigquery_config_options, write_dataset_manifest,
 *   annotate_dataset) with the true path parameter positions. Raw BQRS
 *   extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/fides/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member/field name ("open" / "FileResponse" /
 *                   "is_file" / "exists" / "mkdir"/"makedirs" / "join" /
 *                   "abspath" / "dirname" / "isfile" / "listdir" /
 *                   "iterdir" / "glob" / "Path" / "joinpath" / "resolve" /
 *                   "parent" / "relative_to" / "parents" / "read_text" /
 *                   "ZipFile" / "writestr" / "read" / "write_manifest" /
 *                   "ingest_manifests" / "load_yaml_into_dict" / "load" /
 *                   the function name for file_api_def definition rows)
 *   4. flow_kind  - "file_open" (builtin open(...) - argument 0 carries
 *                   the path; read "r"/"rb" vs write "w"/"w+"/"wb" noted
 *                   via the site context in the description),
 *                   "file_open_member" (pathlib .open(...) - the path is
 *                   the RECEIVER, arg_index -1),
 *                   "dir_create" (os.makedirs/os.mkdir/bare makedirs -
 *                   argument 0 carries the path),
 *                   "file_response" (FileResponse(argument 0) - the
 *                   actual static-file serve; the open happens inside
 *                   starlette, external to this database),
 *                   "path_stat_member" (.is_file()/.exists()/.is_dir() -
 *                   guard reads on the receiver path, arg_index -1),
 *                   "path_stat" (os.path.exists/isfile - argument 0),
 *                   "path_join" (os.path.join / path.join / bare join /
 *                   .joinpath - propagation; argument 0 is the first
 *                   path component, later positional arguments also
 *                   carry components),
 *                   "path_canon" (os.path.abspath / path.abspath -
 *                   normalization), "path_canon_member" (.resolve() -
 *                   receiver-based canonicalization, arg_index -1),
 *                   "path_part" (the .parent attribute read - component
 *                   extraction on the receiver path, arg_index -1),
 *                   "path_containment_check" (.relative_to(argument 0) -
 *                   containment-check-shaped display-path derivation at
 *                   ui.py:88; the .parents attribute read arg_index -1 -
 *                   the lexical `ui_directory in path.parents` guard
 *                   material at ui.py:141),
 *                   "dir_list" (os.listdir(argument 0)),
 *                   "dir_list_member" (.iterdir() - receiver path,
 *                   arg_index -1),
 *                   "path_glob" (glob.glob(argument 0) and
 *                   .glob(argument 0) - directory pattern discovery),
 *                   "path_ctor" (pathlib.Path(...) / pathlib.Path via
 *                   the pathlib attribute - argument 0 carries the
 *                   path),
 *                   "file_read_text" (.read_text(...) - receiver path,
 *                   arg_index -1),
 *                   "zip_ctor" (ZipFile(...) - argument 0 carries the
 *                   file-like/bytes object; all three sites are
 *                   in-memory BytesIO constructions),
 *                   "zip_member_write" (.writestr(argument 0 = the
 *                   archive ENTRY NAME) - in-memory archive member
 *                   creation; the member names derive from graph
 *                   dataset keys and matter when the zip is extracted
 *                   downstream),
 *                   "zip_read" (.read(argument 0) on the uploaded
 *   zip_file - archive entry read, in memory),
 *                   "file_write_ext" (fideslang
 *                   manifests.write_manifest(argument 0) - manifest
 *                   file write inside the external library),
 *                   "file_read_ext" (fideslang
 *                   ingest_manifests/load_yaml_into_dict(argument 0) and
 *                   toml.load(argument 0) - manifest/config file reads
 *                   inside external libraries),
 *                   "file_api_def" (definition row of a tool-internal
 *                   path-taking API, carrying the path parameter
 *                   position)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "os"/"os.path"/"pathlib"/"zipfile"/
 *                   "glob"/"toml"/"manifests" etc., or "" if none;
 *                   "<expr>" when the object expression is neither Name
 *                   nor Attribute - e.g. the Path(os.path.join(...))
 *                   constructions; "" for file_api_def rows - module
 *                   level functions)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal
 *                   module hints "builtins"/"os"/"os.path"/"pathlib"/
 *                   "zipfile"/"glob"/"fideslang.manifests"/"toml"/
 *                   "fastapi.responses" for the stdlib/external channels
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for open/makedirs/mkdir/FileResponse/
 *                   join-family/listdir/glob/Path/ZipFile/writestr/
 *                   read/write_manifest/ingest_manifests/
 *                   load_yaml_into_dict/toml.load; the parameter
 *                   position for file_api_def rows), -1 when the path is
 *                   the RECEIVER (.open/.is_file/.exists/.iterdir/
 *                   .resolve/.read_text) or the ATTRIBUTE itself
 *                   (.parent/.parents)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): the sink core is the FILE
 * PATH PARAMETER of actual filesystem operations (open, FileResponse, mkdir/
 * makedirs, the pathlib .open/.read_text member reads, the external manifest/
 * config IO) plus the path-pipeline nodes that directly determine the
 * accessed path (Path constructions, the os.path join/abspath/dirname
 * propagation, the is_file/exists/isfile guard reads, the .parents lexical
 * containment material) - NOT every path string construction node: the
 * pathlib __truediv__ chains (ui.py:42 package_path / ADMIN_UI_DIRECTORY /
 * path - THE join of the catchall request path onto the UI base - and
 * ui.py:60) and f-string path building (storage.py:184, config/utils.py:14/
 * :16, config/create.py:207-:209) are BinaryExpr/f-string nodes that cannot
 * be distinguished from ordinary arithmetic/formatting at AST level; they
 * are anchored by their consuming sink rows (get_path_to_admin_ui_file def
 * row, is_file, FileResponse, open) and documented in detection.json
 * uncoveredCases as MySummaries material for Phase 2. The zipfile rows mark
 * the in-memory archive boundary: NO extractall/extract exists anywhere in
 * src/fides, so no archive-extraction destination sink is emitted; the
 * writestr rows capture the archive ENTRY NAME channel because the produced
 * zips (DSR reports, CSV bundles) are downloaded and extracted downstream.
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching out entirely
 * (all channels are either builtin/stdlib module members matched on the
 * syntactic qualifier - the stdlib is not part of the database -,
 * external-library members (fideslang/toml/fastapi) or instance/local
 * member calls; the match_kind column is kept "ast" for cross-project
 * contract consistency with the prior projects of this series). Member-call
 * families exclude the qualified os.path./path. forms so each os.path site
 * yields exactly one row; the .open member family excludes the webbrowser
 * receiver (core/deploy.py:287/:288 - a browser URL open, not a filesystem
 * operation).
 *
 * Excluded paths (applied to every row, in addition to the positive scope):
 * /fides-db/ (the CodeQL database directory sits inside the source tree),
 * /src/fides/_version.py (versioneer-generated - its open() at :152 is
 * build tooling). Positive scope %/src/fides/%: root-level tests/, clients/
 * (TypeScript frontends), docs/, scripts/ (dev tooling open() calls at
 * generate_docs.py:18, quickstart.py:186/:224/:473), noxfile.py, setup.py,
 * versioneer.py are never candidates.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  have no dotted module name; their file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
}

/** Forward-slash-normalized absolute path of the file containing n, so path
 *  matching works with both CodeQL path styles on Windows. */
string normalizedPathOf(AstNode n) {
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
}

/** Base name of the object expression of an attribute access, used as a receiver hint. */
string receiverHint(Attribute a) {
  result = a.getObject().(Name).getId()
  or
  result = a.getObject().(Attribute).getName()
  or
  not a.getObject() instanceof Name and
  not a.getObject() instanceof Attribute and
  result = "<expr>"
}

/** True iff the candidate's file path is one of the excluded trees. Path is
 *  normalized to forward slashes before matching so the query works on both
 *  CodeQL path styles. bindingset[path] declares that the caller passes a
 *  bound path (the path only appears in checked positions such as the
 *  receiver of replaceAll/matches inside this predicate). */
bindingset[path]
predicate excludedPath(string path) {
  path.replaceAll("\\", "/").matches("%/fides-db/%")
  or
  path.replaceAll("\\", "/").matches("%/src/fides/_version.py")
}

/** True iff the candidate is inside the audited fides package (positive
 *  scope; everything else - tests/, clients/, docs/, scripts/, build
 *  tooling at the repo root - is out of scope). Same bindingset rationale
 *  as excludedPath. */
bindingset[path]
predicate inScope(string path) {
  path.replaceAll("\\", "/").matches("%/src/fides/%")
}

/* ------------------------------------------------------------------ */
/* Shared fides shapes (kept consistent with sources.ql)                */
/* ------------------------------------------------------------------ */

/** os.path.<member> members performing path propagation/validation/guard
 *  reads, mapped to their flow kind. Covers the qualified os.path form,
 *  the `from os import path` form and the from-imported bare names. */
private predicate osPathFlowKind(string member, string kind) {
  (member = "join" and kind = "path_join")
  or
  (member = "dirname" and kind = "path_part")
  or
  (member = "basename" and kind = "path_part")
  or
  (member = "abspath" and kind = "path_canon")
  or
  (member = "realpath" and kind = "path_canon")
  or
  (member = "normpath" and kind = "path_canon")
  or
  (member = "exists" and kind = "path_stat")
  or
  (member = "isfile" and kind = "path_stat")
  or
  (member = "isdir" and kind = "path_stat")
}

/** Modules that use `from os.path import <member>` (bare-name os.path
 *  calls): app_setup.py imports dirname/join, core/deploy.py imports
 *  dirname/exists/join, core/utils.py imports isfile. Same bindingset
 *  rationale as excludedPath. */
bindingset[path]
private predicate osPathBareImportModule(string path) {
  path.matches("%/src/fides/api/app_setup.py")
  or
  path.matches("%/src/fides/core/deploy.py")
  or
  path.matches("%/src/fides/core/utils.py")
}

/** The tool's internal path-taking API definitions with their path
 *  parameter (function, parameter name, file) - definition rows for the
 *  file_api_def family. Parameter positions (0-based) are documented per
 *  shape in the row-assembly family. */
private predicate fileApiDefShape(Function f, Parameter p) {
  /* fides.config.helpers.load_file(file_names) - helpers.py:15 (module
     function, file_names at position 0) - the search-path file resolver:
     joins each name onto FIDES__CONFIG_PATH/curdir/pardir/two-up/
     .fides/~ before isfile; every caller in this tree passes packaged
     constants (data/saas templates, privacy notices, config) */
  f.getName() = "load_file" and
  normalizedPathOf(f).matches("%/src/fides/config/helpers.py") and
  p.getName() = "file_names" and
  p = f.getAnArg()
  or
  /* fides.config.helpers.get_config_from_file(config_path_override,
     section, option) - helpers.py:50 (position 0) - toml.load(config_path) */
  f.getName() = "get_config_from_file" and
  normalizedPathOf(f).matches("%/src/fides/config/helpers.py") and
  p.getName() = "config_path_override" and
  p = f.getAnArg()
  or
  /* fides.config.helpers.update_config_file(updates,
     config_path_override) - helpers.py:72 (position 1) - the config-file
     rewrite (open at :92) */
  f.getName() = "update_config_file" and
  normalizedPathOf(f).matches("%/src/fides/config/helpers.py") and
  p.getName() = "config_path_override" and
  p = f.getAnArg()
  or
  /* fides.config.get_config(config_path_override, verbose) -
     config/__init__.py:179 (position 0) - env/CLI-selected toml config
     read (toml.load at :201) */
  f.getName() = "get_config" and
  normalizedPathOf(f).matches("%/src/fides/config/__init__.py") and
  p.getName() = "config_path_override" and
  p = f.getAnArg()
  or
  /* fides.config.utils.replace_config_value(fides_directory_location,
     key, old_value, new_value) - config/utils.py:7 (position 0) - the
     fides.toml read/rewrite pair (open at :18/:24) */
  f.getName() = "replace_config_value" and
  normalizedPathOf(f).matches("%/src/fides/config/utils.py") and
  p.getName() = "fides_directory_location" and
  p = f.getAnArg()
  or
  /* fides.config.create.create_config_file(config,
     fides_directory_location) - create.py:202 (position 1) - CLI init's
     .fides dir creation (os.mkdir at :215) and config write */
  f.getName() = "create_config_file" and
  normalizedPathOf(f).matches("%/src/fides/config/create.py") and
  p.getName() = "fides_directory_location" and
  p = f.getAnArg()
  or
  /* fides.config.create.generate_config_docs(config, outfile_path) -
     create.py:159 (position 1) - the config docs write (open at :197) */
  f.getName() = "generate_config_docs" and
  normalizedPathOf(f).matches("%/src/fides/config/create.py") and
  p.getName() = "outfile_path" and
  p = f.getAnArg()
  or
  /* fides.api.util.saas_util.load_yaml_as_string(filename) -
     saas_util.py:25 (position 0) - open(yaml_file, "r") at :27 via
     load_file */
  f.getName() = "load_yaml_as_string" and
  normalizedPathOf(f).matches("%/src/fides/api/util/saas_util.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* fides.api.util.saas_util.load_config(filename) - saas_util.py:31
     (position 0) - open + yaml.safe_load at :34 */
  f.getName() = "load_config" and
  normalizedPathOf(f).matches("%/src/fides/api/util/saas_util.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* fides.api.util.saas_util.load_as_string(filename) - saas_util.py:48
     (position 0) - open at :50 */
  f.getName() = "load_as_string" and
  normalizedPathOf(f).matches("%/src/fides/api/util/saas_util.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* fides.api.util.saas_util.load_datasets(filename) - saas_util.py:72
     (position 0) - open + yaml.safe_load at :75 */
  f.getName() = "load_datasets" and
  normalizedPathOf(f).matches("%/src/fides/api/util/saas_util.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* fides.api.util.saas_util.encode_file_contents(file_path) -
     saas_util.py:376 (position 0) - the packaged icon read
     (open(file_path, "rb") at :381 via load_file) */
  f.getName() = "encode_file_contents" and
  normalizedPathOf(f).matches("%/src/fides/api/util/saas_util.py") and
  p.getName() = "file_path" and
  p = f.getAnArg()
  or
  /* fides.api.util.consent_util.load_default_notices_on_startup(db,
     notice_yaml_file_path) - consent_util.py:498 (position 1) - the
     packaged default-notice yaml read (open at :511 via load_file;
     called from app_setup with the packaged path) */
  f.getName() = "load_default_notices_on_startup" and
  normalizedPathOf(f).matches("%/src/fides/api/util/consent_util.py") and
  p.getName() = "notice_yaml_file_path" and
  p = f.getAnArg()
  or
  /* fides.api.util.consent_util.
     load_default_experience_configs_on_startup(db, notice_yaml_file_path)
     - consent_util.py:549 (position 1) - the packaged experience-config
     yaml read (open at :560) */
  f.getName() = "load_default_experience_configs_on_startup" and
  normalizedPathOf(f).matches("%/src/fides/api/util/consent_util.py") and
  p.getName() = "notice_yaml_file_path" and
  p = f.getAnArg()
  or
  /* fides.api.tasks.storage.upload_to_local(data, file_key,
     privacy_request, ...) - storage.py:172 (position 1) - the local DSR
     upload write: filename = f"fides_uploads/{file_key}" then
     open(filename, "wb") at :187; file_key is the server-generated
     request_id-based key from storage_uploader_service.py:67-:75 */
  f.getName() = "upload_to_local" and
  normalizedPathOf(f).matches("%/src/fides/api/tasks/storage.py") and
  p.getName() = "file_key" and
  p = f.getAnArg()
  or
  /* fides.api.ui.get_path_to_admin_ui_file(path) - ui.py:32 (position 0)
     - THE join of the catchall request path onto the packaged admin UI
     directory: package_path / ADMIN_UI_DIRECTORY / path (pathlib
     __truediv__: an absolute path replaces the base, '..' kept lexical);
     called from main.py:167 with the raw catchall path */
  f.getName() = "get_path_to_admin_ui_file" and
  normalizedPathOf(f).matches("%/src/fides/api/ui.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* fides.api.ui.generate_route_file_map(ui_directory) - ui.py:63
     (position 0) - the admin-UI route-map discovery
     (Path(ui_directory).exists() at :71, ui_path.glob at :82) */
  f.getName() = "generate_route_file_map" and
  normalizedPathOf(f).matches("%/src/fides/api/ui.py") and
  p.getName() = "ui_directory" and
  p = f.getAnArg()
  or
  /* fides.api.ui.match_route(route_file_map, route) - ui.py:108
     (position 1) - the regex route match of the catchall request path
     (values from the globbed UI route map; returns the served file) */
  f.getName() = "match_route" and
  normalizedPathOf(f).matches("%/src/fides/api/ui.py") and
  p.getName() = "route" and
  p = f.getAnArg()
  or
  /* fides.api.ui.path_is_in_ui_directory(path) - ui.py:134 (position 0)
     - THE serving containment guard: `ui_directory in path.parents` at
     :141 - LEXICAL check on the unresolved path (no resolve()/realpath);
     sanitizer candidate for labeling */
  f.getName() = "path_is_in_ui_directory" and
  normalizedPathOf(f).matches("%/src/fides/api/ui.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* fides.core.pull.write_manifest_file(manifest_path, manifest) -
     pull.py:15 (position 0) - open(manifest_path, "w") at :19 */
  f.getName() = "write_manifest_file" and
  normalizedPathOf(f).matches("%/src/fides/core/pull.py") and
  p.getName() = "manifest_path" and
  p = f.getAnArg()
  or
  /* fides.core.utils.get_manifest_list(manifests_dir) - core/utils.py:83
     (position 0) - isfile + the recursive yml glob under manifests_dir
     manifest discovery over the CLI manifests_dir */
  f.getName() = "get_manifest_list" and
  normalizedPathOf(f).matches("%/src/fides/core/utils.py") and
  p.getName() = "manifests_dir" and
  p = f.getAnArg()
  or
  /* fides.core.utils.write_credentials_file(credentials, credentials_path)
     - core/utils.py:159 (position 1) - open(credentials_path, "w") at
     :161 */
  f.getName() = "write_credentials_file" and
  normalizedPathOf(f).matches("%/src/fides/core/utils.py") and
  p.getName() = "credentials_path" and
  p = f.getAnArg()
  or
  /* fides.core.utils.read_credentials_file(credentials_path) -
     core/utils.py:175 (position 0) - isfile + open at :181 +
     toml.load at :182 */
  f.getName() = "read_credentials_file" and
  normalizedPathOf(f).matches("%/src/fides/core/utils.py") and
  p.getName() = "credentials_path" and
  p = f.getAnArg()
  or
  /* fides.cli.utils.handle_bigquery_config_options(fides_config, dataset,
     keyfile_path, credentials_id) - cli/utils.py:345 (position 2) - the
     CLI keyfile read open(keyfile_path) at :361 */
  f.getName() = "handle_bigquery_config_options" and
  normalizedPathOf(f).matches("%/src/fides/cli/utils.py") and
  p.getName() = "keyfile_path" and
  p = f.getAnArg()
  or
  /* fides.core.dataset.write_dataset_manifest(file_name, include_null,
     datasets) - core/dataset.py:319 (position 0) - the generated dataset
     manifest write (manifests.write_manifest at :327; file_name is the
     CLI output_filename) */
  f.getName() = "write_dataset_manifest" and
  normalizedPathOf(f).matches("%/src/fides/core/dataset.py") and
  p.getName() = "file_name" and
  p = f.getAnArg()
  or
  /* fides.core.annotate_dataset.annotate_dataset(config, dataset_file,
     resource_type, ...) - core/annotate_dataset.py:86 (position 1) - the
     in-place dataset annotation: ingest_manifests(dataset_file) at :109
     and manifests.write_manifest(dataset_file, ...) at :163 (dataset_file
     is the CLI input_filename) */
  f.getName() = "annotate_dataset" and
  normalizedPathOf(f).matches("%/src/fides/core/annotate_dataset.py") and
  p.getName() = "dataset_file" and
  p = f.getAnArg()
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: builtin open(...) - the local DSR upload write
     storage.py:187 open(filename, "wb") with filename =
     f"fides_uploads/{file_key}" (file_key = server-generated
     request_id.ext from storage_uploader_service.py:67-:75); the
     packaged notice-yaml reads consent_util.py:511/:560
     (open(load_file([notice_yaml_file_path]), "r")); the packaged SaaS
     template reads saas_util.py:27/:34/:50/:75 (yaml_file via load_file)
     and :381 (encode_file_contents icon read, "rb"); the CLI BigQuery
     keyfile read cli/utils.py:361; the config IO
     config/create.py:197 (write), config/helpers.py:92 (write),
     config/utils.py:18 (read)/:24 (rewrite); the manifest write
     core/pull.py:19; the credentials write/read
     core/utils.py:161/:181. Argument 0 carries the path. */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* family 2: pathlib .open(...) member calls - db/samples.py:93
     yaml_path.open("r") inside load_sample_connections_from_project
     (each iterdir-walked packaged sample connection yaml); the
     webbrowser.open receiver (core/deploy.py:287/:288 - browser URL
     open, not a filesystem operation) is excluded. The path is the
     RECEIVER, hence argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    not func.getObject().(Name).getId() = "webbrowser" and
    node = c and
    flowKind = "file_open_member" and
    callableName = "open" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 3: directory creation - os.makedirs(LOCAL_FIDES_UPLOAD_DIRECTORY)
     storage.py:182 (literal "fides_uploads" before the local DSR upload
     write), os.mkdir(fides_dir_path) config/create.py:215 (CLI init's
     .fides dir, fides_dir_path built from the CLI fides_dir param) and
     the from-imported bare makedirs(FIDES_DEPLOY_UPLOADS_DIR)
     core/deploy.py:160 (CLI deploy's uploads dir). Argument 0 carries
     the path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "makedirs" or func.getName() = "mkdir") and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "dir_create" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "makedirs" and
    osPathBareImportModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "dir_create" and
    callableName = "makedirs" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 4: FileResponse(path) - THE static file serve of the catchall
     flow: main.py:180 FileResponse(ui_file) where ui_file comes from
     match_route(get_ui_file_map(), path) (route-map values - files
     globbed from the packaged UI dir) or get_path_to_admin_ui_file(path)
     (package_path / ADMIN_UI_DIRECTORY / path with the raw catchall
     request path), guarded by ui_file.is_file() (:170) and the LEXICAL
     path_is_in_ui_directory check (:171); and ui.py:50
     FileResponse(index) for the root route (literal "index.html").
     Argument 0 carries the path; the actual file open happens inside
     starlette (external to this database). */
  exists(Call c |
    c.getFunc().(Name).getId() = "FileResponse" and
    node = c and
    flowKind = "file_response" and
    callableName = "FileResponse" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "fastapi.responses" and
    matchKind = "ast"
  )
  or
  /* family 5: receiver-path guard reads: .is_file() / .exists() /
     .is_dir() member calls - main.py:170 ui_file.is_file() (the catchall
     existence check - separate syscall from the FileResponse open,
     TOCTOU shape), ui.py:50 index.is_file() (root route check) and
     ui.py:71 ui_path.exists() (route-map discovery gate). The path is
     the RECEIVER, hence argIndex -1; the qualified os.path./path. forms
     are excluded so those sites only produce the os.path-family rows. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "is_file" or func.getName() = "exists" or func.getName() = "is_dir") and
    not func.getObject() instanceof Attribute and
    not func.getObject().(Name).getId() = "path" and
    node = c and
    flowKind = "path_stat_member" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 6: the os.path propagation/validation family, in all three
     import styles of this tree. (a) qualified os.path.<member>(...):
     join - helpers.py:33/:34/:42 (the load_file search-path joins),
     connector_registry_service.py:75 (data/saas/config listing),
     dsr_report_builder.py:150 (packaged asset join); exists -
     storage.py:181 (uploads dir check); isfile - helpers.py:43 (load_file
     hit test), create.py:221 (config file check); abspath -
     helpers.py:33. (b) the `from os import path` style
     path.<member>(...) in db/database.py: path.dirname(path.abspath(
     __file__)) at :29, path.join at :30/:31 (alembic migration paths -
     module constants). (c) the from-imported bare names: join/dirname
     app_setup.py:51/:56 (packaged privacy-notice paths), join/dirname
     core/deploy.py:19-:23 (sample-project paths), exists
     core/deploy.py:159 (uploads dir check), isfile core/utils.py:87
     (get_manifest_list manifest check). Argument 0 carries the path
     (first component for join). */
  exists(Call c, Attribute func, Attribute mid |
    func = c.getFunc().(Attribute) and
    mid = func.getObject().(Attribute) and
    mid.getName() = "path" and
    mid.getObject().(Name).getId() = "os" and
    osPathFlowKind(func.getName(), flowKind) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getObject().(Name).getId() = "path" and
    normalizedPathOf(c).matches("%/src/fides/api/db/database.py") and
    osPathFlowKind(func.getName(), flowKind) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  exists(Call c, string member |
    c.getFunc().(Name).getId() = member and
    osPathFlowKind(member, flowKind) and
    osPathBareImportModule(normalizedPathOf(c)) and
    node = c and
    callableName = member and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 7: .joinpath(component) member calls - db/samples.py:34
     files(fides.data.sample_project).joinpath("sample_resources/") and
     :87 .joinpath("sample_connections/") (importlib_resources packaged
     traversals); argument 0 carries the joined component. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "joinpath" and
    node = c and
    flowKind = "path_join" and
    callableName = "joinpath" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 8: .resolve() member calls - dsr_report_builder.py:17
     Path(__file__).parent.resolve() and get_email_template.py:22/:24
     pathlib.Path(__file__).parent.resolve() (packaged-directory
     constants - module scope). The path is the RECEIVER, hence
     argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "resolve" and
    node = c and
    flowKind = "path_canon_member" and
    callableName = "resolve" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 9: .parent attribute reads - ui.py:27
     Path(spec.origin).parent (the installed package root), and the
     Path(__file__).parent chains at dsr_report_builder.py:17 and
     get_email_template.py:22/:24. The attribute VALUE carries the
     derived path, hence argIndex -1; matched only on Call receivers
     (the Path(...) constructions) to avoid unrelated .parent reads. */
  exists(Attribute a |
    a.getName() = "parent" and
    a.getObject() instanceof Call and
    node = a and
    flowKind = "path_part" and
    callableName = "parent" and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 10: containment-check shapes - (a) .relative_to(base) calls:
     ui.py:88 filepath.relative_to(ui_path) inside
     generate_route_file_map (the display-route derivation of globbed
     UI files - NOT a serving guard; raises ValueError outside the base);
     argument 0 carries the base. (b) the .parents attribute read:
     ui.py:141 `ui_directory in path.parents` inside
     path_is_in_ui_directory - THE lexical serving-containment material
     (computed on the unresolved path, no resolve()/realpath; passes for
     <ui_dir>/../../x because the lexical parents list still contains
     <ui_dir>); argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "relative_to" and
    node = c and
    flowKind = "path_containment_check" and
    callableName = "relative_to" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Attribute a |
    a.getName() = "parents" and
    node = a and
    flowKind = "path_containment_check" and
    callableName = "parents" and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 11: os.listdir(path) - connector_registry_service.py:73
     os.listdir("data/saas/config") (the packaged SaaS template
     discovery feeding os.path.join + load_config) and
     saas_request/override_implementations/__init__.py:9
     os.listdir(directory) (the module auto-import discovery feeding
     importlib.import_module - Pass 4 adjacent); argument 0 carries the
     path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "listdir" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "dir_list" and
    callableName = "listdir" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 12: .iterdir() member calls - db/samples.py:89
     sample_connections_path.iterdir() (the packaged sample-connections
     walk feeding yaml_path.open at :93); the path is the RECEIVER,
     hence argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "iterdir" and
    node = c and
    flowKind = "dir_list_member" and
    callableName = "iterdir" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 13: globbing - (a) glob.glob(pattern): core/utils.py:92
     the recursive yml wildcard glob (double-star plus *.yml) under manifests_dir
     inside get_manifest_list (the CLI manifest discovery); (b)
     .glob(pattern) member calls: ui.py:82
     ui_path.glob of "**" plus "*.html" (the admin-UI route-map discovery);
     argument 0 carries the pattern. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "glob" and
    func.getObject().(Name).getId() = "glob" and
    node = c and
    flowKind = "path_glob" and
    callableName = "glob" and
    argIndex = 0 and
    receiver = "glob" and
    moduleHint = "glob" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "glob" and
    not func.getObject().(Name).getId() = "glob" and
    node = c and
    flowKind = "path_glob" and
    callableName = "glob" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 14: pathlib Path constructions - the Name form
     (from pathlib import Path): ui.py:27 Path(spec.origin) (installed
     package root), ui.py:70 Path(ui_directory) (route-map discovery),
     dsr_report_builder.py:17 Path(__file__) and :150
     Path(os.path.join(DSR_DIRECTORY, "assets/back.svg")) (packaged
     asset read); and the pathlib.Path attribute form:
     get_email_template.py:22/:24 pathlib.Path(__file__) (template
     directory constants). Argument 0 carries the path. */
  exists(Call c |
    c.getFunc().(Name).getId() = "Path" and
    node = c and
    flowKind = "path_ctor" and
    callableName = "Path" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "Path" and
    func.getObject().(Name).getId() = "pathlib" and
    node = c and
    flowKind = "path_ctor" and
    callableName = "Path" and
    argIndex = 0 and
    receiver = "pathlib" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 15: .read_text(...) member calls - dsr_report_builder.py:150
     Path(os.path.join(DSR_DIRECTORY, "assets/back.svg"))
     .read_text(encoding="utf-8") (the packaged DSR asset read); the
     path is the RECEIVER, hence argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "read_text" and
    node = c and
    flowKind = "file_read_text" and
    callableName = "read_text" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 16: ZipFile constructions - all IN MEMORY (BytesIO): the Name
     form (from zipfile import ZipFile):
     saas_config_endpoints.py:378 ZipFile(BytesIO(file), "r") - the
     request zip upload parse boundary (argument 0 carries the
     file-like object wrapping the request bytes); and the
     zipfile.ZipFile attribute form (import zipfile):
     tasks/storage.py:84 zipfile.ZipFile(zipped_csvs, "w") (the DSR CSV
     bundle) and dsr_report_builder.py:41 zipfile.ZipFile(self.baos, "w")
     (the DSR HTML report). No extractall/extract anywhere - no archive
     entry is written to the filesystem. */
  exists(Call c |
    c.getFunc().(Name).getId() = "ZipFile" and
    node = c and
    flowKind = "zip_ctor" and
    callableName = "ZipFile" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "zipfile" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "ZipFile" and
    func.getObject().(Name).getId() = "zipfile" and
    node = c and
    flowKind = "zip_ctor" and
    callableName = "ZipFile" and
    argIndex = 0 and
    receiver = "zipfile" and
    moduleHint = "zipfile" and
    matchKind = "ast"
  )
  or
  /* family 17: .writestr(name, data) archive member writes - IN MEMORY,
     but the ENTRY NAME channel matters because the produced zips (DSR
     reports, CSV bundles) are downloaded and extracted downstream:
     tasks/storage.py:90 f.writestr(f"{key}.csv", ...) (member names =
     graph dataset keys) and dsr_report_builder.py:83
     self.out.writestr(f"{filename}", ...) (member names =
     f"/{dataset_name}/{collection_name}/{index}.html" from DSR data
     keys - dataset names sourced from connector configs). Argument 0
     carries the member name. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "writestr" and
    node = c and
    flowKind = "zip_member_write" and
    callableName = "writestr" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "zipfile" and
    matchKind = "ast"
  )
  or
  /* family 18: the uploaded zip entry read: zip_file.read(info) -
     connector_registry_service.py:191 inside
     CustomConnectorTemplateLoader.save_template (the entries of the
     zip uploaded through register_custom_connector_template; the entry
     NAMES are only used for endswith selection at :197-:218 - nothing
     is extracted to the filesystem). Matched on the local receiver
     name zip_file scoped to this module; argument 0 carries the entry
     (ZipInfo). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "read" and
    func.getObject().(Name).getId() = "zip_file" and
    normalizedPathOf(c).matches("%/src/fides/api/service/connectors/saas/connector_registry_service.py") and
    node = c and
    flowKind = "zip_read" and
    callableName = "read" and
    argIndex = 0 and
    receiver = "zip_file" and
    moduleHint = "zipfile" and
    matchKind = "ast"
  )
  or
  /* family 19: fideslang manifest write - manifests.write_manifest(path,
     data, resource_type): core/dataset.py:327
     manifests.write_manifest(file_name, ...) inside
     write_dataset_manifest (file_name = the CLI output_filename) and
     core/annotate_dataset.py:163
     manifests.write_manifest(dataset_file, output_dataset, "dataset")
     (the in-place annotate write); the file write happens inside
     fideslang (external to this database); argument 0 carries the
     path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "write_manifest" and
    func.getObject().(Name).getId() = "manifests" and
    node = c and
    flowKind = "file_write_ext" and
    callableName = "write_manifest" and
    argIndex = 0 and
    receiver = "manifests" and
    moduleHint = "fideslang.manifests" and
    matchKind = "ast"
  )
  or
  /* family 20: external manifest/config reads - fideslang
     ingest_manifests(manifests_dir_or_file):
     core/annotate_dataset.py:109 ingest_manifests(dataset_file) and
     core/parse.py:20 ingest_manifests(manifests_dir) (the CLI manifest
     reads); fideslang load_yaml_into_dict(manifest_path):
     core/pull.py:38 (the pull manifest read); toml.load(path):
     config/__init__.py:201 toml.load(config_path) (the env/CLI-selected
     config read) and core/utils.py:182
     toml.load(credentials_file) (the credentials read inside
     read_credentials_file). The file reads happen inside the external
     libraries; argument 0 carries the path. */
  exists(Call c |
    (c.getFunc().(Name).getId() = "ingest_manifests"
     or c.getFunc().(Name).getId() = "load_yaml_into_dict") and
    node = c and
    flowKind = "file_read_ext" and
    callableName = c.getFunc().(Name).getId() and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "fideslang.manifests" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "load" and
    func.getObject().(Name).getId() = "toml" and
    node = c and
    flowKind = "file_read_ext" and
    callableName = "load" and
    argIndex = 0 and
    receiver = "toml" and
    moduleHint = "toml" and
    matchKind = "ast"
  )
  or
  /* the from-imported bare toml load (config/helpers.py:10
     `from toml import dump, load`): helpers.py:61/:84
     load(config_path) inside get_config_from_file/update_config_file -
     the config file reads feeding the rewrite; the companion
     dump(current_config, config_file) at :93 writes an already-opened
     HANDLE (the path was consumed by open() at :92, family 1) and is
     not emitted as a row */
  exists(Call c |
    c.getFunc().(Name).getId() = "load" and
    normalizedPathOf(c).matches("%/src/fides/config/helpers.py") and
    node = c and
    flowKind = "file_read_ext" and
    callableName = "load" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "toml" and
    matchKind = "ast"
  )
  or
  /* family 21: file_api_def definition rows - the tool's internal
     path-taking API definitions with the true path parameter positions
     (0-based, module-level functions, no self slot):
     load_file(file_names) config/helpers.py:15 pos 0,
     get_config_from_file(config_path_override) helpers.py:50 pos 0,
     update_config_file(config_path_override) helpers.py:72 pos 1,
     get_config(config_path_override) config/__init__.py:179 pos 0,
     replace_config_value(fides_directory_location) config/utils.py:7
     pos 0, create_config_file(fides_directory_location)
     config/create.py:202 pos 1,
     generate_config_docs(outfile_path) create.py:159 pos 1,
     load_yaml_as_string(filename) saas_util.py:25 pos 0,
     load_config(filename) saas_util.py:31 pos 0,
     load_as_string(filename) saas_util.py:48 pos 0,
     load_datasets(filename) saas_util.py:72 pos 0,
     encode_file_contents(file_path) saas_util.py:376 pos 0,
     load_default_notices_on_startup(notice_yaml_file_path)
     consent_util.py:498 pos 1,
     load_default_experience_configs_on_startup(notice_yaml_file_path)
     consent_util.py:549 pos 1, upload_to_local(file_key)
     tasks/storage.py:172 pos 1,
     get_path_to_admin_ui_file(path) ui.py:32 pos 0 - THE catchall
     path join -, generate_route_file_map(ui_directory) ui.py:63 pos 0,
     match_route(route) ui.py:108 pos 1,
     path_is_in_ui_directory(path) ui.py:134 pos 0 - THE lexical
     containment guard -, write_manifest_file(manifest_path)
     core/pull.py:15 pos 0, get_manifest_list(manifests_dir)
     core/utils.py:83 pos 0,
     write_credentials_file(credentials_path) core/utils.py:159 pos 1,
     read_credentials_file(credentials_path) core/utils.py:175 pos 0,
     handle_bigquery_config_options(keyfile_path) cli/utils.py:345
     pos 2, write_dataset_manifest(file_name) core/dataset.py:319
     pos 0, annotate_dataset(dataset_file)
     core/annotate_dataset.py:86 pos 1; these rows give the labeling
     step the summary/propagation backbone between the source
     boundaries and the concrete file operations */
  exists(Function f, Parameter p |
    fileApiDefShape(f, p) and
    not p.isSelf() and
    node = p and
    flowKind = "file_api_def" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    (
      f.getEnclosingScope() instanceof Class and
      receiver = f.getEnclosingScope().(Class).getName()
      or
      not f.getEnclosingScope() instanceof Class and
      receiver = ""
    )
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  inScope(node.getLocation().getFile().getAbsolutePath()) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "sink_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
