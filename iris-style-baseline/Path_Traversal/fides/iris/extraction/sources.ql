/**
 * @name fides CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   fides CodeQL database (ethyca-fides on main after 2.15.0, creation sha
 *   1212eadf - the fides webserver + CLI itself is the audit target): the
 *   catchall admin-UI route path variable (request.path_params["catchall"]
 *   at src/fides/api/main.py:160 - the @app.get("/{catchall:path}") route
 *   at :154 whose value drives match_route/get_path_to_admin_ui_file ->
 *   is_file -> path_is_in_ui_directory -> FileResponse static file
 *   serving); the request header boundary (request.headers.get(...) reads:
 *   X-Fides-Source main.py:64, authorization middleware.py:39,
 *   UNESCAPE_SAFESTR_HEADER privacy_notice_endpoints.py:92/:191,
 *   privacy_experience_endpoints.py:168,
 *   privacy_experience_config_endpoints.py:86/:214, User-Agent/Referer
 *   privacy_preference_endpoints.py:244/:245, content-type
 *   dataset_endpoints.py:309 - plus the bare request.headers read at
 *   privacy_preference_endpoints.py:242); the raw request body boundary
 *   (await request.body() calls at middleware.py:45/:124 and
 *   dataset_endpoints.py:314 - the audit-log middleware and the YAML
 *   dataset PATCH handler); the zip upload body parameter (the
 *   file: bytes = Body(...) parameter of register_custom_connector_template
 *   at saas_config_endpoints.py:363 - the ONLY file-upload endpoint,
 *   parsed in memory via ZipFile(BytesIO(file), "r") at :378); the request
 *   metadata reads (request.url/.path/.hostname, request.method,
 *   request.client, request.scope["path"] - analytics/audit middlewares,
 *   not file-targeting, recorded for labeling); the catchall handler
 *   parameter (the request: Request parameter of read_other_paths at
 *   main.py:155); the environment-variable config-path boundary
 *   (getenv FIDES__CONFIG_PATH config/__init__.py:197 and
 *   os.getenv inside load_file helpers.py:30, getenv
 *   FIDES_CREDENTIALS_PATH core/utils.py:171 - OPERATOR-trust level,
 *   recorded for labeling to classify, not automatically attacker
 *   sources); and the CLI parameter boundary (click command parameters
 *   fides_dir/manifests_dir/input_filename/output_filename/keyfile_path/
 *   env_file across src/fides/cli - operator trust level). Raw BQRS
 *   extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/fides/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (e.g. "path_params", "get",
 *                   "headers", "body", "url", "path", "hostname", "method",
 *                   "client", "scope", "getenv", the CLI field name for
 *                   cli_param rows, the function name for parameter rows)
 *   4. flow_kind  - "http_path_param" (request.path_params[...] subscript -
 *                   the catchall route variable),
 *                   "http_header" (request.headers.get(...) call or the bare
 *                   request.headers attribute read),
 *                   "http_body" (await request.body() call),
 *                   "http_body_param" (the bytes Body(...) upload parameter
 *                   of register_custom_connector_template),
 *                   "http_url" (request.url attribute read),
 *                   "http_url_part" (request.url.path/.hostname attribute
 *                   reads),
 *                   "http_request_field" (request.method/.client attribute
 *                   reads),
 *                   "http_scope_path" (request.scope["path"] subscript),
 *                   "handler_param" (the request: Request parameter of the
 *                   catchall handler read_other_paths),
 *                   "env" (getenv/os.getenv config/credentials path
 *                   selection - operator trust level),
 *                   "cli_param" (click command parameters with path
 *                   semantics - operator trust level)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "request"/"request.headers"/"request.url"/
 *                   "os" etc., or "" if none; "" for parameter rows -
 *                   the enclosing function is reported via callable)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hint "os" for the env channel
 *   7. arg_index  - 0-based positional argument index (index of the key
 *                   argument for keyed reads such as path_params[key],
 *                   scope[key] and headers.get(key); -1 when the tainted
 *                   value is the return value or the attribute itself;
 *                   the parameter position in the function definition for
 *                   "http_body_param", "handler_param" and "cli_param"
 *                   rows - module-level click command functions, so the
 *                   ctx parameter occupies position 0)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no source row is expected to resolve at API level:
 * the request-object reads flow through instance/local attribute shapes on
 * the starlette Request (fastapi/starlette are external libraries not part
 * of the database - only the src/fides tree is), getenv is a stdlib name,
 * and the parameter rows are plain definitions. All families below are
 * AST-level matches and the match_kind column is kept "ast" for
 * cross-project contract consistency with the prior projects of this series
 * (aiohttp/airflow/ansible/coderedcms/copyparty/dfetch/django).
 *
 * Receiver-name scoping: the http families match attribute chains whose base
 * local name is exactly "request" - the SaaS connector request objects use
 * different local names (current_request in saas_util.py, prepared_request
 * in authenticated_client.py) and are deliberately NOT matched.
 *
 * Excluded paths (applied to every row, in addition to the positive scope):
 * /fides-db/ (the CodeQL database directory sits inside the source tree),
 * /src/fides/_version.py (versioneer-generated). Positive scope
 * %/src/fides/%: root-level tests/, clients/ (TypeScript frontends), docs/,
 * scripts/, noxfile.py/noxfiles/, setup.py, versioneer.py are never
 * candidates.
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
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: the catchall admin-UI route path variable:
     request.path_params["catchall"] - main.py:160 inside read_other_paths
     (the @app.get("/{catchall:path}") route at :154 - the ONLY route of
     the ~176 registrations with a path variable). The value drives
     match_route(get_ui_file_map(), path) (:163) and the fallback
     get_path_to_admin_ui_file(path) (:167 -> ui.py:42
     package_path / ADMIN_UI_DIRECTORY / path), then is_file (:170),
     path_is_in_ui_directory (:171) and FileResponse (:180). Index
     argument 0 carries the key. */
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "path_params" and
    base.getObject().(Name).getId() = "request" and
    node = s and
    flowKind = "http_path_param" and
    callableName = "path_params" and
    argIndex = 0 and
    receiver = "request" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 2: request header reads: request.headers.get(key) calls -
     main.py:64 (X-Fides-Source analytics), middleware.py:39
     (authorization, audit middleware), privacy_notice_endpoints.py:92/:191,
     privacy_experience_endpoints.py:168,
     privacy_experience_config_endpoints.py:86/:214
     (UNESCAPE_SAFESTR_HEADER consent flags),
     privacy_preference_endpoints.py:244/:245 (User-Agent/Referer consent
     reporting), dataset_endpoints.py:309 (content-type yaml gate).
     Argument 0 carries the header name. */
  exists(Call c, Attribute func, Attribute headers |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    headers = func.getObject().(Attribute) and
    headers.getName() = "headers" and
    headers.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "http_header" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "request.headers" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: the bare request.headers attribute read -
     privacy_preference_endpoints.py:242
     (request_headers = request.headers, then .get("User-Agent")/...
     at :244/:245 which family 2 already captures). The attribute VALUE
     carries the header mapping, hence argIndex -1. */
  exists(Attribute a |
    a.getName() = "headers" and
    a.getObject().(Name).getId() = "request" and
    node = a and
    flowKind = "http_header" and
    callableName = "headers" and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 4: the raw request body boundary: await request.body() calls -
     middleware.py:45 (set_body(request, await request.body()) inside
     handle_audit_log_resource - the audit-log resource middleware reading
     every non-GET request body for fides_key extraction), middleware.py:124
     (body = await request.body() inside get_body) and
     dataset_endpoints.py:314 (body = await request.body() inside
     patch_yaml_datasets - the application/yaml dataset PATCH handler,
     yaml.safe_load(body) at :316). The return value carries the body
     bytes, hence argIndex -1. The Await wrapper is transparent - the
     Call node is the inner expression. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "body" and
    func.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "http_body" and
    callableName = "body" and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5: the zip upload body parameter: the
     file: bytes = Body(..., media_type="application/zip") parameter of
     register_custom_connector_template (saas_config_endpoints.py:363,
     route at :358 with the CONNECTOR_TEMPLATE_REGISTER oauth scope) -
     the ONLY file-upload endpoint of the codebase; the raw zip bytes are
     parsed in memory via ZipFile(BytesIO(file), "r") at :378 (the sink
     side is captured by the zip_ctor/zip_read sink rows). Parameter
     position 0. */
  exists(Function f, Parameter p |
    f.getName() = "register_custom_connector_template" and
    normalizedPathOf(f).matches("%/src/fides/api/api/v1/endpoints/saas_config_endpoints.py") and
    p.getName() = "file" and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "http_body_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 6: request URL metadata: request.url attribute reads -
     main.py:66 (the endpoint f-string of the analytics middleware).
     The attribute VALUE carries the full request URL. */
  exists(Attribute a |
    a.getName() = "url" and
    a.getObject().(Name).getId() = "request" and
    node = a and
    flowKind = "http_url" and
    callableName = "url" and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 7: request URL part reads: request.url.path /
     request.url.hostname - main.py:60 (path.startswith(API_PREFIX)
     analytics gate), :76/:86 (hostname of the analytics event) and :139
     (path of the log_request middleware). The attribute VALUE carries the
     URL component. */
  exists(Attribute a, Attribute url |
    url = a.getObject().(Attribute) and
    url.getName() = "url" and
    url.getObject().(Name).getId() = "request" and
    (a.getName() = "path" or a.getName() = "hostname") and
    node = a and
    flowKind = "http_url_part" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "request.url" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 8: request scalar-field reads: request.method /
     request.client - main.py:66 (request.method in the analytics
     endpoint string) and privacy_preference_endpoints.py:243
     (request.client for consent reporting IP derivation). Not
     file-targeting; recorded for labeling completeness. */
  exists(Attribute a |
    (a.getName() = "method" or a.getName() = "client") and
    a.getObject().(Name).getId() = "request" and
    node = a and
    flowKind = "http_request_field" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 9: request scope reads: request.scope["path"] -
     middleware.py:31 (the audit-log resource path) and main.py:260 (the
     audit middleware path check). Index argument 0 carries the key. */
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "scope" and
    base.getObject().(Name).getId() = "request" and
    node = s and
    flowKind = "http_scope_path" and
    callableName = "scope" and
    argIndex = 0 and
    receiver = "request" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 10: the catchall handler parameter: the
     request: Request parameter of read_other_paths (main.py:155) - the
     framework-injected boundary of the static-file serving route; the
     http_path_param family (family 1) captures the actual path value
     read one step later. Parameter position 0. */
  exists(Function f, Parameter p |
    f.getName() = "read_other_paths" and
    normalizedPathOf(f).matches("%/src/fides/api/main.py") and
    p.getName() = "request" and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "handler_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 11: environment-variable path selection: getenv(...) and
     os.getenv(...) - config/__init__.py:197
     (env_config_path = getenv(DEFAULT_CONFIG_PATH_ENV_VAR) -> toml.load
     at :201), config/helpers.py:30 (os.getenv("FIDES__CONFIG_PATH")
     inside the load_file search list) and core/utils.py:171
     (getenv("FIDES_CREDENTIALS_PATH", ...) selecting the CLI credentials
     file). OPERATOR-trust level: environment configuration, not request
     data - recorded for labeling to classify. Argument 0 carries the
     variable name. Both the bare Name form (from os import getenv) and
     the qualified os.getenv form are matched. */
  (
    exists(Call c |
      c.getFunc().(Name).getId() = "getenv" and
      node = c and
      flowKind = "env" and
      callableName = "getenv" and
      argIndex = 0 and
      receiver = "" and
      moduleHint = "os" and
      matchKind = "ast"
    )
    or
    exists(Call c, Attribute func |
      func = c.getFunc().(Attribute) and
      func.getName() = "getenv" and
      func.getObject().(Name).getId() = "os" and
      node = c and
      flowKind = "env" and
      callableName = "getenv" and
      argIndex = 0 and
      receiver = "os" and
      moduleHint = "os" and
      matchKind = "ast"
    )
  )
  or
  /* family 12: CLI parameter boundary: click command parameters with path
     semantics - fides_dir (ungrouped.py init:126 -> create_config_file ->
     os.mkdir/open), manifests_dir (ungrouped.py push:203 / evaluate:247 /
     parse:304 -> get_manifest_list glob + fideslang ingest_manifests),
     input_filename (annotate.py annotate_dataset -> ingest_manifests /
     write_manifest), output_filename (generate.py generate_dataset_db /
     bigquery / dynamodb / generate_system_* -> write_dataset_manifest),
     keyfile_path (generate.py generate_dataset_bigquery:91 ->
     handle_bigquery_config_options -> open at cli/utils.py:361) and
     env_file (deploy.py up:59 - docker compose env file). OPERATOR-trust
     level: the CLI user owns the tree being read/written - recorded for
     labeling to classify, not automatically attacker sources. Parameter
     positions are 0-based (module-level click command functions, ctx at
     position 0; no self slot). */
  exists(Function f, Parameter p |
    normalizedPathOf(f).matches("%/src/fides/cli/%") and
    p = f.getAnArg() and
    not p.isSelf() and
    (
      p.getName() = "fides_dir"
      or p.getName() = "manifests_dir"
      or p.getName() = "input_filename"
      or p.getName() = "output_filename"
      or p.getName() = "keyfile_path"
      or p.getName() = "env_file"
    ) and
    node = p and
    flowKind = "cli_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  inScope(node.getLocation().getFile().getAbsolutePath()) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "source_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
