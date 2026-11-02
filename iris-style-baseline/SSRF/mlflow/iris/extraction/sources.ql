/**
 * @name MLflow source candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate external-input source nodes from the
 *              MLflow 2.9.2.dev0 application source for subsequent
 *              LLM labeling.
 * @id py/augur/mlflow/pass3-sources
 *
 * Plain multi-column select query (NO @kind metadata declared) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * The database contains ONLY the mlflow application package plus
 * tests (flask, requests, aiohttp, fastapi library internals are
 * external dependencies and are not present). Source candidates
 * therefore anchor on the application code, grounded in repo
 * evidence only:
 *
 *   - Flask request-object attribute reads in the tracking /
 *     model-registry / artifacts server:
 *     request.args / request.json / request.data / request.form /
 *     request.values / request.files / request.query_string /
 *     request.headers / request.cookies and the flask_request
 *     variants (mlflow/server/handlers.py:14 imports `request`
 *     from flask). Materialization points of client-controlled
 *     payloads, e.g. handlers.py:1132
 *     `args = request.args if request.method == "GET" else
 *      request.json` (deployments gateway proxy - gateway_path /
 *     json_data enter here), :547 request.query_string,
 *     :1098 request.json, :1226-1247 request.args / request.data.
 *
 *   - querystring_parser `parser.parse(query_string, ...)`
 *     calls in handlers.py (:548, :1659 and inside
 *     _get_request_message, :418) - the query-string -> dict
 *     materialization used by the get-artifact and
 *     model-versions/get-artifact handlers.
 *
 *   - _get_request_message(...) / _get_request_json(...) call
 *     sites - the protobuf/JSON request-body parsing entry used
 *     by every REST handler in handlers.py.
 *
 *   - REST handler boundary functions: handlers decorated with
 *     @catch_mlflow_exception (handlers.py:493) and the
 *     @app.route-registered view functions in
 *     mlflow/server/__init__.py:58-106.
 *
 *   - DB/registry URI content that later drives server-side
 *     fetches: run.info.artifact_uri reads (handlers.py:554/557),
 *     request_message.source reads (handlers.py:1639,
 *     _create_model_version), and self.artifact_uri reads in the
 *     artifact repositories (http_artifact_repo.py:84/117/130/
 *     142, models_artifact_repo.py, runs_artifact_repo.py, ...)
 *     - the "DB content reused into network sinks" source family.
 *
 *   - Environment configuration: os.environ.get / os.getenv reads
 *     and MLFLOW_DEPLOYMENTS_TARGET.get() /
 *     MLFLOW_TRACKING_URI.get() (handlers.py:1127 uses
 *     MLFLOW_DEPLOYMENTS_TARGET directly in the gateway proxy;
 *     environment_variables.py:81/:390 define both). Operator
 *     configuration (expected FP material for remote SSRF) kept
 *     for labeling recall.
 *
 *   - CLI boundary: click command functions in mlflow/cli.py
 *     (`mlflow run` uri parameter at index 0 -> projects/utils.py
 *     _fetch_zip_repo -> requests.get(uri) at :245).
 *
 * Verified API usage (codeql/python-all 7.1.1/7.1.2 cached under
 * C:\Users\lzh\.codeql\packages, same surface as the earlier
 * label-studio/django/calibre-web/core SSRF runs):
 *   - Attribute.getObject() is bound to Name via equality before
 *     getId() comparisons; Attribute.getName() gives the attr name.
 *   - Call.getFunc() / getPositionalArg(int) / Keyword.getArg() /
 *     Keyword.getValue() for call shapes.
 *   - Function.getADecorator() returns decorator Expr (there is no
 *     Decorator AST type in Python CodeQL).
 *   - Parameter names are read via p.asName().getId(); Parameter
 *     positions come from f.getArg(i).
 *   - moduleHint is bound via getScope().getEnclosingModule().
 *     getName(); the variable is named moduleHint because
 *     `module` is a QL keyword.
 *   - Locations use AstNode.getLocation().getFile().
 *     getRelativePath() and getLocation().getStartLine(); there is
 *     no AstNode.getFile() predicate.
 *
 * Scope: path.matches("mlflow/%") - this cannot match the nested
 * "mlflow-db/" CodeQL database directory (hyphen vs slash at
 * position 7) nor the top-level tests/ directory. mlflow/R/% (R
 * flavor package) and mlflow/java/% (Java flavor assets) are
 * additionally excluded.
 *
 * Output columns (same order as the earlier SSRF runs):
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("source_candidate")
 *  3. callable name       (dotted signature hint)
 *  4. flow kind           (param | return | field)
 *  5. receiver hint       (receiver/type hint)
 *  6. module hint         (dotted module path; variable named
 *                          moduleHint, "module" is a QL keyword)
 *  7. argument index      (-1 when not applicable)
 *  8. line
 *  9. file:line
 * 10. expression text
 */

import python

// ------------------------------------------------------------
// 1. Scope and location helpers
// ------------------------------------------------------------

/**
 * Restrict extraction to the mlflow application package.
 *
 * The CodeQL database source root is the repository root, so
 * relative paths of application files look like
 * "mlflow/server/handlers.py". "mlflow/%" cannot match the nested
 * "mlflow-db/" database directory ('-' vs '/' at position 7) or
 * the top-level tests/ directory. The R and Java flavor packages
 * contain no Python ASTs but are excluded explicitly for clarity.
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("mlflow/%") and
    not path.matches("mlflow/R/%") and
    not path.matches("mlflow/java/%") and
    not path.matches("mlflow/%/tests/%")
  )
}

/**
 * Restrict a candidate to one application module. The path string
 * is bound by equality before any comparison, so no
 * unbound-variable error can occur.
 */
predicate inModule(AstNode n, string relPath) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path = relPath
  )
}

/**
 * Server boundary modules where flask/fastapi request-object
 * reads are untrusted input: the tracking server handlers
 * (mlflow/server/handlers.py, where `request` is imported from
 * flask at :14), the optional auth layer
 * (mlflow/server/auth/__init__.py, which reads request.args /
 * request.json at :139/:141 and request.form at :748-749), and
 * the deployments server app
 * (mlflow/deployments/server/app.py, fastapi Request - the
 * _custom endpoint returns request.json() at :105).
 */
predicate inServerBoundaryModule(AstNode n) {
  inModule(n, "mlflow/server/handlers.py")
  or
  inModule(n, "mlflow/server/auth/__init__.py")
  or
  inModule(n, "mlflow/deployments/server/app.py")
}

/** Dotted module name of a candidate. */
string moduleOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
}

/** Human-readable file and line location. */
string locationOf(AstNode n) {
  result =
    n.getLocation().getFile().getRelativePath() +
    ":" +
    n.getLocation().getStartLine().toString()
}

// ------------------------------------------------------------
// 2. Request-shape signatures (verified against this source)
// ------------------------------------------------------------

/**
 * flask request.<field> names whose contents originate from the
 * HTTP client (query string, JSON body, form data, raw body,
 * uploaded files, headers, cookies). Observed in
 * mlflow/server/handlers.py: request.args (:1132, :1226),
 * request.json (:1132, :1098), request.data (:1247),
 * request.query_string (:547, :412). `method` / `url_rule` /
 * `content_length` are request metadata, not payload data, and
 * are excluded; headers/cookies are included per the flask.md
 * reference cues (low-count but genuine client input).
 */
predicate isClientRequestField(string name) {
  name in [
    "args",
    "json",
    "data",
    "form",
    "values",
    "files",
    "query_string",
    "headers",
    "cookies"
  ]
}

/**
 * MLflow environment variables that directly parameterize
 * outbound network targets (definitions at
 * mlflow/environment_variables.py:81 and :390). Only these two
 * names are matched so that generic `.get()` calls elsewhere do
 * not produce noise; other env reads are covered by the
 * os.environ.get / os.getenv clauses below.
 */
predicate isNetworkTargetEnvVariable(string name) {
  name in ["MLFLOW_DEPLOYMENTS_TARGET", "MLFLOW_TRACKING_URI"]
}

/**
 * Restrict a candidate to the artifact repository package. The
 * path string is bound by equality before the matches() filter,
 * so no unbound-variable error can occur.
 */
predicate inArtifactRepoModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("mlflow/store/artifact/%")
  )
}

// ------------------------------------------------------------
// 3. Candidate extraction
// ------------------------------------------------------------

from
  AstNode n,
  string callableName,
  string flowKind,
  string receiverHint,
  string moduleHint,
  int argIndex
where
  inAnalysisScope(n) and
  moduleHint = moduleOf(n) and
  (
    // --------------------------------------------------------
    // (1) request.<field> reads on a `request` name in the server
    //     boundary modules, e.g. mlflow/server/handlers.py:1132
    //     `args = request.args if request.method == "GET" else
    //      request.json` - the deployments gateway-proxy entry
    //     whose `gateway_path` / `json_data` keys feed
    //     requests.request(..., f"{target_uri}/{gateway_path}")
    //     at :1143; :547 request.query_string (get-artifact);
    //     :1098 request.json (search-datasets);
    //     :1226-1247 request.args / request.data
    //     (upload-artifact); mlflow/server/auth/__init__.py:139/
    //     :141/:748-749 (optional auth layer input);
    //     mlflow/deployments/server/app.py:105 request.json()
    //     (fastapi _custom endpoint). The Attribute node itself
    //     is the materialization of the client-controlled value,
    //     whether it is read directly, chained (.get(...)),
    //     called, or decoded.
    // --------------------------------------------------------

    exists(Attribute a, Name req |
      n = a and
      isClientRequestField(a.getName()) and
      req = a.getObject() and
      req.getId() = "request" and
      inServerBoundaryModule(a) and
      callableName = "request." + a.getName() and
      flowKind = "field" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (2) flask_request.<field> reads inside the shared request
    //     parsing helpers of handlers.py:
    //     _get_request_json(flask_request=request) at :405-409
    //     uses flask_request.get_json(force=True, silent=True);
    //     _get_request_message at :410-470 reads
    //     flask_request.method / flask_request.query_string and
    //     re-parses the query string. These are the body/query
    //     materialization for ALL /api/2.0 REST handlers.
    // --------------------------------------------------------

    exists(Attribute a, Name req |
      n = a and
      isClientRequestField(a.getName()) and
      req = a.getObject() and
      req.getId() = "flask_request" and
      inModule(a, "mlflow/server/handlers.py") and
      callableName = "flask_request." + a.getName() and
      flowKind = "field" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (3) querystring_parser parser.parse(query_string, ...)
    //     calls in handlers.py (:548 get_artifact_handler,
    //     :1659 get_model_version_artifact_handler, :418 inside
    //     _get_request_message). Converts the raw client query
    //     string into the request_dict whose run_id / name /
    //     version / path / path_prefix entries drive artifact
    //     resolution and downloads.
    // --------------------------------------------------------

    exists(Call c, Attribute parse, Name parserName |
      n = c and
      parse = c.getFunc() and
      parse.getName() = "parse" and
      parserName = parse.getObject() and
      parserName.getId() = "parser" and
      inModule(c, "mlflow/server/handlers.py") and
      callableName = "querystring_parser.parser.parse" and
      flowKind = "return" and
      receiverHint = "querystring_parser.parser" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (4) _get_request_message(...) / _get_request_json(...)
    //     call sites - the protobuf/JSON request-body entry used
    //     by every REST handler in handlers.py (e.g. :579
    //     _create_experiment, :1324 _log_batch, :1627
    //     _create_model_version). The returned
    //     request_message.<field> values (source, run_id,
    //     artifact_location, ...) carry API-supplied data.
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc() and
      (
        fn.getId() = "_get_request_message" and
        callableName = "mlflow.server.handlers._get_request_message"
        or
        fn.getId() = "_get_request_json" and
        callableName = "mlflow.server.handlers._get_request_json"
      ) and
      inModule(c, "mlflow/server/handlers.py") and
      flowKind = "return" and
      receiverHint = "mlflow.server.handlers" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (5) request_message.source reads in handlers.py - the
    //     model-version source URI supplied via POST
    //     /api/2.0/mlflow/model-versions/create
    //     (_create_model_version at :1626-1648 passes
    //     request_message.source into _validate_source at :1639
    //     and into the registry store). Registry-stored sources
    //     are later fetched by
    //     /model-versions/get-artifact -> get_artifact_repository.
    // --------------------------------------------------------

    exists(Attribute a, Name rm |
      n = a and
      a.getName() = "source" and
      rm = a.getObject() and
      rm.getId() = "request_message" and
      inModule(a, "mlflow/server/handlers.py") and
      callableName = "request_message.source" and
      flowKind = "field" and
      receiverHint = "mlflow.protos.model_registry.CreateModelVersion" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (6) run.info.artifact_uri reads in handlers.py - the
    //     artifact root of a run (set at run creation from the
    //     experiment artifact_location, which is API-writable via
    //     POST /api/2.0/mlflow/experiments/create). Read at :554
    //     and :557 in get_artifact_handler, where the resulting
    //     repository performs the server-side artifact download.
    // --------------------------------------------------------

    exists(Attribute a, Attribute infoAttr, Name runName |
      n = a and
      a.getName() = "artifact_uri" and
      infoAttr = a.getObject() and
      infoAttr.getName() = "info" and
      runName = infoAttr.getObject() and
      runName.getId() = "run" and
      inModule(a, "mlflow/server/handlers.py") and
      callableName = "run.info.artifact_uri" and
      flowKind = "field" and
      receiverHint = "mlflow.entities.RunInfo.artifact_uri" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (7) self.artifact_uri reads in the artifact repositories -
    //     the constructor-stored artifact URI that selects the
    //     repository (http:// https:// -> HttpArtifactRepository,
    //     artifact_repository_registry.py:100-101) and forms the
    //     fetch URL base in http_artifact_repo.py (:84, :117,
    //     :130, :142). Reached from /get-artifact and
    //     /model-versions/get-artifact via
    //     get_artifact_repository(artifact_uri).
    // --------------------------------------------------------

    exists(Attribute a, Name selfName |
      n = a and
      a.getName() = "artifact_uri" and
      selfName = a.getObject() and
      selfName.getId() = "self" and
      inArtifactRepoModule(a) and
      callableName = "ArtifactRepository.self.artifact_uri" and
      flowKind = "field" and
      receiverHint = "mlflow.store.artifact.ArtifactRepository" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (8) REST handler boundary functions: handlers decorated
    //     with @catch_mlflow_exception - a BARE Name decorator
    //     (no call parens) applied at :543, :576, :1125, :1155,
    //     :1224, :1553, ... and to every proto handler in the
    //     HANDLERS registry, :2126-2170. These functions are the
    //     registered Flask views for /api/2.0/mlflow/* and
    //     /ajax-api/2.0/mlflow/* (the route path/method set comes
    //     from the protobuf endpoint descriptors; get_endpoints,
    //     :2115-2123). argIndex -1: the untrusted input enters
    //     via the flask `request` global rather than a Python
    //     parameter.
    // --------------------------------------------------------

    exists(Function f, Name decName |
      n = f and
      decName = f.getADecorator().(Name) and
      decName.getId() = "catch_mlflow_exception" and
      inModule(f, "mlflow/server/handlers.py") and
      callableName = "mlflow.server.handlers." + f.getName() and
      flowKind = "param" and
      receiverHint = "flask.view" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (9) @app.route-registered view functions in
    //     mlflow/server/__init__.py (:58 /health, :64 /version,
    //     :70-72 serve_artifacts -> get_artifact_handler,
    //     :76-78 serve_model_version_artifact ->
    //     get_model_version_artifact_handler,
    //     :82-84 get_metric_history_bulk_handler,
    //     :88-90 search_datasets_handler,
    //     :94-96 create_promptlab_run_handler,
    //     :99-101 serve_gateway_proxy -> gateway_proxy_handler,
    //     :104-106 serve_upload_artifact). The direct Flask
    //     route boundary of the artifact and gateway-proxy
    //     features.
    // --------------------------------------------------------

    exists(Function f, Expr decorator, Call decCall, Attribute routeAttr |
      n = f and
      decorator = f.getADecorator() and
      decCall = decorator.(Call) and
      routeAttr = decCall.getFunc().(Attribute) and
      routeAttr.getName() = "route" and
      routeAttr.getObject().(Name).getId() = "app" and
      inModule(f, "mlflow/server/__init__.py") and
      callableName = "mlflow.server." + f.getName() and
      flowKind = "param" and
      receiverHint = "flask.view" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (10) os.environ.get(...) environment reads
    //      e.g. mlflow/server/__init__.py:81-83
    //      (STATIC_PREFIX_ENV_VAR prefix for route paths),
    //      mlflow/gateway/config.py, mlflow/environment_variables.py
    //      internals. Operator configuration (expected FP
    //      material for remote SSRF); kept for labeling recall.
    // --------------------------------------------------------

    exists(Call call, Attribute method, Attribute environ, Name osName |
      n = call and
      method = call.getFunc() and
      method.getName() = "get" and
      environ = method.getObject() and
      environ.getName() = "environ" and
      osName = environ.getObject() and
      osName.getId() = "os" and
      callableName = "os.environ.get" and
      flowKind = "return" and
      receiverHint = "os.environ" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (11) os.getenv(...) environment reads
    // --------------------------------------------------------

    exists(Call call, Attribute method, Name osName |
      n = call and
      method = call.getFunc() and
      method.getName() = "getenv" and
      osName = method.getObject() and
      osName.getId() = "os" and
      callableName = "os.getenv" and
      flowKind = "return" and
      receiverHint = "os" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (12) MLFLOW_DEPLOYMENTS_TARGET.get() /
    //      MLFLOW_TRACKING_URI.get() reads
    //      (mlflow/server/handlers.py:1127
    //      target_uri = MLFLOW_DEPLOYMENTS_TARGET.get() - the
    //      gateway proxy target host; environment_variables.py:81
    //      / :390 define the variables). Operator-configured
    //      network targets: the target URI itself is expected FP
    //      material, but the row documents the host side of the
    //      proxy flow for labeling context.
    // --------------------------------------------------------

    exists(Call call, Attribute method, Name envVar |
      n = call and
      method = call.getFunc() and
      method.getName() = "get" and
      envVar = method.getObject() and
      isNetworkTargetEnvVariable(envVar.getId()) and
      callableName = envVar.getId() + ".get" and
      flowKind = "return" and
      receiverHint = "mlflow.environment_variables._EnvironmentVariable" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (13) click command functions in mlflow/cli.py - the CLI
    //      boundary (operator input, expected FP for remote SSRF
    //      but kept for recall of the `mlflow run <uri>` /
    //      `mlflow deployments` / `mlflow gateway` flows).
    //      Matches both `@cli.command()` (AliasedGroup method)
    //      and bare `@command()` forms.
    // --------------------------------------------------------

    exists(Function f, Expr decorator, Call decCall, Attribute cmdAttr |
      n = f and
      decorator = f.getADecorator() and
      decCall = decorator.(Call) and
      cmdAttr = decCall.getFunc().(Attribute) and
      cmdAttr.getName() = "command" and
      inModule(f, "mlflow/cli.py") and
      callableName = "mlflow.cli." + f.getName() and
      flowKind = "param" and
      receiverHint = "click.command" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (14) mlflow.cli.run(uri, ...) `uri` parameter at index 0
    //      (mlflow/cli.py:158) - the project URI accepted by
    //      `mlflow run`, forwarded through
    //      mlflow.projects.fetch_and_validate_project ->
    //      _fetch_project (projects/utils.py:148) ->
    //      _fetch_zip_repo (projects/utils.py:238) ->
    //      requests.get(uri) at projects/utils.py:245. The
    //      earliest function-parameter boundary of the
    //      CLI-supplied fetch URL.
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "run" and
      p.asName().getId() = "uri" and
      i = 0 and
      inModule(f, "mlflow/cli.py") and
      callableName = "mlflow.cli.run.uri" and
      flowKind = "param" and
      receiverHint = "mlflow.cli" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (15) dataset-source HTTP URL boundary:
    //      HTTPDatasetSource._resolve(cls, raw_source) in
    //      mlflow/data/http_dataset_source.py:109 accepts the
    //      raw URL supplied by user code via
    //      mlflow.data.from_... APIs, and the class stores it as
    //      self._url (used by load() at :60-72 ->
    //      cloud_storage_http_request(method="GET",
    //      url=self.url)). `raw_source` sits at parameter index 1
    //      (cls counts as 0).
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "_resolve" and
      p.asName().getId() = "raw_source" and
      i = 1 and
      inModule(f, "mlflow/data/http_dataset_source.py") and
      callableName = "HTTPDatasetSource._resolve.raw_source" and
      flowKind = "param" and
      receiverHint = "mlflow.data.http_dataset_source.HTTPDatasetSource" and
      argIndex = i
    )
  )

select
  n,
  "source_candidate",
  callableName,
  flowKind,
  receiverHint,
  moduleHint,
  argIndex,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()
