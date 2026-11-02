
/**
 * @name Label Studio source candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate external-input source nodes from the
 *              Label Studio 1.5.0dev application source for subsequent
 *              LLM labeling.
 * @id py/augur/label-studio/pass3-sources
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * This database contains ONLY the label_studio application package
 * (Django + DRF framework code itself is an external dependency and is
 * not present). Source candidates therefore anchor on:
 *   - DRF request-object attribute reads (request.data / .FILES /
 *     .query_params / .GET / .POST / .META / .body and the
 *     self.request.<field> variants) - the materialization of
 *     client-controlled POST/GET payloads;
 *   - the proven direct URL entry: request.data.get('url') at
 *     data_import/uploader.py:162 -> tasks_from_url(..., url) whose
 *     `url` parameter is extracted (positional index 3);
 *   - API-writable model-field reads that later reach outbound network
 *     calls (Webhook.url / Webhook.headers, MLBackend self.url, S3
 *     self.s3_endpoint, Redis self.host/.port/.password) - the
 *     "DB content reused into sinks" source family;
 *   - serializer-carried ML backend URL entry
 *     (MLBackendSerializer.validate_url(value) parameter and
 *     attrs['url'] subscript in ml/serializers.py);
 *   - environment reads (get_env(...), os.environ.get(...),
 *     os.getenv(...)) and CLI boundary (sys.argv).
 *
 * Verified API usage (codeql/python-all 7.1.2, same surface as the
 * earlier django/calibre-web/core SSRF runs):
 *   - Parameter is a Name-or-Tuple AST node; parameter names are read
 *     via p.asName().getId().
 *   - Parameter positions include `self` as index 0 for methods
 *     (MLBackendSerializer.validate_url(self, value) -> value at 1);
 *     tasks_from_url is a module-level function without self, so its
 *     `url` parameter sits at index 3
 *     (file_upload_ids=0, project=1, request=2, url=3).
 *   - Attribute.getObject() returns the object expression; it is bound
 *     to Name via equality before getId() comparisons.
 *   - StringLiteral.getText() returns the literal source text with
 *     quotes, so 'url' subscripts are matched against "'url'".
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("source_candidate")
 *  3. callable name       (dotted signature hint)
 *  4. flow kind           (param | return | field)
 *  5. receiver hint       (receiver/type hint)
 *  6. module hint         (dotted module path; variable named moduleHint,
 *                          "module" is a QL keyword and must not be used)
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
 * Restrict extraction to the label_studio application package.
 *
 * The CodeQL database source root is the repository root, so relative
 * paths of application files look like "label_studio/ml/api.py".
 * "label_studio/%" cannot match the nested "label-studio-db/" database
 * directory ('-' vs '_' at position 6). Tests, examples, and generated
 * migrations are additionally excluded.
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("label_studio/%") and
    not path.matches("label_studio/tests/%") and
    not path.matches("label_studio/%/tests.py") and
    not path.matches("label_studio/%/migrations/%") and
    not path.matches("label_studio/%/examples/%")
  )
}

/**
 * Restrict a candidate to one application module. The path string is
 * bound by equality before any comparison, so no unbound-variable
 * error can occur.
 */
predicate inModule(AstNode n, string relPath) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path = relPath
  )
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
 * request.<field> fields whose contents originate from the HTTP
 * client (POST body, query string, form data, headers, files).
 * Observed non-test usage counts in this repo: data 41, GET 42,
 * query_params 13, POST 5, META 4, FILES 4, body 1. `user` (121) and
 * `session` (11) are identity/server-side state, NOT data input, and
 * are excluded.
 */
predicate isClientRequestField(string name) {
  name in [
    "data",
    "FILES",
    "query_params",
    "GET",
    "POST",
    "META",
    "body"
  ]
}

/**
 * API-writable model fields on storage/ML/webhook models whose values
 * later reach outbound network calls. Only the field names actually
 * read in the specific modules listed below are matched; the module
 * restriction prevents accidental matches of same-named attributes in
 * unrelated classes.
 */
predicate isWebhookDataField(string name) {
  name in ["url", "headers"]
}

predicate isRedisConnectionField(string name) {
  name in ["host", "port", "password"]
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
    // (1) request.<field> reads on a `request` name
    //     e.g. data_import/uploader.py:162
    //          `url = request.data.get('url')` (the primary URL
    //          entry for the urlopen import sink),
    //          uploader.py:150 `request.FILES`, :160
    //          `request.content_type`, data_import/api.py:209
    //          load_tasks(request, project)
    //     The Attribute node itself is the materialization of the
    //     client-controlled value, whether it is read directly,
    //     chained (.get(...)), or subscripted.
    // --------------------------------------------------------

    exists(Attribute a, Name req |
      n = a and
      isClientRequestField(a.getName()) and
      req = a.getObject() and
      req.getId() = "request" and
      callableName = "request." + a.getName() and
      flowKind = "field" and
      receiverHint = "rest_framework.request.Request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (2) self.request.<field> reads (class-based API views)
    //     e.g. data_import/api.py:273 `self.request.data`,
    //          :301 `self.request.data.get('file_upload_ids')`,
    //          :394 `self.request.query_params.get('ids')`,
    //          io_storages/api.py:30, ml/api.py:88
    //          `self.request.query_params.get('project')`
    // --------------------------------------------------------

    exists(Attribute a, Attribute reqAttr, Name selfName |
      n = a and
      isClientRequestField(a.getName()) and
      reqAttr = a.getObject() and
      reqAttr.getName() = "request" and
      selfName = reqAttr.getObject() and
      selfName.getId() = "self" and
      callableName = "request." + a.getName() and
      flowKind = "field" and
      receiverHint = "rest_framework.request.Request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (3) tasks_from_url(file_upload_ids, project, request, url)
    //     `url` parameter, label_studio/data_import/uploader.py:114
    //     (module-level function, self not counted -> index 3).
    //     Proven caller: load_tasks (same module, line 177) passes
    //     the value of `request.data.get('url')` (line 162) straight
    //     through; tasks_from_url forwards it to urlopen(url) at
    //     line 123. This is the earliest function-parameter boundary
    //     of the client URL on the import-by-URL flow.
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "tasks_from_url" and
      p.asName().getId() = "url" and
      i = 3 and
      inModule(f, "label_studio/data_import/uploader.py") and
      callableName = "tasks_from_url.url" and
      flowKind = "param" and
      receiverHint = "data_import.uploader" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (4) webhook.url / webhook.headers attribute reads in
    //     label_studio/webhooks/utils.py (run_webhook, lines 25-26:
    //     `requests.post(webhook.url, headers=webhook.headers,
    //      json=data, ...)`).
    //     Webhook.url (models.URLField, webhooks/models.py:42) and
    //     Webhook.headers (models.JSONField, :56) are written by any
    //     authenticated organization member via POST/PATCH
    //     /api/webhooks (WebhookSerializer fields, no local-IP
    //     validation). DB content reused into a network sink.
    // --------------------------------------------------------

    exists(Attribute a, Name wh |
      n = a and
      isWebhookDataField(a.getName()) and
      wh = a.getObject() and
      wh.getId() = "webhook" and
      inModule(a, "label_studio/webhooks/utils.py") and
      callableName = "webhook." + a.getName() and
      flowKind = "field" and
      receiverHint = "webhooks.models.Webhook" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (5) self.url attribute reads in label_studio/ml/models.py -
    //     MLBackend.url (models.TextField, ml/models.py:48-49),
    //     written via POST/PATCH /api/ml (MLBackendSerializer,
    //     url_is_local guard only when settings.ML_BLOCK_LOCAL_IP).
    //     Read at lines 116 (healthcheck -> healthcheck_(self.url)),
    //     119 (setup -> setup_(self.url, ...)),
    //     123 (api -> MLApi(url=self.url, ...)),
    //     309/314 (get_versions_ / get_versions), and consumed by
    //     the requests.Session.request transport in
    //     ml/api_connector.py. DB content reused into a network sink.
    // --------------------------------------------------------

    exists(Attribute a, Name selfName |
      n = a and
      a.getName() = "url" and
      selfName = a.getObject() and
      selfName.getId() = "self" and
      inModule(a, "label_studio/ml/models.py") and
      callableName = "MLBackend.self.url" and
      flowKind = "field" and
      receiverHint = "ml.models.MLBackend" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (6) MLBackendSerializer.validate_url(self, value) `value`
    //     parameter at index 1 (self counts as 0) in
    //     label_studio/ml/serializers.py:9-14 - receives the POSTed
    //     'url' field of /api/ml requests directly; first
    //     application-level hop of ML backend URLs (guard:
    //     settings.ML_BLOCK_LOCAL_IP and url_is_local).
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "validate_url" and
      p.asName().getId() = "value" and
      i = 1 and
      inModule(f, "label_studio/ml/serializers.py") and
      callableName = "MLBackendSerializer.validate_url.value" and
      flowKind = "param" and
      receiverHint = "ml.serializers.MLBackendSerializer" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (7) attrs['url'] subscript reads in
    //     label_studio/ml/serializers.py (validate(), line 19:
    //     `url = attrs['url']`) - validated serializer data carrying
    //     the POSTed ML backend URL; feeds healthcheck_/setup_ calls
    //     in the same validate() body (lines 14-20).
    // --------------------------------------------------------

    exists(Subscript s, Name attrName, StringLiteral idx |
      n = s and
      attrName = s.getObject() and
      attrName.getId() = "attrs" and
      idx = s.getIndex() and
      idx.getText() = "'url'" and
      inModule(s, "label_studio/ml/serializers.py") and
      callableName = "attrs['url']" and
      flowKind = "field" and
      receiverHint = "rest_framework.serializers.validate.attrs" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (8) self.s3_endpoint attribute reads in
    //     label_studio/io_storages/s3/models.py (get_client_and_
    //     resource, lines 58 and 64: cache key + argument to
    //     get_client_and_resource(...)). S3ImportStorage/
    //     S3ExportStorage.s3_endpoint (models.TextField, :52-53) is
    //     written via POST /api/storages/s3 (projects_change
    //     permission) and becomes boto3's endpoint_url in
    //     io_storages/s3/utils.py:37-41. DB content reused into a
    //     network client construction.
    // --------------------------------------------------------

    exists(Attribute a, Name selfName |
      n = a and
      a.getName() = "s3_endpoint" and
      selfName = a.getObject() and
      selfName.getId() = "self" and
      inModule(a, "label_studio/io_storages/s3/models.py") and
      callableName = "S3Storage.self.s3_endpoint" and
      flowKind = "field" and
      receiverHint = "io_storages.s3.models.S3ImportStorage" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (9) self.host / self.port / self.password attribute reads in
    //     label_studio/io_storages/redis/models.py get_client
    //     (lines 66-70: `if self.host: redis_config["host"] =
    //      self.host` ...) feeding redis.StrictRedis(**redis_config)
    //     at line 57. Fields are models.TextField (lines 21-31),
    //     written via POST /api/storages/redis. Non-HTTP network
    //     connection parameters. DB content reused into a network
    //     client construction.
    // --------------------------------------------------------

    exists(Attribute a, Name selfName |
      n = a and
      isRedisConnectionField(a.getName()) and
      selfName = a.getObject() and
      selfName.getId() = "self" and
      inModule(a, "label_studio/io_storages/redis/models.py") and
      callableName = "RedisStorage.self." + a.getName() and
      flowKind = "field" and
      receiverHint = "io_storages.redis.models.RedisImportStorage" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (10) get_env(...) calls - the environment boundary wrapper in
    //      label_studio/core/utils/params.py:102-110 (reads
    //      os.environ.get('LABEL_STUDIO_'|'HEARTEX_'|name)).
    //      Relevant network-facing uses: io_storages/s3/utils.py:22-
    //      37 (AWS credentials, S3_ENDPOINT -> boto3 endpoint_url)
    //      and ml/api_connector.py:25-34 (ML timeouts). Env values
    //      are operator configuration (expected FP material for
    //      remote SSRF) but kept for labeling recall.
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc() and
      fn.getId() = "get_env" and
      callableName = "core.utils.params.get_env" and
      flowKind = "return" and
      receiverHint = "label_studio.core.utils.params" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (11) os.environ.get(...) environment reads
    //      e.g. core/utils/params.py:104 (inside get_env itself)
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
    // (12) os.getenv(...) environment reads
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
    // (13) sys.argv reads - CLI boundary
    //      label_studio/server.py:269
    //      `input_args = parse_input_args(sys.argv[1:])`,
    //      label_studio/manage.py:22
    //      `execute_from_command_line(sys.argv)`.
    //      Operator input (expected FP for remote SSRF); kept for
    //      labeling recall of the CLI startup flows.
    // --------------------------------------------------------

    exists(Attribute a, Name sysName |
      n = a and
      a.getName() = "argv" and
      sysName = a.getObject() and
      sysName.getId() = "sys" and
      callableName = "sys.argv" and
      flowKind = "field" and
      receiverHint = "sys" and
      argIndex = -1
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
