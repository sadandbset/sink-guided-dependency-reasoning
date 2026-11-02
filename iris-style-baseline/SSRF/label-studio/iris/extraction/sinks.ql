
/**
 * @name Label Studio sink candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate outbound-network request call sites
 *              from the Label Studio 1.5.0dev application source for
 *              subsequent LLM labeling.
 * @id py/augur/label-studio/pass3-sinks
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * Only server-side network call sites that exist in this source tree
 * are extracted. This database contains ONLY the label_studio
 * application package; requests / boto3 / redis-py library internals
 * are not present, so HTTP sinks anchor on the application-level call
 * sites. The complete list of genuine outbound-network sites:
 *
 *   - urlopen(url, context=ctx)
 *     label_studio/data_import/uploader.py:123 (tasks_from_url)
 *     URL = request.data.get('url') from POST
 *     /api/projects/{pk}/import; SSL verification disabled; optional
 *     url_is_local guard gated by settings.SSRF_PROTECTION_ENABLED
 *
 *   - requests.post(webhook.url, headers=webhook.headers, ...)
 *     label_studio/webhooks/utils.py:24 (run_webhook) - Webhook
 *     url/headers written by any organization member via /api/webhooks
 *
 *   - self.http.request(method, *args, **kwargs)
 *     label_studio/ml/api_connector.py:83 (BaseHTTPAPI.request) -
 *     requests.Session.request transport for ALL ML backend traffic
 *     (health/train/predict/setup/validate/versions); URL arrives via
 *     **kwargs (keyword `url=`) from MLApi._request; base URL is
 *     MLBackend.url written via /api/ml
 *
 *   - requests.get(pypi_url, timeout=10)
 *     label_studio/core/utils/common.py:362 (get_latest_version) -
 *     hardcoded https://pypi.org endpoint (FP material)
 *
 *   - requests.post(url=url, json=payload, timeout=3.0)
 *     label_studio/core/utils/contextlog.py:177 (send_job) - URL is
 *     the literal 'https://tele.labelstud.io' (keyword form, FP
 *     material)
 *
 *   - requests.get(url, verify=False)
 *     label_studio/core/utils/windows_sqlite_fix/__init__.py:26 -
 *     hardcoded https://www.sqlite.org/2021/... at Windows startup
 *     (FP material)
 *
 *   - session.client('s3', ...)/session.resource('s3', ...)
 *     label_studio/io_storages/s3/utils.py:40-41 - boto3 S3 client
 *     construction; endpoint_url in **settings kwargs may come from
 *     the API-writable S3ImportStorage.s3_endpoint field or the
 *     S3_ENDPOINT env; actual network I/O inside boto3 (not in this
 *     database) - NON-HTTP-via-boto3 family, recorded separately
 *
 *   - redis.StrictRedis(db=..., **redis_config)
 *     label_studio/io_storages/redis/models.py:57 - host/port in
 *     **redis_config from API-writable model fields - non-HTTP
 *     network connection, recorded separately
 *
 * Things deliberately NOT extracted as CWE-918 sinks:
 *   - urllib.parse.urljoin in ml/api_connector.py:132 (_get_url):
 *     URL construction/joining only; dangerous only when tied to the
 *     real session.request transport above.
 *   - urlparse in core/utils/io.py:172, io_storages/s3/utils.py:46,
 *     gcs/models.py:132, azure_blob/models.py:113: parsing only.
 *   - GCS/Azure presigned-URL generation (blob.generate_signed_url,
 *     client.generate_presigned_url, generate_blob_sas): returns URLs
 *     to the annotating browser; the server does not fetch them.
 *   - requests.Request() at io_storages/gcs/models.py:176: object
 *     construction for google-auth signing, not network I/O.
 *   - socket.getaddrinfo('metadata.google.internal', 80) at
 *     gcs/models.py:126: fixed-host DNS probe.
 *   - socket.gethostbyname(domain) at core/utils/io.py:177: DNS
 *     lookup inside the url_is_local sanitizer guard (validation
 *     logic, not a fetch).
 *   - localfiles storage / open() calls elsewhere: local file reads
 *     (Pass 1 territory), not CWE-918 network I/O.
 *   - RedirectView / DRF redirect responses: client-side navigation
 *     (Pass 9 / CWE-601 material).
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("sink_candidate")
 *  3. callable            (dotted signature hint)
 *  4. flow kind           (argument)
 *  5. receiver            (receiver/type hint)
 *  6. module hint         (dotted module path; variable named
 *                          moduleHint, "module" is a QL keyword and
 *                          must not be used)
 *  7. argument index      (0-based positional index of the URL/host
 *                          argument; -1 when the URL travels via
 *                          keyword/**kwargs)
 *  8. line
 *  9. file:line
 * 10. expression text
 *
 * flow kind vocabulary:
 *   argument - the tainted URL/host position is an argument of the
 *              network call (positional index recorded, or -1 when
 *              the URL is passed via keyword/**kwargs)
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
// 2. Candidate extraction
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
    // (1) urlopen(<url>, ...) - urllib.request.urlopen
    //     imported via `from urllib.request import urlopen`
    //     (label_studio/data_import/uploader.py:20), single call
    //     site at line 123 inside tasks_from_url():
    //       with urlopen(url, context=ctx) as file:   # nosec
    //     URL at positional argument 0. The value is
    //     request.data.get('url') (uploader.py:162) passed through
    //     load_tasks -> tasks_from_url; the ssl context disables
    //     certificate verification (lines 118-120) and the optional
    //     url_is_local guard at line 175 is gated by
    //     settings.SSRF_PROTECTION_ENABLED.
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc() and
      fn.getId() = "urlopen" and
      inModule(c, "label_studio/data_import/uploader.py") and
      exists(Expr a0 | a0 = c.getArg(0)) and
      callableName = "urllib.request.urlopen" and
      flowKind = "argument" and
      receiverHint = "urllib.request" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (2) requests.post(<url>, ...) - python-requests POST.
    //     Genuine site: label_studio/webhooks/utils.py:24-29
    //       requests.post(webhook.url, headers=webhook.headers,
    //                     json=data, timeout=...)
    //     inside run_webhook() - webhook delivery of organization-
    //     member-writable URLs (positional argument 0). The second
    //     in-scope site, core/utils/contextlog.py:177
    //       requests.post(url=url, json=payload, timeout=3.0)
    //     passes the URL as keyword `url` (a hardcoded literal) and
    //     is captured by the keyword-form branch below with
    //     argIndex = -1. Only these two requests.post call sites
    //     exist in non-test application code.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name reqModule |
      n = c and
      fn = c.getFunc() and
      fn.getName() = "post" and
      reqModule = fn.getObject() and
      reqModule.getId() = "requests" and
      (
        // positional URL form: webhooks/utils.py:24
        exists(Expr a0 |
          a0 = c.getArg(0) and
          argIndex = 0
        )
        or
        // keyword-only form (no positional args): contextlog.py:177
        (not exists(Expr a0 | a0 = c.getArg(0)) and
         argIndex = -1)
      ) and
      callableName = "requests.post" and
      flowKind = "argument" and
      receiverHint = "requests"
    )

    or

    // --------------------------------------------------------
    // (3) requests.get(<url>, ...) - python-requests GET.
    //     Genuine sites: core/utils/common.py:362
    //       requests.get(pypi_url, timeout=10)
    //     (get_latest_version, hardcoded pypi.org URL, positional
    //     argument 0 - FP material) and
    //     core/utils/windows_sqlite_fix/__init__.py:26
    //       requests.get(url, verify=False)
    //     (startup sqlite-dll download from a fixed sqlite.org URL,
    //     positional argument 0 - FP material). No other non-test
    //     requests.get call sites exist in application code.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name reqModule |
      n = c and
      fn = c.getFunc() and
      fn.getName() = "get" and
      reqModule = fn.getObject() and
      reqModule.getId() = "requests" and
      (
        // positional URL form: common.py:362,
        // windows_sqlite_fix/__init__.py:26
        exists(Expr a0 |
          a0 = c.getArg(0) and
          argIndex = 0
        )
        or
        // keyword-only form (no positional args)
        (not exists(Expr a0 | a0 = c.getArg(0)) and
         argIndex = -1)
      ) and
      callableName = "requests.get" and
      flowKind = "argument" and
      receiverHint = "requests"
    )

    or

    // --------------------------------------------------------
    // (4) self.http.request(method, *args, **kwargs) - the
    //     requests.Session.request transport for ALL ML backend
    //     traffic, label_studio/ml/api_connector.py:81-83
    //     (BaseHTTPAPI.request). Callers: MLApi.get/post (lines
    //     85-89) invoked from MLApi._request (lines 134-163) with
    //     url=... keyword; the base URL is MLBackend.url (written
    //     via /api/ml) joined with fixed suffixes in _get_url
    //     (urllib.parse.urljoin, line 132). The URL travels through
    //     **kwargs, so no positional argument index applies:
    //     argIndex = -1 (keyword `url`). Restricted to the
    //     api_connector module to avoid matching unrelated
    //     `<something>.request(...)` attribute calls elsewhere.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Attribute httpAttr, Name selfName |
      n = c and
      fn = c.getFunc() and
      fn.getName() = "request" and
      httpAttr = fn.getObject() and
      httpAttr.getName() = "http" and
      selfName = httpAttr.getObject() and
      selfName.getId() = "self" and
      inModule(c, "label_studio/ml/api_connector.py") and
      callableName = "requests.Session.request" and
      flowKind = "argument" and
      receiverHint = "ml.api_connector.BaseHTTPAPI.http" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (5) session.client('s3', ...) / session.resource('s3', ...)
    //     - boto3 S3 client construction,
    //     label_studio/io_storages/s3/utils.py:29-41
    //       session = boto3.Session(...)
    //       client = session.client('s3', config=..., **settings)
    //       resource = session.resource('s3', config=..., **settings)
    //     where settings['endpoint_url'] = s3_endpoint (lines 37-39)
    //     when supplied - s3_endpoint comes from the API-writable
    //     S3ImportStorage/S3ExportStorage.s3_endpoint model field
    //     (POST /api/storages/s3) or the S3_ENDPOINT environment
    //     variable. The endpoint travels via **settings kwargs, so
    //     argIndex = -1 (keyword endpoint_url). The actual network
    //     I/O happens inside boto3/botocore (not part of this
    //     database); this call site is where the attacker-influenced
    //     endpoint value enters the network client. Restricted to
    //     the s3/utils module.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name sessionVar |
      n = c and
      fn = c.getFunc() and
      (fn.getName() = "client" or fn.getName() = "resource") and
      sessionVar = fn.getObject() and
      sessionVar.getId() = "session" and
      inModule(c, "label_studio/io_storages/s3/utils.py") and
      callableName = "boto3.Session." + fn.getName() and
      flowKind = "argument" and
      receiverHint = "io_storages.s3.utils" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (6) redis.StrictRedis(db=..., **redis_config) - non-HTTP
    //     network connection construction,
    //     label_studio/io_storages/redis/models.py:57
    //       r = redis.StrictRedis(db=db, charset="utf-8",
    //                              decode_responses=True,
    //                              **redis_config)
    //     (followed by r.ping() at line 59). redis_config is built
    //     in get_client (lines 66-70) from the API-writable
    //     self.host/self.port/self.password model fields (POST
    //     /api/storages/redis). Host/port travel via
    //     **redis_config, so argIndex = -1 (keywords host/port).
    //     Redis is not HTTP(S); recorded separately from the HTTP
    //     fetch sinks because CWE-918 primarily concerns
    //     HTTP(S)-style request forgery, while leaving the
    //     candidate available for labeling.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name redisModule |
      n = c and
      fn = c.getFunc() and
      fn.getName() = "StrictRedis" and
      redisModule = fn.getObject() and
      redisModule.getId() = "redis" and
      inModule(c, "label_studio/io_storages/redis/models.py") and
      callableName = "redis.StrictRedis" and
      flowKind = "argument" and
      receiverHint = "io_storages.redis.models.RedisStorageMixin" and
      argIndex = -1
    )
  )

select
  n,
  "sink_candidate",
  callableName,
  flowKind,
  receiverHint,
  moduleHint,
  argIndex,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()
