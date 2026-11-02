/**
 * @name MLflow sink candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate outbound-network request call
 *              sites from the MLflow 2.9.2.dev0 application source
 *              for subsequent LLM labeling.
 * @id py/augur/mlflow/pass3-sinks
 *
 * Plain multi-column select query (NO @kind metadata declared) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * Only network call sites that exist in this source tree are
 * extracted (mlflow application code only; requests / aiohttp /
 * flask / fastapi library internals are not in the database).
 * The genuine outbound-network families found in the source:
 *
 * FINAL NETWORK I/O:
 *
 *   - requests.request(request_type, f"{target_uri}/{gateway_path}",
 *     json=json_data)
 *     mlflow/server/handlers.py:1143 (gateway_proxy_handler, Flask
 *     route /ajax-api/2.0/mlflow/gateway-proxy, GET+POST) -
 *     gateway_path comes from request.args/request.json (client
 *     controlled), target_uri from the MLFLOW_DEPLOYMENTS_TARGET
 *     env var. The direct server-reachable SSRF-shaped egress.
 *
 *   - session.request(method, url, **kwargs)
 *     mlflow/utils/request_utils.py:190
 *     (_get_http_response_with_retries) - the requests.Session
 *     transport that ultimately performs EVERY mlflow rest-utils
 *     HTTP request: http_request (rest_utils.py:28, builds
 *     url = strip_suffix(host_creds.host) + endpoint at :104-105),
 *     cloud_storage_http_request (request_utils.py:193),
 *     download_chunk (request_utils.py:62, http_uri keyword).
 *
 *   - requests.get(uri)
 *     mlflow/projects/utils.py:245 (_fetch_zip_repo) - zip project
 *     fetch driven by `mlflow run <uri>` (cli.py run uri param).
 *
 *   - requests.put(credential.url, data=data, headers=...)
 *     mlflow/store/artifact/http_artifact_repo.py:157
 *     (_upload_part) - multipart upload part to a presigned URL.
 *
 *   - session.post(url, json=payload, timeout=...)
 *     mlflow/gateway/providers/utils.py:27 (send_request,
 *     aiohttp.ClientSession) - the provider transport used by
 *     every mlflow/gateway/providers/*.py; base_url comes from
 *     gateway route config (operator-configured).
 *
 *   - requests.get/post in mlflow/pyfunc/scoring_server/client.py
 *     (:46, :51, :83) and requests.post(url=...) in
 *     mlflow/openai/api_request_parallel_processor.py:104 and
 *     mlflow/openai/utils.py - client-side utilities; expected
 *     FP material for server SSRF, extracted because they exist.
 *
 * REPO-INTERNAL HTTP WRAPPERS (call sites; the LLM should decide
 * sink vs summary labels - each forwards to the
 * requests.Session.request transport above):
 *
 *   - http_request(host_creds, endpoint, method, ...)
 *     defined rest_utils.py:28; call sites:
 *     mlflow/store/artifact/http_artifact_repo.py:63, :88, :104,
 *     :113, :125, :139, :151 (artifact GET/PUT/DELETE via
 *     /get-artifact and model-version download chains),
 *     mlflow/store/artifact/dbfs_artifact_repo.py:66,
 *     mlflow/deployments/mlflow/__init__.py:130,
 *     mlflow/gateway/client.py:92.
 *   - http_request_safe(host_creds=..., endpoint=..., method=...)
 *     call site mlflow/store/artifact/dbfs_artifact_repo.py:62.
 *   - cloud_storage_http_request(method, url, ...)
 *     defined request_utils.py:193; call sites
 *     mlflow/utils/request_utils.py:65 (download_chunk, http_uri)
 *     and mlflow/data/http_dataset_source.py:70 (load,
 *     url=self.url from HTTPDatasetSource._resolve raw_source).
 *   - _get_http_response_with_retries(method, url, ...)
 *     defined request_utils.py:160; call sites inside
 *     rest_utils.py http_request (:107) and
 *     cloud_storage_http_request (:222).
 *   - call_endpoint / call_endpoints (rest_utils.py:202, :225)
 *     client-side REST API wrappers.
 *   - download_chunk(..., http_uri=...) call sites
 *     mlflow/utils/download_cloud_file_chunk.py:32,
 *     mlflow/utils/file_utils.py:760, :799 - URL travels via the
 *     http_uri keyword (argIndex -1).
 *
 * NON-HTTP REMOTE ACCESS, recorded separately (file-transfer /
 * git protocols, not canonical CWE-918 HTTP(S)):
 *   - ftp = FTP(); ftp.connect(self.config["host"],
 *     self.config["port"]) mlflow/store/artifact/ftp_artifact_
 *     repo.py:40-42 (ftp:// artifact URIs from the registry);
 *   - pysftp.Connection(**self.config)
 *     mlflow/store/artifact/sftp_artifact_repo.py:81 (sftp://);
 *   - git remote/fetch operations in mlflow/projects/utils.py
 *     _fetch_git_repo (:209-233): repo.create_remote("origin",
 *     uri) at :211 (uri at positional index 1) and origin.fetch
 *     calls - remote fetch of `mlflow run` project URIs.
 *
 * Things deliberately NOT extracted as CWE-918 sinks:
 *   - urllib.request.urlopen / urlretrieve: no call site exists
 *     in the mlflow/ package (only url2pathname / pathname2url
 *     local-path conversions, mlflow/projects/docker.py:161 and
 *     mlflow/utils/file_utils.py:630-631).
 *   - urllib.parse.urlparse / urljoin / unquote_plus in
 *     mlflow/utils/uri.py, mlflow/projects/utils.py and
 *     handlers.py:1576-1578: URL construction/parsing only.
 *   - _validate_source / _validate_non_local_source_contains_
 *     relative_paths (handlers.py:1552-1621): sanitizer logic
 *     (path-traversal oriented), not network I/O.
 *   - validate_path_is_safe (mlflow/utils/uri.py): sanitizer.
 *   - boto3 / google-cloud-storage / azure-sdk client
 *     constructions (s3_artifact_repo.py etc.): cloud SDK
 *     internals are external to this database and the URIs are
 *     bucket-based, not HTTP URLs - recorded as a coverage gap
 *     in detection.json, not as sink rows.
 *   - local artifact repository open() calls: local file I/O
 *     (Pass 1 territory), not CWE-918 network I/O.
 *
 * Output columns (same order as the earlier SSRF runs):
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("sink_candidate")
 *  3. callable            (dotted signature hint)
 *  4. flow kind           (argument)
 *  5. receiver            (receiver/type hint)
 *  6. module hint         (dotted module path; variable named
 *                          moduleHint, "module" is a QL keyword)
 *  7. argument index      (0-based positional index of the URL
 *                          argument; -1 when the URL travels via
 *                          keyword)
 *  8. line
 *  9. file:line
 * 10. expression text
 *
 * flow kind vocabulary:
 *   argument - the tainted URL/host position is an argument of
 *              the network call (positional index recorded, or
 *              -1 when the URL is passed via keyword)
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
// 2. Network-call signatures (verified against this source)
// ------------------------------------------------------------

/**
 * requests module-level verb functions actually used in the mlflow
 * tree: requests.get (projects/utils.py:245,
 * pyfunc/scoring_server/client.py:46/51), requests.post
 * (pyfunc/scoring_server/client.py:83,
 * openai/api_request_parallel_processor.py:104,
 * openai/utils.py mock machinery), requests.put
 * (http_artifact_repo.py:157), requests.request
 * (server/handlers.py:1143). `head`/`delete`/`patch` are kept in
 * the family for labeling robustness; only observed call sites
 * will be emitted anyway.
 */
predicate isRequestsVerb(string name) {
  name in ["get", "post", "put", "head", "delete", "patch", "request"]
}

/**
 * URL argument index for a requests module-level verb: 0 for the
 * simple verbs (requests.get(url, ...)), 1 for
 * requests.request(method, url, ...).
 *
 * isRequestsVerb(name) binds `name` positively (via its
 * `name in [...]`) BEFORE the `!=` comparison below - a bare
 * `name != "request"` is a negative constraint and does NOT bind
 * a variable in QL, which is why it must be guarded by a positive
 * binding first.
 */
int requestsVerbUrlIndex(string name) {
  isRequestsVerb(name) and
  (
    name = "request" and result = 1
    or
    name != "request" and result = 0
  )
}

/**
 * mlflow-internal HTTP wrapper function names whose URL/endpoint
 * parameter sits at positional index 1:
 *   http_request(host_creds, endpoint, method, ...)
 *   http_request_safe(host_creds, endpoint, method, ...)
 *   cloud_storage_http_request(method, url, ...)
 *   _get_http_response_with_retries(method, url, ...)
 *   call_endpoint(host_creds, endpoint, method, ...)
 *   call_endpoints(host_creds, endpoints, ...)
 *     (host_creds carries the URL host; the endpoint path is at
 *     index 1 - recorded as the URL-relevant position)
 */
predicate isInternalHttpWrapper(string name) {
  name in [
    "http_request",
    "http_request_safe",
    "cloud_storage_http_request",
    "_get_http_response_with_retries",
    "call_endpoint",
    "call_endpoints"
  ]
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
    // (1) requests.<verb>(url, ...) direct module-level calls
    //     e.g. mlflow/server/handlers.py:1143
    //     requests.request(request_type,
    //     f"{target_uri}/{gateway_path}", json=json_data)
    //     (deployments gateway proxy - Flask-reachable egress);
    //     mlflow/projects/utils.py:245 requests.get(uri);
    //     mlflow/store/artifact/http_artifact_repo.py:157
    //     requests.put(credential.url, ...);
    //     client-side rows: pyfunc/scoring_server/client.py
    //     :46/:51/:83, openai/api_request_parallel_processor.py
    //     :104, openai/utils.py (mock helpers - FP material).
    // --------------------------------------------------------

    exists(Call c, Attribute verb, Name requestsName |
      n = c and
      verb = c.getFunc() and
      isRequestsVerb(verb.getName()) and
      requestsName = verb.getObject() and
      requestsName.getId() = "requests" and
      callableName = "requests." + verb.getName() and
      flowKind = "argument" and
      receiverHint = "requests" and
      argIndex = requestsVerbUrlIndex(verb.getName())
    )

    or

    // --------------------------------------------------------
    // (2) session.request(method, url, **kwargs) - the
    //     requests.Session transport in
    //     mlflow/utils/request_utils.py:190
    //     (_get_http_response_with_retries). This is the final
    //     egress for ALL rest-utils traffic (http_request,
    //     cloud_storage_http_request, download_chunk funnel
    //     here). Restricted to the defining module so that
    //     unrelated `<anything>.request(...)` attribute calls
    //     elsewhere are not matched.
    // --------------------------------------------------------

    exists(Call c, Attribute method, Name sessionName |
      n = c and
      method = c.getFunc() and
      method.getName() = "request" and
      sessionName = method.getObject() and
      sessionName.getId() = "session" and
      inModule(c, "mlflow/utils/request_utils.py") and
      callableName = "requests.Session.request" and
      flowKind = "argument" and
      receiverHint = "requests.Session" and
      argIndex = 1
    )

    or

    // --------------------------------------------------------
    // (3) session.post(url, json=payload, timeout=...) - the
    //     aiohttp provider transport in
    //     mlflow/gateway/providers/utils.py:27 (send_request).
    //     base_url comes from the gateway route config
    //     (_request_base_url, providers/openai.py:20-36;
    //     operator-configured). Restricted to the defining
    //     module to avoid unrelated `<anything>.post(...)`
    //     attribute calls.
    // --------------------------------------------------------

    exists(Call c, Attribute method, Name sessionName |
      n = c and
      method = c.getFunc() and
      method.getName() = "post" and
      sessionName = method.getObject() and
      sessionName.getId() = "session" and
      inModule(c, "mlflow/gateway/providers/utils.py") and
      callableName = "aiohttp.ClientSession.post" and
      flowKind = "argument" and
      receiverHint = "aiohttp.ClientSession" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (4) mlflow-internal HTTP wrapper call sites - calls to
    //     http_request / http_request_safe /
    //     cloud_storage_http_request /
    //     _get_http_response_with_retries / call_endpoint /
    //     call_endpoints (callee is a plain Name, i.e. imported
    //     or same-module function references). Observed sites:
    //     http_artifact_repo.py:63/:88/:104/:113/:125/:139/:151,
    //     dbfs_artifact_repo.py:62/:66,
    //     deployments/mlflow/__init__.py:130,
    //     gateway/client.py:92, rest_utils.py:107/:202/:225/:238,
    //     request_utils.py:65/:222,
    //     data/http_dataset_source.py:70. URL/endpoint position
    //     is index 1 for every wrapper.
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc() and
      isInternalHttpWrapper(fn.getId()) and
      callableName = "mlflow.utils." + fn.getId() and
      flowKind = "argument" and
      receiverHint = "mlflow.http-wrapper" and
      argIndex = 1
    )

    or

    // --------------------------------------------------------
    // (5) download_chunk(..., http_uri=...) call sites - the
    //     URL travels via the `http_uri` keyword argument, so
    //     argIndex is -1. Observed sites:
    //     mlflow/utils/download_cloud_file_chunk.py:32,
    //     mlflow/utils/file_utils.py:760/:799. The wrapper
    //     definition (request_utils.py:62) funnels into
    //     cloud_storage_http_request -> Session.request.
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc() and
      fn.getId() = "download_chunk" and
      callableName = "mlflow.utils.request_utils.download_chunk" and
      flowKind = "argument" and
      receiverHint = "mlflow.http-wrapper" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (6) NON-HTTP family (recorded separately): FTP connection
    //     mlflow/store/artifact/ftp_artifact_repo.py:41
    //     ftp.connect(self.config["host"],
    //     self.config["port"]) - host at index 0. The ftp://
    //     artifact URI (host/port/user/password) comes from the
    //     experiment artifact location, which is API-writable.
    // --------------------------------------------------------

    exists(Call c, Attribute method, Name ftpName |
      n = c and
      method = c.getFunc() and
      method.getName() = "connect" and
      ftpName = method.getObject() and
      ftpName.getId() = "ftp" and
      inModule(c, "mlflow/store/artifact/ftp_artifact_repo.py") and
      callableName = "ftplib.FTP.connect" and
      flowKind = "argument" and
      receiverHint = "ftplib.FTP (non-http)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (7) NON-HTTP family (recorded separately): pysftp
    //     connection pool construction
    //     mlflow/store/artifact/sftp_artifact_repo.py:81
    //     pysftp.Connection(**self.config) - sftp:// artifact URI
    //     parameters travel via **kwargs (argIndex -1). The callee
    //     is the Attribute `pysftp.Connection`.
    // --------------------------------------------------------

    exists(Call c, Attribute ctor, Name pysftpName |
      n = c and
      ctor = c.getFunc() and
      ctor.getName() = "Connection" and
      pysftpName = ctor.getObject() and
      pysftpName.getId() = "pysftp" and
      inModule(c, "mlflow/store/artifact/sftp_artifact_repo.py") and
      callableName = "pysftp.Connection" and
      flowKind = "argument" and
      receiverHint = "pysftp.Connection (non-http)" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (8) NON-HTTP family (recorded separately): git remote
    //     registration and fetch in
    //     mlflow/projects/utils.py:_fetch_git_repo
    //     repo.create_remote("origin", uri) at :211 - the git
    //     project URI (from `mlflow run <uri>`) at index 1;
    //     origin.fetch(...) / origin.fetch(refspec=...) - remote
    //     fetch of the registered URI. Git protocol remote
    //     access, not HTTP(S) fetch.
    // --------------------------------------------------------

    exists(Call c, Attribute method, Name repoName |
      n = c and
      method = c.getFunc() and
      method.getName() = "create_remote" and
      repoName = method.getObject() and
      repoName.getId() = "repo" and
      inModule(c, "mlflow/projects/utils.py") and
      callableName = "git.Repo.create_remote" and
      flowKind = "argument" and
      receiverHint = "git.Repo (non-http)" and
      argIndex = 1
    )

    or

    exists(Call c, Attribute method, Name originName |
      n = c and
      method = c.getFunc() and
      method.getName() = "fetch" and
      originName = method.getObject() and
      originName.getId() = "origin" and
      inModule(c, "mlflow/projects/utils.py") and
      callableName = "git.Remote.fetch" and
      flowKind = "argument" and
      receiverHint = "git.Remote (non-http)" and
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
