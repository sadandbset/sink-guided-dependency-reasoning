/**
 * Augur-generated sink model for the mlflow CWE-918 (SSRF) pass.
 *
 * Machine-generated in Phase 2 Step 4 from the reviewed labels in
 * iris/labels/labels.json (run mlflow-ssrf-pass3-20261020, pass_id 3,
 * pass key "ssrf"). Do not edit by hand; regenerate from the labels.
 *
 * Selection policy: label entries with role "sink" and classification
 * "tp" or "candidate" are modeled (30 of 52 sink candidates: 17 tp +
 * 13 candidate). The 17 "fp" client-side / operator-configured call sites
 * (deployments/gateway/auth clients, REST stores, scoring-server client,
 * openai parallel processor, aiohttp gateway provider with admin-configured
 * base URLs, `mlflow run` zip fetch) and the 5 "none" non-HTTP protocol
 * rows (ftp/sftp/git) are excluded - see report/query_generation_notes.md.
 *
 * Every modeled sink is anchored at the URL-carrying argument of a real
 * outbound-HTTP call (requests.request / requests.put /
 * requests.Session.request / mlflow's rest-utils transport stack) or at a
 * wrapper argument position proven to reach that transport:
 * http_request(host_creds, endpoint, ...) builds the request URL as
 * f"{host_creds.host}{endpoint}" (mlflow/utils/rest_utils.py:104-105),
 * cloud_storage_http_request(method, url, ...) and download_chunk(...,
 * http_uri=...) forward their URL argument to the same transport
 * (mlflow/utils/request_utils.py:65, 190).
 *
 * Attacker control tiers (documented per predicate, kept distinct):
 *  - full URL (response-driven)          : multipartPutSink
 *  - host control via DB-content URI     : httpArtifactRepoRequestSink,
 *    sessionRequestSink, retriesSink, restUtilsRelaySink (host_creds
 *    position)
 *  - path-only on a fixed (admin) host   : gatewayProxyRequestSink,
 *    databricksModelsEndpointSink
 *  - fixed-host operator profile + DB path / cross-SDK signed URI
 *    (candidate labels)                  : databricksCallEndpointSink,
 *    unityCatalogCallEndpointSink, cloudStorageHttpSink, downloadChunkSink
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {

  /** Sink dispatch. Pass key "ssrf" = pass 3 (CWE-918/099/610). */
  predicate isSink(DataFlow::Node node, string passKey) {
    passKey = "ssrf" and (
      gatewayProxyRequestSink(node) or
      httpArtifactRepoRequestSink(node) or
      multipartPutSink(node) or
      sessionRequestSink(node) or
      retriesSink(node) or
      cloudStorageHttpSink(node) or
      restUtilsRelaySink(node) or
      databricksCallEndpointSink(node) or
      databricksModelsEndpointSink(node) or
      downloadChunkSink(node) or
      unityCatalogCallEndpointSink(node)
    )
  }

  /**
   * Deployments gateway proxy egress:
   * requests.request(request_type, f"{target_uri}/{gateway_path}", ...) at
   * mlflow/server/handlers.py:1143, URL = positional arg 1 (method = 0).
   * Control tier: path-only - the host is fixed by the admin environment
   * variable MLFLOW_DEPLOYMENTS_TARGET (handlers.py:1127); the attacker
   * controls the path appended to the proxied base.
   * Labels (1 tp): sink-26.
   */
  private predicate gatewayProxyRequestSink(DataFlow::Node node) {
    exists(Call c, Attribute fn, Name recv |
      c.getFunc() = fn and
      fn.getName() = "request" and
      fn.getObject() = recv and
      recv.getId() = "requests" and
      c.getLocation().getFile().getRelativePath() = "mlflow/server/handlers.py" and
      node.asExpr() = c.getPositionalArg(1)
    )
  }

  /**
   * http_request(host_creds, endpoint, method, ...) call sites in
   * HttpArtifactRepository (http_artifact_repo.py:63, 88, 104, 113, 125,
   * 139, 151). The outbound URL is f"{host_creds.host}{endpoint}"
   * (rest_utils.py:104-105), so the host-controlling position is arg 0
   * (positional or `host_creds=` keyword); the endpoint argument is
   * path-only. The arg index was corrected from the extraction CSV value 1
   * to 0 during labeling (labels/phase1_review.md section 5).
   * Control tier: host control - host_creds is built from the DB-content
   * artifact URI.
   * Labels (7 tp): sink-27, sink-28, sink-29, sink-30, sink-31, sink-32,
   * sink-33.
   */
  private predicate httpArtifactRepoRequestSink(DataFlow::Node node) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "http_request" and
      c.getLocation().getFile().getRelativePath() = "mlflow/store/artifact/http_artifact_repo.py" and
      (
        node.asExpr() = c.getPositionalArg(0) or
        exists(Keyword kw |
          kw = c.getANamedArg() and
          kw.getArg() = "host_creds" and
          node.asExpr() = kw.getValue()
        )
      )
    )
  }

  /**
   * Multipart-upload part PUT: requests.put(credential.url, data=data,
   * headers=credential.headers) at http_artifact_repo.py:157, URL = arg 0.
   * Control tier: full URL - credential.url is parsed from the JSON
   * response of the mpu/create request sent to the (potentially
   * attacker-controlled) artifact host. Note: reaching this sink requires
   * response taint, which is NOT modeled (no unconditional propagation) -
   * see query_generation_notes.md section on uncovered propagation.
   * Labels (1 tp): sink-34.
   */
  private predicate multipartPutSink(DataFlow::Node node) {
    exists(Call c, Attribute fn, Name recv |
      c.getFunc() = fn and
      fn.getName() = "put" and
      fn.getObject() = recv and
      recv.getId() = "requests" and
      c.getLocation().getFile().getRelativePath() = "mlflow/store/artifact/http_artifact_repo.py" and
      node.asExpr() = c.getPositionalArg(0)
    )
  }

  /**
   * Final requests transport: session.request(method, url, **kwargs) inside
   * _get_http_response_with_retries (request_utils.py:190), URL = arg 1
   * (positional or `url=` keyword). All rest-utils traffic (http_request,
   * cloud_storage_http_request, download_chunk) funnels here.
   * Control tier: host control when the taint reaches the URL argument.
   * Labels (1 tp): sink-38.
   */
  private predicate sessionRequestSink(DataFlow::Node node) {
    exists(Call c, Attribute fn, Name recv |
      c.getFunc() = fn and
      fn.getName() = "request" and
      fn.getObject() = recv and
      recv.getId() = "session" and
      c.getLocation().getFile().getRelativePath() = "mlflow/utils/request_utils.py" and
      (
        node.asExpr() = c.getPositionalArg(1) or
        exists(Keyword kw |
          kw = c.getANamedArg() and
          kw.getArg() = "url" and
          node.asExpr() = kw.getValue()
        )
      )
    )
  }

  /**
   * _get_http_response_with_retries(method, url, ...) relay call sites in
   * the rest-utils transport stack (request_utils.py:222,
   * rest_utils.py:107), URL = arg 1 (positional or `url=` keyword).
   * Control tier: host control (url is the constructed request URL).
   * Labels (2 tp): sink-39, sink-42.
   */
  private predicate retriesSink(DataFlow::Node node) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "_get_http_response_with_retries" and
      c.getLocation().getFile().getRelativePath() =
        ["mlflow/utils/request_utils.py", "mlflow/utils/rest_utils.py"] and
      (
        node.asExpr() = c.getPositionalArg(1) or
        exists(Keyword kw |
          kw = c.getANamedArg() and
          kw.getArg() = "url" and
          node.asExpr() = kw.getValue()
        )
      )
    )
  }

  /**
   * cloud_storage_http_request(method, url, ...) call sites: URL = arg 1
   * (positional or `url=` keyword; http_dataset_source.py:70 passes
   * url=self.url as a keyword). tp row: the download_chunk relay
   * (request_utils.py:65). candidate rows: Databricks signed-URI flows
   * (databricks_artifact_repo.py:366, 372, 462, 530), optimized-S3 signed
   * write URI (optimized_s3_artifact_repo.py:159), file_utils remote
   * download (file_utils.py:668), HTTPDatasetSource dataset load
   * (http_dataset_source.py:70). Signed-URI rows are cross-SDK
   * (response-driven) candidates.
   * Labels (8: 1 tp + 7 candidate): sink-14, sink-15, sink-16, sink-17,
   * sink-22, sink-35, sink-36, sink-37.
   */
  private predicate cloudStorageHttpSink(DataFlow::Node node) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "cloud_storage_http_request" and
      c.getLocation().getFile().getRelativePath() =
        ["mlflow/utils/request_utils.py", "mlflow/store/artifact/databricks_artifact_repo.py",
         "mlflow/data/http_dataset_source.py", "mlflow/store/artifact/optimized_s3_artifact_repo.py",
         "mlflow/utils/file_utils.py"] and
      (
        node.asExpr() = c.getPositionalArg(1) or
        exists(Keyword kw |
          kw = c.getANamedArg() and
          kw.getArg() = "url" and
          node.asExpr() = kw.getValue()
        )
      )
    )
  }

  /**
   * rest-utils internal relays in mlflow/utils/rest_utils.py:
   * http_request (http_request_safe body at :143, keyword `host_creds=`)
   * and call_endpoint (:230, positional arg 0) forwarding host_creds into
   * the transport. Control tier: host control (host_creds position; URL =
   * host_creds.host + endpoint, rest_utils.py:104-105).
   * The http_request(**call_kwargs) call sites at rest_utils.py:215/218
   * cannot be matched positionally or by keyword name (dict unpacking) and
   * will not fire - documented as a CodeQL analysis limitation in
   * query_generation_notes.md.
   * Labels (4 tp): sink-43, sink-44, sink-45, sink-46.
   */
  private predicate restUtilsRelaySink(DataFlow::Node node) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      c.getLocation().getFile().getRelativePath() = "mlflow/utils/rest_utils.py" and
      (
        fn.getId() = ["http_request", "call_endpoint"] and
        (
          node.asExpr() = c.getPositionalArg(0) or
          exists(Keyword kw |
            kw = c.getANamedArg() and
            kw.getArg() = "host_creds" and
            node.asExpr() = kw.getValue()
          )
        )
      )
    )
  }

  /**
   * call_endpoint(host_creds, endpoint, ...) at
   * databricks_artifact_repo.py:144: host fixed to the operator Databricks
   * profile (arg 0 / `host_creds=` keyword); the endpoint carries
   * DB-content-derived paths. Candidate label.
   * Labels (1 candidate): sink-13.
   */
  private predicate databricksCallEndpointSink(DataFlow::Node node) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "call_endpoint" and
      c.getLocation().getFile().getRelativePath() = "mlflow/store/artifact/databricks_artifact_repo.py" and
      (
        node.asExpr() = c.getPositionalArg(0) or
        exists(Keyword kw |
          kw = c.getANamedArg() and
          kw.getArg() = "host_creds" and
          node.asExpr() = kw.getValue()
        )
      )
    )
  }

  /**
   * http_request(host_creds=db_creds, endpoint=endpoint, method="GET", ...)
   * at databricks_models_artifact_repo.py:79: endpoint position
   * (positional arg 1 / `endpoint=` keyword). Control tier: path-only on a
   * fixed Databricks host. Candidate label.
   * Labels (1 candidate): sink-18.
   */
  private predicate databricksModelsEndpointSink(DataFlow::Node node) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "http_request" and
      c.getLocation().getFile().getRelativePath() = "mlflow/store/artifact/databricks_models_artifact_repo.py" and
      (
        node.asExpr() = c.getPositionalArg(1) or
        exists(Keyword kw |
          kw = c.getANamedArg() and
          kw.getArg() = "endpoint" and
          node.asExpr() = kw.getValue()
        )
      )
    )
  }

  /**
   * download_chunk(*, range_start, range_end, headers, download_path,
   * http_uri) call sites: the URL is the keyword-only `http_uri` argument
   * (download_cloud_file_chunk.py:32, file_utils.py:760, 799). Chunk
   * downloads from cloud signed URIs / remote dataset URIs. Candidate
   * labels.
   * Labels (3 candidate): sink-21, sink-23, sink-24.
   */
  private predicate downloadChunkSink(DataFlow::Node node) {
    exists(Call c, Name fn, Keyword kw |
      c.getFunc() = fn and
      fn.getId() = "download_chunk" and
      c.getLocation().getFile().getRelativePath() =
        ["mlflow/utils/download_cloud_file_chunk.py", "mlflow/utils/file_utils.py"] and
      kw = c.getANamedArg() and
      kw.getArg() = "http_uri" and
      node.asExpr() = kw.getValue()
    )
  }

  /**
   * call_endpoint(host_creds=db_creds, endpoint=..., method=...) at
   * unity_catalog_models_artifact_repo.py:98: host fixed to the operator
   * Unity Catalog registry (arg 0 / `host_creds=` keyword). Candidate label.
   * Labels (1 candidate): sink-48.
   */
  private predicate unityCatalogCallEndpointSink(DataFlow::Node node) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "call_endpoint" and
      c.getLocation().getFile().getRelativePath() = "mlflow/store/artifact/unity_catalog_models_artifact_repo.py" and
      (
        node.asExpr() = c.getPositionalArg(0) or
        exists(Keyword kw |
          kw = c.getANamedArg() and
          kw.getArg() = "host_creds" and
          node.asExpr() = kw.getValue()
        )
      )
    )
  }
}
