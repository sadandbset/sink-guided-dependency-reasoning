/**
 * Augur-generated additional taint-step model for the mlflow CWE-918 pass.
 *
 * Machine-generated in Phase 2 Step 4 from the reviewed labels in
 * iris/labels/labels.json (run mlflow-ssrf-pass3-20261020, pass_id 3,
 * pass key "ssrf").
 *
 * Every step below is backed by concrete source code (file:line evidence
 * per predicate; full discussion in report/query_generation_notes.md).
 * No unconditional taint propagation is introduced: each step is either
 * conditional on the `from` node being the specific receiver/argument of
 * a structurally matched call, or scoped to an explicit file.
 *
 * Step families:
 *  - request-parameter parsing (requestAccessorGetStep, parserParseStep)
 *  - URL string handling on artifact URIs (artifactUriSplitStep)
 *  - business/URL wrappers (hostCredsWrapperStep, hostCredsHostFieldStep)
 *  - resource-loading wrapper (artifactRepositoryWrapperStep)
 *  - property bridge (hostCredsPropertyStep)
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {

  /** Additional taint-step dispatch. Pass key "ssrf" = pass 3. */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "ssrf" and (
      requestAccessorGetStep(nodeFrom, nodeTo) or
      parserParseStep(nodeFrom, nodeTo) or
      artifactUriSplitStep(nodeFrom, nodeTo) or
      hostCredsWrapperStep(nodeFrom, nodeTo) or
      hostCredsPropertyStep(nodeFrom, nodeTo) or
      artifactRepositoryWrapperStep(nodeFrom, nodeTo) or
      hostCredsHostFieldStep(nodeFrom, nodeTo)
    )
  }

  /**
   * Request-parameter parsing: `.get(key)` on a tainted request-derived
   * container returns attacker-controlled request content.
   * Evidence: mlflow/server/handlers.py:1132-1134 (args = request.args /
   * request.json; gateway_path = args.get("gateway_path")); handlers.py:550
   * (run_id = request_dict.get("run_id") after parser.parse).
   * Scoped to mlflow/server/handlers.py; conditional on the receiver
   * (`from`) carrying taint.
   */
  private predicate requestAccessorGetStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "get" and
      c.getLocation().getFile().getRelativePath() = "mlflow/server/handlers.py" and
      nodeFrom.asExpr() = fn.getObject() and
      nodeTo.asExpr() = c
    )
  }

  /**
   * Request-parameter parsing: querystring_parser.parser.parse(...)
   * materializes the raw query string into the dict consumed by the
   * handlers, so taint on an argument reaches the parsed dict.
   * Evidence: mlflow/server/handlers.py:420, 547-548, 1657-1659
   * (query_string = request.query_string.decode("utf-8");
   * request_dict = parser.parse(query_string, normalized=True)).
   * Scoped to mlflow/server/handlers.py.
   */
  private predicate parserParseStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute fn, Name n |
      c.getFunc() = fn and
      fn.getName() = "parse" and
      fn.getObject() = n and
      n.getId() = "parser" and
      c.getLocation().getFile().getRelativePath() = "mlflow/server/handlers.py" and
      exists(int i | i >= 0 and nodeFrom.asExpr() = c.getPositionalArg(i)) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * URL splitting: str.split(...) on a tainted artifact URI yields tainted
   * parts used to build the host credentials.
   * Evidence: mlflow/store/artifact/http_artifact_repo.py:84
   * (url, tail = self.artifact_uri.split(endpoint, maxsplit=1)) and :85
   * (root = tail.lstrip("/")), feeding host_creds = _get_default_host_creds(url)
   * at :85-86.
   * Scoped to mlflow/store/artifact/http_artifact_repo.py; conditional on
   * the receiver (`from`) carrying taint.
   */
  private predicate artifactUriSplitStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "split" and
      c.getLocation().getFile().getRelativePath() = "mlflow/store/artifact/http_artifact_repo.py" and
      nodeFrom.asExpr() = fn.getObject() and
      nodeTo.asExpr() = c
    )
  }

  /**
   * Business wrapper: _get_default_host_creds(store_uri) returns
   * MlflowHostCreds(host=store_uri, ...), so a tainted store URI taints
   * the returned credentials object (which carries the outbound host).
   * Evidence: mlflow/tracking/_tracking_service/utils.py:141-153
   * (def _get_default_host_creds(store_uri): ... return
   * rest_utils.MlflowHostCreds(host=store_uri, ...)); called at
   * mlflow/store/artifact/http_artifact_repo.py:40 (self.artifact_uri) and
   * :85 (url derived from self.artifact_uri.split).
   * Scoped to http_artifact_repo.py call sites.
   */
  private predicate hostCredsWrapperStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "_get_default_host_creds" and
      c.getLocation().getFile().getRelativePath() = "mlflow/store/artifact/http_artifact_repo.py" and
      exists(int i | i >= 0 and nodeFrom.asExpr() = c.getPositionalArg(i)) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * Property bridge: the HttpArtifactRepository._host_creds property
   * returns _get_default_host_creds(self.artifact_uri), so reads of
   * self._host_creds yield the (possibly tainted) credentials object.
   * Evidence: mlflow/store/artifact/http_artifact_repo.py:38-40
   * (@property def _host_creds: return _get_default_host_creds(self.artifact_uri));
   * consumed as http_request arg 0 at :63, :104, :113.
   * Scoped to http_artifact_repo.py (the only file defining/reading this
   * property).
   */
  private predicate hostCredsPropertyStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute attr |
      c.getFunc().(Name).getId() = "_get_default_host_creds" and
      c.getLocation().getFile().getRelativePath() = "mlflow/store/artifact/http_artifact_repo.py" and
      nodeFrom.asExpr() = c and
      attr = nodeTo.asExpr() and
      attr.getName() = "_host_creds" and
      attr.getObject().(Name).getId() = "self" and
      attr.getLocation().getFile().getRelativePath() = "mlflow/store/artifact/http_artifact_repo.py"
    )
  }

  /**
   * Resource-loading wrapper: get_artifact_repository(artifact_uri)
   * instantiates the repository implementation for the URI scheme and the
   * repository constructor stores the URI as self.artifact_uri, so
   *   (a) a tainted argument taints the returned repository object, and
   *   (b) the constructed repository's self.artifact_uri field reads carry
   *       the URI's taint.
   * Evidence: mlflow/store/artifact/artifact_repository_registry.py:107-117
   * (get_artifact_repository(artifact_uri) -> registry constructor with the
   * URI); mlflow/store/artifact/artifact_repo.py:44-47
   * (def __init__(self, artifact_uri): self.artifact_uri = artifact_uri);
   * call sites mlflow/server/handlers.py:1269, 1319, 1672.
   * Step (b) is approximated structurally (call node -> self.artifact_uri
   * reads in mlflow/store/artifact/, local repo excluded); it does not
   * propagate taint from untainted call nodes.
   */
  private predicate artifactRepositoryWrapperStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "get_artifact_repository" and
      c.getLocation().getFile().getRelativePath() = "mlflow/server/handlers.py" and
      (
        exists(int i |
          i >= 0 and
          nodeFrom.asExpr() = c.getPositionalArg(i) and
          nodeTo.asExpr() = c
        )
        or
        (
          nodeFrom.asExpr() = c and
          exists(Attribute a, Name self |
            a = nodeTo.asExpr() and
            a.getName() = "artifact_uri" and
            a.getObject() = self and
            self.getId() = "self" and
            a.getLocation().getFile().getRelativePath().matches("mlflow/store/artifact/%") and
            a.getLocation().getFile().getRelativePath() != "mlflow/store/artifact/local_artifact_repo.py"
          )
        )
      )
    )
  }

  /**
   * URL construction: http_request / http_request_safe build the request
   * URL from the host field of their host_creds argument
   * (hostname = host_creds.host; url = f"{cleaned_hostname}{endpoint}"),
   * so taint on the host_creds object flows to the host_creds.host read
   * inside mlflow/utils/rest_utils.py, onward into the transport URL.
   * Evidence: mlflow/utils/rest_utils.py:74 (hostname = host_creds.host)
   * and :104-105 (url = f"{cleaned_hostname}{endpoint}").
   * Scoped to mlflow/utils/rest_utils.py, field name "host", receiver
   * name "host_creds" (the parameter of http_request/http_request_safe).
   */
  private predicate hostCredsHostFieldStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Attribute a, Name n |
      a.getName() = "host" and
      a.getObject() = n and
      n.getId() = "host_creds" and
      a.getLocation().getFile().getRelativePath() = "mlflow/utils/rest_utils.py" and
      nodeFrom.asExpr() = n and
      nodeTo.asExpr() = a
    )
  }
}
