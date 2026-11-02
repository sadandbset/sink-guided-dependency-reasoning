/**
 * Augur-generated source model for the mlflow CWE-918 (SSRF) pass.
 *
 * Machine-generated in Phase 2 Step 4 from the reviewed labels in
 * iris/labels/labels.json (run mlflow-ssrf-pass3-20261020, pass_id 3,
 * pass key "ssrf"). Do not edit by hand; regenerate from the labels.
 *
 * Selection policy: label entries with role "source" and classification
 * "tp" or "candidate" are modeled (113 of 251 source candidates). Entries
 * classified "fp" (optional-auth credential reads, CLI operator input,
 * admin environment configuration) and role "none" entries are excluded;
 * route/handler "param" labels are excluded because the labeled Flask view
 * functions and REST handlers take no parameters (request content is
 * materialized inside the handler body by _get_request_message() /
 * _get_request_json(), modeled as requestMaterializerSource). Full mapping
 * and exclusion rationale: report/query_generation_notes.md.
 *
 * Trust boundaries modeled (verified against mlflow source):
 *  - Flask tracking server request fields and request materializers
 *    (server runs unauthenticated by default, mlflow/server/handlers.py).
 *  - FastAPI deployments/gateway server request boundary.
 *  - Second-order DB content: run.info.artifact_uri, model-version
 *    request_message.source, ArtifactRepository.self.artifact_uri.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {

  /** Source dispatch. Pass key "ssrf" = pass 3 (CWE-918/099/610). */
  predicate isSource(DataFlow::Node node, string passKey) {
    passKey = "ssrf" and (
      flaskRequestFieldSource(node) or
      fastapiRequestJsonSource(node) or
      parserParseSource(node) or
      requestMaterializerSource(node) or
      runArtifactUriSource(node) or
      modelVersionSourceFieldSource(node) or
      repoArtifactUriSource(node)
    )
  }

  /**
   * Flask request field reads on the tracking server (unauthenticated by
   * default): request.args / request.json / request.data /
   * request.query_string / flask_request.query_string in
   * mlflow/server/handlers.py, e.g. gateway_path extraction for the
   * deployments proxy (handlers.py:1132-1141).
   * Labels (13 tp): src-82, src-83, src-88, src-137, src-138, src-139,
   * src-141, src-144, src-145, src-147, src-149, src-150, src-186.
   */
  private predicate flaskRequestFieldSource(DataFlow::Node node) {
    exists(Attribute a, Name n |
      a = node.asExpr() and
      a.getObject() = n and
      n.getId() = ["request", "flask_request"] and
      a.getName() = ["args", "json", "data", "query_string"] and
      a.getLocation().getFile().getRelativePath() = "mlflow/server/handlers.py"
    )
  }

  /**
   * FastAPI request boundary on the MLflow deployments/gateway server:
   * request.json() in mlflow/deployments/server/app.py (_custom handler,
   * app.py:104-105).
   * Labels (1 tp): src-38.
   */
  private predicate fastapiRequestJsonSource(DataFlow::Node node) {
    exists(Call c, Attribute fn, Name n |
      c = node.asExpr() and
      c.getFunc() = fn and
      fn.getName() = "json" and
      fn.getObject() = n and
      n.getId() = "request" and
      c.getLocation().getFile().getRelativePath() = "mlflow/deployments/server/app.py"
    )
  }

  /**
   * querystring_parser.parser.parse(...) call result: materializes the raw
   * Flask query string (request.query_string) into the dict consumed by the
   * artifact-serving handlers (handlers.py:420, 547-548, 1657-1659).
   * Labels (3 tp): src-84, src-89, src-187.
   */
  private predicate parserParseSource(DataFlow::Node node) {
    exists(Call c, Attribute fn, Name n |
      c = node.asExpr() and
      c.getFunc() = fn and
      fn.getName() = "parse" and
      fn.getObject() = n and
      n.getId() = "parser" and
      c.getLocation().getFile().getRelativePath() = "mlflow/server/handlers.py"
    )
  }

  /**
   * _get_request_message() / _get_request_json() call results: the protobuf
   * request messages for all /api/2.0/mlflow and /ajax-api/2.0/mlflow REST
   * handlers are materialized from the request query string / JSON body
   * (handlers.py:405-470).
   * Labels (51 tp): src-85, src-93, src-95, src-97, src-99, src-101,
   * src-103, src-105, src-107, src-109, src-111, src-113, src-115, src-117,
   * src-119, src-121, src-123, src-125, src-127, src-129, src-135, src-154,
   * src-158, src-159, src-161, src-163, src-165, src-167, src-169, src-171,
   * src-173, src-175, src-177, src-179, src-182, src-189, src-191, src-193,
   * src-195, src-197, src-199, src-201, src-203, src-205, src-207, src-209,
   * src-213, src-215, src-217, src-219, src-221.
   */
  private predicate requestMaterializerSource(DataFlow::Node node) {
    exists(Call c, Name fn |
      c = node.asExpr() and
      c.getFunc() = fn and
      fn.getId() = ["_get_request_message", "_get_request_json"] and
      c.getLocation().getFile().getRelativePath() = "mlflow/server/handlers.py"
    )
  }

  /**
   * run.info.artifact_uri field reads (second-order DB content): the run
   * artifact root, stored at experiment/run creation (the experiment
   * artifact_location is client-settable via the unauthenticated
   * CreateExperiment API), drives server-side artifact repository
   * selection and fetches (handlers.py:554-570, 947-963, 1225-1270, 1319).
   * Labels (9 tp): src-90, src-91, src-130, src-131, src-132, src-151,
   * src-152, src-156, src-180.
   */
  private predicate runArtifactUriSource(DataFlow::Node node) {
    exists(Attribute uri, Attribute info, Name run |
      uri = node.asExpr() and
      uri.getName() = "artifact_uri" and
      uri.getObject() = info and
      info.getName() = "info" and
      info.getObject() = run and
      run.getId() = "run" and
      uri.getLocation().getFile().getRelativePath() = "mlflow/server/handlers.py"
    )
  }

  /**
   * request_message.source field: attacker-supplied model-version source
   * URI from the CreateModelVersion REST request (handlers.py:1639-1648).
   * Labels (2 tp): src-183, src-184.
   */
  private predicate modelVersionSourceFieldSource(DataFlow::Node node) {
    exists(Attribute a, Name n |
      a = node.asExpr() and
      a.getName() = "source" and
      a.getObject() = n and
      n.getId() = "request_message" and
      a.getLocation().getFile().getRelativePath() = "mlflow/server/handlers.py"
    )
  }

  /**
   * self.artifact_uri field reads on artifact repositories (second-order
   * DB content). HttpArtifactRepository rows are tp - the field directly
   * determines the outbound HTTP host via
   * _get_default_host_creds(self.artifact_uri) (http_artifact_repo.py:39-40).
   * Non-HTTP cloud/DBFS repository rows are candidate labels retained for
   * recall (their network I/O lives in external cloud SDKs).
   * local_artifact_repo.py is excluded (fp label: local filesystem only,
   * no network request).
   * Labels (34 rows: 5 tp + 29 candidate): src-39, src-40, src-43, src-44,
   * src-45, src-46, src-47, src-48, src-55, src-60, src-62, src-63, src-69,
   * src-70, src-71, src-72, src-73, src-74, src-75, src-76, src-223,
   * src-224, src-225, src-226, src-227, src-239, src-241, src-242, src-243,
   * src-244, src-245, src-246, src-247, src-248.
   */
  private predicate repoArtifactUriSource(DataFlow::Node node) {
    exists(Attribute a, Name n |
      a = node.asExpr() and
      a.getName() = "artifact_uri" and
      a.getObject() = n and
      n.getId() = "self" and
      a.getLocation().getFile().getRelativePath().matches("mlflow/store/artifact/%") and
      a.getLocation().getFile().getRelativePath() != "mlflow/store/artifact/local_artifact_repo.py"
    )
  }
}
