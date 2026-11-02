/**
 * Augur Phase 2 Step 4 — Pass 1 (Path Traversal) source model for mlflow.
 *
 * Machine-generated from iris/labels/labels.json (run mlflow-pt-pass1-20261022, pass_id 1,
 * entries with role=source). Every rule cites the label entry id(s) it renders; the source-code
 * evidence for each entry was verified during Phase 1 Step 3 labeling against the mlflow_vuln
 * source tree (see iris/labels/phase1_review.md sections 1 and 2).
 *
 * Only reviewed, genuinely attacker-controlled input boundaries are sources. Internal wrapper
 * parameters that merely carry request-derived paths (labels S07-S18, role=summary) are NOT
 * sources here; they are propagated via MySummaries dispatch steps.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  // --------------------------------------------------------------------------
  // Shared helpers
  // --------------------------------------------------------------------------

  /** Holds if `n` is located in the file given by mlflow-relative path `relPath`. */
  private predicate inFile(DataFlow::Node n, string relPath) {
    n.getLocation().getFile().getRelativePath() = relPath
  }

  // --------------------------------------------------------------------------
  // S01, S02 — proto request field `request_message.path`
  // ListArtifacts (handlers.py:888-898) and ListArtifactsMlflowArtifacts
  // (handlers.py:1485-1486) parse the request JSON/query body into a proto message
  // whose `path` field selects the artifact sub-path to list.
  // --------------------------------------------------------------------------
  private predicate requestMessagePathField(DataFlow::Node n) {
    exists(Attribute att |
      n.asExpr() = att and
      att.getName() = "path" and
      att.getObject() instanceof Name and
      att.getObject().(Name).getId() = "request_message" and
      att.getEnclosingModule().getFile().getRelativePath() = "mlflow/server/handlers.py"
    )
  }

  // --------------------------------------------------------------------------
  // S03-S06 — `request_dict["path"]`
  // Query-string-parsed dict field carrying the requested artifact path in
  // get_artifact_handler (handlers.py:540 proxied branch, :544 direct branch) and
  // get_model_version_artifact_handler (handlers.py:1282 proxied, :1286 direct).
  // --------------------------------------------------------------------------
  private predicate requestDictPathSubscript(DataFlow::Node n) {
    exists(Subscript sub |
      n.asExpr() = sub and
      sub.getObject() instanceof Name and
      sub.getObject().(Name).getId() = "request_dict" and
      sub.getIndex() instanceof StringLiteral and
      sub.getIndex().(StringLiteral).getS() = "path" and
      sub.getEnclosingModule().getFile().getRelativePath() = "mlflow/server/handlers.py"
    )
  }

  // --------------------------------------------------------------------------
  // S19-S22 — Flask request.query_string attribute reads
  // handlers.py:378/384 (generic proto request parsing in _get_request_message),
  // handlers.py:531 (/get-artifact), handlers.py:1272 (/model-versions/get-artifact).
  // The raw URL query is the outermost untrusted boundary for these endpoints.
  // --------------------------------------------------------------------------
  private predicate queryStringAttr(DataFlow::Node n) {
    exists(Attribute att |
      n.asExpr() = att and
      att.getName() = "query_string" and
      att.getObject() instanceof Name and
      att.getObject().(Name).getId() in ["request", "flask_request"] and
      att.getEnclosingModule().getFile().getRelativePath() = "mlflow/server/handlers.py"
    )
  }

  // --------------------------------------------------------------------------
  // S40-S43 — `request_dict.get("run_id"/"run_uuid"/"name"/"version")`
  // Untrusted lookup keys from /get-artifact (handlers.py:533) and
  // /model-versions/get-artifact (handlers.py:1274-1275); they select the run or
  // model version whose artifact repository is used (indirect path influence).
  // --------------------------------------------------------------------------
  private predicate requestDictGetCall(DataFlow::Node n) {
    exists(Call call |
      n.asExpr() = call and
      call.getFunc() instanceof Attribute and
      call.getFunc().(Attribute).getName() = "get" and
      call.getFunc().(Attribute).getObject() instanceof Name and
      call.getFunc().(Attribute).getObject().(Name).getId() = "request_dict" and
      call.getArg(0) instanceof StringLiteral and
      call.getArg(0).(StringLiteral).getS() in ["run_id", "run_uuid", "name", "version"] and
      call.getEnclosingModule().getFile().getRelativePath() = "mlflow/server/handlers.py"
    )
  }

  // --------------------------------------------------------------------------
  // S36 — `flask_request.get_json(force=True, silent=True)` (handlers.py:372)
  // Whole-body request JSON accessor; the parsed body feeds proto request
  // messages (including ListArtifacts.path) via _get_request_message.
  // --------------------------------------------------------------------------
  private predicate getJsonCall(DataFlow::Node n) {
    exists(Call call |
      n.asExpr() = call and
      call.getFunc() instanceof Attribute and
      call.getFunc().(Attribute).getName() = "get_json" and
      call.getFunc().(Attribute).getObject() instanceof Name and
      call.getFunc().(Attribute).getObject().(Name).getId() in ["request", "flask_request"] and
      call.getEnclosingModule().getFile().getRelativePath() = "mlflow/server/handlers.py"
    )
  }

  // --------------------------------------------------------------------------
  // S35, S37, S38, S39 — Flask route handler parameters bound to URL rules
  //   S37: _download_artifact.artifact_path      GET    /mlflow-artifacts/artifacts/<path:artifact_path> (handlers.py:1430)
  //   S38: _delete_artifact_mflflow_artifacts    DELETE /mlflow-artifacts/artifacts/<path:artifact_path> (handlers.py:1502)
  //   S39: _upload_artifact.artifact_path        PUT    /mlflow-artifacts/artifacts/<path:artifact_path> (handlers.py:1456)
  //   S35: serve_static_file.path                GET    /static-files/<path:path> (server/__init__.py:66;
  //        its sink send_from_directory is contained by werkzeug safe_join, cf. MySinks notes)
  // These handlers are registered via app.add_url_rule (server/__init__.py:33-34) and
  // @app.route (server/__init__.py:65), so their parameters are URL-derived.
  // --------------------------------------------------------------------------
  private predicate routedHandlerParam(DataFlow::Node n) {
    exists(Function f, Parameter p |
      n = DataFlow::parameterNode(p) and
      f.getArg(_) = p and
      (
        (
          f.getName() = "serve_static_file" and
          p.getName() = "path" and
          f.getEnclosingModule().getFile().getRelativePath() = "mlflow/server/__init__.py"
        )
        or
        (
          f.getName() in ["_download_artifact", "_upload_artifact", "_delete_artifact_mflflow_artifacts"] and
          p.getName() = "artifact_path" and
          f.getEnclosingModule().getFile().getRelativePath() = "mlflow/server/handlers.py"
        )
      )
    )
  }

  // --------------------------------------------------------------------------
  // S27-S30, S32 (classification=candidate) — second-order `run.info.artifact_uri`
  // The stored run artifact location (originally supplied through the CreateExperiment
  // API `artifact_location` field) is read on the server to select the artifact
  // repository root: handlers.py:536/539 (get_artifact_handler proxied branch),
  // 904/906 (_list_artifacts proxied branch), 1004 (_get_artifact_repo).
  // Line 913 (response root_uri echo, label S31 role=none) is deliberately excluded.
  // --------------------------------------------------------------------------
  private predicate runArtifactUriAttr(DataFlow::Node n) {
    exists(Attribute att, Attribute info, Name run |
      n.asExpr() = att and
      att.getName() = "artifact_uri" and
      att.getObject() = info and
      info.getName() = "info" and
      info.getObject() = run and
      run.getId() = "run" and
      att.getEnclosingModule().getFile().getRelativePath() = "mlflow/server/handlers.py" and
      att.getLocation().getStartLine() in [536, 539, 904, 906, 1004]
    )
  }

  /** Holds if `n` is a pass 1 source node. `passKey` must be "path_traversal". */
  predicate isSource(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      requestMessagePathField(n)
      or requestDictPathSubscript(n)
      or queryStringAttr(n)
      or requestDictGetCall(n)
      or getJsonCall(n)
      or routedHandlerParam(n)
      or runArtifactUriAttr(n)
    )
  }
}
