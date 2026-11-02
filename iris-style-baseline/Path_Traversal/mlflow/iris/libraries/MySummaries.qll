/**
 * Augur Phase 2 Step 4 — Pass 1 (Path Traversal) additional taint-step model for mlflow.
 *
 * Machine-generated from iris/labels/labels.json (run mlflow-pt-pass1-20261022, pass_id 1,
 * entries S07-S18, role=summary). Every step below is required for a request-derived path
 * to reach the labeled sinks and is justified by concrete source code; no unconstrained
 * node-to-node propagation is introduced.
 *
 * Steps:
 *  1. pathTextWrapperStep     — argument -> result of pure path-text transformers
 *                               (os.path.join/normpath/abspath, posixpath.join/dirname).
 *  2. localFileUriToPathStep  — argument -> result of local_file_uri_to_path (pass-through
 *                               of the path text, file_utils.py:505-511).
 *  3. repoMethodDispatchStep  — call-site argument -> concrete ArtifactRepository method
 *                               parameter (dynamic dispatch through get_artifact_repository).
 *  4. submitDownloadFileStep  — ThreadPoolExecutor.submit keyword dispatch into
 *                               LocalArtifactRepository._download_file (artifact_repo.py:155-159).
 *  5. inflightDownloadStep    — namedtuple InflightDownload(dst_local_path=...) construction
 *                               -> `.dst_local_path` attribute read (artifact_repo.py:124-134/163/252).
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  // --------------------------------------------------------------------------
  // 1. Path-text wrapper steps (labels S10, S12, S13, S16 context).
  //
  // These callables are pure string transformations (Python stdlib documentation for
  // os.path/posixpath); taint entering as an argument leaves as the call result:
  //   - os.path.join:       artifact_repo.py:102-103, local_artifact_repo.py:34/53/77/87/103/108
  //   - os.path.normpath:   local_artifact_repo.py:31/51/77/86/103
  //   - os.path.abspath:    local_artifact_repo.py:80, handlers.py:438
  //   - posixpath.join:     handlers.py:231, hdfs_artifact_repo.py:203
  //   - posixpath.dirname:  artifact_repo.py:101
  // Note: python-all already models os.path.join (and, by its path() overapproximation,
  // posixpath.join) as a global AdditionalTaintStep (Stdlib.qll, OsPathJoinCallAdditionalTaintStep);
  // the join rules are kept here so the model is self-contained.
  // posixpath.split is intentionally NOT modelled: its second component is a single path
  // element (upload temp-file name), and label K166 classifies the open of that component as
  // structurally confined — propagating through split would manufacture that false path.
  // --------------------------------------------------------------------------
  private predicate isPathTextWrapperCall(Call call) {
    exists(Attribute fn, Attribute mid, Name osName |
      call.getFunc() = fn and
      fn.getName() in ["join", "normpath", "abspath"] and
      fn.getObject() = mid and
      mid.getName() = "path" and
      mid.getObject() = osName and
      osName.getId() = "os"
    )
    or
    exists(Attribute fn, Name posix |
      call.getFunc() = fn and
      fn.getName() in ["join", "dirname"] and
      fn.getObject() = posix and
      posix.getId() = "posixpath"
    )
  }

  private predicate pathTextWrapperStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call call, Expr arg |
      isPathTextWrapperCall(call) and
      arg = call.getAPositionalArg() and
      nodeFrom.asExpr() = arg and
      nodeTo.asExpr() = call
    )
  }

  // --------------------------------------------------------------------------
  // 2. local_file_uri_to_path step (label S18 context).
  // file_utils.py:505-511:
  //     path = urllib.parse.urlparse(uri).path if uri.startswith("file:") else uri
  //     return urllib.request.url2pathname(path)
  // The function returns the path text derived from `uri` (identity for non-file URIs);
  // urllib.parse/url2pathname are external to the database, so the local flow through the
  // function body stops — this step restores it. Used by
  // LocalArtifactRepository.delete_artifacts (local_artifact_repo.py:107) and __init__ (:20).
  // --------------------------------------------------------------------------
  private predicate localFileUriToPathStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call call |
      call.getFunc() instanceof Name and
      call.getFunc().(Name).getId() = "local_file_uri_to_path" and
      nodeFrom.asExpr() = call.getArg(0) and
      nodeTo.asExpr() = call
    )
  }

  // --------------------------------------------------------------------------
  // 3. Artifact-repository dynamic dispatch step (labels S07, S09, S11, S12, S16, S17, S18).
  //
  // The server invokes the artifact repository through a base-typed receiver, e.g.
  //   handlers.py:1438   artifact_repo.download_artifacts(artifact_path, tmp_dir.name)
  //   handlers.py:1489   artifact_repo.list_artifacts(path)
  //   handlers.py:1509   artifact_repo.delete_artifacts(artifact_path)
  //   handlers.py:1473   artifact_repo.log_artifact(tmp_path, artifact_path=head or None)
  //   artifact_repo.py:74  super().download_artifacts(artifact_path, dst_path)
  //   artifact_repo.py:77  self.list_artifacts(artifact_path)   (inside _is_directory)
  // where the receiver comes from get_artifact_repository(...) (handlers.py:1004) whose
  // return type is not statically resolvable. This step links each call-site argument to
  // the equally-named/positioned parameter of every concrete method implementation in
  // mlflow/store/artifact/**. Positional arguments are shifted by one because these are
  // methods (self occupies parameter position 0). Keyword arguments are matched by name.
  // The Local/Http log_* parameter nodes are barriers (MySanitizers), which is what makes
  // the guarded upload flow stop there.
  // --------------------------------------------------------------------------
  private predicate repoMethodDispatchStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(DataFlow::MethodCallNode call, Function f, Parameter p |
      call.getMethodName() = f.getName() and
      f.getName() in ["download_artifacts", "list_artifacts", "delete_artifacts", "log_artifact", "log_artifacts"] and
      f.getEnclosingModule().getFile().getRelativePath().matches("mlflow/store/artifact/%") and
      f.getArg(0).getName() = "self" and
      f.getArg(_) = p and
      p.getName() != "self" and
      (
        nodeFrom = call.getArg(p.getPosition() - 1)
        or
        nodeFrom = call.getArgByName(p.getName())
      ) and
      nodeTo = DataFlow::parameterNode(p)
    )
  }

  // --------------------------------------------------------------------------
  // 4. ThreadPoolExecutor.submit dispatch into _download_file (label S17).
  // artifact_repo.py:155-159:
  //     download_future = self.thread_pool.submit(
  //         self._download_file,
  //         remote_file_path=src_artifact_path,
  //         local_path=local_destination_file_path,
  //     )
  // CodeQL cannot resolve this function-reference + keyword-argument dispatch, so the
  // step links each keyword argument to the equally-named parameter of
  // LocalArtifactRepository._download_file (local_artifact_repo.py:100-104), whose body
  // performs the join + shutil.copyfile (sinks K087/K094).
  // --------------------------------------------------------------------------
  private predicate submitDownloadFileStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(DataFlow::MethodCallNode call, Function f, Parameter p |
      call.getMethodName() = "submit" and
      call.getArg(0).asExpr() instanceof Attribute and
      call.getArg(0).asExpr().(Attribute).getName() = "_download_file" and
      f.getName() = "_download_file" and
      f.getEnclosingModule().getFile().getRelativePath().matches("mlflow/store/artifact/%") and
      f.getArg(_) = p and
      p.getName() in ["remote_file_path", "local_path"] and
      nodeFrom = call.getArgByName(p.getName()) and
      nodeTo = DataFlow::parameterNode(p)
    )
  }

  // --------------------------------------------------------------------------
  // 5. InflightDownload namedtuple field step (base download return path).
  // artifact_repo.py defines
  //     InflightDownload = namedtuple("InflightDownload",
  //         ["src_artifact_path", "dst_local_path", "download_future"])   (lines 124-134)
  // constructs it with keyword fields (line 163, dst_local_path=local_destination_file_path)
  // and the file-branch return value is inflight_downloads[0].dst_local_path (line 252).
  // Field flow through namedtuple construction/subscript/attribute is beyond the default
  // Python data flow model, so the step links the `dst_local_path` construction keyword to
  // the `.dst_local_path` attribute read inside the same function (the only such read in
  // this code base), which is what carries the attacker-influenced destination to
  // handlers.py:1441 open (sink K165) via the download_artifacts return value.
  // --------------------------------------------------------------------------
  private predicate inflightDownloadStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(DataFlow::CallCfgNode ctor, DataFlow::AttrRead rd |
      ctor.getFunction().asExpr() instanceof Name and
      ctor.getFunction().asExpr().(Name).getId() = "InflightDownload" and
      nodeFrom = ctor.getArgByName("dst_local_path") and
      rd.getAttributeName() = "dst_local_path" and
      rd.getLocation().getFile().getRelativePath() = "mlflow/store/artifact/artifact_repo.py" and
      nodeTo = rd
    )
  }

  /** Holds if taint may step from `nodeFrom` to `nodeTo` for pass 1. `passKey` must be "path_traversal". */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    (
      pathTextWrapperStep(nodeFrom, nodeTo)
      or localFileUriToPathStep(nodeFrom, nodeTo)
      or repoMethodDispatchStep(nodeFrom, nodeTo)
      or submitDownloadFileStep(nodeFrom, nodeTo)
      or inflightDownloadStep(nodeFrom, nodeTo)
    )
  }
}
