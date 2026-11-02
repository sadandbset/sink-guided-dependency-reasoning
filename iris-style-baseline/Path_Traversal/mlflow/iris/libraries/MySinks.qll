/**
 * Augur Phase 2 Step 4 — Pass 1 (Path Traversal) sink model for mlflow.
 *
 * Machine-generated from iris/labels/labels.json (run mlflow-pt-pass1-20261022, pass_id 1).
 * Sink rules render the labels whose role=sink AND whose classification is tp or candidate,
 * plus the barrier-covered upload sinks K086/K093 (classification=fp with an expressible
 * barrier — included so that the X01 sanitizer is actually exercised by the query).
 *
 * Excluded by policy (documented in report/query_generation_notes.md section 5):
 *  - K036/K037 send_from_directory (server/__init__.py:67/74): werkzeug safe_join containment
 *    lives inside the Flask library (not in this database), so it cannot be modelled as a
 *    CodeQL barrier; per label classification=fp the site is kept out of the sink model.
 *  - K166 open (handlers.py:1464): upload temp-file write whose path is structurally confined
 *    by posixpath.split to a single component; no expressible barrier, classification=fp.
 *  - The remaining 276 classification=fp local/CLI file-I/O sites: no untrusted source can
 *    reach them (label rationale), and including them adds no recall for this pass.
 *
 * Sinks match the dangerous *path argument* of real file access / file response /
 * file modification APIs — not path text held in intermediate wrappers, and not file
 * objects returned by opens.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  // --------------------------------------------------------------------------
  // Shared helper: an argument of a call whose callee has the given shape.
  // --------------------------------------------------------------------------

  /** Holds if `call` is `<name>.<attr>(...)` with `obj` being a plain name. */
  private predicate methodCallOnName(Call call, string attrName, string objName) {
    call.getFunc() instanceof Attribute and
    call.getFunc().(Attribute).getName() = attrName and
    call.getFunc().(Attribute).getObject() instanceof Name and
    call.getFunc().(Attribute).getObject().(Name).getId() = objName
  }

  /** Holds if `call` is `<obj>.<mid>.<attr>(...)` such as `os.path.join(...)`. */
  private predicate nestedMethodCall(Call call, string attrName, string midName, string objName) {
    call.getFunc() instanceof Attribute and
    call.getFunc().(Attribute).getName() = attrName and
    call.getFunc().(Attribute).getObject() instanceof Attribute and
    call.getFunc().(Attribute).getObject().(Attribute).getName() = midName and
    call.getFunc().(Attribute).getObject().(Attribute).getObject() instanceof Name and
    call.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = objName
  }

  /** Holds if `n` is positional argument `i` of `call`. */
  private predicate argNode(DataFlow::Node n, Call call, int i) {
    n.asExpr() = call.getArg(i)
  }

  // --------------------------------------------------------------------------
  // K126, K127 — Flask send_file(path) in _send_artifact (handlers.py:443, 445)
  // File response: the served file is read from disk and returned as an HTTP
  // response (arbitrary file read when the path escapes the artifact root).
  // arg 0 = filename (path text, derived from download_artifacts + os.path.abspath).
  // --------------------------------------------------------------------------
  private predicate sendFileArg(DataFlow::Node n) {
    exists(Call call |
      call.getFunc() instanceof Name and
      call.getFunc().(Name).getId() = "send_file" and
      call.getEnclosingModule().getFile().getRelativePath() = "mlflow/server/handlers.py" and
      argNode(n, call, 0)
    )
  }

  // --------------------------------------------------------------------------
  // K165 — open(dst, "rb") in _download_artifact (handlers.py:1441)
  // File read: `dst` is the return value of download_artifacts(artifact_path, tmp_dir)
  // where artifact_path is the URL path-converter variable; the file content is
  // streamed to the client. Line-restricted to 1441 because handlers.py:1464
  // (label K166) is the barrier-inexpressible guarded upload temp write.
  // --------------------------------------------------------------------------
  private predicate downloadStreamOpenArg(DataFlow::Node n) {
    exists(Call call |
      call.getFunc() instanceof Name and
      call.getFunc().(Name).getId() = "open" and
      call.getEnclosingModule().getFile().getRelativePath() = "mlflow/server/handlers.py" and
      call.getLocation().getStartLine() = 1441 and
      argNode(n, call, 0)
    )
  }

  // --------------------------------------------------------------------------
  // K073 — shutil.rmtree(artifact_path) in LocalArtifactRepository.delete_artifacts
  // (local_artifact_repo.py:112). Recursive directory delete: the path is
  // os.path.join(artifact_dir, artifact_path) with no normalization and no
  // verify_artifact_path (contrast log_artifact at line 27).
  // --------------------------------------------------------------------------
  private predicate rmtreeArg(DataFlow::Node n) {
    exists(Call call |
      methodCallOnName(call, "rmtree", "shutil") and
      call.getEnclosingModule().getFile().getRelativePath() = "mlflow/store/artifact/local_artifact_repo.py" and
      argNode(n, call, 0)
    )
  }

  // --------------------------------------------------------------------------
  // K086/K087 (arg 0) and K093/K094 (arg 1) — shutil.copyfile in
  // LocalArtifactRepository (local_artifact_repo.py:38 and :104).
  //  - :104 (_download_file): read side arg 0 = join(artifact_dir,
  //    normpath(remote_file_path)) (traversal survives normpath), write side
  //    arg 1 = _create_download_destination result embedding the attacker path.
  //  - :38 (log_artifact): destination is guarded by verify_artifact_path +
  //    basename (labels K086/K093 classification=fp). Included so the MySanitizers
  //    barrier is exercised; the barrier suppresses the upload flow.
  // --------------------------------------------------------------------------
  private predicate copyfileArg(DataFlow::Node n, int i) {
    exists(Call call |
      methodCallOnName(call, "copyfile", "shutil") and
      call.getEnclosingModule().getFile().getRelativePath() = "mlflow/store/artifact/local_artifact_repo.py" and
      argNode(n, call, i)
    )
  }

  // --------------------------------------------------------------------------
  // K032, K033 — os.makedirs in ArtifactRepository._create_download_destination
  // (artifact_repo.py:105) and the directory-download branch (artifact_repo.py:202).
  // Directory create: local_dir_path = os.path.join(dst, posixpath.dirname(artifact_path))
  // — '..' segments in the request path escape the destination directory.
  // K007 (candidate) — os.makedirs in _download_hdfs_file (hdfs_artifact_repo.py:234):
  // local_file_path = os.path.join(local_dir, os.path.normpath(artifact_path)).
  // --------------------------------------------------------------------------
  private predicate makedirsArg(DataFlow::Node n) {
    exists(Call call |
      nestedMethodCall(call, "makedirs", "path", "os") and
      call.getEnclosingModule().getFile().getRelativePath() in
        ["mlflow/store/artifact/artifact_repo.py", "mlflow/store/artifact/hdfs_artifact_repo.py"] and
      argNode(n, call, 0)
    )
  }

  // --------------------------------------------------------------------------
  // K042 — os.listdir(root) inside list_all (file_utils.py:61)
  // Directory listing read: reached from LocalArtifactRepository.list_artifacts with
  // list_dir = os.path.join(artifact_dir, os.path.normpath(path)) where path is the
  // ListArtifacts request field (listing disclosure outside the artifact root).
  // --------------------------------------------------------------------------
  private predicate listdirArg(DataFlow::Node n) {
    exists(Call call |
      nestedMethodCall(call, "listdir", "path", "os") and
      call.getEnclosingModule().getFile().getRelativePath() = "mlflow/utils/file_utils.py" and
      argNode(n, call, 0)
    )
  }

  // --------------------------------------------------------------------------
  // K175 (candidate) — open(local_file_path, "wb") in _download_hdfs_file
  // (hdfs_artifact_repo.py:235). File write of downloaded bytes to a destination built
  // from join(local_dir, normpath(artifact_path)). Line-restricted to 235 because
  // hdfs_artifact_repo.py:42/75 (labels classification=fp) read caller-local files.
  // --------------------------------------------------------------------------
  private predicate hdfsDownloadOpenArg(DataFlow::Node n) {
    exists(Call call |
      call.getFunc() instanceof Name and
      call.getFunc().(Name).getId() = "open" and
      call.getEnclosingModule().getFile().getRelativePath() = "mlflow/store/artifact/hdfs_artifact_repo.py" and
      call.getLocation().getStartLine() = 235 and
      argNode(n, call, 0)
    )
  }

  // --------------------------------------------------------------------------
  // K132, K133 (candidate) — zipfile .extractall(dst) with no member-name filtering:
  //   utils/_spark_utils.py:80 (temp_dir), projects/utils.py:182 (dst_dir).
  // Archive extraction write: entry names control the written paths (zip-slip);
  // the archive source is a CLI/API-user-chosen project URI, not an HTTP request.
  // --------------------------------------------------------------------------
  private predicate extractallArg(DataFlow::Node n) {
    exists(Call call |
      call.getFunc() instanceof Attribute and
      call.getFunc().(Attribute).getName() = "extractall" and
      call.getEnclosingModule().getFile().getRelativePath() in
        ["mlflow/utils/_spark_utils.py", "mlflow/projects/utils.py"] and
      argNode(n, call, 0)
    )
  }

  // --------------------------------------------------------------------------
  // K134 (candidate) — sftp.mkdir(remote_path) (sftp_artifact_repo.py:19);
  // K135, K136 (candidate) — hdfs.mkdir(hdfs_base_path) (hdfs_artifact_repo.py:57, 70).
  // Remote-filesystem directory create: base path derives from the untrusted
  // artifact_path (no verify_artifact_path in these repositories) and only applies
  // when the deployment artifact destination is sftp:// / hdfs://.
  // --------------------------------------------------------------------------
  private predicate remoteMkdirArg(DataFlow::Node n) {
    exists(Call call |
      (methodCallOnName(call, "mkdir", "sftp") or methodCallOnName(call, "mkdir", "hdfs")) and
      call.getEnclosingModule().getFile().getRelativePath() in
        ["mlflow/store/artifact/sftp_artifact_repo.py", "mlflow/store/artifact/hdfs_artifact_repo.py"] and
      argNode(n, call, 0)
    )
  }

  /** Holds if `n` is a pass 1 sink node. `passKey` must be "path_traversal". */
  predicate isSink(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      sendFileArg(n)
      or downloadStreamOpenArg(n)
      or rmtreeArg(n)
      or copyfileArg(n, 0)
      or copyfileArg(n, 1)
      or makedirsArg(n)
      or listdirArg(n)
      or hdfsDownloadOpenArg(n)
      or extractallArg(n)
      or remoteMkdirArg(n)
    )
  }
}
