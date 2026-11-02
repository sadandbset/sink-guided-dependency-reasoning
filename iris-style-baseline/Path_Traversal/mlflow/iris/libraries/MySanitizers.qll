/**
 * Augur Phase 2 Step 4 — Pass 1 (Path Traversal) sanitizer/barrier model for mlflow.
 *
 * Machine-generated from iris/labels/labels.json (run mlflow-pt-pass1-20261022, pass_id 1,
 * entries X01 verify_artifact_path and X02 path_not_unique, role=sanitizer, classification=tp).
 * Barriers are admitted ONLY where real source code proves the guard executes before the
 * file access and actually blocks the traversal mechanisms (leading '..', absolute paths,
 * non-normalized spellings). os.path.normpath / abspath and similar wrappers are deliberately
 * NOT barriers — in the download/list/delete chains they demonstrably do NOT contain
 * traversal (local_artifact_repo.py:77/86/103 keep leading '..' alive inside os.path.join).
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  // --------------------------------------------------------------------------
  // X01 application points — parameters guarded by verify_artifact_path at entry.
  //
  // Evidence (verified in source):
  //   - LocalArtifactRepository.log_artifact   (local_artifact_repo.py:26-38):
  //       verify_artifact_path(artifact_path) at line 27, BEFORE normpath/join/shutil.copyfile.
  //   - LocalArtifactRepository.log_artifacts  (local_artifact_repo.py:47-58):
  //       verify_artifact_path(artifact_path) at line 48, BEFORE join/dir_util.copy_tree.
  //   - HttpArtifactRepository.log_artifact    (http_artifact_repo.py:18-26):
  //       verify_artifact_path(artifact_path) at line 19, BEFORE the HTTP PUT.
  //
  // Why this blocks the specific mechanisms (mlflow/utils/validation.py:82-84):
  //   path_not_unique(name) := norm := posixpath.normpath(name);
  //     norm != name           -> rejects any non-canonical spelling ('a/./b', 'a//b', 'a/../b')
  //     norm == "."            -> rejects the current-directory alias
  //     norm.startswith("..")  -> rejects leading traversal segments
  //     norm.startswith("/")   -> rejects absolute paths
  //   Because the check requires the *exact* canonical form and rejects leading '..' and '/',
  //   the subsequent os.path.join(artifact_dir, artifact_path) cannot escape the artifact root,
  //   and the destination filename is additionally os.path.basename(local_file) (line 38).
  //
  // The barrier is placed on the artifact_path PARAMETER node of these functions: taint may
  // arrive there (via the MySummaries dispatch step from the call site), but no flow leaves
  // the node, so none of the guarded body uses (normpath/join/copy_tree/PUT) can propagate it.
  // The abstract base ArtifactRepository.log_artifact/log_artifacts (artifact_repo.py:40/53)
  // and the other repository implementations are NOT barriers — they perform no verification.
  // --------------------------------------------------------------------------
  private predicate guardedLogPathParam(DataFlow::Node n) {
    exists(Function f, Parameter p |
      n = DataFlow::parameterNode(p) and
      f.getArg(_) = p and
      p.getName() = "artifact_path" and
      f.getEnclosingModule().getFile().getRelativePath() = "mlflow/store/artifact/local_artifact_repo.py" and
      f.getName() in ["log_artifact", "log_artifacts"]
    )
    or
    exists(Function f, Parameter p |
      n = DataFlow::parameterNode(p) and
      f.getArg(_) = p and
      p.getName() = "artifact_path" and
      f.getEnclosingModule().getFile().getRelativePath() = "mlflow/store/artifact/http_artifact_repo.py" and
      f.getName() = "log_artifact"
    )
  }

  // --------------------------------------------------------------------------
  // X01 / X02 direct call arguments — arguments passed to the guard functions themselves.
  //   - verify_artifact_path: defined at artifact_repo.py:302-306, called at
  //     local_artifact_repo.py:27/48 and http_artifact_repo.py:19.
  //   - path_not_unique: defined at validation.py:82-84 (also used by the
  //     metric/param/tag name validators).
  // Marking the argument nodes of these calls as barriers cuts the branch of flow that
  // enters the guard call itself; the parameter barrier above is what protects the
  // guarded bodies. Both are kept for fidelity to labels X01/X02.
  // --------------------------------------------------------------------------
  private predicate guardCallArgument(DataFlow::Node n) {
    exists(Call call |
      call.getFunc() instanceof Name and
      call.getFunc().(Name).getId() in ["verify_artifact_path", "path_not_unique"] and
      n.asExpr() = call.getArg(0)
    )
  }

  /** Holds if flow through `n` is prohibited for pass 1. `passKey` must be "path_traversal". */
  predicate isBarrier(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      guardedLogPathParam(n)
      or guardCallArgument(n)
    )
  }
}
