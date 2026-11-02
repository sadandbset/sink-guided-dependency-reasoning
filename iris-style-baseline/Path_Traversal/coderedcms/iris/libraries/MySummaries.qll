/**
 * Augur Phase 2 - Pass 1 additional taint steps (machine-generated from
 * reviewed labels).
 *
 * Generated from: iris/labels/labels.json, pass 1 (Path Traversal,
 * CWE-022/023/036/073), run coderedcms-pass1-labeling-20261021, model glm-5.3.
 *
 * Only propagation edges that are NOT already provided by the local
 * codeql/python-all 7.1.x standard library are modeled here, and each is
 * backed by a reviewed summary-role label and by the real code path:
 *
 *  Modeled in this file (labeled summary entries not covered by the stdlib):
 *   - storage.get_available_name(name)   arg 0   -> result
 *     (K-wff_models-243-get_available_name, K-wff_models-340-get_available_name,
 *      K-page_models-1210-get_available_name)
 *   - storage.path(name)                  arg 0   -> result
 *     (K-wff_models-342-path, K-wff_models-344-path, K-wff_models-499-path)
 *   - str(x) builtin conversion          arg 0   -> result
 *     (part of the labeled destination-construction chains
 *      K-wff_models-244-Path / K-page_models-1211-Path:
 *      str(Path(directory) / file.name))
 *   - dict .get(key) on the loaded submission data  receiver -> result
 *     (scoped to coderedcms/wagtail_flexible_forms/models.py - required for
 *      the reviewed db_json source entries to reach the
 *      get_thumbnail_path/delete_file channels)
 *
 *  Already modeled by codeql/python-all 7.1.x (NOT duplicated here - the
 *  labeled summary families resolve through the standard library):
 *   - pathlib.Path(...) constructor, args -> result, the `/` operator
 *     (operand taint -> result), .with_suffix/.with_name injection and
 *     .parent type-preserving attribute:
 *     Stdlib.qll PathlibPathTaintStep (semmle/python/frameworks/Stdlib.qll,
 *     class PathlibPathTaintStep extends TaintTracking::AdditionalTaintStep;
 *     constructor/attribute/method lists at Stdlib.qll:2609-2630).
 *     Covers labels K-wff_models-244-Path, K-page_models-1211-Path,
 *     K-wff_models-336-Path, K-wff_models-337-with_suffix,
 *     K-wff_models-491-Path, K-wff_models-493-parent, K-wff_models-499-Path.
 *   - os.path.join (all args -> result) and os.path.splitext (arg -> result):
 *     Stdlib.qll OsPathComputationAdditionalTaintStep ("join", "splitext",
 *     "abspath", "basename", "normpath", "realpath", ... are path
 *     computations that propagate taint). Covers labels
 *     K-views-114-join, K-forms-68-splitext, K-forms-73-splitext.
 *   Note: os.path.dirname/abspath/normpath/realpath also propagate taint in
 *   the stdlib model - this is standard-library behavior, not a sanitizer,
 *   and the reviewed labels correctly recorded none of them as barriers.
 *
 *  NOT modeled (documented limitation, see report/query_generation_notes.md):
 *   - general dict/list content propagation beyond the scoped .get() step
 *     (dict stores, .values(), list concatenation in
 *     get_files_by_field/delete_files) - the second-order delete channel
 *     (json.loads -> get_files_by_field -> storage.delete) needs those hops
 *     and will not fully resolve without them.
 *   - unconditional parameter->return edges for the 7 reviewed
 *     internal_file_wrapper rows (serve_protected_file, save_files,
 *     process_data, get_thumbnail_path, delete_file, delete_files,
 *     CreateProject.handle): their flows are intra-procedural (source nodes
 *     are inside the wrapper bodies) and global taint tracking handles the
 *     interprocedural call segments; adding param->return edges would be
 *     evidence-free cross-function pollution.
 *
 * Pass key: "path_traversal".
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /**
   * Holds if taint may flow from `nodeFrom` to `nodeTo` in one additional
   * step for the given pass key, beyond the standard data-flow steps.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    (
      storageGetAvailableNameStep(nodeFrom, nodeTo)
      or
      storagePathStep(nodeFrom, nodeTo)
      or
      strConversionStep(nodeFrom, nodeTo)
      or
      submissionDictGetStep(nodeFrom, nodeTo)
    )
  }

  /**
   * The audit scope: the coderedcms package as extracted in Phase 1 Step 2 -
   * excludes generated migrations, tests, the project scaffolding template and
   * the nested CodeQL database tree (WORKFLOW.md 4.3.2).
   * Two named variants (QL forbids overloading these argument types):
   * inAuditScopeAst for AST-matched call sites, inAuditScopeNode for
   * DataFlow::Node/MethodCallNode-matched call sites.
   */
  private predicate inAuditScopeAst(AstNode n) {
    inAuditScopeLoc(n.getLocation())
  }

  private predicate inAuditScopeNode(DataFlow::Node n) {
    inAuditScopeLoc(n.getLocation())
  }

  private predicate inAuditScopeLoc(Location loc) {
    exists(string path |
      path = loc.getFile().getAbsolutePath() and
      path.matches("%/coderedcms/%") and
      not path.matches("%/migrations/%") and
      not path.matches("%/tests/%") and
      not path.matches("%/project_template/%") and
      not path.matches("%/coderedcms-db/%")
    )
  }

  /**
   * Django storage name de-duplication: storage.get_available_name(name) is
   * an external (Django) implementation that returns a storage-usable name
   * derived from its argument; the reviewed labels mark it summary/candidate
   * (0.6) precisely because any sanitization it applies is invisible to this
   * database. Propagation arg 0 -> result is required for the upload write
   * chains:
   *   wff models.py:243  str(Path(directory) / file.name) -> storage.open :245
   *   wff models.py:340  thumbnail_path -> thumbnail.save :344
   *   page_models.py:1210 str(Path(directory) / val.name) -> storage.open :1212
   */
  private predicate storageGetAvailableNameStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(DataFlow::MethodCallNode mc |
      mc.getMethodName() = "get_available_name" and
      inAuditScopeNode(mc) and
      nodeFrom = mc.getArg(0) and
      nodeTo = mc
    )
  }

  /**
   * Django storage path resolution: storage.path(name) resolves a
   * storage-relative name to an absolute filesystem path
   * (FileSystemStorage.path uses safe_join internally - external to this
   * database). Propagation arg 0 -> result per the reviewed summary labels
   * (K-wff_models-342-path, K-wff_models-344-path, K-wff_models-499-path):
   *   wff models.py:342  Image.open(storage.path(path))
   *   wff models.py:344  thumbnail.save(storage.path(thumbnail_path))
   *   wff models.py:499  Path(storage.path(directory)).rmdir()
   * The storage.path calls at wff models.py:241 / page_models.py:1208 are
   * also matched by this step; their argument is the server-generated
   * session_key directory (reviewed as non-tainted), so no flow is introduced
   * there - consistent with their `none` sink-side labels.
   */
  private predicate storagePathStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(DataFlow::MethodCallNode mc |
      mc.getMethodName() = "path" and
      inAuditScopeNode(mc) and
      nodeFrom = mc.getArg(0) and
      nodeTo = mc
    )
  }

  /**
   * str(...) builtin conversion in the audit scope: preserves its argument
   * value as a string. Evidence: the two reviewed upload-destination
   * constructions wrap the pathlib result in str() before passing it to
   * storage.get_available_name:
   *   wff models.py:244   str(Path(directory) / file.name)
   *   page_models.py:1211 str(Path(directory) / val.name)
   *   (also wff models.py:337 str(path.with_suffix(...)) in the thumbnail
   *    chain)
   * Without this step the taint chain from the labeled upload_name sources
   * through Path()/`/` (stdlib steps) to storage.get_available_name would
   * break at the str() call.
   */
  private predicate strConversionStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "str" and
      inAuditScopeAst(c) and
      nodeFrom = DataFlow::exprNode(c.getArg(0)) and
      nodeTo = DataFlow::exprNode(c)
    )
  }

  /**
   * Dict member access on the loaded submission data: `<dict>.get(key)`
   * receiver -> result, scoped to
   * coderedcms/wagtail_flexible_forms/models.py.
   *
   * This is the single container-content step added for the reviewed db_json
   * source entries (json.loads at :204/:444 returns the submission data;
   * step_data.get(name) at :450-:451 / data.get(name) at :364-:365 extract
   * the per-field values that are re-used as file paths by
   * get_thumbnail_path/delete_file). Scope-limited to this one file to avoid
   * general cross-function container pollution; without it, none of the 6
   * reviewed db_json source entries could reach any sink.
   */
  private predicate submissionDictGetStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(DataFlow::MethodCallNode mc |
      mc.getMethodName() = "get" and
      mc.getLocation().getFile().getAbsolutePath()
        .matches("%/coderedcms/wagtail_flexible_forms/models.py") and
      nodeFrom = mc.getObject() and
      nodeTo = mc
    )
  }
}
