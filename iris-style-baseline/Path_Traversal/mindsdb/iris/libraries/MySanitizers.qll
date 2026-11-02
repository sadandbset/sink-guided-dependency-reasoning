/**
 * Augur Pass 1 (Path Traversal) sanitizer (barrier) library for the
 * mindsdb project.
 *
 * Generated in Phase 2 Step 4 from the reviewed Pass 1 labels
 * (labels/labels.json, pass_id 1, pass key "path_traversal").
 *
 * No CSV candidate node was labeled with role = sanitizer; the barriers
 * below are the concrete neutralizations that the label review verified in
 * real source (documented as sanitizer evidence in
 * labels/phase1_review.md section 4), each proven to neutralize a specific
 * traversal mechanism:
 *
 * 1. Path(<tainted>).name - pathlib basename extraction. Returning only the
 *    final component strips every directory segment, so neither '..', an
 *    absolute prefix, nor separator variants survive. Evidence sites:
 *      - integrations.py:69  connection_args[arg_name] = Path(arg_value).name
 *        (IntegrationController.add: the stored connection arg is basenamed;
 *        note the raw value is still read by the shutil.copy at line 68,
 *        which is why that copy is a tp sink reached BEFORE this barrier)
 *      - file_controller.py:71 file_name = Path(file_path).name
 *        (FileController.save_file default file_name when the form field is
 *        absent)
 *      - file_controller.py:128 Path(file_record.source_file_path).name
 *        (FileController.get_file_path retrieval path neutralization)
 *
 * 2. Branch-sensitive checks that CANNOT be modeled as node barriers and
 *    are deliberately absent (documented in
 *    report/query_generation_notes.md):
 *      - config.py:133-136: temp_dir_path.joinpath(file_name).resolve() +
 *        'temp_dir_path not in file_path.parents' containment guard. The
 *        guard only holds on one branch of the if, and dataflow barriers
 *        apply to nodes, not branches; the file.save sink (K100, label fp)
 *        is therefore expected to alert and be filtered at Step 6.
 *      - fs.py:297-298 / 311-312: relative_path.is_absolute() rejection in
 *        FileStorage.get_path/delete. Partial barrier only ('..' segments
 *        are not contained, resolve() is commented out at fs.py:295), and
 *        the rejection is branch-sensitive.
 *      - fs.py:314-316: delete() compares the resolved path for equality
 *        with the root, not containment.
 *      - werkzeug safe_join inside send_from_directory (framework code,
 *        outside this database's scope).
 *    No normpath/resolve/basename/startswith call is treated as a barrier
 *    mechanically: resolve() propagates taint in MySummaries.qll (it does
 *    not strip traversal), and only the specific reviewed `.name` sites
 *    above are barriers.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /**
   * Pass 1 barrier predicate. Only the "path_traversal" pass key is served.
   * Barriers are the reviewed Path(...).name basename extraction sites;
   * everything else flows (see file header for what is intentionally not a
   * barrier).
   */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    exists(Attribute a |
      node.asExpr() = a and
      a.getName() = "name" and
      a.getObject() instanceof Call and
      dottedName(a.getObject().(Call).getFunc()) = "Path" and
      (
        // integrations.py:69 - basename of ARG_TYPE.PATH connection args
        inFunction(a, "add", "mindsdb/interfaces/database/integrations.py")
        or
        // file_controller.py:71 - default file_name basename in save_file
        inFunction(a, "save_file", "mindsdb/interfaces/file/file_controller.py")
        or
        // file_controller.py:128 - retrieval path basename in get_file_path
        inFunction(a, "get_file_path", "mindsdb/interfaces/file/file_controller.py")
      )
    )
  }

  /* ------------------------------------------------------------------ */
  /* Helpers                                                             */
  /* ------------------------------------------------------------------ */

  private string dottedName(Expr e) {
    result = e.(Name).getId()
    or
    result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
  }

  private string relPath(AstNode n) {
    result = n.getLocation().getFile().getRelativePath()
  }

  private predicate inFunction(AstNode n, string funcName, string filePattern) {
    exists(Function f |
      f.getName() = funcName and
      relPath(f) = filePattern and
      relPath(n) = filePattern and
      (n.getScope() = f or n.getScope().getEnclosingScope*() = f)
    )
  }
}
