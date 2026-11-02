/**
 * Augur Phase 2 Step 4 - Pass 1 (Path Traversal) sink library for fides.
 *
 * Deterministically rendered from the reviewed Pass 1 labels in
 * iris/labels/labels.json (run iris-fides-pathtraversal-pass1-20261022):
 * every predicate below corresponds to a reviewed pass-1 entry with role
 * `sink` and classification `tp`, and to no other candidate. The reviewed
 * label set contains exactly two such entries, both on the catch-all
 * static-file serving chain of src/fides/api/main.py:
 *
 *   sink-064 (sink/tp 0.95, PRIMARY):   FileResponse(ui_file)  main.py:180
 *   sink-063 (sink/tp 0.65, secondary): ui_file.is_file()      main.py:170
 *
 * All other sink candidates are deliberately NOT sinks here (117 `none`/fp
 * sink rows: fixed-constant file APIs, operator CLI/config paths,
 * in-memory zip handling, graph-adjacency misfires; and the sanitizer/fp
 * guard rows which belong to MySanitizers) - see
 * iris/report/query_generation_notes.md for the full mapping.
 *
 * Path TEXT versus opened file OBJECT: each sink is anchored on the
 * expression that NAMES the file location - the Path argument handed to
 * FileResponse (sink-064) and the Path object receiving is_file
 * (sink-063) - never on a returned file/response object.
 *
 * Matching is AST-level (shapes already executed by
 * extraction/sinks.ql on this CLI/pack family: 2.25.1 / python-all),
 * constrained to the exact reviewed module and line.
 */

import python

import semmle.python.dataflow.new.DataFlow

module MySinks {

  /**
   * Holds if `sink` is a reviewed Pass 1 taint sink for pass key `passKey`.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and (
      fileResponseSink(sink) or
      isFileExistenceProbe(sink)
    )
  }

  /** Forward-slash-normalized absolute path of the file containing n
   *  (same helper shape as extraction/sinks.ql). */
  private string normalizedPathOf(AstNode n) {
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
  }

  bindingset[modulePathPattern]
  private predicate inModule(AstNode n, string modulePathPattern) {
    normalizedPathOf(n).matches(modulePathPattern)
  }

  /* ------------------------------------------------------------------ */
  /* Primary sink - file response (read + stream to the client)          */
  /* ------------------------------------------------------------------ */

  /**
   * sink-064 (sink/tp 0.95): FileResponse(ui_file) at main.py:180.
   *
   * src/fides/api/main.py:169-180 (read_other_paths):
   *   # Serve up the file as long as it is within the UI directory
   *   if ui_file and ui_file.is_file():
   *     if not path_is_in_ui_directory(ui_file):
   *       raise HTTPException(...)
   *     ...
   *     return FileResponse(ui_file)
   *
   * Dangerous position: argument 0 (the Path object naming the file to
   * serve) - matched as the argument expression, not the FileResponse
   * instance (the response object is never a sink node).
   *
   * Real file operation: starlette.responses.FileResponse opens the path
   * (open(...)/os.stat at response time, inside the external starlette
   * library which is NOT part of this database) and streams the file
   * content to the HTTP client. Access type: file READ exposed as a file
   * response. This call site is reached from read_other_paths, the
   * handler of the unauthenticated catch-all route
   * @app.get("/{catchall:path}") (main.py:154), with `ui_file` tainted
   * via the get_path_to_admin_ui_file fallback (main.py:167, see
   * MySummaries.qll). The path_is_in_ui_directory guard at :171 is NOT a
   * barrier (MySanitizers.qll documents the lexical-parents bypass), so
   * the served location is bounded only by the webserver process's read
   * permissions.
   *
   * ui.py:50 FileResponse(index) (sink-099, none/fp) serves the fixed
   * "index.html" from get_admin_index_as_response and is deliberately
   * NOT matched.
   */
  private predicate fileResponseSink(DataFlow::Node sink) {
    exists(Call c |
      inModule(c, "%/src/fides/api/main.py") and
      c.getLocation().getStartLine() = 180 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "FileResponse" and
      sink.asExpr() = c.getArg(0)
    )
  }

  /* ------------------------------------------------------------------ */
  /* Secondary sink - existence probe (stat oracle)                      */
  /* ------------------------------------------------------------------ */

  /**
   * sink-063 (sink/tp 0.65, secondary): ui_file.is_file() at main.py:170.
   *
   * src/fides/api/main.py:170 (read_other_paths):
   *   if ui_file and ui_file.is_file():
   *
   * Dangerous position: the RECEIVER of is_file - the Path object
   * (matched as the receiver expression `ui_file`, not the boolean
   * return value).
   *
   * Real file operation: pathlib is_file() performs an lstat/stat-family
   * probe; on the UNRESOLVED Path returned by get_path_to_admin_ui_file
   * the OS resolves the lexical ".." segments at stat time, so this node
   * is (a) a filesystem existence/fstype ORACLE that reaches outside the
   * packaged admin-UI root and (b) the gate for the FileResponse
   * exfiltration at :180. Access type: metadata read (no content
   * disclosure). Kept as a sink per the reviewed label at reduced
   * confidence (0.65): the same is_file call also fires on the safe
   * match_route branch (main.py:163 returns trusted packaged-file paths),
   * so alerts ending here are expected to be triaged in Step 6.
   */
  private predicate isFileExistenceProbe(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      inModule(c, "%/src/fides/api/main.py") and
      c.getLocation().getStartLine() = 170 and
      f = c.getFunc().(Attribute) and
      f.getName() = "is_file" and
      sink.asExpr() = f.getObject()
    )
  }
}
