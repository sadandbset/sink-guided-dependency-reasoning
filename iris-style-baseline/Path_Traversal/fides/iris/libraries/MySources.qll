/**
 * Augur Phase 2 Step 4 - Pass 1 (Path Traversal) source library for fides.
 *
 * Deterministically rendered from the reviewed Pass 1 labels in
 * iris/labels/labels.json (run iris-fides-pathtraversal-pass1-20261022):
 * ONLY entries with role=source and classification=tp are modeled. The
 * reviewed label set contains exactly one such entry:
 *
 *   src-044 (source/tp, conf 0.95):
 *     request.path_params["catchall"] at src/fides/api/main.py:160
 *
 * All other source candidates are deliberately NOT sources here (see
 * iris/report/query_generation_notes.md for the full mapping and the
 * exclusion rationale):
 *   - src-043 (source/fp 0.60): the whole `request: Request` parameter of
 *     read_other_paths - rejected to avoid over-tainting every request
 *     field (references/python.md section 7.4); the precise path_params
 *     subscript (src-044) is the reviewed anchor;
 *   - src-068 (source/fp 0.80): the zip upload body parameter of
 *     register_custom_connector_template (saas_config_endpoints.py:363) -
 *     genuine untrusted boundary but classified fp for Pass 1: the zip is
 *     parsed in memory (BytesIO) and its content never reaches a
 *     filesystem path in this pass (manual-review carry-over for Pass 4);
 *   - the 11 os.getenv rows (S1) and 17 Click CLI rows (S2):
 *     operator/deployment-trust boundaries, not the Pass 1 attacker model;
 *   - the middleware/endpoint request-field rows (S3/S5/S6): consumed only
 *     for logging/analytics/audit-DB/consent reporting or outbound SaaS
 *     authentication, never as a filesystem path.
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python

import semmle.python.dataflow.new.DataFlow

module MySources {

  /**
   * Holds if `source` is a reviewed Pass 1 taint source for pass key
   * `passKey`.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and catchallPathParamSource(source)
  }

  /** Forward-slash-normalized absolute path of the file containing n
   *  (same helper shape as extraction/sources.ql; bindingset declares the
   *  caller passes a bound pattern that only appears in checked positions
   *  such as the receiver of matches). */
  private string normalizedPathOf(AstNode n) {
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
  }

  bindingset[modulePathPattern]
  private predicate inModule(AstNode n, string modulePathPattern) {
    normalizedPathOf(n).matches(modulePathPattern)
  }

  /**
   * src-044 (source/tp 0.95): the catch-all route path variable.
   *
   * src/fides/api/main.py:154-160 (read_other_paths):
   *   @app.get("/{catchall:path}", response_class=Response, tags=["Default"])
   *   def read_other_paths(request: Request) -> Response:
   *     ...
   *     path = request.path_params["catchall"]
   *
   * External input boundary: the URL remainder after the leading "/" of
   * ANY request that does not match a more specific route. The Starlette
   * router percent-DECODES the path before populating path_params, so the
   * attacker controls the full decoded string, including ".." segments
   * and "/" separators (GET /..%2F..%2F..%2Fetc%2Fpasswd -> catchall =
   * "../../etc/passwd"). The value is always relative (the router strips
   * the leading "/"), which is what keeps the lexical guard in
   * path_is_in_ui_directory satisfiable (see MySanitizers.qll).
   *
   * Access conditions: the route registers NO scope dependency (no
   * Security(...)/dependencies= on the decorator at main.py:154), so the
   * parameter is reachable by an unauthenticated remote HTTP client; the
   * API_PREFIX 404 branch at main.py:183 only affects api-prefixed paths.
   *
   * Downstream use (each step verified in the real source):
   *   main.py:163  match_route(get_ui_file_map(), path) - fixed-map
   *               selector, no path derivation (NOT a summary edge);
   *   main.py:167  get_path_to_admin_ui_file(path) - the reviewed
   *               summary/tp wrapper (MySummaries.qll);
   *   main.py:170  ui_file.is_file() - sink/tp (existence oracle);
   *   main.py:180  FileResponse(ui_file) - sink/tp (file response).
   */
  private predicate catchallPathParamSource(DataFlow::Node source) {
    exists(Subscript s, Attribute base |
      inModule(s, "%/src/fides/api/main.py") and
      s.getLocation().getStartLine() = 160 and
      base = s.getObject().(Attribute) and
      base.getName() = "path_params" and
      base.getObject().(Name).getId() = "request" and
      source.asExpr() = s
    )
  }
}
