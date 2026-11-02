/**
 * Augur Phase 2 - Pass 3 (CWE-918 SSRF) additional taint-step library.
 * Generated from reviewed labels: iris/labels/labels.json (pass 3, 155 summary/
 * candidate entries).
 *
 * Label -> predicate mapping:
 *   template_render (90 entries: 76 async_render + 14 render)
 *     -> templateRenderStep: any argument of a `.render(...)` / `.async_render(...)`
 *        call flows into the rendered result. Source evidence: the rendered string
 *        interpolates template variables (e.g. rest_command/__init__.py:97-103
 *        `template_url.async_render(variables=service.data, parse_result=False)`
 *        where variables are authenticated service data - the only reviewed path
 *        on which template output becomes a fetch URL).
 *   url_build (65 entries: 48 URL + 9 URL.build + 8 urljoin)
 *     -> urlConstructionStep: argument 0 of yarl.URL(...) / URL.build(...) /
 *        urllib urljoin(...) flows into the resulting URL object. Source evidence:
 *        URL normalization is a documented taint-loss point between input and the
 *        fetch sinks (blueprint/importer.py:174, helpers/network.py:65,
 *        media_player/browse_media.py:63).
 *
 * Both steps are conditional on concrete call shapes; no unconditional taint
 * propagation is introduced. `urljoin` argument 1 (joined relative URL) is NOT
 * modeled because the reviewed labels pin arg index 0 only - recorded as a label
 * gap in report/query_generation_notes.md rather than silently widened.
 *
 * Inter-procedural wrapper propagation (fetch_blueprint_from_*, load_data,
 * async_get_file_from_url, etc.) is intentionally NOT re-modeled here: the
 * reviewed labels mark those wrapper rows role=none precisely because standard
 * call/return data-flow already carries taint from the call arguments into the
 * inner sink rows.
 *
 * Verified against codeql/python-all 7.1.2 (Call.getAnArg(), Call.getANamedArg().
 * getValue(), Attribute.getName()).
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {

  /* ------------------------------------------------------------------
   * Public interface (pass key: "ssrf")
   * ------------------------------------------------------------------ */

  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "ssrf" and
    (
      templateRenderStep(nodeFrom, nodeTo)
      or
      urlConstructionStep(nodeFrom, nodeTo)
    )
  }

  /* ------------------------------------------------------------------
   * Template render: render/async_render arguments -> rendered result
   * ------------------------------------------------------------------ */

  private predicate templateRenderStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute func, Expr arg |
      func = c.getFunc() and
      func.getName() in ["async_render", "render"] and
      (
        arg = c.getAnArg()
        or
        arg = c.getAKeyword().getValue()
      ) and
      nodeFrom = DataFlow::exprNode(arg) and
      nodeTo = DataFlow::exprNode(c)
    )
  }

  /* ------------------------------------------------------------------
   * URL construction: yarl.URL(x) / URL.build(...) / urljoin(x, ...)
   * argument 0 -> URL result
   * ------------------------------------------------------------------ */

  private predicate urlConstructionStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Expr arg |
      isUrlConstructorCall(c) and
      arg = c.getArg(0) and
      nodeFrom = DataFlow::exprNode(arg) and
      nodeTo = DataFlow::exprNode(c)
    )
  }

  /** yarl.URL(x), URL(x) (from-import), URL.build(...), urljoin(...) or <module>.urljoin(...). */
  private predicate isUrlConstructorCall(Call c) {
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() in ["URL", "urljoin"]
    or
    exists(Attribute func |
      func = c.getFunc() and
      (
        func.getName() in ["URL", "urljoin"]
        or
        (func.getName() = "build" and func.getObject() instanceof Name and func.getObject().(Name).getId() = "URL")
      )
    )
  }
}
