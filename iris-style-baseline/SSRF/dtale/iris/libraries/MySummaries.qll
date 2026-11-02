/**
 * Augur Phase 2 - Pass 3 (CWE-918 SSRF) additional taint-step library.
 * Generated from reviewed labels: iris/labels/labels.json (pass 3; 8 summary/
 * candidate entries).
 *
 * Label -> predicate mapping (all steps conditional on concrete, verified
 * call shapes; no unconditional taint propagation):
 *   p3-sink-0013 (csv_loader.loader_func)    \
 *   p3-sink-0017 (excel_loader.load_file)     > kwargsPopStep: inside the three
 *   p3-sink-0019 (json_loader.loader_func)   /  loader wrappers the URL is
 *     extracted from the **kwargs dict via `kwargs.pop("path")`
 *     (csv_loader.py:29 inline, excel_loader.py:29, json_loader.py:38). The
 *     step links the kwargs dict (receiver of the pop call) to the pop
 *     result, which standard data-flow does not reliably model for
 *     dict.pop with a literal key. The keyword-argument -> **kwargs
 *     parameter hop at the load_csv(path=url, proxy=proxy) call sites
 *     (views.py:3933/:3939/:3945/:3951) relies on CodeQL's built-in
 *     star-kwargs modeling (documented as a reliance in
 *     report/query_generation_notes.md).
 *   p3-sink-0014/0018/0020 (handle_path call sites in the loaders) are
 *     covered by kwargsPopStep plus standard argument flow: the popped path
 *     is argument 0 of the handle_path call (csv_loader.py:29,
 *     excel_loader.py:31, json_loader.py:38) - a direct local edge.
 *   p3-sink-0011 (handle_path function, dtale/cli/clickutils.py:238)
 *     -> funnelParamStep: the `path` parameter of handle_path flows into
 *        argument 0 of requests.get(path, **req_kwargs) at
 *        clickutils.py:244. Encodes the reviewed funnel function row
 *        (redundant with standard local flow by design - belt and braces).
 *   p3-sink-0015 (load_zip function, dtale/datasets.py:39)
 *     -> loadZipParamStep: the `url` parameter of load_zip flows into
 *        argument 0 of requests.get(url) at datasets.py:40. No in-tree
 *        caller passes taint (hardcoded literals), so the step currently
 *        carries no flow; kept per the reviewed candidate label.
 *
 * URL concatenation steps (urljoin/urlparse-style) are deliberately NOT
 * modeled: the reviewed labels marked all 12 urllib.parse rows none/fp -
 * this tree builds no URLs by concatenation on the tainted path (the
 * /web-upload URL is passed through verbatim).
 *
 * Not yet compiled (query execution deferred per operator instruction).
 * Written against the codeql/python-all 7.1.2 API surface, which resolves from
 * the local pack cache for iris/qlpack.yml (same surface as the validated
 * SSRF/core sibling libraries). API used: Call.getFunc()/getArg(int),
 * Attribute.getName()/getObject(), Name.getId(), StringLiteral.getText(),
 * Function.getArgByName(), DataFlow::exprNode/parameterNode, Location API;
 * matches() patterns are string literals only, as required by the QL binding
 * rules.
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
      kwargsPopStep(nodeFrom, nodeTo)
      or
      funnelParamStep(nodeFrom, nodeTo)
      or
      loadZipParamStep(nodeFrom, nodeTo)
    )
  }

  /* ------------------------------------------------------------------
   * kwargs.pop("path") in the loader wrappers: kwargs dict -> popped path
   * (labels p3-sink-0013/0017/0019; feeds the handle_path call sites
   * p3-sink-0014/0018/0020 as argument 0 via standard local flow)
   * ------------------------------------------------------------------ */

  private predicate kwargsPopStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute func, Name recv, StringLiteral key |
      c.getLocation().getFile().getAbsolutePath().matches("%/dtale/cli/loaders/%") and
      func = c.getFunc() and
      func.getName() = "pop" and
      recv = func.getObject() and
      recv.getId() = "kwargs" and
      key = c.getArg(0) and
      key.getText() = "path" and
      nodeFrom = DataFlow::exprNode(recv) and
      nodeTo = DataFlow::exprNode(c)
    )
  }

  /* ------------------------------------------------------------------
   * handle_path funnel: `path` parameter -> requests.get argument 0
   * (label p3-sink-0011, dtale/cli/clickutils.py:238 -> :244)
   * ------------------------------------------------------------------ */

  private predicate funnelParamStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function f, Parameter p, Call c |
      f.getName() = "handle_path" and
      f.getLocation().getFile().getAbsolutePath().matches("%/dtale/cli/clickutils.py") and
      p = f.getArgByName("path") and
      c.getLocation().getFile().getAbsolutePath().matches("%/dtale/cli/clickutils.py") and
      c.getLocation().getStartLine() = 244 and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject() instanceof Name and
      c.getFunc().(Attribute).getObject().(Name).getId() = "requests" and
      nodeFrom = DataFlow::parameterNode(p) and
      nodeTo = DataFlow::exprNode(c.getArg(0))
    )
  }

  /* ------------------------------------------------------------------
   * load_zip: `url` parameter -> requests.get argument 0
   * (label p3-sink-0015, dtale/datasets.py:39 -> :40)
   * ------------------------------------------------------------------ */

  private predicate loadZipParamStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function f, Parameter p, Call c |
      f.getName() = "load_zip" and
      f.getLocation().getFile().getAbsolutePath().matches("%/dtale/datasets.py") and
      p = f.getArgByName("url") and
      c.getLocation().getFile().getAbsolutePath().matches("%/dtale/datasets.py") and
      c.getLocation().getStartLine() = 40 and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject() instanceof Name and
      c.getFunc().(Attribute).getObject().(Name).getId() = "requests" and
      nodeFrom = DataFlow::parameterNode(p) and
      nodeTo = DataFlow::exprNode(c.getArg(0))
    )
  }
}
