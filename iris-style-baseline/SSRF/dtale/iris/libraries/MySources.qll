/**
 * Augur Phase 2 - Pass 3 (CWE-918 SSRF) source library.
 * Generated from reviewed labels: iris/labels/labels.json (pass 3; 2 source/tp
 * + 4 source/candidate entries; 9 batches, model glm-5.3, 2026-10-20).
 *
 * Label -> predicate mapping:
 *   p3-src-0164 (tp 0.9)      -> webUploadQueryArgRead: get_str_arg(request, "url")
 *                                 at dtale/views.py:3930 inside web_upload (route
 *                                 "/web-upload", views.py:3921, unauthenticated in
 *                                 the default deployment: global_state.py:38
 *                                 AUTH_SETTINGS active=False; auth.py:40-41
 *                                 requires_auth no-ops when inactive).
 *   p3-src-0165 (tp 0.9)      -> webUploadQueryArgRead: get_str_arg(request, "proxy")
 *                                 at dtale/views.py:3931 (same boundary; forwarded
 *                                 into the loader kwargs and injected as the
 *                                 requests proxies mapping, clickutils.py:240-243).
 *   p3-src-0002/0003/0004     -> cliLoaderOptionValue: the CLI loader options are
 *   (candidate 0.6)              constructed by click.option(...) inside
 *                                 setup_loader_options (dtale/cli/loaders/
 *                                 __init__.py:137/:149/:157) and land in main's
 *                                 **kwargs parameter; the taint origin modeled here
 *                                 is that **kwargs parameter (see
 *                                 report/query_generation_notes.md for the
 *                                 label-location -> node mapping decision).
 *   p3-src-0013 (candidate     -> cliLoaderOptionValue: legacy loader_options
 *   0.55)                         constructor (dtale/cli/clickutils.py:91, no in-tree
 *                                 caller) - the generated options would flow through
 *                                 the same main(**kwargs) boundary, so the identical
 *                                 node is covered.
 *
 * All other reviewed source rows (135 remaining http_query_arg call sites,
 * request.args.to_dict / request.json / request.form / request.files reads, the 22
 * script.py bootstrap options, env and config_file reads) were labeled none/fp
 * with verified no-network-path evidence and are deliberately NOT sources here.
 * Internal network-wrapper parameters (handle_path path/kwargs, loader_func
 * path/proxy, load_zip url) are NOT sources (label decision; concern 9 of the
 * Phase 1 review) - they are covered as summary steps in MySummaries.qll.
 *
 * Not yet compiled (query execution deferred per operator instruction).
 * Written against the codeql/python-all 7.1.2 API surface, which resolves from
 * the local pack cache for iris/qlpack.yml (same surface as the validated
 * SSRF/core sibling libraries). API used: DataFlow::exprNode/parameterNode,
 * Call.getFunc()/getArg(int), Name.getId(), StringLiteral.getText(),
 * Function.getArgByName(), Location API. DB paths are absolute with forward
 * slashes (proven by the Phase 1 CSV output); matches() patterns are string
 * literals only, as required by the QL binding rules.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySources {

  /* ------------------------------------------------------------------
   * Public interface (pass key: "ssrf")
   * ------------------------------------------------------------------ */

  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "ssrf" and
    (
      webUploadQueryArgRead(source)
      or
      cliLoaderOptionValue(source)
    )
  }

  /* ------------------------------------------------------------------
   * /web-upload boundary: get_str_arg(request, "url"/"proxy")
   * (labels p3-src-0164 / p3-src-0165, source/tp)
   *
   * The tainted value is the call result; the node is pinned to the two
   * reviewed call sites (file + start line + wrapper name + literal
   * parameter name), matching the reviewed labels exactly.
   * ------------------------------------------------------------------ */

  private predicate webUploadQueryArgRead(DataFlow::Node source) {
    exists(Call c, StringLiteral key |
      c.getLocation().getFile().getAbsolutePath().matches("%/dtale/views.py") and
      c.getLocation().getStartLine() in [3930, 3931] and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "get_str_arg" and
      key = c.getArg(1) and
      key.getText() in ["url", "proxy"] and
      source = DataFlow::exprNode(c)
    )
  }

  /* ------------------------------------------------------------------
   * CLI loader option boundary: main(**kwargs) of the 'dtale' command
   * (labels p3-src-0002/0003/0004 + p3-src-0013, source/candidate)
   *
   * The loader options --csv-path/--csv-proxy/--json-path/--json-proxy/
   * --excel-path/--excel-proxy (built by setup_loader_options from the
   * loaders' LOADER_PROPS) and --parquet-path arrive through main's
   * **kwargs parameter (dtale/cli/script.py:104-116) and flow
   * check_loaders(kwargs) -> find_loader -> loader_func(**kwargs) ->
   * handle_path -> requests.get. Trust boundary: local CLI operator
   * (weaker attacker model than /web-upload - reviewed candidate, see
   * query_generation_notes.md).
   * ------------------------------------------------------------------ */

  private predicate cliLoaderOptionValue(DataFlow::Node source) {
    exists(Function f, Parameter p |
      f.getName() = "main" and
      f.getLocation().getFile().getAbsolutePath().matches("%/dtale/cli/script.py") and
      p = f.getArgByName("kwargs") and
      source = DataFlow::parameterNode(p)
    )
  }
}
