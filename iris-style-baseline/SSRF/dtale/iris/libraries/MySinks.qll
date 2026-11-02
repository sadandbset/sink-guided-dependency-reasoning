/**
 * Augur Phase 2 - Pass 3 (CWE-918 SSRF) sink library.
 * Generated from reviewed labels: iris/labels/labels.json (pass 3; 2 sink entries:
 * 1 tp + 1 candidate). Sinks are pinned to the exact reviewed call sites and
 * argument positions - the labels marked every other requests.get location in
 * the tree as internal-lifecycle / fixed-host / docs-demo false positives
 * (views.py:196 kill, views.py:210 is_up, app.py:272 reaper, docs/* demo
 * apps), so only the 2 reviewed positions are modeled.
 *
 * Label -> predicate mapping (label id | site | API | arg index | scope):
 *   p3-sink-0012 (tp 0.95)  dtale/cli/clickutils.py:244  requests.get arg0
 *       Attacker control: FULL URL from the unauthenticated /web-upload 'url'
 *       parameter (scheme restricted to http/https by the is_url prefix check,
 *       clickutils.py:234-235; host/port/path/query fully attacker-controlled,
 *       no host allow-list, no private-IP blocking, no redirect control). The
 *       caller's 'proxy' additionally controls the requests proxies mapping
 *       (clickutils.py:240-243) - see query_generation_notes.md on the
 *       proxy-side gap.
 *   p3-sink-0016 (candidate dtale/datasets.py:40         requests.get arg0
 *   0.6)     Genuine URL argument position, but every in-tree caller passes a
 *       hardcoded GitHub literal (datasets.py:60/:72/:81) and /datasets only
 *       dispatches fixed function names (views.py:3984). Expected false
 *       positive unless a custom loader passes a URL - kept for recall per
 *       the reviewed candidate label.
 *
 * getSinkAlertMessage() returns the full alert message for a sink, embedding
 * the reviewed attacker-controllability scope so the query distinguishes
 * full-URL control from fixed-host / no-control sites instead of mixing
 * severities.
 *
 * Not yet compiled (query execution deferred per operator instruction).
 * Written against the codeql/python-all 7.1.2 API surface, which resolves from
 * the local pack cache for iris/qlpack.yml (same surface as the validated
 * SSRF/core sibling libraries). API used: Call.getArg(int),
 * Attribute.getName()/getObject(), Name.getId(), Location API. The database
 * stores forward-slash absolute paths (proven by the Phase 1 CSV output);
 * matches() patterns are string literals only, as required by the QL binding
 * rules.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySinks {

  /* ------------------------------------------------------------------
   * Public interface (pass key: "ssrf")
   * ------------------------------------------------------------------ */

  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "ssrf" and sinkSite(sink, _)
  }

  /** Gets the full CWE-918 alert message for `sink`, embedding its reviewed controllability scope. */
  string getSinkAlertMessage(DataFlow::Node sink, string passKey) {
    passKey = "ssrf" and sinkSite(sink, result)
  }

  /* ------------------------------------------------------------------
   * The 2 reviewed sink sites (label-pinned location + URL argument)
   * ------------------------------------------------------------------ */

  private predicate sinkSite(DataFlow::Node sink, string message) {
    // p3-sink-0012: handle_path funnel - requests.get(path, **req_kwargs)
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/dtale/cli/clickutils.py") and
      c.getLocation().getStartLine() = 244 and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject() instanceof Name and
      c.getFunc().(Attribute).getObject().(Name).getId() = "requests" and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches the URL argument (arg 0) of requests.get inside the shared remote-fetch funnel handle_path. " +
        "Attacker control: full URL - the /web-upload 'url' query parameter on the unauthenticated route (dtale/views.py:3921) controls scheme (limited to http/https by the is_url prefix check), host, port and path; " +
        "no host allow-list, no private-IP blocking, no redirect control. " +
        "The same request's proxy routing is attacker-controlled through the /web-upload 'proxy' parameter (requests proxies mapping, dtale/cli/clickutils.py:240-243)."
    )
    or
    // p3-sink-0016: load_zip demo dataset fetcher - requests.get(url)
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/dtale/datasets.py") and
      c.getLocation().getStartLine() = 40 and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject() instanceof Name and
      c.getFunc().(Attribute).getObject().(Name).getId() = "requests" and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches the URL argument (arg 0) of requests.get inside load_zip. " +
        "Attacker control: none in this tree - all in-tree callers pass hardcoded GitHub literals and /datasets dispatches fixed dataset names only (reviewed candidate sink; expected false positive unless a custom loader passes a URL)."
    )
  }
}
