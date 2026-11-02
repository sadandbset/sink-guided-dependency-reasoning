/**
 * @name Pass 3: Server-side request forgery via request-derived fetch URLs
 * @description Finds untrusted web-request inputs of the Flask routes
 *   (the book-edit cover_url form field, the metadata-search query of
 *   /metadata/search and /metadata/provider, the Kobo proxy
 *   request.full_path path suffix, and second-order response-derived
 *   provider URLs) flowing into the URL argument positions of the
 *   server-side network requests: requests.get in
 *   helper.save_cover_from_url, the Kobo store proxy requests.request,
 *   the metadata provider search fetches, and the Google Drive httplib2
 *   download. Rendered by Augur Phase 2 Step 4-5 from the human-reviewed
 *   Pass 3 labels in iris/labels/labels.json (CWE-918).
 * @id py/augur/calibre-web/pass3-ssrf
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

module Pass3Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "ssrf")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "ssrf")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "ssrf")
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "ssrf")
  }
}

module Pass3Flow = TaintTracking::Global<Pass3Config>;
import Pass3Flow::PathGraph

from Pass3Flow::PathNode source, Pass3Flow::PathNode sink, string msg
where
  Pass3Flow::flowPath(source, sink) and
  ssrfMessage(sink.getNode(), msg)
select sink.getNode(), source, sink, msg

/**
 * The alert message, differentiated by the attacker's URL control scope at
 * the reviewed sink sites (per the labeling rubric: full control, host
 * pinned with request-derived path, fixed-host provider query embedding,
 * and second-order response-derived URLs must not be conflated).
 *
 * Branches are mutually exclusive by sink file (and by line for the two
 * files that carry two different scopes):
 *   - helper.py / editbooks.py (cover flow, snk-004/snk-007): full target
 *     control - the cover_url form value is the entire request URL.
 *   - kobo.py (store proxy, snk-008/snk-009/010/011): host pinned to
 *     storeapi.kobo.com; path suffix, headers and body are request-derived.
 *   - google.py / comicvine.py, lubimyczytac.py:115, amazon.py:110
 *     (provider search fetches): fixed host, quote-encoded search text
 *     (Amazon embeds the raw query after a fixed prefix).
 *   - lubimyczytac.py:203, amazon.py:53, gdriveutils.py:626: second-order
 *     URLs echoed out of earlier remote responses / Drive API metadata.
 */
private predicate ssrfMessage(DataFlow::Node sink, string msg) {
  exists(string base, int line |
    base = sink.asExpr().getLocation().getFile().getBaseName() and
    line = sink.asExpr().getLocation().getStartLine() and
    (
      (
        base = "helper.py" or
        base = "editbooks.py"
      ) and
      msg = "SSRF (full target control): the attacker-supplied cover_url form field of the book edit route flows into the URL argument of a server-side requests.get via helper.save_cover_from_url (cps/helper.py:740). " +
        "Scheme, host, port and path are chosen by the submitting (authenticated edit+upload) user; the localhost check is conditional on the operator allow_localhost flag and redirects are followed."
      or
      base = "kobo.py" and
      msg = "SSRF (partial: host pinned): the request.full_path-derived path suffix (plus verbatim header/body forwarding) reaches the URL argument of requests.request to the fixed Kobo store host storeapi.kobo.com (cps/kobo.py:96). " +
        "The attacker controls the path/query and the forwarded headers, not the host; the proxy is only active when the admin enables config_kobo_proxy."
      or
      (
        base = "google.py" or
        base = "comicvine.py" or
        (base = "lubimyczytac.py" and line <= 150) or
        (base = "amazon.py" and line >= 100)
      ) and
      msg = "SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); " +
        "scheme and host are not attacker-controlled, only the query/path component is."
      or
      (
        (base = "lubimyczytac.py" and line >= 200) or
        (base = "amazon.py" and line <= 60) or
        base = "gdriveutils.py"
      ) and
      msg = "SSRF (second-order): a URL derived from an earlier remote response (provider search-result HTML href or Google Drive file metadata) is re-fetched server-side; " +
        "not directly web-input-controlled - the request target can only be steered by a malicious or compromised upstream service."
    )
  )
}
