/**
 * @name Pass 3: Server-side request forgery via SVG external references
 * @description Finds untrusted SVG document content or document/entry URLs
 *   (public conversion API parameters of the svg2 entry functions and
 *   Surface.convert, document
 *   reference reads such as <image> href, <use>/<tref> href, xml:base and
 *   CSS @import URLs) flowing into the request URL of the single network
 *   egress urllib.request.urlopen (cairosvg/url.py:84) or the url_fetcher
 *   dispatch boundary (cairosvg/url.py:143) whose default target performs
 *   the urlopen request. Rendered by Augur Phase 2 Step 4-5 from the
 *   human-reviewed Pass 3 labels in iris/labels/labels.json (CWE-918).
 * @id py/augur/cairosvg/pass3-ssrf
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

from Pass3Flow::PathNode source, Pass3Flow::PathNode sink
where Pass3Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "SSRF: untrusted SVG content or URL reaches the request URL passed to urllib.request.urlopen() through the CairoSVG resource fetch chain (attacker may control the full target URL - scheme, host, port and path)."
