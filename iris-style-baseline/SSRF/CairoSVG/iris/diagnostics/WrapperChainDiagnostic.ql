/**
 * Diagnostic (NOT part of the official CWE-918 results).
 *
 * @name CairoSVG SSRF wrapper-chain reachability diagnostic
 * @description For every parameter of every cairosvg package function,
 *   checks whether taint can reach the Pass 3 network sinks
 *   (urllib.request.urlopen argument / url_fetcher dispatch argument)
 *   using exactly the Phase 2 sink and summary models. Purpose: verify the
 *   local reachability of the internal wrapper chain
 *   (Node.fetch_url -> read_url -> url_fetcher -> fetch -> urlopen) and
 *   confirm that only the reviewed wrapper URL parameters - not arbitrary
 *   internal parameters (resource_type, dpi, style, ...) - connect to the
 *   network egress. Expected rows: the url parameters of fetch
 *   (url.py:77), read_url (url.py:132), Node.fetch_url (parser.py:242)
 *   and Tree.__init__'s kwargs-derived fetch path inputs; anything else
 *   indicates a modeling gap to re-review. Results from this query are
 *   never counted as CWE-918 alerts (separate directory, no path-problem
 *   metadata, sources here are internal wrapper parameters that the
 *   reviewed labels deliberately keep OUT of MySources).
 * @id iris/cairosvg-cwe918/diagnostics/wrapper-chain
 * @tags ssrf
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySinks
import libraries.MySummaries

module WrapperDiagnosticConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      cairosvgFunctionParameter(p) and
      source = DataFlow::parameterNode(p)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "ssrf")
  }

  predicate isBarrier(DataFlow::Node node) { none() }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "ssrf")
  }
}

module WrapperDiagnosticFlow = TaintTracking::Global<WrapperDiagnosticConfig>;

from WrapperDiagnosticFlow::PathNode source, WrapperDiagnosticFlow::PathNode sink
where WrapperDiagnosticFlow::flowPath(source, sink)
select source.getNode(), sink.getNode(),
  "diagnostic: parameter of an internal cairosvg function reaches the network request URL (wrapper-chain reachability check; not an official CWE-918 finding)"

/** A parameter of a function defined in the cairosvg package (tests excluded). */
private predicate cairosvgFunctionParameter(Parameter p) {
  exists(Function f, int i |
    (
      p = f.getArg(i)
      or
      p = f.getKeywordOnlyArg(i)
    ) and
    isCairosvgFunction(f)
  )
}

private predicate isCairosvgFunction(Function f) {
  f.getEnclosingModule().getFile().getAbsolutePath().matches("%cairosvg%") and
  not f.getEnclosingModule().getFile().getAbsolutePath().matches("%test%")
}
