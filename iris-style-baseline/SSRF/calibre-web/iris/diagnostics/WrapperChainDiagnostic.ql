/**
 * Diagnostic (NOT part of the official CWE-918 results).
 *
 * @name calibre-web SSRF wrapper-chain reachability diagnostic
 * @description For every parameter of every function defined in the cps
 *   package, checks whether taint can reach the Pass 3 network sinks
 *   (requests.get URL arguments, the Kobo store proxy URL, the provider
 *   session.get URLs, the Google Drive httplib2 download URL) using
 *   exactly the Phase 2 sink and summary models. Purpose: verify the local
 *   reachability of the internal wrapper chain
 *   (save_cover_from_url url parameter -> requests.get at
 *   cps/helper.py:740; provider search query parameters -> the provider
 *   fetch sites) and confirm that only the reviewed wrapper URL/query
 *   parameters - not arbitrary internal parameters (book paths, timeouts,
 *   headers, locale) - connect to the network egress. Expected rows: the
 *   url parameter of helper.save_cover_from_url (cps/helper.py:732) and
 *   the query parameters of the five provider search methods; anything
 *   else indicates a modeling gap to re-review. Results from this query
 *   are never counted as CWE-918 alerts (separate directory, no
 *   path-problem metadata, sources here are internal wrapper parameters
 *   that the reviewed labels deliberately keep OUT of MySources).
 * @id iris/calibre-web-cwe918/diagnostics/wrapper-chain
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
      cpsFunctionParameter(p) and
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
  "diagnostic: parameter of an internal cps function reaches a network request URL argument (wrapper-chain reachability check; not an official CWE-918 finding)"

/** A parameter of a function defined in the cps package (DB code only). */
private predicate cpsFunctionParameter(Parameter p) {
  exists(Function f, int i |
    (
      p = f.getArg(i)
      or
      p = f.getKeywordOnlyArg(i)
    ) and
    isCpsFunction(f)
  )
}

private predicate isCpsFunction(Function f) {
  f.getEnclosingModule().getFile().getRelativePath().matches("cps/%")
}
