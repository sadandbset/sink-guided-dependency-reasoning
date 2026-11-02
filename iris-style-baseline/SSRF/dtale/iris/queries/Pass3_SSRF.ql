/**
 * @name Server-Side Request Forgery (CWE-918)
 * @description Detects server-side request forgery in the D-Tale tree:
 *   untrusted input reaching the URL argument of a server-side network
 *   request. Sources, sinks, sanitizers and summary steps are the reviewed
 *   Pass 3 labels (iris/labels/labels.json, pass key "ssrf"): the primary
 *   flow is the unauthenticated /web-upload 'url' parameter ->
 *   csv/json/excel loader kwargs -> handle_path -> requests.get (D-Tale's
 *   shared remote-fetch funnel); the CLI loader options are a reviewed
 *   candidate boundary (local-operator attacker model). Sink alerts carry
 *   the reviewed attacker-controllability scope (full URL vs
 *   fixed-literal-caller candidate) instead of mixing severities.
 * @id py/augur/dtale/pass3-ssrf
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
  MySinks::getSinkAlertMessage(sink.getNode(), "ssrf")
