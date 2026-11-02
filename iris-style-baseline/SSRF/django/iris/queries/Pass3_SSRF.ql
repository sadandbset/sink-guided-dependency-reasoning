/**
 * @name Untrusted URL input flows to a server-side request (SSRF)
 * @description Tracks untrusted URL/CLI input boundaries reviewed in Augur pass 3 to the server-side HTTP fetch argument of urllib.request.urlopen (django/contrib/sitemaps/__init__.py:27) or urllib.request.urlretrieve (django/core/management/templates.py:265) in the Django framework source. Sources are the reviewed ping_google() parameters and the management-CLI argv boundary; the smtplib connection sink is reviewed as a false positive and its alerts must be filtered in Step 6.
 * @id py/augur/django/pass3-ssrf
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-918
 *       external/cwe/cwe-099
 *       external/cwe/cwe-610
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
  "Untrusted URL input reaches a server-side request URL argument (CWE-918, Augur pass 3)."
