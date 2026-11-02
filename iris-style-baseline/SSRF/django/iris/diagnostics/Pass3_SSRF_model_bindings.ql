/**
 * @name Augur pass 3 model bindings (diagnostic, not a CWE-918 alert)
 * @description Diagnostic-only query: reports every data-flow node matched by the pass-3 source/sink models and every endpoint of the pass-3 additional taint steps, so the generated model's AST bindings (ping_google parameters, argv parameters, urlopen/urlretrieve/connection_class call arguments, summary edges) can be verified before the formal pass query is executed. Paths reported here MUST NOT be counted as formal CWE-918 findings; Step 6 only consumes the output of queries/Pass3_SSRF.ql.
 * @id py/augur/django/pass3-ssrf-diag
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @tags diagnostics
 */

import python
import semmle.python.dataflow.new.DataFlow

import libraries.MySources
import libraries.MySinks
import libraries.MySummaries

from DataFlow::Node node, string msg
where
  (
    MySources::isSource(node, "ssrf") and
    msg = "pass3 source binding: " + node.toString()
  )
  or
  (
    MySinks::isSink(node, "ssrf") and
    msg = "pass3 sink binding: " + node.toString()
  )
  or
  (
    exists(DataFlow::Node other |
      MySummaries::isAdditionalTaintStep(node, other, "ssrf")
    ) and
    msg = "pass3 summary step 'from' endpoint: " + node.toString()
  )
  or
  (
    exists(DataFlow::Node other |
      MySummaries::isAdditionalTaintStep(other, node, "ssrf")
    ) and
    msg = "pass3 summary step 'to' endpoint: " + node.toString()
  )
select node, msg
