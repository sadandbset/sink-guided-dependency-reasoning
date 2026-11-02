/**
 * @name BinderHub CWE-78 diagnostic: internal parameters reaching command sinks
 * @description DIAGNOSTIC ONLY - NOT A VULNERABILITY FINDING. This query deliberately models internal function parameters (Build constructor command fields repo_url/ref/appendix/image_name/git_credentials, and the get_provider spec parameter) as sources. It checks reachability from those internal parameters to the Pass 2 command sinks when external control over the value is NOT established. Alerts from this query must be excluded from formal vulnerability results; only queries/Pass2_CommandInjection.ql produces formal detections.
 * @id py/augur/binderhub/pass2-diagnostic-parameter
 * @kind path-problem
 * @problem.severity error
 * @precision low
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

/**
 * Internal parameters with reachability evidence toward the command
 * construction, but WITHOUT external-control evidence:
 *   - Build.__init__ keyword-only parameters (build.py:60-121) consumed by
 *     Build.get_cmd()/submit() as the repo2docker command list elements.
 *   - BaseHandler.get_provider(provider_prefix, spec) parameter (base.py:159),
 *     from which the provider's spec-derived fields originate.
 */
private predicate isDiagnosticParameterSource(DataFlow::Node source) {
  exists(Function init, Parameter p |
    init.getName() = "__init__" and
    init.getScope().(Class).getName() = "Build" and
    (p = init.getArg(_) or p = init.getAKeywordOnlyArg()) and
    p.asName().getId() in ["repo_url", "ref", "appendix", "image_name", "git_credentials"] and
    source = DataFlow::parameterNode(p)
  )
  or
  exists(Function getProvider, Parameter specParam |
    getProvider.getName() = "get_provider" and
    getProvider.getScope().(Class).getName() = "BaseHandler" and
    specParam = getProvider.getArg(2) and
    source = DataFlow::parameterNode(specParam)
  )
}

module Pass2DiagnosticConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isDiagnosticParameterSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "command_injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "command_injection")
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "command_injection")
  }
}

module Pass2DiagnosticFlow = TaintTracking::Global<Pass2DiagnosticConfig>;
import Pass2DiagnosticFlow::PathGraph

from Pass2DiagnosticFlow::PathNode source, Pass2DiagnosticFlow::PathNode sink
where Pass2DiagnosticFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "[DIAGNOSTIC - not a vulnerability finding] Internal parameter reaches a command execution sink. No external control over this parameter was established; if it is, re-run the formal query queries/Pass2_CommandInjection.ql."
