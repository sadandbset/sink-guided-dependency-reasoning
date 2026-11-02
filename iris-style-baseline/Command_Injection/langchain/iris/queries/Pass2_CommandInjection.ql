/**
 * @name LangChain Pass 2: Command/Argument Injection (CWE-078)
 * @description
 *   Tracks untrusted input (chain entry parameters, LLM output, parsed
 *   agent actions, deserialized LLM text) through the agent tool-dispatch
 *   chain into command and code execution sinks (subprocess.run with
 *   shell=True, pexpect sendline, builtin exec/eval, and the
 *   ShellTool/PythonREPLTool/PythonAstREPLTool/BashProcess execution
 *   wrappers). Threat model: prompt injection - LLM output is treated as
 *   untrusted because prompts embed user/external content, and
 *   AgentAction.tool_input is the dispatch carrier into tools.
 *   Sources and sinks are Phase 1 reviewed labels (classification=tp)
 *   from run langchain-iris-pass2-labeling-20261015; a finding is a
 *   review candidate, not a confirmed vulnerability.
 * @id py/augur/langchain/pass2-command-injection
 * @kind path-problem
 * @problem.severity error
 * @precision low
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-077
 *       external/cwe/cwe-088
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

module Pass2Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "command_injection")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "command_injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "command_injection")
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node nodeFrom,
    DataFlow::Node nodeTo
  ) {
    MySummaries::isAdditionalTaintStep(
      nodeFrom, nodeTo, "command_injection"
    )
  }
}

module Pass2Flow = TaintTracking::Global<Pass2Config>;
import Pass2Flow::PathGraph

from Pass2Flow::PathNode source, Pass2Flow::PathNode sink
where Pass2Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted input flows from $@ into a command/code execution sink ($@). " +
    "Augur pass 2 (CWE-078, prompt-injection threat model): the source is " +
    "a reviewed tp label, and the sink is a labeled shell/exec surface in " +
    "the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> " +
    "ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review " +
    "before treating as a vulnerability.",
  source, "untrusted source", sink, "execution sink"
