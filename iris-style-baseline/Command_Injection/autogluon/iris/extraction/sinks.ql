/**
 * @name AutoGluon command execution candidates for Augur Pass 2
 * @description Extract subprocess, os, asyncio and pexpect execution calls for CWE-78 labeling.
 * @kind problem
 * @problem.severity recommendation
 * @id py/augur/autogluon/sink-candidates
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

predicate commandApiCall(
  DataFlow::CallCfgNode call, string moduleName, string apiName
) {
  (moduleName = "os" and apiName = "system" and
    call = API::moduleImport("os").getMember("system").getACall())
  or
  (moduleName = "os" and apiName = "popen" and
    call = API::moduleImport("os").getMember("popen").getACall())
  or
  (moduleName = "subprocess" and apiName = "run" and
    call = API::moduleImport("subprocess").getMember("run").getACall())
  or
  (moduleName = "subprocess" and apiName = "Popen" and
    call = API::moduleImport("subprocess").getMember("Popen").getACall())
  or
  (moduleName = "subprocess" and apiName = "call" and
    call = API::moduleImport("subprocess").getMember("call").getACall())
  or
  (moduleName = "subprocess" and apiName = "check_call" and
    call = API::moduleImport("subprocess").getMember("check_call").getACall())
  or
  (moduleName = "subprocess" and apiName = "check_output" and
    call = API::moduleImport("subprocess").getMember("check_output").getACall())
  or
  (moduleName = "subprocess" and apiName = "getoutput" and
    call = API::moduleImport("subprocess").getMember("getoutput").getACall())
  or
  (moduleName = "subprocess" and apiName = "getstatusoutput" and
    call = API::moduleImport("subprocess").getMember("getstatusoutput").getACall())
  or
  (moduleName = "asyncio" and apiName = "create_subprocess_shell" and
    call = API::moduleImport("asyncio").getMember("create_subprocess_shell").getACall())
  or
  (moduleName = "asyncio" and apiName = "create_subprocess_exec" and
    call = API::moduleImport("asyncio").getMember("create_subprocess_exec").getACall())
  or
  (moduleName = "pexpect" and apiName = "spawn" and
    call = API::moduleImport("pexpect").getMember("spawn").getACall())
}

from DataFlow::CallCfgNode call, DataFlow::Node commandArg,
  string moduleName, string apiName
where
  commandApiCall(call, moduleName, apiName) and
  (
    commandArg = call.getArg(0)
    or
    commandArg = call.getArgByName("args")
    or
    commandArg = call.getArgByName("cmd")
  )
select call.getNode(), "Review command argument for CWE-78; not a confirmed vulnerability.",
  "command_execution", moduleName, apiName, 0, commandArg.toString(),
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine()