/**
 * @name Robust RCE Sink Finder (API Graphs & AST Fallback)
 * @description Accurately locates OS command injection and Code injection sinks using API graphs.
 * @id python/robust-rce-sinks
 * @kind problem
 * @problem.severity error
 */

import python
import semmle.python.ApiGraphs

from AstNode sink, string funcName
where
  // ==========================================
  // 1. 现代 API Graph 追踪 (精准捕获导入和内置函数)
  // 无论代码是 from subprocess import Popen 还是 import subprocess; subprocess.Popen 都能捕获
  // ==========================================
  exists(API::CallNode call |
    (
      // 追踪 subprocess 模块
      call = API::moduleImport("subprocess").getMember("Popen").getACall() and funcName = "subprocess.Popen" or
      call = API::moduleImport("subprocess").getMember("run").getACall() and funcName = "subprocess.run" or
      call = API::moduleImport("subprocess").getMember("call").getACall() and funcName = "subprocess.call" or
      // 追踪 os 模块
      call = API::moduleImport("os").getMember("system").getACall() and funcName = "os.system" or
      call = API::moduleImport("os").getMember("popen").getACall() and funcName = "os.popen" or
      // 追踪 Python 内置代码执行函数
      call = API::builtin("exec").getACall() and funcName = "builtin.exec" or
      call = API::builtin("eval").getACall() and funcName = "builtin.eval" or
      call = API::builtin("compile").getACall() and funcName = "builtin.compile"
    ) and
    sink = call.asExpr()
  )
  or
  // ==========================================
  // 2. 纯 AST 匹配兜底 (防止 API Graph 解析失败)
  // ==========================================
  exists(Call call, Expr func |
    call.getFunc() = func and
    (
      func.(Name).getId() = funcName or
      func.(Attribute).getName() = funcName
    ) and
    funcName in ["Popen", "system", "run", "call", "exec", "eval", "compile"] and
    sink = call
  )
  or
  // ==========================================
  // 3. 致命盲区修复：Python 2 遗留语法的 exec 语句
  // 如果 CodeQL 提取器将其识别为 statement 而非 function call，这里能精准捕获
  // ==========================================
  exists(Exec execStmt |
    sink = execStmt and
    funcName = "exec (statement)"
  )
select sink,
  "Potential RCE sink (" + funcName + ") found at " + 
  sink.getLocation().getFile().getRelativePath() + ":" + 
  sink.getLocation().getStartLine().toString()
