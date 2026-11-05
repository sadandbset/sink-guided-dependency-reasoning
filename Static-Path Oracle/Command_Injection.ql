/**
 * @name Wide Command Injection (SEVDF Phase 1 - Balanced High Recall, Fixed)
 * @description 高召回平衡版命令注入查询：宽 Source/Sink，最小附加污点步，Barrier 剪枝，缓解路径爆炸。
 * @kind path-problem
 * @problem.severity warning
 * @id py/wide-command-injection-balanced
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.ApiGraphs

module WideCommandInjectionConfig implements DataFlow::ConfigSig {

  // ============ Source：宽覆盖 ============
  predicate isSource(DataFlow::Node source) {
    // 1) 官方远程流源
    source instanceof RemoteFlowSource
    or
    // 2) 所有函数参数：宽召回
    source instanceof DataFlow::ParameterNode
    or
    // 3) sys.argv
    exists(Attribute attr |
      attr = source.asExpr() and
      attr.getName() = "argv" and
      attr.getObject().(Name).getId() = "sys"
    )
    or
    // 4) os.environ
    exists(Attribute attr |
      attr = source.asExpr() and
      attr.getName() = "environ" and
      attr.getObject().(Name).getId() = "os"
    )
    or
    // 5) input() / raw_input() / getpass() / os.getenv()
    exists(Call call |
      source.asExpr() = call and
      (
        call.getFunc().(Name).getId() in ["input", "raw_input", "getpass"]
        or
        call.getFunc().(Attribute).getName() in ["getenv", "getpassword"]
      )
    )
    or
    // 6) 外部容器下标
    exists(Subscript sub |
      sub = source.asExpr() and
      (
        sub.getObject().(Name).getId().regexpMatch(
          "(?i)^(request|req|payload|body|query|params|headers|form|files|json|kwargs|args|data|info|env|config|options|opts|conf)$"
        )
        or
        exists(Attribute a |
          a = sub.getObject() and
          a.getName() in [
            "args", "form", "files", "json", "data",
            "GET", "POST", "body", "query", "params", "headers",
            "environ", "environb", "cookies"
          ]
        )
      )
    )
    or
    // 7) 文件读取
    exists(API::CallNode readCall |
      readCall = API::builtin("open").getACall()
      or
      readCall = API::moduleImport("pathlib")
        .getMember("Path").getReturn()
        .getMember(["read_text", "read_bytes"]).getACall()
      or
      readCall = API::moduleImport("os").getMember("read").getACall()
    |
      source = readCall
    )
    or
    // 8) 反序列化
    exists(API::CallNode parseCall |
      parseCall = API::moduleImport("json").getMember("loads").getACall()
      or
      parseCall = API::moduleImport("pickle").getMember(["loads", "load"]).getACall()
      or
      parseCall = API::moduleImport("yaml").getMember(["load", "safe_load"]).getACall()
    |
      source = parseCall
    )
  }

  // ============ Sink：宽覆盖 ============
  predicate isSink(DataFlow::Node sink) {
    // 1) 官方概念
    sink instanceof SystemCommandExecution
    or
    // 2) os.system / os.popen
    exists(API::CallNode call |
      call = API::moduleImport("os").getMember(["system", "popen"]).getACall() and
      sink = call.getArg(0)
    )
    or
    // 3) os.exec*
    exists(API::CallNode call |
      call = API::moduleImport("os")
        .getMember(["execv", "execve", "execvp", "execvpe",
                    "execl", "execle", "execlp", "execlpe"])
        .getACall() and
      (
        sink = call.getArg(0)
        or
        sink = call.getArg(1)
      )
    )
    or
    // 4) subprocess.*
    exists(API::CallNode call |
      call = API::moduleImport("subprocess")
        .getMember(["Popen", "run", "call", "check_call", "check_output",
                    "getoutput", "getstatusoutput"])
        .getACall() and
      (
        sink = call.getArg(0)
        or
        sink = call.getKeywordParameter("args").getAValueReachingSink()
        or
        sink = call.getKeywordParameter("cmd").getAValueReachingSink()
      )
    )
    or
    // 5) commands / commands2
    exists(API::CallNode call |
      call = API::moduleImport(["commands", "commands2"])
        .getMember(["getoutput", "getstatusoutput", "getstatus"])
        .getACall() and
      sink = call.getArg(0)
    )
    or
    // 6) 常见自定义包装函数
    exists(DataFlow::CallCfgNode callNode, string funcName |
      (
        callNode.getFunction().asExpr().(Name).getId() = funcName
        or
        callNode.getFunction().asExpr().(Attribute).getName() = funcName
      ) and
      funcName.regexpMatch(
        "(?i).*(run_cmd|exec_cmd|exec_command|run_command|do_command|shell_exec|system_call|run_shell|call_command|popen|os_popen|run_process|spawn_process|execute_command|exec_shell|run_script).*"
      )
    |
      sink = callNode.getArg(0)
      or
      sink = callNode.getArgByName("cmd")
      or
      sink = callNode.getArgByName("command")
    )
  }

  // ============ Barrier：剪枝，砍掉无效路径 ============
  predicate isBarrier(DataFlow::Node node) {
    // 1) 命令参数净化
    exists(DataFlow::CallCfgNode call |
      (
        call.getFunction().asExpr().(Attribute).getName() = "quote" and
        call.getFunction().asExpr().(Attribute).getObject().(Name).getId() in ["shlex", "pipes", "shell"]
      )
      or
      call.getFunction().asExpr().(Attribute).getName() in [
        "escape_shell_arg", "escape", "sanitize", "sanitize_cmd"
      ]
    |
      node = call
    )
    or
    // 2) 数字/布尔转换
    exists(DataFlow::CallCfgNode call |
      call.getFunction().asExpr().(Name).getId() in ["int", "float", "bool", "len", "range"]
    |
      node = call
    )
    or
    // 3) 显式白名单函数
    exists(DataFlow::CallCfgNode call |
      call.getFunction().asExpr().(Attribute).getName() in [
        "basename", "normpath", "realpath", "abspath", "expanduser"
      ]
    |
      node = call
    )
    // 注意：删除了原来的 `node.asExpr() instanceof Literal`
    // 因为 Python CodeQL 中没有 `Literal` 类，且字面量本来就不是污点节点
  }

  // ============ 附加污点步：只补默认未覆盖的，避免路径爆炸 ============
  additional predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // 1) str.join
    exists(DataFlow::CallCfgNode call |
      call.getFunction().asExpr().(Attribute).getName() = "join" and
      node1 = call.getArg(0) and
      node2 = call
    )
    or
    // 2) list/tuple/sorted/map 构造
    exists(DataFlow::CallCfgNode call |
      call.getFunction().asExpr().(Name).getId() in ["list", "tuple", "sorted", "map"] and
      (
        node1 = call.getArg(0)
        or
        node1 = call.getArg(1)
      ) and
      node2 = call
    )
    or
    // 3) dict.get：用 DataFlow::exprNode 包装 Expr，修复类型不兼容
    exists(DataFlow::CallCfgNode call |
      call.getFunction().asExpr().(Attribute).getName() = "get" and
      node1 = DataFlow::exprNode(call.getFunction().asExpr().(Attribute).getObject()) and
      node2 = call
    )
    or
    // 4) os.path.join / pathlib.Path
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("os").getMember("path").getMember("join").getACall()
      or
      call = API::moduleImport("pathlib").getMember("Path").getACall()
    |
      exists(int i | node1 = call.getArg(i)) and
      node2 = call
    )
  }
}

module WideCommandInjectionFlow = TaintTracking::Global<WideCommandInjectionConfig>;
import WideCommandInjectionFlow::PathGraph

from WideCommandInjectionFlow::PathNode source, WideCommandInjectionFlow::PathNode sink
where
  WideCommandInjectionFlow::flowPath(source, sink)
  // 如果仍然路径爆炸，先打开同文件限制，快速定位高价值告警：
  // and source.getNode().getLocation().getFile() = sink.getNode().getLocation().getFile()
select sink.getNode(), source, sink,
       "Potential command injection: data reaches command execution.",
       source.getNode(), "potential input"