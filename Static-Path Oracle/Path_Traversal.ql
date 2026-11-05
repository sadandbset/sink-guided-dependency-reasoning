/**
 * @name Extreme Relaxed Path Injection (SEVDF Phase 1 - Ultimate Balance)
 * @description 极限放宽的路径穿越查询（终极平衡版）：通过高危词汇字典和 ApiGraphs 解决路径爆炸，同时增加 os.path.join 等专用污点穿透，确保极高召回率。
 * @kind path-problem
 * @problem.severity warning
 * @id py/extreme-relaxed-path-injection-ultimate
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.ApiGraphs // 引入 ApiGraphs 用于精准捕获标准库

module RelaxedPathInjectionConfig implements DataFlow::ConfigSig {
  
  // 【维度 1：扩充 Source (防爆版)】
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    or
    // 扩充 1：使用庞大的字典覆盖绝大多数与文件/路径相关的参数名，拒绝无差别捕获
    exists(DataFlow::ParameterNode param |
      source = param and
      param.getParameter().getName().regexpMatch("(?i).*(path|file|dir|folder|name|doc|img|image|upload|download|template|asset|resource|key|id|slug).*")
    )
    or
    exists(Attribute attr | attr = source.asExpr() and attr.getName() = ["argv", "environ"])
    or
    exists(Call call | call.getFunc().(Name).getId() = ["input", "raw_input", "getenv"] and source.asExpr() = call)
    or
    // 扩充 2：覆盖绝大多数外部输入字典 (如 request.FILES, data['path'])
    exists(Subscript sub, Name objName |
      sub = source.asExpr() and
      sub.getObject() = objName and
      objName.getId().regexpMatch("(?i).*(request|req|data|kwargs|payload|body|query|params|headers|form|files|json|args|val|info).*")
    )
  }

  // 【维度 2：放宽并模糊匹配 Sink (防爆版)】
  predicate isSink(DataFlow::Node sink) {
    // 1. 官方概念中的文件系统访问
    sink instanceof FileSystemAccess
    or
    // 2. 扩充 3：使用 ApiGraphs 精准捕获 os, shutil, pathlib 等高危文件操作，无视 AST 混淆
    exists(API::CallNode call |
      call = API::builtin("open").getACall() or
      call = API::moduleImport("os").getMember(["remove", "unlink", "mkdir", "rmdir", "rename", "replace"]).getACall() or
      call = API::moduleImport("shutil").getMember(["rmtree", "copy", "copy2", "copyfile", "move"]).getACall() or
      call = API::moduleImport("pathlib").getMember("Path").getReturn().getMember(["open", "read_bytes", "read_text", "write_bytes", "write_text", "unlink", "rmdir", "rename", "replace"]).getACall()
    |
      // 修复语法错误：使用 exists 显式声明 int 变量
      exists(int i | sink = call.getArg(i)) or 
      sink = call.getKeywordParameter(["file", "path", "src", "dst"]).getAValueReachingSink()
    )
    or
    // 3. 扩充 4：模糊匹配自定义文件操作包装函数
    // 注意：移除了极易爆炸的 read, write, join，改为更明确的文件操作词汇
    exists(DataFlow::CallCfgNode callNode, string funcName |
      (
        callNode.getFunction().asExpr().(Name).getId() = funcName or
        callNode.getFunction().asExpr().(Attribute).getName() = funcName
      ) and
      funcName.regexpMatch("(?i).*(open_file|read_file|write_file|send_file|download_file|upload_file|safe_join|resolve_path|delete_file).*")
    |
      // 修复语法错误
      exists(int i | sink = callNode.getArg(i)) or
      exists(string s | sink = callNode.getArgByName(s))
    )
  }

  // 【维度 3：强制污点穿透】
  predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // 1. 穿透加法和取模 (限制 BinaryExpr，防止纯数学运算爆炸)
    exists(BinaryExpr binop |
      (binop.getOp() instanceof Add or binop.getOp() instanceof Mod) and
      (node1.asExpr() = binop.getLeft() or node1.asExpr() = binop.getRight()) |
      node2.asExpr() = binop
    )
    or
    // 2. 穿透 f-string
    exists(Fstring fstring |
      node1.asExpr() = fstring.getAValue() |
      node2.asExpr() = fstring
    )
    or
    // 3. 扩充 5：穿透常见的字符串操作
    exists(DataFlow::CallCfgNode callNode, string funcName |
      callNode.getFunction().asExpr().(Attribute).getName() = funcName and
      funcName = ["format", "replace", "split", "join", "strip", "lstrip", "rstrip"] and
      (
        exists(int i | node1 = callNode.getArg(i)) or 
        exists(string s | node1 = callNode.getArgByName(s))
      ) |
      node2 = callNode
    )
    or
    // 4. 扩充 6：【极其重要】穿透 os.path.join 和 pathlib.Path
    // 很多路径穿越漏洞中，污点在 os.path.join(base, user_input) 处就断裂了
    exists(DataFlow::CallCfgNode callNode |
      callNode = API::moduleImport("os").getMember("path").getMember("join").getACall() or
      callNode = API::moduleImport("pathlib").getMember("Path").getACall()
    |
      exists(int i | node1 = callNode.getArg(i)) and
      node2 = callNode
    )
    or
    // 5. 对象属性污点传递 (如 req.filename)
    exists(Attribute attr |
      attr.getObject() = node1.asExpr() |
      node2.asExpr() = attr
    )
  }
}

module RelaxedPathInjectionFlow = TaintTracking::Global<RelaxedPathInjectionConfig>;
import RelaxedPathInjectionFlow::PathGraph

from RelaxedPathInjectionFlow::PathNode source, RelaxedPathInjectionFlow::PathNode sink
where RelaxedPathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
       "Extreme relaxed path injection: data reaches file/path operation.",
       source.getNode(), "potential input"
