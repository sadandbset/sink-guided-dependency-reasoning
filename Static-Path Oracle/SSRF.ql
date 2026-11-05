/**
 * @name Extreme Relaxed SSRF (SEVDF Phase 1 - Academic Paper Edition)
 * @description 论文最终版：结合了极限词汇放宽、修复了底层语法匹配，并增加了面向对象与 URL 解析的污点穿透，在防爆前提下实现理论最高召回率。
 * @kind path-problem
 * @problem.severity warning
 * @id py/extreme-relaxed-ssrf-academic
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.ApiGraphs

module RelaxedSSRFConfig implements DataFlow::ConfigSig {
  
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    or
    // 扩充 1：覆盖绝大多数 SSRF 场景的参数名
    exists(DataFlow::ParameterNode param |
      source = param and
      param.getParameter().getName().regexpMatch("(?i).*(url|uri|host|domain|target|path|file|ip|address|link|endpoint|dest|server|site|webhook|callback|proxy|redirect|next|command|addon|slug|config|options).*")
    )
    or
    exists(Attribute attr | attr = source.asExpr() and attr.getName() = ["argv", "environ"])
    or
    exists(Call call | call.getFunc().(Name).getId() = ["input", "raw_input", "getenv"] and source.asExpr() = call)
    or
    // 扩充 2：覆盖绝大多数外部输入字典
    exists(Subscript sub, Name objName |
      sub = source.asExpr() and
      sub.getObject() = objName and
      objName.getId().regexpMatch("(?i).*(request|req|data|kwargs|payload|body|query|params|headers|form|get|post|json|args|val|info).*")
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Http::Client::Request req |
      sink = req.getAUrlPart()
    )
    or
    // 扩充 3：覆盖现代异步与第三方网络库
    exists(API::CallNode call |
      call = API::moduleImport("requests").getMember(["get", "post", "request", "put", "delete"]).getACall() or
      call = API::moduleImport("urllib").getMember("request").getMember("urlopen").getACall() or
      call = API::moduleImport("urllib3").getMember("PoolManager").getReturn().getMember("request").getACall() or
      call = API::moduleImport("urllib3").getMember("request").getACall() or
      call = API::moduleImport("httpx").getMember(["get", "post", "request"]).getACall() or
      call = API::moduleImport("aiohttp").getMember("ClientSession").getReturn().getMember(["get", "post", "request"]).getACall() or
      call = API::moduleImport("tornado").getMember("httpclient").getMember(["HTTPClient", "AsyncHTTPClient"]).getReturn().getMember("fetch").getACall()
    |
      // 修复：使用 exists 显式声明 int 变量，完美匹配任意位置参数
      exists(int i | sink = call.getArg(i)) or 
      sink = call.getKeywordParameter("url").getAValueReachingSink()
    )
    or
    // 扩充 4：模糊匹配自定义网络请求包装函数
    exists(DataFlow::CallCfgNode callNode, string funcName |
      (
        callNode.getFunction().asExpr().(Name).getId() = funcName or
        callNode.getFunction().asExpr().(Attribute).getName() = funcName
      ) and
      funcName.regexpMatch("(?i).*(request|urlopen|fetch|http_get|http_post|download|send|webhook|proxy|redirect).*")
    |
      // 修复：使用 exists 显式声明变量，完美匹配任意位置参数和关键字参数
      exists(int i | sink = callNode.getArg(i)) or
      exists(string s | sink = callNode.getArgByName(s))
    )
  }

  predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(BinaryExpr binop |
      (binop.getOp() instanceof Add or binop.getOp() instanceof Mod) and
      (node1.asExpr() = binop.getLeft() or node1.asExpr() = binop.getRight()) |
      node2.asExpr() = binop
    )
    or
    exists(Fstring fstring |
      node1.asExpr() = fstring.getAValue() |
      node2.asExpr() = fstring
    )
    or
    // 扩充 5：穿透常见的字符串操作与 URL 解析函数
    exists(DataFlow::CallCfgNode callNode, string funcName |
      callNode.getFunction().asExpr().(Attribute).getName() = funcName and
      funcName = ["format", "urljoin", "split", "join", "urlparse", "urlunparse", "netloc", "replace"] and
      (
        exists(int i | node1 = callNode.getArg(i)) or 
        exists(string s | node1 = callNode.getArgByName(s))
      ) |
      node2 = callNode
    )
    or
    // 扩充 6：对象属性污点传递 (解决面向对象封装导致的污点断裂)
    exists(Attribute attr |
      attr.getObject() = node1.asExpr() |
      node2.asExpr() = attr
    )
  }
}

module RelaxedSSRFFlow = TaintTracking::Global<RelaxedSSRFConfig>;
import RelaxedSSRFFlow::PathGraph

from RelaxedSSRFFlow::PathNode source, RelaxedSSRFFlow::PathNode sink
where RelaxedSSRFFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
       "Extreme relaxed SSRF path: data reaches HTTP request.",
       source.getNode(), "potential input"
