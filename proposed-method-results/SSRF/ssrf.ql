/**
 * @name Universal SSRF Sink Finder (Max Recall)
 * @description Broadly locates potential Server-Side Request Forgery (SSRF) sinks using pure AST matching. Designed for maximum recall across all Python projects.
 * @id python/universal-ssrf-sinks
 * @kind problem
 * @problem.severity warning
 */

import python

// 定义所有可能发起网络请求的函数/方法/类名集合
predicate is_ssrf_func_name(string name) {
  name in [
    // 1. urllib / urllib2 (Python 标准库)
    "urlopen", "urlretrieve", 
    
    // 2. http.client / httplib (Python 标准库)
    "HTTPConnection", "HTTPSConnection",
    
    // 3. requests / httpx / aiohttp / urllib3 (主流 HTTP 客户端)
    "request", "get", "post", "put", "delete", "patch", "head", "options",
    
    // 4. tornado.httpclient / JS渲染引擎 (如 pyppeteer, playwright)
    "fetch", "goto",
    
    // 5. socket / websockets (底层网络连接)
    "connect", "connect_ex",
    
    // 6. xmlrpc (RPC 调用)
    "ServerProxy"
  ]
}

from AstNode sink, string funcName
where
  // 捕获所有函数/方法/类实例化调用
  exists(Call call, Expr func |
    call.getFunc() = func and
    (
      func.(Name).getId() = funcName or
      func.(Attribute).getName() = funcName
    ) and
    is_ssrf_func_name(funcName) and
    sink = call
  )
select sink,
  "Potential SSRF sink (" + funcName + ") found at " + 
  sink.getLocation().getFile().getRelativePath() + ":" + 
  sink.getLocation().getStartLine().toString()
