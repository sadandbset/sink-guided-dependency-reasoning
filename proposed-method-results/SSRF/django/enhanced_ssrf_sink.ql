/**
 * @name Universal SSRF Sink and Validator Finder (Max Recall)
 * @description Broadly locates potential Server-Side Request Forgery (SSRF) sinks and IP/URL validation bypass points using pure AST matching.
 * @id python/universal-ssrf-sinks-and-validators
 * @kind problem
 * @problem.severity warning
 */

import python

// 1. 定义发起网络请求的函数/方法/类名集合 (触发层)
predicate is_request_sink_name(string name) {
  name in [
    // urllib / urllib2
    "urlopen", "urlretrieve", 
    // http.client / httplib
    "HTTPConnection", "HTTPSConnection",
    // requests / httpx / aiohttp / urllib3
    "request", "get", "post", "put", "delete", "patch", "head", "options",
    // requests.Session 底层发送 / aiohttp stream / 其他执行方法 (新增)
    "send", "stream", "execute", "perform", "call",
    // tornado.httpclient / JS渲染引擎
    "fetch", "goto",
    // socket / websockets
    "connect", "connect_ex",
    // xmlrpc
    "ServerProxy"
  ]
}

// 2. 定义 IP/URL 验证与解析的函数/类名集合 (防护层/解析层)
predicate is_validator_sink_name(string name) {
  name in [
    // Django 及常见 Web 框架的验证器
    "validate_ipv4_address", "validate_ipv6_address", "validate_ipv46_address", "URLValidator",
    // Python ipaddress 模块 (CVE-2021-33571 核心解析点)
    "IPv4Address", "IPv6Address", "IPv4Network", "IPv6Network", "IPv4Interface", "IPv6Interface", 
    "ip_address", "ip_network", "ip_interface",
    // URL 解析函数 (常用于 SSRF 绕过与解析歧义)
    "urlparse", "urlsplit"
  ]
}

// 3. 排除常见的字典操作误报 (纯 AST 启发式过滤)
predicate is_dict_get_false_positive(Expr func, string funcName) {
  funcName = "get" and
  exists(Attribute attr |
    attr = func and
    // 如果调用对象是常见的字典变量名，则判定为误报
    attr.getObject().(Name).getId() in [
      "headers", "environ", "cookies", "data", "form", "args", "kwargs", "meta", "config"
    ]
  )
}

from AstNode sink, string funcName, string sinkCategory
where
  // 捕获所有函数/方法/类实例化调用
  exists(Call call, Expr func |
    call.getFunc() = func and
    (
      func.(Name).getId() = funcName or
      func.(Attribute).getName() = funcName
    ) and
    (
      (is_request_sink_name(funcName) and sinkCategory = "HTTP Request Sink") or
      (is_validator_sink_name(funcName) and sinkCategory = "Validation/Parsing Sink")
    ) and
    // 过滤掉明显的字典 .get() 误报
    not is_dict_get_false_positive(func, funcName) and
    sink = call
  )
select sink,
  "Potential SSRF related point [" + sinkCategory + "] (" + funcName + ") found."
