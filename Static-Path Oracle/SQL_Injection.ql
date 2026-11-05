/**
 * @name Extreme Relaxed SQL Injection (SEVDF Phase 1)
 * @description 极限放宽的 SQL 注入查询：模糊匹配 SQL 执行函数，扩充 Source，强制污点穿透，无视参数化或 ORM 防御。
 * @kind path-problem
 * @problem.severity warning
 * @id py/extreme-relaxed-sql-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources

module RelaxedSqlInjectionConfig implements DataFlow::ConfigSig {
  
  // 【维度 1：扩充 Source】（保持全量外部输入捕获）
  predicate isSource(DataFlow::Node source) {
    // 1. 官方定义的远程输入源
    source instanceof RemoteFlowSource
    or
    // 2. 任何函数参数
    source instanceof DataFlow::ParameterNode
    or
    // 3. 命令行参数与环境变量
    exists(Attribute attr | attr = source.asExpr() and attr.getName() = ["argv", "environ"])
    or
    exists(Call call | call.getFunc().(Name).getId() = ["input", "raw_input", "getenv"] and source.asExpr() = call)
    or
    // 4. 任何字典/下标读取 (例如 request.POST['username'], data['id'])
    source.asExpr() instanceof Subscript
  }

  // 【维度 2：放宽并模糊匹配 Sink】
  predicate isSink(DataFlow::Node sink) {
    // 1. 官方概念中的 SQL 执行 (涵盖 PEP 249 DB-API, Django, SQLAlchemy 等)
    sink instanceof SqlExecution
    or
    // 2. 模糊匹配：只要函数名包含常见 SQL 操作关键字，其参数即视为 Sink
    // 涵盖 execute, query, raw, cursor, select, update, insert, delete, sql 等
    exists(DataFlow::CallCfgNode callNode, string funcName |
      (
        callNode.getFunction().asExpr().(Name).getId() = funcName or
        callNode.getFunction().asExpr().(Attribute).getName() = funcName
      ) and
      funcName.regexpMatch("(?i).*(execute|query|raw|cursor|select|update|insert|delete|sql).*")
    |
      sink = callNode.getArg(_) or
      sink = callNode.getArgByName(_)
    )
  }

  // 【维度 3：强制污点穿透】（针对 SQL 语句拼接极其重要）
  predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // 1. 穿透所有二元操作符（如 SQL 字符串拼接 "SELECT * FROM users WHERE id = " + id）
    exists(BinaryExpr binop |
      node1.asExpr() = binop.getLeft() or node1.asExpr() = binop.getRight() |
      node2.asExpr() = binop
    )
    or
    // 2. 穿透 f-string (如 f"SELECT * FROM users WHERE id = {id}")
    exists(Fstring fstring |
      node1.asExpr() = fstring.getAValue() |
      node2.asExpr() = fstring
    )
    or
    // 3. 穿透 .format() 调用 (如 "SELECT * FROM users WHERE id = {}".format(id))
    exists(DataFlow::CallCfgNode callNode |
      callNode.getFunction().asExpr().(Attribute).getName() = "format" and
      (node1 = callNode.getArg(_) or node1 = callNode.getArgByName(_)) |
      node2 = callNode
    )
  }
}

module RelaxedSqlInjectionFlow = TaintTracking::Global<RelaxedSqlInjectionConfig>;
import RelaxedSqlInjectionFlow::PathGraph

from RelaxedSqlInjectionFlow::PathNode source, RelaxedSqlInjectionFlow::PathNode sink
where RelaxedSqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
       "Extreme relaxed SQL injection: data reaches database execution.",
       source.getNode(), "potential input"
