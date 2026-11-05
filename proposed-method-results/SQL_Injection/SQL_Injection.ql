/**
 * @name Universal SQL Injection Sink Finder (Max Recall)
 * @description Broadly locates potential SQL injection sinks using pure AST matching. Designed for maximum recall across all Python projects.
 * @id python/universal-sqli-sinks
 * @kind problem
 * @problem.severity warning
 */

import python

// 定义所有可能执行 SQL 语句的函数/方法名集合
predicate is_sqli_func_name(string name) {
  name in [
    // 1. Python DB-API 2.0 标准 (sqlite3, pymysql, psycopg2, pyodbc 等)
    "execute", "executemany", "executescript",
    
    // 2. 常见 ORM 框架 (Django, SQLAlchemy, Peewee 等)
    "raw",          // Django: User.objects.raw() / Peewee: Model.raw()
    "extra",        // Django: User.objects.extra(where=[...]) (老代码中极易产生SQLi)
    "text",         // SQLAlchemy: session.execute(text(sql))
    "execute_sql",  // Peewee: database.execute_sql()
    
    // 3. 异步数据库驱动 (asyncpg, databases, aiomysql 等)
    "fetch", "fetchrow", "fetchval", "iterate",
    
    // 4. 数据分析库 (Pandas)
    "read_sql", "read_sql_query", "read_sql_table",
    
    // 5. 其他常见直接查询方法 (部分老旧框架或自定义封装类)
    "query"
  ]
}

from AstNode sink, string funcName
where
  // 捕获所有函数/方法调用
  exists(Call call, Expr func |
    call.getFunc() = func and
    (
      func.(Name).getId() = funcName or
      func.(Attribute).getName() = funcName
    ) and
    is_sqli_func_name(funcName) and
    sink = call
  )
select sink,
  "Potential SQLi sink (" + funcName + ") found at " + 
  sink.getLocation().getFile().getRelativePath() + ":" + 
  sink.getLocation().getStartLine().toString()
