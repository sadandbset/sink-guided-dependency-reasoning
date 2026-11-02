/**
 * Augur Phase 2 - Pass 5 (CWE-89 SQL Injection) sink library.
 *
 * Project : django (CodeQL DB snapshot django-db, Django 4.2.0-alpha0, sha eb3699ea -
 *           file/line references below use snapshot numbering, NOT the 2.2.4 working tree)
 * Labels  : iris/labels/labels.json, pass 5 (approved; see iris/labels/phase1_review.md)
 *
 * Label id -> modeling:
 *
 *   Call-site SQL text (argument 0 of an execute-family call):
 *     p5-sink-001  <obj>.execute(sql, ...) / .executemany(sql, ...) / .callproc(proc, ...)
 *                 -> ExecuteSqlTextArgument (only inside the SQL execution layer)
 *
 *   Definition-side SQL-text parameters (execute-family wrappers and raw-SQL APIs):
 *     p5-sink-002  CursorWrapper.execute(sql, ...)          django/db/backends/utils.py:66
 *     p5-sink-003  CursorWrapper.executemany(sql, ...)      django/db/backends/utils.py:71
 *                  (CursorDebugWrapper.execute/executemany, utils.py:101/:105, share the
 *                  same signature - deduplicated per labels)
 *     p5-sink-004  CursorWrapper.callproc(procname, ...)    django/db/backends/utils.py:48
 *     p5-sink-006  SQLiteCursorWrapper.execute(query)       django/db/backends/sqlite3/base.py:353
 *     p5-sink-007  SQLiteCursorWrapper.executemany(query)   django/db/backends/sqlite3/base.py:359
 *     p5-sink-008  mysql CursorWrapper.execute(query)       django/db/backends/mysql/base.py:72
 *     p5-sink-009  mysql CursorWrapper.executemany(query)   django/db/backends/mysql/base.py:83
 *     p5-sink-010  oracle FormatStylePlaceholderCursor.execute(query)     oracle/base.py:552
 *     p5-sink-011  oracle FormatStylePlaceholderCursor.executemany(query) oracle/base.py:558
 *     p5-sink-019  BaseDatabaseSchemaEditor.execute(sql, params)  base/schema.py:170
 *                  -> SqlTextDefinitionParameter (functions named execute/executemany/
 *                     callproc with a parameter named sql/query/procname in the SQL layer)
 *
 *   ORM raw-SQL API definition parameters:
 *     p5-sink-013  QuerySet.raw(raw_query, ...)            django/db/models/query.py:1284
 *     p5-sink-014  QuerySet.extra(select, where, tables, order_by)  query.py:1670
 *     p5-sink-015  RawSQL.__init__(sql, ...)               django/db/models/expressions.py:1049
 *     p5-sink-016  RawQuery.__init__(sql, ...)             django/db/models/sql/query.py:85
 *     p5-sink-017  RawQuerySet.__init__(raw_query, ...)    django/db/models/query.py:1995
 *                  -> RawSqlApiParameter
 *
 *   Bound-parameter channels are NOT sinks (labels p5-san-035 treats them as the
 *   sanitizer); extra()'s params/select_params and raw()'s params are excluded for
 *   the same reason.
 *
 *   Name-collision false positives (labeled none/fp) are excluded by the positive
 *   path scoping: CLI command dispatch `.execute()` (django/core/management/**),
 *   Redis `pipeline.execute()` (django/core/cache/backends/redis.py) and
 *   django/test/** all fall outside the SQL execution layer defined below.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /** Holds if `n` is a sink for the pass identified by `passKey`. */
  predicate isSink(DataFlow::Node n, string passKey) {
    passKey = "sql_injection" and
    (
      n instanceof ExecuteSqlTextArgument
      or n instanceof SqlTextDefinitionParameter
      or n instanceof RawSqlApiParameter
    )
  }

  /**
   * The audited SQL execution layer: the module families that carry the 220
   * approved execute-call-site rows (django/db/** incl. backends, ORM compiler,
   * migrations and schema editors; django/contrib/gis/db/backends;
   * django/contrib/postgres; the SQL database cache backend). File paths inside
   * this CodeQL database use forward slashes (verified against extraction CSVs).
   */
  private predicate sqlExecutionLayer(AstNode n) {
    inScope(n) and
    exists(string p | p = n.getLocation().getFile().getAbsolutePath() |
      p.matches("%/django/db/%")
      or p.matches("%/django/contrib/gis/db/%")
      or p.matches("%/django/contrib/postgres/%")
      or p.matches("%/django/core/cache/backends/db.py")
    )
  }

  /** Phase 1 extraction scope filter (same as MySources). */
  private predicate inScope(AstNode n) {
    not excludedPath(n.getLocation().getFile().getAbsolutePath())
  }

bindingset[p]
  private predicate excludedPath(string p) {
    p.matches("%/tests/%")
    or p.matches("%/django-db/%")
    or p.matches("%/docs/%")
    or p.matches("%/js_tests/%")
    or p.matches("%/node_modules/%")
    or p.matches("%/fixtures/%")
  }

  /**
   * `.execute` / `.executemany` / `.callproc` calls in the SQL execution layer.
   *
   * Excludes the explicit-unbound idiom `<Class>.execute(self, query, ...)`
   * (e.g. `Database.Cursor.execute(self, query)` at
   * django/db/backends/sqlite3/base.py:355/:357/:361 and oracle/base.py:556/:570):
   * there argument 0 is the `self` receiver, not SQL text. Those driver-level
   * calls are covered by the definition-side wrapper-parameter sinks instead
   * (SqlTextDefinitionParameter), which also keeps the bound-parameter barrier
   * of MySanitizers from mistakenly blocking argument 1 (the SQL text in the
   * unbound idiom).
   */
  private class SqlExecuteCall extends Call {
    SqlExecuteCall() {
      this.getFunc() instanceof Attribute and
      this.getFunc().(Attribute).getName() in ["execute", "executemany", "callproc"] and
      sqlExecutionLayer(this) and
      not explicitSelfArgument(this)
    }
  }

  /** Holds if `c`'s first positional argument is the literal name `self`. */
  private predicate explicitSelfArgument(Call c) {
    c.getPositionalArg(0) instanceof Name and
    c.getPositionalArg(0).(Name).getId() = "self"
  }

  /**
   * The SQL-text argument (positional index 0) of execute-family calls
   * (label p5-sink-001). For callproc, argument 0 is the procedure name, which
   * is SQL structure per label p5-sink-004.
   * Evidence: django/db/models/sql/compiler.py:1395/:1657
   * `cursor.execute(sql, params)`; django/db/backends/base/schema.py:199
   * `cursor.execute(sql, params)`; django/db/backends/base/base.py:370
   * `cursor.execute(self.ops.savepoint_create_sql(sid))`.
   */
  private class ExecuteSqlTextArgument extends DataFlow::Node {
    ExecuteSqlTextArgument() {
      exists(SqlExecuteCall c | this.asExpr() = c.getPositionalArg(0))
    }
  }

  /**
   * The SQL-text parameter of execute-family wrapper definitions in the SQL
   * layer (labels p5-sink-002/003/004, 006-011, 019). Parameter names are the
   * audited ones: `sql` (CursorWrapper/CursorDebugWrapper/SchemaEditor, and the
   * raw-SQL object constructors handled below), `query`
   * (SQLiteCursorWrapper/mysql/oracle), `procname` (callproc).
   */
  private class SqlTextDefinitionParameter extends DataFlow::Node {
    SqlTextDefinitionParameter() {
      exists(Parameter p, Function f |
        f.getAnArg() = p and
        f.getName() in ["execute", "executemany", "callproc"] and
        p.getName() in ["sql", "query", "procname"] and
        sqlExecutionLayer(f) and
        this = DataFlow::parameterNode(p)
      )
    }
  }

  /**
   * ORM raw-SQL API definition parameters (labels p5-sink-013..017):
   *   QuerySet.raw(raw_query)                    django/db/models/query.py:1284
   *   QuerySet.extra(select/where/tables/order_by)  django/db/models/query.py:1670
   *   RawQuerySet.__init__(raw_query)            django/db/models/query.py:1995
   *   RawSQL.__init__(sql)                       django/db/models/expressions.py:1049
   *   RawQuery.__init__(sql)                     django/db/models/sql/query.py:85
   * (function-name + parameter-name + file pairs were verified unique in the
   * snapshot; extra()'s `params`/`select_params` and raw()'s `params` are the
   * bound channel and are intentionally not matched).
   */
  private class RawSqlApiParameter extends DataFlow::Node {
    RawSqlApiParameter() {
      exists(Parameter p, Function f |
        f.getAnArg() = p and
        rawApiDefinition(f, p) and
        this = DataFlow::parameterNode(p)
      )
    }
  }

  private predicate rawApiDefinition(Function f, Parameter p) {
    (
      fileIs(f, "django/db/models/query.py") and
      (
        (f.getName() = "raw" and p.getName() = "raw_query")
        or (f.getName() = "extra" and p.getName() in ["select", "where", "tables", "order_by"])
        or (f.getName() = "__init__" and p.getName() = "raw_query")
      )
    )
    or
    (fileIs(f, "django/db/models/expressions.py") and f.getName() = "__init__" and p.getName() = "sql")
    or
    (fileIs(f, "django/db/models/sql/query.py") and f.getName() = "__init__" and p.getName() = "sql")
  }

bindingset[relPath]
  private predicate fileIs(AstNode n, string relPath) {
    n.getLocation().getFile().getAbsolutePath().matches("%/" + relPath)
  }
}
