/**
 * Augur Phase 2 - Pass 5 (CWE-89 SQL Injection) sanitizer (barrier) library.
 *
 * Project : django (CodeQL DB snapshot django-db, Django 4.2.0-alpha0, sha eb3699ea -
 *           file/line references below use snapshot numbering, NOT the 2.2.4 working tree)
 * Labels  : iris/labels/labels.json, pass 5 (approved; see iris/labels/phase1_review.md)
 *
 * Label id -> modeling:
 *
 *   p5-san-035 (tp, 0.85) - the bound-parameter channel of the execute family:
 *     (a) call-site argument 1 of `.execute(sql, params)` / `.executemany(sql,
 *         param_list)` / `.callproc(proc, params)`, and the keyword forms
 *         `params=` / `param_list=` / `args=` / `kparams=`;
 *     (b) the definition-side `params` / `param_list` / `args` / `kparams`
 *         parameters of those wrappers (parameter 2 after `self` per labels).
 *     -> BoundParameterArgument and BoundParameterDefinitionParameter.
 *     Values substituted by the DB driver cannot alter SQL text; this is the
 *     proven parameterization barrier for pass 5 and is modeled as isBarrier.
 *
 *   p5-san-036 (candidate, 0.4) - connection.ops.quote_name is NOT modeled as a
 *     barrier: the verified implementations wrap the identifier in quotes
 *     without escaping embedded quote characters
 *     (sqlite3/operations.py:189-192 `'"%s"' % name`;
 *      mysql/operations.py `` '`%s`' % name ``; postgresql/operations.py the
 *     same shape). Quoting is adequate only for framework-controlled identifier
 *     character sets, so per the Phase 1 review recommendation it is kept as
 *     documentation only - taint that reaches SQL structure (table/column
 *     names, ORDER BY fragments) through %-interpolation is NOT neutralized
 *     here and will still flow to the SQL-text sinks.
 *
 * The barrier deliberately applies only to the bound-value channel; it never
 * blocks the SQL-text argument itself.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /** Holds if `n` is a taint barrier for the pass identified by `passKey`. */
  predicate isBarrier(DataFlow::Node n, string passKey) {
    passKey = "sql_injection" and
    (
      n instanceof BoundParameterArgument
      or n instanceof BoundParameterDefinitionParameter
    )
  }

  /**
   * The audited SQL execution layer (same positive scoping as MySinks, which
   * excludes the CLI `.execute()` and Redis `pipeline.execute()` name
   * collisions). File paths inside this CodeQL database use forward slashes.
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

  /** Phase 1 extraction scope filter (same as MySources/MySinks). */
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
   * Execute-family calls in the SQL layer, excluding the explicit-unbound
   * idiom `<Class>.execute(self, query, ...)` where argument 1 is the SQL text
   * (see MySinks::SqlExecuteCall for the rationale).
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
   * Call-site bound-parameter nodes (label p5-san-035a):
   *   positional argument 1 - e.g. `cursor.execute(sql, params)` at
   *   django/db/models/sql/compiler.py:1395, `[key]` at
   *   django/core/cache/backends/db.py:151/:172/:185/:196;
   *   keyword form - e.g. `schema_editor.execute(sql, params=params)` at
   *   django/db/migrations/operations/special.py:129.
   */
  private class BoundParameterArgument extends DataFlow::Node {
    BoundParameterArgument() {
      exists(SqlExecuteCall c |
        this.asExpr() = c.getPositionalArg(1)
        or
        exists(Keyword kw | c.getAKeyword() = kw |
          kw.getArg() in ["params", "param_list", "args", "kparams"] and
          this.asExpr() = kw.getValue()
        )
      )
    }
  }

  /**
   * Definition-side bound-parameter nodes (label p5-san-035b): the
   * `params`/`param_list`/`args`/`kparams` parameters of execute-family
   * wrappers in the SQL layer (CursorWrapper.execute params, utils.py:66;
   * SchemaEditor.execute params, base/schema.py:170; mysql CursorWrapper args,
   * mysql/base.py:72; callproc params, utils.py:48).
   */
  private class BoundParameterDefinitionParameter extends DataFlow::Node {
    BoundParameterDefinitionParameter() {
      exists(Parameter p, Function f |
        f.getAnArg() = p and
        f.getName() in ["execute", "executemany", "callproc"] and
        p.getName() in ["params", "param_list", "args", "kparams"] and
        sqlExecutionLayer(f) and
        this = DataFlow::parameterNode(p)
      )
    }
  }
}
