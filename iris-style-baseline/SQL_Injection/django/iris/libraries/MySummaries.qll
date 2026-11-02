/**
 * Augur Phase 2 - Pass 5 (CWE-89 SQL Injection) additional taint-step library.
 *
 * Project : django (CodeQL DB snapshot django-db, Django 4.2.0-alpha0, sha eb3699ea -
 *           file/line references below use snapshot numbering, NOT the 2.2.4 working tree)
 * Labels  : iris/labels/labels.json, pass 5 (approved; see iris/labels/phase1_review.md)
 *
 * Modeled edge (label p5-sum-018, RawQuery._execute_query):
 *   RawQuery.__init__(self, sql, using, params) stores the raw SQL text into
 *   `self.sql` (django/db/models/sql/query.py:87); other RawQuery methods read
 *   it back, in particular `self.cursor.execute(self.sql, params)` at
 *   sql/query.py:152. Cross-method attribute flow is not connected by default
 *   in the Python dataflow library, so one field-flow edge is added:
 *   from the `sql` parameter of RawQuery.__init__ to the `self.sql` attribute
 *   reads in the same file.
 *   Scope justification (verified in the snapshot): every `self.sql`
 *   occurrence in django/db/models/sql/query.py belongs to class RawQuery
 *   (lines 87, 101, 132, 133, 152), and the only `__init__` in that file with
 *   a parameter named `sql` is RawQuery.__init__ at line 85.
 *
 * Summary labels that intentionally get NO extra edge (adding one would create
 * unconditional propagation that the source code does not warrant; standard
 * interprocedural data flow already connects them, and the definition-side
 * sinks in MySinks fire first):
 *   p5-sum-005  CursorWrapper._execute/_executemany: (sql, params) reach the
 *               driver cursor through ordinary argument flow
 *               (django/db/backends/utils.py:82-94).
 *   p5-sum-012  SQLCompiler.execute_sql / SQLInsertCompiler.execute_sql: the
 *               compiled (sql, params) pair reaches cursor.execute through
 *               ordinary argument flow (compiler.py:1382-1395, 1656-1657).
 *   p5-sum-020/021/022/023/024 schema editor, introspection, test-db creation,
 *               backend operations and connection-state wrappers: parameters
 *               reach the inner execute-family calls through ordinary
 *               argument flow (e.g. base/schema.py:170-199;
 *               sqlite3/introspection.py:94; base/creation.py:186).
 *   p5-sum-029  call_command / execute_from_command_line / run_from_argv:
 *               not modeled - the CLI options family is not a source in this
 *               query (operator-level trust, labels p5-src-048/p5-src-050 are
 *               'candidate'), so no propagation is needed; enabling it would
 *               fabricate a source-to-SQL path.
 *   p5-sum-032  DatabaseCache wrappers: keys and values are make_and_validate_key'd
 *               and passed as bound parameters (cache/backends/db.py:143-196),
 *               i.e. they terminate at the MySanitizers barrier.
 *   p5-sum-033/034 management SQL commands and migration operations: reached
 *               from CLI/migration state, not from the audited HTTP sources;
 *               their execute calls are covered by the call-site sink.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /** Holds if taint may step from node `nodeFrom` to node `nodeTo` for `passKey`. */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "sql_injection" and rawQuerySqlFieldFlow(nodeFrom, nodeTo)
  }

  /**
   * Field flow for RawQuery.sql: the raw SQL text accepted by
   * RawQuery.__init__ is stored into `self.sql` and read (and executed) in the
   * other RawQuery methods of the same file. This is the only audited
   * construction where SQL text crosses a method boundary through a field, so
   * it is the only additional edge.
   */
  private predicate rawQuerySqlFieldFlow(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Parameter p, Attribute a |
      // store side: __init__(self, sql, using, params) at sql/query.py:85
      p.getName() = "sql" and
      exists(Function f |
        f.getAnArg() = p and
        f.getName() = "__init__" and
        fileIs(f, "django/db/models/sql/query.py")
      ) and
      nodeFrom = DataFlow::parameterNode(p) and
      // load side: `self.sql` attribute reads in class RawQuery (same file)
      a.getName() = "sql" and
      a.getObject().toString() = "self" and
      fileIs(a, "django/db/models/sql/query.py") and
      nodeTo.asExpr() = a
    )
  }

bindingset[relPath]
  private predicate fileIs(AstNode n, string relPath) {
    n.getLocation().getFile().getAbsolutePath().matches("%/" + relPath)
  }
}
