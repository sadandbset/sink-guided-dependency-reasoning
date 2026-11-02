/**
 * Augur Phase 2 Step 4 - generated sink library.
 *
 * Pass 5 (CWE-89, SQL Injection) for the OpenAdapt project.
 *
 * Machine-generated from `iris/labels/labels.json` (pass_id 5, role=sink,
 * 3 reviewed entries: pass5-sink-005, pass5-sink-006, pass5-sink-010).
 * The remaining 6 reviewed sink-candidate rows are role `none` and are
 * intentionally NOT modeled as sinks:
 *   - crud.py:48 `db.execute(sa.insert(table), to_insert)` argument 0 is a
 *     Core insert statement object (compiled with bound parameters) - see
 *     MySanitizers for the argument-1 bound-values channel.
 *   - crud.py:48 `sa.insert(table)` statement construction: identifiers are
 *     static (openadapt/models.py), values bound separately.
 *   - crud.py:30 `_insert` wrapper: body executes only the parameterized
 *     Core insert.
 *   - crud.py:161/164/169 f-strings inside `create_db`: output database
 *     filename, env-file backup path and `DB_FNAME=` env line - never
 *     executed as SQL.
 *
 * The three modeled sinks form the single raw-SQL execution chain of the
 * project (all in openadapt/crud.py):
 *   crud.py:142  export_sql: f"INSERT INTO recording VALUES (...)"  (construction)
 *   crud.py:150  create_db(recording_id, sql) parameter 1            (wrapper param)
 *   crud.py:180  connection.execute(sql) argument 0                  (execution)
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {

  /** Restricts `n` to the openadapt source file with the given basename. */
  private predicate inPyFile(AstNode n, string basename) {
    n.getLocation().getFile().getShortName() = basename
  }

  /**
   * Label pass5-sink-010: `connection.execute(sql)` at openadapt/crud.py:180,
   * argument 0 - the raw SQL string execution sink.
   *
   * crud.py:179-180:
   *   with engine.begin() as connection:
   *       connection.execute(sql)
   *
   * SQLAlchemy `Connection.execute` with a plain string argument compiles it
   * as literal SQL text (text() semantics); the `sql` value is the f-string
   * built by `export_sql` (crud.py:142) and handed over via `create_db`'s
   * `sql` parameter (crud.py:209). Receiver `connection` comes from
   * `engine.begin()`; the receiver is matched by name because the sqlalchemy
   * library itself is not part of the CodeQL database.
   */
  private predicate rawSqlExecuteArgument0(DataFlow::Node sink) {
    exists(Call c |
      inPyFile(c, "crud.py") and
      c.getLocation().getStartLine() = 180 and
      c.getFunc().(Attribute).getName() = "execute" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "connection" and
      sink.asExpr() = c.getPositionalArg(0)
    )
  }

  /**
   * Label pass5-sink-005: the dynamic raw-SQL construction f-string in
   * `export_sql` at openadapt/crud.py:142 - the point where untrusted data
   * enters SQL statement text (argument positions are the 8 interpolated
   * `recording.<column>` expressions; the two string columns are wrapped
   * only in literal single quotes with no escaping).
   */
  private predicate exportSqlFstringConstruction(DataFlow::Node sink) {
    exists(Fstring f |
      inPyFile(f, "crud.py") and
      f.getLocation().getStartLine() = 142 and
      sink.asExpr() = f
    )
  }

  /**
   * Label pass5-sink-006: parameter 1 (`sql`) of the internal SQL wrapper
   * `create_db(recording_id, sql)` (openadapt/crud.py:150), whose body
   * executes it verbatim at crud.py:180 (`connection.execute(sql)` inside
   * `engine.begin()`).
   */
  private predicate createDbSqlParameter(DataFlow::Node sink) {
    exists(Parameter p |
      inPyFile(p, "crud.py") and
      p.getLocation().getStartLine() = 150 and
      p.getName() = "sql" and
      p.getPosition() = 1 and
      exists(Function f |
        f.getName() = "create_db" and
        f.getArg(1) = p
      ) and
      sink = DataFlow::parameterNode(p)
    )
  }

  /**
   * Holds if `sink` is a CWE-89 taint sink for the given pass key.
   * Only `passKey = "sql_injection"` (Pass 5) is defined in this round.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "sql_injection" and
    (
      rawSqlExecuteArgument0(sink)
      or
      exportSqlFstringConstruction(sink)
      or
      createDbSqlParameter(sink)
    )
  }
}
