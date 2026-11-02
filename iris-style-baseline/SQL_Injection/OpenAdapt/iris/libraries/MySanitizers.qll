/**
 * Augur Phase 2 Step 4 - generated sanitizer (barrier) library.
 *
 * Pass 5 (CWE-89, SQL Injection) for the OpenAdapt project.
 *
 * Machine-generated from `iris/labels/labels.json` (pass_id 5, role=sanitizer,
 * 1 reviewed entry: pass5-sink-003).
 *
 * The only proven CWE-89 sanitizer in the project is the SQLAlchemy Core
 * bound-parameters channel at openadapt/crud.py:48:
 *
 *   crud.py:48  result = db.execute(sa.insert(table), to_insert)
 *
 * inside `_insert` (crud.py:30-53): argument 0 is a Core `sa.insert(table)`
 * statement whose table/column identifiers come from the statically defined
 * models (openadapt/models.py), and argument 1 (`to_insert`, the row-value
 * list built from `event_data`) is supplied as bound parameter values -
 * values are never concatenated into SQL statement text. All recorded GUI
 * event data flows through this channel (insert_action_event /
 * insert_screenshot / insert_window_event / insert_perf_stat), so taint that
 * reaches this argument is neutralized for CWE-89.
 *
 * No sanitizer exists on the raw-SQL export chain
 * (export_sql crud.py:142 -> create_db crud.py:209 -> connection.execute
 * crud.py:180): the f-string performs no quoting, escaping, identifier
 * allowlisting or validation of the interpolated values.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /** Restricts `n` to the openadapt source file with the given basename. */
  private predicate inPyFile(AstNode n, string basename) {
    n.getLocation().getFile().getShortName() = basename
  }

  /**
   * Label pass5-sink-003: the bound-parameters argument of the Core insert
   * at openadapt/crud.py:48 - `db.execute(sa.insert(table), to_insert)`
   * argument 1. Receiver `db` is the SQLAlchemy `Session()` created at
   * crud.py:23 (matched by name; the library is outside the database).
   *
   * This barrier only removes the bound-VALUES argument node from the graph;
   * it does not affect the raw-SQL text channel at crud.py:180, which is a
   * different call site with a different argument kind (SQL statement text).
   */
  private predicate coreInsertBoundValuesArgument(DataFlow::Node node) {
    exists(Call c |
      inPyFile(c, "crud.py") and
      c.getLocation().getStartLine() = 48 and
      c.getFunc().(Attribute).getName() = "execute" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "db" and
      node.asExpr() = c.getPositionalArg(1)
    )
  }

  /**
   * Holds if `node` is a CWE-89 sanitizer barrier for the given pass key.
   * Only `passKey = "sql_injection"` (Pass 5) is defined in this round.
   */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "sql_injection" and
    coreInsertBoundValuesArgument(node)
  }
}
