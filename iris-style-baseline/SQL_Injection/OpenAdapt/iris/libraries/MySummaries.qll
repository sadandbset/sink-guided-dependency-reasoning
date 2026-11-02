/**
 * Augur Phase 2 Step 4 - generated taint-summary (additional flow step)
 * library.
 *
 * Pass 5 (CWE-89, SQL Injection) for the OpenAdapt project.
 *
 * Machine-generated from `iris/labels/labels.json` (pass_id 5, role=summary,
 * 1 reviewed entry: pass5-src-049 - the create_db argument-1 hand-off of
 * `export_sql`'s return value at openadapt/crud.py:209).
 *
 * This predicate deliberately resolves to `none()`:
 *
 * The single reviewed summary label marks the value hand-off
 *   crud.py:208  sql = export_sql(recording_id)
 *   crud.py:209  t, db_file_path = create_db(recording_id, sql)
 * whose tainted value (the f-string built at crud.py:142) is executed
 * verbatim at crud.py:180. CodeQL's default interprocedural taint tracking
 * already models every edge of this chain: f-string component taint
 * (TaintTrackingPrivate "Fstring.getAValue" step), local assignment to
 * `sql`, the `return sql` of `export_sql`, the return value at the call
 * site, the argument-1 expression of `create_db`, the `sql` parameter, and
 * the use as argument 0 of `connection.execute`. Adding an additional
 * unconditional edge (e.g. export_sql return -> create_db argument 1)
 * would create context-insensitive propagation that is NOT proven by the
 * source code, so no additional taint step is established.
 *
 * Known gaps that would require an explicit summary edge are intentionally
 * left unmodeled because no in-source data-flow evidence exists for them
 * (they cross process or persistence boundaries):
 *   - UI name (cards.py:44) -> Popen -> `python3 -m openadapt.record`
 *     -> fire CLI `record(task_description)` (process boundary),
 *   - `record(task_description)` -> parameterized ORM insert -> SQLite
 *     database -> ORM re-read in `export_sql` (database round-trip).
 * The DB-resident side of the chain is instead modeled directly by the
 * `recording.<column>` sources at crud.py:142 in MySources.qll.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {

  /**
   * Holds if taint may additionally flow from `nodeFrom` to `nodeTo` for
   * the given pass key. Only `passKey = "sql_injection"` (Pass 5) is
   * defined in this round, and no additional flow step is justified by
   * the source code, so this always fails.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    none()
  }
}
