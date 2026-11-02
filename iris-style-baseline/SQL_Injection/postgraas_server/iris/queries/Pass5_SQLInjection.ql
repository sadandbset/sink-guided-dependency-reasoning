/**
 * @name Pass 5: SQL Injection (CWE-89)
 * @description Tracks the reqparse HTTP request boundary of the postgraas_server
 *   REST API (POST /api/v2/postgraas_instances — postgraas_instance_name /
 *   db_name / db_username / db_pwd; DELETE /api/v2/postgraas_instances/<int:id> —
 *   db_pwd) into the raw SQL text executed by cursor.execute in the pg_cluster
 *   backend driver, where every statement is assembled with str.format and no
 *   bound parameters are used anywhere. Sources, sinks, barriers and additional
 *   taint steps are rendered from the human-reviewed labels in
 *   iris/labels/labels.json (run postgraas-server-iris-pass5-20261021, pass 5,
 *   classification tp only, pass key "sql_injection"): eight location-pinned tp
 *   sink sites (postgres_cluster_driver.py:22/:24/:43/:44/:50/:52/:65/:75,
 *   argument 0 — the SQL text) and an empty confirmed sanitizer set (no
 *   bound-parameter channel, no identifier whitelisting; the double-quote
 *   quoting in the GRANT/DROP templates is partial identifier quoting that a
 *   '"' in the value breaks out of). The wrapper propagation (reqparse dict
 *   elements, current_app.postgraas_backend dynamic dispatch, DBInstance field
 *   stores, connection_dict element reads and **-unpacked format templates) is
 *   modeled by evidence-pinned summary edges in MySummaries.qll.
 * @id py/augur/postgraas_server/pass5-sql-injection
 * @kind path-problem
 * @problem.severity error
 * @precision low
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

/**
 * Pass 5 (CWE-89) flow configuration. The pass key "sql_injection" selects the
 * reviewed (tp) label set. The barrier predicate always exists (WORKFLOW.md
 * 5.2.3) — it delegates to MySanitizers, whose confirmed set is EMPTY (no
 * DB-API bound parameters, no identifier whitelist, no quoting construct that
 * neutralizes the interpolated values exists anywhere in the snapshot), so it
 * resolves to none(); it never blocks unconditionally.
 */
module Pass5Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "sql_injection")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "sql_injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "sql_injection")
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "sql_injection")
  }
}

module Pass5Flow = TaintTracking::Global<Pass5Config>;
import Pass5Flow::PathGraph

from Pass5Flow::PathNode source, Pass5Flow::PathNode sink
where Pass5Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection: attacker-controlled request value (reqparse argument of the " +
  "postgraas REST API) flows into the SQL query text of a cursor.execute call " +
  "in the pg_cluster driver, which assembles every statement with str.format " +
  "and uses no bound parameters."
