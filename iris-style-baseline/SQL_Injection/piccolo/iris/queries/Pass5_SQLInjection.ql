/**
 * @name Piccolo SQL injection (untrusted data in SQL text)
 * @description Finds flows of untrusted input into SQL text that piccolo
 *   executes verbatim: raw-SQL template arguments (Table.raw / WhereRaw /
 *   SelectRaw), DDL identifier parameters interpolated into ALTER/SCHEMA
 *   statements, savepoint names, AS OF / ON CONFLICT SQL fragments, and the
 *   engine-layer execute/fetch/cursor SQL text argument. Bound parameters
 *   (asyncpg *args, aiosqlite execute(query, args) argument 1) are excluded
 *   from the sink model, so correctly parameterized values are not reported.
 * @id py/augur/piccolo/pass5-sql-injection
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
 * Pass 5 (CWE-89 SQL Injection) taint configuration, rendered from the
 * reviewed Pass 5 labels (iris/labels/labels.json, run
 * piccolo-iris-pass5-20261021). All four libraries share the pass key
 * "sql_injection".
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
  "Untrusted input reaches SQL text that is executed verbatim (CWE-89)."
