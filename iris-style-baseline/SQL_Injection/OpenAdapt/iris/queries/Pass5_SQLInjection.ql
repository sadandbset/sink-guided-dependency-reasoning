/**
 * @name OpenAdapt: SQL injection in recording export
 * @description Finds untrusted data from database content (recording columns
 *   such as task_description and platform, populated from UI/CLI input or
 *   from an imported database file) flowing into raw SQL statement text that
 *   is executed by openadapt's recording export chain:
 *   export_sql (crud.py:142 f-string construction) -> create_db sql parameter
 *   (crud.py:209) -> connection.execute (crud.py:180).
 * @id py/augur/openadapt/pass5-sql-injection
 * @kind path-problem
 * @problem.severity error
 * @precision high
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
  "SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute)."
