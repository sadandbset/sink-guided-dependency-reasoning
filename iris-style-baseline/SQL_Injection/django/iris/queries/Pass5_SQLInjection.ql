/**
 * @name SQL Injection (CWE-89, Pass 5)
 * @description Tracks attacker-controlled data from the framework's HTTP/WSGI request boundary into raw SQL text that is executed verbatim by a database cursor, a schema-editor DDL funnel, or one of the ORM raw-SQL APIs (QuerySet.raw/extra, RawSQL, RawQuery, RawQuerySet). Bound parameters are modeled as a barrier, so correctly parameterized values do not raise alerts.
 * @id py/augur/django/pass5-sql-injection
 * @kind path-problem
 * @problem.severity error
 * @precision medium
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
  "This data originates from an HTTP/WSGI request boundary (source) and flows into SQL text that is executed verbatim by a database API (sink). If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89)."
