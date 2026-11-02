/**
 * @name SQL Injection (CWE-89, Pass 5)
 * @description Tracks attacker-controlled data from the Flask request boundary (request.args/form/json, FAB rison-injected kwargs, @expose route path variables) and the SQL Lab celery payload into raw SQL text executed by a database API (DBAPI cursor.execute, the legacy Engine.execute channel, engine-spec execute adapters, the SQL Lab execute_sql_statement(s) entry points, pd.read_sql_query) or into SQL-fragment/identifier parameters of the project's own SQL channel APIs (select_star table_name/schema, get_text_clause / ExploreMixin.text / SqlaTable.text clauses, SqlJsonExecutor rendered_query). Bound parameters are modeled as a barrier, so correctly parameterized values do not raise alerts; identifier quoting and the ad-hoc-clause structural guard are deliberately NOT barriers, so dynamically built SQL structure is still checked.
 * @id py/augur/superset/pass5-sql-injection
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
  "This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89)."
