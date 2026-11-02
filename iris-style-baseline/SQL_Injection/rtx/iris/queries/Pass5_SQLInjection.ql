/**
 * @name RTX: SQL injection in ARAX and autocomplete raw SQL
 * @description Finds untrusted data from external input boundaries - the
 *   connexion/Flask OpenAPI request bodies and JSON reads of POST /query and
 *   POST /asyncquery, and the tornado query parameters of GET /nodeslike -
 *   flowing into raw SQL statement text executed by sqlite3's
 *   cursor.execute(): the autocomplete term lookups in rtxcomplete.py, the
 *   predictor feature/DTD-probability lookups in predictor.py, the
 *   Fisher-exact-test category-count lookup in fisher_exact_test.py, and the
 *   COHD paired-concept-frequency lookups in COHDIndex.py (second-order
 *   candidate channel). Parameterized execute calls, ORM query channels,
 *   quote-escaped IN-lists and int()-cast numeric limits are excluded via
 *   the reviewed sanitizer barriers.
 * @id py/augur/rtx/pass5-sql-injection
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
  "SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup)."
