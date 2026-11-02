/**
 * @name Pass 5: SQL Injection (CWE-89)
 * @description Tracks Django HTTP request input (request.GET / request.POST /
 *   request.body / request.FILES / request.META reads, request-parameter
 *   .get()/subscript reads, and reviewed handler/route parameters) into raw
 *   SQL query text executed by a database cursor. Sources, sinks, barriers
 *   and additional taint steps are rendered from the human-reviewed labels in
 *   iris/labels/labels.json (run arches-iris-pass5-20261020, pass 5):
 *   7 confirmed (tp) sink entries on two unauthenticated RDM endpoints —
 *   /concepts/paged_dropdown (request "query" -> sql.format at
 *   views/concept.py:424 -> execute :426, and query -> get_child_edges
 *   %-format LIKE literal at models/concept.py:635 -> execute :723) and
 *   /concepts/dropdown (request "conceptid" -> get_e55_domain .format at
 *   models/concept.py:1180 -> execute :1216, no uuid validation) — plus 11
 *   operator-trust candidate sink entries (export/packages/v3/index_database
 *   management-command paths) and 80+26 candidate sources (CLI options /
 *   operator files) that the labels kept for conservative recall; candidate
 *   alerts must be triaged at Step 6, they are not confirmed
 *   remote-attacker vulnerabilities. Bound parameters (execute argument 1)
 *   are barriers, never sinks; the uuid.UUID/int()/float()/GEOSGeometry
 *   sanitizers reviewed in Phase 1 are barriers.
 * @id py/augur/arches/pass5-sql-injection
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

/**
 * Pass 5 (CWE-89) flow configuration. The pass key "sql_injection" selects
 * the reviewed pass-5 label set (tp + candidate — the candidate entries are
 * operator-trust paths kept for conservative recall; see
 * report/query_generation_notes.md). The barrier predicate always exists
 * (WORKFLOW.md 5.2.3 mandatory barrier hook) and delegates to MySanitizers
 * (44 bound-parameter rows + 6 code-evidence sanitizer sites); it never
 * blocks unconditionally. The additional flow steps delegate to MySummaries
 * (reviewed wrapper/helper hand-off edges; every step is bound to a concrete
 * call site and callee parameter).
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
  "SQL injection: attacker-influenced value flows into raw SQL query text " +
  "executed by a database cursor (dynamic SQL construction via %-formatting " +
  "or str.format, not a bound parameter)."
