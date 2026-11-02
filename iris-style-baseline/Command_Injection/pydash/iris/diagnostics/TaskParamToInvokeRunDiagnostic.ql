/**
 * DIAGNOSTIC QUERY - not part of the formal analysis results.
 *
 * @name Diagnostic: invoke task parameter propagation into invoke.run command string
 * @description Checks that the Pass 2 source labeling is complete and sound:
 *   for EVERY parameter of every invoke @task function in tasks.py, report
 *   whether local taint propagation reaches the shell command string of any
 *   `invoke.run` call. The human-reviewed labels (labels/labels.json) mark only
 *   `test.args`, `docs.bind`, and `docs.port` as sources; this diagnostic must
 *   therefore produce exactly those three findings and nothing else. Any
 *   additional finding would indicate a missed source label; the absence of
 *   `ctx`/`quiet`/`serve` findings re-confirms the negative labeling decisions.
 *   Results of this query are excluded from the formal vulnerability report.
 * @id py/augur/pydash/diag/task-param-to-invoke-run
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @tags diagnostics
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySinks

from Parameter p, DataFlow::Node sink
where
  isTaskParameter(p) and
  MySinks::isSink(sink, "command_injection") and
  TaintTracking::localTaint(DataFlow::parameterNode(p), sink)
select p,
  "Task parameter '" + p.getName() + "' locally propagates into an invoke.run command string (sink at " +
    sink.getLocation().getFile().getShortName() + ":" + sink.getLocation().getStartLine() +
    "); verify that its Pass 2 source label is correct."

/** Any parameter of any module-level invoke @task function in tasks.py. */
private predicate isTaskParameter(Parameter p) {
  exists(Function f |
    f.getLocation().getFile().getShortName() = "tasks.py" and
    f.getEnclosingScope() instanceof Module and
    hasInvokeTaskDecorator(f) and
    p = f.getAnArg()
  )
}

/** Recognizes both `@task` (bare name) and `@task(help={...})` (call form). */
private predicate hasInvokeTaskDecorator(Function f) {
  exists(Expr dec | dec = f.getADecorator() |
    dec.(Name).getId() = "task"
    or
    dec.(Call).getFunc().(Name).getId() = "task"
  )
}
