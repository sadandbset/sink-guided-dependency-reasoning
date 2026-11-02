/**
 * @name AutoGluon Python parameter candidates for Augur Pass 2
 * @description Extract Python function parameters for manual CWE-78 source classification.
 * @kind problem
 * @problem.severity recommendation
 * @id py/augur/autogluon/source-candidates
 */
import python

from Function f, Parameter p, int argIndex
where
  f.inSource() and
  not p.isSelf() and
  (
    (argIndex >= 0 and p = f.getArg(argIndex))
    or
    (argIndex = -1 and p = f.getAKwonlyarg())
  )
select p, "Review as possible CWE-78 source; not a confirmed source.",
  "function_parameter", f.getQualifiedName(), p.getName(),
  argIndex, f.getEnclosingScope().toString(),
  p.getLocation().getFile().getRelativePath(),
  p.getLocation().getStartLine()