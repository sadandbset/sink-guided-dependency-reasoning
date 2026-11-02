/**
 * @name pydash CWE-78 source candidate extraction
 * @description Extract source candidates for raw BQRS decoding.
 * @id iris/pydash-cwe78/extraction/sources
 */

import python
import semmle.python.ApiGraphs

// Preserve the original test-path policy; this is a substring filter.
bindingset[p]
predicate isTestPath(string p) { p.matches("%tests%") }

// Syntax only: @task or @task(...), not import resolution.
predicate hasInvokeTaskDecorator(Function f) {
  exists(Expr d |
    d = f.getADecorator() and
    (
      d instanceof Name and d.(Name).getId() = "task"
      or
      d instanceof Call and
      d.(Call).getFunc() instanceof Name and
      d.(Call).getFunc().(Name).getId() = "task"
    )
  )
}

bindingset[n]
predicate isPublicName(string n) { not n.regexpMatch("_.*") }

// API::CallNode must be converted to an AST expression before matching Call.
predicate resolvedEnvRead(Call c, string moduleHint, string callableName) {
  (
    c = API::moduleImport("os").getMember("getenv").getACall().asExpr() and
    moduleHint = "os" and
    callableName = "getenv"
  )
  or
  (
    c = API::moduleImport("os").getMember("environ").getMember("get")
          .getACall().asExpr() and
    moduleHint = "os.environ" and
    callableName = "environ.get"
  )
}

predicate sourceCandidate(
  string nodeDesc, string callableName, string flowKind, string receiver,
  string moduleHint, int argIdx, string filePath, int line, string matchKind
) {
  // Family 1: the returned environment value is the candidate source.
  exists(Call c |
    resolvedEnvRead(c, moduleHint, callableName) and
    filePath = c.getLocation().getFile().getAbsolutePath() and
    not isTestPath(filePath) and
    line = c.getLocation().getStartLine() and
    flowKind = "return" and
    receiver = "" and
    argIdx = -1 and
    matchKind = "resolved_api" and
    nodeDesc = "Call:" + callableName
  )
  or
  // Family 2: positional parameters, including the Invoke context parameter.
  // Keyword-only parameters, *args and **kwargs are not included here.
  exists(Function f, int idx |
    hasInvokeTaskDecorator(f) and
    idx in [0 .. f.getPositionalParameterCount() - 1] and
    f.getArg(idx) instanceof Parameter and
    filePath = f.getLocation().getFile().getAbsolutePath() and
    not isTestPath(filePath) and
    line = f.getLocation().getStartLine() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = "" and
    moduleHint = f.getLocation().getFile().getBaseName() and
    argIdx = idx and
    matchKind = "syntax" and
    nodeDesc = "Parameter:" + idx.toString() + ":" + f.getName()
  )
  or
  // Family 3: preserve the original sys.argv ATTRIBUTE-reference match.
  // This also matches sys.argv without subscripting; it is not element-only.
  exists(Attribute a |
    a.getName() = "argv" and
    a.getObject() instanceof Name and
    a.getObject().(Name).getId() = "sys" and
    filePath = a.getLocation().getFile().getAbsolutePath() and
    not isTestPath(filePath) and
    line = a.getLocation().getStartLine() and
    callableName = "argv" and
    flowKind = "reference" and
    receiver = "sys" and
    moduleHint = "sys" and
    argIdx = -1 and
    matchKind = "syntax" and
    nodeDesc = "Attribute:sys.argv"
  )
  or
  // Family 4: public definitions, excluding tasks and nested functions.
  // This is a definition-level candidate, not an individual parameter node.
  exists(Function f |
    (f.getEnclosingScope() instanceof Module or f.getEnclosingScope() instanceof Class) and
    isPublicName(f.getName()) and
    not hasInvokeTaskDecorator(f) and
    filePath = f.getLocation().getFile().getAbsolutePath() and
    not isTestPath(filePath) and
    line = f.getLocation().getStartLine() and
    callableName = f.getName() and
    flowKind = "param" and
    argIdx = -1 and
    moduleHint = f.getLocation().getFile().getBaseName() and
    matchKind = "definition" and
    nodeDesc = "FunctionDef:" + f.getName() and
    (
      f.getEnclosingScope() instanceof Class and
      receiver = f.getEnclosingScope().(Class).getName()
      or
      f.getEnclosingScope() instanceof Module and
      receiver = ""
    )
  )
}

from string nodeDesc, string callableName, string flowKind, string receiverValue,
     string moduleHint, int argIdx, string filePath, int startLine, string matchKind
where
  sourceCandidate(nodeDesc, callableName, flowKind, receiverValue, moduleHint,
    argIdx, filePath, startLine, matchKind)
select
  nodeDesc as node,
  "source_candidate" as candidate_kind,
  callableName as callable,
  flowKind as flow_kind,
  receiverValue as receiver,
  moduleHint as module_hint,
  argIdx as arg_index,
  filePath as file,
  startLine as line,
  matchKind as match_kind