/**
 * @name maltrail CWE-78 sink candidate extraction
 * @description Extract command/process execution sink candidates from the maltrail
 *   CodeQL database (snapshot bb4d24b): subprocess / os execution API calls (resolved
 *   via API graphs and by AST shape), call sites using shell=True, dynamic command
 *   construction ('%'-string formatting with a literal format string, either passed
 *   directly as the command argument or located inside an executing function, and
 *   .format() template calls inside executing functions), and internal wrapper
 *   functions that directly run OS commands. Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database analyze).
 *   This is a plain multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/maltrail/extraction/sinks
 * @tags command-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or attribute name;
 *                   "percent_format" for '%' command formatting expressions)
 *   4. flow_kind  - "arg" (command argument position), "shell_true" (call site passing
 *                   shell=True - shell string execution rather than argv-list execution),
 *                   "cmd_format" (dynamic command string construction),
 *                   "internal_exec_wrapper" (function that directly executes OS commands)
 *   5. receiver   - syntactic receiver hint (base name of the object expression, "" if none)
 *   6. moduleHint - module hint: external module name, or dotted python module path for
 *                   internal candidates (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the command, -1 if not applicable
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath(); AstNode.getFile()
 *                    does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast" (syntax-level match)
 *
 * Shell / non-shell distinction: "shell_true" rows mark call sites that interpret the
 * command argument through a shell; every subprocess site in this snapshot passes
 * shell=True, and no argv-list (shell=False/None) execution site exists in project
 * source. "cmd_format" rows mark dynamic command construction ('%'-formatting is the
 * maltrail idiom, .format() is matched as well).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for internal
 *  candidates). Top-level scripts that are not on an import path (sensor.py, server.py,
 *  core/update.py) have no dotted module name; their file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
}

/** Base name of the object expression of an attribute access, used as a receiver hint. */
string receiverHint(Attribute a) {
  result = a.getObject().(Name).getId()
  or
  result = a.getObject().(Attribute).getName()
  or
  not a.getObject() instanceof Name and
  not a.getObject() instanceof Attribute and
  result = "<expr>"
}

/** Receiver hint for the callee expression of a call ("" when there is no attribute receiver). */
string receiverHintOfCall(Call c) {
  exists(Attribute a |
    a = c.getFunc() and
    result = receiverHint(a)
  )
  or
  not c.getFunc() instanceof Attribute and result = ""
}

/** Syntactic name of the callee of a call ("<expr>" if it is neither Name nor Attribute). */
string calledName(Call c) {
  result = c.getFunc().(Name).getId()
  or
  result = c.getFunc().(Attribute).getName()
  or
  not c.getFunc() instanceof Name and
  not c.getFunc() instanceof Attribute and
  result = "<expr>"
}

/* ------------------------------------------------------------------ */
/* Sink family 1: resolved process-execution API calls (API graphs)    */
/* ------------------------------------------------------------------ */

/**
 * Process/command execution APIs with the 0-based positional argument index that carries
 * the command string / argv. os.spawn* takes the command at index 1 (index 0 is the mode).
 * Only subprocess.check_output and subprocess.Popen are exercised in this snapshot; the
 * remaining members are the standard CWE-78 sink set and are kept for exhaustiveness.
 */
private predicate execApiArgIndex(string moduleHint, string member, int argIndex) {
  moduleHint = "subprocess" and
  member in ["run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"] and
  argIndex = 0
  or
  moduleHint = "os" and
  member in ["system", "popen", "execv", "execve", "execl", "execle", "execlp", "execlpe",
             "execvp", "execvpe"] and
  argIndex = 0
  or
  moduleHint = "os" and
  member in ["spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp",
             "spawnvpe"] and
  argIndex = 1
}

/** Holds if cn is a call node genuinely resolved to a process-execution API (alias-aware). */
private predicate resolvedExecCall(API::CallNode cn, string moduleHint, string member, int argIndex) {
  execApiArgIndex(moduleHint, member, argIndex) and
  cn = API::moduleImport(moduleHint).getMember(member).getACall()
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Sink family 2: syntax-level process-execution call shapes           */
/* ------------------------------------------------------------------ */

/**
 * AST-only matches: syntactic `<module>.<member>(...)` shapes with a known execution-API
 * member, plus bare distinctive names (from-import aliases). moduleHint is "<unresolved>"
 * for bare names because the defining module cannot be confirmed syntactically.
 */
private predicate syntacticExecCall(Call c, string moduleHint, string member, int argIndex) {
  execApiArgIndex(moduleHint, member, argIndex) and
  c.getFunc().(Attribute).getName() = member and
  c.getFunc().(Attribute).getObject().(Name).getId() = moduleHint
  or
  member in ["system", "popen", "getoutput", "getstatusoutput"] and
  argIndex = 0 and
  moduleHint = "<unresolved>" and
  c.getFunc().(Name).getId() = member
}

/* ------------------------------------------------------------------ */
/* Sink family 3: shell=True call sites                                */
/* ------------------------------------------------------------------ */

/** Holds if c passes the keyword argument shell=True. */
private predicate shellTrueCall(Call c) {
  exists(Keyword k |
    k = c.getANamedArg().(Keyword) and
    k.getArg() = "shell" and
    k.getValue() instanceof True
  )
}

/* ------------------------------------------------------------------ */
/* Sink families 4+5: internal wrappers and command formatting         */
/* ------------------------------------------------------------------ */

/** Holds if c is any call site (resolved or syntactic shape) into a process-execution API. */
private predicate execCallSite(Call c) {
  exists(API::CallNode cn |
    resolvedExecCall(cn, _, _, _) and
    c = astCallOf(cn)
  )
  or
  syntacticExecCall(c, _, _, _)
}

/** Functions in this codebase whose body directly calls a process-execution API. */
private predicate internalExecWrapper(Function f) {
  exists(Call c |
    execCallSite(c) and
    c.getScope().(Function) = f
  )
}

/**
 * Dynamic command construction nodes:
 *   - a '%' string-formatting expression (BinaryExpr with a Mod operator and a literal
 *     format string on the left) passed directly as a positional argument of an execution
 *     call site (the maltrail idiom, e.g. core/httpd.py:399 and sensor.py:1037), or
 *   - a '%' string-formatting expression with a literal format string located inside a
 *     function that directly executes OS commands (command stored in a variable first), or
 *   - a `.format(...)` template call inside a function that directly executes OS commands.
 */
private predicate cmdFormatNode(AstNode n) {
  exists(BinaryExpr m, Call c |
    execCallSite(c) and
    m.getOp() instanceof Mod and
    m.getLeft() instanceof StringLiteral and
    m = c.getAPositionalArg() and
    n = m
  )
  or
  exists(BinaryExpr m, Function f |
    internalExecWrapper(f) and
    m.getOp() instanceof Mod and
    m.getLeft() instanceof StringLiteral and
    m.getScope().(Function) = f and
    not exists(Call c |
      execCallSite(c) and
      m = c.getAPositionalArg()
    ) and
    n = m
  )
  or
  exists(Call c, Function f |
    internalExecWrapper(f) and
    c.getFunc().(Attribute).getName() = "format" and
    c.getScope().(Function) = f and
    n = c
  )
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: resolved process-execution API calls (API graphs, alias-aware) */
  exists(API::CallNode cn |
    resolvedExecCall(cn, moduleHint, callableName, argIndex) and
    node = astCallOf(cn) and
    flowKind = "arg" and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 2: syntax-level process-execution call shapes */
  exists(Call c |
    syntacticExecCall(c, moduleHint, callableName, argIndex) and
    node = c and
    flowKind = "arg" and
    receiver = "" and
    matchKind = "ast"
  )
  or
  /* family 3: call sites using shell=True */
  exists(Call c |
    shellTrueCall(c) and
    node = c and
    flowKind = "shell_true" and
    callableName = calledName(c) and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    argIndex = -1 and
    matchKind = "ast"
  )
  or
  /* family 4: internal functions that directly run OS commands */
  exists(Function f |
    internalExecWrapper(f) and
    node = f and
    flowKind = "internal_exec_wrapper" and
    callableName = f.getName() and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    (
      f.getEnclosingScope() instanceof Class and
      receiver = f.getEnclosingScope().(Class).getName()
      or
      not f.getEnclosingScope() instanceof Class and
      receiver = ""
    )
  )
  or
  /* family 5: dynamic command construction ('%'-formatting / .format() templates) */
  exists(AstNode n |
    cmdFormatNode(n) and
    node = n and
    flowKind = "cmd_format" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(n) and
    (
      n.(Call).getFunc().(Attribute).getName() = "format" and
      callableName = "format" and
      receiver = receiverHint(n.(Call).getFunc().(Attribute))
      or
      not n instanceof Call and
      callableName = "percent_format" and
      receiver = ""
    )
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind)
select
  node,
  "sink_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
