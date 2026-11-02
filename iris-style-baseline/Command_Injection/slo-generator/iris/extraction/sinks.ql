/**
 * @name slo-generator CWE-78 sink candidate extraction
 * @description Extract command/process execution sink candidates from the
 *   slo-generator CodeQL database (snapshot 50ce1bf). Verified fact: this
 *   codebase contains ZERO direct process-execution call sites (no
 *   subprocess.*, os.system, os.popen, os.exec*, os.spawn*, no shell=True
 *   anywhere in slo_generator/, samples/ or setup.py); those standard CWE-78
 *   families are still included (resolved via API graphs and by AST shape)
 *   as the exhaustive baseline. The execution-shaped boundary that actually
 *   exists in this project is name-based dynamic resolution, driven by
 *   configuration that can originate from the Functions Framework request
 *   body: dynamic import (importlib.import_module), dynamic attribute
 *   dispatch (getattr, argument 1 carries the resolved name), indirect
 *   invocation of dispatch results (calls whose callee was assigned from a
 *   getattr / import_dynamic / import_cls / get_backend_cls /
 *   get_exporter_cls call in the same function), environment writes
 *   (os.environ[...] = value consumed by the prometheus client and the API
 *   module), sys.path.append (widening the dynamic module search path),
 *   internal wrapper functions that resolve and invoke code by name, and
 *   f-string name construction feeding the dispatch calls. Raw BQRS
 *   extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong shape
 *   for candidate tables and @kind table is not assumed to exist.
 * @id iris/slo-generator/extraction/sinks
 * @tags command-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name (API member name, function name, attribute name,
 *                   the env var name for env_write rows, or "fstring" /
 *                   "percent_format" / "format" for name_format rows)
 *   4. flow_kind  - "arg" (command argument position of a process-exec API),
 *                   "shell_true" (call site passing shell=True),
 *                   "dynamic_import" (module imported from a config-derived path),
 *                   "getattr_dispatch" (attribute name resolved from data, arg 1),
 *                   "dispatch_invocation" (indirect call of a dispatch result),
 *                   "env_write" (os.environ[...] assignment),
 *                   "sys_path_write" (sys.path.append),
 *                   "internal_exec_wrapper" (function that resolves/invokes code
 *                   by name), "name_format" (dynamic name construction feeding a
 *                   dispatch call)
 *   5. receiver   - syntactic receiver hint (base name of the object expression, "" if none)
 *   6. moduleHint - module hint: external module name, or dotted python module path for
 *                   internal candidates (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the command / module
 *                   path / attribute name, -1 if not applicable
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath(); AstNode.getFile()
 *                    does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast" (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), avoids assigning API::Node
 * values to DataFlow::Node variables, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced a row).
 * "Normal command execution functionality is not automatically a vulnerability": the
 * dynamic import / getattr chain is a documented plugin extension point of
 * slo-generator; rows are candidates for labeling, not findings.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Files not on an import path fall back to the file
 *  base name. */
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

/** Holds if n is inside the analysis scope: the tests/ tree (tests/unit,
 *  fixtures) is excluded as candidate noise per the Augur candidate strategy.
 *  Path matching is separator-agnostic (Windows or POSIX layout). */
predicate inScope(AstNode n) {
  not n.getLocation().getFile().getAbsolutePath().toLowerCase().regexpMatch(
    "^.*[/\\\\]tests[/\\\\].*$"
  )
}

/* ------------------------------------------------------------------ */
/* Sink family 1: resolved process-execution API calls (API graphs)    */
/* ------------------------------------------------------------------ */

/**
 * Process/command execution APIs with the 0-based positional argument index that carries
 * the command string / argv. os.spawn* takes the command at index 1 (index 0 is the mode).
 * Verified: zero call sites of any of these members exist in this snapshot; the family is
 * kept as the exhaustive CWE-78 baseline.
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
 * Verified: zero such shapes exist in this snapshot.
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
/* Sink families 4-8: the dynamic resolution boundary                  */
/* ------------------------------------------------------------------ */

/** Holds if cn is a call genuinely resolved to importlib.import_module
 *  (the only dynamic import API used in this codebase, utils.py:337). */
private predicate resolvedImportCall(API::CallNode cn) {
  cn = API::moduleImport("importlib").getMember("import_module").getACall()
}

/**
 * AST-only dynamic import shapes: `<alias>.import_module(...)` (any module alias name)
 * or a bare from-imported `import_module(...)`. Rows already resolved through API graphs
 * are filtered out at row assembly so no call site is emitted twice.
 */
private predicate syntacticImportCall(Call c) {
  c.getFunc().(Attribute).getName() = "import_module" and
  c.getFunc().(Attribute).getObject() instanceof Name
  or
  c.getFunc().(Name).getId() = "import_module"
}

/** Holds if c is a bare getattr(...) call: the attribute name (argument 1) is
 *  resolved from data. This is the dominant dispatch shape of this codebase. */
private predicate getattrDispatchCall(Call c) {
  c.getFunc().(Name).getId() = "getattr"
}

/**
 * Internal wrapper functions of the name-resolution chain: their results are
 * code objects obtained from (config-derived) names. Called by bare name or by
 * module attribute (e.g. utils.import_cls / utils.get_backend_cls).
 */
private predicate internalWrapperCall(Call c) {
  c.getFunc().(Name).getId() in ["import_dynamic", "import_cls",
                                 "get_backend_cls", "get_exporter_cls"]
  or
  c.getFunc().(Attribute).getName() in ["import_dynamic", "import_cls",
                                        "get_backend_cls", "get_exporter_cls"]
}

/** Holds if c is any call site that resolves code by name: a dynamic import
 *  (resolved or syntactic shape), a bare getattr dispatch, or a call into an
 *  internal name-resolution wrapper. */
private predicate dispatchCallSite(Call c) {
  exists(API::CallNode cn |
    resolvedImportCall(cn) and
    c = astCallOf(cn)
  )
  or
  syntacticImportCall(c)
  or
  getattrDispatchCall(c)
  or
  internalWrapperCall(c)
}

/** Functions in this codebase whose body directly resolves code by name
 *  (dynamic import / getattr / internal wrapper call). */
private predicate internalExecWrapper(Function f) {
  exists(Call c |
    dispatchCallSite(c) and
    c.getScope().(Function) = f
  )
}

/**
 * Indirect invocation of a dispatch result: a call whose callee is a bare Name
 * that was assigned the result of a getattr / import_dynamic / import_cls /
 * get_backend_cls / get_exporter_cls call within the same enclosing function.
 * Observed shapes: migrator.py:79/89/141 ebp_func/exporters_func/slo_func(...),
 * report.py:203 instance = cls(...) and report.py:216 method(...),
 * dynatrace.py:311/313 req(url, headers=...).
 * Not covered: compute.py:119 instance().export(...) (callee is an attribute of
 * a call result, not a Name) - see detection.json uncoveredCases.
 */
private predicate indirectInvocCall(Call c) {
  exists(AssignStmt a, Variable v, Call g |
    c.getFunc().(Name).getVariable() = v and
    a.getATarget().(Name).getVariable() = v and
    g = a.getValue().(Call) and
    (
      getattrDispatchCall(g)
      or
      internalWrapperCall(g)
    ) and
    a.getScope() = c.getScope()
  )
}

/** Holds if e is a dynamic name construction expression: an f-string, a
 *  '%'-format with a literal format string, or a .format(...) template call. */
private predicate isFormatExpr(Expr e) {
  e instanceof Fstring
  or
  exists(BinaryExpr m |
    m = e and
    m.getOp() instanceof Mod and
    m.getLeft() instanceof StringLiteral
  )
  or
  exists(Call fc |
    fc = e and
    fc.getFunc().(Attribute).getName() = "format"
  )
}

/**
 * Dynamic name construction feeding a dispatch call:
 *   - a format expression passed directly as a positional argument of a dispatch
 *     call site (migrator.py:78/87/139 f"ebp_{curver}to{version}" as the getattr
 *     name; utils.py:321 f'slo_generator.{...}.{...}' as the import_dynamic package), or
 *   - a format expression assigned to a variable that is later passed as a
 *     positional argument of a dispatch call site in the same function
 *     (utils.py:319 full_cls_name -> import_dynamic name argument).
 */
private predicate nameFormatNode(AstNode n) {
  exists(Call dc, Expr arg |
    dispatchCallSite(dc) and
    arg = dc.getAPositionalArg() and
    isFormatExpr(arg) and
    n = arg
  )
  or
  exists(AssignStmt a, Variable v, Call dc, Expr arg |
    isFormatExpr(a.getValue()) and
    n = a.getValue() and
    a.getATarget().(Name).getVariable() = v and
    arg = dc.getAPositionalArg() and
    arg.(Name).getVariable() = v and
    dispatchCallSite(dc) and
    a.getScope() = dc.getScope()
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
  /* family 4a: resolved dynamic import (API graphs) */
  exists(API::CallNode cn |
    resolvedImportCall(cn) and
    node = astCallOf(cn) and
    flowKind = "dynamic_import" and
    callableName = "import_module" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "importlib" and
    matchKind = "api"
  )
  or
  /* family 4b: syntactic dynamic import shapes not resolved by API graphs
     (moduleHint "<unresolved>": the alias cannot be confirmed syntactically) */
  exists(Call c |
    syntacticImportCall(c) and
    not exists(API::CallNode cn |
      resolvedImportCall(cn) and
      astCallOf(cn) = c
    ) and
    node = c and
    flowKind = "dynamic_import" and
    callableName = "import_module" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "<unresolved>" and
    matchKind = "ast"
  )
  or
  /* family 5: bare getattr dispatch (argument 1 carries the resolved name) */
  exists(Call c |
    getattrDispatchCall(c) and
    node = c and
    flowKind = "getattr_dispatch" and
    callableName = "getattr" and
    argIndex = 1 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6: indirect invocation of a dispatch result */
  exists(Call c |
    indirectInvocCall(c) and
    node = c and
    flowKind = "dispatch_invocation" and
    callableName = calledName(c) and
    argIndex = -1 and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 7: environment writes: os.environ[<name>] = value
     (callable is the env var name when it is a string literal) */
  exists(AssignStmt a, Subscript sub |
    sub = a.getATarget() and
    sub.getObject().(Attribute).getName() = "environ" and
    sub.getObject().(Attribute).getObject().(Name).getId() = "os" and
    node = sub and
    flowKind = "env_write" and
    argIndex = -1 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast" and
    (
      (
        sub.getIndex() instanceof StringLiteral and
        callableName = sub.getIndex().(StringLiteral).getText()
      )
      or
      (
        not sub.getIndex() instanceof StringLiteral and
        callableName = "<expr>"
      )
    )
  )
  or
  /* family 8: sys.path.append(...) - widens the dynamic module search path */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "append" and
    c.getFunc().(Attribute).getObject().(Attribute).getName() = "path" and
    c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "sys" and
    node = c and
    flowKind = "sys_path_write" and
    callableName = "append" and
    argIndex = 0 and
    receiver = "sys.path" and
    moduleHint = "sys" and
    matchKind = "ast"
  )
  or
  /* family 9: internal functions that resolve / invoke code by name */
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
  /* family 10: dynamic name construction feeding a dispatch call */
  exists(AstNode n |
    nameFormatNode(n) and
    node = n and
    flowKind = "name_format" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(n) and
    (
      (
        n.(Call).getFunc().(Attribute).getName() = "format" and
        callableName = "format" and
        receiver = receiverHint(n.(Call).getFunc().(Attribute))
      )
      or
      (
        n instanceof Fstring and
        callableName = "fstring" and
        receiver = ""
      )
      or
      (
        n instanceof BinaryExpr and
        callableName = "percent_format" and
        receiver = ""
      )
    )
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  inScope(node)
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
