/**
 * @name yt-dlp CWE-78 sink candidate extraction
 * @description Extract command/process execution sink candidates from the yt-dlp
 *   CodeQL database (snapshot 61bdf15): subprocess execution APIs (subprocess.call
 *   exercised in yt_dlp/postprocessor/exec.py, subprocess.run only under devscripts/),
 *   the internal yt_dlp.utils.Popen wrapper (class Popen(subprocess.Popen) at
 *   yt_dlp/utils/_utils.py:802 with its run() classmethod) which nearly every
 *   production execution site goes through, call sites passing shell=True
 *   (exec.py:31, extractor/common.py:1311, update.py:376 via atexit.register),
 *   indirect execution where the Popen callable is passed as a callback argument
 *   (atexit.register(Popen, cmd, shell=True) in update.py), internal wrapper
 *   functions that directly run OS commands, and dynamic command construction
 *   ('%'-formatting, .format()/.replace() string surgery, list concatenation)
 *   feeding those sinks. os.system / os.popen / os.exec* / os.spawn* / pexpect do
 *   not occur in this tree and are kept only as the standard CWE-78 API set.
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain multi-column
 *   select query on purpose: @kind problem is the wrong shape for candidate
 *   tables and @kind table is not assumed to exist.
 * @id iris/yt-dlp/extraction/sinks
 * @tags command-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name (API member name, function/class name, or attribute
 *                   name; "percent_format" for '%' command formatting expressions,
 *                   "list_concat" for argv list concatenation)
 *   4. flow_kind  - "arg" (command/argv argument position of a real execution API),
 *                   "shell_true" (call site passing shell=True - the command argument
 *                   is interpreted through a shell),
 *                   "internal_exec_wrapper" (function/class that directly runs OS
 *                   commands),
 *                   "cmd_format" (dynamic command string construction),
 *                   "cmd_build" (command argv list construction),
 *                   "indirect_exec" (call handing an execution callable elsewhere,
 *                   e.g. atexit.register(Popen, ...))
 *   5. receiver   - syntactic receiver hint (base name of the object expression, ""
 *                   if none, enclosing class name for function-definition rows)
 *   6. moduleHint - module hint: external module name, "yt_dlp.utils" for the
 *                   internal Popen wrapper, or the dotted python module path of the
 *                   candidate (variable intentionally named moduleHint; `module` is
 *                   not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the command, -1 if
 *                   not applicable
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath(); AstNode.getFile()
 *                    does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast" (syntax-level match)
 *
 * Shell / non-shell distinction: "shell_true" rows mark call sites that interpret
 * the command argument through a shell. All three shell=True sites in this snapshot
 * take string commands; every other execution site passes an argv list without a
 * shell. The "arg" rows of the internal Popen wrapper cover both Popen(...) and
 * Popen.run(...) forms.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for internal
 *  candidates). Files that are not on an import path (top-level scripts like
 *  pyinst.py, devscripts/*.py, test/*.py) have no dotted module name; their file
 *  base name is used instead. */
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
/* Sink family 1: resolved external process-execution API calls        */
/* ------------------------------------------------------------------ */

/**
 * External process/command execution APIs with the 0-based positional argument index
 * that carries the command string / argv. os.spawn* takes the command at index 1
 * (index 0 is the mode). Only subprocess.call (yt_dlp/postprocessor/exec.py:31) and
 * subprocess.run (devscripts) are exercised in this snapshot; the remaining members
 * are the standard CWE-78 sink set and are kept for exhaustiveness. os.* members do
 * not occur anywhere in this tree.
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
/* Sink family 2: syntax-level external process-execution call shapes  */
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
/* Sink families 3+4: the internal yt_dlp.utils.Popen wrapper          */
/* ------------------------------------------------------------------ */

/**
 * yt_dlp re-exports Popen from yt_dlp.utils (class Popen(subprocess.Popen),
 * yt_dlp/utils/_utils.py:802; utils/__init__.py `from ._utils import *`). Modules
 * bind it with `from ..utils import Popen` / `from yt_dlp.utils import Popen` and
 * then call the bare name, so these shapes are matched both through API graphs
 * (alias-aware, "api") and syntactically ("ast"). Popen.run is a classmethod that
 * constructs cls(*args) and communicate()s - the command/argv is positional arg 0
 * for both Popen(...) and Popen.run(...).
 */
private predicate resolvedInternalPopenCall(API::CallNode cn, string callableName, int argIndex) {
  argIndex = 0 and
  callableName = "Popen" and
  cn = API::moduleImport("yt_dlp.utils").getMember("Popen").getACall()
  or
  argIndex = 0 and
  callableName = "run" and
  cn = API::moduleImport("yt_dlp.utils").getMember("Popen").getMember("run").getACall()
}

/** AST-only matches for the internal wrapper: bare `Popen(...)` and `Popen.run(...)`. */
private predicate syntacticInternalPopenCall(Call c, string callableName, int argIndex) {
  argIndex = 0 and
  callableName = "Popen" and
  c.getFunc().(Name).getId() = "Popen"
  or
  argIndex = 0 and
  callableName = "run" and
  c.getFunc().(Attribute).getName() = "run" and
  c.getFunc().(Attribute).getObject().(Name).getId() = "Popen"
}

/* ------------------------------------------------------------------ */
/* Sink family 5: shell=True call sites                                */
/* ------------------------------------------------------------------ */

/** Holds if c passes the keyword argument shell=True (any callee - includes the
 *  atexit.register(Popen, cmd, shell=True, ...) deferred-execution shape in update.py). */
private predicate shellTrueCall(Call c) {
  exists(Keyword k |
    k = c.getANamedArg().(Keyword) and
    k.getArg() = "shell" and
    k.getValue() instanceof True
  )
}

/* ------------------------------------------------------------------ */
/* Exec-site / wrapper / command-builder plumbing                      */
/* ------------------------------------------------------------------ */

/** Holds if c is any call site (resolved or syntactic shape) into a process-execution
 *  API, including the internal yt_dlp.utils.Popen wrapper. */
private predicate execCallSite(Call c) {
  exists(API::CallNode cn |
    (resolvedExecCall(cn, _, _, _) or resolvedInternalPopenCall(cn, _, _)) and
    c = astCallOf(cn)
  )
  or
  syntacticExecCall(c, _, _, _)
  or
  syntacticInternalPopenCall(c, _, _)
}

/**
 * Functions in this codebase whose body directly calls a process-execution API
 * (external or internal Popen wrapper). The Popen.run classmethod itself is
 * special-cased: it dispatches through the dynamic `cls(*args, **kwargs)` call,
 * which is not a syntactic exec site, but every Popen.run(...) call site is
 * captured by families 3/4.
 */
private predicate internalExecWrapper(Function f) {
  exists(Call c |
    execCallSite(c) and
    c.getScope().(Function) = f
  )
  or
  f.getName() = "run" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "Popen"
}

/**
 * Functions that build command strings/argv consumed by an exec wrapper: either a
 * direct exec wrapper itself, or a function called (by bare or attribute name, in the
 * same file) from within a direct exec wrapper. The second arm captures helpers such
 * as ExecPP.parse_cmd (yt_dlp/postprocessor/exec.py:14), which %-formats and
 * .replace()s the command string that ExecPP.run then passes to subprocess.call.
 */
private predicate commandBuilder(Function f) {
  internalExecWrapper(f)
  or
  exists(Function g, Call c |
    internalExecWrapper(g) and
    c.getScope().(Function) = g and
    (c.getFunc().(Name).getId() = f.getName() or c.getFunc().(Attribute).getName() = f.getName()) and
    f.getLocation().getFile() = g.getLocation().getFile()
  )
}

/**
 * Dynamic command construction nodes:
 *   - a '%' string-formatting expression (BinaryExpr with a Mod operator and a literal
 *     format string on the left) passed directly as a positional argument of an
 *     execution call site, or located inside a command-builder function
 *     (ExecPP.parse_cmd's `escape_outtmpl(tmpl) % tmpl_dict` idiom), or
 *   - a `.format(...)` template call inside a command-builder function, or
 *   - a `.replace(...)` call inside a command-builder function (the '{}' placeholder
 *     substitution idiom: ExecPP.parse_cmd exec.py:24 and the --netrc-cmd
 *     cmd.replace('{}', netrc_machine) in extractor/common.py:1309).
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
    commandBuilder(f) and
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
    commandBuilder(f) and
    c.getFunc().(Attribute).getName() in ["format", "replace"] and
    c.getScope().(Function) = f and
    n = c
  )
}

/**
 * Command argv construction nodes: list concatenation (BinaryExpr with an Add operator
 * and a List operand) passed directly as a positional argument of an execution call
 * site, or located inside a direct exec wrapper function. Covers shapes such as
 * `[exe] + args` (utils/_utils.py:2070) and `['bidiv'] + width_args` (YoutubeDL.py:662).
 * Augmented assignments (`cmd += [...]`, downloader/external.py _make_cmd) are not
 * represented by BinaryExpr and are documented as uncovered.
 */
private predicate cmdBuildNode(AstNode n) {
  exists(BinaryExpr b, Call c |
    execCallSite(c) and
    b.getOp() instanceof Add and
    (b.getLeft() instanceof List or b.getRight() instanceof List) and
    b = c.getAPositionalArg() and
    n = b
  )
  or
  exists(BinaryExpr b, Function f |
    internalExecWrapper(f) and
    b.getOp() instanceof Add and
    (b.getLeft() instanceof List or b.getRight() instanceof List) and
    b.getScope().(Function) = f and
    not exists(Call c |
      execCallSite(c) and
      b = c.getAPositionalArg()
    ) and
    n = b
  )
}

/**
 * Indirect execution: a call that passes the internal Popen wrapper as a positional
 * argument without invoking it here. The only in-tree shape is
 * atexit.register(Popen, cmd, shell=True, ...) (yt_dlp/update.py:376) - the process
 * is spawned later with the given command. The call site itself also carries a
 * shell=True row from family 5.
 */
private predicate indirectExecTransfer(Call c, int argIndex) {
  exists(int i |
    c.getPositionalArg(i).(Name).getId() = "Popen" and
    argIndex = i
  ) and
  not execCallSite(c)
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: resolved external process-execution API calls (API graphs, alias-aware) */
  exists(API::CallNode cn |
    resolvedExecCall(cn, moduleHint, callableName, argIndex) and
    node = astCallOf(cn) and
    flowKind = "arg" and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 2: syntax-level external process-execution call shapes */
  exists(Call c |
    syntacticExecCall(c, moduleHint, callableName, argIndex) and
    node = c and
    flowKind = "arg" and
    receiver = "" and
    matchKind = "ast"
  )
  or
  /* family 3: resolved internal yt_dlp.utils.Popen wrapper calls (API graphs) */
  exists(API::CallNode cn |
    resolvedInternalPopenCall(cn, callableName, argIndex) and
    node = astCallOf(cn) and
    flowKind = "arg" and
    receiver = "" and
    moduleHint = "yt_dlp.utils" and
    matchKind = "api"
  )
  or
  /* family 4: syntax-level internal Popen wrapper calls
     (bare Popen(...) / Popen.run(...) from-imported from yt_dlp.utils) */
  exists(Call c |
    syntacticInternalPopenCall(c, callableName, argIndex) and
    node = c and
    flowKind = "arg" and
    receiver = "" and
    moduleHint = "yt_dlp.utils" and
    matchKind = "ast"
  )
  or
  /* family 5: call sites using shell=True */
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
  /* family 6a: internal functions that directly run OS commands */
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
  /* family 6b: the internal Popen wrapper class itself
     (class Popen(subprocess.Popen), yt_dlp/utils/_utils.py:802) */
  exists(Class cl |
    cl.getName() = "Popen" and
    node = cl and
    flowKind = "internal_exec_wrapper" and
    callableName = "Popen" and
    argIndex = -1 and
    matchKind = "ast" and
    receiver = "" and
    moduleHint = moduleHintOf(cl)
  )
  or
  /* family 7: dynamic command construction
     ('%'-formatting / .format() / .replace() string surgery) */
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
      n.(Call).getFunc().(Attribute).getName() = "replace" and
      callableName = "replace" and
      receiver = receiverHint(n.(Call).getFunc().(Attribute))
      or
      not n instanceof Call and
      callableName = "percent_format" and
      receiver = ""
    )
  )
  or
  /* family 8: command argv building (list concatenation) */
  exists(AstNode n |
    cmdBuildNode(n) and
    node = n and
    flowKind = "cmd_build" and
    argIndex = -1 and
    matchKind = "ast" and
    callableName = "list_concat" and
    receiver = "" and
    moduleHint = moduleHintOf(n)
  )
  or
  /* family 9: indirect execution - Popen passed as a callback argument */
  exists(Call c |
    indirectExecTransfer(c, argIndex) and
    node = c and
    flowKind = "indirect_exec" and
    callableName = calledName(c) and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
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
  matchKind as match_kind
