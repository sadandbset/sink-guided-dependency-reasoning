/**
 * @name tensorflow CWE-78 sink candidate extraction
 * @description Extract command/process execution sink candidates from the tensorflow
 *   CodeQL database (snapshot 349172cf, tensorflow_vuln tree): subprocess / os execution
 *   API calls (resolved via API graphs - including the `import subprocess as _subprocess`
 *   alias of lite/python/convert.py - and by AST shape with os/_os, subprocess/_subprocess
 *   module prefixes), call sites passing shell=True (notably the runtime TFLite converter
 *   path convert.py:_run_toco_binary), explicit shell argument lists
 *   (["bash", "-c", cmd] / ["cmd", "/c", cmd]), command-template formatting
 *   (str.format, f-strings and string-literal %-formatting) inside executing functions,
 *   and internal wrapper functions that directly run OS commands (_run_toco_binary,
 *   _get_num_nvidia_gpus, the flatc schema-upgrade helpers and the tensorflow/tools
 *   build/CI/doc/packaging mains).
 *   Shell execution and non-shell argument-list execution are distinguished by
 *   flow_kind: "arg" = argument-list exec (command string/argv at the given arg index),
 *   "shell_true" = shell=True string command, "shell_arg_list" = explicit shell wrapper
 *   list (command string at list position 2), "cmd_format" = command template formatting
 *   inside an executing function, "internal_exec_wrapper" = function that directly runs
 *   OS commands.
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain multi-column select query
 *   on purpose: @kind problem is the wrong shape for candidate tables and @kind table is
 *   not assumed to exist.
 * @id iris/tensorflow/extraction/sinks
 * @tags command-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or attribute name)
 *   4. flow_kind  - "arg" (argument-list execution; command string/argv at arg_index),
 *                   "shell_true" (call site passes shell=True), "shell_arg_list"
 *                   (["bash", "-c", cmd] style list; command string at arg_index),
 *                   "cmd_format" (command template formatting inside an executing
 *                   function), "internal_exec_wrapper" (function that directly runs
 *                   OS commands)
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
 * Note: this file defines no QL classes (only predicates), avoids assigning API::Node
 * values to DataFlow::Node variables, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced a row).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for internal candidates). */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
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
string calledNameOf(Call c) {
  result = c.getFunc().(Name).getId()
  or
  result = c.getFunc().(Attribute).getName()
  or
  not c.getFunc() instanceof Name and
  not c.getFunc() instanceof Attribute and
  result = "<expr>"
}

/**
 * Holds if n sits inside a test file or test harness: any path under a tests/, test/ or
 * testing/ directory (bazel test infra and tflite test harnesses), conftest.py, or a
 * *_test.py / *_test_base.py basename.
 */
predicate isTestLocation(AstNode n) {
  n.getLocation().getFile().getAbsolutePath().matches("%/tests/%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\tests\\%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%/test/%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\test\\%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%/testing/%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\testing\\%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%/conftest.py")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\conftest.py")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%_test.py")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\_test.py")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%_test_base.py")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\_test_base.py")
}

/* ------------------------------------------------------------------ */
/* Sink family 1: resolved process-execution API calls (API graphs)    */
/* ------------------------------------------------------------------ */

/**
 * Process/command execution APIs with the 0-based positional argument index that carries
 * the command string / argv. os.spawn* takes the command at index 1 (index 0 is the mode).
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

/** os module aliases observed in this tree (import os / import os as _os). */
private predicate osModuleName(string name) { name in ["os", "_os"] }

/** subprocess module aliases observed in this tree (import subprocess / as _subprocess). */
private predicate subprocessModuleName(string name) { name in ["subprocess", "_subprocess"] }

/**
 * AST-only matches: syntactic `<module>.<member>(...)` shapes with a known execution-API
 * member and a module prefix from the observed alias sets, plus bare from-imported names.
 * No `from subprocess import ...` / `from os import <exec>` form exists in this tree, so
 * bare names are matched only for the distinctive members (system, popen, getoutput,
 * getstatusoutput); bare run/call/Popen/check_call/check_output are too collision-prone
 * and are excluded (documented in detection.json). moduleHint is "<unresolved>" for bare
 * names because the defining module cannot be confirmed syntactically.
 */
private predicate syntacticExecCall(Call c, string moduleHint, string member, int argIndex) {
  (
    execApiArgIndex("subprocess", member, argIndex) and
    subprocessModuleName(moduleHint) and
    c.getFunc().(Attribute).getName() = member and
    c.getFunc().(Attribute).getObject().(Name).getId() = moduleHint
    or
    execApiArgIndex("os", member, argIndex) and
    osModuleName(moduleHint) and
    c.getFunc().(Attribute).getName() = member and
    c.getFunc().(Attribute).getObject().(Name).getId() = moduleHint
  )
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
/* Sink family 4: explicit shell argument lists                        */
/* ------------------------------------------------------------------ */

/** Shell program names used as the first element of explicit shell wrapper lists. */
private predicate shellProgramName(string name) {
  name in ["bash", "/bin/bash", "/usr/bin/bash", "sh", "/bin/sh", "/usr/bin/sh", "cmd"]
}

/** Shell option elements that make the list an explicit shell invocation. */
private predicate shellOptionName(string name) { name in ["-c", "/c"] }

/**
 * Holds if lst is an explicit shell wrapper list `["bash", "-c", command]` /
 * `["cmd", "/c", command]` (also when built into a variable and then passed to an exec
 * API). The command string sits at list position 2. No such list exists in non-test
 * project source of this snapshot; the family is kept because it is the standard
 * CWE-78 shell-wrapper shape.
 */
private predicate shellArgList(List lst) {
  shellProgramName(lst.getElt(0).(StringLiteral).getS()) and
  shellOptionName(lst.getElt(1).(StringLiteral).getS())
}

/* ------------------------------------------------------------------ */
/* Sink families 5+6: internal wrappers and command formatting         */
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

/**
 * Functions (including methods) in this codebase whose body directly calls a
 * process-execution API or builds an explicit shell wrapper list. In this snapshot these
 * are, among others, lite/python/convert.py:_run_toco_binary (Popen with shell=True),
 * distribute/cluster_resolver/slurm_cluster_resolver.py:_get_num_nvidia_gpus
 * (check_output nvidia-smi), the lite/schema/upgrade_schema.py flatc helpers, and the
 * tensorflow/tools build/CI/doc/packaging mains.
 */
private predicate internalExecWrapper(Function f) {
  exists(Call c |
    execCallSite(c) and
    c.getScope().(Function) = f
  )
  or
  exists(List lst |
    shellArgList(lst) and
    lst.getScope().(Function) = f
  )
}

/** Holds if c is a logging call (logger.<level>(...) / print(...)). */
private predicate isLoggingCall(Call c) {
  c.getFunc().(Attribute).getName() in
    ["debug", "info", "warning", "warn", "error", "exception", "critical", "log",
     "fine", "trace"]
  or
  c.getFunc().(Name).getId() = "print"
}

/**
 * Command-template formatting inside functions that directly execute OS commands:
 * str.format(...) calls, f-string literals (Fstring) and string-literal %-formatting
 * (BinaryExpr whose operator is Mod with a StringLiteral left operand - this snapshot
 * is %-heavy, e.g. the tflite testing harnesses), excluding expressions whose direct
 * parent is a logging call (log-message formatting, not command building).
 */
private predicate cmdFormatExpr(Expr e) {
  (
    e.(Call).getFunc().(Attribute).getName() = "format"
    or
    e instanceof Fstring
    or
    e.(BinaryExpr).getOp() instanceof Mod and
    e.(BinaryExpr).getLeft() instanceof StringLiteral
  ) and
  exists(Function f |
    f = e.getScope().(Function) and
    internalExecWrapper(f)
  ) and
  not (e.getParent() instanceof Call and isLoggingCall(e.getParent().(Call)))
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: resolved process-execution API calls (API graphs, alias-aware:
     also matches the `import subprocess as _subprocess` Popen in convert.py) */
  exists(API::CallNode cn |
    resolvedExecCall(cn, moduleHint, callableName, argIndex) and
    node = astCallOf(cn) and
    flowKind = "arg" and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 2: syntax-level process-execution call shapes (subprocess/_subprocess,
     os/_os prefixes, distinctive bare names) */
  exists(Call c |
    syntacticExecCall(c, moduleHint, callableName, argIndex) and
    node = c and
    flowKind = "arg" and
    receiver = "" and
    matchKind = "ast"
  )
  or
  /* family 3: call sites using shell=True (string command through the shell) */
  exists(Call c |
    shellTrueCall(c) and
    node = c and
    flowKind = "shell_true" and
    callableName = calledNameOf(c) and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    argIndex = -1 and
    matchKind = "ast"
  )
  or
  /* family 4: explicit shell wrapper lists ["bash", "-c", command] (shell execution
     without shell=True; the command string sits at list position 2) */
  exists(List lst |
    shellArgList(lst) and
    node = lst and
    flowKind = "shell_arg_list" and
    callableName = lst.getElt(0).(StringLiteral).getS() and
    receiver = "" and
    moduleHint = moduleHintOf(lst) and
    argIndex = 2 and
    matchKind = "ast"
  )
  or
  /* family 5: internal functions (or methods) that directly run OS commands */
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
  /* family 6: command-template formatting inside executing functions */
  exists(Expr e |
    cmdFormatExpr(e) and
    node = e and
    flowKind = "cmd_format" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(e) and
    (
      e instanceof Call and
      callableName = "format" and
      receiver = receiverHintOfCall(e.(Call))
      or
      e instanceof Fstring and
      callableName = "fstring" and
      receiver = ""
      or
      e instanceof BinaryExpr and
      e.(BinaryExpr).getOp() instanceof Mod and
      callableName = "percent_format" and
      receiver = ""
    )
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  not isTestLocation(node)
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
