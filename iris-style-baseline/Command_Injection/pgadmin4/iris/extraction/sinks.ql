/**
 * @name pgadmin4 CWE-78 sink candidate extraction
 * @description Extract command/process execution sink candidates from the pgadmin4
 *   CodeQL database (snapshot 61fa8b1): subprocess / os execution API calls (resolved
 *   via API graphs and by AST shape, including the eventlet.green subprocess import in
 *   the psql tool and the bare from-imported Popen names of the background-process
 *   pipeline), call sites using shell=True, dynamic command construction (.format()
 *   template calls and '%' string formatting, either passed directly as the command
 *   argument or located inside an executing function), the winpty PtyProcess.spawn
 *   terminal spawn, internal wrapper functions that directly run OS commands
 *   (BatchProcess.start, process_executor.execute, PasswordExec.get,
 *   get_master_password_from_master_hook, set_binary_path, validate_binary_path,
 *   create_pty_terminal, windows_platform), and the internal execution boundaries that
 *   carry command data toward the OS (BatchProcess and PasswordExec construction,
 *   get_master_password_from_master_hook calls). Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database analyze).
 *   This is a plain multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/pgadmin4/extraction/sinks
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
 *   4. flow_kind  - "arg" (command argument position of a process-execution API),
 *                   "shell_true" (call site passing shell=True - shell string
 *                   interpretation rather than argv-list interpretation),
 *                   "cmd_format" (dynamic command string construction),
 *                   "internal_exec_wrapper" (function that directly executes OS
 *                   commands or spawns the pty process),
 *                   "exec_boundary" (internal call that carries command data toward
 *                   process execution: BatchProcess / PasswordExec construction,
 *                   master-password hook invocation, winpty spawn)
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
 * command argument through a shell (passexec.py:38 and master_password.py:140 pass the
 * literal keyword shell=True). process_executor.py:324 sets the shell flag through a
 * kwargs dict ('kwargs['shell'] = True if _IS_WIN else False'), which is not a literal
 * keyword argument and is therefore documented in detection.json instead of producing a
 * shell_true row. "cmd_format" rows mark dynamic command construction: the
 * '"{0}" --version'.format(...) probes passed directly to subprocess.getoutput and the
 * r'"{0}" "{1}" 2>>&1'.format(...) shell write inside the windows_platform pty wrapper.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for internal
 *  candidates). Top-level scripts that are not on an import path (pgAdmin4.py,
 *  setup.py) have no dotted module name; their file base name is used instead. */
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

/** Holds if n sits in a file excluded from candidate extraction: the web/regression
 *  feature-test harness, any per-module tests/ directory, or the repo-root tools/
 *  dev scripts. Both path separators are matched. */
predicate excludedLocation(AstNode n) {
  exists(string p |
    p = n.getLocation().getFile().getAbsolutePath() and
    (
      p.matches("%/regression/%") or
      p.matches("%\\regression\\%") or
      p.matches("%/tests/%") or
      p.matches("%\\tests\\%") or
      p.matches("%\\pgadmin4_vuln\\tools\\%") or
      p.matches("%/pgadmin4_vuln/tools/%")
    )
  )
}

/* ------------------------------------------------------------------ */
/* Sink family 1: resolved process-execution API calls (API graphs)    */
/* ------------------------------------------------------------------ */

/**
 * Process/command execution APIs with the 0-based positional argument index that carries
 * the command string / argv. os.spawn* takes the command at index 1 (index 0 is the mode).
 * In this snapshot the exercised members are subprocess.run (passexec), subprocess.Popen
 * (master_password), subprocess.getoutput (utils/misc version probes) and os.popen
 * (generate_keywords dev script); the remaining members are the standard CWE-78 sink
 * set and are kept for exhaustiveness.
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
 * member - this also catches 'from eventlet.green import subprocess' usage in the psql
 * tool, whose module prefix is still the name 'subprocess' - plus bare distinctive
 * from-imported names (Popen in the bgprocess pipeline, system, popen, getoutput, ...).
 * moduleHint is "<unresolved>" for bare names because the defining module cannot be
 * confirmed syntactically. The bare names 'call' and 'run' are too collision-prone and
 * are deliberately not matched (documented in detection.json: the only affected site is
 * the javascript_bundler's 'from subprocess import call').
 */
private predicate syntacticExecCall(Call c, string moduleHint, string member, int argIndex) {
  execApiArgIndex(moduleHint, member, argIndex) and
  c.getFunc().(Attribute).getName() = member and
  c.getFunc().(Attribute).getObject().(Name).getId() = moduleHint
  or
  member in ["Popen", "system", "popen", "getoutput", "getstatusoutput",
             "check_output", "check_call"] and
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
/* Sink family 4: pty / internal execution boundaries                  */
/* ------------------------------------------------------------------ */

/**
 * Internal execution boundary calls (AST shapes):
 *   - BatchProcess(...) construction: the entry point of the backup/restore/
 *     import_export/maintenance/cloud background-process pipeline (cmd + args travel
 *     through the DB store into process_executor's Popen),
 *   - PasswordExec(...) construction: wraps the per-server passexec_cmd shell command,
 *   - get_master_password_from_master_hook(...): hands the MASTER_PASSWORD_HOOK-derived
 *     command to subprocess.Popen(shell=True),
 *   - PtyProcess.spawn(...): winpty terminal process spawn in the psql tool.
 */
private predicate execBoundaryCall(Call c, string moduleHint, string callableName, int argIndex) {
  (
    moduleHint = "pgadmin.misc.bgprocess.processes" and
    callableName = "BatchProcess" and
    argIndex = -1 and
    c.getFunc().(Name).getId() = "BatchProcess"
  )
  or
  (
    moduleHint = "pgadmin.utils.passexec" and
    callableName = "PasswordExec" and
    argIndex = -1 and
    c.getFunc().(Name).getId() = "PasswordExec"
  )
  or
  (
    moduleHint = "pgadmin.utils.master_password" and
    callableName = "get_master_password_from_master_hook" and
    argIndex = 0 and
    (
      c.getFunc().(Name).getId() = "get_master_password_from_master_hook"
      or
      c.getFunc().(Attribute).getName() = "get_master_password_from_master_hook"
    )
  )
  or
  (
    moduleHint = "winpty" and
    callableName = "spawn" and
    argIndex = 0 and
    c.getFunc().(Attribute).getName() = "spawn" and
    c.getFunc().(Attribute).getObject().(Name).getId() = "PtyProcess"
  )
}

/* ------------------------------------------------------------------ */
/* Sink families 5+6: internal wrappers and command formatting         */
/* ------------------------------------------------------------------ */

/** Holds if c is the winpty pty spawn boundary (PtyProcess.spawn(...)). */
private predicate ptySpawnCall(Call c) {
  execBoundaryCall(c, "winpty", "spawn", 0)
}

/** Holds if c is any call site (resolved or syntactic shape) into a process-execution
 *  API, or the pty/winpty spawn boundary. */
private predicate execCallSite(Call c) {
  exists(API::CallNode cn |
    resolvedExecCall(cn, _, _, _) and
    c = astCallOf(cn)
  )
  or
  syntacticExecCall(c, _, _, _)
  or
  ptySpawnCall(c)
}

/** Functions in this codebase whose body directly calls a process-execution API or the
 *  pty spawn (BatchProcess.start / get_process_output, process_executor.execute,
 *  PasswordExec.get, get_master_password_from_master_hook, set_binary_path,
 *  validate_binary_path, create_pty_terminal, windows_platform, ...). */
private predicate internalExecWrapper(Function f) {
  exists(Call c |
    execCallSite(c) and
    c.getScope().(Function) = f
  )
}

/**
 * Dynamic command construction nodes:
 *   - a `.format(...)` template call or a '%' string-formatting expression (BinaryExpr
 *     with a Mod operator and a literal format string on the left) passed directly as a
 *     positional argument of an execution call site (the '"{0}" --version'.format(...)
 *     subprocess.getoutput probes in utils/__init__.py:375 and misc/__init__.py:274), or
 *   - a '%' string-formatting expression with a literal format string, or a `.format(...)`
 *     call with a literal receiver, located inside a function that directly executes OS
 *     commands or spawns the pty process (e.g. the r'"{0}" "{1}" 2>>&1'.format(...) shell
 *     write inside windows_platform at psql/__init__.py:237).
 */
private predicate cmdFormatNode(AstNode n) {
  exists(Call fmt, Call c |
    execCallSite(c) and
    fmt.getFunc().(Attribute).getName() = "format" and
    fmt = c.getAPositionalArg() and
    n = fmt
  )
  or
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
  exists(Call fmt, Function f |
    internalExecWrapper(f) and
    fmt.getFunc().(Attribute).getName() = "format" and
    fmt.getFunc().(Attribute).getObject() instanceof StringLiteral and
    fmt.getScope().(Function) = f and
    not exists(Call c |
      execCallSite(c) and
      fmt = c.getAPositionalArg()
    ) and
    n = fmt
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
    not excludedLocation(astCallOf(cn)) and
    node = astCallOf(cn) and
    flowKind = "arg" and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 2: syntax-level process-execution call shapes (eventlet.green subprocess,
     from-imported bare Popen, os.popen in dev scripts, ...) */
  exists(Call c |
    syntacticExecCall(c, moduleHint, callableName, argIndex) and
    not excludedLocation(c) and
    node = c and
    flowKind = "arg" and
    receiver = "" and
    matchKind = "ast"
  )
  or
  /* family 3: call sites using shell=True */
  exists(Call c |
    shellTrueCall(c) and
    not excludedLocation(c) and
    node = c and
    flowKind = "shell_true" and
    callableName = calledName(c) and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    argIndex = -1 and
    matchKind = "ast"
  )
  or
  /* family 4: internal execution boundary calls (BatchProcess / PasswordExec
     construction, master-password hook invocation, winpty spawn) */
  exists(Call c |
    execBoundaryCall(c, moduleHint, callableName, argIndex) and
    not excludedLocation(c) and
    node = c and
    flowKind = "exec_boundary" and
    matchKind = "ast" and
    (
      callableName = "spawn" and
      receiver = "PtyProcess"
      or
      callableName != "spawn" and
      receiver = receiverHintOfCall(c)
    )
  )
  or
  /* family 5: internal functions that directly run OS commands or spawn the pty */
  exists(Function f |
    internalExecWrapper(f) and
    not excludedLocation(f) and
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
  /* family 6: dynamic command construction ('%'-formatting / .format() templates) */
  exists(AstNode n |
    cmdFormatNode(n) and
    not excludedLocation(n) and
    node = n and
    flowKind = "cmd_format" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(n) and
    (
      n.(Call).getFunc().(Attribute).getName() = "format" and
      callableName = "format" and
      (
        n.(Call).getFunc().(Attribute).getObject() instanceof StringLiteral and
        receiver = "<literal>"
        or
        not n.(Call).getFunc().(Attribute).getObject() instanceof StringLiteral and
        receiver = receiverHint(n.(Call).getFunc().(Attribute))
      )
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
