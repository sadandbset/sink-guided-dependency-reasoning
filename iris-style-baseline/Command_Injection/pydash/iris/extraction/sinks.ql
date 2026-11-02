/**
 * @name pydash CWE-78 sink candidate extraction
 * @description Extract sink candidate AST nodes (process/command execution)
 *   for the pydash repository, Pass 2 / CWE-78 (Command Injection).
 *   Sink families derived from real source inspection:
 *     1. resolved process-execution API calls (subprocess.*, os.system,
 *        os.popen, os.exec* or spawn*, pexpect.*, invoke.run via import bindings)
 *     2. syntactic local-alias calls of invoke.run (run / _run bound through
 *        `from invoke import run as _run` and `partial(_run, pty=True)` in
 *        tasks.py; the invoke package is not part of the CodeQL database,
 *        so these calls cannot be resolved as real API calls)
 *     3. syntactic invoke Context method calls (ctx.run / ctx.sudo)
 *   Arg index gives the position of the command/argument parameter that
 *   carries attacker-controlled data.
 *   This is a raw BQRS extraction query for `codeql query run` +
 *   `codeql bqrs decode`. No @kind metadata is declared: multi-column
 *   candidate tables are neither `@kind problem` queries nor SARIF alerts.
 * @id iris/pydash-cwe78/extraction/sinks
 */

import python
import semmle.python.ApiGraphs

/**
 * Test-path filter (Augur candidate strategy: exclude tests and fixtures).
 *
 * `string` is an infinite-domain QL type. This predicate is intended to be
 * called only with a path that has already been obtained from a CodeQL File
 * location, so explicitly declare p as an input binding set.
 */
bindingset[p]
predicate isTestPath(string p) {
  p.matches("%tests%")
}

/**
 * Resolved process-execution API calls, bound through real import
 * statements via the API graph. These are the standard Pass 2 baseline
 * families (not rules targeting any known vulnerability location); none of
 * them occur in the current pydash sources except the invoke family.
 *
 * The trailing column is the index of the command/argument parameter.
 */
predicate resolvedProcessExecCall(
  API::CallNode c, string moduleHint, string callableName, int argIdx
) {
  // subprocess family: first positional argument is the command.
  c = API::moduleImport("subprocess").getMember("run").getACall() and
  moduleHint = "subprocess" and
  callableName = "run" and
  argIdx = 0

  or

  c = API::moduleImport("subprocess").getMember("Popen").getACall() and
  moduleHint = "subprocess" and
  callableName = "Popen" and
  argIdx = 0

  or

  c = API::moduleImport("subprocess").getMember("call").getACall() and
  moduleHint = "subprocess" and
  callableName = "call" and
  argIdx = 0

  or

  c = API::moduleImport("subprocess").getMember("check_call").getACall() and
  moduleHint = "subprocess" and
  callableName = "check_call" and
  argIdx = 0

  or

  c = API::moduleImport("subprocess").getMember("check_output").getACall() and
  moduleHint = "subprocess" and
  callableName = "check_output" and
  argIdx = 0

  or

  c = API::moduleImport("subprocess").getMember("getoutput").getACall() and
  moduleHint = "subprocess" and
  callableName = "getoutput" and
  argIdx = 0

  or

  c = API::moduleImport("subprocess").getMember("getstatusoutput").getACall() and
  moduleHint = "subprocess" and
  callableName = "getstatusoutput" and
  argIdx = 0

  or

  // os family: os.system/os.popen take the command at index 0;
  // exec*/spawn* take the executable at index 0 and the argument list at 1.
  c = API::moduleImport("os").getMember("system").getACall() and
  moduleHint = "os" and
  callableName = "system" and
  argIdx = 0

  or

  c = API::moduleImport("os").getMember("popen").getACall() and
  moduleHint = "os" and
  callableName = "popen" and
  argIdx = 0

  or

  c = API::moduleImport("os").getMember("execv").getACall() and
  moduleHint = "os" and
  callableName = "execv" and
  argIdx = 1

  or

  c = API::moduleImport("os").getMember("execve").getACall() and
  moduleHint = "os" and
  callableName = "execve" and
  argIdx = 1

  or

  c = API::moduleImport("os").getMember("execvp").getACall() and
  moduleHint = "os" and
  callableName = "execvp" and
  argIdx = 1

  or

  c = API::moduleImport("os").getMember("execvpe").getACall() and
  moduleHint = "os" and
  callableName = "execvpe" and
  argIdx = 1

  or

  c = API::moduleImport("os").getMember("spawnv").getACall() and
  moduleHint = "os" and
  callableName = "spawnv" and
  argIdx = 1

  or

  c = API::moduleImport("os").getMember("spawnvp").getACall() and
  moduleHint = "os" and
  callableName = "spawnvp" and
  argIdx = 1

  or

  // pexpect family: command is the first positional argument.
  c = API::moduleImport("pexpect").getMember("spawn").getACall() and
  moduleHint = "pexpect" and
  callableName = "spawn" and
  argIdx = 0

  or

  c = API::moduleImport("pexpect").getMember("run").getACall() and
  moduleHint = "pexpect" and
  callableName = "run" and
  argIdx = 0

  or

  // invoke family, resolved import form (`import invoke` + invoke.run(...)).
  c = API::moduleImport("invoke").getMember("run").getACall() and
  moduleHint = "invoke" and
  callableName = "run" and
  argIdx = 0
}

/**
 * Syntactic local-alias calls of invoke.run.
 *
 * In tasks.py, `run` is bound via
 * `from invoke import ... run as _run`
 * and
 * `run = partial(_run, pty=True)`.
 *
 * The invoke package is not part of the CodeQL database and `partial`
 * aliasing is not tracked by the API graph, so these call sites are matched
 * syntactically on the local callee name.
 */
predicate localAliasExecCall(Call c, string callableName) {
  exists(Name n |
    c.getFunc() = n and
    (
      n.getId() = "run"
      or
      n.getId() = "_run"
    ) and
    callableName = n.getId()
  )
}

/**
 * Syntactic invoke Context method calls (ctx.run / ctx.sudo), matched on the
 * attribute name with a qualifier named `ctx` (the invoke convention).
 *
 * No such calls currently need to exist in the repository for this family
 * to be useful as a recall-oriented candidate rule.
 */
predicate invokeContextExecCall(Call c, string callableName) {
  exists(Attribute a, Name q |
    c.getFunc() = a and
    (
      a.getName() = "run"
      or
      a.getName() = "sudo"
    ) and
    a.getObject() = q and
    q.getId() = "ctx" and
    callableName = a.getName()
  )
}

/**
 * Unified sink candidate relation.
 *
 * matchKind distinguishes syntactic AST matches from resolved API calls:
 *
 *   - "resolved_api":
 *       call resolved through import bindings via the API graph
 *
 *   - "syntax":
 *       AST callee-name match only (local alias / context method)
 */
predicate sinkCandidate(
  string nodeDesc,
  string callableName,
  string flowKind,
  string receiver,
  string moduleHint,
  int argIdx,
  string filePath,
  int line,
  string matchKind
) {
  // ------------------------------------------------------------------
  // Family 1: resolved process-execution API calls.
  // ------------------------------------------------------------------
  exists(API::CallNode c |
    resolvedProcessExecCall(c, moduleHint, callableName, argIdx) and

    filePath = c.getLocation().getFile().getAbsolutePath() and
    not isTestPath(filePath) and

    line = c.getLocation().getStartLine() and

    flowKind = "arg" and
    receiver = "" and
    matchKind = "resolved_api" and

    nodeDesc = "Call:" + callableName
  )

  or

  // ------------------------------------------------------------------
  // Family 2: local-alias invoke.run calls (tasks.py run(...)).
  // ------------------------------------------------------------------
  exists(Call c |
    localAliasExecCall(c, callableName) and

    filePath = c.getLocation().getFile().getAbsolutePath() and
    not isTestPath(filePath) and

    line = c.getLocation().getStartLine() and

    flowKind = "arg" and
    receiver = "" and
    moduleHint = "local" and
    argIdx = 0 and
    matchKind = "syntax" and

    nodeDesc = "Call:" + callableName
  )

  or

  // ------------------------------------------------------------------
  // Family 3: invoke Context method calls (ctx.run / ctx.sudo).
  // ------------------------------------------------------------------
  exists(Call c |
    invokeContextExecCall(c, callableName) and

    filePath = c.getLocation().getFile().getAbsolutePath() and
    not isTestPath(filePath) and

    line = c.getLocation().getStartLine() and

    flowKind = "arg" and
    receiver = "ctx" and
    moduleHint = "invoke" and
    argIdx = 0 and
    matchKind = "syntax" and

    nodeDesc = "Call:" + callableName
  )
}

from
  string nodeDesc,
  string callableName,
  string flowKind,
  string receiver,
  string moduleHint,
  int argIdx,
  string filePath,
  int line,
  string matchKind
where
  sinkCandidate(
    nodeDesc,
    callableName,
    flowKind,
    receiver,
    moduleHint,
    argIdx,
    filePath,
    line,
    matchKind
  )
select
  nodeDesc as node,
  "sink_candidate" as candidate_kind,
  callableName as callable,
  flowKind as flow_kind,
  receiver as receiver_col,
  moduleHint as module_hint,
  argIdx as arg_index,
  filePath as file,
  line as line_col,
  matchKind as match_kind