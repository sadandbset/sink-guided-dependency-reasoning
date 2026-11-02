
/**
 * @name Abilian-devtools sink candidate extraction (Pass 2 / CWE-78)
 * @description Extract command-execution call candidates and their
 *              enclosing wrapper functions from Abilian-devtools ("adt").
 *              Only subprocess has import/call evidence in this repo
 *              (subprocess.Popen in abilian/devtools/main.py); os and
 *              asyncio families are kept for Pass 2 coverage consistency
 *              and will simply yield no rows.
 * @kind table
 * @id py/abilian-devtools/extraction/sinks
 */

import python

/**
 * Command execution API families.
 * These are candidate APIs, not confirmed vulnerabilities.
 */
predicate isProcessApi(string moduleName, string callableName) {
  (
    moduleName = "subprocess" and
    callableName in [
      "run",
      "Popen",
      "call",
      "check_call",
      "check_output",
      "getoutput",
      "getstatusoutput"
    ]
  )
  or
  (
    moduleName = "os" and
    callableName in [
      "system",
      "popen"
    ]
  )
  or
  (
    moduleName = "asyncio" and
    callableName in [
      "create_subprocess_exec",
      "create_subprocess_shell"
    ]
  )
}

/**
 * Detect calls such as:
 *
 * subprocess.Popen(...)
 * os.system(...)
 * os.popen(...)
 * asyncio.create_subprocess_shell(...)
 *
 * Also collects some unqualified function calls, such as
 * Popen(...) or system(...), as candidates for review.
 *
 * This is syntactic matching. Unqualified calls must be
 * checked against their real imports during LLM labeling.
 */
predicate isProcessCall(
  Call c,
  string moduleName,
  string callableName
) {
  // Module-qualified call.
  exists(Attribute attr, Name receiver |
    attr = c.getFunc() and
    receiver = attr.getObject() and
    moduleName = receiver.getId() and
    callableName = attr.getName() and
    isProcessApi(moduleName, callableName)
  )
  or
  // Potential directly imported process API.
  exists(Name callee |
    callee = c.getFunc() and
    callableName = callee.getId() and
    (
      (
        moduleName = "subprocess" and
        callableName in [
          "Popen",
          "check_call",
          "check_output",
          "getoutput",
          "getstatusoutput"
        ]
      )
      or
      (
        moduleName = "os" and
        callableName in [
          "system",
          "popen"
        ]
      )
      or
      (
        moduleName = "asyncio" and
        callableName in [
          "create_subprocess_exec",
          "create_subprocess_shell"
        ]
      )
    )
  )
}

/**
 * Exclude test directories (defensive: this repo has no tests/ directory).
 */
predicate inProductionCode(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    not path.matches("tests/%") and
    not path.matches("%/tests/%")
  )
}

/**
 * Receiver information for project-internal functions.
 */
string receiverOf(Function f) {
  result = f.getScope().(Class).getName()
  or
  (
    not f.getScope() instanceof Class and
    result = ""
  )
}

/**
 * Module name for project-internal functions.
 */
string moduleOf(Function f) {
  result = f.getEnclosingModule().getName()
  or
  (
    not exists(f.getEnclosingModule().getName()) and
    result = f.getLocation().getFile().getBaseName()
  )
}

/*
 * Extract direct command execution calls and wrapper functions.
 *
 * Output fields:
 * 1. AST node
 * 2. candidate type
 * 3. callable name
 * 4. flow kind
 * 5. receiver hint
 * 6. module hint
 * 7. argument index
 * 8. file
 * 9. line
 */
from
  AstNode node,
  string callableName,
  string flowKind,
  string receiverHint,
  string moduleHint,
  int argIndex
where
  inProductionCode(node) and
  (
    // Case 1: Direct process-execution API call.
    //         In this repo: subprocess.Popen(args) in abilian/devtools/main.py.
    exists(Call c, string m, string name |
      isProcessCall(c, m, name) and
      node = c and
      callableName = name and
      flowKind = "argument" and
      receiverHint = m and
      moduleHint = m and
      argIndex = 0
    )
    or
    // Case 2: Project-internal function wrapping a process API.
    //         In this repo: run(cmd) wraps subprocess.Popen; the `cmd`
    //         parameter (index 0) carries the caller-built command string
    //         (f-string interpolation of CLI arguments in check()).
    //         argIndex is -1 here; the LLM labeling step identifies which
    //         parameter feeds the wrapped process call.
    exists(Function f, Call c, string m, string name |
      isProcessCall(c, m, name) and
      c.getScope() = f and
      node = f and
      callableName = f.getName() and
      flowKind = "param" and
      receiverHint = receiverOf(f) and
      moduleHint = moduleOf(f) and
      argIndex = -1
    )
  )
select
  node,
  "sink_candidate",
  callableName,
  flowKind,
  receiverHint,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getRelativePath(),
  node.getLocation().getStartLine()
