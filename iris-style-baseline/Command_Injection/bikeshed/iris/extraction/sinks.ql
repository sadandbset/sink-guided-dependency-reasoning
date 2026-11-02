
/**
 * @name BinderHub sink candidate extraction (Pass 2, CWE-78)
 * @description Extract command-execution and related API candidates
 *              from the BinderHub application package.
 * @kind problem
 * @id py/augur/binderhub/pass2-sinks
 * @problem.severity recommendation
 */

import python

/**
 * Restrict extraction to BinderHub production code.
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("binderhub/%") and
    not path.matches("%/tests/%") and
    not path.matches("%_version.py")
  )
}

/**
 * Dotted module name of a candidate.
 */
string moduleOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
}

/**
 * Enclosing class name, or empty for module-level calls.
 */
string receiverOf(AstNode n) {
  exists(Class c |
    n.getScope().getEnclosingScope+() = c and
    result = c.getName()
  )
  or
  (
    result = "" and
    not exists(Class c |
      n.getScope().getEnclosingScope+() = c
    )
  )
}

/**
 * Relative file path and source line.
 */
string locationOf(AstNode n) {
  result =
    n.getLocation().getFile().getRelativePath() +
    ":" +
    n.getLocation().getStartLine().toString()
}

/**
 * Name of the invoked callable.
 */
string calleeName(Call c) {
  result = c.getFunc().(Attribute).getName()
  or
  result = c.getFunc().(Name).getId()
}

/**
 * Standard subprocess API names.
 */
predicate isSubprocessCallName(string name) {
  name in [
    "run",
    "Popen",
    "call",
    "check_call",
    "check_output",
    "getoutput",
    "getstatusoutput"
  ]
}

predicate isDistinctiveSubprocessName(string name) {
  name in [
    "Popen",
    "check_call",
    "check_output",
    "getoutput",
    "getstatusoutput"
  ]
}

/**
 * Syntactic subprocess candidates.
 *
 * Directly imported function names are also included.
 * Import resolution must be checked during labeling.
 */
predicate isSubprocessCall(Call c) {
  exists(Attribute attr |
    attr = c.getFunc() and
    isSubprocessCallName(attr.getName()) and
    (
      (
        attr.getObject() instanceof Name and
        attr.getObject().(Name).getId() = "subprocess"
      )
      or
      isDistinctiveSubprocessName(attr.getName())
    )
  )
  or
  exists(Name fn |
    fn = c.getFunc() and
    isSubprocessCallName(fn.getId())
  )
}

/**
 * OS-level process execution calls.
 */
predicate isOsCommandCallName(string name) {
  name in [
    "system",
    "popen",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe"
  ]
}

predicate isOsCommandCall(Call c) {
  exists(Attribute attr |
    attr = c.getFunc() and
    isOsCommandCallName(attr.getName()) and
    attr.getObject() instanceof Name and
    attr.getObject().(Name).getId() = "os"
  )
  or
  exists(Name fn |
    fn = c.getFunc() and
    isOsCommandCallName(fn.getId())
  )
}

/**
 * asyncio subprocess factories.
 */
predicate isAsyncioSubprocessCall(Call c) {
  exists(Attribute attr |
    attr = c.getFunc() and
    attr.getName() in [
      "create_subprocess_shell",
      "create_subprocess_exec"
    ] and
    (
      (
        attr.getObject() instanceof Name and
        attr.getObject().(Name).getId() = "asyncio"
      )
      or
      (
        attr.getObject() instanceof Attribute and
        attr.getObject().(Attribute).getName() = "asyncio"
      )
    )
  )
  or
  exists(Name fn |
    fn = c.getFunc() and
    fn.getId() in [
      "create_subprocess_shell",
      "create_subprocess_exec"
    ]
  )
}

/**
 * Kubernetes model constructor candidates.
 */
predicate isKubeCtorCall(Call c, string ctorName) {
  ctorName in [
    "V1Container",
    "V1EnvVar",
    "V1ExecAction"
  ] and
  (
    exists(Attribute attr |
      attr = c.getFunc() and
      attr.getName() = ctorName
    )
    or
    exists(Name fn |
      fn = c.getFunc() and
      fn.getId() = ctorName
    )
  )
}

/**
 * Keyword arguments carrying command or environment values.
 */
predicate isKubeCommandKeyword(
  string ctorName,
  string kwName
) {
  (
    ctorName = "V1Container" and
    kwName in ["args", "command"]
  )
  or
  (
    ctorName = "V1EnvVar" and
    kwName = "value"
  )
  or
  (
    ctorName = "V1ExecAction" and
    kwName = "command"
  )
}

/**
 * Kubernetes Pod creation.
 */
predicate isKubePodCreateCall(Call c) {
  exists(Attribute attr |
    attr = c.getFunc() and
    attr.getName() = "create_namespaced_pod"
  )
  or
  exists(Name fn |
    fn = c.getFunc() and
    fn.getId() = "create_namespaced_pod"
  )
}

/**
 * Worker-pool dispatch calls.
 */
predicate isExecutorSubmitCall(Call c) {
  exists(Attribute attr |
    attr = c.getFunc() and
    attr.getName() = "submit"
  )
}

/**
 * Project command-construction wrapper.
 */
predicate isGetCmdCall(Call c) {
  exists(Attribute attr |
    attr = c.getFunc() and
    attr.getName() = "get_cmd"
  )
}

/**
 * Candidate extraction.
 *
 * Output columns:
 *  1. node
 *  2. candidate type
 *  3. callable
 *  4. flow kind
 *  5. receiver
 *  6. module
 *  7. argument index
 *  8. line
 *  9. file:line
 * 10. expression
 *
 * IMPORTANT:
 * moduleHint is used instead of the reserved word "module".
 */
from
  AstNode n,
  string callable,
  string flow_kind,
  string receiver,
  string moduleHint,
  int arg_index
where
  inAnalysisScope(n) and
  moduleHint = moduleOf(n) and
  (
    // 1. subprocess calls
    exists(Call c |
      c = n and
      isSubprocessCall(c)
    |
      callable = "subprocess." + calleeName(c) and
      flow_kind = "argument" and
      receiver = "subprocess" and
      arg_index = 0
    )

    or

    // 2. os process APIs
    exists(Call c |
      c = n and
      isOsCommandCall(c)
    |
      callable = "os." + calleeName(c) and
      flow_kind = "argument" and
      receiver = "os" and
      arg_index = 0
    )

    or

    // 3. asyncio subprocess calls
    exists(Call c |
      c = n and
      isAsyncioSubprocessCall(c)
    |
      callable = "asyncio." + calleeName(c) and
      flow_kind = "argument" and
      receiver = "asyncio" and
      arg_index = 0
    )

    or

    // 4. Kubernetes constructor keywords
    exists(
      Call c,
      Keyword k,
      string ctorName
    |
      isKubeCtorCall(c, ctorName) and
      k = c.getAKeyword() and
      isKubeCommandKeyword(ctorName, k.getArg()) and
      n = k.getValue()
    |
      callable = ctorName + "." + k.getArg() and
      flow_kind = "argument" and
      receiver = "kubernetes.client" and
      arg_index = -1
    )

    or

    // 5. Kubernetes Pod creation
    exists(Call c |
      c = n and
      isKubePodCreateCall(c)
    |
      callable = "create_namespaced_pod" and
      flow_kind = "argument" and
      receiver = "kubernetes.client.CoreV1Api" and
      arg_index = 1
    )

    or

    // 6. Worker-pool submission
    exists(Call c |
      c = n and
      isExecutorSubmitCall(c)
    |
      callable = "submit" and
      flow_kind = "argument" and
      receiver = "concurrent.futures.Executor" and
      arg_index = 0
    )

    or

    // 7. Command construction wrapper
    exists(Call c |
      c = n and
      isGetCmdCall(c)
    |
      callable = "get_cmd" and
      flow_kind = "return" and
      receiver = receiverOf(n) and
      arg_index = -1
    )
  )

select
  n,
  "sink_candidate",
  callable,
  flow_kind,
  receiver,
  moduleHint,
  arg_index,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()