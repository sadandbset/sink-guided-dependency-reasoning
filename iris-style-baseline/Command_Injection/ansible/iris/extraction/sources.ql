/**
 * @name Ansible source candidate extraction (Pass 2, CWE-78)
 * @description
 *   Extracts input-boundary API candidates for CWE-78 labeling from the
 *   Ansible codebase. Boundaries are derived from repository evidence:
 *   AnsibleModule parameters (stdin/argv -> params), task/playbook args,
 *   environment variables, CLI args, stdin, deserialized remote/external
 *   data, and remote-command wrapper return values.
 *   Columns: node, kind, api, module, receiver, flow_kind, arg_index,
 *   file, line, boundary.
 * @kind problem
 * @id py/augur/ansible/extract-sources
 * @problem.severity recommendation
 */

import python

/* ------------------------------------------------------------------ */
/* Input boundary shapes                                              */
/* ------------------------------------------------------------------ */

/**
 * A call to the `AnsibleModule(...)` constructor. The constructed object
 * carries the module's parameters, parsed from stdin/argv by
 * `module_utils/basic.py:370 _load_params()`.
 */
class AnsibleModuleCtorCall extends Call {
  AnsibleModuleCtorCall() { this.getFunc().(Name).getId() = "AnsibleModule" }
}

/**
 * A read of `<obj>.params` in a file that constructs an `AnsibleModule`
 * (or in `ansible.module_utils.basic` itself). This is how packaged modules
 * consume the module-argument boundary.
 */
class ModuleParamsRead extends Attribute {
  ModuleParamsRead() {
    this.getName() = "params" and
    this.getObject() instanceof Name and
    (
      exists(AnsibleModuleCtorCall c | c.getEnclosingModule() = this.getEnclosingModule())
      or this.getEnclosingModule().getName() = "ansible.module_utils.basic"
    )
  }
}

/**
 * A call to `AnsibleModule._load_params()` or the module-level
 * `ansible.module_utils.basic._load_params()`, both of which return the
 * raw `ANSIBLE_MODULE_ARGS` payload read from stdin/argv.
 */
class LoadParamsCall extends Call {
  LoadParamsCall() {
    this.getFunc().(Name).getId() = "_load_params"
    or (
      this.getFunc() instanceof Attribute and
      this.getFunc().(Attribute).getName() = "_load_params"
    )
  }
}

/** A read of `os.environ` (including `os.environ[...]` and `os.environ.get(...)`). */
class OsEnvironRead extends Attribute {
  OsEnvironRead() {
    this.getName() = "environ" and
    this.getObject().(Name).getId() = "os"
  }
}

/** A call to `os.getenv(name, ...)`. */
class OsGetenvCall extends Call {
  OsGetenvCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() = "getenv" and
    this.getFunc().(Attribute).getObject().(Name).getId() = "os"
  }
}

/** A read of `sys.argv` (including `sys.argv[...]`). */
class SysArgvRead extends Attribute {
  SysArgvRead() {
    this.getName() = "argv" and
    this.getObject().(Name).getId() = "sys"
  }
}

/** A read of `sys.stdin` (covers `sys.stdin.buffer` and `sys.stdin.read()`). */
class SysStdinRead extends Attribute {
  SysStdinRead() {
    this.getName() = "stdin" and
    this.getObject().(Name).getId() = "sys"
  }
}

/**
 * A read of a task's argument dictionary: `self._task.args`, `task.args`,
 * `self.task.args`, or `_task.args`, restricted to `lib/ansible/**`.
 * Task args are the controller-side playbook/inventory input boundary.
 */
class TaskArgsRead extends Attribute {
  TaskArgsRead() {
    this.getName() = "args" and
    this.getLocation().getFile().getRelativePath().matches("lib/ansible/%") and
    (
      (
        this.getObject() instanceof Attribute and
        this.getObject().(Attribute).getName() = "_task" and
        this.getObject().(Attribute).getObject().(Name).getId() = "self"
      )
      or this.getObject().(Name).getId() = "task"
      or this.getObject().(Name).getId() = "_task"
      or (
        this.getObject() instanceof Attribute and
        this.getObject().(Attribute).getName() = "task" and
        this.getObject().(Attribute).getObject().(Name).getId() = "self"
      )
    )
  }
}

/** A read of `ansible.context.CLIARGS`, the parsed global CLI argument store. */
class CliArgsRead extends Attribute {
  CliArgsRead() {
    this.getName() = "CLIARGS" and
    this.getObject().(Name).getId() = "context"
  }
}

/**
 * A call to `json.loads` / `json.load`. In Ansible these primarily
 * deserialize remote-command output and inter-plugin payloads.
 */
class JsonLoadCall extends Call {
  JsonLoadCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() in ["loads", "load"] and
    this.getFunc().(Attribute).getObject().(Name).getId() = "json"
  }
}

/**
 * A definition of the remote-command execution protocol
 * (`exec_command` / `_exec_command` on connection plugins,
 * `_low_level_execute_command` on action plugins) under `lib/ansible/**`.
 * Return values carry remote-host output.
 */
class RemoteCommandFunction extends Function {
  RemoteCommandFunction() {
    this.getName() in ["exec_command", "_exec_command", "_low_level_execute_command"] and
    this.getLocation().getFile().getRelativePath().matches("lib/ansible/%")
  }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/** Test/fixture paths, excluded from candidate extraction. */
predicate isExcludedPath(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    (
      path.matches("test/%")
      or path.matches("%/test/%")
      or path.matches("%/tests/%")
    )
  )
}

/**
 * Gets the receiver label for a function definition: the enclosing class
 * name for methods, "-" otherwise.
 */
string definitionReceiver(Function f) {
  exists(Class c | c = f.getEnclosingScope() | result = c.getName())
  or
  (
    not f.getEnclosingScope() instanceof Class and
    result = "-"
  )
}

/* ------------------------------------------------------------------ */
/* Candidate rows                                                     */
/* ------------------------------------------------------------------ */

/**
 * Holds if `n` is a source candidate with the given metadata.
 * `flowKind`: "return" (call/ctor yields untrusted data),
 *             "value" (attribute read of untrusted data),
 *             "param" (definition parameter).
 */
predicate sourceCandidate(
  AstNode n, string kind, string api, string moduleName, string receiver,
  string flowKind, int argIndex, string boundary
) {
  /* AnsibleModule(...) constructor: the object's params come from stdin/argv */
  exists(AnsibleModuleCtorCall c |
    n = c and
    kind = "constructor_call" and
    api = "AnsibleModule" and
    moduleName = c.getEnclosingModule().getName() and
    receiver = "-" and
    flowKind = "return" and
    argIndex = -1 and
    boundary = "module_params_stdin_argv"
  )
  or
  /* `<obj>.params` reads: the module-argument boundary */
  exists(ModuleParamsRead a |
    n = a and
    kind = "attribute_read" and
    api = "AnsibleModule.params" and
    moduleName = a.getEnclosingModule().getName() and
    receiver = a.getObject().toString() and
    flowKind = "value" and
    argIndex = -1 and
    boundary = "module_params"
  )
  or
  /* module-level `_load_params()`: raw ANSIBLE_MODULE_ARGS payload */
  exists(LoadParamsCall c |
    n = c and
    c.getFunc() instanceof Name and
    kind = "call" and
    api = "ansible.module_utils.basic._load_params" and
    moduleName = c.getEnclosingModule().getName() and
    receiver = "-" and
    flowKind = "return" and
    argIndex = -1 and
    boundary = "module_params_stdin_argv"
  )
  or
  /* `self._load_params()`: sets self.params from the raw payload */
  exists(LoadParamsCall c |
    n = c and
    c.getFunc() instanceof Attribute and
    kind = "call" and
    api = "AnsibleModule._load_params" and
    moduleName = c.getEnclosingModule().getName() and
    receiver = c.getFunc().(Attribute).getObject().toString() and
    flowKind = "return" and
    argIndex = -1 and
    boundary = "module_params_stdin_argv"
  )
  or
  /* `os.environ` reads */
  exists(OsEnvironRead a |
    n = a and
    kind = "attribute_read" and
    api = "os.environ" and
    moduleName = a.getEnclosingModule().getName() and
    receiver = "os" and
    flowKind = "value" and
    argIndex = -1 and
    boundary = "environment"
  )
  or
  /* `os.getenv()` calls */
  exists(OsGetenvCall c |
    n = c and
    kind = "call" and
    api = "os.getenv" and
    moduleName = c.getEnclosingModule().getName() and
    receiver = "os" and
    flowKind = "return" and
    argIndex = 0 and
    boundary = "environment"
  )
  or
  /* `sys.argv` reads */
  exists(SysArgvRead a |
    n = a and
    kind = "attribute_read" and
    api = "sys.argv" and
    moduleName = a.getEnclosingModule().getName() and
    receiver = "sys" and
    flowKind = "value" and
    argIndex = -1 and
    boundary = "cli_args"
  )
  or
  /* `sys.stdin` reads */
  exists(SysStdinRead a |
    n = a and
    kind = "attribute_read" and
    api = "sys.stdin" and
    moduleName = a.getEnclosingModule().getName() and
    receiver = "sys" and
    flowKind = "value" and
    argIndex = -1 and
    boundary = "stdin"
  )
  or
  /* task argument dictionary reads (playbook/inventory boundary) */
  exists(TaskArgsRead a |
    n = a and
    kind = "attribute_read" and
    api = "task.args" and
    moduleName = a.getEnclosingModule().getName() and
    receiver = a.getObject().toString() and
    flowKind = "value" and
    argIndex = -1 and
    boundary = "task_args_playbook"
  )
  or
  /* `context.CLIARGS` reads */
  exists(CliArgsRead a |
    n = a and
    kind = "attribute_read" and
    api = "ansible.context.CLIARGS" and
    moduleName = a.getEnclosingModule().getName() and
    receiver = "context" and
    flowKind = "value" and
    argIndex = -1 and
    boundary = "cli_args"
  )
  or
  /* `json.loads` / `json.load`: deserialized remote/external data */
  exists(JsonLoadCall c |
    n = c and
    kind = "call" and
    api = "json." + c.getFunc().(Attribute).getName() and
    moduleName = c.getEnclosingModule().getName() and
    receiver = "json" and
    flowKind = "return" and
    argIndex = 0 and
    boundary = "deserialized_remote_or_external_data"
  )
  or
  /* remote-command protocol definitions: return values carry remote output */
  exists(RemoteCommandFunction f |
    n = f and
    kind = "definition" and
    api = f.getQualifiedName() and
    moduleName = f.getEnclosingModule().getName() and
    receiver = definitionReceiver(f) and
    flowKind = "return" and
    argIndex = -1 and
    boundary = "remote_host_output"
  )
}

from AstNode n, string kind, string api, string moduleName, string receiver, string flowKind, int argIndex, string boundary
where
  sourceCandidate(n, kind, api, moduleName, receiver, flowKind, argIndex, boundary) and
  not isExcludedPath(n)
select n, kind, api, moduleName, receiver, flowKind, argIndex,
  n.getLocation().getFile().getRelativePath(),
  n.getLocation().getStartLine(),
  boundary
