/**
 * Name : MySources.qll
 * Gen  : Augur Phase 2 Step 4 (machine-generated from reviewed Pass 2 labels)
 * Run  : ansible-iris-manual-phase1-step3-pass2-cwe78
 * Labels source : iris/labels/labels.json (54 entries; Pass 2 / CWE-78, Ansible)
 *
 * Pass key dispatch (WORKFLOW 5.1.5 sharded organization):
 *   "command_injection" -> Pass2CommandInjectionSources (CWE-78)
 *   any other key       -> no match (none())
 *
 * Materialized Pass 2 source label IDs:
 *   P2-001 (AnsibleModule.params, tp, 510 rows)
 *   P2-002 (ansible.context.CLIARGS, candidate, 332 rows)
 *   P2-004 (task.args, candidate, 182 rows)
 *   P2-005 (os.environ, candidate, 64 rows)
 *   P2-006 (AnsibleModule ctor return, candidate, 49 rows)
 *   P2-009 (json.loads return, tp, 32 rows)
 *   P2-010 (sys.argv, candidate, 31 rows)
 *   P2-012 (os.getenv return, candidate, 20 rows)
 *   P2-013 (sys.stdin, candidate, 17 rows)
 *   P2-018 (Connection.exec_command return, tp, 5 rows)
 *   P2-026 (_low_level_execute_command return, tp, 1 row)
 *   P2-027 / P2-045 (_load_params return, tp)
 *   P2-032 (ConnectionBase.exec_command return, tp)
 *   P2-037 (NetworkConnectionBase.exec_command return, tp)
 *   P2-047 (module_utils.connection exec_command return, tp)
 *   P2-049 (json.load return, candidate)
 *
 * Source usage forms are matched directly (attribute read, subscript read,
 * .get()/.pop() call on the attribute) because object-taint does not propagate
 * through subscript/method-call reads under default Python taint steps.
 *
 * NOTE: matching is name/shape based (dynamic dispatch limits static type
 * resolution in Ansible's plugin architecture); approximations are documented
 * in iris/report/query_generation_notes.md.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /**
   * Holds if `source` is a taint source for the pass identified by `passKey`.
   * Currently only the "command_injection" pass (Pass 2 / CWE-78) is defined;
   * any other pass key resolves to no sources.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "command_injection" and
    Pass2CommandInjectionSources::isSource(source)
  }
}

/**
 * Pass 2 (CWE-78) source models, rendered from reviewed label signatures.
 * Internal function parameters are NOT treated as sources; only the labeled
 * input-boundary and remote-output APIs below are sources.
 */
module Pass2CommandInjectionSources {
  predicate isSource(DataFlow::Node source) {
    isAnsibleModuleParamsSource(source) or
    isCliArgsSource(source) or
    isTaskArgsSource(source) or
    isOsEnvironSource(source) or
    isAnsibleModuleCtorSource(source) or
    isJsonLoadSource(source) or
    isSysArgvSource(source) or
    isOsGetenvSource(source) or
    isSysStdinSource(source) or
    isExecCommandReturnSource(source) or
    isLowLevelExecuteCommandReturnSource(source) or
    isLoadParamsSource(source)
  }

  /** P2-001: AnsibleModule.params — module-side input boundary (basic.py:1288). */
  private predicate isAnsibleModuleParamsSource(DataFlow::Node source) {
    exists(Attribute a |
      a.getName() = "params" and
      a.getCtx() instanceof Load and
      source.asExpr() = a
    )
    or
    exists(Subscript s, Attribute a |
      s.getObject() = a and
      a.getName() = "params" and
      s.getCtx() instanceof Load and
      source.asExpr() = s
    )
    or
    exists(Call c, Attribute m, Attribute a |
      c.getFunc() = m and
      m.getName() in ["get", "pop"] and
      m.getObject() = a and
      a.getName() = "params" and
      source.asExpr() = c
    )
  }

  /** P2-002: ansible.context.CLIARGS — controller CLI option reads (context.py:25). */
  private predicate isCliArgsSource(DataFlow::Node source) {
    exists(Attribute a |
      a.getName() = "CLIARGS" and
      a.getCtx() instanceof Load and
      source.asExpr() = a
    )
    or
    exists(Subscript s, Attribute a |
      s.getObject() = a and
      a.getName() = "CLIARGS" and
      s.getCtx() instanceof Load and
      source.asExpr() = s
    )
    or
    exists(Call c, Attribute m, Attribute a |
      c.getFunc() = m and
      m.getName() = "get" and
      m.getObject() = a and
      a.getName() = "CLIARGS" and
      source.asExpr() = c
    )
  }

  /** P2-004: task.args — controller-side playbook task arguments (task_executor.py:509+). */
  private predicate isTaskArgsSource(DataFlow::Node source) {
    exists(Attribute a |
      isTaskArgsAttr(a) and
      a.getCtx() instanceof Load and
      source.asExpr() = a
    )
    or
    exists(Subscript s, Attribute a |
      s.getObject() = a and
      isTaskArgsAttr(a) and
      s.getCtx() instanceof Load and
      source.asExpr() = s
    )
    or
    exists(Call c, Attribute m, Attribute a |
      c.getFunc() = m and
      m.getName() in ["get", "pop"] and
      m.getObject() = a and
      isTaskArgsAttr(a) and
      source.asExpr() = c
    )
  }

  /** Holds if `a` is a `task.args`-shaped attribute (`self._task.args`, `task.args`, `*_task.args`). */
  private predicate isTaskArgsAttr(Attribute a) {
    a.getName() = "args" and
    isTaskObject(a.getObject())
  }

  private predicate isTaskObject(Expr obj) {
    obj.(Attribute).getName() = "_task"
    or
    obj.(Name).getId() = "task"
    or
    obj.(Name).getId().matches("%_task")
  }

  /** P2-005: os.environ reads (env write sites are excluded via Load context). */
  private predicate isOsEnvironSource(DataFlow::Node source) {
    exists(Subscript s |
      isOsEnvironExpr(s.getObject()) and
      s.getCtx() instanceof Load and
      source.asExpr() = s
    )
    or
    exists(Call c, Attribute m |
      c.getFunc() = m and
      m.getName() = "get" and
      isOsEnvironExpr(m.getObject()) and
      source.asExpr() = c
    )
    or
    exists(Attribute a |
      isOsEnvironExpr(a) and
      a.getCtx() instanceof Load and
      source.asExpr() = a
    )
  }

  private predicate isOsEnvironExpr(Expr e) {
    e.(Attribute).getName() = "environ" and
    e.(Attribute).getObject().(Name).getId() = "os"
  }

  /** P2-006: AnsibleModule(...) construction — the returned object holds parsed external input. */
  private predicate isAnsibleModuleCtorSource(DataFlow::Node source) {
    exists(Call c, Name n |
      c.getFunc() = n and
      n.getId() = "AnsibleModule" and
      source.asExpr() = c
    )
  }

  /** P2-009 / P2-049: json.loads / json.load return — deserialized remote or external data. */
  private predicate isJsonLoadSource(DataFlow::Node source) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() in ["loads", "load"] and
      f.getObject().(Name).getId() = "json" and
      source.asExpr() = c
    )
  }

  /** P2-010: sys.argv reads (module-arguments channel in basic.py:389-397). */
  private predicate isSysArgvSource(DataFlow::Node source) {
    exists(Attribute a |
      isSysArgvExpr(a) and
      a.getCtx() instanceof Load and
      source.asExpr() = a
    )
    or
    exists(Subscript s |
      isSysArgvExpr(s.getObject()) and
      s.getCtx() instanceof Load and
      source.asExpr() = s
    )
  }

  private predicate isSysArgvExpr(Expr e) {
    e.(Attribute).getName() = "argv" and
    e.(Attribute).getObject().(Name).getId() = "sys"
  }

  /** P2-012: os.getenv return — local environment read. */
  private predicate isOsGetenvSource(DataFlow::Node source) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "getenv" and
      f.getObject().(Name).getId() = "os" and
      source.asExpr() = c
    )
  }

  /** P2-013: sys.stdin reads (module-args stdin channel, basic.py:401-403). */
  private predicate isSysStdinSource(DataFlow::Node source) {
    exists(Attribute a |
      isSysStdinExpr(a) and
      a.getCtx() instanceof Load and
      source.asExpr() = a
    )
    or
    exists(Call c, Attribute m |
      c.getFunc() = m and
      m.getName() in ["read", "readline", "readlines"] and
      isSysStdinExpr(m.getObject()) and
      source.asExpr() = c
    )
  }

  private predicate isSysStdinExpr(Expr e) {
    e.(Attribute).getName() = "stdin" and
    e.(Attribute).getObject().(Name).getId() = "sys"
  }

  /**
   * P2-018 / P2-032 / P2-037 / P2-047: exec_command return values —
   * remote-host command output (connection plugins, module_utils.connection
   * helper, NetworkConnectionBase relay).
   */
  private predicate isExecCommandReturnSource(DataFlow::Node source) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "exec_command" and
      source.asExpr() = c
    )
    or
    exists(Call c, Name n |
      c.getFunc() = n and
      n.getId() = "exec_command" and
      source.asExpr() = c
    )
  }

  /** P2-026: _low_level_execute_command return — remote execution output dict (action/__init__.py:1290). */
  private predicate isLowLevelExecuteCommandReturnSource(DataFlow::Node source) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "_low_level_execute_command" and
      source.asExpr() = c
    )
  }

  /** P2-027 / P2-045: _load_params() return — stdin/argv JSON parse point (basic.py:370-417). */
  private predicate isLoadParamsSource(DataFlow::Node source) {
    exists(Call c, Name n |
      c.getFunc() = n and
      n.getId() = "_load_params" and
      source.asExpr() = c
    )
  }
}
