# Augur Phase 2 Step 4–5 — Query Generation Notes (Pass 2 / CWE-78, Ansible)

- **Run**: `ansible-iris-manual-phase1-step3-pass2-cwe78` (Phase 1) → Step 4 library generation, 2026-10-14
- **Model**: `glm-5.3` (Claude Code CLI agent session)
- **Inputs**: `iris/labels/labels.json` (54 reviewed Pass 2 entries — the audit artifact; not modified),
  `iris/labels/label_stats.md`, `iris/labels/phase1_review.md`, `iris/qlpack.yml`,
  Augur `WORKFLOW.md` §5.1–5.2, `references/python.md`, `assets/taint_query.ql.tmpl`,
  and the Ansible source tree `dataset/codeql_databases/ansible_vuln` (read-only spot-verification).
- **Generated files**:
  - `iris/libraries/MySources.qll`, `iris/libraries/MySinks.qll`,
    `iris/libraries/MySanitizers.qll`, `iris/libraries/MySummaries.qll`
  - `iris/queries/Pass2_CommandInjection.ql` (rendered from `assets/taint_query.ql.tmpl`)
- **Not done (per user instruction)**: `codeql pack install`, query compilation, and the formal
  analysis run (Step 5 execution). Generation stops here.
- **Constraints honored**: no modification of labels, databases, or project source; PyVul ground
  truth not consulted; no diagnostic/extra queries emitted into the formal result path.

## 1. Query identity

| field | value |
|---|---|
| Query ID | `py/augur/ansible/pass2-command-injection` |
| File | `iris/queries/Pass2_CommandInjection.ql` |
| Kind | `path-problem` |
| Severity | `error` |
| CWE tag | `external/cwe/cwe-078` only (Pass 2 was restricted to CWE-78 by user scope; CWE-77/88 semantics recorded in label rationales, no extra tags emitted) |
| Precision | `low` — sources include weak/candidate boundaries (CLI args, environment, stdin/argv) and sink gating accepts dynamic `use_unsafe_shell`/`shell` flags; recall-oriented per Step 3 rubric |
| Pass key | `"command_injection"` (normalized pass key used by all four library dispatchers) |
| Dataflow API | `DataFlow::ConfigSig` (`Pass2Config`) + `TaintTracking::Global<Pass2Config>` (`Pass2Flow`) + `import Pass2Flow::PathGraph` + `Pass2Flow::flowPath(source, sink)` — Python modular data-flow API per WORKFLOW 3.1 |

Template substitutions: `{{CONFIG_NAME}}=Pass2Config`, `{{FLOW_MODULE}}=Pass2Flow`,
`{{SOURCE_MODULE}}=MySources`, `{{SINK_MODULE}}=MySinks`, `{{SANITIZER_MODULE}}=MySanitizers`,
`{{SUMMARY_MODULE}}=MySummaries`, `{{LANGUAGE_IMPORTS}}` = `import python` +
`semmle.python.dataflow.new.DataFlow` + `semmle.python.dataflow.new.TaintTracking`.
`{{EXTRA_TAGS}}` rendered empty (CWE-78 only). The mandatory `isBarrier` hook is present and
delegates to `MySanitizers::isBarrier` (WORKFLOW rule 6 / 5.2.3).

Library imports use dotted module syntax (`import libraries.MySources` etc.); the four QLLs live
in `iris/libraries` under the `iris/qlpack.yml` root. No `API::Node` is assigned to a
`DataFlow::Node` anywhere (API graphs are not used; all matching is AST/dataflow-node based).
No `AstNode.getFile()` calls; no QL classes are declared (predicate-only modules), so no
parent-type/`this`-binding class errors are possible.

## 2. Effective label IDs

### 2.1 Materialized sources (all 17 source-role entries)

| Label ID | Signature | Class | Modeling in `MySources.qll` |
|---|---|---|---|
| P2-001 | `AnsibleModule.params` (field) | tp (510 rows) | attribute read / subscript read / `.get()`/`.pop()` call on any `*.params` attribute (load context only) |
| P2-002 | `ansible.context.CLIARGS` (field) | candidate (332) | attribute / subscript / `.get()` on `*.CLIARGS` |
| P2-004 | `task.args` (field) | candidate (182) | attribute / subscript / `.get()`/`.pop()` on `self._task.args`, `task.args`, `*_task.args` |
| P2-005 | `os.environ` (field) | candidate (64) | subscript read / `.get()` / bare load of `os.environ` (writes excluded via Load context — S-12 fp) |
| P2-006 | `AnsibleModule(...)` (return) | candidate (49) | call result of `AnsibleModule(...)` |
| P2-009 | `json.loads` (return) | tp (32) | call result of `json.loads(...)` |
| P2-010 | `sys.argv` (field) | candidate (31) | `sys.argv` attribute load and subscript read |
| P2-012 | `os.getenv` (return) | candidate (20) | call result of `os.getenv(...)` |
| P2-013 | `sys.stdin` (field) | candidate (17) | `sys.stdin` load and `sys.stdin.read/readline/readlines()` |
| P2-018 | `Connection.exec_command` (return) | tp (5) | call result of any `*.exec_command(...)` method call |
| P2-026 | `ActionBase._low_level_execute_command` (return) | tp (1) | call result of `*._low_level_execute_command(...)` |
| P2-027, P2-045 | `_load_params` (return) | tp | call result of `_load_params()` (merged; same signature) |
| P2-032 | `ConnectionBase.exec_command` (return) | tp (1) | covered by the P2-018 model (method-name match) |
| P2-037 | `NetworkConnectionBase.exec_command` (return) | tp (1) | covered by the P2-018 model |
| P2-047 | `module_utils.connection.exec_command` (return) | tp (1) | plain-name call result of `exec_command(module, command)` (network-module from-import) |
| P2-049 | `json.load` (return) | candidate (1) | call result of `json.load(...)` |

Source usage forms are matched directly (attribute / subscript / `.get()`/`.pop()`) because
object-taint does not propagate through subscript or method-call reads under default Python
taint steps; matching only the bare attribute would lose `module.params['user']` and
`self._task.args.get('_raw_params')`.

Internal function parameters are **not** treated as sources (e.g. lookup-plugin `run(terms, ...)`
parameters are not sources; see §6 for the resulting known miss).

### 2.2 Materialized sinks (5 of 15 sink-role entries)

| Label ID | Signature | Class | Modeling in `MySinks.qll` |
|---|---|---|---|
| P2-008 | `run_command` arg0, `use_unsafe_shell=True` | tp (33) | `DataFlow::MethodCallNode` name `run_command`, flag literal-True or dynamic; sink = arg0 or `args=` kwarg |
| P2-014 + P2-023 | `_low_level_execute_command` arg0/`cmd=` | tp (14+2, same signature, merged) | `MethodCallNode` name `_low_level_execute_command`, sink = arg0 or `cmd=` kwarg |
| P2-015 | `Connection.exec_command` arg0 | tp (7) | `MethodCallNode` name `exec_command`, sink = arg0, excluding `super(...)`-receiver calls |
| P2-020 | `subprocess.Popen` arg0, `shell=True` | tp (3) | `CallCfgNode` with `subprocess.Popen` / from-imported `Popen`, flag literal-True or dynamic; sink = arg0 |

Dynamic-flag acceptance materializes the K-89 tp row (`modules/command.py:359`
`use_unsafe_shell=shell` from `module.params['shell']`) and K-246
(`plugins/connection/local.py:97` `shell=isinstance(cmd, str)`).

### 2.3 Sanitizers (1 of 1)

| Label ID | Signature | Modeling in `MySanitizers.qll` |
|---|---|---|
| P2-SAN-001 | `shlex_quote` (return, tp) | barrier at the `shlex_quote(...)` call node (function is the from-imported Name `shlex_quote`); `shlex.quote`/`pipes.quote` attribute forms unused in this tree and not matched |

### 2.4 Summaries (0 of 18 materialized — deliberate)

All 18 `summary` labels (P2-017, P2-025, P2-028, P2-029, P2-030, P2-031, P2-033, P2-034, P2-038,
P2-039, P2-040, P2-041, P2-042, P2-043, P2-044, P2-046, P2-048, P2-053) describe
`direct_param_passthrough_to_exec` wrapper definitions. `MySummaries::isAdditionalTaintStep`
resolves to `none()` (explicitly permitted by the generation contract) because:

1. **Covered by default analysis.** `TaintTracking::Global` performs inter-procedural flow through
   function parameters, and local flow carries each wrapper parameter to the exec call argument in
   its body. Every wrapper is invoked via a statically resolvable edge (same class, same module, or
   direct import): `CLI.pager_pipe` (cli/__init__.py:429→439), `RpmKey.execute_command`
   (rpm_key.py:205→206), `Group/User/Service.execute_command`, `Subversion._exec`, ohai
   `run_ohai`, vault `_run` (x2), `apt_repository._run_command`, `galaxy.run_scm_cmd`,
   `module_utils.connection.exec_command`, `NetworkConnectionBase.exec_command` (def at
   connection/__init__.py:271), ssh `_bare_run` (same-class chain
   `exec_command → _run → _bare_run → Popen`).
2. **Sinks sit at the wrapper call sites.** For `exec_command`, `_low_level_execute_command` and
   `run_command(use_unsafe_shell=True)`, the sink fires at the call itself (P2-015/P2-014/P2-008),
   so taint never needs to enter the callee body via a summary edge.
3. **Name-based call-site→body edges would be false propagation.** Connecting the argument of any
   method call named e.g. `execute_command` to a fixed node inside one specific definition would
   cross-wire unrelated same-named methods (`Group.execute_command` vs `RpmKey.execute_command` vs
   `User.execute_command`), which the contract forbids (no propagation without unambiguous evidence).

### 2.5 Excluded entries (not materialized)

| Label ID | Role/Class | Reason |
|---|---|---|
| P2-003, P2-007 | sink/candidate | `run_command` with default `use_unsafe_shell=False`: string arg0 is `shlex.split` then argv exec (basic.py:1930-1941); list arg0 is pure argv (basic.py:1928-1943). CWE-88 (argument injection) surface only — out of the CWE-78 formal scope. 288 candidate rows excluded on execution semantics, not silently. |
| P2-011 | sink/candidate (mixed) | `Popen` without an explicit truthy `shell`: the sub-rows with real shell semantics are `basic.py:2016` (`Popen(args, **kwargs)` inside `run_command`, shell flag hidden in `**kwargs`) and `local.py:97` (dynamic shell) — both reached through the `run_command(unsafe=True)` / `exec_command` wrapper sinks instead. Remaining no-shell Popen sites are argv execution (CWE-88) or fixed literals. |
| P2-016 | none/fp | `super(...).exec_command(...)` delegations to the abstract `ConnectionBase` method execute nothing (local.py:67, paramiko_ssh.py:377, psrp.py:419, ssh.py:1265, winrm.py:552). Excluded from the P2-015 sink via the `isSuperDelegation` guard. |
| P2-019 | sink/fp | `Popen` with fixed argv literals (display.py:226 cowsay probe, ssh.py:577 sshpass probe, ssh_functions.py:43). No untrusted component. |
| P2-021, P2-024 | sink/fp, sink/candidate | `subprocess.call`: fixed literals (vault `_shred_file`, respawn, pkg_mgr) or `EDITOR`-env argv lists without a shell (cli/config.py:157-159, vault/__init__.py:852/1125-1129). CWE-88 surface at most. |
| P2-022 | sink/candidate | `subprocess.check_call` galaxy git clone/checkout argv tuples (concrete_artifact_manager.py:350-364) — no shell; pkg_mgr.py:108 fixed literal. |
| P2-050, P2-051, P2-052 | sink/candidate | `pexpect.run`/`_run`/`spawn`: argv semantics without a shell (expect.py:202/209, winrm.py:335 kinit). CWE-88 surface; excluded from the CWE-78 formal query. |
| P2-035, P2-036 | none/fp | `NetworkConnectionBase.exec_command` params `in_data` (stdin payload) and `sudoable` (bool flag) never reach the command position (connection/__init__.py:271-272). |

## 3. API modeling decisions (execution semantics, not call-name blanket rules)

1. **`AnsibleModule.run_command` (basic.py:1842)** — gated on the `use_unsafe_shell` keyword:
   `True` (literal) → `Popen(shell=True)` or `[shell, '-c', args]` (basic.py:1912-1927, verified);
   absent/`False` → shlex-split argv (not a CWE-78 sink). Dynamic flag expressions
   (non-`NameConstant`) are accepted as enabled: `modules/command.py:359`
   (`use_unsafe_shell=shell`, K-89 tp) and `modules/user.py:608`
   (`use_unsafe_shell=use_unsafe_shell`). Verified call-site census: 34× `use_unsafe_shell=True`,
   2× dynamic, 0× positional.
2. **`Connection.exec_command` (connection/__init__.py:135, abstract protocol)** — sink at every
   concrete call site's arg0 (remote command string): paramiko `chan.exec_command(cmd)`
   (paramiko_ssh.py:407, remote login shell), local `Popen(cmd, shell=isinstance(cmd, str))`
   (local.py:97), psrp PowerShell script (psrp.py:444-446), network-device CLI commands
   (module_utils/connection.py:96). `super()` delegations excluded (P2-016).
3. **`ActionBase._low_level_execute_command` (action/__init__.py:1212)** — arg0/`cmd=` is the
   command string forwarded to `self._connection.exec_command` (line 1265); both positional
   (P2-014, e.g. raw.py:42 `_raw_params`) and keyword (P2-023, action/__init__.py:152
   `cmd=cmd`, script.py:142 `cmd=script_cmd`) forms modeled.
4. **`subprocess.Popen`** — sink only with `shell` keyword truthy or dynamic
   (cli/__init__.py:434 PAGER flow, lookup/lines.py:56, lookup/pipe.py:70, local.py:97).
   `shell=False`/absent argv calls are not CWE-78 sinks.
5. **Remote-output sources** — call results of `exec_command`/`_low_level_execute_command`
   (P2-018/026/032/037/047) and `json.loads`/`json.load` (P2-009/049) feed the
   remote-data→command reuse class of flows (e.g. interpreter_discovery.py:97-106).
6. **`shlex_quote` barrier** (P2-SAN-001) — evidence: basic.py:1915-1916 (per-element quoting
   before shell join), action/__init__.py:1037 (module-arg quoting), cron.py:517-537 (user/path
   quoting in `su`/`chown` strings). Barrier at the call node so quoted values stop propagating.

## 4. Key source evidence (spot-verified this run, read-only)

- `module_utils/basic.py:1843` run_command signature; `1912-1927` unsafe-shell branch;
  `1994-2016` `kwargs['shell']` construction and `Popen(args, **kwargs)`.
- `modules/command.py:359` dynamic `use_unsafe_shell=shell`; `modules/user.py:601-608` dynamic
  flag passthrough (known runtime-False site, see §7).
- `plugins/action/__init__.py:1212/1265/1290` `_low_level_execute_command` def / exec_command
  forward / result dict.
- `plugins/connection/local.py:64,67,97-99`, `paramiko_ssh.py:374,377,399,407`,
  `psrp.py:418-446`, `ssh.py:1262-1298`, `winrm.py:552` — exec_command family.
- `cli/__init__.py:415-439` PAGER→`pager_pipe`→`Popen(cmd, shell=True)`.
- `executor/interpreter_discovery.py:97-106` remote stdout → `json.loads` → executed interpreter.
- `executor/task_executor.py:488-516` `self._task.args` consumption patterns (`.pop`, subscript,
  `.update`).
- `context.py` / 307× `context.CLIARGS[...]` subscript reads across `cli/` and `galaxy/`.
- Usage-form censuses (grep): `self._task.args.get` ×101, `self._task.args[` ×17,
  `self._task.args.pop` ×5, `*_task.args` ×175; `.params` ×522 (only two `self.params =`
  assignments in the tree: basic.py:1288 and one module-side `self.params = self.module.params`);
  `os.environ.get` ×16, `os.getenv` ×16, `json.loads|load` ×35; `subprocess.Popen(` ×31,
  from-imported `Popen(` ×4; `shlex_quote` used only via `ansible.module_utils.six.moves`
  (cli/pull.py:23, modules/cron.py:212).

## 5. Cross-checks against historical compile-error rules

- Dotted imports `import libraries.MySources` … only; no slash imports.
- No `API::Node`→`DataFlow::Node` assignment (API graphs unused).
- No `AstNode.getFile()` (unused).
- No QL classes generated at all — predicate-only modules, so no unbound-`this`/missing-supertype
  class errors.
- Query `isSource`/`isSink`/`isBarrier`/`isAdditionalFlowStep` signatures match the QLL exports
  exactly (`MySources::isSource(node, "command_injection")`, `MySinks::isSink(node, key)`,
  `MySanitizers::isBarrier(node, key)`, `MySummaries::isAdditionalTaintStep(from, to, key)`).
- APIs used were verified against the installed `codeql/python-all 7.1.2` pack sources
  (`semmle/python/Exprs.qll`, `AstGenerated.qll`, `dataflow/new/internal/DataFlowPublic.qll`):
  `Call.getFunc/getPositionalArg`, `Attribute.getName/getObject/getCtx`, `Subscript.getObject`,
  `Name.getId`, `Load`, `NameConstant`, `True`, `DataFlow::CallCfgNode.getArgByName/getArg/getFunction`,
  `DataFlow::MethodCallNode.getMethodName/getObject`, `DataFlow::localFlow`, `DataFlow::exprNode`,
  `Node.asExpr()`.

## 6. Uncovered execution interfaces (documented, not silently dropped)

1. **Shell-plugin command builders** — `_shell.build_module_command(...)`, `_shell.exists(path)`,
   `_shell.chmod(paths, mode)`, `_shell.remove(...)`, `_shell.mkdtemp(...)` (8 sites) build
   command strings from task/module data on the controller and feed
   `_low_level_execute_command` (K-19/K-13 label the sink side). No source→return propagation is
   modeled for these builders (not labeled in Step 3), so task-args→`build_module_command`→sink
   paths are missed unless the sink argument is directly tainted.
2. **`pexpect` argv interfaces** (P2-050/051/052) — excluded from the CWE-78 formal query
   (argv semantics, CWE-88). A separate CWE-88 pass would be needed.
3. **`async_wrapper` argv channel** — `wrapped_module`/argsfile from `sys.argv` form the executed
   command; argv execution without a shell (not a labeled sink).
4. **`modules/git.py` `set_git_ssh`** — module param `ssh_opts` exported as `GIT_SSH_OPTS` and
   expanded unquoted (`BASEOPTS=$GIT_SSH_OPTS`, git.py:427-430) inside a `/bin/sh` wrapper script.
   Env-var write→script-expansion is not representable as an AST taint step without fabrication;
   unmodeled.
5. **`run_command` stdout as a source** — the module-side remote-output→shell loop
   (service_facts.py:172/227, the Phase 1 review's top candidate) is not reachable:
   `AnsibleModule.run_command`'s *return* was not labeled as a Pass 2 source in Step 3 (only
   `exec_command` returns were, P2-018/032/037/047). Verifying this internal loop would require a
   diagnostic query with `run_command` returns as sources — deliberately not placed in the formal
   result set per the generation contract.
6. **`os.system` / `os.popen`** — absent from the entire `lib/ansible` tree (grep-verified), so
   no coverage gap.
7. **CLI/console `ansible_connection_cli_stub` socket channel** — network-received JSON is
   covered via the `json.loads` source (P2-009 evidence includes it); the raw socket recv itself
   is not separately modeled.

## 7. Known limitations

- **Name-based matching**: `MethodCallNode.getMethodName()`/attribute-name matching cannot
  resolve dynamic dispatch; e.g. any `.exec_command(...)` call is a sink regardless of receiver
  type. In this tree the name is confined to the connection/terminal families, but the
  approximation should be revisited if the codebase grows.
- **`.params` breadth**: any `*.params` attribute read is a source (P2-001 approximation). Grep
  shows `params` attributes are effectively AnsibleModule-bound in this tree (522 uses, 2
  assignments), so the blast radius is acceptable, but non-AnsibleModule `params` fields would
  also match.
- **Dynamic-flag sinks**: `user.py:608` (`use_unsafe_shell=use_unsafe_shell`, runtime False,
  argv-list form) will match the sink predicate; expect a possible false positive there if taint
  reaches `cmd`. Accepted for recall (command.py:359 is the true-positive counterpart).
- **CLIARGS aliasing**: only direct `context.CLIARGS[...]` / `.get()` / bare-load forms are
  sources; `op = context.CLIARGS; op['x']` indirection loses taint at the subscript.
- **json from-imports**: `from json import loads` call sites would not match (attribute-on-`json`
  form only); none observed in the tree, but a pattern to watch.
- **Tuple unpacking** from `exec_command` returns relies on default local-flow steps
  (`rc, out, err = self._connection.exec_command(...)`).
- **`sys.stdin.buffer`** indirection (ansible_connection_cli_stub.py:226) is not matched by the
  `sys.stdin.read()` source form.
- **Barrier semantics**: `shlex_quote` blocks propagation through the quoted call result;
  string-formatting steps around it (`"%s" % shlex_quote(x)`) remain modeled by default steps.
- **Precision**: `@precision low` reflects the candidate-grade source boundaries retained for
  recall (CLI args, environment, stdin/argv) — Step 6 heuristic filtering and path triage
  (WORKFLOW 7.2) are the intended noise-reduction stages.
- **Version note**: `iris/qlpack.yml` pins `codeql/python-all: 7.0.4`; the local pack cache holds
  7.1.1/7.1.2. All APIs used exist in 7.1.x and are long-standing, but `codeql pack install` plus
  a compile check (`codeql query compile`) must precede the Step 5 run — adjust the pin to a
  resolved 7.1.x version if 7.0.4 cannot be fetched.

## 8. Provenance and integrity

- Only `iris/labels/labels.json` (reviewed Pass 2 labels) drove modeling; no label, database, or
  source file was modified; PyVul ground truth and fix commits were not read.
- Per-row classifications (`tp`/`candidate`/`fp`) from Phase 1 were used to gate sink
  materialization (fp-role sinks excluded, §2.5) and to justify the `@precision low` rating.
- This file is the Step 4 audit record; the Step 5 execution log will go to
  `iris/results/run_log.md` when the analysis is run.
