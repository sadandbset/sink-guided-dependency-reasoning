# Query Generation Notes — pgadmin4, Pass 2 (CWE-78)

**Augur 0.3.0 · Phase 2 Step 4–5** · Run `pgadmin4-iris-pass2-20261016` · Generated 2026-10-16
**Inputs:** `iris/labels/labels.json` (human-reviewed, 1705 entries: 1068 tp source / 2 tp sink / 0 sanitizer / 20 tp summary / 24 candidate source + 5 candidate sink / 586 fp) and the source tree at `dataset/codeql_databases/pgadmin4_vuln` (sha 61fa8b1, identical to the CodeQL database snapshot — tree, DB and CSV line numbers agree 1:1).
**Outputs:** `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass2_CommandInjection.ql` (formal), plus the supplementary `diagnostics/Pass2_CommandInjectionDiagnostics.ql` (candidate labels only; NOT a formal result). `libraries/MySources.qll` is rendered deterministically from labels.json by `libraries/scripts/build_mysources.py` (its 252 + 24 location pins are read from the label file at generation time, never hand-typed).
**Toolchain:** CodeQL CLI 2.25.1, `codeql/python-all` resolved from the local pack cache via `iris/qlpack.yml` (name `iris/pgadmin4-cwe78`). Per the task directive, **only files were generated — no CodeQL compile or analysis was executed in this step**; every QL idiom used (API-graph call conversion `cn.getNode().getNode().(Call)`, `shellTrueCall` keyword check, `DataFlow::exprNode`/`parameterNode` conversions, `Function.getArg`/`getAnArg`/`getPositionalArg`, `getRelativePath()`/`getStartLine()` pinning, `getADecorator()` handler shapes) is reused verbatim from this project's compile-verified Phase-1 extraction queries (`extraction/sources.ql`/`sinks.ql`, extraction family `match_kind` "api" rows prove the API-graph idiom resolves in this database) and the compile-verified maltrail/dcnnt-py Phase-2 artifacts. `codeql query compile` / `codeql database analyze` are deferred to the run step.

**Threat model (from the reviewed labels):** any client that passes a route's authentication (login_required on most tool/browser endpoints; the heartbeat routes are CSRF-exempt) controls the Flask request state (body, form, query string, json, files, headers, cookies, WSGI environ) and the URL path parameters; a connected socket client controls the /pty event payloads; an importing user controls the import-file content; and the batch-job command list crosses into process_executor.py as sys.argv. The two confirmed sinks — the `validate_binary_path` getoutput probe (request-derived `utility_path`) and the executor Popen over the BatchProcess command list (request-derived args, cmd.exe-interpreted on Windows) — are reached with no metacharacter-blocking construct anywhere on the paths (#DQ# marker handling and dquote doubling are partial, `os.path.exists` checks existence only).

---

## 1. Label ID → CodeQL predicate mapping

All library predicates take `(DataFlow::Node, string passKey)` (summaries: `(DataFlow::Node, DataFlow::Node, string passKey)`), called exactly as `MySources::isSource(source, "command_injection")` etc. from the query config. Pass-key dispatch (WORKFLOW.md 5.1.5):

| Pass key | Entry classifications admitted | Used by |
| --- | --- | --- |
| `command_injection` | `tp` only | `queries/Pass2_CommandInjection.ql` (formal) |
| `command_injection_diagnostics` | `tp` + `candidate` (+ unpinned sink family) | `diagnostics/Pass2_CommandInjectionDiagnostics.ql` (NOT formal) |

Rationale: labels.json defines `candidate` as "plausible but unresolved, human review requested" (phase1_review.md §6 lists the 29 pending decisions). Pending-review items must not become formal findings; they are preserved in the diagnostics query so recall is not lost (mirrors the task directive: candidate/diagnostic paths and internal-wrapper propagation checks belong in diagnostics, never in the formal result set).

### 1.1 MySources::isSource(node, passKey)

| Source family (predicate) | Label IDs (all `source`/tp) | Matching shape |
| --- | --- | --- |
| `flaskRequestStateSource` — request-proxy state (552 entries) | p2-e-0006, 0008, 0010, … — every `http_request` tp entry (id list = all 574 flask-state ids minus the 22 `.get` rows below; full enumeration deterministic in labels.json) | `<request\|req\|request_object>.<data\|form\|args\|json\|values\|files\|cookies\|headers\|environ>` attribute node + `request.get_json(...)` call result; `appFile` restricts to web/ minus regression/tests (the extraction's exclusion set) |
| `flaskRequestParamSource` — request field reads (22 entries) | the 22 ids with `signature.callable = "get"` among the 574 flask-state entries | `request.<collection>[key]` subscript node; `request.<collection>.get/getlist(...)` call result |
| `jsonRequestDecodeSource` — reviewed json decodes (252 entries, location-pinned) | p2-e-0007, 0009, 0013, … — every json tp entry except the 2 import files (p2-e-0035, p2-e-1064) | `json.loads/load(...)` call-result node at the 252 pinned (file, line) pairs (68 files); pins rendered from labels.json by `build_mysources.py` (`jsonDecodePin`) |
| `handlerParamSource` — route/socket handler params (239 entries) | p2-e-0004, 0005, 0011, 0030, 0031, 0039-0042, 0082-0091, … — every `param` tp entry | every non-self parameter of a function decorated `@<name>.route(...)` or `@<name>.on(...)` (the compile-verified extraction shapes) |
| `importFileDecodeSource` (2 entries, pinned) | p2-e-0035 (import_export_servers:130), p2-e-1064 (utils:613) | `json.loads(j.read())` / `json.load(f)` call-result node at the pinned lines |
| `executorArgvSource` (1 entry, pinned) | p2-e-1551 (process_executor.py:414) | `sys.argv` attribute node, pinned to the only read in the file |
| candidate — diagnostics only (24 entries, pinned) | p2-e-0092-0108 (misc/cloud/biganimal 17), p2-e-1140 (browser:441), p2-e-1380/1381 (pgacloud/providers/biganimal 2), p2-e-1563 (processes:547), p2-e-1630/1632/1633 (servers/types.py 3) | `json.loads(...)` call-result node at the pinned (file, line) pairs (`candidateDecodePin`) |

**Deliberately NOT sources (label fp, documented not dropped):** `config.<NAME>` reads (423 rows — local web/config.py + PGADMIN_CONFIG_* env of the launching admin, incl. MASTER_PASSWORD_HOOK and DEFAULT_BINARY_PATHS whose sink chains are recorded in tailored fp rationales), `os.environ` reads (61 rows — the process_executor PROCID/OUTDIR/PGPASSWORD values are an internal parent-set handoff), CLI input (71 rows — setup.py/pgacloud argparse, pkg/win32 dev script), server-generated internal responses, flask test-client responses, local templates/credential files, executor status file, DB rows (chart_data/query_history/Process.desc), stored user settings (25 json entries).

The two AST-shape families (flask state/param, handler params) replicate the Phase-1 extraction predicates exactly (`appFile` = the extraction's `excludedLocation` negation), and Phase 1 dispositioned **every** row those families produced as tp — so shape ≡ reviewed label set. The json decode family cannot be shape-matched (request-derivation of the loads argument is not syntactic: `json.loads(request.data)` vs `json.loads(data)` where `data = request.data.decode()`), hence location pinning from the labels.

### 1.2 MySinks::isSink(node, passKey)

| Label ID | Site | Verdict | Formal key |
| --- | --- | --- | --- |
| **p2-e-1677** | **`web/pgadmin/misc/__init__.py:274` `subprocess.getoutput(r'"{0}" --version'.format(full_path.replace('"', '""')))` arg 0** (inside `validate_binary_path`) | **tp 0.75** | **yes (location-pinned, getoutput shape)** |
| **p2-e-1698** | **`web/pgadmin/misc/bgprocess/process_executor.py:330` `Popen(command, stdout=PIPE, stderr=PIPE, **kwargs)` arg 0** (inside `execute()`, `kwargs['shell'] = True if _IS_WIN else False` at :324) | **tp 0.85** | **yes (location-pinned, Popen shape)** |
| p2-e-1697 | `utils/passexec.py:36` `subprocess.run(self.cmd, shell=True, ...)` arg 0 | candidate 0.60 | diagnostics only (pinned + shell=True check) |
| p2-e-1694 | `utils/master_password.py:140` `subprocess.Popen(command, stdout=PIPE, shell=True)` arg 0 | candidate 0.60 | diagnostics only (pinned + shell=True check) |
| p2-e-1684 | `tools/psql/__init__.py:182` `subprocess.Popen(connection_data, preexec_fn=os.setsid, ...)` arg 0 | candidate 0.60 | diagnostics only (pinned; eventlet.green import matched by the `subprocess.Popen` AST fallback) |
| p2-e-1685 | `tools/psql/__init__.py:237` `process.write(r'"{0}" "{1}" 2>>&1'.format(connection_data[0], connection_data[1]))` arg 0 | candidate 0.65 | diagnostics only (pinned write shape) |
| p2-e-1683 | `utils/__init__.py:375` `subprocess.getoutput('"{0}" --version'.format(full_path))` arg 0 | candidate 0.65 | diagnostics only (pinned) |

Matching shape: command argument = **positional arg 0** of the call, resolved via API graphs (alias-aware; the extraction's `match_kind` "api" rows for :330/:36/:140 prove the idiom resolves in this database) with syntax-level fallbacks (`subprocess.<member>`, bare `Popen` from-import, `os.popen`). The diagnostics key additionally admits the **unpinned** `commandExecCall` family (every `subprocess.{call,check_call,check_output,run,Popen,getoutput}` / `os.popen` site): the rejected static-literal sites (generate_keywords.py:20/:21, javascript_bundler.py:63, psql:235 spawn — labels p2-e-1686/1691/1692/1693) produce no flow because their commands are all-literal, and the six message-format rows (p2-e-1695/1696/1699/1700/1704/1705) are not command semantics at all.

**Shell command string vs argv-list modeling (task directive):** argument 0 is the dangerous argument in both shapes and is modeled uniformly; the per-site mode is recorded in the library header: shell string — misc:274 / utils:375 (getoutput always shells out), passexec:36 (`run(..., shell=True)`), master_password:140 (`Popen(..., shell=True)`), psql:237 (format-write into the running cmd.exe); argv list — process_executor:330 (Windows-only cmd.exe interpretation via the :324 toggle; POSIX argv-list mode) and psql:182 (argv-list, no shell). For the argv-list sites, python-all's container/element taint steps carry taint of individual list elements (e.g. a tainted db name inside `connection_data`) to the arg-0 list node.

### 1.3 MySanitizers::isBarrier(node, passKey)

| Label ID | API | Verdict | Model |
| --- | --- | --- | --- |
| (none) | — | — | **`none()`** — zero sanitizer entries of any classification exist in labels.json |

Evidence (label_stats.md "Sanitizers", phase1_review.md §4): (1) `escape_dquotes_process_arg` (bgprocess/__init__.py:157) wraps only already-double-quoted arguments in #DQ# markers, stripped again at process_executor.py:414 — not shell quoting; (2) the dquote doubling at misc/__init__.py:275 and the `os.path.exists` gates (misc:268, utils:338) are partial mitigations recorded in the sink rationales; (3) `PasswordExec.get`'s SERVER_MODE `NotImplementedError` (passexec.py:26-28) is a deployment-mode gate — modeling it as a barrier could suppress the p2-e-1697 review; (4) Flask `<int:sid>` route converters are runtime parameter typing, not data-flow barriers; (5) no `shlex.quote`/`pipes.quote`/`shlex.join` exists anywhere in the snapshot. The predicate resolves to `none()` (WORKFLOW.md 5.2.3: always exists, never blocks unconditionally).

### 1.4 MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, passKey)

| Label IDs | Step family (predicate) | Formal key |
| --- | --- | --- |
| p2-e-0306 (misc:258), p2-e-1063 (utils:363), p2-e-1631 (types:184), p2-e-1629 (types:77), p2-e-1636/1637 (types:246/:250) | `binaryPathStep`: set_binary_path / replace_binary_path call arg 0 → def param 0 (utils/__init__.py:354 / :404) | yes (both keys) |
| p2-e-1249 (psql:302) | `connectionStrStep`: get_connection_str call args 0/1 (utility path, socket db name) → the call result node | yes (both keys) |
| p2-e-1674-1676, 1678-1680, 1687-1690 (10 sites) | `batchProcessStep`: any argument of the pinned BatchProcess(...) constructions → the `self.cmd`/`self.args` attribute loads in processes.py | yes (both keys) |
| p2-e-1702 (processes:330/:345), p2-e-1703 (processes:381) | `batchPopenTransportStep`: `self.cmd`/`self.args` loads in processes.py → arg 0 of the three BatchProcess-side Popen calls | yes (both keys) |
| p2-e-1701 (process_executor:493) | `detachedReexecStep`: `argv` name loads in process_executor.py → arg 0 of the Windows detached re-exec Popen | yes (both keys) |

Rejected `summary`/`none` labels correctly excluded: the 2 no-argument BatchProcess constructions (bgprocess/__init__.py:78/:118 — pid lookup only) and the 6 message-formatting sink rows.

**Internal-wrapper directive compliance:** no wrapper parameter was auto-promoted to a source. `set_binary_path`/`replace_binary_path`/`get_connection_str`/BatchProcess appear only as *propagation steps* (the summary role the reviewed labels assigned); the only "internal parameter" that is a source is `process_executor.py`'s `sys.argv` (p2-e-1551), which Phase 1 explicitly reviewed as the inter-process command transport, and the handler entry parameters, which Phase 1 reviewed as the request boundary. Verification of internal wrapper propagation for the unresolved candidate set (e.g. BatchProcess construction → start() transport → Popen) is exactly what `diagnostics/Pass2_CommandInjectionDiagnostics.ql` is for; none of it enters the formal result.

---

## 2. Source evidence for every effective source/sink

All line numbers verified against the source tree (`pgadmin4_vuln` @ 61fa8b1 — same state as the database); each label entry's first evidence string in labels.json is the verbatim source line.

**Formal chain A — validate_binary_path getoutput probe (p2-e-1677 sink):**

- `web/pgadmin/misc/__init__.py:249-253` `data = request.data.decode('utf-8')` → `data = json.loads(data)` — request body read (family 1 source at :249) and its decode (family 3 pinned source at :253, label p2-e-…-253 pin).
- `web/pgadmin/misc/__init__.py:256-258` `if 'utility_path' in data …: binary_path = replace_binary_path(data['utility_path'])` — subscript of the tainted decode result (container→element is native) into the utility-path step (summary p2-e-0306).
- `web/pgadmin/misc/__init__.py:261-264` `full_path = os.path.abspath(os.path.join(binary_path, utility))` — native flow through join/abspath; `replace_binary_path` returns its argument when no `$DIR` is present (utils/__init__.py:404-420).
- `web/pgadmin/misc/__init__.py:268` `if not os.path.exists(binary_path):` — existence gate (not a barrier, §1.3); `:274` `subprocess.getoutput(r'"{0}" --version'.format(full_path.replace('"', '""')))` — **sink p2-e-1677**; getoutput executes through the shell; the `.format` argument→result propagation is python-all's native string-formatting modeling.

**Formal chain B — BatchProcess pipeline into the executor Popen (p2-e-1698 sink):**

- Web side (context for the transported command): e.g. `web/pgadmin/tools/backup/__init__.py:401` `data = json.loads(request.data)` (family 3 source) → `:447-449` `escaped_args = [escape_dquotes_process_arg(arg) for arg in args]` → `:456` `BatchProcess(desc=…, cmd=utility, args=escaped_args)` (summary p2-e-1687; `#DQ#` markers do not neutralize metacharacters) → `processes.py:290-291` `cmd = [interpreter, executor, self.cmd]; cmd.extend(self.args)` → `processes.py:330/:345` `Popen(cmd, …)` (summary p2-e-1702, argv-list, fixed executables — the fork boundary ends the web-side path).
- Executor side (the formal source→sink path): `process_executor.py:413-415` `argv = [unescape_dquotes_process_arg(arg) for arg in sys.argv]` — **source p2-e-1551** (the `sys.argv` read; CodeQL cannot cross the fork, so the label deliberately pins the handoff) → `:298` `command = argv[1:]` (native slice flow) → `:322-324` `kwargs['shell'] = True if _IS_WIN else False` → `:330` `Popen(command, stdout=PIPE, stderr=PIPE, **kwargs)` — **sink p2-e-1698**: on Windows the command list is joined and interpreted by cmd.exe; `detachedReexecStep` (p2-e-1701) additionally bridges the `cmd = [sys.executable]; cmd.extend(argv)` mutation at :488-493.

**Socket /pty chain (diagnostics; candidate sinks p2-e-1684/1685):** `psql/__init__.py:278-280` `@sio.on('start_process', namespace='/pty') def start_process(data):` — family 4 source (socket payload) → `:295-296` `db = underscore_unescape(data['db'])` → `:302` `connection_data = get_connection_str(psql_utility, db, manager)` (summary p2-e-1249; `connectionStrStep` bridges the `manager.utility`/`manager.create_connection_string` dynamic dispatch at :301/:380) → `:182` `Popen(connection_data, …)` (p2-e-1684, argv-list) and `:237` `process.write(r'"{0}" "{1}" 2>>&1'.format(connection_data[0], connection_data[1]))` (p2-e-1685, command typed into the cmd.exe spawned at :235).

**Import-file chain (diagnostics; candidate sink p2-e-1697):** `import_export_servers/__init__.py:118-130` — filename from request data → `json.loads(j.read())` (source p2-e-0035) → `validate_json_data` (structure check) → server registration incl. `passexec_cmd` → `server_manager.py:86` `PasswordExec(server.passexec_cmd, …)` → `passexec.py:36` `subprocess.run(self.cmd, shell=True, …)` behind the SERVER_MODE `NotImplementedError` gate at :26-28.

**Supporting source families (verified per-entry in Phase 1; counts here, enumeration in labels.json):** request-proxy state across 82 files (top: sqleditor 61 rows, tables 18, file_manager 15, servers 15 — incl. the `req` alias at file_manager:210/:1127 and the `request_object` delete-helper reads); request field `.get`/subscript reads (22); the 252 pinned json decodes (68 files); 239 handler parameters of 131 distinct route/socket functions (`ddl_compare` :675-677 has 11 params, arg indices 0-10; `check_utility_exists`, `panel`, `close`, `poll`, … — all @blueprint.route; `start_process`/`socket_input`/`resize`/`server_disconnect` are @sio.on).

---

## 3. Parameter indices and controllability decisions

Index convention (labels.json metadata + extraction contract): **0-based position in the function definition with `self` counted at 0** — `Parameter.getPosition()` / `Function.getArg(n)` in CodeQL Python returns exactly this, so label `arg_index` maps 1:1 to `functionParamAt` and to `handlerParamSource`'s `f.getAnArg()` positions.

| Site / family | Index | Label | Controllability judgment |
| --- | --- | --- | --- |
| route/socket handler params (239) | 0–10, self excluded | all `param` tp entries | URL path values / socket payloads supplied by the client before validation; `<int:sid>` converters restrict some to numerals at runtime (recorded, not a barrier) |
| `get_connection_str` call (psql:302) | 0 (utility), 1 (db) | p2-e-1249 | arg 1 = socket-client `data['db']`; arg 0 = preference-derived psql path — both flow into the psql argv / cmd.exe write |
| `set_binary_path` / `replace_binary_path` calls | 0 | p2-e-0306/1063/1629/1631/1636/1637 | request `utility_path` at misc:258; preference `old_path`/`bin_path` at types:77/:184; config defaults at types:246/:250 (trusted operand — step kept because the shared callee reaches the getoutput probe) |
| BatchProcess(...) constructions | any argument (`cmd=`/`args=` keyword values at all 10 sites) | p2-e-1674-1690 | the `args` lists are built from request JSON at every site (backup `_get_args_params_values`, cloud deploy params, views `--command SQL`) |
| subprocess family | 0 | p2-e-1677/1698 tp; 1683/1684/1685/1694/1697 candidate | the shell command string (getoutput/run/Popen shell sites) or the command list (argv-list sites); uniform arg 0, mode documented per site |

No `os.system`/`os.exec*`/`eval`/`exec` sites exist in the non-test source (Phase-1 sink extraction found none), so no predicates were emitted for them; `os.popen` appears only at the two static-literal codegen sites (fp).

---

## 4. Sanitizer and summary modeling evidence

**Sanitizer set — empty:** §1.3; `MySanitizers::isBarrier` resolves to `none()` for both pass keys — never an unconditional block.

**Summaries (20 tp):**
- *binaryPathStep (6 labels, 0.6-0.8)* — evidenced by the six call sites and the two definitions (utils/__init__.py:354/:404); statically resolvable bare-name calls, so the step is label-mandated redundancy over native call-to-parameter propagation (same policy as maltrail's logEventStep).
- *connectionStrStep (p2-e-1249, 0.8)* — evidenced by psql/__init__.py:302 and the callee body :370-385: the argv is assembled from `manager.utility('sql')` and `manager.create_connection_string(database, user)` — dynamic dispatch CodeQL cannot resolve — so the arg→result step is **load-bearing** for the /pty chain (the call result becomes `connection_data[0]/[1]` at :182/:237).
- *batchProcessStep (10 labels, 0.75-0.8)* — evidenced by the construction sites (all passing `cmd=`/`args=` keyword values built from request JSON) and `BatchProcess.__init__(**kwargs)` → `_create_process(kwargs['desc'], _cmd, kwargs['args'])` (processes.py:117-121) → `self.cmd = _cmd` / `self.args = _args` (:205/:227): the kwargs-dict indirection inside `__init__` and the cross-method attribute flow make the any-argument → `self.cmd`/`self.args` step the reliable bridge.
- *batchPopenTransportStep (p2-e-1702/1703, 0.7-0.75)* — evidenced by `cmd = [interpreter, executor, self.cmd]; cmd.extend(self.args)` (:290-291) and the three Popen calls (:330/:345/:381): `list.extend` container mutation is not natively tracked, so the attribute→arg-0 step carries the transport. These Popens execute fixed interpreters in list mode — the step transports taint toward the child, it is not a sink.
- *detachedReexecStep (p2-e-1701, 0.7)* — evidenced by `cmd = [sys.executable]; cmd.extend(argv)` (process_executor.py:488-489) and the Popen at :493; bridges the same extend-mutation gap on the executor side.

All steps are strictly conditional on location-pinned call/attribute shapes; no unconditional propagation exists anywhere in the four libraries.

---

## 5. Uncovered APIs, dynamic calls, and known limitations

1. **The fork boundary** — the web-side request→BatchProcess chain and the executor-side sys.argv→Popen chain are two separate CodeQL paths by construction (CodeQL cannot follow `Popen([interpreter, executor, …])` into the child). The labels' deliberate `sys.argv` source (p2-e-1551) makes the executor half self-contained; the formal finding's source node will therefore be `sys.argv`, with the request-side chain visible via the diagnostics query and the summary steps.
2. **`manager.utility(...)` / `manager.create_connection_string(...)` / `get_utility_path` dynamic dispatch** — not natively resolvable; bridged by `connectionStrStep` (arg→result) for the psql chain. The preference→utility-path chain (types.py `get_utility_path`, ORM/preference reads not extracted) remains second-order: covered by the candidate sources p2-e-1630/1632/1633 in diagnostics only.
3. **`data['db']` / `data['input']` / `data['pwd']` subscripts inside the @sio.on handlers** are not individually extracted (Phase-1 uncoveredCases) — carried by the handler `data`-parameter sources plus native container→element flow.
4. **`current_user.username`** (the `%u` substitution of the master-password hook, master_password.py:41-43) is an ORM attribute read with no label row — the p2-e-1694 sink stays candidate; no source was invented for it.
5. **BatchProcess ORM round-trip** (`p.command`/`p.arguments` reads in `_retrieve_process`) is not extracted; the live pipeline is covered by the construction summary + executor argv source; the retrieved-process path only serves status display (Phase-1 fp labels).
6. **AST-shape collision risk** — the flask state/param families match the closed receiver-name list `request`/`req`/`request_object` with the closed state-attribute list; a *local variable* named `request` holding a non-Flask object with one of those attribute names would match. Phase 1 verified all 699 rows of exactly this shape as genuine request reads, so the closure equals the reviewed set for this snapshot.
7. **Decorator-shape closure** — `handlerFunction` matches any `@<name>.route(...)`/`@<name>.on(...)`; only Flask blueprints and the `/pty` SocketIO handlers use these shapes in the web/ tree (269 routes + 6 socket handlers, Phase-1 verified).
8. **Windows-only shell interpretation for p2-e-1698** — on POSIX, process_executor runs argv-list mode (no shell); the sink models arg 0 uniformly and the platform distinction is recorded in the rationale/notes. The psql:182 site is argv-list on all platforms.
9. **String-format reliance** — chains A and the psql write rely on python-all's native `.format`/`%` argument→result taint modeling; if a pack version dropped it, the sinks would need explicit format steps (none added now — evidence-free steps are not created).
10. **Line pins are snapshot-pinned** — the 252+24 source pins, 7 sink pins and 10 BatchProcess pins are correct for sha 61fa8b1 (tree == database). If the tree moves, re-run `libraries/scripts/build_mysources.py` and re-verify the hand-written pins before running.
11. **`escape_dquotes_process_arg` is deliberately not a barrier** (§1.3); if a reviewer disagrees, the change belongs in labels + MySanitizers, not in the query.
12. **No compile was executed** (task directive: generate files only). Idiom risk is minimized by reuse from this project's compile-verified extraction queries and the maltrail/dcnnt-py Phase-2 artifacts; `codeql query compile` should be the first step of the run phase.

---

## 6. Modeling principles (consistent with the other project experiments)

1. **Render from reviewed labels only** — formal predicates admit `tp` entries; `candidate` entries go to the diagnostics query; `fp`/`none` entries are documented as rejected, never silently dropped.
2. **Threat model = the authenticated web client, the socket client, the importing user (and the inter-process command transport on the executor side)** — request state/fields, json request decodes, handler params and import files are untrusted; local `config.<NAME>`, `os.environ`, CLI input, server-generated responses and locally authored files stay on the trusted side (maltrail/dcnnt-py precedent).
3. **Signature-level matching with positional precision** — module + callable + argument/parameter index; sibling parameters of one function are judged individually (route params tp while `BatchProcess(id=pid)` constructions are fp; `struct`-style arg-0-constant vs arg-1-data splits appear in the json field-decode family).
4. **Location pinning for formal sinks** when signature matching would admit unreviewed sites; diagnostics keep the unpinned family. The 252 json-decode sources are pinned because their request-derivation is semantic, not syntactic — pins are rendered from labels.json by script, never hand-typed.
5. **Barriers only with evidence** — with no metacharacter-blocking construct in the snapshot, the barrier predicate resolves to `none()`, never to unconditional taint or blocking.
6. **Summaries are conditional, location-pinned steps** — no unconditional propagation; internal-wrapper parameters are sources only where Phase 1 reviewed them as boundaries (handler params, executor sys.argv — never auto-promoted); wrapper/diagnostic propagation checks stay out of the formal result (task directive).
7. **Shell-string vs argv-list modeling** — dangerous argument = arg 0 in both shapes, modeled uniformly; the per-site mode (shell string / argv list / write-into-shell) is recorded in the library headers and these notes.
8. **Diagnostics-vs-formal separation** — the formal query's pass key admits tp only; the diagnostics query (separate file, severity warning, `[DIAGNOSTICS ONLY]` message) carries candidates and unpinned families; its findings are never counted as formal pass-2 results.
9. **No execution in this step** — files only; compile and analysis are deferred to the run step.

---

## 7. Files

```
iris/
├── libraries/MySources.qll          # sources, pass-key dispatch; 252+24 pins rendered from labels.json
├── libraries/MySinks.qll            # arg-0 command sinks; 2 formal sites pinned, 5 candidate, unpinned diagnostics family
├── libraries/MySanitizers.qll       # empty barrier set (none()) — label state
├── libraries/MySummaries.qll        # binary-path / connection-string / BatchProcess / transport steps
├── libraries/scripts/build_mysources.py   # deterministic MySources.qll renderer (reads labels.json)
├── queries/Pass2_CommandInjection.ql      # formal @kind path-problem, severity error
├── diagnostics/Pass2_CommandInjectionDiagnostics.ql  # candidate labels only, severity warning
└── report/query_generation_notes.md # this file
```

No source files, CodeQL database, Phase-1 labels, or extraction artifacts were modified; only the files under `iris/{libraries,queries,diagnostics,report}/` were generated.
