# Query Generation Notes — Paddle, Pass 2 (CWE-78)

**Augur 0.3.0 · Phase 2 Step 4–5** · Run `paddle-iris-phase1-step3-pass2-20261015` · Generated 2026-10-16
**Inputs:** `iris/labels/labels.json` (human-reviewed per `iris/labels/phase1_review.md`; pass 2 only: 11 source / 13 sink / 2 summary / 0 sanitizer signature-level entries, all classification `candidate`, covering 367+61+6 raw rows of the 925-row extraction; 491 `none` rows) and the source tree at `dataset/codeql_databases/Paddle_vuln` (sha `e64a054ff6b3964070fb2eb24c9aace4db5965eb`, identical to the CodeQL DB snapshot — every line pin below was re-verified against the tree in this step).
**Outputs:** `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass2_CommandInjection.ql` (formal), plus the supplementary `diagnostics/Pass2_CommandInjectionDiagnostics.ql` (wrapper-parameter propagation check; NOT a formal result).
**Toolchain:** CodeQL CLI 2.25.1 (`E:\codeql`), `codeql/python-all` 7.1.1/7.1.2 from the local pack cache via `iris/qlpack.yml` (name `iris/paddle-cwe78`). Per the task directive, **only files were generated — no CodeQL compile or analysis was executed in this step**; every QL idiom used is reused verbatim from this project's compile-verified Phase-1 extraction queries (`iris/extraction/sources.ql`, `iris/extraction/sinks.ql`) or mirrors library code in `codeql/python-all` 7.1.2 itself (verified in the pack cache; list in §7). `codeql query compile` / `codeql database analyze` are deferred to the run step.

**Threat model (from the reviewed labels):** Paddle is a library/CLI framework; "attacker" control means control by the invoking user or a cluster peer — CLI arguments of the distributed launchers (`python -m paddle.distributed.launch / fleet / elastic`), environment variables, JSON/protobuf config supplied by the user, download URLs, etcd cluster state and socket peer data. The five tp-shaped sink chains confirmed during Phase-1 review: `--elastic_pre_hook` → `Popen(..., shell=True)` (manager.py:364), wget f-string with caller URL (download.py:204), hadoop fs strings from `fleet_desc` config (pslib:814/:834, fs.py:506), `os.popen("echo -n " + days/hours)` (fleet_util.py:1320/:1321), and the auto-tuner shell f-string (prune.py:521).

---

## 1. Label ID → CodeQL predicate mapping

All library predicates take `(DataFlow::Node, string passKey)` (summaries: `(DataFlow::Node, DataFlow::Node, string passKey)`). Pass-key dispatch (WORKFLOW.md 5.1.5):

| Pass key | Entry set admitted | Used by |
| --- | --- | --- |
| `command_injection` | the reviewed labels.json label set (all `role` source/sink/summary entries; this project's reviewed classification is uniformly `candidate`) | `queries/Pass2_CommandInjection.ql` (formal) |
| `command_injection_diagnostics` | wrapper / public-API parameter seeds only (labels.json metadata "Source-side coverage gaps recorded for Step 4" + phase1_review.md §7) | `diagnostics/Pass2_CommandInjectionDiagnostics.ql` (NOT formal) |

Rationale for the formal-key policy: unlike maltrail (tp entries existed) this project's reviewed label set contains **no `tp` classification at the signature level** — every labels.json entry is `candidate`, because the Phase-1 human review deliberately kept the "concrete paths need Phase 2 taint confirmation" verdict in the label state. Rendering only tp entries would produce an empty formal query; the review gate approved this exact candidate set as the Phase-2 input. The formal query is therefore tagged `@precision low` and its result message states findings need review. The wrapper-parameter seeds (which would auto-promote internal wrapper params to sources, contra the task directive) are excluded from the formal key and live only in the diagnostics query — same split as the autogluon experiment (strict vs diagnostic sources over an all-candidate label set).

### 1.1 MySources::isSource(node, passKey) — formal families

| Source family (predicate) | Label IDs (conf) | Matching shape |
| --- | --- | --- |
| `sysArgvSource` | p2-src-sysargv (0.75) | `sys.argv` attribute **load** in the 3 reviewed files (all 7 `sys.argv` sites in `python/paddle/` are exactly the 7 labeled rows — grep-verified) |
| `parsedCliSource` | p2-src-parse-args (0.7), p2-src-parse-known (0.7) | call result of `.parse_args()` / `.parse_known_args()` in the 9 reviewed files (7 parse_args + 2 parse_known_args rows) |
| `envReadSource` | p2-src-getenv, p2-src-environ-get, p2-src-environ-getitem (0.6 each) | `os.getenv(...)`, `os.environ.get(...)` call results and `os.environ[...]` subscript **loads**, restricted to the 43 Tier-A command-construction files (the reviewed 304/433 split; the 129 Tier-B compute-module reads are excluded) |
| `backupEnvSource` | p2-src-getenv-or-backup (0.6) | bare-name `getenv_or_backup(...)` call result (7 call sites = the 7 labeled rows; name grep-verified unique) |
| `jsonConfigSource` | p2-src-json-load, p2-src-json-loads (0.55) | `json.load/loads(...)` call result in the 12 reviewed config-decode files (25 source rows; the 10 in-process metadata rows excluded) |
| `etcdStateSource` | p2-src-etcd (0.55) | `.get_prefix(...)` call result in the 5 reviewed files (13 rows) |
| `socketPeerSource` | p2-src-socket-recv (0.5) | `.recv(...)` call result, location-pinned to `auto_parallel/static/utils.py:1809/:1829` (the 2 `get_cluster()` rows; the other 20 socket.recv rows are `none`) |

**Deliberately NOT sources (role `none`, documented not dropped):** `open()` return values (217 rows, p2-none-open — paired json decoders carry the label), `argparse.add_argument` declarations (112 rows, p2-none-add-argument), `httpx.stream` response bodies (p2-none-httpx — written to disk, never executed), the 129 Tier-B env reads, the 20 non-`get_cluster` socket.recv rows, and the 10 in-process json rows.

**Diagnostics-only seeds (not in labels.json as source entries):** the wrapper / public-API parameters of §3. These are the labels' recorded coverage gaps, rendered per the task directive as diagnostics sources — never formal.

### 1.2 MySinks::isSink(node, passKey)

Exec-API families (both pass keys; argument 0, plus argv-list elements for the non-shell shape — see §3):

| Label ID (conf) | API family | Reviewed tp sites (per-row verdicts in labels_raw_pass2.json) |
| --- | --- | --- |
| p2-snk-os-system (0.6) | `os.system` arg 0 | pslib/__init__.py:814/:834 (hadoop fs string, tp 0.75); main.py:989 (`"kill -9 " + pid`, unknown 0.45); fixed-literal sites alert nothing |
| p2-snk-os-popen (0.55) | `os.popen` arg 0 | fleet_util.py:1320/:1321 (`"echo -n " + days/hours`, tp 0.7); fixed literals elsewhere |
| p2-snk-popen (0.6) | `subprocess.Popen` arg 0 (+ list elements) | elastic/manager.py:364 (elastic_pre_hook, shell=True, tp 0.85); utils/download.py:204 (wget f-string, shell=True, tp 0.75); launch_utils training-script argv lists (candidate, designed launcher feature); shlex.split sites (structural mitigation, still matched) |
| p2-snk-subprocess-run (0.6) | `subprocess.run` arg 0 | auto_tuner/prune.py:521 (tuner-config f-string, shell=True, tp 0.65) |
| p2-snk-check-call (0.55) | `subprocess.check_call` arg 0 (the entry's evidence also covers the `subprocess.call` row at framework.py:5570) | extension_utils.py:1389/:1393 (run_cmd's check_call, shell=True); framework.py:5570 (`'dot -Tpdf ' + path`, shell=True, candidate 0.65) |
| p2-snk-check-output (0.5) | `subprocess.check_output` arg 0 (+ list elements) | extension_utils compiler argv/scalar rows (candidate 0.5); nvsmi.py:66 (candidate 0.45); fixed argv lists alert nothing |
| p2-snk-shell-execute-cmd (0.65) | `core.shell_execute_cmd` arg 0 | fleet/utils/fs.py:506 (`exe_cmd = f'{self._base_cmd} -{cmd}'`, tp 0.65) — only repo site, grep-verified |

Wrapper-parameter sinks (formal key only; parameter node of the wrapper, per the labels' `flow_kind: param`):

| Label ID (conf) | Wrapper parameter | Terminal exec inside the wrapper (verified) |
| --- | --- | --- |
| p2-snk-run-shell-command (0.6) | `run_shell_command` cmd — base/core.py:184, non-self idx 0 | `Popen(cmd, shell=True)` core.py:187 |
| p2-snk-run-cmd (0.65) | `run_cmd` command — extension_utils.py:1379, idx 0 | `check_call(command, shell=True)` :1389/:1393 |
| p2-snk-hdfs-run-cmd (0.65) | `HDFSClient._run_cmd` cmd — fs.py:500, idx 0 (CSV idx 2 → reviewed 0) | `core.shell_execute_cmd(exe_cmd, ...)` fs.py:506 |
| p2-snk-call-cmd (0.6) | `call_cmd` cmd — topology.py:20, idx 0 | `Popen(cmd, shell=True)` topology.py:21 |
| p2-snk-jit-compile (0.65) | `_jit_compile` file_path — extension_utils.py:1325, idx 0 (CSV idx 1 → reviewed 0) | `'cd {ext_dir} && … build'` → `run_cmd` :1354 → check_call(shell=True) |
| p2-snk-check-abi (0.5) | `check_abi_compatibility` compiler — extension_utils.py:1399, idx 0 | `check_output(['which', compiler])` / `[compiler, '-dumpfullversion', …]` :1408/:1433 (argv-list only) |

### 1.3 MySanitizers::isBarrier(node, passKey)

| Label ID | API | Verdict | Model |
| --- | --- | --- | --- |
| (none) | — | — | **`none()`** — zero sanitizer entries of any classification exist in labels.json |

Evidence (phase1_review.md §4, re-verified in tree): `startswith("hdfs:")/("afs:")` at pslib:801/:819 is branch selection only (`hdfs:; cmd` passes); the `memory_estimation_tool` existence check (prune.py:503-506) and the env length check (process_context.py:59-62) filter nothing character-wise; `shlex.split` + argv-list Popen (optimization_tuner.py:462/:477, parallelizer.py:412-417) is a real structural mitigation but was not a CSV candidate and does not neutralize argument injection — it is documented, not modeled as a barrier.

### 1.4 MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, passKey) — both keys

| Step | Label basis | Evidence (verified in tree) |
| --- | --- | --- |
| `parsedNamespaceAttrStep` | p2-src-parse-known (connects the labeled source to the labeled sink) | mirrors python-all `ArgumentParserAnyAttributeStep` (Stdlib.qll, covers parse_args only) for `parse_known_args`; load-bearing for fleet/launch.py:257 → manager.py:364 |
| `downloadDispatchStep` | labels.json metadata coverage-gap note; p2-snk-popen evidence (utils/download.py:204 tp 0.75) | download.py:219-222 dict `{'get': _get_download, 'wget': _wget_download}`; dispatch call `_download_methods[method](url, fullname)` at :254 — not natively resolvable |
| `jitCompileStep` | p2-sum-run-cmd-call evidence row :1354 | extension_utils.py:1325-1354: file_path → dirname/basename (:1329/:1330, not taint-tracked by python-all) → f-string → `run_cmd(compile_cmd)` :1354 |
| `runCmdStep` | p2-sum-run-cmd-call (candidate 0.55) | run_cmd param → check_call args :1389/:1393; label-mandated redundancy over native flow (maltrail/dcnnt-py policy) |
| `runShellCommandStep` | p2-sum-run-shell-command-call (fp call-site rows) | run_shell_command param → Popen arg core.py:187; the fp verdict applies to the fixed ldd/grep operands at the label's call sites (:198/:225/:229), not to the propagation edge, which is threat-neutral |

---

## 2. Source/sink evidence for every effective rule

All line numbers re-verified against `Paddle_vuln` in this step (tree == DB snapshot; DB `codeql-database.yml` sha `e64a054ff…`).

**Formal source→sink chains the model is expected to complete (Phase-2 run will confirm):**

1. **CLI → shell (manager.py:364, the highest-confidence tp, 0.85).** `fleet/launch.py:244` declares `--elastic_pre_hook` ("elastic pre_hook shell cmd"); `:257` `known_args, _ = parser.parse_known_args()` (source, p2-src-parse-known); `:743` `args = _parse_args()`; `:768` `launch_elastic(args, distribute_mode)`; `elastic/__init__.py:55` `ElasticManager(args, etcd_client)`; `manager.py:127-128` `self.args = args`; `:358-370` `if not self.args.elastic_pre_hook: return … subprocess.Popen(self.args.elastic_pre_hook, env=…, shell=True)` (sink p2-snk-popen). Native steps cover parse-result → tuple unpack → return → param → attribute store; the object→attribute-read hop for parse_known_args is `parsedNamespaceAttrStep`.
2. **sys.argv → relaunch command.** `fleet/launch.py:364-365` `original_args = sys.argv[1:]; os.environ['PADDLE_ORIGINAL_CMD_ARGS'] = " ".join(original_args)` (source p2-src-sysargv); `auto_parallel/static/parallelizer.py:405-417` re-expands it into the relaunch command (sink family subprocess.Popen; the shlex.split+argv-list form is the recorded structural mitigation — argument-level injection still matches the element sinks).
3. **fleet launch CLI → training command.** `fleet/launch.py:167` `base_group.add_argument('training_script_args', nargs=REMAINDER)`; parsed `args.training_script` / `args.training_script_args` reach `fleet/launch_utils.py:828-833` `cmd = [sys.executable, '-u', args.training_script] + args.training_script_args` → `Popen(cmd)` at :833 (non-shell argv-list — element sinks, by-design launcher feature flagged for triage).
4. **Auto-tuner config → shell string.** `auto_tuner/utils.py` json.load of the tuner config (source p2-src-json-load family) → `prune.py:495-520` `memory_estimation_tool`/`cur_cfg`/`model_cfg` values → f-string `memory_estimation_cmd` → `subprocess.run(..., shell=True)` at :521 (tp 0.65).
5. **Hadoop config → os.system / core.shell_execute_cmd.** pslib/__init__.py:795-834: `fleet_desc.fs_client_param` (`fs_name`, `fs_ugi`, `hadoop_bin`) + `model_path`/`model_proto_file` concatenated into `cmd` → `os.system(cmd)` at :814/:834 (tp 0.75); `fs.py:483-495` `_base_cmd` from `hadoop_home`/`configs` → `:501` `exe_cmd = f"{self._base_cmd} -{cmd}"` → `:506` `core.shell_execute_cmd(exe_cmd, 0, 0, redirect_stderr)` (tp 0.65). The `fleet_desc` protobuf side is a recorded modeling gap (§5) — only the reachable `model_path`/`model_proto_file` parameters (diagnostics seeds) and any config-decoded values complete paths.
6. **Env → compiler/launcher commands.** `extension_utils.py` `os.environ.get('CUDA_HOME')`/`os.getenv('CC')`-family reads (Tier-A env sources; e.g. `:669`/`:684` area) feed compiler command construction reaching `check_output`/`run_cmd` sinks; `launch/context/args_envs.py:225-226` `parse_known_args()` + `os.getenv('PADDLE_TRAINER_ID')` at the launch CLI boundary.
7. **Download URL → wget shell string.** `utils/download.py:117` `get_path_from_url(url, …)` → `:225` `_download(url, …)` → `:254` `_download_methods[method](url, fullname)` (dispatch step) → `:199-206` `_wget_download`: `command = f'wget -O {tmp_fullname} -t {DOWNLOAD_RETRY_LIMIT} {url}'`; `Popen(command, shell=True)` at :204 (tp 0.75). The public url parameter is a diagnostics-only seed per the task directive.
8. **fleet_util days/hours → os.popen.** `fleet_util.py:1290` `get_online_pass_interval(self, days, hours, …)`; `:1320/:1321` `os.popen("echo -n " + days/hours)` (tp 0.7). Parameters are diagnostics-only seeds.

**Sinks verified in tree:** all 14 `os.system`/`os.popen` sites, 43 subprocess-family sites, `core.shell_execute_cmd` (1 site), and the six wrapper signatures (core.py:184-189; extension_utils.py:1325-1354, 1379-1396, 1399-1440; fs.py:475-514; topology.py:20-33) — shapes and shell=True flags match the extraction CSV's `exec_mode` column (cross-checked in Phase 1, spot re-verified here).

---

## 3. Parameter indices and controllability decisions

Index convention (labels.json + phase1_review.md §6): **`arg_index` counts the first non-self parameter as 0** — opposite of maltrail's convention, matching this project's CSV/labels. CodeQL `Function.getArg`/`Parameter.getPosition` counts `self` at 0, so `methodParam(…, nonSelfIndex)` uses `f.getArg(nonSelfIndex + 1)`; module functions use `f.getArg(index)` directly.

| Function (site) | Label index | Controllability judgment |
| --- | --- | --- |
| `run_shell_command` cmd (core.py:184) | 0 | wrapper param → `Popen(cmd, shell=True)`; current call sites pass fixed ldd/grep strings (fp) — the *parameter* is the reviewed sink; caller-controlled in general |
| `run_cmd` command (extension_utils.py:1379) | 0 | wrapper param → `check_call(command, shell=True)`; fed by cpp_extension build helpers with user-API-derived paths |
| `HDFSClient._run_cmd` cmd (fs.py:500) | 0 (CSV said 2; review corrected) | first non-self param, concatenated into `exe_cmd` → `core.shell_execute_cmd` |
| `call_cmd` cmd (topology.py:20) | 0 | wrapper param → `Popen(cmd, shell=True)`; current call sites fixed (lscpu/lspci) |
| `_jit_compile` file_path (extension_utils.py:1325) | 0 (CSV said 1; review corrected) | from `cpp_extension.load` user API; reaches the `'cd … && … build'` shell string |
| `check_abi_compatibility` compiler (extension_utils.py:1399) | 0 | reaches `check_output` argv lists only — argument-injection exposure, no shell |
| `subprocess.{Popen,run,call,check_call,check_output}` | 0 | arg 0 = shell command string, or the argv list / its elements (see below) |
| `os.system` / `os.popen` / `core.shell_execute_cmd` | 0 | the shell command string |
| Diagnostics seeds: `get_path_from_url` url (0), `_download` url (0), `_wget_download` url/fullname (0/1), `get_online_pass_interval` days/hours (0/1), `IrGraph.draw` save_path/name (0/1), `HDFSClient.__init__` hadoop_home/configs (0/1), `PSLib.load_one_table` model_path (1), `PSLib._load_one_table_from_paddle_model` model_path/model_proto_file (2/3) | — | public-API / config-boundary parameters recorded as coverage gaps; diagnostics-only, never formal sources |

**Shell-string vs argv-list modeling (task directive, modeled separately in `subprocessSink`):**
- shell command **string** (all `os.system`/`os.popen`, `shell=True` subprocess, `core.shell_execute_cmd`): dangerous argument = arg 0, the whole string (metacharacter injection);
- non-shell argv **list** (launch_utils.py:606/:610/:833 etc., `check_output(['which', compiler])`): dangerous arguments = the individual `List` elements (`getAnElt()`), and additionally the list node itself since python-all's `containerStep` (TaintTrackingPrivate.qll:169, `listStoreStep`) propagates element taint to the list — both shapes are covered, and the distinction is per actual dangerous argument, not duplicated predicates.

**Internal-wrapper directive compliance:** no wrapper parameter is a formal source. The six sink-side wrapper params appear as *sinks* (the reviewed `flow_kind: param` labels), which is the mlflow/maltrail rendering; their propagation to the dangerous call is verified by the diagnostics query, never credited to the formal result.

---

## 4. Sanitizer and summary modeling evidence

**Sanitizers — empty set, `none()`:** see §1.3. No shlex/pipes quote, no allow-list, no metacharacter-neutralizing check exists on any reviewed path (phase1_review.md §4; re-verified: the only string construction on the tp paths is raw `+` concatenation, `%`-format and f-strings, all taint-preserving).

**Summaries — five steps, all conditional (never unconditional propagation):**
1. `parsedNamespaceAttrStep` — verbatim mirror of python-all 7.1.2 `Stdlib.qll` `ArgumentParserAnyAttributeStep` (which states: "if result of `parse_args` is tainted … then the parsed values accessed on any attribute lookup is also tainted"), extended to `parse_known_args` only (the stdlib already handles `parse_args`). Without it, chain 1 of §2 stops at `self.args`, because whole-object taint does not cross attribute reads for parse_known_args namespaces.
2. `downloadDispatchStep` — the dict-of-functions call `_download_methods[method](url, fullname)` (download.py:254) cannot be resolved natively; the step fans into exactly the two functions in the dict (:164 `_get_download`, :199 `_wget_download`) at positions 0/1 — same pattern as maltrail's dynamic-dispatch step.
3. `jitCompileStep` — bridges `os.path.dirname`/`os.path.basename` (extension_utils.py:1329/:1330), which python-all does not taint-track (checked: stringManipulation covers str methods, `%`-format and f-strings only), from `_jit_compile`'s file_path to the `run_cmd(compile_cmd)` argument at :1354 — the exact hop the p2-sum-run-cmd-call evidence row documents.
4. `runCmdStep`, 5. `runShellCommandStep` — parameter→terminal-exec edges rendered at the parameter level (mlflow `execCmdStep` precedent); label-mandated redundancy over native intra-function flow so the edges survive built-in-model changes. No step creates taint from nothing and every step is pinned by call shape or (file, line).

---

## 5. Uncovered APIs, dynamic calls, and known limitations

1. **`fleet_desc` protobuf config (pslib/fs.py tp sinks)** — the `fs_client_param` values are protobuf message fields, invisible to the CSV extraction and to data flow (C++-populated). No source or step was invented for them (task directive: no evidence-free edges); the pslib sinks are still reachable via the `model_path`/`model_proto_file` parameters (diagnostics seeds) and any config-decoded formal sources.
2. **Dynamic dispatch `_download_methods[method](...)`** — covered by `downloadDispatchStep`; other dict-based dispatches (e.g. `_download_methods` is the only one on a reviewed path) are not modeled.
3. **Dynamic import / C++ bindings** — `core.shell_execute_cmd` is matched syntactically by attribute name (grep-verified unique in `python/paddle/`; the binding module itself is a compiled `.so`, not import-resolvable). `etcd.get_prefix` receivers are typed clients; matched by method name within the 5 reviewed files.
4. **API-graph recall of the parse_known_args chain** — `parsedNamespaceAttrStep` relies on `getAValueReachableFromSource()` following known_args → return → param → `self.args`; API graphs are approximate. If the Phase-2 run drops the manager.py:364 path, the fix belongs in MySummaries (e.g. pin an explicit `self.args` attr step), not in promoting `self.args.elastic_pre_hook` to a source.
5. **`from subprocess import <exec>` / `from os import <exec>` aliases** — no such imports exist in the tree (extraction-verified); fallback branches are kept in `subprocessExecCall`/`osExecCall` and yield no rows today.
6. **`os.exec*`/`os.spawn*` family** — not observed in the tree (extraction OsProcessExecCall expected no rows); not modeled.
7. **Launch `Popen` argv-list sites (13 rows)** — designed launcher feature (`training_script` + REMAINDER); matched by the element sinks, flagged for by-design vs argument-injection policy triage in Step 6 (phase1_review.md §6).
8. **shlex.split + argv-list relaunch (parallelizer.py:412-417, optimization_tuner.py:462/:477)** — metachar-safe but not a barrier (argument injection remains); element sinks stay live there.
9. **`main.py:989` `os.system("kill -9 " + pid)`** — second-order (pid from `fuser` output, unknown 0.45); matched by the os.system family; no taint source expected to reach it.
10. **`base/__init__.py:193-196` `sys.argv[0]` (init_glog)** — labeled source rows but no exec sink downstream; harmless.
11. **Snapshot-pinned lines** — 1809/1829 (utils.py), 1354/1389/1393 (extension_utils.py), 187 (core.py), 254 (download.py), fs.py wrapper params; correct for sha `e64a054ff…`. Re-verify pins if the tree moves.
12. **No compile was executed** (task directive: generate files only). Idiom risk is minimized by reuse from this project's compile-verified extraction queries and 1:1 mirroring of python-all 7.1.2 library code; `codeql query compile` must be the first step of the run phase.

---

## 6. Modeling principles (consistent with the other project experiments)

1. **Render from reviewed labels only** — every formal predicate family cites its label id(s); `none`/fp entries are documented as rejected, never silently dropped (maltrail principle 1). Deviation from maltrail's tp-only formal key is forced by this project's label state (all candidate) and follows the autogluon all-candidate precedent; precision is tagged `low` to carry the candidate state into the finding metadata.
2. **Threat model = invoking user / cluster peer** — CLI args, env, config files, etcd/socket peer data are untrusted; in-process metadata (profiler/quanter/checkpoint json) is not (dcnnt-py/maltrail precedent: local-user input stays trusted in web projects; here the CLI user IS the boundary, so sys.argv/argparse are sources — the Paddle-specific reviewed decision).
3. **Signature-level matching with positional precision and file pinning** — each family is restricted to exactly the raw rows the labels reviewed (Tier-A env files, json config files, parse files, etcd files, socket lines); wrapper params are pinned by (file, class, function, non-self index).
4. **Location/shape pinning for load-bearing edges** — summary steps and dispatch steps are pinned to verified (file, line) or call shapes; no unconditional propagation exists anywhere.
5. **Barriers only with evidence** — zero sanitizer labels ⇒ `none()`, never an unconditional block or unconditional taint.
6. **Wrapper parameters are never auto-promoted to sources** — they are sinks where the labels say so (flow_kind param), and their propagation is verified by a separate diagnostics query whose results are excluded from the formal report (task directive; autogluon diagnostic precedent).
7. **Shell-string vs argv-list modeled per actual dangerous argument** — arg 0 for shell strings; individual list elements (plus the list node, which containerStep already taints) for non-shell argv lists.
8. **No execution in this step** — files only; compile and analysis deferred.

---

## 7. API compatibility verification (local pack cache, `~/.codeql/packages/codeql/python-all/7.1.2`)

- `DataFlow::ConfigSig` (isSource/isSink/isBarrier/isAdditionalFlowStep), `TaintTracking::Global<Config>`, `PathGraph`, `PathNode`, `flowPath` — WORKFLOW.md 5.2.1 contract, used identically by the maltrail/autogluon/bikeshed/mlflow artifacts.
- `DataFlow::exprNode`, `DataFlow::parameterNode` — official usage in `frameworks/Websockets.qll`; reused from this project's Phase-1 queries.
- `Call.getFunc().(Attribute).getName()/getObject().(Name).getId()`, `Call.getPositionalArg`, `List.getAnElt()`, `Subscript.getObject()`, `Attribute.getName()/getObject()`, `Assign.getATarget()` (store exclusion), `Function.getArg/getEnclosingScope` (+ `instanceof Class`, `Class.getName()`), `Parameter.isSelf()/getPosition()`, `Import.getAnImportedModuleName()/getScope().(Module)`, `Call.getEnclosingModule()`, `getLocation().getFile().getRelativePath()/getStartLine()` — all reused from this project's compile-verified `iris/extraction/{sources,sinks}.ql`.
- `API::moduleImport("argparse").getMember("ArgumentParser").getReturn().getMember("parse_known_args").getReturn().getAValueReachableFromSource()` and `nodeTo.(DataFlow::AttrRead).getObject()` — 1:1 mirror of `semmle/python/frameworks/Stdlib.qll` `ArgumentParserAnyAttributeStep` (verified in the cached pack source).
- `containerStep`/`listStoreStep` element→list taint — `semmle/python/dataflow/new/internal/TaintTrackingPrivate.qll:164-186`; `%`-format and f-string steps — same file, lines 141/157.
- `import libraries.MySources` dot-syntax intra-pack imports from `queries/` — pack root is `iris/` (qlpack.yml); same shape as the maltrail queries.

---

## 8. Files

```
iris/
├── libraries/MySources.qll          # formal source families + diagnostics param seeds, pass-key dispatch
├── libraries/MySinks.qll            # exec-API arg-0/argv-element sinks + wrapper-param sinks (formal key)
├── libraries/MySanitizers.qll       # empty barrier set (none()) — label state
├── libraries/MySummaries.qll        # namespace-attr / download-dispatch / jit / run_cmd / run_shell_command steps
├── queries/Pass2_CommandInjection.ql           # formal @kind path-problem, severity error, py/augur/Paddle/pass2-command-injection
├── diagnostics/Pass2_CommandInjectionDiagnostics.ql  # wrapper-param propagation, severity warning, NOT formal
└── report/query_generation_notes.md # this file
```

No source files, CodeQL database, Phase-1 labels, or extraction artifacts were modified; only the files under `iris/{libraries,queries,diagnostics,report}/` were generated.

**Suggested execution (run phase, sequential per WORKFLOW.md 5.2.4):**

```bash
codeql query compile iris/queries/Pass2_CommandInjection.ql --search-path iris
codeql database analyze "C:\Users\lzh\Desktop\github\PyVul-main\dataset\codeql_databases\Paddle-db" \
  iris/queries/Pass2_CommandInjection.ql --format=sarifv2.1.0 --output=iris/results/pass2.sarif
# diagnostic (NOT counted as findings):
codeql database analyze "C:\Users\lzh\Desktop\github\PyVul-main\dataset\codeql_databases\Paddle-db" \
  iris/diagnostics/Pass2_CommandInjectionDiagnostics.ql --format=sarifv2.1.0 --output=iris/results/pass2_diagnostics.sarif
```
