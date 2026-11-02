# Phase 1 / Step 3 - LLM Candidate Labeling Review (Pass 2: CWE-78)

- run_id: `paddle-iris-phase1-step3-pass2-20261015`
- model: glm-5.3 (in-process LLM labeling by the Augur agent; no external API calls)
- batches: 11 (source families S1-S7, sink clusters K1-K4); 925 CSV candidates processed (sources.csv 858 rows + sinks.csv 67 rows); **every row labeled, none dropped**
- artifacts: `labels/labels.json` (schema-valid against `assets/labels_schema.json`, jsonschema 4.26.0), `labels/labels_raw_pass2.json` (per-row audit), `labels/label_stats.md`
- generator: `gen_labels_pass2.py` (workspace root, deterministic renderer of the decisions below; source tree, CodeQL DB and extraction outputs were not modified)
- verdict per row was decided against the real sources under `dataset/codeql_databases/Paddle_vuln/python/paddle/**`; the repository's audit-looking artifacts (vulnerability_audit_report.md, confirmed_vulns.json, cmd_sinks.csv, patches/) were NOT read, per experiment constraints.

## 1. Label counts

| role | rows (raw) | signature entries (labels.json) |
| --- | --- | --- |
| source | 367 | 11 |
| sink | 61 | 12 |
| summary | 6 | 2 |
| sanitizer | 0 | 0 |
| none | 491 | 3 |

Sink verdicts (raw): 8 tp / 36 candidate / 16 fp / 1 unknown, plus 6 wrapper call-site rows (3 fp, 3 candidate) labeled `summary`.
Source verdicts (raw): 367 source-candidate, 491 none. Dedup collapsed 3 duplicate CSV rows (identical callable+file+line).

## 2. Top high-risk sinks (tp)

1. `subprocess.Popen(self.args.elastic_pre_hook, shell=True)` - `python/paddle/distributed/fleet/elastic/manager.py:364`. The `--elastic_pre_hook` CLI option of `paddle.distributed elastic` is passed verbatim to a shell. Direct CLI → shell execution. Confidence 0.85.
2. `subprocess.Popen(f'wget -O {tmp_fullname} -t N {url}', shell=True)` - `python/paddle/utils/download.py:204` (`_wget_download`). `url`/`fullname` are function parameters supplied by user code through the public download API. Confidence 0.75.
3. `os.system(cmd)` - `pslib/__init__.py:814` and `:834`. `cmd` concatenates `fleet_desc.fs_client_param` values (`hadoop_bin`, `fs_name`, `fs_ugi` containing user/password) with `model_path`/`model_proto_file` from save/load APIs. The `startswith('hdfs:'/'afs:')` check only selects the branch; it does not neutralize shell metacharacters. Confidence 0.75.
4. `os.popen("echo -n " + days)` / `hours` - `incubate/distributed/fleet/fleet_util.py:1320/1321` (`get_online_pass_interval`), documented API parameters concatenated into a shell string. Confidence 0.7.
5. `core.shell_execute_cmd(exe_cmd, ...)` - `distributed/fleet/utils/fs.py:506`. `exe_cmd = f'{self._base_cmd} -{cmd}'` where `_base_cmd` embeds hadoop_bin/fs_ugi from the fleet distributed-strategy config (C++-backed shell exec). Confidence 0.65.
6. `subprocess.run(memory_estimation_cmd, shell=True)` - `distributed/auto_tuner/prune.py:521`. f-string interpolating the tuner-config `memory_estimation_tool` path (existence-checked only) and decoded JSON config values. Confidence 0.65.

Highest-value candidate (not yet tp): `subprocess.call('dot -Tpdf ' + dot_file_path + ' -o ' + pdf_save_path, shell=True)` - `base/framework.py:5570` inside the public `Graph.draw(save_path, name)` API; caller-controlled path segments in a shell string. Confidence 0.65.

## 3. Top broad sources (signature-level)

- `sys.argv` (field) - 7 rows, source 0.75. `master.py:107` forwards `sys.argv[1:]` into the launch command; `fleet/launch.py:364-365` packs it into `PADDLE_ORIGINAL_CMD_ARGS`, re-expanded into the `parallelizer.py:412-417` relaunch command.
- `argparse.parse_args` / `parse_known_args` (return) - 9 rows, source 0.7. Parsed fields (`training_script`, `training_script_args` REMAINDER, `elastic_pre_hook`) demonstrably reach subprocess command construction.
- `os.getenv` / `os.environ.get` / `os.environ.__getitem__` (return) - 433 rows; 304 in command-construction modules (Tier A, source-candidate 0.6), 129 in compute modules (Tier B, none). The split is recorded per-row in `labels_raw_pass2.json`.
- `json.load` / `json.loads` (return) - 35 rows; source-candidate 0.55 in launch/auto_tuner/backup_env/cluster/engine config decodes, fleet_util 0.5 (unverified), none elsewhere.
- `etcd.get_prefix` (return) - 13 rows, source 0.55 (external cluster state).
- `socket.recv` (return) - 22 rows; only the 2 `get_cluster()` rows (`auto_parallel/static/utils.py:1809/1829`, peer-supplied rank/host) are source-candidates; the other 20 (tensor/record/sync receives, incl. syntactically matched paddle tensor-recv APIs) are none.

## 4. Sanitizer list

**Empty.** No allow-list, escaping, or metacharacter-neutralizing validation was observed on any command-construction path. Specifically examined and rejected as sanitizers:

- `startswith("hdfs:")/("afs:")` in pslib and fleet_util - branch selection only; a value like `hdfs:; cmd` passes.
- `os.path.isfile`/assertion on `memory_estimation_tool` (prune.py:505) - existence check only.
- env length check in `process_context.py:59-62` (`len(v) < max_len`) - size limit only.
- `shlex.split(...)` + argv-list `Popen` without shell (`optimization_tuner.py:462/477`, `parallelizer.py:412-417`) - a genuine structural mitigation (metacharacters become literal arguments), recorded in rationales; it was not a CSV candidate, so it is not a sanitizer entry, and it does not neutralize argument-level injection.

## 5. Answers to the directed review questions

1. **Network data into plugins (validation/decryption/protocol parsing)?** The only network-message fields reaching launch logic are `socket.recv` in `get_cluster()` (peer rank/host strings, decoded and used for cluster topology - they currently feed endpoint/env data, not command strings) and etcd cluster state (drives launch decisions, endpoints). httpx download bodies are written to disk and never executed. No decryption or protocol validation step limits command parameters because no network field demonstrably reaches a command parameter - hence those rows are candidate/none rather than confirmed sources.
2. **External input / files / config / request params reaching system commands?** Yes - CLI args (`elastic_pre_hook` → shell; `training_script`/`training_script_args` → argv lists), JSON config (auto_tuner → `prune.py` shell string; controller configs → launch command lists), protobuf distributed-strategy config (`fleet_desc` → pslib/`shell_execute_cmd` hadoop strings), env (`PADDLE_ORIGINAL_CMD_ARGS` → relaunch command), and download URLs (wget shell string). File *content* itself (open()) does not reach commands; decoded json config does.
3. **subprocess/os call shapes?** All four shapes are present and were labeled individually: `shell=True` string construction (tp sites above), argv-list Popen/check_output without shell (launch_utils training commands - candidate, designed feature; nvsmi/dot/vm_stat lists), scalar argv (extension_utils.py:1440 Windows compiler), and fixed constants (core.py/role_maker/fleet_util diagnostics - fp). exec_mode from the extraction CSV was cross-checked against the real call sites and confirmed in every spot-checked case.
4. **Internal functions: Source / Sink / Summary / plain?** Source-side wrapper `backup_env.getenv_or_backup` → source (env value return; env→return summary edge also viable). Sink-side wrappers `run_shell_command`, `run_cmd`, `HDFSClient._run_cmd`, `call_cmd`, `_jit_compile`, `check_abi_compatibility` → sink (param passthrough to shell/argv execution). Their *call sites* → summary (argument → exec taint step). `ProcessContext`, `nvsmi` wrappers → plain sink candidates. All other internal functions in the CSVs are plain intermediates (none).
5. **Config-file fixed commands vs attacker-controlled input - trust boundary?** Clear boundary in `pslib`/`fs.py`: `fleet_desc` (user-supplied DistributedStrategy/hadoop config, including credentials) is *config*, but it crosses a trust boundary into `os.system`/`shell_execute_cmd` as a concatenated string - under this experiment's model (invoking user = boundary) these are tp candidates, not fixed commands. Genuinely fixed diagnostic strings (role_maker route/ip, core.py cpuinfo, vm_stat) are labeled fp.
6. **Data checks blocking dangerous characters / illegal arguments?** None found (see §4). The only structural mitigations are shlex.split+argv-list and the absence of shell in argv-list call sites.

## 6. Unresolved / low-confidence items (manual review queue)

- `launch/main.py:989` `os.system("kill -9 " + pid)` - pid parsed from fixed `fuser` output (second-order); unknown, 0.45.
- `fleet_util.py` json.loads rows - candidate 0.5; path into hadoop/xbox shell workflows not fully traced.
- `etcd.get_prefix`, `socket.recv(get_cluster)` - source-candidates whose command-injection path is unproven (topology/env only).
- Launch `Popen` argv-list rows (13 sites) - designed launcher feature; needs a policy decision in Phase 2 triage (by-design vs argument-injection finding).
- CSV arg-index discrepancies, corrected after manual verification (recorded in entries `p2-snk-hdfs-run-cmd` and `p2-snk-jit-compile`): `HDFSClient._run_cmd` CSV index 2 → labeled 0 (`cmd`); `_jit_compile` CSV index 1 → labeled 0 (`file_path`).

## 7. Coverage gaps for Step 4 (recorded, not fixed here)

- Function parameters of public APIs are not source candidates under the syntactic extraction: `paddle.utils.download` url, `fleet_util.get_online_pass_interval(days, hours)`, `Graph.draw(save_path, name)`, `HDFSClient` hadoop config. Recommend param-source or summary edges in `MySources.qll` / `MySummaries.qll` so the tp sinks above have reachable sources.
- Protobuf config objects (`fleet_desc`) carrying the pslib/shell_execute_cmd inputs are invisible to the CSV extraction; the tp sinks there may need model sinks or additional summaries.
- `pass_id: 1` block in labels.json is a deliberate empty placeholder required by the schema's `passes.contains` constraint; pass 1 is out of scope for this experiment (detection.json `selected_passes=[2]`).

## 8. Checkpoint decision

Advisory human review gate per WORKFLOW.md §4.5: labeling is complete and schema-valid; stop here. **Phase 2 is not started** per instruction.
