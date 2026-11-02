# Pass 2 (CWE-78 Command/Argument Injection) - Label Statistics

- run_id: `paddle-iris-phase1-step3-pass2-20261015`
- generated_at: 2026-10-15T11:30:01Z
- LLM model: **glm-5.3** (invoked in-process by the Augur agent)
- labeling batches: **11** (source families S1-S7, sink clusters K1-K4)
- total CSV candidates processed: **925** (sources.csv: 858 rows, sinks.csv: 67 rows; every row labeled, none dropped)
- deduplicated signature entries in labels.json pass 2: **29**; 3 duplicate CSV rows (identical callable+file+line) collapsed
- schema: validated against augur-0.3.0/assets/labels_schema.json with jsonschema 4.26.0 - VALID


## Role counts (raw per-row, all 925 candidates)

| role | source rows | sink rows | total |
| --- | --- | --- | --- |
| source | 367 | 0 | 367 |
| sink | 0 | 61 | 61 |
| sanitizer | 0 | 0 | 0 |
| summary | 0 | 6 | 6 |
| none | 491 | 0 | 491 |

## Classification counts (raw per-row)

| classification | source rows | sink rows | total |
| --- | --- | --- | --- |
| tp | 0 | 8 | 8 |
| fp | 0 | 19 | 19 |
| candidate | 858 | 39 | 897 |
| unknown | 0 | 1 | 1 |

## Source candidate families

| family | rows | raw verdict |
| --- | --- | --- |
| `os.getenv` | 295 | Tier A (S2) source-candidate 0.6 in command-construction modules; Tier B (S3) none elsewhere |
| `os.environ.get` | 61 | same Tier A/B rule |
| `os.environ.__getitem__` | 77 | same Tier A/B rule |
| `argparse.add_argument` | 112 | none 0.8 - declaration, not a flow node |
| `argparse.parse_args` | 7 | source-candidate 0.7 |
| `argparse.parse_known_args` | 2 | source-candidate 0.7 (same rule as parse_args) |
| `sys.argv` | 7 | source-candidate 0.75 |
| `open` | 217 | none 0.6 - pass-2 irrelevant (pass-1 API) |
| `json.load` | 17 | source-candidate 0.55 in launch/auto_tuner/backup_env/cluster/engine; fleet_util 0.5 candidate; none elsewhere |
| `json.loads` | 18 | source-candidate 0.55 in launch/auto_tuner/backup_env/cluster/engine; fleet_util 0.5 candidate; none elsewhere |
| `socket.recv` | 20 | source-candidate 0.5 only for auto_parallel get_cluster peer data; none for tensor/record/sync receives |
| `httpx.stream` | 2 | none 0.6 - bytes written to disk |
| `httpx.Response.iter_bytes` | 3 | none 0.6 - bytes written to disk |
| `etcd.get_prefix` | 13 | source-candidate 0.55 - external cluster state |
| `paddle.distributed.backup_env.getenv_or_backup` | 7 | source-candidate 0.6 - env wrapper return (env -> return summary edge also viable) |

## Sink verdict highlights (per-row)

| verdict | rows | representative sites |
| --- | --- | --- |
| tp | 8 | pslib os.system(hadoop cmd) x2; download.py Popen(wget f-string); fleet_util os.popen('echo -n '+days) x2; elastic/manager Popen(elastic_pre_hook, shell=True); fs.py core.shell_execute_cmd; prune.py subprocess.run(shell=True) |
| candidate | 36 | launch_utils Popen argv-lists (training_script_args); framework.py 'dot -Tpdf '+path (shell=True); cpp_extension run_cmd/_jit_compile compiler and path flows; topology call_cmd; graphviz/util_factory dot lists |
| fp | 16 | fixed-literal diagnostics: core.py cpuinfo/sysctl, role_maker route/ip, fleet_util echo $VAR, vm_stat, which nvcc/hipcc, rocm-smi, fuser |

Sink-side rows only (61 sink rows + 6 wrapper call-site rows labeled `summary`, of which 3 fp / 3 candidate).
| unknown | 1 | launch/main.py:989 os.system('kill -9 '+pid) from fuser output (second-order) |

## Batches

| batch | kind | rows | content |
| --- | --- | --- | --- |
| S1 | source | 128 | CLI boundary: sys.argv, argparse parse/add |
| S2 | source | 304 | env reads in command-construction modules (source) |
| S3 | source | 129 | env reads elsewhere (none) |
| S4 | source | 217 | open() file reads (none) |
| S5 | source | 35 | json.load/loads config decode |
| S6 | source | 20 | socket.recv peer data |
| S7 | source | 25 | httpx / etcd / getenv_or_backup |
| K1 | sink | 14 | os.system / os.popen sinks |
| K2 | sink | 40 | subprocess.* direct sinks |
| K3 | sink | 7 | internal wrapper function sinks (run_shell_command, run_cmd, HDFSClient._run_cmd, call_cmd, _jit_compile, check_abi_compatibility, core.shell_execute_cmd) |
| K4 | sink | 6 | wrapper call sites labeled summary (argument -> shell exec taint step) |

## Deduplication and exclusion record

- All 925 CSV candidate rows were labeled; no row was excluded.
- 3 duplicate rows (identical callable+file+line, e.g. pslib/__init__.py:1332, extension_utils.py:669/711) kept in labels_raw_pass2.json and collapsed in labels.json signature dedup.
- argparse.add_argument rows (112) are labeled `none`: they are option declarations, not data-flow nodes; the parsed values are covered by the parse_args/parse_known_args source entries.
- open() rows (217) are labeled `none` for pass 2 (file content is not a command parameter under this experiment's trust model); pass-1 relevance is noted for a future pass.
- Zero sanitizer entries: no concrete neutralization observed (see metadata notes in labels.json).

## Manual review queue

- launch/main.py:989 `os.system('kill -9 ' + pid)` - second-order (fuser output), unknown, 0.45.
- fleet_util.py json.loads rows - candidate 0.5, path into hadoop/xbox shell workflows unverified.
- etcd.get_prefix / socket.recv(get_cluster) - source-candidates whose command-injection path is unproven (topology/env only).
- Launch Popen argv-list rows - designed launcher feature; policy decision needed in Phase 2 triage.
