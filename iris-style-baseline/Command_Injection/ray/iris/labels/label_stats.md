# Label Statistics — ray, Pass 2 (CWE-78)

**Run ID:** `ray-iris-pass2-20261016` · Generated 2026-10-16
**Snapshot:** source tree and CodeQL database (ray-db) both at sha `79a5643` (sourceLocationPrefix
== tree). Every CSV line number was re-read from the tree during labeling; each entry's first
evidence string is the verbatim source line at its location (pulled from the tree by
`labels/_work/build_labels.py`).

## Labeling session

| Item | Value |
| --- | --- |
| Model | glm-5.3 (in-session labeling by the agent's underlying LLM; no external LLM API calls) |
| Batches | 7 (batch-1 dashboard boundary sources 358 rows · batch-2 serve/client/runtime-env sources 422 · batch-3 CLI boundaries 874 · batch-4 env reads 738 · batch-5 open/decode rows 904 · batch-6 runtime-core sinks 204 · batch-7 CI/release/doc sinks 328) |
| Candidate rows processed | 3828 (sources.csv 3296 + sinks.csv 532) — **all rows dispositioned** |
| Rows merged into sibling entries | 615 (source-side api+ast decode facets of one call; sink-side arg api/ast + shell_true + cmd_format + indirect_exec + internal_exec_wrapper facets of one exec call site) |
| Supplementary (out-of-CSV) entries | 0 |
| Final label entries | 3213 (pass 2) + 1 pass-1 schema stub with 0 entries |
| Re-ask threshold | 0.55 — entries at/below: 346 (all at exactly 0.5, CLI/workload/CI-dev-tooling boundary candidates; recorded as human-review requests instead of re-ask, since the in-session model already reviewed the per-site source context dumps in `labels/_work/dump_*.txt`) |
| Minimum confidence used | 0.5 |

## Entries by role × classification

| Role | tp | candidate | fp | total |
| --- | ---: | ---: | ---: | ---: |
| source | 331 | 1402 | 0 | 1733 |
| sink | 12 | 254 | 26 | 292 |
| sanitizer | 0 | 0 | 0 | 0 |
| summary | 2 | 0 | 0 | 2 |
| none | 0 | 0 | 1186 | 1186 |
| **total** | **345** | **1656** | **1212** | **3213** |

Accept / reject / unresolved by label entry: **accepted (tp) 345 · rejected (fp) 1212 ·
unresolved (candidate, human review) 1656**. By raw CSV row (3828 rows, before merging):
**tp 402 · candidate 2037 · fp 1389** — the exact per-row verdicts are in
`labels/labels_raw_pass2.json` (`source_row_dispositions` + `sink_row_dispositions`, every row
mapped to its entry id; zero rows skipped).

Confidence histogram (entries): 0.5×346 · 0.55×1215 · 0.6×1244 · 0.65×224 · 0.7×107 · 0.75×59 ·
0.8×6 · 0.85×8 · 0.9×2 · 0.95×2.

## Confirmed (tp) sinks — 8 exec sites (12 entries incl. wrapper functions)

| # | Entry | Site | Conf | Notes |
| --- | --- | --- | --- | --- |
| 1 | p2-e-0332 (+ p2-e-0330 `_exec_entrypoint` wrapper) | `dashboard/modules/job/job_manager.py:229` `subprocess.Popen(self._entrypoint, shell=True, ...)` | 0.95 | Submitted job entrypoint executed through a shell; remotely reachable via unauthenticated POST /api/jobs/ (job_head.py:273 → utils.py:140 → job_agent). Arg 0 is the command string; no quoting/allowlist on the path. |
| 2 | p2-e-0395 (+ p2-e-0394 `cpu_profile` wrapper) | `dashboard/modules/reporter/profile_manager.py:104` `asyncio.create_subprocess_shell(cmd, shell=True)` with `cmd = f"py-spy record -o {profile_file_path} -p {pid} -d {duration} -f {format}"` | 0.9 | `format` arrives raw from `req.query.get("format")` (reporter_head.py:351, default only, no validation) over gRPC (reporter_agent.py:358) and is interpolated unquoted into the shell command; also part of the output path. |
| 3 | p2-e-0393 (+ p2-e-0392 `trace_dump` wrapper) | `dashboard/modules/reporter/profile_manager.py:74` `asyncio.create_subprocess_shell(cmd, shell=True)` with `cmd = f"py-spy dump -p {pid}"` | 0.8 | Same chain via /worker/traceback, /task/traceback; pid is integer-typed on both the HTTP (`int(req.query["pid"])`) and protobuf sides — coercion documented, blocks metacharacters but the site remains a genuine remote-reachable shell exec. |
| 4 | p2-e-0763 | `python/ray/_private/runtime_env/context.py:95` `os.execvp("bash", args=["bash", "-c", command_str])` | 0.8 | Worker replaced by `bash -c` of a string joining `command_prefix` (conda activate fragments from the runtime_env config, conda_env_name not shell-quoted, conda.py:404) + escaped passthrough args; DYLD_LIBRARY_PATH prepended unescaped. Tainted operand is arg 1 (args list); CSV row carried arg 0. |
| 5 | p2-e-0333 | `dashboard/modules/job/job_manager.py:258` watchdog `subprocess.Popen(f"while kill -s 0 {parent_pid}; ...", shell=True)` | 0.6 (candidate) | Internal pids only — listed here for context, classified candidate not tp. |
| 6 | p2-e-0762 (+ p2-e-0759 `exec_worker` wrapper) | `python/ray/_private/runtime_env/context.py:88` `subprocess.Popen(cmd, shell=True)` (Windows worker) | 0.75 | cmd list = command_prefix + executable + passthrough args; runtime_env origin. |
| 7 | p2-e-1111 / p2-e-1112 (+ p2-e-1110 `_run_and_process_output` wrapper) | `python/ray/autoscaler/_private/subprocess_output_util.py:243` `process_runner.check_call(cmd)` (dynamic dispatch) and `:251` `subprocess.Popen(cmd)` | 0.7 | Autoscaler exec engine for the ssh/docker line built from the user cluster config; argv mode locally but the remote ssh command is executed by the node shell. |
| 8 | — | (job pipeline transfer: `parse_and_validate_request` call sites labeled **summary** tp 0.75, job_agent.py:35 / job_head.py:275) | 0.75 | Taint step connecting `await req.json()` to the JobSubmitRequest that reaches the :229 sink. |

Static-literal / internally-derived exec sites rejected as fp sinks (26 entries): the
`sudo -n true` probe (profile_manager.py:52), the static multi-line py-spy `ray stack` script
(scripts.py:1829), `nvidia-smi` (spark/utils.py:303), `df -h` (benchmark_worker_startup.py:151),
`pip uninstall -y ray` (wheels.py:432), static argv `ray start/stop` / WMIC / accelerator probes,
`sleep 20` example, cluster_utils fixed argv lists, and `install_nightly`'s
wheel-from-shipped-yaml pip install.

## Confirmed (tp) sources — 331 entries

Remote boundaries of the unauthenticated service surface (per-family counts):

- **Dashboard HTTP API reads (116 rows → entries incl. job/reporter/serve raises):** query /
  match_info / headers / body reads across dashboard head + agent modules — job (66 tp incl.
  the submission body chain), state (43), log (20), test (19), serve agent (13), snapshot (9),
  event (5), node (5), actor (3), healthz/metrics (4), reporter_head (29+17, raised to 0.75 with
  command-relevant rationale).
- **gRPC message fields (78 rows):** reporter agent pid/duration/format/native (tp 0.85 — direct
  py-spy command feed), ray client server/proxier servicer fields (tp 0.65), log agent fields
  (tp 0.6), event_head event_strings (tp 0.65).
- **Handler / servicer parameters (151 tp entries):** aiohttp route-handler `req` params (tp
  0.65-0.75), gRPC servicer request params (tp 0.6-0.75).
- **Runtime env agent HTTP body reads (3):** `await request.read()` of
  GetOrCreateRuntimeEnvRequest (tp 0.8 — runtime_env payloads drive conda/pip subprocess chain
  and worker exec).
- **Serve ingress adapters (2, http_adapters.py)** and serve agent `Schema.parse_obj(await
  req.json())` (2, tp 0.75); serve controller downstream decodes kept candidate.
- **Job payload decodes (json.loads of runtime_env_json / serialized job info, 10):** tp 0.7.

## Candidate (unresolved) sources — 1402 entries (queued for human review)

- **Environment reads (866 field entries, 0.5-0.65):** operator-set env vars — same-trust
  configuration; raised individually where a command path exists: EDITOR (tune/cli/commands.py:26,
  0.65 → subprocess.call argv[0]), DYLD_LIBRARY_PATH (runtime_env/context.py:81, 0.65 →
  concatenated unescaped into the `bash -c` string), RAY_JOB_STOP_SIGNAL (0.55, equality check
  only), RAY_ON_SPARK_* (0.5, int-coerced).
- **CLI parameters (385 param entries, 0.5-0.65):** click-bound `ray`/state/serve/tune/release-CLI
  function params and argparse workload mains — local-operator boundary; `ray job submit
  --entrypoint` raised to 0.6 (same downstream exec as the remote path).
- **Config-file and decode rows (151 return entries, 0.55-0.7):** cluster-config yaml.safe_load /
  open pairs (commands.py exec_cluster paths, autoscaler live reload, cluster_dump,
  launch_and_verify), serve CLI configs, runtime_env serialized payload decodes, remote-API
  response decodes in release tooling, tune web-server request decodes.
- 512 click decorator entries (511 CSV rows) → role `none` (fp): registration nodes, not
  data-flow values (CLI values enter via the labeled param rows).

## Rejected (fp) entries — 1186 `none` + 26 sink-role fp

- Locally authored file opens (checkpoints, tune trial state, logs, metrics outputs, /proc and
  /sys reads, temp state) and their json/yaml decodes — no remote origin.
- Documentation example code (doc/source/** request reads, parse_obj examples, subprocess
  examples).
- Message-formatting `.format()`/`%` rows matched by the cmd_format heuristic (assertion texts,
  log messages, error strings, path joins) — not commands.
- Static-literal / fixed-argv exec sites (see fp sink list above).

## Summary entries — 2

- `parse_and_validate_request(req, JobSubmitRequest)` call sites (job_agent.py:35,
  job_head.py:275, tp 0.75): the taint-preserving transfer from the decoded request body to the
  JobSubmitRequest that reaches the entrypoint Popen.

## Sanitizers — 0 entries (documented observations)

- `int()` coercion at reporter_head.py:348 (duration) / :416 (pid): neutralizes shell
  metacharacters for those fields but **not** for the raw `format` string (:351).
- `shlex.quote` in the autoscaler (command_runner.py:9/86, docker.py:7, commands.py:77): quotes
  selected env-var fragments only; caller cmd strings are still appended raw
  (command_runner.py:304-309 `cmd += "; sudo shutdown -h now"`).
- pydantic/dataclass validation in the job and serve pipelines: shape validation only; the
  entrypoint is typed as a free string (pydantic_models.py:67).
- Cluster config `fillout_defaults`/`validate`: structure validation, not command neutralization.

None qualifies as a complete CWE-78 barrier, so no sanitizer entries were emitted and
`MySanitizers.qll` should resolve to `none()` for this pass.

## Signature mapping notes (for library generation)

- flow_kind per labels_schema.json: request-state / message / env / cli reads → `field`; decode
  returns (json, yaml, getenv, parse_obj, open content) → `return`; handler/servicer/CLI function
  parameters → `param` (arg_index = 0-based parameter position from the CSV); sink exec arguments
  → `argument` (arg_index 0; `os.execvp` entry uses arg_index 1 — the args list carrying
  command_str, with the CSV's arg-0 noted in evidence); `internal_exec_wrapper` entries (enclosing
  function of an exec call) use `unknown`.
- Merged facets are documented per entry in `labels_raw_pass2.json` `dedup_log` (615 merged rows).
