# Augur Phase 1 — Human Review Gate (Step 3 output, Pass 2 / CWE-78, ray)

Status: **Step 3 (LLM candidate labeling) complete; pipeline intentionally halted here per user
instruction — Step 4 (library generation) and taint analysis not started.**

- Run: `ray-iris-pass2-20261016` (2026-10-16), model `glm-5.3` (in-session labeling by the
  Claude Code CLI agent's underlying LLM; no external LLM API calls). Labels:
  `labels/labels.json` (3213 pass-2 entries, schema-valid per `assets/labels_schema.json`,
  including the pass_id=1 empty stub required by the schema's `contains` clause — pass 1 was NOT
  labeled in this run), `labels/labels_raw_pass2.json` (all 3828 per-row dispositions, dedup log,
  batch records, manual-review requests). Full stats: `label_stats.md`.
- All 3828 candidate rows (sources.csv 3296 + sinks.csv 532) were dispositioned — zero rows
  skipped or silently excluded; `fp`/`none`/`candidate` are explicit labeled outcomes, not
  omissions. 615 duplicate CSV rows (api+ast decode facets; arg/shell_true/cmd_format/wrapper
  facets of one exec call) were merged into sibling entries, each merge logged with its reason in
  `labels_raw_pass2.json` `dedup_log`.

## 1. Label counts by pass and role

Per-entry (deduplicated): source 1733 (tp 331 / candidate 1402) · sink 292 (tp 12 / candidate
254 / fp 26) · summary 2 (tp) · sanitizer 0 · none 1186 (fp). Per raw CSV row: source-side
3296 rows = tp 377 / candidate 1607 / none 1310 / summary 2; sink-side 532 rows = tp 23 /
candidate 430 / fp 50 / none 29 (the message-formatting cmd_format rows).
Classifications per entry: **tp 345 · candidate 1656 · fp 1212**; per row: tp 402 · candidate
2037 · fp 1389.

API-label `tp` means confirmed genuine for the assigned role in this pass — it is **not** a
vulnerability ground-truth verdict. Two sites are exec-by-design service features (job
entrypoint, serve user code) whose security question is network reachability, which is why the
sink is labeled while the vulnerability decision is deferred to Phase 2 triage.

## 2. Top high-risk sink APIs / paths (strongest CWE-78 review candidates)

Execution semantics (shell=True vs argv list vs static literal) were verified against source,
not assumed:

1. **`dashboard/modules/job/job_manager.py:229` (p2-e-0332, 0.95)** —
   `subprocess.Popen(self._entrypoint, shell=True)` executes the job entrypoint submitted via
   unauthenticated `POST /api/jobs/` (job_head.py:273 → utils.py:140 `await req.json()` → job_agent
   → JobSupervisor). Arg 0 is the command string; no quoting or allowlist anywhere on the path.
   Designed feature (Ray Jobs runs arbitrary commands), but in this snapshot there is no
   dashboard authentication — the reachability question is the core review item.
2. **`dashboard/modules/reporter/profile_manager.py:104` (p2-e-0395, 0.9)** —
   `asyncio.create_subprocess_shell(cmd, shell=True)` with
   `cmd = f"py-spy record -o {path} -p {pid} -d {duration} -f {format}"`; `format` is a raw
   query parameter (`req.query.get("format", "flamegraph")`, reporter_head.py:351 — default only,
   no validation) forwarded over gRPC (reporter_agent.py:358). Not an exec-by-design surface:
   the most vulnerability-shaped path in the set.
3. **`profile_manager.py:74` (p2-e-0393, 0.8)** — same chain for `py-spy dump -p {pid}` via
   /worker/traceback and /task/traceback; pid/duration are int-coerced at the HTTP boundary and
   protobuf-typed (partial neutralization, documented), `native` is bool.
4. **`python/ray/_private/runtime_env/context.py:95` (p2-e-0763, 0.8)** —
   `os.execvp("bash", ["bash", "-c", command_str])`: worker command string joins
   `command_prefix` = conda activate fragments derived from the submitted runtime_env
   (conda.py:404, `conda_env_name` unquoted) + escaped passthrough args; DYLD_LIBRARY_PATH is
   prepended unescaped. Tainted operand recorded as arg 1 (args list), CSV row carried arg 0.
   Companion Windows path `context.py:88` `Popen(cmd, shell=True)` (p2-e-0762, 0.75).
5. **`python/ray/autoscaler/_private/subprocess_output_util.py:243/:251` (p2-e-1111/1112,
   0.7)** — the autoscaler exec engine (`process_runner.check_call(cmd)` dynamic dispatch +
   `subprocess.Popen(cmd)`) for the ssh/docker line built from the user cluster config
   (commands.py yaml.safe_load → SSHCommandRunner/DockerCommandRunner). Local argv mode, remote
   shell semantics on the node; shlex.quote covers only selected fragments.
6. **runtime_env conda/pip chain (candidates 0.6-0.65)** — conda_utils.py:196/:222 `Popen(cmd)`,
   runtime_env/utils.py:80 `create_subprocess_exec(*cmd)`, conda.py:79 `check_output(...)`: argv
   mode, arguments derive from the submitted runtime_env (env name, prefix, pip packages);
   argument-injection (CWE-88) flavored.
7. **`release/.../benchmark_util.py:60/:71` (0.6)** — `subprocess.check_call(cmd)` with a
   **string** cmd (implicit shell) supplied to @ray.remote runners by benchmark drivers.
8. Notable shell=True dev/test sites kept as candidates: repro-ci.py:575 (f-string ssh command),
   fake_multi_node test_utils docker commands (:219/:229/:281/:293/:370), k8s_tests:143/:259,
   ray_release/util.py:146, wheels.py:429, benchmark_worker_startup.py:261 (release-test
   entrypoint via shell).
9. Static-literal shell/argv sites rejected as fp: `ray stack` py-spy script (scripts.py:1829),
   `sudo -n true`, `nvidia-smi`, `df -h`, `pip uninstall -y ray`, accelerator/WMIC probes, doc
   examples — no input reaches the command string.

## 3. Top broad source APIs

- **Dashboard HTTP request reads (tp, 0.7-0.75)** — 116 CSV rows across head+agent modules
  (query/match_info/headers/body): job submission chain (66 tp), state (43), log (20), test (19),
  serve agent (13), snapshot/event/node/actor/metrics/healthz. The dashboard has **no
  authentication** in this snapshot, so these are genuine remote boundaries; they only produce
  alerts where a path to a sink exists.
- **Reporter profiling parameters (tp, 0.75-0.85)** — reporter_head query reads → gRPC
  CpuProfiling fields → py-spy commands (the chain behind review items 2-3); `format` raw,
  pid/duration int-coerced.
- **gRPC message fields (tp 0.6-0.85, 78 rows)** — reporter agent (direct command feed), ray
  client server/proxier servicers (data-plane, no exec path observed), log agent.
- **Runtime env agent HTTP body (tp 0.8)** — GetOrCreateRuntimeEnvRequest payloads that drive
  the conda/pip exec chain.
- **Serve boundaries (tp 0.7-0.75)** — serve_agent `Schema.parse_obj(await req.json())` and
  http_adapters Starlette ingress (user code execution by design).
- **Env reads (candidate, 0.5-0.65, 984 rows → 866 entries)** — operator-trust boundary, kept
  for conservative recall; individually raised only where a command path was read in source
  (EDITOR → subprocess argv[0]; DYLD_LIBRARY_PATH → unescaped `bash -c` concatenation).
- **CLI params (candidate, 0.5-0.65)** — click/argparse boundaries; `ray job submit --entrypoint`
  raised to 0.6 as the CLI twin of the tp submission path.
- **Cluster-config yaml.safe_load + open pairs (candidate 0.6)** — commands.py autoscaler entry
  points; config fields are executed on nodes (exec-by-design for the local operator).
- Rejected as non-boundaries: locally authored file opens and their decodes (checkpoints, logs,
  /proc), documentation example code, click decorator registration nodes (512 entries), and
  message-formatting `.format()` rows.

## 4. Sanitizers

No sanitizer entries (0). Documented partial neutralizations, none sufficient as an
`isBarrier`:

- `int()` coercion of pid/duration at reporter_head.py:348/:416 — does not cover the raw
  `format` field.
- `shlex.quote` in the autoscaler (command_runner.py:9/86, docker.py:7, commands.py:77) —
  per-fragment quoting only; caller commands appended raw (`cmd += "; sudo shutdown -h now"`).
- pydantic/dataclass request validation (job/serve pipelines) — shape validation only;
  entrypoint is a free string.
- Cluster-config schema validation — structure, not command neutralization.

`MySanitizers.qll` should resolve to `none()` for this pass.

## 5. Unresolved / low-confidence items (human review requested)

1656 candidate entries (2037 rows) are by definition unresolved and queued for this review
gate; 346 entries sit at the 0.5 confidence floor. `labels_raw_pass2.json`
`manual_review_requests` groups them into 33 rule families with reasons; the largest:

| Family | Entries | Review question |
| --- | ---: | --- |
| CI/dev tooling exec sites (git/bazel/docker/kubectl, argv or shell) | 83 | confirm CI-only exposure |
| env reads (operator trust) | ~590 | confirm no deployment exposes these as service config |
| click/argparse CLI params | 385 | confirm no service boundary wraps these CLIs |
| fake-multi-node / release-test / k8s-test shell sites | ~60 | confirm test-infra-only exposure |
| cluster-config decode/open pairs | ~40 | confirm config files are never remotely writable/servable |
| runtime_env conda/pip helpers | ~8 | confirm runtime_env is only submission-reachable |

Specific follow-ups worth manual eyes: (a) whether the reporter gRPC port is reachable off-node
(it is reached through the head, which is unauthenticated — the effective boundary);
(b) `load_package()` curl/tar argv with regex-constrained GitHub URL components; (c)
`.buildkite/copy_files.py:49` docker password (API-sourced) as an argv element; (d)
`benchmark_util.py` string-cmd check_call (implicit shell).

## 6. Process record

- Model: glm-5.3, in-session; 7 batches (358 + 422 + 874 + 738 + 904 + 204 + 328 = 3828 rows);
  per-site context dumps reviewed before each family decision are preserved in
  `labels/_work/dump_*.txt`; the deterministic build/validate scripts are
  `labels/_work/build_labels.py` and `labels/_work/validate_labels.py` (schema validation:
  PASS — every constraint of `assets/labels_schema.json` checked, including the `contains`
  pass_id=1 requirement, argument-flow arg_index constraint, enums and patterns).
- Deduplication: 615 rows merged (reasons in `dedup_log`); no candidates were dropped without a
  disposition.
- Constraints honored: no PyVul ground truth, vulnerability patch commits, CVE reports or
  external security advisories consulted; project source, the CodeQL database, the Augur
  installation and the extraction artifacts were not modified (writes were limited to
  `iris_manual/ray/iris/labels/**`).

## 7. Recommendation

Proceed to Step 4 (generate `MySources/MySinks/MySanitizers/MySummaries.qll` from the tp
entries, keeping the candidate entries out of the first query round or behind a recall flag) and
run the Pass 2 taint query, prioritizing alert triage on the job entrypoint chain and the
reporter py-spy `format` chain. The 0.5-confidence CI/dev-tooling sink candidates can be
excluded from the first run to control noise, provided the exclusion is recorded.
