# Query Generation Notes — ray, Pass 2 (CWE-78), Augur Phase 2 Step 4–5

**Run:** `ray-iris-pass2-20261016` · generated 2026-10-16 · model `glm-5.3` (in-session)
**Inputs:** `iris/labels/labels.json` (human-reviewed Phase 1 labels, pass_id 2, cwes `["078"]`),
the ray_vuln source tree at sha `79a5643` (identical to the ray-db CodeQL database snapshot),
`augur-0.3.0/WORKFLOW.md` §5 (Phase 2), `references/python.md`, `references/patterns.md`,
`assets/taint_query.ql.tmpl`.
**Outputs:**
`libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`,
`libraries/MySummaries.qll`, `queries/Pass2_CommandInjection.ql`,
`queries/Pass2_CommandInjection_diagnostics.ql` (diagnostics-only companion, NOT a formal
result query).
**Toolchain:** CodeQL CLI 2.25.1, `codeql/python-all` 7.1.2 (pack cache; qlpack
`iris/ray-cwe78` at the iris root). Both queries passed `codeql query compile` (syntax +
API check only — **no database analysis was executed**; per instruction, generation stops
here before Step 5's `database analyze`).

Rendering follows `assets/taint_query.ql.tmpl`: `@kind path-problem`,
`@problem.severity error`, `@tags security`, `external/cwe/cwe-078`, query id
`py/augur/ray/pass2-command-injection`, `DataFlow::ConfigSig` +
`TaintTracking::Global<Pass2Config>` + `import Pass2Flow::PathGraph` + `flowPath`, libraries
imported with dotted paths (`import libraries.MySources`) and invoked as
`MySources::isSource(source, "command_injection")` etc., matching the generated predicate
interfaces exactly. The `isBarrier` predicate exists and delegates to `MySanitizers`
(WORKFLOW §5.2.3, mandatory even when empty).

## 1. Modeling principles (shared with the sibling experiments)

1. **Labels are the contract.** Only entries with classification `tp` and role
   `source`/`sink`/`summary` become predicates. The 1402 `source`/`candidate`, 254
   `sink`/`candidate`, 1186 `none`/fp and 26 `sink`/fp entries are excluded from the formal
   query (Phase 1 review recommendation: candidates stay out of the first round; they are
   retrievable later by widening the pass-key dispatch, as in the maltrail experiment).
2. **Source families generalize the labeled sites by AST shape + module scope**, mirroring
   the extraction query families (`extraction/sources.ql`): a family predicate matches the
   same request/servicer/decode shapes that produced the tp rows, scoped to the modules
   whose rows were labeled tp. No source family covers a module that only produced
   candidate/fp rows.
3. **Sinks are location-pinned to the labeled exec modules** and match the dangerous
   argument at its actual index; shell command strings and non-shell argument lists are
   modeled separately per site (task directive).
4. **No unconditional taint propagation:** the only additional flow step is the labeled
   `parse_and_validate_request` summary, strictly conditional on a call shape; barriers
   resolve to `none()` because no sanitizer label exists.
5. **Internal wrapper parameters are never auto-promoted to sources** (task directive);
   wrapper→sink local propagation is verified by the separate diagnostics query, whose
   results are excluded from the formal vulnerability result set.
6. API::Node values are converted to `DataFlow::Node` through the documented API
   (`API::CallNode` extends `DataFlow::CallCfgNode`, `getArg(i)`/`getArgByName`;
   AST expressions via `n.asExpr() = e` / `DataFlow::exprNode`; parameters via
   `DataFlow::ParameterNode`). No deprecated or non-existent AST classes are used
   (`Decorator`/`StrConst` avoided per WORKFLOW §9).

## 2. MySources — label ID ↔ predicate mapping (all 331 source tp entries)

| Library predicate (all keyed `"command_injection"`) | Label entries | Labeled sites (tp) |
| --- | --- | --- |
| `isDashboardRequestStateRead` — `req.query/match_info/headers.get(k)`, `[k]` subscripts, bare state reads | 89 field entries: job_head 10 (p2-e-0310..328, match_info ×9 + read), job_agent 4 (match_info :76/:109/:142/:170), reporter_head 29 (p2-e-0413..446), state_head 27 (p2-e-0477..519), snapshot 6, test_head 5, test_agent 1, node 2, log_head 4, event 1, actor 1 | aiohttp handler reads on the unauthenticated dashboard head/agent API; presence checks only, no charset validation (label rationales src_dashboard_http/src_reporter_head, 0.7/0.75) |
| `isDashboardRequestBodyRead` — `await req.json()/read()` | 5 field entries: job/utils p2-e-0343 (:140), log_head :69, optional_utils p2-e-0541 (:202), serve_agent :196/:280 (json) | job submission body, log proxy body, dashboard SDK body, serve deployment bodies (tp 0.7-0.75) |
| `isServeIngressRead` — Starlette `request.json()` + `raw_request.query_params` | 2 field entries: http_adapters p2-e-1603 (:75), p2-e-1604 (:100) | serve per-deployment ingress (tp 0.7; user code execution by design) |
| `isRuntimeEnvAgentBodyRead` — `await request.read()` | 3 field entries: runtime_env/agent/main.py p2-e-0732/:0733/:0734 (:153/:165/:177) | POST /get_or_create_runtime_env etc.; body is a serialized GetOrCreateRuntimeEnvRequest driving the conda/pip exec chain (tp 0.8) |
| `isDashboardRouteHandlerParam` — `req` param of @routes.<verb> handlers | 96 param entries: job_head 10, job_agent 5, serve_agent 8, serve_head 1, state 16, reporter_head 6, snapshot 3, test_head 9, test_agent 4, log_head 2, node 3, actor 2, metrics 2, healthz 2, event 1 (get_event), usage_stats 1 | the aiohttp route-table handler boundary itself (tp 0.65-0.75) |
| `isJobCliParam` — click-bound function params in dashboard/modules/job/cli.py | 33 param entries (p2-e-0247..p2-e-0297 range) + covered by labels' job-module scope | `ray job submit --entrypoint/--runtime-env`, stop, logs, status (labeled tp; see §5 caveat: local-operator CLI boundary, Phase 1 route-handler family) |
| `isGrpcServicerParam` — request param of (req*, context) servicer-shaped methods | 22 param entries: reporter_agent 3 (:348/:355/:366), log_agent 2 (:283/:373), event_head 1 (ReportEvents :71), server.py 19, proxier 16, dataservicer 1, logservicer 1 | gRPC message objects: reporter GetTraceback/CpuProfiling/ReportOCMetrics, ray client servicers (tp 0.6-0.75) |
| `isGrpcMessageFieldRead` — `request.<field>` in servicer-shaped functions | 78 message entries → 36 unique merged entries: reporter_agent 8 (pid :349/:356, native, duration :357, **format :358**, worker_id, metrics), log_agent 12, event_head 3, proxier 10, server.py 44 | reporter fields flow into the py-spy f-string commands; client fields are data-plane (tp 0.6-0.85) |
| `isJobPipelineJsonDecode` — `json.loads/load` in dashboard/modules/job/** | 5 return entries: common.py p2-e-0296/:0297 (:173 runtime_env_json, :223 serialized job info), cli.py :47 (headers JSON), serve_agent parse_obj ×2 are modeled by the next predicate | job payload decodes feeding the submission pipeline (tp 0.7) |
| `isServeAgentConfigDecode` — `<X>Schema.parse_obj(await req.json())` | 2 return entries: serve_agent p2-e-0457 (:196 ServeApplicationSchema), p2-e-0459 (:280 ServeDeploySchema) | REST deployment config decode; pydantic shape validation only (tp 0.75) |
| `MySummaries.isAdditionalTaintStep` | 2 summary entries: p2-e-0299 (job_agent.py:35), p2-e-0317 (job_head.py:275) | see §4 |

Excluded tp-side rows: none — every one of the 331 source tp entries maps to a predicate
above. The generalization from labeled sites to family predicates adds only the same shapes
(`text`/`post` body variants, `query_params` subscripts) within the same tp-labeled module
scopes; no new modules are covered.

## 3. MySinks — label ID ↔ predicate mapping (all 12 sink tp entries)

| Site | Label entries | Predicate + dangerous argument | Controllability / source evidence |
| --- | --- | --- | --- |
| `dashboard/modules/job/job_manager.py:229` `subprocess.Popen(self._entrypoint, shell=True, ...)` | p2-e-0332 (call, tp 0.95) + p2-e-0330 (wrapper `_exec_entrypoint` :208) | `isJobEntrypointExec`: API-graph `subprocess.Popen` call, **arg 0 = shell command string** (shell=True routes through /bin/sh) | entrypoint is the job submission entrypoint string: job_head.py:273 `@routes.post("/api/jobs/")` → utils.py:140 `await req.json()` → `parse_and_validate_request` → job_agent → JobSupervisor; dashboard has no authentication in this snapshot, so the value is network-client controlled. No quoting/allowlist on the path. |
| `dashboard/modules/reporter/profile_manager.py:104` `asyncio.create_subprocess_shell(cmd, ..., shell=True)` | p2-e-0395 (call, tp 0.9) + p2-e-0394 (wrapper `cpu_profile` :86) | `isPyspyShellExec`: **arg 0 = shell command string** `f"py-spy record -o {profile_file_path} -p {pid} -d {duration} -f {format}"` | `format` is raw from `req.query.get("format", "flamegraph")` (reporter_head.py:351 — default only, no validation) via gRPC `request.format` (reporter_agent.py:358); interpolated unquoted. `pid`/`duration` are int-coerced (partial neutralization, §4). |
| `profile_manager.py:74` `asyncio.create_subprocess_shell(cmd, ..., shell=True)` | p2-e-0393 (call, tp 0.8) + p2-e-0392 (wrapper `trace_dump` :67) | `isPyspyShellExec`: **arg 0** = `f"py-spy dump -p {pid}"` (+sudo/-n prefix) | pid from /worker/traceback (`int(req.query["pid"])`, reporter_head.py:416) and /task/traceback (task-resolved) via gRPC; integer-typed end to end. |
| `python/ray/_private/runtime_env/context.py:95` `os.execvp("bash", args=["bash", "-c", command_str])` | p2-e-0763 (tp 0.8) | `isRuntimeEnvWorkerExec`: **arg 1 = args list** carrying `command_str = " ".join(command_prefix + [exec_command])`; the call passes it as the keyword `args=`, so both `getArg(1)` and `getArgByName("args")` are matched (label arg_index 1; the CSV extraction row carried 0 — noted in the label evidence) | `command_prefix` = conda activate fragments from the runtime_env config (conda.py:404 `context.command_prefix += get_conda_activate_commands(conda_env_name)`, `conda_env_name` not shell-quoted); origin is the job submission runtime_env via the runtime-env agent (source family §2 row 4). DYLD_LIBRARY_PATH is prepended unescaped (context.py:78-84). |
| `context.py:88` `subprocess.Popen(cmd, shell=True).wait()` | p2-e-0762 (tp 0.75) + p2-e-0759 (wrapper `exec_worker` :47) | `isRuntimeEnvWorkerExec`: **arg 0 = argv list** `[*command_prefix, executable, *passthrough_args]` (Windows; list2cmdline quoting then cmd.exe) | same command_prefix origin as above. |
| `python/ray/autoscaler/_private/subprocess_output_util.py:251` `subprocess.Popen(cmd, ...)` | p2-e-1112 (tp 0.7) + p2-e-1110 (wrapper `_run_and_process_output` :171) | `isAutoscalerExec`: **arg 0 = ssh/docker argv list** | the autoscaler exec engine: cmd is the ssh command line built by SSHCommandRunner/DockerCommandRunner from the user cluster config (commands.py yaml.safe_load chain) and caller-supplied node commands (updater.py). Argv mode locally, but the joined remote command runs under the node's shell, so taint in any element is remote command injection. |
| `subprocess_output_util.py:243` `process_runner.check_call(cmd, ...)` | p2-e-1111 (tp 0.7, `indirect_exec` row) | `isAutoscalerExec` AST branch: attribute call `check_call` on the dynamic receiver `process_runner`, **arg 0** | `process_runner` is an injected module variable (autoscaler.py:192 `process_runner: Any = subprocess`), unresolvable through API graphs — matched syntactically, exactly like the Phase 1 extraction row. |
| `job_manager.py:258` watchdog Popen (candidate 0.6) | — | **excluded** (candidate): f-string of internal pids only | documented, not modeled in the formal key |

Wrapper-entry representation: the 5 `internal_exec_wrapper` tp entries
(p2-e-0330/:0392/:0394/:0759/:1110) label the *enclosing functions* of exec calls; a
function-definition node is not a data-flow sink, so each wrapper is represented by its
enclosed call-site predicate (same label evidence, same locations ±the def line). This is
the same policy the maltrail experiment used for its `internal_exec_wrapper` facets.

**Shell string vs argv list modeling (task directive):** arg 0 is the dangerous parameter
for every string-command exec (`Popen(entrypoint, shell=True)`,
`create_subprocess_shell`) — any taint in the string is shell-interpreted; for argv-list
execs the list node at arg 0 (`Popen(cmd_list)`, autoscaler ssh argv) or arg 1
(`os.execvp("bash", args=[...])` — arg 0 is the literal "bash") is modeled, which flags
taint reaching *any element* of the list (argument injection, CWE-88-adjacent) without
inventing shell semantics that a list-mode call does not have.

## 4. MySanitizers / MySummaries — modeling evidence

**Sanitizers: none (barrier resolves to `none()`), with the Phase 1 observations recorded
in the QLL header:**
- `int()` coercion at reporter_head.py:348 (duration) / :416 (pid): blocks metacharacters
  for those two fields but NOT for `format` (:351), so modeling a barrier at the boundary
  would over- and under-cut the labeled sink; not a complete CWE-78 barrier.
- `shlex.quote` (command_runner.py:9/:86, docker.py:7, commands.py:77): fragment-level
  quoting only; caller cmd strings appended raw (command_runner.py:304-309).
- pydantic/dataclass validation (job/serve pipelines): shape validation only;
  `entrypoint: str = Field(...)` (pydantic_models.py:67) is a free string.
None carries the evidence required by the labeling contract, so `isBarrier` stays empty —
identical to the maltrail pass-2 outcome.

**Summary (additional taint step): `parse_and_validate_request(req, request_type)`**
(labels p2-e-0299 job_agent.py:35, p2-e-0317 job_head.py:275, summary/tp 0.75).
Evidence (dashboard/modules/job/utils.py:121-148): the wrapper reads the request body
(`json_data = strip_keys_with_value_none(await req.json())`, :140) and returns the
validated request object, so taint on the request argument is transferred to the call's
return value — the labeled step connecting the dashboard request sources to the
JobSubmitRequest fields (entrypoint, runtime_env) that reach the job_manager.py:229 sink.
The step is restricted to calls of this exact wrapper by bare name (as observed at the two
labeled sites); it creates no taint from nothing and is not unconditional.

## 5. Label-faithfulness caveat (documented, labels NOT modified)

The 33 `ray job` CLI param entries (dashboard/modules/job/cli.py) and the cli.py:47
`json.loads` entry carry Phase 1 tp classification via the dashboard job-module families;
they are click CLI boundaries (local operator trust: `ray job submit --entrypoint` is the
CLI twin of the remote submission path), not aiohttp handlers. Per the labels-are-the-
contract principle they ARE modeled (`isJobCliParam`, scoped to click-bound functions in
that one file), and the query may therefore also report CLI-argument→entrypoint flows.
Triage should treat those paths as operator-trust by design; the remote paths are the
security-relevant ones. No label was edited.

## 6. Diagnostics query (NOT part of the formal results)

`queries/Pass2_CommandInjection_diagnostics.ql` is a plain select query (no
`@kind problem`): it reports LOCAL (intraprocedural) taint from any parameter of the
wrapper functions enclosing the labeled sinks to the sink arguments, validating the
modeled argument indices (trace_dump `pid`, cpu_profile `pid/duration/format`,
exec_worker `passthrough_args`/list construction, `_run_and_process_output` `cmd`) without
counting diagnostic paths as vulnerabilities. Attribute-mediated propagation
(`self._entrypoint` in `_exec_entrypoint`, `self.command_prefix` in `exec_worker`) is
outside a local query by design; it is exercised (or not) by the global query's
interprocedural field-flow steps — a triage checklist item for Step 6.

## 7. Uncovered APIs, dynamic calls, known limitations

1. **Dynamic dispatch not resolvable through API graphs** (mirrors the Phase 1
   `uncoveredCases`): the autoscaler `process_runner.check_call` (subprocess_output_util
   :243) is matched syntactically on the receiver name; `cmd_runner.run(cmd)` in
   updater.py and `SSHCommandRunner._run_helper` were never extracted as candidate rows
   and are NOT covered by any sink predicate; the autoscaler exec chain is covered only
   through the subprocess_output_util engine sites.
2. **gRPC servicer detection is signature-shape based** (a parameter matching `req.*` next
   to `context`): a non-servicer function with the same shape inside the scoped modules
   would also match — accepted recall/precision trade-off inherited from the extraction.
3. **Generated pb2/pb2_grpc modules** are outside the extracted tree, so
   `reporter_pb2.CpuProfilingRequest(...)` construction sites and servicer base classes
   are invisible; the chain head→gRPC is bridged by the head-side request reads and the
   agent-side message field sources, not by the protobuf layer itself.
4. **runtime_env kwargs/attribute chain:** `RuntimeEnvContext(**json.loads(json_string))`
   (context.py:45) → `command_prefix`/`py_executable` attribute reads rely on the standard
   taint library's field-flow steps; no evidence-based additional step was labeled for
   this in Phase 1, so none was added (no unconditional propagation). If the global query
   under-reports the runtime-env chain, the diagnostics query plus a manual check of
   context.py:47-95/conda.py:404 is the prescribed follow-up.
5. **Job pipeline attribute hops:** `JobSubmitRequest` construction from the decoded JSON
   (`validate_request_type` → `request_type(**json_data)`) and
   `JobSupervisor.__init__(entrypoint)` → `self._entrypoint` → `_exec_entrypoint` also
   depend on standard kwargs/field-flow steps; the labeled summary covers only the
   `parse_and_validate_request` hop.
6. **Candidate sinks excluded from the formal key** (recoverable later): the job watchdog
   (job_manager.py:258, internal pids), the 254 candidate exec sites in CI/release/doc
   tooling, the runtime-env conda/pip helpers (conda_utils.py:196/:222, conda.py:79,
   runtime_env/utils.py:80 — argv mode, runtime_env-config origin), cluster_dump
   (check_call of the ssh dump command), spark utils exec_cmd, tune CLI EDITOR exec, and
   the fake-multi-node docker shell sites. Their exclusion follows the Phase 1 review
   recommendation and is recorded here for the Step-6 triage.
7. **Env/config/cluster-config candidate sources excluded:** operator-trust boundaries
   (984 env rows, cluster-config yaml rows, serve CLI configs) are not sources in the
   formal query; only the remote tp boundaries are. The autoscaler exec sinks therefore
   only pair with remote sources if any exist — expected outcome: no remote source reaches
   them in this snapshot (the config file is CLI-supplied), which is the documented
   exec-by-design posture.
8. **Compile-only validation:** `codeql query compile` passed for both queries (CLI
   2.25.1, python-all 7.1.2 from the local pack cache); no `database analyze` was run, so
   alert counts, path completeness and performance are unverified at this stage by design
   (the task stops after generation).

## 8. Phase 1 artifact maintenance note (transparent disclosure)

While building the label→predicate mapping, a defect was found in
`labels/labels_raw_pass2.json` (audit artifact only): its per-row `entry` back-references
were computed against the pre-sort entry order, so after the stable id sort every row
pointed at a shifted entry id. **`labels/labels.json` itself was always correct** (ids,
locations, signatures, classifications are all derived from the entry objects after
sorting) and no label decision changed. The build script
(`labels/_work/build_labels.py`) was corrected to carry entry-object references through
the sort, and `labels_raw_pass2.json` was regenerated with correct row→entry mappings.
Verification of the regenerated artifacts: `labels.json` is identical to the pre-fix copy
(`labels/_work/labels_before_fix.json`), the schema validator passes (3213 entries), and
all 3828 disposition rows now resolve to an entry at the same file and line — except 4
`cmd_format` facet rows of the cluster_utils.py:94 exec site (:79/:81/:83/:86), which are
intentionally merged (with the :75 facet row) into one entry anchored at the
representative facet line, as recorded in the `dedup_log`. All label content (roles,
classifications, confidences, rationales, evidence) is untouched.
