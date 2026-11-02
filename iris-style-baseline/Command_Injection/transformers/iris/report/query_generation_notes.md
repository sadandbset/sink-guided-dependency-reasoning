# Phase 2 Step 4–5 — Query Generation Notes (Pass 2 / CWE-78, transformers)

- run_id: `transformers-cwe78-phase1-step3-20260119` (labels) → Step 4–5 generation on 2026-10-19
- inputs: `iris/labels/labels.json` (38 pass-2 entries: 30 source, 5 sink, 3 summary, 0 sanitizer; 18 tp / 19 candidate / 0 fp at entry level), `extraction/sources.csv` (1034 rows), `extraction/sinks.csv` (53 rows), real sources under `dataset/codeql_databases/transformers_vuln/src/transformers/` (commands/, onnx/, pipelines/, testing_utils.py, utils/import_utils.py, hf_argparser.py — re-read during generation)
- toolchain: CodeQL CLI 2.25.1 (E:\codeql), `codeql/python-all` 7.1.2 from `C:\Users\lzh\.codeql\packages`
- generated artifacts: `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass2_CommandInjection.ql`, `diagnostics/Pass2_CommandInjectionDiagnostics.ql` (diagnostics variant, dcnnt-py precedent — its results are NOT formal findings)
- both queries were compile-checked with `codeql query compile` (PASS, no errors/warnings); no database analysis was executed per task instruction
- no vulnerability ground truth (confirmed_vulns.json, CVE申请报告.md, cmd_sinks.csv, cmd_safe_sinks.csv) was read; the Phase 1 labels, extraction results, source tree and database were not modified

## 1. Library / query contract

All four libraries expose pass-key-dispatched predicates; the formal query's `Pass2Config implements DataFlow::ConfigSig` delegates to exactly these names and types (verified by compiling both queries):

| library | predicate | signature |
| --- | --- | --- |
| `libraries/MySources` | `MySources::isSource` | `(DataFlow::Node source, string passKey)` |
| `libraries/MySinks` | `MySinks::isSink` | `(DataFlow::Node sink, string passKey)` |
| `libraries/MySanitizers` | `MySanitizers::isBarrier` | `(DataFlow::Node node, string passKey)` |
| `libraries/MySummaries` | `MySummaries::isAdditionalTaintStep` | `(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey)` |

Pass keys (dcnnt-py two-key contract): `command_injection` = formal query, **tp-classified labels only**; `command_injection_diagnostics` = diagnostics query, additionally admits the `candidate`-classified labels — per the task directive, diagnostic paths (including any local propagation from internal wrapper parameters into dangerous calls) must never be counted as formal findings.

Formal query: `py/augur/transformers/pass2-command-injection`, `@kind path-problem`, `@problem.severity error`, `@precision medium`, `@tags security external/cwe/cwe-078`, built on `TaintTracking::Global<Pass2Config>` + `import Pass2Flow::PathGraph` + `flowPath` (modern modular Python data-flow API). Diagnostics query: `py/augur/transformers/pass2-command-injection-diagnostics` (`@problem.severity warning`).

Path-scope idiom: every rule is restricted to `src/transformers/` via `getLocation().getFile().getAbsolutePath().regexpMatch("(?i).*[\\\\/]src[\\\\/]transformers[\\\\/].*")` — the exact pattern the Step-2 extraction queries ran successfully against this database (the DB covers the whole repository including 903 test files; the labels' scope is the package only).

## 2. Label → QL mapping (sources)

Formal key (tp entries, 18/30 modeled):

| QL rule (MySources) | label ids | matching semantics | source-node kind |
| --- | --- | --- | --- |
| `stdinSource` | `src-sys-stdin` (tp 0.9) | attribute read `sys.stdin` (AST match); sites commands/lfs.py:107/165 (git-lfs stdin protocol), pipelines/base.py:649 (piped rows) | `exprNode(Attribute)` |
| `argvSource` | `src-sys-argv` (tp 0.8) | attribute read `sys.argv` + subscripts over it (hf_argparser.py:330 `file_args + sys.argv[1:]`) | `exprNode(Attribute/Subscript)` |
| `parseArgsSource` | `src-argparse-parse-args` (tp 0.75) | result of any `<obj>.parse_args()` call in scope — installed entries transformers_cli.py:47 and onnx/__main__.py:232, plus the ~201 dev conversion-script mains (label merges them; recall-kept) | `exprNode(Call)` |
| `parseKnownArgsSource` | `src-argparse-parse-known-args` (tp 0.7) | result of any `<obj>.parse_known_args()` call (hf_argparser.py:317/331) | `exprNode(Call)` |
| `commandHandlerParamSource` | `src-cmd-BaseUserCommand` … `src-cmd-TrainCommand` (12 entries, tp 0.6) | every non-self `__init__` parameter (QL arg index ≥ 1, self = 0 — same convention as the labels' arg_index) of the 12 named command classes in src/transformers/commands/ | `parameterNode(Parameter)` |
| `onnxExportParamSource` | `src-onnx-export_with_optimum-param` (tp 0.65), `src-onnx-export_with_transformers-param` (tp 0.6) | `args` parameter at index 0 of the module-level `export_with_optimum` / `export_with_transformers` functions (onnx/__main__.py:35/69) | `parameterNode(Parameter)` |

Diagnostics-only key (candidate entries, 13/13 modeled):

| QL rule | label ids | matching semantics |
| --- | --- | --- |
| `environSource` / `getenvSource` | `src-os-environ` / `src-os-getenv` (0.55) | `os.environ` attribute reads (86 sites) / `os.getenv(...)` call results (60 sites) — caches, flags, integration vars; no observed command flow, recall only |
| `jsonLoadSource` / `jsonLoadsSource` | `src-json-load` / `src-json-loads` (0.7) | `json.load/loads(...)` call results, API-graph resolved (`API::moduleImport("json")…getACall()`, dcnnt idiom) + AST fallback; includes the 2 tp lfs stdin protocol decodes (lfs.py:107/165) and the hub-downloaded config decodes (tokenization_utils_base.py:1970, configuration_utils.py:828) |
| `requestsSource` | `src-requests-get/post/put/head` (0.6) | requests member call results, API-graph + AST fallback; lfs.py:197/217 targets come from stdin JSON (request-target influence) |
| `hubDownloadSource` | `src-hfhub-hf-hub-download` (0.65) / `src-hfhub-cached-download` (0.6) | huggingface_hub call results — **API-graph resolution is required here**: the package uses `from huggingface_hub import hf_hub_download` (tools/base.py:59/63, convert scripts), invisible to the AST fallback |
| `convertMainParamSource` | `src-convert-main-*` (2 entries, 0.5) | `raw_args` parameter (index 0) of `main()` in models/bert/convert_bert_pytorch_checkpoint_to_original_tf.py:92 and models/gpt_sw3/convert_megatron_to_pytorch.py |

Deliberately not modeled as sources (labels role none / raw fp rows): the 11 internal exec wrappers, the f-string/str.join expression rows, logging/display f-strings — per the task directive, internal wrapper parameters are not automatically sources; wrapper-param → dangerous-call propagation is verifiable only through the diagnostics key.

## 3. Label → QL mapping (sinks)

Formal key (tp entries, 1/5):

| QL rule (MySinks) | label id | matching semantics | sink node |
| --- | --- | --- | --- |
| `popenShellTrueCommand` | `snk-subprocess-popen-shell-true` (tp 0.8; label flow_kind `unknown`, arg_index null) | `subprocess.Popen(cmd, …, shell=True)` where `shell` is literal `True` (`kw.getArg() = "shell"`, `kw.getValue().(Name).getId() = "True"`); rendered on the **dangerous argument = positional argument 0 (the shell command string)**, since that is where the label's rationale pins the risk. The extraction verified onnx/__main__.py:59 is the only shell=True exec site in the package | `exprNode(c.getArg(0))` |

Diagnostics-only key (candidate entries, 4/5 additionally):

| QL rule | label ids | matching semantics |
| --- | --- | --- |
| `execApiArg0Command` (subprocess part) | `snk-subprocess-popen-arg0` (0.75), `snk-subprocess-run-arg0` (0.7), `snk-subprocess-check-output-arg0` (0.7) | positional argument 0 of `subprocess.Popen/run/check_output` (API-graph + AST): onnx:59 (shell string), audio_utils.py:34/221 + audio_classification.py:54 (ffmpeg argv lists), lfs.py:87/90 (constant git-config strings), user.py:159/165 + import_utils.py:570 (fixed argv), testing_utils.py:1991 (`run_command`, caller-provided list) |
| `execApiArg0Command` (asyncio part) | `snk-asyncio-create-subprocess-exec-arg0` (0.7) | positional argument 0 of `asyncio.create_subprocess_exec(cmd[0], *cmd[1:], …)` (testing_utils.py:1845) |

Shell command string vs argument list are modeled separately, per the task directive: the formal query matches only the shell-string form (`shell=True` + joined string); the argument-list (no-shell) form is diagnostics-only, because in this snapshot every argv-list site is either fixed-argv, int-formatted, or test-helper usage (raw-artifact fp/candidate rows), while the one shell=True site interpolates unquoted CLI values.

## 4. Source/sink code evidence and argument controllability

- `onnx/__main__.py:50-59` — `cmd_line = [sys.executable, "-m", "optimum.exporters.onnx", f"--model {args.model}", f"--task {args.feature}", f"--framework {args.framework}" …, f"{args.output}"]`; `subprocess.Popen(" ".join(cmd_line), stdout=subprocess.PIPE, shell=True)`. The fixed prefix (`sys.executable -m optimum.exporters.onnx`) is trusted code; **argument 0 as a whole is attacker-influenced exactly through the four interpolated CLI values** (argparse strings, no validation, no quoting). This is the only formal sink.
- `onnx/__main__.py:232-236` — `args = parser.parse_args()`; `export_with_optimum(args)` / `export_with_transformers(args)` receive the full Namespace (parameter index 0, direct controllability of `args.model/args.feature/args.framework/args.output`).
- `commands/transformers_cli.py:47-55` — `args = parser.parse_args(); service = args.func(args); service.run()`; the `set_defaults(func=lambda args: XCommand(args))` factories (lfs.py:63/72 and each command's `register_subcommand`) unpack the Namespace into the `__init__` parameters of the 12 command classes (all non-self parameters, controllability = parsed CLI values; e.g. `LfsEnableCommand.__init__` `args.path` reaches only the subprocess `cwd=`, a path, not the command text).
- `commands/lfs.py:105-117/165` — `json.loads(sys.stdin.readline().strip())`: the git-lfs protocol envelope (event/type) is validated but the message values (oid, path, action.href, action.header) are not; they flow to `requests.put/post` targets and `FileSlice` file reads — no path into any command string exists in this snapshot (review point 1).
- `pipelines/audio_utils.py:14-34, 221, 231-244` / `audio_classification.py:34-54` — ffmpeg argv lists: constants plus int-formatted sampling rate; `_ffmpeg_stream`'s parameter is the caller-built argv (argument-position injection shape only). `_get_microphone_name` parses the local ffmpeg device listing into the later `-i` input (local hardware enumeration, no external control identified).
- `commands/user.py:159/165`, `utils/import_utils.py:570` — fixed argv probes (`["git", "--version"]`, `"ninja --version".split()`), no attacker-controlled data in the command.
- `testing_utils.py:1841-1999` — `_stream_subprocess(cmd)` / `run_command(command)`: caller-provided `List[str]` executed argv-form without shell; test helpers.

## 5. Sanitizer and summary modeling evidence

Sanitizers (confirmed set EMPTY, `isBarrier` resolves to `none()`, never an unconditional block): no `shlex.quote` / `pipes.quote` / escaping wrapper exists at any exec site in src/transformers (only testing_utils.py:1596 `shlex.split` — tokenization, not escaping). Not modeled as barriers: the argv-list call shape (structural, not a data check), read_msg's envelope validation (values unrestricted), `int()` conversions, argparse typing — none neutralizes shell metacharacters or restricts the command input (review point 6).

Summaries (`MySummaries`, all conditional, no unconditional propagation):

| QL rule | label | evidence |
| --- | --- | --- |
| `namespaceFieldStep` | model refinement (binderhub steps-4/5 precedent) — required for the reachability the labels assert | parsed CLI values live in attribute reads of the argparse Namespace (`args.model`, `args.output`, …), not in the `parse_args()` result object itself. Step: from the CLI-namespace nodes (parse_args/parse_known_args results, onnx export `args` params, *Command handler params) to any attribute read whose base the Namespace reaches via `DataFlow::localFlow`. Evidence: transformers_cli.py:49-55 dispatch, onnx/__main__.py:54-57 interpolations. Downstream propagation (f-string → list literal → `" ".join`) is built into python-all 7.1.2 (Fstring step TaintTrackingPrivate.qll:158, listStoreStep, join step) and needs no modeling |
| `funcDispatchStep` | `sum-cli-func-dispatch` (0.6) | `service = args.func(args)` at transformers_cli.py:54 — the factory is attached via `set_defaults(func=lambda args: XCommand(args))` and is not statically resolvable; taint on the argument → the constructed command object |
| `serviceRunStep` | `sum-cli-service-run` (0.55) | `service.run()` at transformers_cli.py:55 — modeled binderhub `executorDispatchStep`-style: receiver → `self` parameter of `run()` methods of `%Command` classes under commands/ (bound-method invocation semantics) |
| `readMsgStep` | `sum-lfs-read-msg` (0.55) | `msg = read_msg()` at lfs.py:179 — the `sys.stdin` read / `json.loads` decode inside `read_msg` → the `read_msg()` call result; redundant fallback for the formal key (standard return-flow already carries the inner json.loads source under the diagnostics key) |

## 6. Uncovered APIs, dynamic calls, known limitations

- **`args.func(args)` dispatch target**: the `XCommand(args)` construction inside the `set_defaults` lambdas is not statically resolvable; covered by `funcDispatchStep` (arg → object) + the handler-parameter sources, not by call resolution.
- **`self.args = args` store → `self.args.path` read across methods** (`*Command.__init__` → `run()`): no step models the cross-method attribute store/load on `self`; documented in MySummaries header. No formal sink consumes handler-attacker data (command strings in the handlers are constant; external values reach only `cwd=`), so no reviewed path is lost.
- **`asyncio.create_subprocess_exec` spread**: `*cmd[1:]` is not an argument-0 node, so tainted elements spread via `*args` are not matched (label arg_index 0 honored; testing_utils only).
- **`from_pretrained(...)` (2112 sites)**: deliberately not extracted in Step 2 (volume); the hub-content boundary is covered instead by the `hf_hub_download` / `json.load`/`loads` candidate sources (diagnostics key). A Phase-2 MySummaries `from_pretrained` parameter step remains a possible recall extension, per detection.json.
- **`os.environ.get(...)` bound-method form** (`map(os.environ.get, …)`) and `os.environb`: not modeled (extraction-level gap noted in detection.json uncoveredCases).
- **Bare-name exec APIs** (`system`, `popen`, `getoutput`): none exist in src/transformers (grep-verified); no `os.system`/`os.popen`/`subprocess.call`/`check_call` sites and no `from subprocess import …` / `from json import …` / `from requests import …` in scope, so the AST fallbacks and API-graph clauses resolve the same call sets.
- **`hf_hub_download` from-import sites** are resolved only through API graphs (AST fallback cannot see them) — included.
- **Dev conversion-script `parse_args` mains** (~201 sites) match the formal `parseArgsSource` (label merges them); they cannot reach the single formal sink, and Step 6 FP heuristics should treat `models/**/convert_*.py` as dev scripts (phase1_review.md item 3).
- **`requests.*` target URLs** (lfs.py:197/217) are attacker-influenced via the stdin protocol; this is request-target (SSRF-shaped) influence — the labeled boundary here is the response body, not the URL.
- Diagnostics query expectations: candidate sources (env/json/requests/hub) are broad families; results are recall signals for human review only and must not be counted as formal pass-2 findings.

## 7. Modeling principles (consistency with the other project experiments)

Same contract as dcnnt-py / binderhub / autogluon / mlflow / Paddle / maltrail / pydash / ray / slo-generator / tensorflow / binderhub runs:

1. pass-key dispatch (`command_injection` formal / `command_injection_diagnostics` diagnostics) with tp-only formal rendering (dcnnt-py);
2. four self-contained libraries exposing `isSource/isSink/isBarrier/isAdditionalTaintStep` with `(node, passKey)` signatures, dot-path imported by the query;
3. `TaintTracking::Global<ConfigSig>` + `PathGraph` + `flowPath` path-problem skeleton with `@problem.severity error`;
4. `isBarrier` always defined, resolving to `none()` when the confirmed sanitizer set is empty;
5. every additional taint step conditional and evidence-grounded; wrapper parameters never auto-promoted to sources (dcnnt-py / task directive), wrapper-param propagation verifiable only via the diagnostics key;
6. scope restriction to the labeled source scope via the extraction-proven path regexp;
7. API-graph resolution with syntax-level fallback for external-module calls (dcnnt-py idiom), API graphs mandatory where from-imports exist (huggingface_hub);
8. shell command string (shell=True) and argument-list (no-shell) invocation modeled as distinct sink shapes (task directive; dcnnt-py notes the same distinction);
9. machine-generated headers documenting the label run, target pack and deliberate non-modeling decisions in each file.
