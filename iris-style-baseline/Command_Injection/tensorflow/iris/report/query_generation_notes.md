# Query Generation Notes — TensorFlow, Pass 2 (CWE-78), Augur Step 4–5

Generated artifacts (Phase 2 Step 4–5; no analysis was executed — `codeql
query compile` only, which succeeded with 0 warnings):

| file | size | content |
| --- | --- | --- |
| `libraries/MySources.qll` | 2714 lines | 120 tp + 314 candidate source labels rendered, 5 strict + 5 candidate predicates |
| `libraries/MySinks.qll` | 137 lines | 11 candidate sink labels (formal tier), 13 fp sinks excluded |
| `libraries/MySanitizers.qll` | 57 lines | 1 sanitizer label (shlex.quote barrier) |
| `libraries/MySummaries.qll` | 126 lines | 3 tp summary labels as additional taint steps |
| `queries/Pass2_CommandInjection.ql` | 78 lines | formal path query (`py/augur/tensorflow/pass2-command-injection`) |

Renderer: `labels/work/render_libraries.py` (deterministic, reads
`labels/labels.json`, writes QL text only). Rendered from run
`tensorflow-iris-pass2-labeling-20261016` (glm-5.3, 1077 pass-2 entries).
Pin check: every `/* <label-id>: <file>:<line> */` comment in the four QLL
files was verified against labels.json — 445/445 pins match, 0 mismatches
(120 tp sources, 314 candidate sources, 11 candidate sinks all rendered).

## 1. Modeling principles (consistent with the mlflow experiment)

1. **Site-pinned rules only.** Every predicate pins the labeled `(file, line)`
   pair (parameters additionally pin the label's 0-based argument index).
   Generic name-based rules were rejected: the tree contains far more
   `open()`/`loads()`/`environ` reads and `add_argument` calls than the
   reviewed label set, so a name-based rule would bind unreviewed sites.
   This is identical to mlflow's `MySources.qll` discipline.
2. **Tiered dispatch.** `isSource`/`isSink` take a `passKey` argument
   (`"command_injection"` for pass 2) and dispatch to a strict tier; the
   formal query only ever reaches the strict tier. Candidate labels are
   rendered as `*Candidate` predicates that no formal query dispatches to.
3. **No unconditional taint propagation.** Every `isAdditionalTaintStep` edge
   is a reviewed, pinned, conditional hop; the wrapper functions are NOT
   sources and get NO wrapper-level edges (their parameters reach the
   directly-labeled exec call arguments through native local data flow).
4. **AST-level matching with `DataFlow` conversions.** Nodes are matched via
   `Call`/`Attribute`/`Parameter` AST classes and converted with
   `DataFlow::exprNode`/`DataFlow::parameterNode` — no `API::Node` usage, so
   no `API::Node`→`DataFlow::Node` conversion is needed (same approach as
   mlflow; the `six.moves` import indirection that motivated mlflow's
   ApiGraphs use does not appear on tensorflow's labeled receive paths —
   the one `six.moves.urllib` site (tpu client) is matched by callee name
   `urlopen`, which `calledNameOf` resolves for both `Name` and `Attribute`
   forms).
5. **Shell string vs argv list modeled separately** (see §3): the
   shell-interpreted command string sink and the argv-list sinks are distinct
   predicates, each modeling argument 0 — the actual dangerous parameter at
   every reviewed site.
6. **Formal query shape** (template `assets/taint_query.ql.tmpl`):
   `module Pass2Config implements DataFlow::ConfigSig` with the four
   delegating predicates, `module Pass2Flow = TaintTracking::Global<Pass2Config>`,
   `import Pass2Flow::PathGraph`, `from … where Pass2Flow::flowPath(source, sink)`.
   Metadata: `@kind path-problem`, `@problem.severity error`, `@precision low`,
   `@tags security` + `external/cwe/cwe-078` (primary, per instruction) +
   `external/cwe/cwe-077` + `external/cwe/cwe-088` (pass-2 CWE set, mlflow
   convention). `isBarrier` is always delegated — never omitted — even though
   only one barrier label exists.

### Tier policy difference vs mlflow (documented deviation)

mlflow pass 2 had 16 tp sink labels → its formal sink tier was tp-only.
Tensorflow pass 2 has **zero tp sink labels** — every reviewed exec site
carries static, internally derived or list-form operands — so the formal sink
tier takes the **11 classification=candidate sink labels** (the genuine
command-execution boundaries whose argument 0 has external/environmental/
parameter influence). The 13 fp sinks are excluded from the model
(rationales in `labels/labels.json`, summarized in §3). Without this
documented deviation the pass would have no sinks at all.

## 2. Label ID → predicate mapping (sources)

`MySources::isSource(source, "command_injection")` → `isSourceStrict` →
5 buckets (the 120 tp labels):

| predicate | label IDs | count | signature shape | node |
| --- | --- | --- | --- | --- |
| `isGrpcHandlerParamSource` | src-0496…src-0511 (param-flow tp labels) | 16 | `labeledParam(p, path, line, idx)` — `SendEvents`/`SendTracebacks`/`SendSourceFiles` servicer request params (idx 1) and `on_value_event`/`on_graph_def`/`on_core_metadata_event` callback params (idx 1/2) in `grpc_debug_server.py`, `grpc_debug_test_server.py`, `debug_service_pb2_grpc.py` | `DataFlow::parameterNode(p)` |
| `isCliArgvSource` | tp `argv` labels | 47 | `Attribute` named `argv` pinned by (file, line) | `DataFlow::exprNode(a)` |
| `isCliParseSource` | tp `parse_args`/`parse_known_args` labels | 47 | `Call` with `calledNameOf(c)` pinned by (file, line) | `DataFlow::exprNode(c)` (return value) |
| `isInteractiveInputSource` | tp `input`/`_input` labels | 5 | `Call` pinned by (file, line) | `DataFlow::exprNode(c)` |
| `isNetworkFetchSource` | tp `urlopen` labels | 5 | `Call` pinned by (file, line) | `DataFlow::exprNode(c)` |

Candidate tier (rendered, **not** dispatched — recall reserve for diagnostics
only; enabling them in `isSourceStrict` is a one-line change): 
`isFileOpenCandidate` (93 read-mode `open`/`GFile`/`Open` labels),
`isEnvReadCandidate` (85 `os.environ`/`os.environ.get`/`os.getenv` labels),
`isProtoDecodeCandidate` (74 `ParseFromString` labels — node is
`c.getPositionalArg(0)`, the serialized-bytes argument),
`isJsonDecodeCandidate` (26 `json.loads`/`json.load` labels),
`isCliCandidate` (36 argv/parse labels in developer-operated tooling).

Excluded from rendering (label review): 615 `none`/fp labels (444
`add_argument` declarations, write-mode opens, test-support modules, gRPC
context/wall_time args, cmd_format and wrapper rows) — rationales in
`labels/labels.json`.

## 3. Label ID → predicate mapping (sinks) and source evidence

`MySinks::isSink(sink, "command_injection")` → `isSinkStrict` → 2 buckets
(the 11 candidate labels; every sink node is
`DataFlow::exprNode(c.getPositionalArg(0))` — argument 0, the command
position at all reviewed sites):

### `isShellStringCommandSink` — 1 site (shell command string)

| label | site | controllability of the dangerous argument (verified in source) |
| --- | --- | --- |
| snk-0044 | `tensorflow/tools/tensorflow_builder/config_detector/config_detector.py:140` `Popen(args, shell=True)` | `args` is the `run_shell_cmd(args)` parameter — a shell-interpreted command string. All current callers pass fixed literals from the module `cmds_linux` dict (:96–119), so no live flow exists; the site is the only reviewed shell-string execution boundary, hence retained as candidate |

### `isArgvListCommandSink` — 10 sites (non-shell argv lists)

| label | site | controllability of argument 0 (verified in source) |
| --- | --- | --- |
| snk-0001/0002 | `configure.py:150/:154` `check_output(cmd, …)` | `run_shell()` cmd list; argv carries the interactive/env-configured `PYTHON_BIN_PATH` python binary (caller `configure.py:197`) plus literals — environment-influenced executable, list form |
| snk-0003 | `configure.py:1246` `Popen([environ_cp['PYTHON_BIN_PATH'], paths[0]] + cuda_libraries)` | argv[0] is the `PYTHON_BIN_PATH` environment/interactive value; argv[1] a glob-resolved script path; rest fixed names |
| snk-0009 | `tensorflow/lite/schema/upgrade_schema.py:130` `subprocess.call([flatc, -t, …, input_file])` | `input_file` is the CLI-supplied model path (Converter ctor → `main` argv); flatc path is constructor-supplied |
| snk-0013 | `upgrade_schema.py:166` `subprocess.call([flatc, -b, …, temp paths])` | tempdir-internal operands + constructor-supplied flatc path (weakest candidate, conf 0.5) |
| snk-0021 | `tensorflow/tools/ci_build/sizetrack_helper.py:189` `subprocess.run([git, log, …, commit_range, pretty])` | `commit_range`/`pretty_format` are `git_pretty()` parameters (CLI-derived values of the size-tracking tool) |
| snk-0024 | `sizetrack_helper.py:237` `subprocess.run([tool, *args])` | `gcloud(tool, args)` relays both parameters; callers pass fixed tool names and CLI-derived arguments |
| snk-0026 | `tensorflow/tools/ci_build/update_version.py:237` `check_output([grep, -rnoH, formatted_string, TF_SRC_DIR])` | `formatted_string` derives from the `lingering_string` parameter (old-version string from CLI/version constants) |
| snk-0039 | `tensorflow/tools/git/gen_git_source.py:163` `check_output([git, --git-dir=…, --work-tree=…, describe…])` | `--git-dir`/`--work-tree` values interpolate the `git_base_path` parameter (repo path) |
| snk-0046 | `third_party/gpus/check_cuda_libs.py:62` `check_output([objdump, -p, path])` | `path` is the library-path parameter from the CUDA-discovery caller |

Argv-list element modeling: argument 0 is a list at every site; CodeQL's
native local data flow propagates taint from a tainted list element to the
list expression, so modeling the whole argument node covers every element
(argv[0] executable and all operands) — this is the "actual dangerous
parameter" separation from mlflow's `getElt(2)` bash−c payload modeling,
which does not apply here because tensorflow's lists have no fixed payload
position.

### Excluded (fp, NOT rendered) — 13 sites, each verified in source

`tensorflow/lite/python/convert.py:400` (`Popen(" ".join(cmd), shell=True)`;
command string provably limited to the fixed toco binary + tempfile paths —
model data is written *into* the temp files, never interpolated);
docs-build literal argv `Popen`/`check_call` (build_cc_api_headers.py:39/40/45/47,
build_java_api_docs.py:62/63/68); `slurm_cluster_resolver.py:147` fixed
`['nvidia-smi','--list-gpus']`; `set-build-env.py:246` fixed string +
`:254` toolchain-lookup-derived gcc; `find_cuda_config.py:140` fixed ldconfig
+ `:264` filesystem-searched nvcc. Plus 12 `cmd_format` rows and 14
`internal_exec_wrapper` rows (role=none labels).

## 4. Sanitizer modeling evidence

`MySanitizers::isBarrier(node, "command_injection")` → `isQuoteCallBarrier`
(san-001): barrier = the value of any call named `quote`/`_shlex_quote`
inside `tensorflow/python/tools/saved_model_aot_compile.py`. Evidence
(verified in source): `_shlex_quote()` (:63–67) wraps `pipes.quote`/`shlex.quote`
and is applied to every interpolated value of the XLA makefile command
template — `tensorflow_includes` (:114), `compiled_dir` (:139) — and
`output_prefix` (:358). It is the only shell-quoting helper in the tree.
Scope is deliberately pinned to this file (the only reviewed evidence);
quote-named calls elsewhere are not barriers, which can only add findings,
never hide a path. No other sanitizer was confirmed: no argv-allowlist or
metacharacter-blocking helper exists in non-test project source
(`grpc_debug_test_server.py:95-98` strips a leading `/` — path domain, not
command domain; `check_for_lingering_string` regex-escapes for *grep*, not
for a shell).

## 5. Summary (additional taint step) modeling evidence

`MySummaries::isAdditionalTaintStep(from, to, "command_injection")` → 3
steps (src-0509/0510/0511, the only tp summary labels):

| label | hop | why an explicit edge is needed |
| --- | --- | --- |
| src-0509 | `stream_handler.on_value_event(<event>)` argument at `grpc_debug_server.py:157` → `on_value_event(self, event)` parameter (position 1) | dispatch through the dynamically constructed `self._stream_handler_class()` instance — cross-class, not natively tracked |
| src-0510 | `on_graph_def` arguments 0/1 at `:168` → `on_graph_def` parameters 1/2 (`graph_def`, `device_name`; call arg idx → declared position idx+1) | same dynamic dispatch; `wall_time` (fp label) deliberately not connected |
| src-0511 | `on_core_metadata_event(<event>)` argument at `:177` → parameter 1 | same |

Handler implementations pinned to `grpc_debug_server.py` (base class :52/:68/:87)
and `grpc_debug_test_server.py` (:87/:113/:131) via `handlerImplFile`.

**No diagnostics query was generated** (the `iris/diagnostics/` directory
stays empty): tensorflow's labels mark all 14 internal wrapper functions
(`run_shell_cmd`, `run_shell`, `_run_toco_binary`, `gcloud`, `git_pretty`,
…) as `none`/fp — wrapper parameters are not sources, and each wrapper's
contained exec call is labeled directly with the parameter→argument hop
covered by native local data flow. A diagnostic query would therefore
duplicate what the formal query already covers; per the "wrapper parameters
are not automatically sources" rule, nothing was added to the formal path
results either.

## 6. Uncovered APIs, dynamic dispatch, known limitations

1. **No complete path expected.** Honest expectation for Step 5: the
   reviewed sources (tfdbg gRPC receive, CLI boundaries, urlopen) have no
   data-flow connection to the 11 reviewed exec sinks (build/config/GPU
   tooling) — the label set records boundaries, and the analysis decides.
   Zero findings is the expected outcome for this snapshot, not a defect.
2. **`six.moves` / conditional imports:** `urlopen` in
   `python/tpu/client/client.py` and `keras/utils/data_utils.py` is imported
   via `six.moves.urllib.request` — matched by callee name only (both tp
   labels are urlopen); API-graph resolution is impossible for these, which
   is why `calledNameOf` (Name or Attribute) is used throughout.
3. **Import aliases:** `import subprocess as _subprocess`
   (lite/python/convert.py), `import json as _json` — callee-name matching
   is alias-transparent. No labeled site is missed by this.
4. **Dynamic dispatch:** the `stream_handler.on_*` hops are covered by the 3
   summary edges; `self._stream_handler_class()` itself is not resolved.
   `getattr`-based dispatch is unmodeled (none observed on the labeled paths,
   per detection.json uncoveredCases).
5. **grpc debug test server's `grpc_path`** flows into `os.path.join`
   (path domain, pass 1 scope) — intentionally not a command sink.
6. **Native execution boundaries** (`_pywrap_toco_api.TocoConvert`, C++ gRPC
   servers, `tf.compile`) are not Python CWE-78 sinks (out of scope, per
   detection.json).
7. **`multiprocessing.set_executable(sys.argv[0])`**
   (distribute/multi_process_lib.py:126) is not a subprocess-API sink; the
   argv read is captured as a CLI source.
8. **`ParseFromString`/`loads`/file-open candidates are not dispatched** —
   if Phase 2 recall must increase, add the `*Candidate` predicates to
   `isSourceStrict` (one line each); alert volume will rise sharply.
9. **Element-level argv modeling** relies on native local flow
   (element → list). If a future CodeQL version drops that step, model
   `c.getPositionalArg(0).(List).getElt(i)` per site as mlflow did for the
   fixed `bash -c` position 2.
10. **configure.py location caveat:** detection.json's run note stated the
    repository-root scripts were outside the database, but the extraction
    CSVs (and the bqrs results behind them) contain `configure.py` rows —
    the pins compile against the database, so the rows are genuine; the
    note is recorded here for transparency.

## 7. Constraints honored

- No vulnerability ground truth (PyVul `confirmed_vulns.json`,
  `cmd_sinks*.csv`, CVE reports, fix commits, tensorflow-safe-db) was read.
- No project source, CodeQL database, or Phase 1 label/extraction artifact
  was modified; only `iris/libraries/*`, `iris/queries/*`,
  `iris/report/query_generation_notes.md` and the renderer script under
  `iris/labels/work/` were written.
- No formal analysis was executed: `codeql query compile
  queries/Pass2_CommandInjection.ql` (validation only) — 1/1 compiled, 0
  warnings, 0 errors.
