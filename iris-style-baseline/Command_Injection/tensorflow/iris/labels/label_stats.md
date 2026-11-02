# Label Stats — TensorFlow Pass 2 (CWE-077/078/088, focus CWE-78), Step 3 LLM labeling

## 1. Run identity

- run_id: `tensorflow-iris-pass2-labeling-20261016`
- generated_at: 2026-10-16
- model: glm-5.3 (Claude Code CLI harness; deterministic tool-assisted labeling, batched review)
- language: python; framework: none (library codebase — absl/argparse CLIs + gRPC + tfdbg;
  no web framework detected, language-reference path per `references/python.md`)
- project: tensorflow (vulnerable snapshot, CodeQL database sha `349172cf0ac29ba1346d244a40dc4761b4600f2e`,
  2945 Python files in database scope)
- inputs: `extraction/sources.csv` (1086 rows), `extraction/sinks.csv` (78 rows),
  `exploration/detection.json`; all 1164 candidate rows were reviewed against the
  tensorflow_vuln source tree (every sink site, every gRPC receive boundary and the key
  CLI/env/exec paths read in full; the per-site decisions are encoded in
  `labels/work/build_labels.py`, which only formats them)
- output: `labels/labels.json` (schema-valid per
  `iris_tools/augur-0.3.0/assets/labels_schema.json`, validated with `jsonschema` 4.26.0 —
  0 errors; pass 1 is a zero-entry stub required by the schema's `contains` constraint on
  pass_id=1), `labels/labels_raw_pass2.json` (per-site raw decisions + reconciliation log)

Threat model: external input enters via (1) the unauthenticated tfdbg gRPC debug server
(`SendEvents`/`SendTracebacks`/`SendSourceFiles` streams over a `[::]:port` listener with no
authentication), (2) argparse/absl CLI entry points and `sys.argv` reads, (3) environment
variables (`TF_CONFIG` cluster specs, `SLURM_*`/`CUDA_VISIBLE_DEVICES`, `PYTHON_BIN_PATH`
and `TF_*` build configuration), (4) files/models/configs (SavedModel/keras configs, TFLite
flatbuffers/JSON, debug dump files), and (5) outbound HTTP fetches whose responses are
trusted (TPU/GCE metadata, keras data mirrors). Command execution concentrates in the TFLite
toco conversion path (`Popen(shell=True)`), GPU/toolchain discovery (nvidia-smi, nvcc,
ldconfig, objdump, flatc, git) and `tensorflow/tools` build/CI/doc/packaging scripts.
`classification=tp` marks a genuine source/sink/sanitizer API for CWE-78 — it is NOT a
final vulnerability ground-truth TP.

## 2. Batch policy

11 batches (WORKFLOW §4.4.4: stable scopes, conservative recall, re-ask threshold 0.55;
entries at/below 0.55 were re-checked against source before confirming):

| batch | focus | candidates |
| --- | --- | --- |
| snk-01 | all 24 exec-API sink sites (subprocess Popen/check_output/check_call/call/run; 2 `shell_true` marker rows folded into their Popen entries) — hand-reviewed line by line | 24 |
| snk-02 | internal_exec_wrapper function sites — hand-reviewed; all none/fp (contained exec calls labeled directly, local taint flow propagates wrapper params) | 14 |
| snk-03 | cmd_format string-construction sites (str.format / %-format) — hand-reviewed; command flags, path joins, error text or logging, never execution APIs | 12 |
| src-01 | tfdbg gRPC network receive boundaries: servicer params, on_* callbacks, 3 stream_handler dispatch sites → summary | 34 |
| src-02 | network fetch + decode boundaries: urlopen, json.loads/load, ParseFromString | 128 |
| src-03 | CLI input: sys.argv, parse_args/parse_known_args, input()/self._input | 111 |
| src-04 | add_argument CLI flag declarations → none/fp (values surface at parse_args) | 444 |
| src-05 | environment reads: os.environ / os.environ.get / os.getenv (zone-differentiated) | 85 |
| src-06 | file opens: open/GFile/Open, read vs write mode distinguished from the balanced-paren source text | 122 |
| re-ask | entries at confidence ≤ 0.55 re-checked against source before confirming | 85 |
| sanitizer-supplement | shlex.quote/_shlex_quote from detection.json sanitizerObservations after in-repo verification (no CSV row) | 1 |

## 3. Candidate coverage (all 1164 rows processed)

| | count |
| --- | --- |
| source CSV rows | 1086 |
| sink CSV rows | 78 |
| api/ast + same-site duplicate-row merges | 88 |
| **unique source sites** | **1026** |
| **unique sink sites** (incl. 2 shell_true rows folded into Popen entries) | **50** |
| additional sanitizer entries (API verified in code) | 1 |
| **entries emitted (pass 2)** | **1077** |

Reconciliation detail (per-site row merges, match kinds, dispositions) is in
`labels_raw_pass2.json` (`reconciliation`, `sites`). Nothing was invented: every entry
traces to a CSV site, except the sanitizer entry, which traces to a reviewed in-repo API
(`tensorflow/python/tools/saved_model_aot_compile.py:63-67 _shlex_quote` → `shlex.quote`).

## 4. Role / classification counts

| role | count | tp | candidate | fp |
| --- | --- | --- | --- | --- |
| source | 434 | 120 | 314 | 0 |
| sink | 24 | 0 | 11 | 13 |
| summary | 3 | 3 | 0 | 0 |
| sanitizer | 1 | 1 | 0 | 0 |
| none | 615 | 0 | 0 | 615 |
| **total** | **1077** | **124** | **325** | **628** |

No entry carries classification `unknown` — every candidate received a decided label.

Confidence distribution: <0.6: 265, 0.6–0.7: 71, 0.7–0.8: 582, 0.8–0.9: 159, 0.9–1.0: 0.
The 85 entries below 0.55 were re-checked against source (82 source candidates in the
file/JSON-decode families where CWE-78 relevance is indirect, 3 sink candidates).

## 5. Boundary-level decisions

| extraction family | unique sites | decision |
| --- | --- | --- |
| grpc param (SendEvents/SendTracebacks/SendSourceFiles request args) | 8 | source/tp 0.7–0.85 — unauthenticated gRPC receive boundary (grpc_debug_server.py:123/461/478, generated pb2_grpc stubs, test server subclasses); ServicerContext arg 2 → none/fp 0.7 (not payload data) |
| grpc param (on_value_event/on_core_metadata_event event args) | 4 | source/tp 0.75–0.8 — receive callbacks handed network Event protos (JSON log_message, tensor summaries) |
| grpc param (on_graph_def graph_def/device_name/wall_time) | 6 | graph_def tp 0.8 (ParseFromString-decoded network chunks); device_name tp 0.6–0.65 (attacker string); wall_time none/fp 0.7 (numeric) |
| internal_transfer (stream_handler.on_* dispatch) | 3 | summary/tp 0.75 — dynamic-dispatch hop from servicer into handler implementations |
| urlopen (six.moves.urllib.request) | 5 | source/tp 0.7 — HTTP response boundary (TPU/GCE metadata, version switcher, keras mirrors, NVIDIA data) |
| json.loads / json.load | 26 | source/candidate 0.45–0.5 — decode boundary of config/SavedModel/debug-event/network bytes; downstream is data structures and paths, not commands |
| ParseFromString | 76 | source/candidate 0.5–0.55 — proto wire decode of externally supplied serialized data; decoded content never reaches command strings in this tree |
| sys.argv | 81 | tp 0.7 in runtime library code (47 sites, direct CLI boundary); candidate 0.6 in dev/examples tooling (18); none/fp 0.8 in test-support modules (16) |
| parse_args / parse_known_args | 65 | tp 0.75 in library code (47); candidate 0.6 in dev/examples tooling (18) |
| add_argument | 444 | none/fp 0.75 — declarative flag registration; the input value surfaces at parse_args/parse_known_args (labeled separately) |
| input / self._input | 5 | source/tp 0.7 — interactive input boundary (tfdbg CLI loop, grpc_wrapper prompt, keras overwrite confirmation) |
| os.environ / os.environ.get / os.getenv | 105 | candidate 0.5–0.6 (library 0.55, build tooling 0.6 where env feeds executed commands, e.g. PYTHON_BIN_PATH → Popen argv[0]); none/fp 0.8 in test-support (24) |
| open / GFile / Open | 122 | read-mode → source/candidate 0.5–0.55 (93 sites; file content feeds proto/JSON parsing and file writes, not commands — conservative recall); write-mode → none/fp 0.8 (29 sites, output writes); mode not literal → candidate 0.45 |
| subprocess exec APIs (arg 0) | 24 | sink — 11 candidate (env/param-influenced operands, list form) + 13 fp (fixed or internally derived operands); see §6 |
| cmd_format (str.format / %-format) | 12 | none/fp 0.7–0.85 — command-flag construction, path joins, error/log text; not execution APIs (each rationale names the exec sink it feeds, when it does) |
| internal_exec_wrapper | 14 | none/fp 0.55–0.85 — contained exec calls are labeled directly; CodeQL local taint flow propagates wrapper parameters to the call arguments without summary edges |

## 6. Sinks (24) — the CWE-78 execution surface

Candidate (11) — genuine exec boundaries whose operands have external/param influence,
all list-form (no shell) except one:

| API | site | confidence | note |
| --- | --- | --- | --- |
| `subprocess.Popen` (shell=True) | tensorflow_builder/config_detector/config_detector.py:140 | 0.55 | run_shell_cmd(args) relays its param string to `Popen(args, shell=True)`; every current caller passes fixed shell-command literals from the module cmds dict — no live flow, but a genuine string-command boundary |
| `subprocess.Popen` | configure.py:1246 | 0.55 | argv list whose first element is env/interactive-configured `PYTHON_BIN_PATH`; no shell, developer-operated configure script |
| `subprocess.check_output` | configure.py:150 / :154 | 0.55 | run_shell() helper relays cmd lists; python binary path is env-influenced; no shell |
| `subprocess.call` | lite/schema/upgrade_schema.py:130 / :166 | 0.55 / 0.5 | flatc argv with CLI-supplied model paths (list form) |
| `subprocess.run` | ci_build/sizetrack_helper.py:189 / :237 | 0.55 / 0.6 | git log argv with commit_range/pretty_format params; gcloud() relays tool/args params (list form) |
| `subprocess.check_output` | ci_build/update_version.py:237 | 0.5 | grep argv with the lingering_string param (list form, release tooling) |
| `subprocess.check_output` | tools/git/gen_git_source.py:163 | 0.55 | git describe argv with --git-dir/--work-tree from git_base_path param (list form) |
| `subprocess.check_output` | third_party/gpus/check_cuda_libs.py:62 | 0.5 | objdump argv with library path param (list form) |

Rejected (13 fp, kept labeled with rationale): `lite/python/convert.py:400`
`Popen(" ".join(cmd), shell=True)` — the joined string contains only the fixed toco binary
name, tempfile-generated paths and a formatted tempfile flag; the model/proto strings are
written into the temp files as *content*, never interpolated into the command (retained as
the highest-interest fp: shell=True + PATH-resolved binary); docs-build `Popen/check_call`
with literal argv (build_cc_api_headers.py:39/40/45/47, build_java_api_docs.py:62/63/68);
`slurm_cluster_resolver.py:147` fixed `['nvidia-smi','--list-gpus']`;
`set-build-env.py:246` fixed `command -v gcc` string (shell=True, no interpolation) and
:254 toolchain-lookup-derived gcc path; `find_cuda_config.py:140` fixed ldconfig argv and
:264 filesystem-searched nvcc path.

12 cmd_format rows → none/fp: `'--debug_proto_file={}'.format(tempfile)`,
`--git-dir=%s` flag construction, gcloud Windows tool-path formatting, and 8 error-message /
print / path-join formatting sites — none is a command-execution API.

14 internal_exec_wrapper rows → none/fp (rationales per function): the exec call each
wrapper contains is labeled directly and local taint flow propagates the wrapper's
parameters to the call argument; `_run_toco_binary` additionally writes its params to temp
files as content so they never reach the command string at all.

## 7. Summaries (3) — data-propagation steps

| call | site | hop modeled |
| --- | --- | --- |
| `stream_handler.on_value_event(maybe_tensor_event)` | debug/lib/grpc_debug_server.py:157 | servicer-side reassembled tensor event → on_value_event(event) handler param |
| `stream_handler.on_graph_def(...)` | debug/lib/grpc_debug_server.py:168 | decoded GraphDef + device_name → on_graph_def handler params |
| `stream_handler.on_core_metadata_event(event)` | debug/lib/grpc_debug_server.py:177 | core-metadata Event → on_core_metadata_event handler param (json.loads of event.log_message.message in handlers) |

The dispatch goes through the dynamically constructed stream-handler class
(`self._stream_handler_class()`), so the taint step keeps cross-class propagation visible.

## 8. Sanitizers (1 confirmed)

| API | site | verdict |
| --- | --- | --- |
| `shlex.quote` (via `_shlex_quote`) | python/tools/saved_model_aot_compile.py:67 | sanitizer/tp 0.75 — pipes.quote (py2) / shlex.quote (py3); the only shell-quoting helper in the tree, applied to every interpolated value of the XLA makefile command template (:114, :139) and output_prefix (:358). Supplementary entry verified in source from detection.json sanitizerObservations (no CSV row). |

No other sanitizer was confirmed: the tree contains no shell-escaping, argv-allowlist or
metacharacter-blocking helper beyond `_shlex_quote`; `grpc_debug_test_server.py:95-98` only
strips a leading `/` (path domain); argument-list invocation sites are API properties, not
barrier nodes.

## 9. Quality checks (WORKFLOW §4.4.6)

1. Schema validated with `jsonschema` against
   `augur-0.3.0/assets/labels_schema.json` — 0 errors (required fields, enums, patterns,
   confidence range, argument-flow arg_index rule, passes-contains-pass_id=1, unique ids).
2. Pass 2 has 24 sink entries (11 candidate) — "at least one sink" check satisfied.
3. Duplicates removed: 1164 CSV rows → 1076 unique sites (88 api/ast and same-site row
   merges; 2 shell_true marker rows folded into their Popen entries), recorded per site in
   `labels_raw_pass2.json`.
4. Argument indexes preserved from the extraction CSV convention (0-based positional
   index) and validated (int ≥ 0 for flow_kind=argument/param; null elsewhere).
5. No candidate was left unclassified: 0 entries carry classification `unknown`; the 85
   entries at confidence ≤ 0.55 were re-checked against source before confirming.
