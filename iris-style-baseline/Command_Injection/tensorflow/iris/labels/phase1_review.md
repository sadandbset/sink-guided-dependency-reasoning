# Phase 1 Review — TensorFlow, Pass 2 (CWE-78 Command/Argument Injection)

Human-review checkpoint for Step 3 (LLM candidate labeling) before Phase 2
(query generation, taint analysis, reporting). This document summarizes what was
labeled, what the labels mean, and what a reviewer should check.

## 1. Scope and provenance

- Workspace: `iris_manual/tensorflow/iris` (Augur 0.3.0 workflow, Phase 1 only)
- Source of candidates: `extraction/sources.csv` (1086 rows) and
  `extraction/sinks.csv` (78 rows), extracted from the tensorflow_vuln CodeQL
  database (sha 349172cf, 2945 Python files).
- Labeling model: **glm-5.3** (Claude Code CLI harness; deterministic
  tool-assisted labeling), **11 batches, 1164 candidate rows → 1077 label
  entries** (all rows processed; dedup and exclusions recorded in
  `labels_raw_pass2.json`).
- Ground-truth isolation: no PyVul vulnerability truth, fix commits, or external
  security advisories were consulted; only the repository source, the loaded
  Augur references (`python.md`, `patterns.md`) and `detection.json` evidence
  were used. Project source, the CodeQL database and prior extraction outputs
  were not modified.

## 2. Label counts (pass 2)

| role | tp | candidate | fp | total |
| --- | --- | --- | --- | --- |
| source | 120 | 314 | 0 | 434 |
| sink | 0 | 11 | 13 | 24 |
| summary | 3 | 0 | 0 | 3 |
| sanitizer | 1 | 0 | 0 | 1 |
| none | 0 | 0 | 615 | 615 |
| **total** | **124** | **325** | **628** | **1077** |

Schema validity: `labels.json` validates cleanly against
`assets/labels_schema.json` (jsonschema 4.26.0, 0 errors; pass 1 is a
zero-entry stub required by the schema's `contains` constraint).

## 3. Top high-risk sink APIs (the CWE-78 execution surface)

No site was confirmed as an actively exploitable command-injection sink
(classification `tp`) — every command-execution site in this snapshot has
static, internally derived, or list-form operands. 11 sites remain
**candidate** (genuine boundaries with external/param influence):

1. `config_detector.py:140` — `Popen(args, shell=True)` inside `run_shell_cmd`:
   the only string-command + shell=True wrapper reachable from a parameter.
   All current callers pass fixed literals from the module cmds dict.
2. `configure.py:1246` — `Popen([environ_cp['PYTHON_BIN_PATH'], ...])`: argv[0]
   from the environment/interactive input (list form, developer-operated).
3. `configure.py:150/154` — `run_shell()` relays cmd lists to check_output; the
   python binary path is environment-influenced.
4. `upgrade_schema.py:130/166` — flatc argv with CLI-supplied model paths.
5. `sizetrack_helper.py:189/237` — git/gcloud argv with CLI-derived params.
6. `update_version.py:237`, `gen_git_source.py:163`, `check_cuda_libs.py:62` —
   grep/git/objdump argv with param-derived operands (list form).

Highest-interest fp (worth a reviewer's eyes despite classification fp):
`lite/python/convert.py:400` — `Popen(" ".join(cmd), shell=True)` on the runtime
TFLite conversion path. Verified safe on current data flow (command = fixed
toco binary + tempfile paths; model/proto strings are written *into* the temp
files), but the shape (shell=True + PATH-resolved binary + string join) is the
classic CWE-78 pattern and any future operand change would be exploitable.

## 4. Top broad source APIs

- tfdbg gRPC receive boundary (12 tp entries): `SendEvents`/`SendTracebacks`/
  `SendSourceFiles` servicer params and `on_value_event`/`on_graph_def`/
  `on_core_metadata_event` callback params — unauthenticated network input;
  the concrete data flows observed are JSON/proto decode and file paths
  (`grpc_path` → `os.path.join`), no command flow.
- CLI boundaries (120 tp entries): `sys.argv` (47 tp), `parse_known_args` (28),
  `parse_args` (19), `input`/`_input` (5) — concentrated in runtime library
  entry points (tflite_convert, toco_from_protos, saved_model_cli, freeze_graph,
  tfdbg CLIs, grpc_tensorflow_server).
- `urlopen` (5 tp): HTTP responses trusted as data.
- Candidate-tier boundaries (314 entries): file reads (`open`/`GFile`/`Open`,
  93), proto decode (`ParseFromString`, 74), environment reads (85), JSON
  decode (26) — genuine input boundaries retained for conservative recall; in
  this tree their data feeds parsing and paths, not command strings.
- `add_argument` (444 rows) → none/fp: declarative registrations; the values
  surface at `parse_args`/`parse_known_args` (labeled separately).

## 5. Sanitizers

- `shlex.quote` / `_shlex_quote` (`saved_model_aot_compile.py:63-67`), applied
  to all XLA makefile template interpolations — the only shell-quoting helper
  in the tree. Supplementary entry (no CSV row), verified in source.

## 6. Summaries

- 3 taint steps for the tfdbg gRPC dispatch
  (`stream_handler.on_value_event/on_graph_def/on_core_metadata_event`,
  grpc_debug_server.py:157/168/177) modeling the dynamic-dispatch hop from the
  servicer into the stream-handler implementations.

## 7. Unresolved / low-confidence items needing human review

- 0 entries carry classification `unknown`; every candidate was decided.
- 85 entries sit at confidence < 0.55 (82 source candidates in the
  file/JSON-decode families — CWE-78 relevance is indirect; 3 sink candidates
  at 0.5). These were re-checked against source; a reviewer may demote the
  file-read family to none if pass-2 precision is preferred over recall.
- Judgment calls to confirm:
  1. **Zone policy**: test-support modules (test_util.py, runlit.site.cfg.py,
     benchmark.py, combinations.py, multi_process_lib/runner) labeled none/fp;
     `tensorflow/tools`, `tensorflow/compiler`, `third_party`, `configure.py`
     treated as developer-operated tooling (source=candidate, weaker attacker
     model) while `tensorflow/python`/`lite`/`keras` runtime code gets
     source=tp.
  2. **Exec wrappers as none**: the 14 `internal_exec_wrapper` functions are
     labeled none/fp on the grounds that local taint flow propagates their
     params to the (separately labeled) exec calls; a reviewer preferring
     mlflow-style summary entries for wrappers like `run_shell_cmd` should say
     so before Step 4.
  3. **convert.py:400 as fp vs candidate**: currently fp 0.65 with the
     shell=True/PATH note; flip to candidate if the review wants alerting on
     the shape rather than the current data flow.
- Expected Phase 2 outcome, stated honestly: no complete source→sink
  confirmation of a CWE-78 vulnerability is expected from these labels in the
  Python layer of this snapshot — the command-execution surface is dominated by
  build/CI/doc/GPU-discovery tooling with static operands, and the runtime
  toco path keeps model data out of the command string. The candidate-tier
  labels are retained so the taint analysis, not the labeler, makes the final
  call.

## 8. Review decision

- [ ] Approve labels for Phase 2 (Step 4 library generation)
- [ ] Return adjustments (list per §7)

Reviewer: ____________________  Date: ____________

(Per WORKFLOW §4.5 this checkpoint is advisory; the run stops here and does not
proceed to Phase 2 until approved.)
