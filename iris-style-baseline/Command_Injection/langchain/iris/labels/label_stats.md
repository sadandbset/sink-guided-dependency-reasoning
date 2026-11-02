# Label Stats — LangChain Pass 2 (CWE-077/078/088), Step 3 LLM labeling

## 1. Run identity

- run_id: `langchain-iris-pass2-labeling-20261015`
- generated_at: 2026-10-15T02:09:42Z
- model: glm-5.3 (Claude Code CLI harness; deterministic tool-assisted labeling, batched review)
- language: python; framework: null (library-level analysis, no web framework)
- project: langchain (vulnerable snapshot 61938a02a1e76fa6c6e8203c98a9344a179c810d)
- inputs: `extraction/sources.csv` (470 rows), `extraction/sinks.csv` (26 rows),
  code context dumps under `labels/work/` (all 496 candidates reviewed with
  per-site source context)
- output: `labels/labels.json` (schema-valid per
  `iris_tools/augur-0.3.0/assets/labels_schema.json`; pass 1 is a zero-entry
  stub required by the schema's `contains` constraint on pass_id=1),
  `labels/labels_raw_pass2.json` (raw per-batch decisions + reconciliation log)

## 2. Batch policy

10 batches (WORKFLOW §4.4.4: stable sizes, conservative recall, re-ask
threshold 0.55):

| batch | focus | candidates |
| --- | --- | --- |
| batch-01 | sink rows 1–13 (exec primitives, wrappers) | 13 |
| batch-02 | sink rows 14–26 (tool wrappers, exec/eval) | 13 |
| batch-03 | chain_user_input | 58 |
| batch-04 | llm_output / parsed_llm_action / agent_tool_input | 35 |
| batch-05..07 | tool_input_from_agent_action (3 × 82) | 246 |
| batch-08 | deserialized_text | 87 |
| batch-09 | environment | 44 |
| batch-10 | reconciliation: dedup, conflicts, sanitizer review, re-check | 13 |

Entries rated ≤ 0.55 at first pass (local-file deserialization sites,
ExceptionTool/InvalidTool) were re-reviewed in batch-10; ratings confirmed,
none re-classified.

## 3. Candidate coverage (all 496 processed)

| | count |
| --- | --- |
| source CSV rows | 470 |
| exact duplicate rows removed | 5 |
| source rows merged into sink entries (API site also an execution wrapper) | 6 |
| sink CSV rows | 26 |
| exact duplicate sink rows removed | 2 |
| **entries emitted (pass 2)** | **486** |
| additional sanitizer-review entries (APIs verified in code) | 3 |

Dedup/merge details are recorded in `labels_raw_pass2.json`
(`reconciliation`). Nothing was invented: every entry traces to a CSV row or
to a reviewed in-repo API (the three sanitizer-review entries).

## 4. Role / classification counts

| role | count | tp | candidate | fp |
| --- | --- | --- | --- | --- |
| source | 414 | 120 | 294 | 0 |
| sink | 21 | 13 | 0 | 8 |
| summary | 5 | 5 | 0 | 0 |
| sanitizer | 0 | 0 | 0 | 0 |
| none | 46 | 0 | 0 | 46 |
| **total** | **486** | 138 | 294 | 54 |

Confidence distribution: {'0.55-0.6': 36, '0.6-0.7': 24, '0.7-0.8': 275, '0.8-0.9': 69, '0.9-1.0': 82}.

## 5. Boundary-level decisions

| extraction boundary | rows (unique) | decision |
| --- | --- | --- |
| chain_user_input | 58 | source/tp 0.9 — chain entry boundary for user task text |
| llm_output | 22 | source/tp 0.85 — model text untrusted (prompts embed user/external content) |
| parsed_llm_action | 9 | source/tp 0.85 — AgentAction.tool_input carrier |
| agent_tool_input | 4 | source/tp 0.9 — tool_input reads at dispatch sites |
| tool_input_from_agent_action | 246 (240 unique) | 238 source/candidate 0.7 (2 BaseTool rows → summary; 6 wrapper rows merged into sink entries) |
| deserialized_text | 87 (86 unique) | 21 source/tp 0.85 (LLM/agent text parsing) · 6 source/tp 0.8 (LLM provider responses) · 24 source/candidate 0.6 (remote web responses) · 32 source/candidate 0.55 (local file/DB/cache) · 3 none/fp 0.9 (internal json round-trips) |
| environment | 44 (40 unique) | none/fp 0.75 — config/credential reads only; not attacker-influenced under this threat model |

## 6. Sinks (21) — the CWE-78 execution surface

Confirmed (tp):

| API | site | confidence | note |
| --- | --- | --- | --- |
| `subprocess.run` (shell=True, str) | utilities/bash.py:76 | 0.95 | primary sink: ShellTool → BashProcess → shell |
| `ShellTool._run` | tools/shell/tool.py:69 | 0.95 | command-execution wrapper (terminal tool) |
| `ShellTool._arun` | tools/shell/tool.py:77 | 0.90 | async wrapper |
| `BashProcess._run` | utilities/bash.py:73 | 0.90 | param → subprocess.run(shell=True) locally |
| `exec` | utilities/python.py:19 | 0.95 | PythonREPL.run → exec(command) |
| `PythonREPLTool._run` / `_arun` | tools/python/tool.py:58/68 | 0.90/0.85 | code-exec wrapper tools |
| `PythonAstREPLTool._run` | tools/python/tool.py:108 | 0.90 | ast.parse → exec/eval wrapper |
| `exec`/`eval`/`exec` | tools/python/tool.py:117/123/130 | 0.90 | unparsed tool-input execution |
| `pexpect.spawn.sendline` | utilities/bash.py:102 | 0.90 | persistent-shell command channel |
| `exec` | utilities/jira.py:192 | 0.90 | exec(f"result = {query}") from JiraAction input |

Rejected (fp, kept labeled as sink with rationale): `subprocess.run` beam.py:219
(fixed literal, shell=True), server.py:13/14 (fixed argv list, no shell),
`pexpect.spawn` bash.py:52 (fixed argv), sendline bash.py:56 (uuid prompt) /
106 (empty literal), `exec` prompts/loading.py:151 (local prompt module
content), `PythonAstREPLTool._arun` (NotImplementedError stub).

Distinctions applied per task rubric: string command vs argv list,
shell=True vs no explicit shell, fixed command vs dynamic argument — each
rationale states which form the site uses.

## 7. Summaries (5)

| API | site | hop modeled |
| --- | --- | --- |
| `BaseTool.run` | tools/base.py:256 | agent tool.run(tool_input) → subclass _run (validation + _to_args_and_kwargs) |
| `BaseTool.__call__` | tools/base.py:400 | __call__ → run dispatch |
| `BashProcess.run` | utilities/bash.py:61 | commands → _run (subprocess shell=True) / _run_persistent (sendline) |
| `BashProcess._run_persistent` | utilities/bash.py:97 | command → sendline(command) |
| `PythonREPL.run` | utilities/python.py:14 | command → exec(command) |

## 8. Sanitizers

**0 confirmed.** Reviewed and rejected (recorded as `none`/fp entries
x-r001..x-r003 with evidence):

- `sanitize_input` (tools/python/tool.py:25) — strips backticks/whitespace and
  a leading "python" token; does not neutralize code.
- `ShellInput._validate_commands` (tools/shell/tool.py:26) — str→list
  normalization + warning; "TODO: Add real validators".
- `BaseTool._parse_input` (tools/base.py:194) — pydantic type validation only.

## 9. Quality checks (WORKFLOW §4.4.6)

1. Schema validated (manual validator implementing every constraint in
   `labels_schema.json`: required fields, enums, patterns, argument-flow
   arg_index rule, passes-contains-pass_id=1) — 0 errors.
2. Pass 2 has 13 confirmed sinks — check satisfied.
3. Duplicates removed (5 source, 2 sink exact dups; 6 cross-CSV conflicts
   merged) — all recorded in `labels_raw_pass2.json`.
4. Argument indexes preserved from extraction (1-based param position
   excluding self/cls; 0-based for argument call sites) and validated.
