# Phase 1 Review — LangChain CWE-78 (Pass 2) labeling checkpoint

Human-review payload per WORKFLOW §4.5 (advisory gate). Status: **Phase 1
complete** — extraction (Step 2) + LLM labeling (Step 3) done; Phase 2
(libraries/queries/report) intentionally not started.

## Label counts (pass 2)

- entries: 486 — source 414, sink 21,
  summary 5, sanitizer 0, none 46
- classifications: tp 138, candidate 294, fp 54
- all 496 extraction candidates processed; dedup/merges recorded (see
  `label_stats.md` §3 and `labels_raw_pass2.json`)

## Top high-risk sink APIs

- `subprocess.run` — langchain/utilities/bash.py:76 (conf 0.95): Primary CWE-78 sink: subprocess.run(command, shell=True) with string command
- `exec` — langchain/utilities/python.py:19 (conf 0.95): exec(command, self.globals, self.locals): arbitrary code execution with command from PythonREPL.run parameter (PythonREPLTool input).
- `ShellTool._run` — langchain/tools/shell/tool.py:69 (conf 0.95): Primary command-execution wrapper: ShellTool._run(commands) -> BashProcess.run -> subprocess.run(command, shell=True)
- `BashProcess._run` — langchain/utilities/bash.py:73 (conf 0.9): Real execution wrapper: parameter `command` flows directly into subprocess.run(command, shell=True) at line 76 within the same function body.
- `pexpect.spawn.sendline` — langchain/utilities/bash.py:102 (conf 0.9): Persistent-shell command injection line: sendline(command) writes the (tool-input-derived) command into the running bash
- `exec` — langchain/utilities/jira.py:192 (conf 0.9): exec(f"result = {query}") with `query` supplied by JiraAction tool input (agent/LLM-derived) - direct code execution of interpolated input.

Primary modeled path (end-to-end, verified in source):
`AgentExecutor._call(inputs)` → LLM `_generate` return →
`AgentOutputParser.parse` → `AgentAction.tool_input` (agent.py:851) →
`BaseTool.run` (summary) → `ShellTool._run` (sink, tools/shell/tool.py:69) →
`BashProcess.run` (summary) → `subprocess.run(command, shell=True)`
(utilities/bash.py:76). Persistent mode: `_run_persistent` → `sendline`
(bash.py:102). Code-exec variants: `PythonREPLTool._run` → `PythonREPL.run`
→ `exec` (utilities/python.py:19); `PythonAstREPLTool._run` → exec/eval
(tools/python/tool.py:117/123/130); `JiraAction` → `exec(f"result = {query}")`
(jira.py:192).

## Top broad source APIs

- LLM output returns (22 sites, tp 0.85): `BaseLLM._generate/generate/predict`,
  `BaseChatModel._generate/generate/predict`, per-provider `_generate`.
- Agent action parsing (9 sites, tp 0.85): `MRKLOutputParser.parse`,
  `StructuredChatOutputParser.parse`, `ConvoOutputParser.parse`, …
- Chain user-input entrypoints (58 sites, tp 0.9): `Chain.call/_call`,
  `AgentExecutor._call/_acall`, and 50+ chain subclasses.
- Tool entry params (238 sites, candidate 0.7): every `BaseTool` subclass
  `_run/_arun` param (Gmail/O365, file_management, search, SQL, requests…).
- LLM-text JSON parsing (21 sites, tp 0.85): function-call arguments,
  output-parser JSON, openapi planner request JSON, Jira tool input.

## Sanitizer list

Empty — 0 sanitizers confirmed. `sanitize_input`,
`ShellInput._validate_commands`, `BaseTool._parse_input` reviewed and rejected
(cosmetic normalization only; see entries x-r001..x-r003).

## Unresolved / low-confidence items

36 entries below 0.6, all deliberately conservative:
- deserialized local-file/cache/DB sites (32, candidate 0.55): untrusted only
  if the file/DB source is attacker-controlled; re-reviewed and kept for recall.
- `ExceptionTool`/`InvalidTool` params (4, candidate 0.55): agent-internal
  echo tools, kept for recall.
No `unknown` classifications remain.

## Scope and constraints honored

- Passes in scope: [2] (CWE-077/078/088). Pass 1 block in `labels.json` is a
  schema-required zero-entry stub.
- No ground-truth artifacts read (`confirmed_vulns.json`, `cmd_sinks*.csv`,
  CVE/audit reports, `langchain-safe-db`); no source or DB modified.
- Every entry preserves API, file, line, arg index, flow kind, and a rationale
  with code-level evidence; no invented APIs.

## Next step (on approval)

Phase 2 Step 4: compile `labels.json` into `iris/libraries/MySources.qll`,
`MySinks.qll`, `MySanitizers.qll` (empty predicate, documented),
`MySummaries.qll`, then generate and run the pass-2 taint query. **Stopped
here per instruction — no CodeQL taint query executed yet.**
