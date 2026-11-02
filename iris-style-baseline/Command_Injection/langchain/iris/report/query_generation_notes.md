# Query Generation Notes — LangChain Pass 2 (CWE-077/078/088)

Phase 2 Step 4/5 output of the Augur 0.3.0 workflow (`iris_tools/augur-0.3.0/WORKFLOW.md`
§5.1–§5.2): rendering the reviewed Phase 1 labels into CodeQL libraries and the
formal pass-2 taint query.

## 1. Run identity

- run_id: `langchain-iris-pass2-labeling-20261015` (labels), Phase 2 rendered 2026-10-15
- target: LangChain vulnerable snapshot `61938a02a1e76fa6c6e8203c98a9344a179c810d`
  (`dataset/codeql_databases/langchain_vuln`), CodeQL DB `langchain-db`
- labels input: `labels/labels.json` (486 pass-2 entries), reviewed in
  `labels/phase1_review.md`
- threat model: prompt injection — LLM output is untrusted because prompts embed
  user/external content; `AgentAction.tool_input` is the agent→tool dispatch carrier
- renderer: `scripts/render_libraries.py` (deterministic; grouping/dedup/stable
  ordering per WORKFLOW §5.1.4). Regenerate with
  `python -I scripts/render_libraries.py <iris_root>`
- Pass 1 block in labels.json is a schema-required zero-entry stub and is
  deliberately not rendered (this run is scoped to pass 2).

## 2. Generated artifacts

| file | lines | role |
| --- | --- | --- |
| `libraries/MySources.qll` | 1063 | source model (120 tp strict + 294 candidate diagnostic tier) |
| `libraries/MySinks.qll` | 146 | sink model (13 tp labels) |
| `libraries/MySanitizers.qll` | 38 | empty barrier model (0 confirmed sanitizers) |
| `libraries/MySummaries.qll` | 186 | 5 additional taint steps (agent→tool→shell chain) |
| `queries/Pass2_CommandInjection.ql` | 62 | formal pass-2 query (`@kind path-problem`) |

## 3. Source model — 120 tp entries (formal tier)

`MySources::isSource(node, "command_injection")` dispatches to
`isSourceStrict` = classification=tp labels only. Five buckets:

| bucket | n | label ids | modeling basis |
| --- | --- | --- | --- |
| `isChainEntryParamSource` | 58 | src-r008..src-r452 | `inputs` param (arg 1) of the enumerated `Chain._call/_acall/acall` overrides — user task-text entry boundary, conf 0.9 |
| `isLlmOutputReturnSource` | 22 | src-r014..src-r463 | return values of enumerated `generate/_generate/predict/generate_prompt` methods on `BaseLanguageModel`-derived classes — untrusted model text, conf 0.85 |
| `isAgentActionParseSource` | 9 | src-r001..src-r246 | return values of the enumerated `AgentOutputParser.parse` overrides — `AgentAction` carrier, conf 0.85 |
| `isAgentActionToolInputSource` | 4 | src-r004..src-r007 | `.tool_input` attribute reads at the four tool dispatch sites in `agents/agent.py` (822/851/911/944), conf 0.9 |
| `isLLMTextDeserializationSource` | 27 | src-r024..src-r370 | `json.loads` return values at the labeled LLM/agent text parsing sites, conf 0.8/0.85 |

Every rule pins the labeled **(file, class, method)** triple for definitions or
**(file, line)** pair for call sites. Generic name/derivation rules were
rejected after measuring the repository: 114 `_call`-family definitions vs 58
labeled, 45 `parse` definitions vs 9 labeled, 28 generate-family definitions
vs 22 labeled — a name-based rule would have pulled in unreviewed sites
(“不添加未经标签审核的硬编码规则”).

### Candidate tier — 294 entries (NOT used by the formal query)

`isSourceDiagnostic` additionally includes:

- `isToolEntryParamCandidate` (238, src-r002..src-r470, conf 0.55–0.7):
  `BaseTool`-subclass `_run/_arun/run/__call__` params receiving agent-dispatched
  tool input. Kept out of the formal model because (a) they are candidates,
  not tp, and (b) six of these API sites are also execution-wrapper sinks —
  the phase-1 reconciliation already applied "sink role wins" and merged them;
  wiring all 238 into the formal query would fabricate trivial
  source==sink paths at every tool boundary ("不要把所有 Tool…自动标记为
  Source/Sink").
- `isDeserializedCandidate` (56, src-r011..src-r464, conf 0.55–0.6):
  `json.loads`/`json.load` over local-file/cache/DB/remote-response content —
  untrusted only if that origin is attacker-controlled.

## 4. Sink model — 13 tp entries

`MySinks::isSink(node, "command_injection")` = 7 argument-flow + 6 wrapper-param:

| rule | labels | sites |
| --- | --- | --- |
| `isShellSubprocessRunSinkArg` | snk-r06 | `subprocess.run(command, shell=True)` arg 0, `utilities/bash.py:76` — constrained to that file + literal `shell=True`, which resolves to exactly the one labeled call |
| `isPersistentShellSendlineSinkArg` | snk-r08 | `self.process.sendline(command)` arg 0, `bash.py:102` — `Name` argument requirement excludes the fixed-string calls at bash.py:56 (uuid prompt) and :106 (empty literal) |
| `isBuiltinExecEvalSinkArg` | snk-r11, r15, r21, r22, r23 | builtin `exec`/`eval` arg 0 in `utilities/jira.py` (:192, only exec in file), `utilities/python.py` (:19, only exec), `tools/python/tool.py` (:117/:123/:130, exactly the three labeled calls) |
| `isExecWrapperParamSink` | snk-r04, r18, r19, r20, r25, r26 | command param (arg 1) of `BashProcess._run`, `ShellTool._run/_arun`, `PythonREPLTool._run/_arun`, `PythonAstREPLTool._run`, pinned by (file, class, method) |

Excluded by label review (8 fp sinks, documented in the QLL header, not
modeled): `subprocess.run` beam.py:219 (fixed literal) and server.py:13/14
(fixed argv); `pexpect.spawn` bash.py:52; `sendline` bash.py:56/:106; `exec`
prompts/loading.py:151; `PythonAstREPLTool._arun` (NotImplementedError stub).

## 5. Sanitizer model — 0 entries

`MySanitizers::isBarrier(node, passKey)` resolves to `none()`. Three
candidates were reviewed against source and rejected (labels x-r001..x-r003):
`sanitize_input` (cosmetic token stripping), `ShellInput._validate_commands`
(str→list normalization, "TODO: Add real validators"), `BaseTool._parse_input`
(pydantic type validation only). The predicate is kept per WORKFLOW hard
constraint 6 so the query's `isBarrier` hook always compiles.

## 6. Summary model — 5 taint steps (agent → tool → shell)

| step | label | hop modeled |
| --- | --- | --- |
| `baseToolRunToSubclassRunStep` | src-r057 (`BaseTool.run`, base.py:256) | `run(tool_input)` param → every `BaseTool`-subclass `_run` input param. Essential: `run` dispatches through `_parse_input` + `_to_args_and_kwargs` + `self._run(*tool_args, **tool_kwargs)`, which native dataflow does not resolve for virtual dispatch. This is the agent→tool propagation edge. |
| `baseToolDunderCallToRunStep` | src-r058 (`BaseTool.__call__`, base.py:400) | `__call__(tool_input)` param → `run(tool_input)` param |
| `bashProcessRunToInternalStep` | snk-r03 (`BashProcess.run`, bash.py:61) | `run(commands)` param → `_run` / `_run_persistent` command param |
| `bashRunPersistentToSendlineStep` | snk-r07 (`BashProcess._run_persistent`, bash.py:97) | `command` param → the `sendline(command)` argument (sink node of snk-r08) |
| `pythonReplRunToExecStep` | snk-r13 (`PythonREPL.run`, python.py:14) | `run(command)` param → the `exec(command)` argument (sink node of snk-r15) |

The last three hops are also natively tracked (direct local calls); they are
rendered anyway because the labels model them explicitly and the explicit
steps guarantee the path even where `";".join(commands)` or call-object
indirection breaks native flow. `classHasBaseNamed` is copied verbatim from
`extraction/sinks.ql` (phase 1) because `Class.getABase()` yields unresolved
base expressions in this pack.

End-to-end modeled path (matches `phase1_review.md` §"Primary modeled path"):
`AgentExecutor._call` (source) → LLM output (source) →
`AgentOutputParser.parse` (source) → `agent_action.tool_input` (source,
agent.py:851) → `BaseTool.run` (summary) → `ShellTool._run` (sink snk-r25) →
`BashProcess.run` (summary) → `BashProcess._run` (sink snk-r04) →
`subprocess.run(command, shell=True)` (sink snk-r06); persistent mode via
`_run_persistent` → `sendline` (snk-r08); code-exec variants via
`PythonREPLTool/PythonAstREPLTool` → `exec/eval` (snk-r15/r21/r22/r23) and
`JiraAction` → `exec` (snk-r11).

## 7. Formal query — `queries/Pass2_CommandInjection.ql`

- rendered from `assets/taint_query.ql.tmpl` with:
  `{{QUERY_ID}}` `py/augur/langchain/pass2-command-injection`,
  `{{PASS_KEY}}` `command_injection`, `{{CONFIG_NAME}}` `Pass2Config`,
  `{{FLOW_MODULE}}` `Pass2Flow`, primary CWE 78 with extra tags 077/088,
  `{{PRECISION}}` low, Python language imports
  (`python`, `semmle.python.dataflow.new.DataFlow`,
  `semmle.python.dataflow.new.TaintTracking`)
- `@kind path-problem`; `select sink.getNode(), source, sink, message`
  plus two `$@` placeholder columns labeling the source/sink ends —
  this is the standard CodeQL idiom for richer SARIF messages and is what
  SARIF codeFlows render per result
- `TaintTracking::Global<Pass2Config>` (global taint tracking: sources and
  sinks sit in different modules and dispatch hops)
- no hardcoded rules beyond the label tables; every source/sink/summary rule
  cites its label id(s)

## 8. Deviations from the Augur template / compatibility notes

1. **Site pinning instead of signature-only matching.** The template expects
   rules that "match labeled API signatures"; for this repository a bare
   signature match (method name + class derivation) over-matches heavily
   (see §3 numbers), so all rules pin (file, class, method) or (file, line)
   to the reviewed sites. This is stricter than, not looser than, the
   template contract.
2. **`ReturnStmt` → `Return`.** python-all 7.1.2 names the return-statement
   class `Return`; the first compile failed with `could not resolve type
   ReturnStmt` and was fixed in the renderer (see
   `diagnostics/compile_notes.md`).
3. **Strict/diagnostic tiering** follows the interface convention used by the
   previous manual run (`iris_manual/autogluon/iris`): pass-key dispatch
   (`isSource(node, "command_injection")`) resolves to the tp-only strict
   model; the candidate tier exists as `isSourceDiagnostic` for future
   diagnostic queries and is not referenced by any formal query.
4. **`classHasBaseNamed`** (name-based recursive base matching) instead of a
   `getABaseClass()`-style API, which does not exist in this pack
   (`Class.getABase()` returns base expressions). Copied from the phase-1
   extraction queries, which compiled and ran against the same DB.
5. **Sanitizer predicate resolves to `none()` with a `passKey` binding** —
   the autogluon reference left the parameter unused; we bind
   `passKey = "command_injection"` for symmetry with the other libraries
   (this produces the one benign unused-parameter warning noted in the
   compile notes).
6. No `os.system`/`os.popen`/`subprocess.Popen` generic sinks: none of those
   sites carry a tp label in this run (all were fp or absent), so adding them
   would be an unreviewed hardcoded rule.

## 9. Not done (per instruction)

No formal database analysis was run (`codeql database analyze` / query
execution stopped at `codeql query compile`); no ground-truth artifacts in
the `langchain_vuln` root were read.
