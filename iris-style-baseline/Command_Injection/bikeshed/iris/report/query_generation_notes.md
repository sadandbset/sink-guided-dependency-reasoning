# Query Generation Notes — Augur Phase 2, Step 4/5 (Bikeshed, Pass 2, CWE-78)

- **Generated:** 2026-10-14 (files only; final CodeQL analysis deliberately NOT run)
- **Run:** `bikeshed-iris-pass2-step3-20261013` (labels minted at Step 3)
- **Input labels:** `iris/labels/labels.json` — Pass 1 is an empty schema placeholder (no CWE-22 work); Pass 2 (CWE-78 only, narrowed from Augur's default 077/078/088) has 49 entries: 14 source / 20 sink / 0 sanitizer / 3 summary / 12 none; by classification 15 tp / 10 candidate / 24 fp.
- **Generated artifacts:** `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass2_CommandInjection.ql`, `diagnostics/Pass2_DiagnosticParameter.ql`.
- **Toolchain:** CodeQL CLI 2.25.1; target pack `codeql/python-all@7.0.4`; all used APIs verified against the local pack cache 7.1.2 (`semmle.python.dataflow.new.DataFlow`, `semmle.python.dataflow.new.TaintTracking`, AST classes — all version-stable across 7.0.x–7.1.x).
- **Label filter applied:** an entry is modeled iff `role != none` AND `classification in {tp, candidate}`. `classification=fp` entries are per-site refutations and are excluded; `role=none` entries are excluded outright. This preserves conservative recall (candidates kept) without re-admitting refuted sites.

## 1. Label → model mapping (complete disposition of all 49 entries)

### 1.1 Sources (`role=source`) → `libraries/MySources.qll`

| label | API / site | class | disposition | QL modeling |
| --- | --- | --- | --- | --- |
| p2-src-001 | `StdinInputSource.read` return, InputSource.py:118 | tp | modeled | `SpecInputChain::InputSourceFunctionReturns`: `DataFlow::exprNode(Return.getValue())` of the method (global taint propagates the return to every call site) |
| p2-src-002 | `sys.stdin.readlines()`, InputSource.py:119 | tp | modeled | `SpecInputChain::InputSourcePrimitives`: value node of the call, restricted to file+line |
| p2-src-003 | `UrlInputSource._fetch` return, InputSource.py:136 | tp | modeled | same function-return shard as p2-src-001 |
| p2-src-004 | `requests.get(...)`, InputSource.py:137 | tp | modeled | call value node, restricted to InputSource.py:137 (the 12 other `requests.get` sites are fp — not modeled) |
| p2-src-005 | `UrlInputSource.read` return, InputSource.py:146 | tp | modeled | function-return shard |
| p2-src-006 | `FileInputSource.read` return, InputSource.py:168 | tp | modeled | function-return shard |
| p2-src-007 | `open(...)`, InputSource.py:169 | tp | modeled | call value node, restricted to InputSource.py:169 (the 45-site internal `open` family is fp — not modeled) |
| p2-src-008 | `argparse add_argument` family (75 sites) | candidate | modeled (remapped) | see §2.3 — mapped onto `parse_args`/`parse_known_args` return values (the point where CLI values materialize), per the label's own Phase-2 note and phase1_review.md §7.6 |
| p2-src-009 | `argparser.parse_args()` return, fonts.py:218 | candidate | modeled | covered by the same `CommandLineSurface` shard (all production parse calls: cli.py:432, fonts.py:218, release.py:48) |
| p2-src-010 | `sys.stdin.readlines()`, fonts.py:174 | candidate | modeled | `RetainedCandidateReads`, restricted to file+line |
| p2-src-011 | `open(...)`, fonts.py:176 | candidate | modeled | `RetainedCandidateReads`, file+line (fonts.py also has open at 66/197 — excluded) |
| p2-src-012 | `open(...)`, issuelist.py:31 | candidate | modeled | `RetainedCandidateReads`, file+line (open at 54 is a write — excluded) |
| p2-src-013 | `open("semver.txt")`, release.py:23 | candidate | modeled | `RetainedCandidateReads`, file+line (release.py opens at 71/75/112 excluded) |
| p2-src-014 | `open("secrets.json")`, release.py:28 | candidate | modeled | same branch as p2-src-013 |
| p2-src-015 | `os.environ.get`, cli.py:441 | fp | **excluded** | color cosmetics only; no command route |
| p2-src-016 | `requests.get` (12 merged sites) | fp | **excluded** | update tooling / link linting; Pass 3 family, not CWE-78 |
| p2-src-017 | `requests.post`, publish.py:32 | fp | **excluded** | response never used in command construction |
| p2-src-018 | `open()` (45 merged internal sites) | fp | **excluded** | internal data / pipeline outputs; not an external boundary |
| p2-src-019 | `os.environ[...]`, update.py:121 | fp | **excluded** | GITHUB_TOKEN for API client |
| p2-src-020 | `DataFileRequester.fetch` return | fp | **excluded** | install-dir spec-data reads |

### 1.2 Sinks (`role=sink`) → `libraries/MySinks.qll`

| label | API / site | class | disposition | QL modeling |
| --- | --- | --- | --- | --- |
| p2-sink-001 | `Popen` arg 0 (shell=True), inlineTags/__init__.py:14 | tp | modeled | `ProcessExecutionSinks`: `DataFlow::exprNode(Call.getArg(0))` of the unqualified `Popen` call, file+line |
| p2-sink-002 | `processTags(doc)` param | tp | modeled | `WrapperParameterSinks`: `DataFlow::parameterNode(f.getArgByName("doc"))` |
| p2-sink-003 | `os.system` arg 0, cli.py:669 | tp | modeled | `ProcessExecutionSinks`, file+line 669 |
| p2-sink-004 | `os.system` arg 0, cli.py:675 | tp | modeled | same branch, line 675 |
| p2-sink-005 | `handleProfile(options)` param | tp | modeled | `WrapperParameterSinks`: `parameterNode(getArgByName("options"))` |
| p2-sink-006/007/008/009 | `check_output` arg 0, boilerplate.py:36/49/92/103 | fp | **excluded** | literal command strings; cwd is not the command argument |
| p2-sink-015/016 | `check_output` arg 0, release.py:14/65 | fp | **excluded** | literal `git diff --stat` / `git log` |
| p2-sink-017/020/021/023/025/026 | `call`/`check_output`/`check_call` arg 0, release.py:80/109/117/122/128/81 | fp | **excluded** | literal commands |
| p2-sink-018 | `check_call` arg 0, release.py:83 | candidate | modeled | `ProcessExecutionSinks`, release.py line 83 |
| p2-sink-019 | `check_call` arg 0, release.py:97 | candidate | modeled | line 97 |
| p2-sink-022 | `check_call` arg 0, release.py:121 | candidate | modeled | line 121 (f-string `git commit -m 'Bump semver to {newVersion}'`) |

### 1.3 `role=none` (12 entries) — all excluded

p2-sink-010 (`addBikeshedVersion`), p2-sink-011 (`addSpecVersion`), p2-sink-013 (`getSpecRepository`), p2-sink-014 (`createRelease`), p2-sink-024 (`inBikeshedRoot`), p2-sink-012 (`check_output` list-form at metadata.py:1169), p2-src-015/016/017/018/019/020 (see §1.1). These are refuted candidacies — no predicates generated for them.

### 1.4 Summaries (`role=summary`) → `libraries/MySummaries.qll`

| label | function | class | modeling |
| --- | --- | --- | --- |
| p2-sum-001 | `metadata.parse(lines)` param 0 | tp | additional taint step: `parameterNode(parse.getArg(0))` → value node of each `metadata.parse(...)` call in production code (Spec.py:146) |
| p2-sum-002 | `metadata.fromCommandLine(overrides)` param 0 | tp | same shape (call sites cli.py:503–606, 653) |
| p2-sum-003 | `metadata.fromJson(data)` param 0 | tp | same shape (call sites Spec.py:150, 164) |

### 1.5 Sanitizers (`role=sanitizer`)

**None labeled.** `MySanitizers.isBarrier(node, passKey)` is defined with a `none()` body per WORKFLOW.md 5.2.3 (mandatory barrier hook, empty fallback). The only neutralization evidence in the codebase — the argument-list, no-shell `check_output(["git","remote","-v"])` at metadata.py:1169 — was recorded as role=none (p2-sink-012) and is deliberately NOT turned into a barrier (that would be an invented sanitizer).

## 2. Source/Sink modeling rationale

### 2.1 Two-level source modeling (function return + primitive)

The InputSource boundary is labeled at two levels, and both are modeled:
1. **Primitive level** (p2-src-002/004/007): the `sys.stdin.readlines()` / `requests.get()` / `open()` call value nodes at their exact labeled lines. Taint originates at the actual external-input primitive.
2. **Function level** (p2-src-001/003/005/006): the *return expression inside* each labeled `InputSource` method is a source node. Global taint tracking (`TaintTracking::Global`) propagates a tainted return value to the value of every call of that method, so `Spec.py:114 self.inputSource.read()` becomes tainted even if the primitive-level chain is interrupted (e.g. if `open()` → `with ... as fh` → `fh.readlines()` receiver flow is not modeled by the stdlib taint summaries).

### 2.2 Param-level wrapper sinks

`processTags(doc)` and `handleProfile(options)` are labeled as param-level sinks precisely because object-level taint (a tainted `doc`/`options` object) is the realistic arrival point; CodeQL does not generally propagate taint from an object to individual attribute values (`options.root`, `doc.md.inlineTagCommands[tag]`).

### 2.3 CLI surface remapping (the known extraction gap)

`add_argument` only *declares* arguments; values materialize at `parse_args`/`parse_known_args`. `cli.py:432 parse_known_args()` was an extraction gap (phase1_review.md §7.6). Per the p2-src-008 label's own Phase-2 instruction, `MySources::CommandLineSurface` marks the **return value of every production `parse_args`/`parse_known_args` call** as a source (the argparse Namespace). In this database that is exactly three sites: cli.py:432, fonts.py:218, release.py:48 — all within the add_argument label's merged site set (71×cli.py, 2×fonts.py, 2×release.py).

Expected effect: `options` (cli.py:432, tainted via tuple unpacking) → `handleProfile(options)` (cli.py:470) → param sink p2-sink-005 fires. The arg-level `os.system` sinks (669/675) additionally require Namespace→attribute-value taint (`options.root`), which standard taint propagation does not provide — so the arg-level CLI chain is expected NOT to fire; the param-level sink is the labeled compensation.

## 3. Model limitations (expected behavior of the generated query)

These are honest consequences of modeling *only* the labeled entries; none of them was patched with invented summaries (per the experiment rule: no unconditional propagation rules without evidence):

1. **The canonical Popen chain has a propagation gap at the metadata merge.** Chain: `read()` → `self.lines` → `metadata.parse(lines)` (summary step p2-sum-001 taints the returned `(newlines, md)` tuple → `self.mdDocument`) → `metadata.join(mdBaseline, mdDefaults, mdDocument, mdCommandLine)` → `self.md` → `doc.md.inlineTagCommands[tag]` → `Popen(command, shell=True)`. `metadata.join` and the `MetadataManager` attribute chain (`md.inlineTagCommands[...]`) are **not** labeled as summaries, so taint is expected to stop at `mdDocument`/`mdCommandLine` unless the standard library models object-attribute flow further than anticipated. The param-level sink `processTags(doc)` also requires object-level taint on the whole `Spec` instance, which standard propagation does not produce from a tainted attribute.
2. **`with open(...) as fh: fh.read()` receiver flow.** For FileInputSource and the release.py candidates, taint from the `open()` call node to the `read()`/`readlines()` result depends on CodeQL's stdlib context-manager/file-read taint summaries. The function-level source shard (§2.1) compensates for the spec-file chain; the release.py candidate chain (open@23/28 → check_call@83/97/121) may or may not fire depending on this modeling.
3. **CLI arg-level sinks** need Namespace→attribute taint (see §2.3) — expected to fire only via `handleProfile(options)`.
4. **Candidate entries may produce Step-6 FPs by design** (release.py local-file → twine/git-commit interpolations, and any fonts/issuelist reads that connect). These are retained deliberately for recall and are to be resolved by the Step 6 heuristic filter and path triage, not by weakening the model.

`diagnostics/Pass2_DiagnosticParameter.ql` exists to measure exactly these gaps: it reports whether source taint reaches the parameters of `metadata.parse`/`fromCommandLine`/`fromJson` (summary params) and `processTags`/`handleProfile` (wrapper sinks) using **standard propagation only** (no MySummaries steps), so its results explain where each chain fires or stops. Its findings are diagnostics — they must not be counted as vulnerability TPs (marked `@tags diagnostics`, `@problem.severity warning`, separate query id).

## 4. QL interface choices

- **Modular Python data flow API:** `import semmle.python.dataflow.new.DataFlow` + `import semmle.python.dataflow.new.TaintTracking`, with `module X implements DataFlow::ConfigSig` and `module Flow = TaintTracking::Global<Config>` + `import Flow::PathGraph` — the exact shape prescribed by WORKFLOW.md 5.2.1a / 3.1(2). `ConfigSig` members used: `isSource`, `isSink`, `isBarrier` (mandatory even though empty), `isAdditionalFlowStep`.
- **AST↔DataFlow node conversion (type-safe, verified in the local 7.1.2 pack):**
  - expression/call value nodes: `DataFlow::exprNode(Expr)` (e.g. `DataFlow::exprNode(c)`, `DataFlow::exprNode(c.getArg(0))`, `DataFlow::exprNode(r.getValue())`);
  - parameter nodes: `DataFlow::parameterNode(Parameter)` (via `Function.getArg(0)` / `Function.getArgByName(...)`);
  - AST call-shape matching mirrors the Phase 1 extraction queries (`Call.getFunc()` → `Attribute.getName()/getObject()` / `Name.getId()`), which already compiled and reproduced the labeled sites — so every modeled node is provably one of the labeled candidates. API Graph nodes were **not** needed (no framework wrappers; all sinks are plain module-qualified or from-imported calls already matched exactly by AST shape); this keeps the generated code independent of API-graph version drift between 7.0.4 and the local cache.
- **Sharded libraries per WORKFLOW.md 5.1.5:** each `My*.qll` exposes one pass-key-dispatching predicate (`isSource/isSink/isBarrier/isAdditionalTaintStep` taking `string passKey`) and delegates to per-family nested modules (`SpecInputChain`, `CommandLineSurface`, `RetainedCandidateReads`, `ProcessExecutionSinks`, `WrapperParameterSinks`, `MetadataParsingSteps`). All pass keys except `"command_injection"` deliberately resolve to nothing.
- **Import style:** the query imports the libraries with dot syntax relative to the pack root — `import libraries.MySources` etc. (NOT `import iris.generated.MySources`, NOT slash syntax). Inside the query config the imported modules are referenced by their module names (`MySources::isSource(source, "command_injection")`).
- **Template rendering deviation (documented):** in `assets/taint_query.ql.tmpl`, `{{SOURCE_MODULE}}` (and the sink/sanitizer/summary equivalents) appears both in the import line and in the config body. It is rendered as `libraries.MySources` for the import statement and as `MySources` in the config body, because in QL the import path (`libraries/MySources.qll` relative to the pack root) and the module defined in that file (`module MySources`) are different names; `libraries.MySources::isSource(...)` would not resolve. All other placeholders follow the template contract (`{{PASS_KEY}}` = `command_injection`, `{{CONFIG_NAME}}` = `Pass2Config`, `{{FLOW_MODULE}}` = `Pass2Flow`, `{{LANGUAGE_IMPORTS}}` = python + new DataFlow/TaintTracking, `{{CWE_PRIMARY}}` = 078, `{{EXTRA_TAGS}}` = none — the experiment is narrowed to CWE-78 only).
- **Python-specific pitfalls (WORKFLOW.md §9):** no `Decorator` AST class is used (no decorators in the model); no deprecated `StrConst`/string-literal classes; flow config predicates are minimal and explicit.

## 5. Query metadata choices (`queries/Pass2_CommandInjection.ql`)

- `@kind path-problem` with `@problem.severity error` (mandatory, WORKFLOW.md 3.5/5.2.2).
- `@id py/bikeshed/iris/pass2-command-injection` — unique to this Bikeshed experiment (distinct from any AutoGluon run; no AutoGluon paths/functions/ids reused).
- `@tags security`, `external/cwe/cwe-078` only (scope narrowed to CWE-78; no cwe-077/088 extra tags).
- `@precision medium`: source/sink models are site-restricted (file+line) from reviewed labels, but param-level wrapper sinks and candidate-class entries (release.py local-file interpolations) are deliberately kept for recall and will need Step 6 triage.

## 6. Pending items for Step 5 execution (not performed here)

Per the instruction, **no CodeQL analysis was run**; generation stopped after writing the files. Before the first `codeql database analyze` run:

1. **`iris/qlpack.yml` does not exist.** `import libraries.MySources` (dot-path resolution) requires a pack root at `iris/` with, per WORKFLOW.md 4.1.4: `name: iris/generated`, `version: 0.0.1`, `dependencies: codeql/python-all: "*"`. It was not created here because this step is only allowed to write to `libraries/`, `queries/`, `diagnostics/`, `report/`. It must be created (and `codeql pack install` run from `iris/`) before any query executes. (How exactly Step 2 resolved `import python` for the extraction queries without a visible qlpack.yml in the workspace was not re-derived here; the Step 5 operator should verify the pack setup before the first run.)
2. Recommended compile check before analysis: `codeql query compile iris/queries/Pass2_CommandInjection.ql` (and the diagnostic query), then sequential runs per WORKFLOW.md 5.2.4 into `iris/results/pass2.sarif`, appending `iris/results/run_log.md`.
3. Run the diagnostic query separately (e.g. `--output=iris/results/pass2_diagnostic.sarif`); exclude its results from TP counting.
4. `iris/exploration/run_manifest.json` is still missing (noted at Step 3); record CLI 2.25.1 / python-all 7.0.4 / model glm-5.3 there when the run happens.
