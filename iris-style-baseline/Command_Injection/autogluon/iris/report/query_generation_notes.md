# Augur Phase 2 - Step 4/5 Query Generation Notes (Pass 2 / CWE-078, AutoGluon)

- run_id: `autogluon-pass2-phase1-20261012` (labels: `iris/labels/labels.json`, reviewed)
- generated_at: 2026-10-12
- target DB: `C:\Users\lzh\Desktop\github\PyVul-main\dataset\codeql_databases\autogluon-db`
- toolchain: CodeQL CLI 2.25.1; qlpack `iris/qlpack.yml` depends on `codeql/python-all: "*"`

## Generated files

| file | content |
| --- | --- |
| `iris/libraries/MySources.qll` | strict / diagnostic / dispatch source predicates |
| `iris/libraries/MySinks.qll` | shell=True `subprocess.check_output` sink rule (arg 0) |
| `iris/libraries/MySanitizers.qll` | empty barrier hook (compilable `none()`) |
| `iris/libraries/MySummaries.qll` | empty additional-taint-step hook |
| `iris/queries/Pass2_CommandInjection.ql` | formal pass-2 taint query (strict sources) |
| `iris/diagnostics/Pass2_DiagnosticParameter.ql` | diagnostic-only propagation check |

## Effective source rules and label evidence

All source labels are `classification=candidate` - **not confirmed attacker-controlled input**.
The model is split so the formal query only uses the strict set:

| rule (in `MySources.qll`) | label ids | evidence (verified in source) | confidence | used by |
| --- | --- | --- | --- | --- |
| `isSourceStrict` - `os.environ["SM_CURRENT_HOST"]` | p2-supp-001 | `current_host = os.environ['SM_CURRENT_HOST']` (sync_remote.py:13); only read of this key in the repo | 0.50 | formal + diagnostic |
| `isSourceStrict` - `os.environ["SM_HOSTS"]` | p2-supp-002 | `hosts = json.loads(os.environ['SM_HOSTS'])` (sync_remote.py:14) | 0.50 | formal + diagnostic |
| `isSourceSyncTrainingProcessId` - parameter `proccess_id_string` (arg 0) of `sync_training_processes` | p2-src-4863 | `def sync_training_processes(proccess_id_string, worker_id, sync_frequency=300)` (sync_remote.py:46); parameter is interpolated into the `shell=True` f-strings at lines 50/52; sole in-repo caller `sagemaker_setup` passes fixed literal `'dask-scheduler'`; module `__all__` exports only `sagemaker_setup` | 0.50 | **diagnostic only** |
| `isSourceDiagnostic` - `main(args)` (arg 0), argparse-fed | p2-src-0971, p2-src-1912, p2-src-2326, p2-src-4091 | argparse-fed `main(args)` in examples/automm/distillation/automm_distillation.py:19, examples/automm/tabular_dl/example_tabular.py:55, examples/text_prediction/generate_submission.py:24, examples/text_prediction/prepare_glue.py:614; no path from these scripts to any command-execution API | 0.45 | diagnostic only |
| `isSource(node, passKey)` | dispatch | `passKey = "command_injection"` -> `isSourceStrict` only | - | formal query |

Not rendered into the model: **6453 `role=none` entries** (function parameters with no
external-attacker-control evidence and no path to a command-execution API). Rendering them
would turn thousands of internal parameters into bogus sources.

## Effective sink rule and label evidence

One signature-level rule (labels p2-sink-002 and p2-sink-003 share the same signature and were
deduplicated):

| rule (in `MySinks.qll`) | label ids | evidence | confidence |
| --- | --- | --- | --- |
| `isShellEnabledCheckOutputCall` + `isShellCommandSinkArg`: `subprocess.check_output`, argument 0, with literal `shell=True`, in `core/src/autogluon/core/utils/sync_remote.py` | p2-sink-002 (line 50), p2-sink-003 (line 52) | `subprocess.check_output(f'ps -elf | grep "{proccess_id_string}"', encoding='utf-8', shell=True)` - the only `shell=True` command executions in the entire repository | 0.90 |

The rule is deliberately narrow (file + `shell=True` + API + argument 0) so that the other
`subprocess` calls in the project are **not** treated as equally dangerous sinks:

| excluded call site | label | why excluded |
| --- | --- | --- |
| `subprocess.Popen(["/usr/sbin/sshd", "-D"])` (sync_remote.py:16) | role=none/fp | fixed literal argument list, no shell |
| `subprocess.check_output(COMMAND.split())` (utils.py:890) | role=none/fp | fixed literal "nvidia-smi ..." command, list form, no shell |
| 9x `Popen(['flake8', ...])` in `tests/test_check_style.py` | role=none/fp | test files, fixed literal list, no shell |

## Barrier rules

| rule | labels | evidence |
| --- | --- | --- |
| `MySanitizers::isBarrier(node, passKey)` -> `none()` | none | Zero sanitizer labels: repository-wide search found no `shlex` usage, no allow-list validation, no quoting on the two `shell=True` call sites. Sanitizers are only labeled with concrete evidence. The predicate is kept (empty) so the query's `isBarrier` hook always compiles (workflow hard constraint 6). |

## Propagation rules

| rule | labels | evidence |
| --- | --- | --- |
| `MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, passKey)` -> `none()` | none active | Label p2-supp-003 (`get_gpu_free_memory`, summary/candidate 0.55) is deliberately **not** rendered: the function has no input parameters, so there is no parameter-to-return propagation to model; its command is a fixed literal (output not attacker-influenced); and if the `check_output` result were ever a source, native data flow already carries the parsed output to the return value. |

## Template substitutions (assets/taint_query.ql.tmpl -> Pass2_CommandInjection.ql)

| placeholder | value |
| --- | --- |
| `{{QUERY_NAME}}` | AutoGluon Pass 2: Command/Argument Injection (CWE-078) |
| `{{QUERY_DESCRIPTION}}` | tracks candidate external input (env vars) to the shell-enabled check_output sink; sources are label candidates |
| `{{QUERY_ID}}` | `py/augur/autogluon/pass2-command-injection` |
| `{{PRECISION}}` | `low` (all sources are candidates; findings need human review) |
| `{{CWE_PRIMARY}}` | `078` |
| `{{EXTRA_TAGS}}` | none - the pass was scoped to CWE-078 only, so the line was omitted (no CWE-077/088 tags added) |
| `{{LANGUAGE_IMPORTS}}` | `import python`, `import semmle.python.dataflow.new.DataFlow`, `import semmle.python.dataflow.new.TaintTracking` |
| `{{SOURCE_MODULE}}` / `{{SINK_MODULE}}` / `{{SANITIZER_MODULE}}` / `{{SUMMARY_MODULE}}` | `MySources` / `MySinks` / `MySanitizers` / `MySummaries` |
| `{{CONFIG_NAME}}` | `Pass2Config` |
| `{{FLOW_MODULE}}` | `Pass2Flow` |
| `{{PASS_KEY}}` | `command_injection` |
| `{{RESULT_MESSAGE}}` | review-candidate message embedded in the select |

Deviations from the literal template (both documented, both required for a working build):

1. The four library imports are written as pack-relative file paths
   (`import libraries/MySources`, ...) because the `.qll` files live in
   `iris/libraries/` while the pack root (qlpack.yml) is `iris/`. Intra-pack imports
   resolve from the pack root (verified against `semmle/python/frameworks/Stdlib.qll`).
   The call sites keep the template shape `MySources::isSource(source, "<passKey>")`.
2. `@problem.severity error` and `@kind path-problem` are set exactly as required.

## API compatibility verification

All QL primitives used were verified against the locally cached `codeql/python-all`
sources (pack cache: 7.1.1 and 7.1.2; qlpack resolves `*`; the stated local version was
7.0.4 - the used API surface is stable across 7.0.x-7.1.x, every symbol was
re-checked in the cached 7.1.2 source):

- `DataFlow::ConfigSig` (isSource/isSink/isBarrier/isAdditionalFlowStep) -
  `codeql/dataflow/2.1.7/codeql/dataflow/DataFlow.qll:401`
- `TaintTracking::Global<Config>`, `Flow::PathGraph`, `Flow::PathNode`, `Flow::flowPath`
  - `TaintTracking.qll:313` and `DataFlow.qll:710` (GlobalFlowSig)
- `DataFlow::parameterNode(Parameter)` - `DataFlowPublic.qll:350`, official usage in
  `frameworks/Websockets.qll:69`
- `DataFlow::CallCfgNode`, `getArg(int)`, `getArgByName(string)` - proven to compile on
  this exact toolchain by the Phase 1 extraction query `iris/extraction/sinks.ql`
- `API::moduleImport(...).getMember(...).getACall()` and `getSubscript(key)` -
  `semmle/python/ApiGraphs.qll:271`
- literal `True` check via `asExpr() instanceof True` - `semmle/python/Exprs.qll:597`

## Diagnostic query semantics (iris/diagnostics/Pass2_DiagnosticParameter.ql)

- Source: **only** `MySources::isSourceSyncTrainingProcessId` (label p2-src-4863,
  `proccess_id_string`), never the strict env sources.
- Sink: same narrowed sink rule (arg 0 of the `shell=True` `check_output` calls).
- It is tagged `@problem.severity warning` and `@tags diagnostic`, and both the
  description and result message state it must not be counted as a CWE-78 detection
  or as a true positive in the Augur final report. It answers exactly one question:
  does `proccess_id_string` propagate to the command argument at lines 50/52?

## Suggested execution (to be run manually by the reviewer)

```bash
codeql query compile iris/queries/Pass2_CommandInjection.ql --search-path iris
codeql database analyze "C:\Users\lzh\Desktop\github\PyVul-main\dataset\codeql_databases\autogluon-db" \
  iris/queries/Pass2_CommandInjection.ql --format=sarifv2.1.0 --output=iris/results/pass2.sarif
# diagnostic (NOT counted as findings):
codeql database analyze "C:\Users\lzh\Desktop\github\PyVul-main\dataset\codeql_databases\autogluon-db" \
  iris/diagnostics/Pass2_DiagnosticParameter.ql --format=sarifv2.1.0 --output=iris/results/pass2_diagnostic.sarif
```

## Expected outcome (for calibration only - not a claim)

The strict env sources flow into `current_host`/`worker_id`, which only reach `print()`
inside `sync_training_processes`; the formal query is therefore expected to produce zero
or few paths. The diagnostic query is expected to produce one path
(`proccess_id_string` -> f-string -> `check_output` arg 0), which confirms in-model
propagation but not attacker control. Any result must still be human-verified - no CWE-78
vulnerability is claimed at this stage.

---

## v2 Post-triage Remediation（2026-10-19，本轮追加）

正式查询 v1 结果为 0 条告警，未命中真实漏洞（`multimodal/src/autogluon/multimodal/predictor.py:1124`
`_top_k_average` 的 `yaml.load(f, Loader=yaml.Loader)` 不安全反序列化；上游修复提交 23a37e7
"[Security] load --> safe_load (#1987)"）。经操作员授权执行最小增补并重跑。

### 关键事实：DB 版本 vs 磁盘版本

- CodeQL 数据库 `autogluon-db` 创建于 **sha 1a62b445（漏洞版父提交）**——DB 内代码为
  `yaml.load(f, Loader=yaml.Loader)`（已从 DB src.zip 验证，predictor.py:1124，全库唯一一处
  unsafe yaml.load）。
- 磁盘工作树 `autogluon_vuln` 的 git HEAD 为 **23a37e74（修复提交）**——磁盘上该位置已是
  `yaml.safe_load`。**行号锚定与源码核验必须以 DB 版本为准**（读 DB 的 src.zip 或 checkout
  1a62b44），不能信当前磁盘树。

### 修改内容（originals 保存在 `iris/backup_v1/`，含 v1 的 results/pass2.sarif）

1. `labels/labels.json`（6463 → 6465 条）：
   - `p2-supp-004`（source, candidate 0.55）：predictor.py:1123 `open(best_k_models_yaml_path, "r")`
     文件内容边界（best_k_models.yaml 模型工件，DB 版本行号）
   - `p2-sink-013`（sink, **tp 0.85**）：predictor.py:1124 `yaml.load(f, Loader=yaml.Loader)`
     流实参（PyYAML unsafe full Loader）
   - metadata.notes 追加 v2 remediation 说明
2. `libraries/MySources.qll`：新增 `isSourceFileContent` 谓词（AST 匹配 builtin `open()` +
   文件/行锚定 predictor.py:1123），接入 `isSource("command_injection")` 分发（formal 生效）
3. `libraries/MySinks.qll`：新增 `unsafeYamlLoadSink` 谓词（callee `Attribute(load)` +
   `fn.getObject().(Name).getId()="yaml"` + keyword `Loader` 值为 unsafe loader Attribute +
   arg 0 + 行锚定 1124），接入 `isSink("command_injection")`
4. `queries/Pass2_CommandInjection.ql`：更新 `@description` 与 select 消息（覆盖两类 sink，
   消除对 yaml 告警的 shell 误导文本）；查询逻辑零改动（委托库谓词）

无需 sanitizer / 自定义 taint step（`with open(p) as f: yaml.load(f, ...)` 由原生局部数据流传播）。
独立先行验证：`../hitcheck/`（最小查询对同一 DB 验证 1 命中 0 误报）。

### 重跑命令与结果

```
codeql query compile queries/Pass2_CommandInjection.ql --search-path=<python-all>,<threat-models>   # Done [1/1]
codeql database analyze <autogluon-db> queries/Pass2_CommandInjection.ql \
  --format=sarifv2.1.0 --output=results/pass2.sarif --rerun \
  --search-path="E:/codeql-codeql-cli-2.25.2/python/ql/lib" \
  --search-path="E:/codeql-codeql-cli-2.25.2/shared/threat-models"
python iris_tools/augur-0.3.0/scripts/filter_and_report.py \
  --input-dir results_v2 --labels labels/labels.json --output report/iris_report_v2.md
```

（注意：`database analyze` 必须加 `--rerun`；报告输入目录用 `results_v2/`（仅正式 sarif 副本），
避免把 results/ 里的 pass2_diagnostic.sarif 与 pass2_review_queue.json 混入计数。）

- `results/pass2.sarif`：**1 条正式告警**（v1 为 0）——predictor.py:1124，指纹 191261928bc5f45d:1，
  codeFlow：`1123 open() → f → 1124 yaml.load(...)`（3 步，全部真实代码行）
- **命中行 1124 与修复提交 23a37e7 在 `_top_k_average` 中改动的行完全重合（位置重叠 100%），
  真实漏洞 recall 1/1；全库唯一 unsafe yaml.load，零误报**
- `report/iris_report_v2.md`：Label Summary 8 sources / 3 sinks；该告警因报告工具的 pass-2
  TP 启发式只识别 shell 文本模式而落入 "Candidate"——已附 Analyst Addendum（判定 likely_tp 0.9）
  并给出工具改进建议（TP 模式应包含 unsafe-loader 反序列化族）；共享脚本未修改
- 运行通知中 examples/automm/kaggle_pawpularity/kaggle_pawpularity_submit.py 的 parse error 为
  DB 既有问题（v1 运行同样存在），与本轮修改无关

### 约束遵守

- v1 的 `results/pass2.sarif`（0 条）已备份至 `backup_v1/`；其余被修改文件原始版本同在 `backup_v1/`
- 本轮增补受操作员提供的修复提交参照（23a37e7/PR #1987）驱动，属 post-triage remediation 性质，
  已在 labels.json metadata notes 中如实记录
