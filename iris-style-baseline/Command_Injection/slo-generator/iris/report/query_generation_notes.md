# Query Generation Notes — Augur Phase 2 Step 4–5（Pass 2 / CWE-78，slo-generator）

- Run: `slo-generator-iris-pass2-cwe78-20261016`；标签来源：`iris/labels/labels.json`（Pass 2，CWE-78，模型 glm-5.3，人工审核门见 `iris/labels/phase1_review.md`）
- 工具链：CodeQL CLI 2.25.1（E:\codeql），codeql/python-all 7.1.1（本地 pack 缓存），qlpack `iris/slo-generator-cwe78`（`iris/qlpack.yml`，依赖 `codeql/python-all: "*"`）
- 生成文件：`libraries/MySources.qll`、`libraries/MySinks.qll`、`libraries/MySanitizers.qll`、`libraries/MySummaries.qll`、`queries/Pass2_CommandInjection.ql`、`diagnostics/DispatchChainDiagnostics.ql`（附加诊断查询）
- 编译验证（仅编译，未执行分析，符合"仅生成文件"约束）：`codeql query compile` 对 `queries/Pass2_CommandInjection.ql` 与 `diagnostics/DispatchChainDiagnostics.ql` 均 **Done [1/1]**，无 ERROR、无未使用变量告警
- 库导入语法：主查询通过 `import libraries.MySources`（等点号语法）导入，调用 `MySources::isSource`、`MySinks::isSink`、`MySanitizers::isBarrier`、`MySummaries::isAdditionalTaintStep`，四者签名均为 `(DataFlow::Node, string passKey)`（isAdditionalTaintStep 为 `(DataFlow::Node, DataFlow::Node, string)`），与库内定义逐一匹配

---

## 1. 建模原则（与其他项目实验保持一致）

1. **标签驱动、逐条锚定**：每个 source/sink 标签渲染为一条独立的谓词分支；分支注释携带标签 ID、classification 与置信度。分支同时锚定标签核验过的源码位置（相对路径 + 1-based 起始行，与提取 CSV 一致，数据库创建 sha 50ce1bf）与标签 signature 中的结构形状（callable / receiver / flow_kind / arg_index）。
2. **文件锚定方式**：`Location.getFile().getRelativePath() = "<relpath>"`（相对 DB sourceLocationPrefix），并以绝对路径等值判断兜底（`getAbsolutePath() = "C:/…/slo-generator_vuln/" + relpath`）。不用 `matches()` 通配——QL 要求 matches 模式为全绑定表达式。相对路径可区分 `backends/cloud_monitoring.py` 与 `exporters/cloud_monitoring.py` 等同名文件。
3. **API 匹配方式**：库调用（json/yaml/base64/importlib）按 AST 形状匹配（`Call.getFunc()` 为 `Attribute` 且模块名为直接 import 的 Name）。Step 1 检测已确认目标中**不存在这些模块的别名导入**，故 AST 匹配与 API graph 解析等价，且规避了 `CallNode`/`Call` 的类型互通问题。框架对象（`request`）本就无法静态解析，与提取阶段的 `matchKind=ast` 一致。
4. **pass key 分发**：四个库谓词均以 `passKey = "command_injection"`（WORKFLOW 规范化 pass key）作为唯一启用分支；其他 pass 返回空，供将来多 pass 复用同一库文件。
5. **内部包装器参数 ≠ Source**：`load_config`/`parse_config`/`compute`/`export`/`do_migrate`/`import_cls`/`import_dynamic`/`run_backend` 等内部函数参数一律不进入 `MySources`；它们之间的传播由原生数据流（直接调用可解析）与 `MySummaries` 的锚定胶水边承担。内部参数→危险调用的局部传播验证单独放在 `diagnostics/DispatchChainDiagnostics.ql`（`@kind problem`、severity warning、消息中显式标注 DIAGNOSTIC ONLY），**不计入正式漏洞结果**。
6. **无证据不传播**：`MySanitizers::isBarrier` 返回 `none()`（Pass 2 无 sanitizer 标签）；`MySummaries` 仅在 CodeQL 无法解析的动态分发点建边，全部锚定到核验过的调用点/参数定义，不存在无条件污点传播。
7. **shell 命令串 vs 参数列表分别建模**：本目标**不存在任何**进程/shell 执行调用点（全树 grep `subprocess|os.system|popen|execv*|spawn*|pexpect|shell=True|shlex` 为零命中），因此"命令字符串构造"与"参数列表"两类危险参数形态在本项目中均无实例；CWE-78 语义下的危险参数按标签映射为"名字解析/分发调用的参数"（见 §3）。
8. **结果分级**：所有 sink 标签均为 `candidate`；查询 `@precision low`，结果消息明确写"CWE-78 candidate"，供 Step 6 过滤与人工分诊，不预设漏洞成立。

## 2. MySources — 27 条 source 标签的谓词映射

| 标签 | 分类/置信度 | 源码依据（文件:行 + 代码） | 渲染分支 | Node 形态 |
| --- | --- | --- | --- | --- |
| S136 | tp 0.90 | api/main.py:41 `def run_compute(request):`（Functions Framework 入口，GOOGLE_FUNCTION_TARGET 选定） | entryParamSource | `parameterNode(f.getArg(0))`，param 名 request |
| S145 | tp 0.85 | api/main.py:80 `def run_export(request):` | entryParamSource | 同上 |
| S023 | candidate 0.60 | cli.py:77 `def compute(slo_config, ...)`（click --slo-config，操作员边界） | entryParamSource | param 0 |
| S024 | candidate 0.60 | cli.py:77 `def compute(slo_config, config, ...)`（--config） | entryParamSource | param 1 |
| S038 | candidate 0.50 | cli.py:133 `def api(ctx, config, ...)`（--config，envvar CONFIG_PATH，写往 cli.py:137 env） | entryParamSource | param 1 |
| S040 | candidate 0.50 | cli.py:133 `def api(..., target)`（--target → ctx.invoke(_cli, target=...)，框架在 api/main.py 模块内解析目标函数） | entryParamSource | param 3 |
| S159 | candidate 0.65 | migrator.py:48 `version`（--version 无 allowlist，拼入 f"slo_config_{curver}to{version}" → migrator.py:139 getattr 名） | entryParamSource | param 4 |
| S139 | tp 0.85 | api/main.py:59 `base64.b64decode(request.data)`（CloudEvent 载荷解码） | decodeSource | `exprNode(Call)`（返回值污点） |
| S148 | tp 0.80 | api/main.py:94 `base64.b64decode(request.data)` | decodeSource | 同上 |
| S147 | candidate 0.60 | api/main.py:94 `yaml.safe_load(...)`（请求派生字节解码；safe loader 只消除对象反序列化，字符串值仍传播） | decodeSource | 同上 |
| S217 | candidate 0.60 | utils.py:145 `yaml.safe_load(content)`（本地配置解码） | decodeSource | 同上 |
| S012 | unknown 0.45 | exporters/bigquery.py:166 `json.loads(...)`（BigQuery API 响应） | decodeSource | 同上 |
| S078 | unknown 0.45 | backends/cloud_service_monitoring.py:683 `json.loads(...)` | decodeSource | 同上 |
| S125 | unknown 0.45 | backends/dynatrace.py:339 `json.loads(res)` | decodeSource | 同上 |
| S193 | unknown 0.45 | backends/prometheus.py:151 `json.loads(...)` | decodeSource | 同上 |
| S137 | tp 0.90 | api/main.py:54 `request.get_data().decode('utf-8')`（原始请求体→SLO 配置串） | requestObjectSource | `exprNode(Call)`，attr=get_data、obj=Name request |
| S146 | tp 0.85 | api/main.py:92 `request.get_json()` | requestObjectSource | 同上，attr=get_json |
| S162 | candidate 0.55 | migrator.py:117 `source_path.open().read()`（迁移输入文件；apiVersion 派生 curver 进入 getattr 名） | fileReadSource | `exprNode(Call)`，attr=read |
| S164 | candidate 0.50 | migrator.py:118 `yaml.util.load_yaml_guess_indent(slo_config_str)` | fileReadSource | attr=load_yaml_guess_indent |
| S216 | candidate 0.55 | utils.py:142 `config.read()`（本地配置文件内容） | fileReadSource | attr=read、obj=Name config |
| S224 | candidate 0.55 | utils.py:450 `blob.download_as_string()`（GCS 取回配置） | fileReadSource | attr=download_as_string |
| S130 | candidate 0.50 | api/main.py:33 `os.environ['CONFIG_PATH']`（部署/操作员边界，选全局配置文件） | envSource | `exprNode(Subscript)` |
| S132 | candidate 0.50 | api/main.py:34 `os.environ.get('EXPORTERS_PATH', None)` | envSource | `exprNode(Call)`，os.environ.get |
| S204/S207/S213 | candidate 0.50 | utils.py:45/63/103 `ctx=os.environ`（${VAR} 替换上下文默认值，env 值经 utils.py:132 内插进配置内容） | envSource（三分支合一，`line in [45,63,103]`） | `exprNode(Attribute os.environ)` |
| S214 | candidate 0.50 | utils.py:132 `full_value.replace(f'${{{var}}}', ctx[var])` | envSource | `exprNode(Subscript ctx[...])` |

可控性判断：**tp（6 条）= 远程请求方可控**（Functions Framework 请求体/解码）；**candidate（17 条）= 操作员/部署域**（CLI 参数、环境变量、本地文件、GCS、经认证的远端配置）；**unknown（4 条）= 远端服务响应**（json.loads，无到达名字解析边界的已观察路径，低置信召回项，保留进模型并在审核文档中列示）。

## 3. MySinks — 12 条 sink 标签的谓词映射与参数索引

零 OS 命令执行点 ⇒ CWE-78 语义下的"危险参数"映射为名字解析/分发边界。dispatch_invocation 类标签（flow_kind=unknown，标签位置即调用点本身）建模为"锚定调用点的任一实参表达式"——污点相关事件是被名字选出的可调用对象接收到污点数据；getattr/import 类标签按 arg_index 精确到参数位。

| 标签 | 置信度 | 源码依据 | 建模（参数索引） | 可控性判断 |
| --- | --- | --- | --- | --- |
| K033 | 0.70 | report.py:204 `method = getattr(instance, method)`；method 名来自 report.py:193 `config['spec']['method']`（**无 allowlist**，API 模式下请求可控），216 行调用 | getattrNameSink，**arg 1**（名字实参） | 请求方选择已加载 backend 实例的既有方法 |
| K041 | 0.60 | utils.py:337 `getattr(importlib.import_module(package), name)` | getattrNameSink，**arg 1** | name 来自配置派生类名 |
| K042 | 0.65 | utils.py:337 `importlib.import_module(package)`；package 由 import_cls（utils.py:313-322）构造，含 `.` 的插件名**原样导入** | dynamicImportSink，**arg 0**（模块路径） | 配置派生；默认流程经 get_backend/get_exporters 成员校验约束（操作员信任边界），插件路径无 allowlist |
| K020 | 0.50 | migrator.py:78 `getattr(sys.modules[__name__], f"ebp_v1to{version}")`，79 行调用 | getattrNameSink，**arg 1** | 名字 = 固定 'v1' + CLI --version（本地操作员） |
| K023 | 0.50 | migrator.py:87 同构（exporters_v1to{version}），89 行调用 | getattrNameSink，**arg 1** | 同上 |
| K026 | 0.55 | migrator.py:139 `getattr(..., f"slo_config_{curver}to{version}")`，141 行调用；curver = 文件内容 apiVersion 派生（migrator.py:531） | getattrNameSink，**arg 1** | 名字含文件内容分量 + CLI 分量 |
| K034 | 0.65 | report.py:216 `data = method(self.timestamp, self.window, config)` | dispatchInvocationSink，**任一实参**（实际污点载体是 arg 2 `config`） | 请求派生 SLO 配置进入被分发方法 |
| K032 | 0.60 | report.py:203 `instance = cls(client=client, **backend_cfg)` | dispatchInvocationSink，任一实参（含 keyword 与 `**` 解包） | backend 配置进入被解析类构造 |
| K014 | 0.60 | compute.py:119 `response = instance().export(data, **config)`（callee 为 Call 的属性，提取阶段记录的未覆盖形态） | dispatchInvocationSink，任一实参 | 请求派生报告数据 + exporter 配置 |
| K022 | 0.50 | migrator.py:79 `ebp_func(ebp_paths, ...)` | dispatchInvocationSink，任一实参 | CLI 路径参数 |
| K025 | 0.50 | migrator.py:89 `exporters_func(exporters_paths, ...)` | dispatchInvocationSink，任一实参 | 同上 |
| K028 | 0.55 | migrator.py:141 `slo_func(slo_config, ...)` | dispatchInvocationSink，任一实参 | 迁移输入文件解析结果（S164 可达） |

`anArgument` 取 `getAnArg()` ∪ `getANamedArg().(Keyword).getValue()` ∪ `getANamedArg().(DictUnpacking).getValue()`，覆盖位置实参、关键字实参与 `**` 解包实参。

## 4. MySanitizers — 零条及依据

`isBarrier(node, passKey) { none() }`，按 WORKFLOW 5.2.3 保留必空的 barrier 钩子。依据（见 phase1_review.md §2.6）：
- 全库无 shlex/转义助手，且无 shell 命令构造可净化；
- `yaml.safe_load` 净化的是 YAML 对象反序列化（CWE-502/Pass 6），字符串值仍传播，非 CWE-78 barrier；
- **刻意不**将 `utils.get_backend`（utils.py:246-248 `sys.exit`）与 `utils.get_exporters`（utils.py:220-223 skip）的成员校验建成 barrier：它们约束的是"选择"，被选出/派生的值上的污点恰是本 pass 要上送分诊的对象，建成 barrier 会压制 K033/K042 路径；
- `click.Choice`（cli.py:127）、`strptime` 固定格式（api/main.py:58）、report 数值校验：作用于无分发路径的输入，与 CWE-78 无关。

## 5. MySummaries — 传播边建模证据

`isAdditionalTaintStep(from, to, passKey)` 经查询配置的 `isAdditionalFlowStep` 接入 `TaintTracking::Global`（本版库中 ConfigSig 的唯一自定义步进钩子；经查 codeql/dataflow 2.1.6 与 python-all 7.1.1 源码，此版本不存在 `isAdditionalTaintStep` 配置签名，故按 Augur 模板形态接线）。四族边：

| 边族 | 标签依据 | from → to | 为什么需要（原生不可解析） |
| --- | --- | --- | --- |
| backendDispatchStep | S057, S063, S096, S099, S104, S108, S116, S120, S128, S186, S190（11 条 %Backend `slo_config` 参数，arg_index 3 含 self） | report.py:216 调用 arg 2（`config`）→ 各锚定 backend 方法的 `slo_config` 参数 | callee 是 getattr 选出的方法（report.py:204/216），过程间分析不可见 |
| exporterDispatchStep | S001, S007, S101, S195（4 条 `export` data 参数，arg_index 1） | compute.py:119 调用 arg 0（`data`）→ 各锚定 `export` 方法 data 参数 | callee 是 import_dynamic 返回类的实例属性方法（compute.py:112-119） |
| metricDispatchStep | S006, S060, S100, S112, S113, S194（6 条 `export_metric` data 参数，arg_index 1） | exporters/base.py:109 调用 arg 0（`metric`）→ 各锚定 `export_metric` data 参数 | `self.export_metric` 经抽象基类分发到子类实现，类型不可静态解析 |
| reSubStep | K035, K036, K037, K038, K039, K040（名字解析链 summary） | utils.py 四处 `re.sub(p, r, s)`（:320 import_cls 文件名派生、:362 capitalize、:374 snake_to_caml、:386 caml_to_snake）的 **arg 2 → 调用结果** | 默认污点步覆盖字符串方法（split/join/replace…）但**不**覆盖 `re` 模块调用；无此边则请求→派生类名→import_module 链在 re.sub 处断开（已核对 TaintTrackingPrivate.qll 的 stringManipulation 覆盖清单） |

**未显式建边的 summary 标签（67 条中的其余 46 条）及理由**：内部直调（S028-S031, S054, S080, S082-S085, S142-S144, S150-S151, S153-S154, S205, S208-S212 及 K001/K013/K019/K031/K035-K037/K040 的包装函数本体，其中 K035-K040 同时作为 reSubStep 的标签依据）由原生过程间数据流覆盖；dict 成员读取（S079, S084, S152, S198, S200, S201, S218-S221）与 f-string 构造（K021, K024, K027, K038, K039）由默认污点步覆盖（已核对 pack 源码：`subscriptStep`＝下标读取、`containerStep`＝`dict.get`/`<tainted>.get(...)`、`stringManipulation`＝字符串方法、f-string 步在 TaintTrackingPrivate.qll:157）；K010（enum 成员 getattr，结果不被调用）与 K015（DynatraceClient.request，HTTP 面）按标签 unknown/fp 评级**不建模**，仅文档记录。

## 6. 正式查询结构

`queries/Pass2_CommandInjection.ql`：`@kind path-problem`、`@problem.severity error`、`@id py/augur/slo-generator/pass2-command-injection`、`@precision low`、`@tags security` + `external/cwe/cwe-078`；`module Pass2Config implements DataFlow::ConfigSig` 四谓词分别委托四个库（pass key "command_injection"），`module Pass2Flow = TaintTracking::Global<Pass2Config>` + `import Pass2Flow::PathGraph` + `flowPath(source, sink)`，select 形如 `select sink.getNode(), source, sink, "..."`（与 Augur taint_query.ql.tmpl 渲染一致）。语言导入块为 `import python` + `semmle.python.dataflow.new.DataFlow/TaintTracking`（模板 Python 形态）。

`diagnostics/DispatchChainDiagnostics.ql`（附加）：`@kind problem`、`@problem.severity warning`、`@id py/augur/slo-generator/diagnostics/dispatch-chain-local`；isSource 为内部包装器参数（import_dynamic 的 package/name、import_cls 的 cls_name、run_backend 的 config/backend、get_backend_cls/get_exporter_cls 首参），isSink 复用 `MySinks::isSink`，`DispatchDiagnosticsFlow::flow` 验证内部参数→分发 sink 的传播；消息显式声明"DIAGNOSTIC ONLY (not an official finding)"，不进入正式结果。

## 7. 未覆盖的 API、动态调用与已知局限

1. **外部依赖不在库内**：functions_framework、flask（仅 `jsonify` 导入）、prometheus_http_client、googleapiclient、google.cloud.storage/pubsub/bigquery、requests 等为外部依赖，数据库不含其源码；只建模了项目侧调用点。Functions Framework 的目标函数分发（GOOGLE_FUNCTION_TARGET）本身在框架内部完成，只能以 `run_compute`/`run_export` 参数（S136/S145）近似入口。
2. **`request` 对象不可解析**：flask.Request/cloudevent.CloudEvent 按提取阶段同样以 AST 形状匹配（attr 名 + receiver 名 request）；`request["time"]/["id"]` 等字段按标签 fp 不建模。
3. **run_export 的信任边界**：S152——请求只控制 exporter **名字**，class 字符串来自受信全局配置（utils.py:220-223 成员校验），未按直接注入建模；分诊时应注意该路径的告警属低危形态。
4. **导入链的约束**：backend/exporter class 名经 `capitalize/snake_to_caml` 派生自受 allowlist 约束的配置 key（utils.py:246-252）；reSubStep 使该链可被查询观察到，但**不**表示绕过 allowlist——分诊时结合 K042 rationale 判断。
5. **dynatrace.py:296 `getattr(self.client, method)`**：库内调用点全部传字面量 `'get'`（dynatrace.py:144/168），标签为 fp，未建为 sink；若上游配置未来可控，需重新标注。
6. **`instance()` 属性调用形态**（compute.py:119）在提取阶段的 dispatch_invocation 家族未覆盖，此处按 K014 标签以行锚 + callee attr 名（export）建模，与标签语义一致。
7. **`os.environ[...] = value` 赋值目标**（cli.py:137-139、prometheus.py:38/40）在提取中被误匹配为读，标签 fp；sink 侧 K007-K009/K029-K030 亦为 fp，未建模（env 写非命令边界）。
8. **json.loads 四条 unknown 源**：含入模型以保守召回；若 Step 5 结果噪声偏高，可在 Step 6 过滤时按 classification=unknown 降权。
9. **samples/custom 插件样例**（S096/S099/S100/S101）与 MySummaries 边族包含之，体现文档化插件扩展点形状；其函数体无 sink，不会产生正式告警。
10. **`__init__.py`、常量模块、setup.py**：无标签候选（fp/none），未建模。
11. **行锚定的快照依赖**：所有行号锚定与 50ce1bf 数据库快照一致；源码变更后需重跑 Phase 1 提取与标注再重生成。
12. **未执行**：按指令未运行任何 `database analyze`/`query run`，Step 5 的执行与 Step 6 过滤待后续指令。

## 8. 约束遵守

- 未读取漏洞真值、修复提交或外部安全公告；所有依据来自 Phase 1 标签、提取 CSV 与源码树本身（及 CodeQL pack 的公开库源码，用于核对默认污点步语义）。
- 未修改源码、数据库、Phase 1 标签与提取产物；仅新增 `iris/libraries/*.qll`、`iris/queries/Pass2_CommandInjection.ql`、`iris/diagnostics/DispatchChainDiagnostics.ql`、本说明文件。
- 编译验证仅调用 `codeql query compile`（无数据库、无结果产出），不构成正式分析。

---

## 9. v2 Post-triage Remediation（2026-10-16，本轮追加）

独立 LLM 路径复核（`report/llm_triage.json`）确认 Pass 2 的 CWE-78 sink 模型与项目真实代码执行边界零重叠后，经操作员授权执行最小增补并重跑：

### 9.1 修改内容（ originals 保存在 `iris/backup_v1/`）

1. `labels/labels.json`：新增 4 条标签
   - `S226`（source, candidate 0.55）：migrator.py:228 `open(exp_path)` — exporters 迁移文件内容
   - `S227`（source, candidate 0.55）：migrator.py:263 `open(ebp_path)` — error budget policy 迁移文件内容
   - `K043`（sink, **tp 0.85**）：migrator.py:229 `yaml.load(conf, Loader=yaml.Loader)` 流实参（exporters_v1tov2）
   - `K044`（sink, **tp 0.85**）：migrator.py:264 同构（ebp_v1tov2）
   - metadata.notes 追加 v2 remediation 说明
2. `libraries/MySources.qll`：`fileReadSource` 增加两个 `open()` 分支（S226/S227，行锚定 + AST 形状 `Call.getFunc().(Name).getId() = "open"`）
3. `libraries/MySinks.qll`：新增 `unsafeYamlLoadSink` 谓词（K043/K044）：callee 为 `Attribute(load)` 且 `fn.getObject().(Name).getId() = "yaml"`（同时覆盖 PyYAML `import yaml` 与 ruamel `from ruamel import yaml`，本项目为后者）、keyword `Loader` 的值为 `Attribute`（name ∈ Loader/UnsafeLoader/FullLoader）、sink 节点为 `c.getArg(0)`；接入 `isSink` 的 `command_injection` 分支
4. `queries/Pass2_CommandInjection.ql`：仅更新 `@description`（追加 v2 sink 语义说明）；查询逻辑零改动（委托库谓词）

无需 sanitizer / 自定义 taint step：`with open(p) as conf: yaml.load(conf, ...)` 的传播由 CodeQL 原生局部数据流完成。

### 9.2 重跑命令与结果

```
codeql query compile queries/Pass2_CommandInjection.ql --search-path=<python-all>,<threat-models>   # Done [1/1]
codeql database analyze <slo-generator-db> queries/Pass2_CommandInjection.ql \
  --format=sarifv2.1.0 --output=results_v2/pass2.sarif --search-path=<python-all>,<threat-models> --rerun
python iris_tools/augur-0.3.0/scripts/filter_and_report.py \
  --input-dir results_v2 --labels labels/labels.json --output report/iris_report_v2.md
```

（注意：`database analyze` 需加 `--rerun`，否则命中 DB 结果缓存返回旧 10 条结果。）

- `results_v2/pass2.sarif`：**12 条结果** = 原 10 条 + migrator.py:229 + migrator.py:264
- 新告警污点路径（各 3 步）：`migrator.py:228 open() → conf → 229 yaml.load(...)`；`migrator.py:263 open() → conf → 264 yaml.load(...)`
- **命中行 229/264 与修复提交 36318be 改动的两行完全重合（位置重叠 100%），真实漏洞命中（recall 1/1）**
- `report/iris_report_v2.md`：Label Summary 29 sources / 14 sinks；新告警被 filter_and_report 的 migration file 路径启发式归入 Likely FP（该启发式先于内容模式执行）——已在报告中附 Analyst Addendum 说明并为共享工具提出改进建议（unsafe-loader 反序列化 TP 模式应先于路径启发式）；共享脚本本轮未修改
- 验证过程产物：`hitcheck/`（独立最小查询先行验证 2 命中 0 误报）

### 9.3 约束遵守

- 原 `results/pass2.sarif`、`iris_report.md` 未改动；被修改文件的原始版本全部备份于 `iris/backup_v1/`
- 本轮增补受操作员提供的修复提交参照（36318be/PR #173）驱动，属 post-triage remediation 性质，已在 labels.json metadata notes 中如实记录
