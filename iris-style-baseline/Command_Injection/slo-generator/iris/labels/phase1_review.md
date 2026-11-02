# Phase 1 Step 3 人工审核文档 — Pass 2 / CWE-78 命令注入（slo-generator）

- Run: `slo-generator-iris-pass2-cwe78-20261016`
- 生成时间: 2026-10-16T04:23:30+00:00（与 labels.json `metadata.generated_at` 一致）
- 实际使用的 LLM 模型: **glm-5.3**（Claude Code CLI agent 驱动，单次确定性标注，无 re-ask）
- 批次数: **10**（b01–b07 为 source 候选按模块分组，b08–b10 为 sink 候选分组）
- 处理候选总数: **267**（sources.csv 225 行 + sinks.csv 42 行，全部逐行处理，无一丢弃）
- 输入: `iris/extraction/sources.csv`、`iris/extraction/sinks.csv`、`iris/exploration/detection.json`
- 依据: Augur `WORKFLOW.md`、`references/python.md`、`references/patterns.md`、`assets/labels_schema.json`，以及 `slo-generator_vuln` 源码逐文件核对

---

## 1. 标签统计（按 role / classification）

| role | 数量 | | classification | 数量 |
| --- | --- | --- | --- | --- |
| source | 27 | | tp | 6 |
| sink | 12 | | fp | 161 |
| sanitizer | 0 | | candidate | 90 |
| summary | 67 | | unknown | 10 |
| none | 161 | | | |

置信度分布: ≥0.75: 83 条；0.65–0.74: 29 条；0.55–0.64: 112 条；0.45–0.54: 42 条；<0.45: 1 条。
明细见 `label_stats.md`。`labels.json` 已通过 `assets/labels_schema.json`（Draft 2020-12 + `contains` 约束）的机器校验。

**Schema 合规说明**: `labels_schema.json` 的 `passes` 数组带有 `contains(pass_id == 1)` 硬约束，因此 labels.json 中包含一个 `pass_id=1`（Path Traversal）的**空占位块**（`entries: []`）。本次运行范围仅限 Pass 2（CWE-78），未对 Pass 1 做任何标注；该占位块仅为满足 schema，已在 `metadata.notes` 中记录。Pass 2 的 `cwes` 按照检测阶段（detection.json）收窄后的范围记为 `["078"]`（Augur 全集 077/078/088 中的命令注入主类）。

## 2. 核心语义结论（针对六项审查要求）

1. **是否存在 OS 命令执行**: **不存在**。对整个源码树（slo_generator/、samples/、setup.py）grep `subprocess|os.system|os.popen|Popen|check_output|check_call|execv*|spawn*|pexpect|shell=True|shlex` 为零命中（唯二字面命中是 docstring 中 "empty." 匹配 `pty\.` 的假阳性）。因此**没有任何已确认的 CWE-78 sink**；12 条 `sink` 标签全部为 `candidate`（非 `tp`），指向本代码库中最接近 CWE-78/88 形态的边界——**配置驱动的名字解析与动态分发链**（`importlib.import_module` + `getattr` + 分发调用）。不存在 shell=True、字符串命令拼接或参数列表构造，因此 python.md 中的命令参数列表/引用转义类判定均不适用。

2. **外部输入是否影响"可执行内容"**：存在三条真实输入→分发链，均已标注并区分信任边界：
   - **最强链（API 模式，远程攻击者面）**: `run_compute(request)`（api/main.py:41, tp 0.9）→ `request.get_data()`/`b64decode(request.data)`（tp）→ `load_config(data)` → `compute()` → `config['spec']['method']`（report.py:193, summary 0.7，**无 allowlist**）→ `getattr(instance, method)`（report.py:204, sink K033, conf 0.7）→ `method(timestamp, window, config)`（report.py:216, sink K034）。请求方可选择已加载 backend 实例上的任意既有方法（无法注入新代码），属受限的参数注入形态。
   - **导入链（operator 信任边界，非请求直控）**: `spec['backend']`/`spec['exporters']`（请求控制的名字）必须通过 `config['backends']`/`config['exporters']`（受信配置文件）的**成员校验**（utils.py:246-248 `sys.exit`、utils.py:220-223 skip），随后 class 字符串由受信 key 派生（`capitalize(snake_to_caml(key.split('/')[0]))`），再经 `import_cls`（含 `.` 的名字**原样导入**为插件路径，无 allowlist）到达 `importlib.import_module`（utils.py:337, sink K042, conf 0.65）。即：**默认流程中请求攻击者无法直接注入任意模块路径**；风险面在于受信配置本身含 `.` 插件名时被原样导入、以及 `sys.path.append(os.getcwd())`（cli.py:32）扩大了模块搜索范围。
   - **迁移器链（本地 CLI operator 面）**: `--version`（CLI 字符串，无 allowlist）与输入文件内容派生的 `curver`（`detect_config_version` 取 `apiVersion.split('/')[-1]`）拼入 `f"slo_config_{curver}to{version}"` → `getattr(sys.modules[__name__], ...)` → 调用（migrator.py:78/87/139 + 79/89/141，sink K020–K028，conf 0.50–0.55）。选择范围限定于 migrator 模块既有函数（否则 AttributeError）。
   - 另: `run_export` 路径中请求仅控制 exporter **名字**，class 字符串来自受信全局配置（见 S152 rationale）——清晰的信任边界，故未按直接注入处理。

3. **subprocess/os 调用参数的 shell=True / 字符串构造 / 参数列表 / 固定常量情形**: 全库无 subprocess/os 执行调用点，该判定维度在本快照中为空集（已核实）。`dynatrace.py:296 getattr(self.client, method)` 的 `method` 在库内所有调用点均为字面量 `'get'`（dynatrace.py:144/168），故标为 `none/fp`；`exporters/base.py:82/83/139` 与 `cloud_monitoring.py:254/256`（enum 成员选取，结果不 invocable）同理标 `none/fp`。

4. **内部函数的角色判定**: 内部传递/包装函数（`load_config`、`parse_config`、`compute`、`export`、`do_migrate`、`run_backend`、`import_cls`/`import_dynamic`、`get_backend_cls`/`get_exporter_cls`、`DynatraceClient.request`）一律标 **summary**（供 MySummaries.qll 生成框架胶水层的传播边），不冒充 source/sink；后端/导出器插件接口的 `slo_config`/`data` 参数标 summary（请求派生数据进入被动态分发的方法体），`timestamp`/`window` 等数值参数标 none/fp。`%Exporter.export/export_metric` 与 `%Backend.query_sli/good_bad_ratio` 均为被分发调用的插件接口，非入口边界。

5. **配置文件固定命令与攻击者输入的信任边界**: 存在且已逐条记录——受信全局配置（CONFIG_PATH/EXPORTERS_PATH 指向的文件、GCS blob）提供 class 名；请求仅提供选择名并受成员校验约束；`${VAR}` 环境变量替换（utils.py:132）把 operator 级环境值内插进配置内容（S204/S207/S213/S214, source candidate 0.5）。`yaml.safe_load`（utils.py:145, api/main.py:94）消除 YAML 对象反序列化风险（CWE-502 面），但对字符串值传播到名字分发**不构成净化**，故未标为 sanitizer；迁移器中 `yaml.load(Loader=yaml.Loader)`（migrator.py:229/264）属不安全 Loader，但那是 Pass 6 范围且无到达命令边界的路径，本 Pass 标 none/fp。

6. **是否存在阻断危险字符/非法参数的检查**: **无 CWE-78 语义上的 sanitizer**（无 shlex/转义助手，也没有需要净化的命令构造）。已审查的约束性检查及其局限：`utils.get_backend/get_exporters` 成员校验（限定选择范围，不校验派生 class 字符串的语法）；`click.Choice(['http','cloudevent'])`（S039，限定 signature_type 为二值）；`datetime.strptime` 固定格式（S138，时间字段严格解析为数值）；`report._validate` 数值类型校验（仅作用于后端返回值）。**sanitizer 计数为 0 是有依据的结论**，Phase 2 的 `MySanitizers.qll` 将按 WORKFLOW 要求以 `none()` 空实现保留。

## 3. 高风险 sink 清单（全部为 candidate，未确认漏洞）

| ID | 位置 | API | conf | 说明 |
| --- | --- | --- | --- | --- |
| K033 | report.py:204 | `getattr(instance, method)` arg 1 | 0.70 | 请求控制的 method 名（无 allowlist）→ 分发调用，最强请求→分发边 |
| K042 | utils.py:337 | `importlib.import_module(package)` arg 0 | 0.65 | 配置派生模块路径导入（插件名原样导入）；受 allowlist 间接约束 |
| K034 | report.py:216 | `method(timestamp, window, config)` | 0.65 | 名字选中方法的实际调用点 |
| K014 | compute.py:119 | `instance().export(data, **config)` | 0.60 | 配置解析出的 exporter 类实例化并调用 |
| K032 | report.py:203 | `cls(client=client, **backend_cfg)` | 0.60 | 配置解析出的 backend 类实例化 |
| K041 | utils.py:337 | `getattr(import_module(...), name)` arg 1 | 0.60 | 导入模块上的成员名选取 |
| K026 | migrator.py:139 | `getattr(sys.modules[__name__], f"slo_config_{curver}to{version}")` | 0.55 | 名字含文件内容派生分量（apiVersion）|
| K028 | migrator.py:141 | `slo_func(...)` | 0.55 | 上行的调用点 |
| K020/K023 | migrator.py:78/87 | getattr（固定 'v1' + CLI --version）| 0.50 | 本地 operator 输入 |
| K022/K025 | migrator.py:79/89 | ebp_func/exporters_func 调用 | 0.50 | 同上 |

## 4. 广义 source 清单（27 条）

- **tp（6，API 远程边界）**: S136 `run_compute(request)` 0.9；S137 `request.get_data()` 0.9；S139 `b64decode(request.data)` 0.85；S145 `run_export(request)` 0.85；S146 `request.get_json()` 0.85；S148 `b64decode(request.data)` 0.8。
- **candidate（CLI/env/文件/GCS 边界，operator 信任域）**: S023/S024（CLI --slo-config/--config 0.6）、S038/S040（CLI api --config/--target 0.5）、S130/S132（CONFIG_PATH/EXPORTERS_PATH 环境读取 0.5）、S147（safe_load 请求派生解码 0.6）、S159（migrator --version 0.65）、S162/S164（迁移输入文件内容/解码 0.55/0.5）、S216/S217（本地配置文件 read/safe_load 0.55/0.6）、S224（GCS blob 下载 0.55）、S204/S207/S213/S214（os.environ 作为 ${VAR} 替换上下文 0.5）。
- **unknown（4，远端 API 响应 json.loads，低置信召回项）**: S012、S078、S125、S193（0.45）。

**刻意未标为 source 的外部输入**（避免过度泛化，rationale 均已记录）: `request["time"]`（strptime 严格格式化为数值）、`request["id"]`（仅进日志）、click 装饰器注册点、数值/布尔参数（timestamp/window/export/delete/quiet/verbose/signature_type）、各 backend 内部的 config 字段读取（仅进入监控 API 的 filter/查询对象）、`os.environ[...] = value` 赋值 LHS 的误匹配读、`json.loads` 以外的远程数据消费点。

## 5. sanitizer 清单

**空**（0 条）。依据见 §2 第 6 条。约束性检查的存在与局限已写入相关条目 rationale（S220/S221/K042/S152 等），供 Phase 2 决定是否在 `isBarrier` 之外另做人工评估。

## 6. 未决项 / 需人工复核（conf < 0.55，共 33 条）

- **unknown（10）**: K010（get_aggregation enum getattr 传播，0.40）、K015（DynatraceClient.request 包装，0.45）、S012/S078/S125/S193（远程响应 json.loads 召回项，0.45）、S096/S099/S100/S101（samples/custom 插件样例接口，0.45）。
- **candidate conf=0.50（23）**: 插件接口 summary 边（S006/S007/S057/S060/S063/S104/S108/S112/S113/S116/S120/S128/S186/S190/S194/S195）、CLI/env source（S038/S040/S130/S132/S204/S207/S213/S214）、S152/S153、S164、迁移器 sink 侧（K020–K025）。
- 人工复核建议聚焦三点：(a) 是否认可"config 名字派生 + 成员校验"对导入链的约束强度（K042）；(b) `spec['method']` 无校验分发（K033/K034）是否需要在 Phase 2 前补充 method allowlist 证据；(c) samples/custom 与远程 json.loads 召回项是否保留进 MySources。

## 7. 去重与排除记录（无候选被静默丢弃）

- 267 行 CSV 全部一一对应 labels.json 条目（S001–S225 / K001–K042）。
- 22 行标为同位置提取噪声（none/fp，理由中均指明主行或对应 sink 行）: 17 行为同一 file:line 的 base-expression 重复（os.environ 属性 vs 下标配对 ×13、request.data vs b64decode ×2、Path.open() vs .read() ×2）；5 行为把 `os.environ[...] = value` 赋值目标误匹配为读（S041/S043/S045/S180/S182，写侧已在 sinks.csv K007–K009/K029–K030 记录）。
- Step 2 既定排除（本次未重新处理）: tests/unit/**、纯日志输出点。

## 8. 约束遵守情况

- 未读取 PyVul 真值、漏洞修复提交或任何外部安全公告；标注仅基于源码树与加载的 Augur 参考文档。
- 未修改项目源码、CodeQL 数据库（slo-generator-db）及 extraction 阶段产物（sources.csv/sinks.csv/sinks.ql/sources.ql 等保持只读）。
- 本次仅写入 `iris/labels/` 下四个输出文件及工作区根目录的构建脚本 `build_labels_pass2.py`（在 iris 树外，便于复现与审计）。

## 9. 结论与状态

- **结论**: 本快照内 CWE-78（OS 命令注入）的攻击面为空——无任何进程/shell 执行 API。Pass 2 的有效输出是"配置驱动的名字解析/动态分发"这一参数注入形态边界的 source→summary→sink 标签集（27 source / 67 summary / 12 sink），全部以 candidate/unknown 级别保留，供 Phase 2 taint 查询验证是否存在从 API 请求到分发边界的真实数据流；**未断言任何已确认漏洞**。
- **状态**: Phase 1 Step 3 完成。按指令在此**停止**，不进入 Phase 2（Step 4 库生成、Step 5 taint 查询）。本文件即 WORKFLOW §4.5 人工审核门（advisory）的审核载荷，等待人工批准或修正意见。
