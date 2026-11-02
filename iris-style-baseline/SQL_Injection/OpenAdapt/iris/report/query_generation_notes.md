# Augur Phase 2 Step 4–5 — 污点模型与路径查询生成笔记（Pass 5 / CWE-89 SQL Injection）

## 0. 生成概览

| 项 | 值 |
| --- | --- |
| 项目 | openadapt（nicegui 1.2.16 native 桌面 UI + python-fire CLI + SQLAlchemy 1.4.43 + alembic 1.8.1） |
| 数据库 | `dataset/codeql_databases/sql_injection_dbs/OpenAdapt_vuln/OpenAdapt-db`（python，CLI 2.25.1，sha 0a0208e；本轮未执行任何 CodeQL 命令） |
| 标签来源 | `iris/labels/labels.json` pass 5（CWE-89），128 条唯一条目，人工审核通过 |
| pass key | `sql_injection`（四个 QLL 与主查询统一） |
| 生成文件 | `libraries/MySources.qll`、`MySinks.qll`、`MySanitizers.qll`、`MySummaries.qll`、`queries/Pass5_SQLInjection.ql`、本笔记 |
| 模板 | `augur-0.3.0/assets/taint_query.ql.tmpl`（QUERY_ID=`py/augur/openadapt/pass5-sql-injection`，CONFIG_NAME=`Pass5Config`，FLOW_MODULE=`Pass5Flow`，PRECISION=`high`，CWE_PRIMARY=89，EXTRA_TAGS=空——Pass 5 仅 CWE-089） |
| API 依据 | 全部 AST/dataflow API 已对照本地 pack 缓存 `codeql/python-all 7.1.2` 源码核验（见 §7） |

**关于 `labels/review_decision.json`**：Phase 1 Step 5 的人工审核以 `phase1_review.md`（advisory checkpoint 文档）形式记录，`review_decision.json` 未作为独立文件产生。本轮依据任务声明"人工审核通过"直接采用 labels.json 的当前内容，未对任何标签做修改（若后续需要调整标签，须回到第五步重审并记录不足）。

## 1. 标签 → QLL 谓词映射（全量对应关系）

QL 库按 WORKFLOW §5.1 以 pass key 分派（`predicate is*(DataFlow::Node, string passKey)`，本轮仅 `"sql_injection"` 分支非空）。全部谓词为纯 predicate（不定义 QL class，避免未绑定/无效类）；AST 匹配使用 `import python` 的类 + `DataFlow::Node.asExpr()` / `DataFlow::parameterNode()` 转换（API::Node 与 DataFlow::Node 未混用——本模型不使用 API graphs）。

### 1.1 MySources.qll（16 条 source 标签 → 6 个分支）

| 标签 ID | 源码位置 | 分支（private predicate） | 匹配方式 |
| --- | --- | --- | --- |
| pass5-src-028…-035（8 条：id/timestamp/monitor_width/monitor_height/double_click_interval_seconds/double_click_distance_pixels/platform/task_description） | openadapt/crud.py:142 | `recordingColumnAtCrud142` | `Attribute`：文件 basename=crud.py、行=142、对象名 `recording`、属性名 ∈ 8 列集合；`source.asExpr() = a` |
| pass5-src-065 | openadapt/record.py:508 | `recordTaskDescriptionParam` | `Parameter` `task_description`（position 0，`Function "record"` 的 `getArg(0)`）；`source = DataFlow::parameterNode(p)` |
| pass5-src-007 | openadapt/app/cards.py:44 | `uiInputWidgetCall` | `Call`：`ui.input(...)`（func=Attribute name `input`，object=Name `ui`）；`source.asExpr() = c`（调用返回值节点） |
| pass5-src-006 | openadapt/app/cards.py:21 | `localFilePickerCall`（与 -054 合并同分支） | `Call`：`LocalFilePicker(...)`（func=Name `LocalFilePicker`）；`source.asExpr() = c` |
| pass5-src-054 | openadapt/app/objects/local_file_picker.py:101 | 同上 | 同上（行 101 的 demo 调用） |
| pass5-src-053 | openadapt/app/objects/local_file_picker.py:87 | `pickerEventPayload` | `Subscript`：对象名 `msg`；`source.asExpr() = s` |
| pass5-src-097 | openadapt/app/util.py:21 | `importChannelArgument` | `Call` `open` 的 `getPositionalArg(0)`（`on_import` 中 `open(src,"wb")`） |
| pass5-src-098 | openadapt/app/util.py:22 | 同上 | `Call` `bz2.BZ2File` 的 arg 0（`BZ2File(selected_file,"rb")`：func=Attribute name `BZ2File`，object=Name `bz2`） |
| pass5-src-099 | openadapt/app/util.py:23 | 同上 | `Call` `copyfileobj` 的 arg 0（`copyfileobj(f2, f)`） |

**未建模的 101 条 source 候选（role=none）**：45 config、4 env、16 file（配置/静态资源/导出通道）、11 db_read（仅进参数化 ORM filter/展示）、11 cli（fire 注册/strategy/wormhole 等）、1 cli_spawn（Popen，Pass-2 形态）、13 internal_transfer（进绑定参数通道）——均按审核结论排除，未进入 MySources。

### 1.2 MySinks.qll（3 条 sink 标签 → 3 个分支）

| 标签 ID | 源码位置 | 分支 | 匹配方式 |
| --- | --- | --- | --- |
| pass5-sink-010 | openadapt/crud.py:180 | `rawSqlExecuteArgument0` | `Call`：`connection.execute(sql)`，func=Attribute name `execute`、object=Name `connection`；`sink.asExpr() = c.getPositionalArg(0)`（危险参数索引 0） |
| pass5-sink-005 | openadapt/crud.py:142 | `exportSqlFstringConstruction` | `Fstring`（crud.py:142 的 SQL 文本构造点）；`sink.asExpr() = f` |
| pass5-sink-006 | openadapt/crud.py:150 | `createDbSqlParameter` | `Parameter` `sql`（position 1，`Function "create_db"` 的 `getArg(1)`，即危险参数索引 1）；`sink = DataFlow::parameterNode(p)` |

**未建模的 6 条 sink 候选（role=none）**：crud.py:48 execute arg 0（Core 语句对象）、crud.py:48 `sa.insert` 构造、crud.py:30 `_insert` 包装器、crud.py:161/164/169 三个非 SQL f-string（文件名/备份路径/env 行）——已在 QLL 头注与 §4 说明。

### 1.3 MySanitizers.qll（1 条 sanitizer 标签 → 1 个分支）

| 标签 ID | 源码位置 | 分支 | 匹配方式 |
| --- | --- | --- | --- |
| pass5-sink-003 | openadapt/crud.py:48 | `coreInsertBoundValuesArgument` | `Call`：`db.execute(sa.insert(table), to_insert)`，func=Attribute name `execute`、object=Name `db`；`node.asExpr() = c.getPositionalArg(1)`（绑定值参数位，参数索引 1） |

### 1.4 MySummaries.qll（1 条 summary 标签 → none()）

| 标签 ID | 源码位置 | 处理 |
| --- | --- | --- |
| pass5-src-049 | openadapt/crud.py:209（`create_db(recording_id, sql)` 参数 1 交接） | **不建立额外污点边**（`none()`）。理由见 §5 |

## 2. SQL 执行 Sink 的实际 API、接收者、危险参数索引与执行证据

本项目仅有的两个 SQL 执行调用（openadapt/crud.py）：

| Sink | API（真实语义） | 接收者 | 危险参数 | 执行证据 |
| --- | --- | --- | --- | --- |
| crud.py:180 | `Connection.execute(sql)` —— SQLAlchemy 1.4 `Engine.begin()` 连接上的 execute，传入**纯字符串**时按 `text()` 语义作为字面 SQL 文本编译执行，无参数化 | `connection`（来自 `engine.begin()`，crud.py:179；engine 由 `sa.create_engine(config.DB_URL)` 于 :173 创建） | 参数索引 0（SQL 语句文本） | `with engine.begin() as connection: connection.execute(sql)`；`sql` 是 `create_db` 的参数 1，由 `export_recording`（crud.py:208-209）传入 `export_sql` 的返回值 |
| crud.py:48 | `Session.execute(stmt, values)` —— Core insert + 行值列表：值以绑定参数（executemany 语义）传递，**非** SQL 文本 | `db`（`Session()`，crud.py:23） | arg 0=Core 语句对象（安全）；arg 1=绑定值（sanitizer/barrier） | `result = db.execute(sa.insert(table), to_insert)`，语句由静态模型（openadapt/models.py）编译 |

接收者按名字匹配（`db`/`connection`）：sqlalchemy 库本身不在 CodeQL 数据库内，API graphs 无法解析到库模块（detection.json matchKind 语义已记录全部行为 `ast`），名称匹配 + 行号 + 文件限定在本项目中唯一。

**危险通道完整链**（供路径查询预期）：`recording.<col>`（source，crud.py:142 属性读）→ f-string 构造（sink #1，crud.py:142）→ `sql` 局部变量 → `export_sql` 返回 → 调用点返回值（crud.py:208）→ `create_db` 参数 1（sink #2）→ 使用点 `connection.execute` 参数 0（sink #3，crud.py:180）。

## 3. Source 的外部边界、可控范围与传播链

| Source 家族 | 外部边界 | 可控范围 | 传播链（源码证据） |
| --- | --- | --- | --- |
| `recording.<col>` @ crud.py:142（主 source） | DB 内容（二阶） | 全部 8 列；task_description/platform 为 tp（UI/CLI 文本直接入库），6 数值列为 candidate（正常为机器值，导入后任意） | task_description：cards.py:44 `ui.input` → cards.py:76 `Popen("python3 -m openadapt.record "+name)` → record.py:507 `record(task_description)` → record.py:457 入 recording_data → crud.py:110-115 `insert_recording`（参数化 ORM 写入）→ DB；platform：record.py:456 `sys.platform`（机器值）；导入通道见下行 |
| 导入通道（cards.py:21 / local_file_picker.py:87/101 / util.py:21-23） | nicegui 文件选择器 + bz2 解压整库替换 | 整个 openadapt.db 内容（含全部 recording 列） | local_file_picker.py:87 `msg["args"]["data"]["path"]` → cards.py:21 `LocalFilePicker` → cards.py:32 `f(selected_file.text, …)` → util.py:20-23 `on_import`：`open(src,"wb")` + `bz2.BZ2File(selected_file)` + `copyfileobj` 覆盖 openadapt.db |
| `record(task_description)` 参数 @ record.py:508 | fire CLI（pyproject console script `record`） | 任意文本 | record.py:518/520 → create_recording → 参数化 ORM insert → DB（**之后必须经 DB round-trip 才达 sink，见 §5**） |
| `ui.input` 调用 @ cards.py:44 | nicegui 唯一文本输入控件 | 任意文本（记录名） | 经 Popen 子进程边界进入 record CLI（Pass-2 形态的命令拼接，此处仅记录为 SQL 污点起点上下文） |

**不做的事**：未把 `cursor.execute`/`connection.execute` 所在包装函数（`_insert`、`create_db`）的任意形参当外部 Source——`_insert` 的 event_data 经绑定参数（安全）；`create_db` 的 `sql` 形参本身即 sink（标签 pass5-sink-006），而非 source。

## 4. SQL 动态构造、标识符/ORDER BY、参数绑定、ORM 与 sanitizer 证据

- **动态 SQL 构造**：全项目唯一动态 SQL 是 crud.py:142 的 f-string（8 个插值无转义，`'{recording.platform}'`、`'{recording.task_description}'` 仅字面单引号包裹 → 单引号即可逃逸值上下文）。config.py:61 的 `f"sqlite:///{DB_FPATH}"` 是连接 URL 不是 SQL。crud.py:161/164/169 的 f-string 是文件名/路径/env 行。
- **标识符/ORDER BY**：本项目不存在用户可控表名、列名或 ORDER BY 片段——表/列名全部来自静态 models.py（`sa.insert(table)` 的 table 为 ORM 类）；导出 SQL 的表名 `recording` 为字面量。故无需标识符白名单建模；绑定参数足以覆盖全部值位（用户可控数据只出现在值位——但值位在 142 行被直接拼接而非绑定，这正是漏洞本体）。
- **参数绑定**：crud.py:48 arg 1 是唯一绑定值通道（barrier，pass5-sink-003）；该 barrier 只移除绑定值参数节点，不影响 180 行的 SQL 文本通道（不同调用点、不同参数性质）。
- **ORM 安全调用**：`db.query(...).filter_by/.filter/.order_by`（crud.py:103-246）、`db.add/commit/refresh`（crud.py:112-114）编译为参数化 SQL，未建模为 sink/source。
- **SQL 构造器/RawSQL/text**：不存在 Django `raw()`/`RawSQL()`（无 Django）、SQLAlchemy `text()`/`from_statement()`、psycopg SQL 对象、DB-API `cursor.execute`（无 cursor 对象；DB-API 在库内部）。`sa.insert(table)` 是唯一"构造器"，按其真实执行语义（arg 0 传入 execute、标识符静态、值绑定）建模为 none 而非 sink。
- **sanitizer 证据**：注入链（142→209→180）上无任何转义/白名单/校验；导入路径（on_import）对 bz2 内容无验证。故除绑定参数通道外无 barrier。

## 5. 自定义 summary 的必要性分析

唯一 summary 标签（pass5-src-049，crud.py:209 `create_db` 参数 1 交接）**不需要**额外污点边，`isAdditionalTaintStep` 为 `none()`：

- CodeQL 默认的 `TaintTracking::Global` 已逐边覆盖该交接：f-string 分量污点（python-all `TaintTrackingPrivate` 中 `nodeTo.asExpr().(Fstring).getAValue() = nodeFrom.asExpr()` 一步）→ `sql` 局部赋值 → `return sql` → 调用点返回值 → `create_db` 实参 1 → 形参 → 180 行使用点。若再手动加"export_sql 返回值→create_db 参数 1"的边，将建立**无调用上下文约束的无条件传播**，违反"绝不建立无条件传播关系"的合同。
- **已知真实缺口（有意不建模，因为无源码内数据流证据）**：① UI 名字 → Popen → fire CLI 的进程边界；② `record(task_description)` → ORM 参数化写入 → SQLite → `export_sql` ORM 重读的 DB round-trip。这两段跨越进程/持久化边界，CodeQL 默认不可跟踪；处理方式是把 DB 驻留侧（crud.py:142 的 8 个属性读）直接建模为 source（"DB content reused into SQL" 家族），而非伪造 summary 边。若未来人工审核裁定需要端到端追踪，应在第五步重审后增加显式受控的 summary（例如仅限 `crud.insert_recording` 调用点到 `crud.export_sql` 内 recording 读的有界边）。
- 动态 fire 注册（`fire.Fire(get_functions(__name__))`，scrub.py:281 / utils.py:525）不可静态解析，未建模；其 CLI 命令面不影响本 pass 的 sink 集合。

## 6. 正式结果边界与隔离原则

- 正式 CWE-89 结果只来自 `queries/Pass5_SQLInjection.ql`（`@kind path-problem`、`@problem.severity error`、`@tags security` + `external/cwe/cwe-089`、`@id py/augur/openadapt/pass5-sql-injection`）。本轮**未生成、未执行**任何诊断查询；如后续需要核查内部包装器（`_insert`/`create_db`）的实参到形参传播，可另建 `iris/diagnostics/` 查询，但其路径不计入正式结果。
- 独立标注原则与此前命令注入/SSRF 实验一致：source/sink/summary 的取舍仅来自 Phase 1 独立 LLM 标注 + 人工审核（labels.json），未参考 PyVul 真值、修复差异、CVE 或外部公告（OpenAdapt_vuln 根目录的 sql_sinks.csv 与 漏洞审查报告.md 未打开）。本轮未修改源码、数据库、Phase 1 产物（labels/、extraction/、exploration/）及 augur-0.3.0。
- 按任务合同：本轮**不编译、不执行** CodeQL（`codeql pack install`、query run/compile、database analyze 均未运行）；qlpack.yml 沿用现有 `iris/openadapt-cwe89`（依赖 `codeql/python-all: "*"`，解析到本地缓存 7.1.1/7.1.2）。

## 7. API 核验清单（对照 `codeql/python-all 7.1.2` 源码）

| API | 核验位置 |
| --- | --- |
| `DataFlow::Node.asExpr()` | `dataflow/new/internal/DataFlowPublic.qll:200`（基类 none，ExprNode 覆写） |
| `DataFlow::parameterNode(Parameter)` | `DataFlowPublic.qll:350`（`ExtractedParameterNode parameterNode(Parameter p)`，库内公开使用） |
| `DataFlow::ConfigSig`（isSource/isSink/isBarrier/isAdditionalFlowStep，含 default） | `codeql/dataflow 2.1.7` `DataFlow.qll:405-427` |
| `TaintTracking::Global<Config>`、`flowPath(PathNode,PathNode)`、`PathNode`、`PathGraph` | `codeql/dataflow 2.1.7` `TaintTracking.qll:167`、`DataFlow.qll:710-760`；模板 `import <FlowModule>::PathGraph` 模式 |
| f-string 分量→f-string 值的污点步 | `dataflow/new/internal/TaintTrackingPrivate.qll:158` |
| `Call.getFunc()` / `Call.getPositionalArg(int)` | `AstGenerated.qll:198-206`（Call_ 类；`getArg` 为兼容别名，已用推荐的 getPositionalArg） |
| `Attribute.getName()/getObject()`、`Name.getId()`、`Subscript.getObject()`、`Fstring` | `Exprs.qll:90/627/408`（detection.json 亦已核验） |
| `Function.getName()` / `Function.getArg(int)`→Parameter | `AstGenerated.qll:533-539` |
| `Parameter.getName()/getPosition()/getLocation()` | `Function.qll:71-74/210` |
| `AstNode.getLocation().getFile()`、`Location.getStartLine()`、`File.getShortName()`（=getBaseName） | `Files.qll:31-56` |

工程选择：文件限定用 basename（`getShortName()`），避免 Windows 正/反斜杠路径差异；行号限定直接采用标签 location 的行号（本快照确定）；未使用 `module` 作为变量名；未定义 QL class；未使用 API::Node。

## 8. 编译验证（2026-10-21 追加）

用户侧 `codeql query compile --check-only` 暴露一个语法错误：`MySources.qll` 第 125 行 `pickerEventPayload` 声明漏写 `predicate` 关键字（`private pickerEventPayload(...)` → `private predicate pickerEventPayload(...)`）。该单点解析失败级联产生了当时输出的全部其余报错（QLDoc 未附着、`isSource/2` 无法解析、模块收尾 `}` 多余、各 private 谓词"unused"等）。已修复并复验：

```
codeql query compile --check-only \
  --additional-packs=<packs>/codeql/python-all/7.1.2 \
  --additional-packs=<packs>/codeql/concepts/0.0.25 \
  --additional-packs=<packs>/codeql/dataflow/2.1.7 \
  --additional-packs=<packs>/codeql/mad/1.0.51 \
  --additional-packs=<packs>/codeql/regex/1.0.51 \
  --additional-packs=<packs>/codeql/threat-models/1.0.51 \
  --additional-packs=<packs>/codeql/tutorial/1.0.51 \
  --additional-packs=<packs>/codeql/util/2.0.38 \
  --additional-packs=<packs>/codeql/xml/1.0.51 \
  --additional-packs=<packs>/codeql/yaml/1.0.51 \
  --additional-packs=<packs>/codeql/controlflow/2.0.35 \
  --additional-packs=<packs>/codeql/ssa/2.0.27 \
  --additional-packs=<packs>/codeql/typetracking/2.0.35 \
  -- queries/Pass5_SQLInjection.ql
```

结果：`Done [1/1]`，无错误无警告（四个 QLL 随主查询一并通过编译）。注意：`--additional-packs` 直接指向整个 `~/.codeql/packages` 会因多版本并存报 "found in multiple locations"——需按 python-all 7.1.2 的依赖锁定逐个传入精确版本目录（版本组合即其 qlpack.yml 声明的精确依赖）。§6 中"本轮不编译"的声明以本节为准更新：生成于 2026-10-20 的文件未经编译，2026-10-21 完成上述修复与验证性编译；仍未执行正式分析（database analyze / query run）。

## 9. 预期路径（供 Step 5 执行后核对，非结果）

执行 `Pass5_SQLInjection.ql` 时，基于当前模型可预期的 path-problem 结果（全部锚定 openadapt/crud.py）：
1. source=`recording.task_description`（及 platform，共 8 列）@142 → sink=f-string@142；
2. 同 source → sink=`create_db.sql` 参数@150（经 export_sql 返回值）；
3. 同 source → sink=`connection.execute` 参数 0@180。
仅依赖 DB 驻留 source（二阶链）；UI/CLI/导入通道 source 因进程/DB 边界不会产生路径（CodeQL 局限，见 §5）。预期无来自 `record(task_description)` 等外部 origin 的路径——这是建模的已知边界，由人工审核结论（crud.py:142 的 DB 读即受控输入位）背书。
