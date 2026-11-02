# Augur Phase 2 Step 4–5 — mlflow Pass 1 (Path Traversal) 污点模型与路径查询生成说明

- Run ID：`mlflow-pt-pass1-20261022`（与 Phase 1 标签一致）
- 生成时间：2026-10-22
- 输入：`labels/labels.json`（343 entries，schema 校验通过）、`labels/label_stats.md`、`labels/phase1_review.md`、`extraction/{sources,sinks}.csv`、`assets/taint_query.ql.tmpl`、`references/{python.md,patterns.md,flask.md}`、`WORKFLOW.md` §5（Phase 2），以及 `mlflow_vuln` 源码树中全部被引用位置（逐行核对）
- 产物：`libraries/MySources.qll`、`libraries/MySinks.qll`、`libraries/MySanitizers.qll`、`libraries/MySummaries.qll`、`queries/Pass1_PathTraversal.ql`（本报告为第六件）
- 工具链事实：CodeQL CLI 2.25.1，本地解析 pack `codeql/python-all 7.1.2`（qlpack.yml 已在 iris 根目录，Step 0 产物，未修改）。本步只生成文件，不编译、不执行分析（按指令）。
- 独立性声明：未读取 PyVul 真值、已知 CVE 行号或修复补丁；未修改源码、数据库、Augur 目录与 Phase 1 标签。

## 0. 审核状态说明（review_decision.json）

`labels/review_decision.json` 不存在：Step 3 的 CHECKPOINT 以 advisory 模式执行（WORKFLOW §4.5 允许），`phase1_review.md` §5 记录了复核请求但未写审计文件。本次用户指令"执行 Phase 2 Step 4–5"即视为进入 Phase 2 的批准。据此采取的策略：

- role=source 且 classification=tp 的 19 条 → 全部生成 Source 规则。
- role=source 且 classification=candidate 的 5 条（二阶 `run.info.artifact_uri`）→ 生成 Source 规则（保守召回，WORKFLOW §7.1），其告警属人工复核项。
- role=sink 的 tp（9 条）与 candidate（7 条）→ 全部生成 Sink 规则。
- role=sink 且 classification=fp 的 282 条 → 不进入 Sink 模型（见 §5 排除策略），其中 2 条（K086/K093）例外保留以激活 Barrier。
- role=summary 的 12 条 → 对应 MySummaries 传播边（见 §4）。
- role=sanitizer 的 X01/X02 → MySanitizers Barrier（见 §3）。

## 1. 标签 → QLL 谓词对应总表

### 1.1 MySources::isSource(n, "path_traversal")

| 标签 | 谓词规则 | 外部输入边界 | 权限/访问条件 | 源码证据 |
| --- | --- | --- | --- | --- |
| S01, S02 | `requestMessagePathField` | proto 请求字段 `request_message.path`（ListArtifacts / ListArtifactsMlflowArtifacts 端点，请求 JSON/query body 经 `parse_dict` 解析） | 任何能调用 tracking API 的客户端（默认无鉴权） | handlers.py:888-898、1485-1486 |
| S03–S06 | `requestDictPathSubscript` | `request_dict["path"]`（query string 经 `querystring_parser.parser.parse`） | 同上（/get-artifact、/model-versions/get-artifact 为公开端点） | handlers.py:531-544、1272-1286 |
| S19–S22 | `queryStringAttr` | `request.query_string` / `flask_request.query_string` 原始 URL 查询串（最外层边界） | 同上 | handlers.py:378/384/531/1272 |
| S40–S43 | `requestDictGetCall` | `request_dict.get("run_id"/"run_uuid"/"name"/"version")` 查询键 | 同上；仅间接影响（选择 run / 模型版本，FileStore 侧有 `_RUN_ID_REGEX` 校验） | handlers.py:533、1274-1275 |
| S36 | `getJsonCall` | `flask_request.get_json(force=True, silent=True)` 整个请求体 | 同上（POST JSON 请求） | handlers.py:371-372 |
| S37, S38, S39 | `routedHandlerParam` | Flask `<path:artifact_path>` URL 转换器变量（GET/PUT/DELETE `/mlflow-artifacts/artifacts/<path:artifact_path>`，经 `app.add_url_rule` 注册） | `--serve-artifacts` 启用的 artifact 服务端点（默认开启 serve-artifacts 时） | handlers.py:1430/1456/1502；server/__init__.py:33-34；protos/mlflow_artifacts.proto:23-62 |
| S35 | `routedHandlerParam` | `/static-files/<path:path>` URL 变量 | 公开端点；其唯一 sink `send_from_directory` 被 safe_join 阻断（见 §5） | server/__init__.py:65-67 |
| S27–S30, S32（candidate） | `runArtifactUriAttr`（行集 {536,539,904,906,1004}） | 二阶：`run.info.artifact_uri`，源于 CreateExperiment API 的 `artifact_location`，存库后读出 | 需要实验/模型版本创建权限；标签 classification=candidate，人工复核项 | handlers.py:536/539/904/906/1004；label S31（913 行，role=none）按标签排除 |

未成为 Source 的内部形参（S07–S18，role=summary）通过 MySummaries 传播，不作为污点起点——符合"内部函数形参不自动是 Source"。

### 1.2 MySinks::isSink(n, "path_traversal")

| 标签 | 谓词规则 | 危险路径参数索引 | 真实文件操作 / 访问类型 | 调用关系（谁到达此处） |
| --- | --- | --- | --- | --- |
| K126, K127 | `sendFileArg` | arg 0 | 文件响应：读磁盘文件并作为 HTTP 附件返回（任意文件读原语） | `_send_artifact` ← get_artifact_handler / get_model_version_artifact_handler / 代理分支（handlers.py:437-445） |
| K165 | `downloadStreamOpenArg`（限 handlers.py:1441 行） | arg 0 | 文件读：`open(dst, "rb")` 流式回传 | `_download_artifact` ← `download_artifacts(artifact_path, tmp_dir)` 返回值（handlers.py:1430-1451） |
| K073 | `rmtreeArg` | arg 0 | 递归目录删除（任意目录删除，`..`/绝对路径均未过滤） | `LocalArtifactRepository.delete_artifacts` ← DELETE 端点（local_artifact_repo.py:106-112） |
| K086, K087 | `copyfileArg(n, 0)` | arg 0 | 文件读（copy 源） | K087：`_download_file` 内 join+normpath 后的路径（local_artifact_repo.py:100-104）；K086 为 barrier 覆盖的上传流（:38） |
| K093, K094 | `copyfileArg(n, 1)` | arg 1 | 文件写（copy 目的） | K094：`_create_download_destination` 拼入攻击者路径的落盘位置；K093 为 barrier 覆盖（:38） |
| K032, K033 | `makedirsArg`（artifact_repo.py） | arg 0 | 目录创建（逃逸下载目的目录） | 基类 `download_artifacts` 文件/目录分支（artifact_repo.py:100-106、193-202） |
| K007（candidate） | `makedirsArg`（hdfs_artifact_repo.py） | arg 0 | 目录创建（hdfs 下载落盘目的） | `_download_hdfs_file`（hdfs_artifact_repo.py:230-236） |
| K042 | `listdirArg` | arg 0 | 目录列举读（信息泄露） | `list_all` ← `LocalArtifactRepository.list_artifacts` ← ListArtifacts 请求字段（file_utils.py:59-62；local_artifact_repo.py:82-89） |
| K175（candidate） | `hdfsDownloadOpenArg`（限 235 行） | arg 0 | 文件写（下载字节落盘） | 同 K007 链 |
| K132, K133（candidate） | `extractallArg` | arg 0 | 归档解压落盘（zip-slip：条目名控制写路径） | `zip_ref.extractall(temp_dir)` / `zip_in.extractall(dst_dir)`（_spark_utils.py:77-81；projects/utils.py:179-182） |
| K134–K136（candidate） | `remoteMkdirArg` | arg 0 | 远端文件系统目录创建 | sftp/hdfs 仓库 `log_artifact(s)`，artifact_path 未过 verify（sftp:14-21；hdfs:31-76） |

每条规则匹配的是**路径文本参数**（`getArg(0/1)` 的表达式节点），不是被打开的文件对象；`send_file`/`open`/`copyfile` 的对象句柄不在匹配范围内。

### 1.3 MySanitizers::isBarrier(n, "path_traversal")

| 标签 | 谓词规则 | 阻断机制 |
| --- | --- | --- |
| X01（应用点） | `guardedLogPathParam`：Local `log_artifact`/`log_artifacts` 与 Http `log_artifact` 的 `artifact_path` 参数节点 | 见 §3 |
| X01 / X02（直接调用） | `guardCallArgument`：`verify_artifact_path` / `path_not_unique` 调用的 arg 0 | 见 §3 |

### 1.4 MySummaries::isAdditionalTaintStep(from, to, "path_traversal")

| 标签 | 谓词规则 | 边 |
| --- | --- | --- |
| S10, S12, S13, S16 | `pathTextWrapperStep` | `os.path.join/normpath/abspath`、`posixpath.join/dirname` 的参数 → 调用结果 |
| S18 | `localFileUriToPathStep` | `local_file_uri_to_path` arg0 → 结果 |
| S07, S09, S11, S12, S16, S17, S18 | `repoMethodDispatchStep` | 仓库方法调用点实参 → `mlflow/store/artifact/**` 同名方法形参（self 位置偏移 +1；关键字按名匹配） |
| S17 | `submitDownloadFileStep` | `thread_pool.submit(self._download_file, remote_file_path=…, local_path=…)` 关键字实参 → `_download_file` 形参 |
| （S12 返回链） | `inflightDownloadStep` | `InflightDownload(dst_local_path=…)` 构造关键字 → `.dst_local_path` 属性读取 |

## 2. 路径连接 / 解码 / 规范化与允许根目录、符号链接证据

- **URL 解码**：Flask 在路由层对 `<path:…>` 变量解码一次；查询串由 `request.query_string`（bytes）→ `.decode("utf-8")` → `re.sub("%5B%5D", …)`（仅替换数组括号，不产生二次解码）→ `querystring_parser.parser.parse`（外部库，不建模；污点起点放在解析后的字段读取 S03–S06）。无双重解码放大点。
- **路径连接**：`os.path.join`（含 `posixpath.join`）在默认全局污点库中已有 arg→result 步骤（python-all `Stdlib.qll` `OsPathJoinCallAdditionalTaintStep`，其 `path()` 节点把 `posixpath/ntpath/genericpath` 并入 `os.path`）；MySummaries 另行保留 join 规则使模型自包含。`os.path.join(dir, "/abs")` 语义上直接替换为绝对路径——这正是 delete/download 链对绝对路径 payload 不设防的原因。
- **规范化顺序**：`LocalArtifactRepository.download_artifacts/list_artifacts/_download_file` 均为 `join(artifact_dir, normpath(path))`——normpath 在 join **之前**且只做规范化不做包含性检查，前导 `..` 存活（`normpath("../../x") == "../../x"`）；对比 `path_not_unique`（X02）要求"norm 与原文一致 + 拒绝前导 `..`/`/`/`.`"，配合 join 才构成守卫——因此 normpath/abspath 本身不设为 Barrier（WORKFLOW 与本指令均禁止机械认定）。
- **允许根目录检查**：upload 链有（`verify_artifact_path`，见 §3）；download/list/delete 链**不存在任何** `startswith`/`relative_to`/包含性判断/白名单（源码核对：local_artifact_repo.py:60-112、artifact_repo.py:80-272、handlers.py:437-445/1430-1509）。
- **符号链接**：全库无 `os.path.islink/realpath/lexists` 使用（grep 核对）；规范化使用 normpath（不解析链接）。源码层面符号链接既未防护也未构成已知利用路径，标签阶段已记录"不适用"；查询模型对链接透明（与真实行为一致）。
- **文件访问时机**：`_send_artifact` 先 `download_artifacts`（内部 `os.path.exists`）后 `send_file` 再开文件，存在 TOCTOU 窗口；这不改变静态模型，已在 Phase 1 review §2.7 记录。

## 3. Barrier 有效性论证

**X01/X02 能阻断的机制**（`mlflow/utils/validation.py:82-84`，`artifact_repo.py:302-306`）：

`path_not_unique(name)` 当 `normpath(name) != name`（拒绝 `a/./b`、`a//b`、`a/../b` 等一切非规范写法）、`norm == "."`、`norm` 前缀 `..` 或 `/` 时为真 → `verify_artifact_path` 抛 `MlflowException`。因此在 `LocalArtifactRepository.log_artifact`（:27，先于 :31 normpath、:34 join、:38 copyfile）、`log_artifacts`（:48，先于 :58 copy_tree）与 `HttpArtifactRepository.log_artifact`（:19）内，进入函数体的 `artifact_path` 一定是相对、规范、不含 `..` 的形式，后续 `join(artifact_dir, artifact_path)` 无法逃逸 artifact 根；目的文件名再经 `os.path.basename(local_file)`（:38）二次收敛。

**Barrier 摆放**：`isBarrier` 作用于上述三个函数的 `artifact_path` **参数节点**——污点可经 dispatch 边到达该节点，但任何离开该节点的流（→ normpath → join → copyfile/copy_tree/PUT）被切断，与"守卫在文件访问之前执行"的真实时序一致。同时保留 `verify_artifact_path`/`path_not_unique` 调用实参节点为 barrier（标签 X01/X02 直接对应物；该类节点只切断进入守卫调用的分支，是文档性补充）。

**未设为 Barrier 的项及理由**：`os.path.normpath/abspath/join`（纯文本变换，download 链中已证明不阻断）；`posixpath.split`（单分量限制，属结构约束而非可插入节点的守卫——对应 K166 以排除 sink 方式处理）；werkzeug `safe_join`（Flask 库内部代码，不在本数据库，无法建为节点 barrier——对应 K036 以排除 sink 方式处理）；FileStore `_RUN_ID_REGEX` 等（作用于 run_id 而非路径文本，且无 tp sink 依赖该链）。

## 4. 额外传播边、动态调用/别名遗漏、CodeQL 局限

### 4.1 依赖的库内建模型（已核实存在）

- `os.path.join` / `posixpath.join` arg→result：python-all `semmle/python/frameworks/Stdlib.qll`（`OsPathJoinCallAdditionalTaintStep`，`path()` 含 posixpath 过近似）。MySummaries 的 join 规则为冗余保险。

### 4.2 已建模的必要传播边（均见 §1.4，证据行号见 qll 注释）

normpath/abspath/dirname 包装、`local_file_uri_to_path` 透传、仓库动态分发、submit 关键字分发、InflightDownload namedtuple 字段。

### 4.3 已知局限 / 未建模（不影响标签正确性，影响召回或精度）

1. **namedtuple 字段流**：`InflightDownload` 构造 → `[0].dst_local_path` 只能以 `inflightDownloadStep` 的名字限定边近似；K165 告警依赖该边，若失效属漏报而非误报（诊断见 §6）。
2. **property getter**：`LocalArtifactRepository.artifact_dir` 是 `@property`（返回 `self._artifact_dir`）；二阶 `run.info.artifact_uri` 污点经 `__init__` 字段写入到 property 读取的传播可能中断，二阶告警召回不完整（candidate 级，可接受）。
3. **`querystring_parser` / protobuf `parse_dict`**：外部解析库不建模——污点起点置于边界字段读取（S01–S06/S19–S22），与 Phase 1 设计一致。
4. **动态分发的过近似**：`repoMethodDispatchStep` 按方法名把调用点实参连到 `mlflow/store/artifact/**` 所有同名方法（s3/gcs/dbfs/ftp/azure/databricks 等）。后果：upload 流除了被 barrier 挡住的 Local/Http 外，会流入 hdfs/sftp 等未校验仓库并可能触发 K135/K136/K134（与标签 candidate 一致——这些仓库确实没有 verify）；其余仓库无已建 sink，不产生告警。
5. **别名导入**：`from X import Y as Z` 形式的 FS API 别名未被结构性匹配覆盖（Phase 1 已核对 mlflow 无此写法，风险为零，记录备查）。
6. **`urllib.parse`**：`_get_proxied_run_artifact_destination_path` 中 `urlparse(proxied_artifact_root).path` 不传播——只影响二阶源（root 部分），相对路径部分（请求字段）经 `posixpath.join` 正常传播。
7. **`getattr`/`setattr` 动态属性**：未见相关用法，不适用。

### 4.4 诊断路径（不计入正式 Pass 1 告警）

按指令未生成诊断文件，建议 Step 5 调试时临时使用（用后删除或不作为正式产物）：

- **wrapper/dispatch 边自检**：将 `MySummaries::isAdditionalTaintStep(f, t, "path_traversal")` 直接 select（`@kind table` 或 `select f, t`），核对每类边的条数与位置（预期：join/normpath/abspath 边集中于 handlers/local_artifact_repo/artifact_repo；dispatch 边覆盖 handlers.py:1438/1489/1509/1473 与 artifact_repo.py:74/77；submit 边 2 条；inflight 边 1 条）。
- **barrier 自检**：select `MySanitizers::isBarrier(n, "path_traversal")`（预期 3 个参数节点 + 3 个调用实参节点）。
- **K165 可达性**：临时去掉 sink 行限制对比告警差异，验证 namedtuple 边是否生效。

## 5. Sink 排除策略（fp 标签的实现决定）

- **K036/K037（send_from_directory, server/__init__.py:67/74）**：`serve_static_file` 的 path（S35）真实来自 URL，但 werkzeug `safe_join` 在库内部拒绝一切逃逸 STATIC_DIR 的路径（404）。该守卫不在数据库内、无法表达为节点 barrier，故不建 sink——否则将产生与标签（fp）矛盾的正式告警。S35 保留为 source（标签如此），无 sink 可达即无告警。
- **K166（open, handlers.py:1464）**：`posixpath.split` 的 tail 为单一路径分量，唯一穿越形态 `..` 解析到已存在的临时目录（`open(..., "wb")` 抛 IsADirectoryError）；残余风险在 head，已被 X01 barrier 阻断。同理不建 sink（这也是不建模 `posixpath.split` 传播边的原因）。
- **K086/K093（copyfile, local_artifact_repo.py:38）**：唯一例外保留的 fp sink——其守卫（X01）可表达为 barrier，保留使 barrier 在正式查询中被实际执行；上传污点在参数节点处被切断，不产生告警。
- **其余 276 个 fp sink（本地模型 flavor/pipeline/CLI 文件 I/O）**：标签判定无不可信流可达，进入 sink 模型不会增加召回（无 source 到达），只会稀释谓词；按 IRIS 精度优先策略排除。若 Step 6 过滤后需要提高召回，可在 Step 4 迭代时按签名批量加入（签名数据已在 labels.json）。

## 6. 预期告警面（预测，Step 5 验证，本轮不执行）

- **tp 主链**（预测将命中）：
  1. `S04/S06 → _send_artifact → LocalArtifactRepository.download_artifacts → send_file`（K126/K127，/get-artifact 与 /model-versions/get-artifact）；
  2. `S38 → delete_artifacts → shutil.rmtree`（K073，DELETE 端点）；
  3. `S01/S02 → list_artifacts → list_all → os.listdir`（K042，ListArtifacts 端点）；
  4. `S37 → 基类 download_artifacts → _create_download_destination → makedirs`（K032/K033）与 `submit → _download_file → copyfile`（K087/K094）；
  5. `S37 → download_artifacts 返回 → open`（K165，依赖 namedtuple 边）。
- **candidate 链**（人工复核）：`S39 → log_artifact → hdfs/sftp 仓库 → hdfs.mkdir/sftp.mkdir`（K135/K136/K134，仅部署 artifact 根为 hdfs/sftp 时真实可达）；二阶 `S27–S30/S32`（若字段流/property 链完整）。
- 上传链（S39 → K086/K093）被 barrier 阻断，预测**无**告警。

## 7. 标签遗漏检查（是否退回第五步）

逐链核对 tp 流所需节点后结论：**未发现已审核标签的遗漏**——本轮发现的问题全部是建模层面的 gap（namedtuple 字段流、property getter、动态分发过近似、safe_join 不可建模），已按 §4/§5 处理并记录，无需修改 labels.json 或退回 Step 5 复审。若 Step 5 执行后发现某 tp 链完全不可达且根因在标签（而非模型），再按指令退回第五步。

## 8. API 使用核对（防"调用不存在的 AST API"）

所有谓词/类均在本地 `codeql/python-all 7.1.2` 源码中核实：`DataFlow::Node/asExpr/getLocation`（DataFlowPublic.qll:164-207）、`DataFlow::CallCfgNode.getArg/getArgByName/getFunction`（:228-254）、`DataFlow::MethodCallNode.getMethodName/getObject/calls`（:256-295）、`DataFlow::AttrRead.getAttributeName`（Attributes.qll:244+）、`DataFlow::parameterNode`（DataFlowPublic.qll:345，Websockets.qll:69 同款用法）、AST `Call.getArg/getFunc/getAPositionalArg/getANamedArg`（Exprs.qll:104+、AstGenerated.qll:198+）、`Attribute.getName/getObject`（Exprs.qll:67+）、`Subscript.getObject/getIndex`（Exprs.qll:90+、AstGenerated.qll:1371-1376）、`Name.getId`、`StringLiteral.getS`（AstGenerated.qll:1312-1314）、`Function.getName/getArg`、`Parameter.getName/getPosition`（Function.qll:88/280）、`AstNode.getLocation/getEnclosingModule`、`Module.getFile`、`File.getRelativePath`、`Location.getStartLine`（Files.qll:247-268）；核心机制 `DataFlow::ConfigSig`（codeql/dataflow 2.1.7 DataFlow.qll:401-427，isBarrier/isAdditionalFlowStep 有默认实现）、`TaintTracking::Global` + `flowPath` + `PathGraph`（TaintTracking.qll:158-189、DataFlow.qll:710-739）。未使用 `module` 作为变量名；未使用 API::Node（无 API 图混用）；`import libraries.MySources` 点号语法与 iris 根 qlpack.yml 的包结构一致。
