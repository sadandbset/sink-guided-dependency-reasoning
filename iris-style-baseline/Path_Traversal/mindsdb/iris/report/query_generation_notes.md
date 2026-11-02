# Phase 2 Step 4–5 建模报告 — Pass 1 Path Traversal (mindsdb 23.2.2.1)

- run: `mindsdb-pass1-20261022`（沿用 Phase 1 run_id）
- 输入契约: `labels/labels.json`（pass_id 1，200 条目；source 29 / sink 28 / summary 33 / none 110 / sanitizer 0）
- 审核状态说明: `labels/review_decision.json` 不存在——Phase 1 的 CHECKPOINT 为 advisory（WORKFLOW 4.5），审核材料为 `labels/phase1_review.md`。本次按用户指示将 labels.json 视为已审核契约，未读取 PyVul 真值 / CVE / 补丁，未修改源码、数据库与 Phase 1 标签。
- 生成文件（本步骤仅生成、未编译未执行）: `libraries/MySources.qll`、`MySinks.qll`、`MySanitizers.qll`、`MySummaries.qll`、`queries/Pass1_PathTraversal.ql`；`qlpack.yml`（iris 根，`iris/mindsdb-cwe22`，依赖 `codeql/python-all: *`，实测环境 CLI 2.25.1 + python-all 7.1.1）沿用 Step 0 产物。
- 查询元数据: `@kind path-problem`、`@problem.severity error`、`@precision medium`（标签为逐站点精确匹配，但容器/回调传播为近似，综合取 medium）、`@tags security + external/cwe/cwe-022/023/036/073`、ID `py/augur/mindsdb/pass1-path-traversal`；统一 pass key `"path_traversal"`；`TaintTracking::Global<Pass1Config>` + `PathGraph`/`flowPath`，config 走 `DataFlow::ConfigSig` 四谓词（isBarrier 非空）。

## 1. 标签 → QLL 谓词对应总表

| 标签（角色） | QLL 实现 | 说明 |
| --- | --- | --- |
| S021–S036, S042（source，flask request 读取） | `MySources::flaskRequestSource`：bare attribute / subscript / `.get()` 三种形态，按审核过的六个 handler 作用域限定 | request.args / request.headers 的 none 标签站点被结构性排除 |
| S048–S054（source，上传对象属性） | `MySources::multipartUploadSource`：`file.filename / file.file_name / field.field_name / field.value`，限定三个上传 put 作用域 | `file.file_object`（none）排除 |
| S057–S060（source，multipart 回调形参） | `MySources::boundaryParamSource`（on_file/on_field 参数 0） | 污点经 E 组 summary 步进入 `.file_name` 等属性 |
| S061, S062（source，线协议 SQL 边界） | `boundaryParamSource`（`run_sql_command.ast_query`、`MysqlProxy.process_query.sql`） | 外部 MySQL/Mongo 客户端输入边界 |
| S013（source，连接参数边界） | `boundaryParamSource`（`IntegrationController.add.connection_args`） | SQL PARAMETERS / HTTP params 值的落地边界；配合 H 组循环近似边到达 K093 |
| S002, S003, S005, S006（source 标签，内部边界形参） | **不作为 isSource**；由 `MySummaries` A/B 桥接实现 | 依 Step 4 source 政策：内部形参不是外部输入节点；标签不变，仅在 QLL 层改用真实调用边实现（file.py:149 → save_file 形参 → file_handler.py:75/100） |
| S004（none） | 不实现 | DB 查找键，取回路径经 `.name` barrier |
| S007–S012（summary，FileStorage 封装） | `MySummaries` C/D 组路径构造传播（join/Path/joinpath/resolve/`/`） | 参数污点可穿过封装到达 fs.py 内部 sink（K048/K049/K068/K008/K016 等）；无污点调用方时天然不触发 |
| S063–S090（summary，wrapper RPC） | **不实现边** | 跨进程网络跳（DBServiceClient/MLClient 拉起独立 Flask 服务），库内无 intra-DB 数据流边可加；伪造传播被禁止，见第 5 节 |
| K009, K024, K034, K041, K046–K049, K063, K068, K072, K076, K079, K082, K089–K093, K095–K098, K100, K101, K105（sink） | `MySinks::argumentSink`：按（callee 点名或属性名, 危险参数索引, 所在函数）逐站点匹配 | 危险参数索引与 labels.json 的 signature.arg_index 一一对应 |
| K008, K016（sink，receiver 形态） | `MySinks::receiverSink`：`path.unlink()/rmdir()` 的 receiver 表达式 | fs.py delete；candidate 级，无已审污点调用方 |
| （sanitizer 0 条） | `MySanitizers::isBarrier`：三处 `Path(...).name` | 见第 4 节 |
| 其余 none 标签 | 不实现 | — |

QLL 内注释逐条标注了标签 ID；`dottedName`/`relPath`/`inFunction`（`getScope` + `getEnclosingScope*` 闭包）等 API 惯用法与已在本数据库编译通过的 Step 2 抽取查询一致。

## 2. Source 的外部输入边界与权限/访问条件

| source | 边界 | 访问/权限条件 |
| --- | --- | --- |
| file.py:80/70（File.put） | `PUT /api/files/<name>`，JSON body 或 multipart 原始流 | HTTP API；`http_auth_enabled` 时受 basic auth 保护（start.py before_request），默认关闭（utilities/config.py:100） |
| handlers.py:127/117（BYOMUpload.put） | `PUT /api/handlers/byom/<name>` | 同上 |
| config.py:121/122/127/192/193（Integration.put/post） | `PUT|POST /api/config/integrations/<name>`（params JSON/form/files） | 同上 |
| sql.py:22、analysis.py:28 | `POST /api/sql/query`、`POST /api/analysis/query`（`request.json['query']`） | 同上 |
| multipart 属性/回调（file.py:42–52、handlers.py:89–99、config.py:133） | 上述路由的 python-multipart/werkzeug 上传，客户端完全控制 `file_name`/`filename`/表单值 | 同上 |
| mysql_proxy.py:432 `process_query(sql)` | MySQL 线协议（47335 端口，外部客户端）及 FakeMysqlProxy | 线协议服务绑定 host 由配置决定（默认 127.0.0.1，docker 0.0.0.0） |
| query_sql.py:5 `run_sql_command(ast_query)` | Mongo 线协议（47336）命令翻译出的 SQL AST | 同上 |
| integrations.py:45 `add(connection_args)` | SQL `CREATE DATABASE ... PARAMETERS` / HTTP 集成 params 的值落地边界 | 跨 SQL 解析不透明性（parse_sql 字符串→AST 无数据流）后的务实边界，labels S013 tp |

内部 wrapper（db/ml/executor）的 `request.json` 仅来自 mindsdb 自身拉起的本机 RPC 服务，不视为外部边界，与 labels 的 summary 角色一致。

## 3. 危险 Sink 的真实操作、参数索引、访问类型与调用关系

| sink | 操作 | 索引 | 访问类型 | 主要调用关系（已审链） |
| --- | --- | --- | --- | --- |
| K034 file.py:123 `open` | 任意写 | 0 | 写（URL 分支内容为远端取回数据） | request.json['name'] → join → open |
| K095/K096 file.py:133/136 `ZipFile`/`tarfile.open` | 归档读 | 0 | 读 | data['file'] → join → 归档打开 |
| K097/K098 file.py:134/137 `extractall` | 解压落盘 | 0（目的目录） | 写（成员名） | 与 K095/K096 同源；zip-slip 成员名写是归档内容而非字符串污点，实际检出靠 K095/K096 |
| K072 file.py:138 `os.remove` | 任意删 | 0 | 删 | data['file'] → join |
| K009 handlers.py:136 `os.unlink` | 任意删 | 0 | 删 | BYOM data['file'] → join |
| K079 file_controller.py:100 `shutil.move` | 任意移动/删除源 | 0 | 读+删 | A 桥（file.py:149）→ save_file.file_path |
| K082 同上 | 任意写目的 | 1 | 写 | A 桥（original_file_name 关键字）→ joinpath → str |
| K024 file_handler.py:158 `open` | 任意读 | 0 | 读（内容成为可 SELECT 的表数据） | A/B 桥 → _handle_source → _get_data_io |
| K093 integrations.py:68 `shutil.copy` | 任意读+拷贝 | 0 | 读 | S013 → H 循环近似边 |
| K041 bigquery_handler.py:47 `open` | 任意读 | 0 | 读 | 连接检查用原始路径；**污点不可达**（构造经 DBServiceClient 跨进程/构造器字段流，见第 5 节） |
| K105 sqlite_handler.py:60 `sqlite3.connect` | 任意 DB 文件打开/建 | 0 | 读/写/建 | 同 K041 |
| K100 config.py:137 `file.save` | 上传写 | 0 | 写 | file.filename → Path → joinpath → resolve；受 config.py:133-136 分支护栏（fp 标签，Step 6 过滤） |
| K101 start.py:67 `send_from_directory` | 文件响应 | 1 | 读 | 已审 source 集无该路由参数 source → 不会正式告警（fp 标签） |
| K046–K049, K063, K068, K076, K089–K092（fs.py 内部） | copy/file_set/file_get/get_path 内部 open/rmtree/makedirs/remove/copytree/copy2 | 0/1 | 混合 | candidate：需 FileStorage 形参污点，当前已审 source 集无调用方（byom create 休眠） |
| K008/K016 fs.py:326/328 `path.unlink()/rmdir()` | 删除 | receiver | 删 | candidate，同上 |

## 4. Barrier 有效性论证

| barrier | 位置 | 阻断机制 | 结论 |
| --- | --- | --- | --- |
| `Path(x).name` | integrations.py:69（add）、file_controller.py:71（save_file 默认名）、file_controller.py:128（get_file_path 取回） | basename 剥离全部目录段：`..`、绝对前缀、分隔符变体均不保留 | **有效**，且与使用时机正确：line 69 在存储值上生效（line 68 的 copy 刻意在其前，故 K093 不被阻断）；line 128 使 SQL 取回流不越界（S004 标 none 的依据） |
| config.py:133-136 `resolve()+parents` 包含检查 | Integration.put | 分支敏感 | **无法建模为节点 barrier**（barrier 作用于节点而非分支）；K100 预期告警、Step 6 按显式包含检查启发式过滤 |
| fs.py:297/311 `is_absolute()` 拒绝 | get_path/delete | 仅拒绝绝对路径 | 部分屏障且分支敏感：`..` 相对段不受控（fs.py:295 resolve 被注释）；不建模 |
| fs.py:314-316 相等比较 | delete | 仅保护根目录自身 | 非包含检查；不建模 |
| werkzeug `safe_join` | send_from_directory 内部 | 框架层 | 仓库外代码，不可建模；K101 依赖"无 source"自然不告警 |
| `resolve()` | — | 规范化不消除越界 | 在 MySummaries C 组作为**传播**步建模（非 barrier） |

允许根目录检查的真实状态：全仓库无 `realpath`/`normpath`/`secure_filename`/`safe_join` 调用（Step 1 grep 验证）；`os.path.join` 遇绝对第二参数丢弃基目录（file.py:129 等），符号链接处理代码不存在（N/A，无 follow 策略可评估）。

## 5. 额外传播边、动态调用/别名遗漏、CodeQL 局限与诊断路径

已建边（MySummaries，全部有真实代码依据）: A（file.py:149 动态 receiver `ca.file_controller.save_file` → save_file 形参；关键字 `file_name` 用变量 `original_file_name` 桥接，因不可解析调用上关键字形参匹配不可表达）、B（file_controller.py:75 / file_handler.py:100 静态调用安全网，可解析时冗余）、C（os.path.join/Path/joinpath/resolve/str 全局按 callee 约束 + file_controller 限定 str）、D（fs.py 的 pathlib `/`）、E（multipart 参数→属性→decode）、F（两个上传 handler 内 `data` 字典的容器近似）、G（config.py `.get()` receiver→结果）、H（add 的 `connection_args` → copy 原始参数循环近似）。

已知局限（不影响标签，不修改 labels.json）:
1. **参数节点匹配不确定**：`isSource` 用 `source.asExpr() = p.asName()` 匹配形参——编译安全（两 API 均在已编译查询中出现过），但若本版本新 DataFlow 库的形参节点不以其 Name 为 asExpr，则 S013/S061/S062 及回调参数 source 语义上不触发；HTTP 侧主要链路（Expr 形态 source）不受影响。诊断方式：对 `MySources` 各分支写 diagnostics 计数查询（iris/diagnostics/ 下，不计入正式告警）。
2. **K041/K105 不可达**：SQL 连接检查流经 `create_tmp_handler → DBServiceClient`（跨进程/构造器字段流），且 bigquery/sqlite 的 `self.connection_data[...]` 跨方法字段流默认不跟踪；不为此造任意边。代码层漏洞性已由标签（tp）记录，污点查询内属诊断盲区。
3. **wrapper RPC（S063–S090）**：网络跳无 intra-DB 边；如需验证可写 diagnostics 查询（不计入 Pass 1 结果）。
4. **zip-slip 成员名**（K097/K098）不是字符串污点，实际由归档打开 sink（K095/K096）承检。
5. 容器（字典元素）与 for-target 传播的默认覆盖不确定，F/H 用作用域限定的近似边兜底；近似可能引入少量额外路径（如 `data['source_type']` 等比较操作数），不影响 sink 判定本身。

## 6. 标签遗漏检查

未发现需要退回第五步重审的遗漏。唯一偏离：S002/S003/S005/S006 四条"source（内部边界形参）"标签按 Step 4 源政策改由 summary 边实现（第 1 节）——这是 QLL 实现层的角色选择，标签文件未动；若人工审核坚持将四条作为 isSource，可在 MySources::boundaryParamSource 增补四个站点，无需重标。

## 7. 实验独立性

本步骤及全部产物仅依据 mindsdb_vuln 源码、Step 1–3 的 exploration/extraction/labels 工件与 Augur 模板/参考文件；未读取 PyVul 真值、已知 CVE 行号或修复补丁；未修改源码、CodeQL 数据库、Augur 目录与 Phase 1 标签；按指令仅生成六个文件，Phase 2 后续步骤（Step 5 运行、Step 6 过滤）待命。

## 8. 编译验证记录（Step 4 收尾追加）

用户在本机首次编译 `queries/Pass1_PathTraversal.ql` 时报错，随后由本步骤完成修复并验证（`codeql query compile`，CLI 2.25.1 + 本地 python-all 缓存，仅编译类型检查，未对数据库执行正式污点分析）：

1. **`from` 关键字冲突**（报错形态："select clause conflicts with select clause"，遍布 MySummaries.qll:66–397）：初版 `isAdditionalTaintStep` 及各私有步谓词使用了 `DataFlow::Node from` / `to` 作形参名。`from` 是 QL 查询子句关键字，含它的每个谓词被误解析为带 from 子句的查询体，而一个编译单元只允许一个 select 子句，故产生级联冲突。修复：全部改名为 `nodeFrom`/`nodeTo`（与 Augur `taint_query.ql.tmpl` 的形参命名一致）；MySources/MySinks/MySanitizers 未受影响（其形参名为 source/sink/node）。
2. **`filePattern` 形参不可绑定**（报错形态："'filePattern' is not bound to a value"，四个库的 `inFunction` 声明处）：初版在谓词体内仅以 `relPath(f).matches(filePattern)` 使用该形参——`matches` 的模式参数是 bound-only 位置，谓词体无法绑定它（对照 `f.getName() = funcName` 可绑定 `funcName` 故不报错）。修复：因全部已审调用点都传精确相对路径，改为 `relPath(f) = filePattern` / `relPath(n) = filePattern`（等式可绑定形参）；带 `%` 通配的站点本就直接以字面量调用 `relPath(...).matches("...%")`，不受影响。顺带删除 MySources 中冗余的 `source.asExpr() instanceof Expr` 守卫（编译告警 "test is always true"）。
3. 修复后 `codeql query compile queries/Pass1_PathTraversal.ql` 通过（`Done [1/1 comp 19.8s]`，无错误无告警），证明四个库的全部 AST/DataFlow API 选择（`getScope`/`getEnclosingScope*`/`Subscript.getValue`/`getArgByName`/`p.asName()`/`asExpr()`/`getPositionalArg`/`BinaryExpr` 等）在本 python-all 版本下均有效。本记录仅涉及 QL 语法层修复，未改变任何 source/sink/barrier/summary 的建模语义，labels.json 仍未改动。
