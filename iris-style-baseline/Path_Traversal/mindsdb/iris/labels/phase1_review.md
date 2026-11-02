# Phase 1 Step 3 人工审核材料 — Pass 1 Path Traversal (mindsdb 23.2.2.1)

- run_id: `mindsdb-pass1-20261022`
- 标注模型: glm-5.3（Claude Code 代理进程内 LLM 分析，直接阅读 mindsdb_vuln 源码逐批标注；未调用外部 LLM API，未参考 PyVul 真值 / 补丁差异 / CVE 公告）
- 批次: 8 批（S1–S4 源候选、K1–K4 汇候选）
- 样本量: 原始候选 236 行（sources.csv 120 行 + sinks.csv 116 行），全部处理；去重后 200 个唯一条目（源 90 + 汇 110）
- 去重依据: 同一 file:line 上 flask request 读取的三种抽取形态（下标 / 属性读 / `.get()` 字段访问）合并为一条，保留最具体访问器；同一语句的 pathlib receiver 形态与 `os.unlink`/`os.rmdir` 参数形态合并（handlers.py:136、cache.py:181、handlers.py:137、file.py:141/146/151，共 6 行）
- 排除依据（非候选重标，而是 `none` 标注）: 迁移脚本、进程标记/证书/缓存/遥测/静态 GUI 等服务端固定路径；`company-id`/`user-class` 头部经 int() 转换仅进入 f-string 记录名；CLI/环境变量为运维边界；Content-Type 等仅作分支判断的头部
- Schema 校验: labels.json 已通过 `assets/labels_schema.json`（jsonschema 4.26.0 本地校验）

## 1. 标签计数（Pass 1）

| role | 数量 | 说明 |
| --- | --- | --- |
| source | 29 | 其中 tp 22 / candidate 7 |
| sink | 28 | 其中 tp 13 / candidate 13 / fp 2 |
| sanitizer | 0 | 见第 4 节说明 |
| summary | 33 | FileStorage 内部封装 6 + 内部 RPC 包装器 request.json 27 |
| none | 110 | 与路径无关或服务端固定路径 |

classification 合计: tp 35 / fp 112 / candidate 53 / unknown 0。

## 2. 高风险 sink（完整流的核心）

| id | 位置 | API | 危险参数 | 置信度 |
| --- | --- | --- | --- | --- |
| K024 | integrations/handlers/file_handler/file_handler.py:158 | `open(file_path,'rb')` | arg 0 | 0.95 |
| K034 | api/http/namespaces/file.py:123 | `open(file_path,'wb')` | arg 0 | 0.90 |
| K095/K096 | api/http/namespaces/file.py:133/136 | `zipfile.ZipFile` / `tarfile.open` | arg 0 | 0.90 |
| K097/K098 | api/http/namespaces/file.py:134/137 | `extractall`（zip-slip） | arg 0 | 0.90 |
| K072 | api/http/namespaces/file.py:138 | `os.remove` | arg 0 | 0.90 |
| K009 | api/http/namespaces/handlers.py:136 | `os.unlink` | arg 0 | 0.90 |
| K079/K082 | interfaces/file/file_controller.py:100 | `shutil.move` 源/目的 | arg 0/1 | 0.90 |
| K093 | interfaces/database/integrations.py:68 | `shutil.copy(arg_value, files_dir)` | arg 0 | 0.90 |
| K041 | integrations/handlers/bigquery_handler/bigquery_handler.py:47 | `open(service_account_keys)` | arg 0 | 0.85 |
| K105 | integrations/handlers/sqlite_handler/sqlite_handler.py:60 | `sqlite3.connect(db_file)` | arg 0 | 0.85 |

### 完整污点链（source → … → sink，均经真实代码逐步跟踪）

1. **`/api/files/<name>` 文件上传（multipart 或 JSON 分支）**: `on_file`/`file.file_name`（S059/S053）或 `request.json`（S033）→ `data['file']` → `os.path.join(temp_dir_path, data['file'])`（file.py:129；绝对路径直接替换拼接基目录，`..` 逃逸临时目录）→ `open 'rb'`（K024，任意读，内容成为可 SELECT 的 file 表）/ `open 'wb'`（K034，URL 分支任意写）/ `ZipFile`/`tarfile.open`/`extractall`（K095–K098，zip-slip 无成员名校验）/ `os.remove`（K072，任意删）/ 经 `save_file` 的 `shutil.move`（K079/K082）。`original_file_name` 表单字段（S050）→ `file_dir.joinpath(file_name)` → move 目的路径越界（K082）。
2. **`/api/handlers/byom/<name>`**: `on_file`/`file.file_name`（S060/S054）或 `request.json`（S029）→ `os.path.join(temp_dir_path, data['file'])`（handlers.py:129）→ `model_code`（ARG_TYPE.PATH 连接参数）→ `IntegrationController.add` 内 `shutil.copy` 原始路径（K093）→ `os.unlink(file_path)`（K009）。注：`BYOMHandler.create` 在本版本直接 `raise 'BYOM disabled yet'`（byom_handler.py:53），`file_get` 下游休眠，但上传时连接参数与 copy/unlink 均为活代码。
3. **SQL / MySQL 线协议 / Mongo 线协议**: `process_query(sql)`（S062）、`request.json['query']`（S036）、`run_sql_command(ast_query)`（S061）→ `CREATE DATABASE ... PARAMETERS` → `executor_commands.py:730-757` 以**原始路径**运行 `create_tmp_handler + check_connection` → `open(service_account_keys)`（K041）/ `sqlite3.connect(db_file)`（K105）；随后 `IntegrationController.add` 的 copy+basename（K093 + integrations.py:69）才生效。
4. **`PUT /api/config/integrations/<name>`**: `request.json['params']`/`request.form`（S021/S022）→ `add` → `shutil.copy` 原始 PATH 参数（K093）。

## 3. 广覆盖 source（供 MySources.qll）

`request.json`（file.py:80 / sql.py:22 / analysis.py:28 / handlers.py:127 / config.py:121）、`request.form`/`request.files`（config.py:122/127）、multipart 回调 `on_file`/`on_field` 与 `file.file_name`/`field.value`（file.py:42-52、handlers.py:89-99）、边界形参 `save_file(file_path/file_name)`、`_handle_source`/`_get_data_io`、`IntegrationController.add(connection_args)`、`process_query(sql)`、`run_sql_command(ast_query)`。内部 RPC 包装器（db/ml/executor wrapper 的 `request.json`）标为 summary 而非 source（见第 6 节）。

## 4. Sanitizer 清单

无候选节点被标注为 sanitizer——抽取 CSV 中没有任何节点本身就是被证明的净化屏障。真实存在于源码、将写入 Step 4 `MySanitizers.qll` 的屏障：

- `config.py:133-136`: `temp_dir_path.joinpath(Path(file.filename)).resolve()` + `temp_dir_path not in file_path.parents` 检查——对 werkzeug 集成上传是**有效**的 resolve+包含屏障（file.save K100 标 sink/fp 的依据）。
- `integrations.py:68-69`: `shutil.copy(arg_value, files_dir)` 后 `Path(arg_value).name`——basename 对**存储值**有效，但 copy 仍读原始路径（K093 tp 的依据），且 `executor_commands` 的连接检查先于 basename 执行。
- `file_controller.py:128`: `Path(file_record.source_file_path).name`——文件取回路径 basename 中和（get_file_path 的 name 形参标 none 的依据）。
- `fs.py:297-298/311-312`: `is_absolute()` 拒绝——仅部分屏障：`..` 相对段不受控（resolve 被注释掉，fs.py:295）。
- `fs.py:314-316`: delete 中仅与根目录做**相等**比较而非包含——部分屏障。
- werkzeug `safe_join`（`send_from_directory` 内部，框架层）——start.py:67 标 sink/fp 的依据；同时 `path.startswith('api/')` 只是路由分流。

## 5. 无法确认 / 待人工复核项

- `fs.py` FileStorage 系列（S007–S012、K008/K016/K046–K049/K063/K068/K076/K089–K092，均为 candidate，conf ≤ 0.6）: `file_set/file_get` 无绝对路径拒绝、`get_path` 的 resolve 被注释、`delete` 仅做相等比较——**结构上存在越界缺口**，但未找到带污点的真实调用方（已知调用传入固定字面量或 basename 后的值）。建议人工确认是否存在其他版本/路径的调用方。
- `config.py:192/193`（Integration.post 修改流，S024/S025）: modify 不经 add 的 basename，原始 PATH 值入库；但 `get_handler` 在使用时会用 `fs_store.get_path(参数名)` 整体替换值（integrations.py:286-294），未发现直接消费原始值的文件操作。
- `stream.py:48`（S037）: 流参数未发现路径消费方，保留人工复核点。
- request.stream（S028/S032）: 客户端文件名写入发生在 python-multipart 库内部（UPLOAD_KEEP_FILENAME=True），仓库侧仅见 data['file'] 传播；库内写出超出 CodeQL 数据库范围。
- 内部 RPC 包装器（S063–S090，summary/candidate）: 仅本机回环服务的再入口，跨网络跳的数据流需要 summary 边建模；若部署暴露这些端口则应升级为 source。

## 6. 十项审查要点的结论摘要

1. **Source 真实性**: 仅公共 HTTP API（flask request 访问器、multipart 回调、上传属性）与 SQL/MySQL/Mongo 线协议边界标为 source；内部形参不自动为 source（save_file 等标注时逐一验证了调用方为不可信入口）。
2. **路径传播可跟踪**: 上述第 2 节 4 条链的每一步（join / joinpath / 字典传递 / 形参传递）均对应真实代码行。
3. **Sink 为真实文件访问**: `Path(...)`、`join()`、字符串拼接本身未标 sink；全部 28 个 sink 均为实际 open/删除/移动/解压落盘/文件响应/数据库文件打开。
4. **越界能力**: `os.path.join` 遇绝对路径丢弃基目录、`..` 逃逸、zip/tar 成员名 `../`（zip-slip）、多重解码不涉及（无二次 URL 解码点）。
5. **受限根目录检查**: 仅 config.py:133-136 是执行于文件访问前的有效包含检查；fs.py 的两类检查均为部分屏障（见第 4 节）。
6. **按函数名不认定为 sanitizer**: normpath/resolve/basename/startswith/黑名单逐个验证实际语义后分类（`Path(...).name` 仅在 integrations.py:69 与 file_controller.py:128 被认定为有效 basename 中和）。
7. **符号链接**: 仓库内无 symlink 处理与跟随策略代码——不适用（记录为 N/A，非人工审核点）。
8. **授权访问**: `GET /<path:path>` 静态文件服务（start.py:67）为正常应用功能且受 safe_join 保护，标 sink/fp 而非漏洞；`/api/handlers/<name>/icon` 路径组件全部来自服务端 handler 元数据，标 none。
9. **测试/常量/生成文件**: 迁移脚本、mkstemp 证书、缓存校验和、GUI 静态更新等服务端路径共 109 条标 none/fp；mindsdb-db、tests/、setup.py 在抽取阶段已被结构性排除，本步骤未重标。
10. **完整流 vs 局部流**: 完整流见第 2 节（4 条）；fs.py 系列为"内部封装 → 文件 API"的局部流，无不可信 source 接入，故保留 candidate 而非 tp。

## 7. 审核决定

按 Augur WORKFLOW 4.5（advisory checkpoint）：本文件为审核材料；经人工批准后方可进入 Phase 2（Step 4 生成 CodeQL 库）。建议重点复核第 5 节各项及第 2 节链 3（SQL 连接检查先于 basename 的时序问题）。
