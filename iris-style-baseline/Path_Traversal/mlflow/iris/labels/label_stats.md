# Augur Phase 1 Step 3 — Pass 1 (Path Traversal) Label Statistics

- 项目：mlflow 2.0.0.dev0（`dataset/codeql_databases/path_traversal_dbs/mlflow_vuln` 源码树）
- 语言/框架：Python / Flask（detection.json：Flask 置信度 1.0）
- Pass：1（CWE-22 / CWE-23 / CWE-36 / CWE-073，Path Traversal）
- 标注模型：glm-5.3（Claude Code CLI 内联逐批标注，确定性输出，无温度采样）
- Run ID：`mlflow-pt-pass1-20261022`
- 生成时间：2026-10-22

## 1. 输入候选与处理量

| 输入 | 行数 | 处理 | 去重 | 排除 |
| --- | --- | --- | --- | --- |
| `extraction/sources.csv` | 43 | 43 | 0（无完全重复行） | 0 |
| `extraction/sinks.csv` | 298 | 298 | 0（无完全重复行） | 0 |
| 标注期新增 sanitizer 条目 | — | — | — | —（X01/X02，来源与依据见下） |
| **labels.json 条目总数** | | **343** | | |

- 无候选在标注阶段被整行丢弃：全部 341 个 CSV 候选都有对应 entry（role 可为 `none`）。
- 去重依据：以（nodeRepr/filePath/line）或（filePath/line/callable/argIndex）为键检查完全重复，结果为 0；语义上同一 API 的多处调用点保留为独立条目（每条携带各自 location 与证据）。
- 测试/生成代码排除：Step 2 提取阶段已排除 `tests/`、`examples/`、`mlflow/protos/**`、`mlflow-db/` 等（见 detection.json `scope_and_exclusions`），标注阶段未再发现测试文件候选，故无标注期排除。
- 新增 sanitizer（X01 `verify_artifact_path`、X02 `path_not_unique`）：不在 Step 2 CSV 中，为标注过程中依据真实源码（`mlflow/store/artifact/artifact_repo.py:302-306`、`mlflow/utils/validation.py:82-84`）确认的守卫，专为 Phase 2 `MySanitizers.qll` 记录；来源已在 `labels_raw_pass1.json` 与 `phase1_review.md` 中声明。

## 2. 批次与样本量

| 批次 | 样本数 | 候选范围 | 内容 |
| --- | --- | --- | --- |
| B1 | 43 | S01–S43 | 全部 source 候选（HTTP 边界 / repo 内部边界 / 二阶 artifact_uri） |
| B2 | 40 | K001–K040 | sink 候选（os.makedirs / send_from_directory / os.listdir 起始段） |
| B3 | 40 | K041–K080 | shutil.move / rmtree / copyfile |
| B4 | 40 | K081–K120 | tarfile / os.mkdir / zipfile / os.walk / os.remove / getsize / copytree / send_file / scandir / write_text / extractall / mkdir |
| B5 | 40 | K121–K160 | open() 前段 |
| B6 | 40 | K161–K200 | open() 中段 |
| B7 | 40 | K201–K240 | open() 后段 |
| B8 | 40 | K241–K280 | open() 尾段 |
| B9 | 20 | K281–K298 + X01–X02 | codecs.open 与新增 sanitizer |

低置信度（<0.55）条目复核：hdfs/sftp 远端仓库类 candidate（置信 0.45–0.5）在 B2/B9 审查时对照 `hdfs_artifact_repo.py`、`sftp_artifact_repo.py` 源码复核一次，结论保持 classification=candidate（人工审核点）。

## 3. 角色分布（343 条）

| role | 数量 | 说明 |
| --- | --- | --- |
| source | 24 | 19 条直接 HTTP 输入边界（query_string、request_dict['path']、proto path 字段、`<path:artifact_path>` 路由变量、get_json、run_id/name/version 查询键）+ 5 条二阶 `run.info.artifact_uri`（classification=candidate） |
| sink | 292 | 真实文件访问/文件响应 API 调用点（open、copyfile、rmtree、makedirs、listdir、send_file、extractall、walk、move、copytree、mkdir、remove、getsize、scandir、write_text、tarfile、zipfile、send_from_directory、codecs.open） |
| sanitizer | 2 | X01 `verify_artifact_path`、X02 `path_not_unique`（标注期新增，证据充分） |
| summary | 12 | 内部边界形参（ArtifactRepository / LocalArtifactRepository 的 log/download/list/delete 路径形参、`_send_artifact.path`、`_get_proxied_run_artifact_destination_path.relative_path` 等）——请求派生路径的传播步骤 |
| none | 13 | 客户端侧读取、固定常量/包资源路径、响应回显（role=none，classification=fp） |

## 4. classification 分布

| classification | 数量 | 构成 |
| --- | --- | --- |
| tp | 42 | source/tp 19、summary/tp 12、sink/tp 9、sanitizer/tp 2 |
| candidate | 12 | 二阶 source 5；sink candidate 7（extractall×2 zip-slip、hdfs mkdir×2、hdfs makedirs、hdfs open、sftp mkdir） |
| fp | 289 | 276 个本地/CLI/临时路径 sink + 6 个固定路径 sink（role=none）+ 7 个客户端侧 source（role=none） |

## 5. 高风险 sink（classification=tp，9 处）

| ID | 位置 | API | 流 |
| --- | --- | --- | --- |
| K126 | `mlflow/server/handlers.py:443` | `send_file` arg0 | /get-artifact 请求 `path` → download_artifacts（仅 normpath）→ abspath → 任意文件读并作为 HTTP 响应返回 |
| K127 | `mlflow/server/handlers.py:445` | `send_file` arg0 | 同上（非文本扩展名分支） |
| K165 | `mlflow/server/handlers.py:1441` | `open` arg0 | GET /mlflow-artifacts/artifacts/<path> → download_artifacts(artifact_path) → open(dst,'rb') 流式返回 |
| K073 | `mlflow/store/artifact/local_artifact_repo.py:112` | `shutil.rmtree` arg0 | DELETE /mlflow-artifacts/artifacts/<path> → join（无 normpath、无 verify）→ 任意目录删除 |
| K087 | `mlflow/store/artifact/local_artifact_repo.py:104` | `shutil.copyfile` arg0 | _download_file：join+normpath 保留前导 `..`，读 artifact 根之外的文件 |
| K094 | `mlflow/store/artifact/local_artifact_repo.py:104` | `shutil.copyfile` arg1 | 写侧：dst 由 _create_download_destination 拼入攻击者路径 |
| K032 | `mlflow/store/artifact/artifact_repo.py:105` | `os.makedirs` arg0 | 下载目的地目录：join(dst, dirname(攻击者路径))，`..` 逃逸 |
| K033 | `mlflow/store/artifact/artifact_repo.py:202` | `os.makedirs` arg0 | 目录下载分支同类 join |
| K042 | `mlflow/utils/file_utils.py:61` | `os.listdir` arg0 | list_all 被 list_artifacts 以 join(normpath(请求 path)) 调用 → 目录列举越界（CWE-22/73 信息泄露） |

## 6. 主要 source（直接 HTTP 边界，19 条）

- `request.query_string` / `flask_request.query_string`（handlers.py:378/384/531/1272）
- `request_dict["path"]`（handlers.py:540/544/1282/1286）
- `request_message.path`（handlers.py:898/1486）
- 路由变量 `<path:artifact_path>`（handlers.py:1430/1456/1502；`serve_static_file` 的 path 于 server/__init__.py:66）
- `flask_request.get_json`（handlers.py:372）
- 查询键 run_id/run_uuid/name/version（handlers.py:533/1274/1275）

## 7. Sanitizer（2 条，标注期新增）

- X01 `verify_artifact_path`（`artifact_repo.py:302`）：仅作用于上传（log_artifact / log_artifacts / HttpArtifactRepository.log_artifact），对 download/list/delete 路径不生效。
- X02 `path_not_unique`（`validation.py:82`）：normpath 不一致 / `.` / 前导 `..` / 前导 `/` 全部拒绝。

## 8. 人工审核点（classification=candidate，12 条）

1. 二阶 source `run.info.artifact_uri`（handlers.py:536/539/904/906/1004）：经 CreateExperiment `artifact_location` 存入，可影响 repo 根选择；需实验创建权限，可控范围未完全确认。
2. `extractall`（projects/utils.py:182、utils/_spark_utils.py:80）：zip-slip 形态存在（无成员名过滤），但归档来源为本地 CLI/API 用户指定的项目 URI，非 HTTP 请求。
3. hdfs/sftp 远端仓库 mkdir/makedirs/open（hdfs_artifact_repo.py:57/70/234/235、sftp_artifact_repo.py:19）：artifact_path 未过 verify_artifact_path，但仅在部署 artifact 根为 hdfs:// / sftp:// 时被选中（管理员配置）。

## 9. 质量检查（WORKFLOW 4.4.6）

- Schema 校验：`labels.json` 通过 `assets/labels_schema.json`（本地手工校验器 `validate_labels.py`，环境无 `jsonschema` 包）；pass_id=1，entries 343。
- 每个启用 pass 至少一个 sink：满足（292 个 sink 条目，其中 9 个 tp）。
- 重复条目：无（见第 1 节）。
- arg_index 边界：`flow_kind=argument` 的条目均携带 ≥0 的整数 arg_index（0 或 1，与被调用的双参文件 API 匹配）；`field` 类 arg_index 为 null；`param` 类为 0/1/2（log_artifact 的 artifact_path 按 CSV 记录为 2）。未发现越界索引。
