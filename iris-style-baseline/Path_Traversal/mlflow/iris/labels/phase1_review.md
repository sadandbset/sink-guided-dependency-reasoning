# Augur Phase 1 Step 3 — mlflow Pass 1 (Path Traversal) 标注审查报告

- Run ID：`mlflow-pt-pass1-20261022`（2026-10-22）
- 标注模型：glm-5.3（Claude Code CLI 内联逐批标注；确定性输出，无温度采样）
- 范围：`extraction/sources.csv` 43 行 + `extraction/sinks.csv` 298 行，全部处理；输出 `labels/labels.json`（343 entries，schema 校验通过）、`labels/labels_raw_pass1.json`、`labels/label_stats.md`
- 参考文件：`references/patterns.md`、`references/python.md`、`references/flask.md`（Flask 为 detection.json 判定的主框架）、`assets/labels_schema.json`、`WORKFLOW.md` §4.4
- 独立性声明：未查看 PyVul 真值、补丁差异、CVE 公告；仅基于 `mlflow_vuln` 真实源码独立标注。未修改源码、CodeQL 数据库、Augur 目录与 Phase 1 原始 CSV。

## 1. 核心结论

mlflow 2.0.0.dev0 的 artifact 服务面存在**两类真实的、未设防的路径穿越流**和**一类被真实守卫阻断的上传流**：

### 1.1 未设防（tp 流）

**A. 下载/读取链（CWE-22 任意文件读）**

```
GET /get-artifact?path=../../etc/passwd        (get_artifact_handler, handlers.py:528)
GET /model-versions/get-artifact?path=...      (get_model_version_artifact_handler, handlers.py:1269)
  request.query_string → request_dict["path"]
  → _send_artifact(artifact_repo, path)                     [S14, summary]
  → LocalArtifactRepository.download_artifacts(path)        [S12, summary]
      local = os.path.join(artifact_dir, os.path.normpath(path))   ← 仅 normpath，无包含性检查
  → os.path.abspath(local)
  → send_file(filename)                                     [K126/K127, tp]
```

`os.path.normpath` 会折叠内部 `..`，但**保留前导 `..`**：`normpath("../../etc/passwd") == "../../etc/passwd"`，`os.path.join(artifact_dir, "../../etc/passwd")` 直接逃逸 artifact 根。整个链路上没有任何 `startswith`/`relative_to`/`resolve`-包含性检查或 `verify_artifact_path`（后者只挂在 log 路径）。`_is_servable_proxied_run_artifact_root` 分支走 `_get_proxied_run_artifact_destination_path` 的 `posixpath.join`（handlers.py:230-234），绝对路径或 `../` 前缀同样逃逸（S13）。

**B. mlflow-artifacts 专用路由（GET/PUT/DELETE `/mlflow-artifacts/artifacts/<path:artifact_path>`）**

```
GET    → _download_artifact(artifact_path)      handlers.py:1430
         → download_artifacts(artifact_path, tmp_dir)   [S11/S10, base impl]
             _create_download_destination: os.path.join(dst, posixpath.dirname(攻击者路径)) → makedirs  [K032, tp]
             local_file_path = os.path.join(dst, src_artifact_path) → _download_file
                 LocalArtifactRepository._download_file: join + normpath → shutil.copyfile   [K087/K094, tp]
         → open(dst, "rb") → 流式响应             [K165, tp]
DELETE → _delete_artifact_mflflow_artifacts(artifact_path)  handlers.py:1502
         → LocalArtifactRepository.delete_artifacts        [S18, summary]
             os.path.join(self._artifact_dir, artifact_path)   ← 无 normpath、无 verify_artifact_path
             shutil.rmtree(artifact_path)                   [K073, tp]  任意目录删除
```

注意 `LocalArtifactRepository.delete_artifacts`（local_artifact_repo.py:106-112）与同类中 `log_artifact`（第 27 行调 `verify_artifact_path`）形成鲜明对比：delete 路径完全未校验，是最直接的 CWE-22 删除原语（`..`、绝对路径、重复解码形态均可通过，仅受 `os.path.exists` 限制）。

**C. 列举链（CWE-22/73 信息泄露）**

`ListArtifacts`（handlers.py:898）与 `GET /mlflow-artifacts/artifacts?path=`（handlers.py:1486）的请求字段 → `list_artifacts` → `normpath + os.path.join + os.path.isdir + list_all` → `os.listdir`（file_utils.py:61，K042）。前导 `..` 存活，可列举 artifact 根之外的目录内容。

### 1.2 被真实守卫阻断（fp，guard 有据）

- **上传（PUT）**：`_upload_artifact` 把 URL 路径拆成 `(head, tail)`；`tail` 是单一路径分量（无 `/`），唯一穿越形态 `..` 解析到已存在的临时目录本身（`open(...,'wb')` 抛 IsADirectoryError）→ K166 fp；`head` 进入 `log_artifact` 时被 `verify_artifact_path`（X01）拒绝（normpath 不一致、`.`、前导 `..`、前导 `/` 全部 raise），且目标文件名经 `os.path.basename` → K086/K093 fp。`path_not_unique`（X02）是该守卫的正确实现。
- **静态文件**：`serve_static_file` 的 `<path:path>`（S35，真实 source）进入 `send_from_directory(STATIC_DIR, path)`，Flask/werkzeug `safe_join` 拒绝任何逃逸 STATIC_DIR 的路径 → K036 fp。
- **FileStore 路径**：`file_store.py` 的 rmtree/open/remove/walk 调用点路径全部由 `_validate_run_id`（`_RUN_ID_REGEX`：字母数字+`_\-`，无 `/`、无 `.`）与 `_validate_experiment_id`、参数/标签名校验构成 → 全部 fp。

### 1.3 人工审核点（candidate，12 条）

见 `label_stats.md` 第 8 节：二阶 `run.info.artifact_uri`（CreateExperiment `artifact_location` 可影响 repo 根选择，需实验创建权限）、`extractall` zip-slip（归档来源为本地 CLI/API 用户而非 HTTP）、hdfs/sftp 远端仓库的未校验 artifact_path（仅当部署 artifact 根为 hdfs://、sftp:// 时可达）。

## 2. 对十条审查要点的逐条回答

1. **Source 是否真正不可信？** 是——直接 source 全部来自 Flask 请求边界：原始 `query_string`、解析后的 `request_dict` 字段、proto `request_message.path`、`<path:artifact_path>`/`<path:path>` URL 转换器变量、`get_json` 全body。内部形参（`_send_artifact.path`、各 repo 方法形参）按规则标为 **summary** 而非 source（12 条）；客户端侧的 `run.info.artifact_uri` 读取（fluent/client/cli/artifact_utils）标 none/fp；服务端二阶读取（5 处）标 source/candidate。
2. **路径解码/拼接/对象转换链是否可跟踪？** 是，逐行核实：`query_string.decode('utf-8')` + `re.sub('%5B%5D',...)` → `querystring_parser.parser.parse` → dict 字段（handlers.py:378-385/531-532）；proto 侧 `parse_dict`。URL 解码由 Flask 完成（`<path:>` 转换器已解码一次）；`re.sub` 仅替换 `%5B%5D`，不会引入二次解码放大。风险链的每一步（join/normpath/abspath/split）都有真实代码位置记录在 entry 的 evidence 中。
3. **Sink 是否为实际文件访问？** 是——只把真正的文件读/写/删/解压落盘/文件响应 API 标为 sink（open、copyfile、rmtree、makedirs、listdir、send_file、extractall、walk、move、copytree、mkdir、remove、getsize、scandir、write_text、tarfile.open、zipfile.ZipFile、send_from_directory、codecs.open）。`Path()`、`join()`、字符串拼接本身不是 sink（与 Step 2 抽取策略一致，detection.json coverage_gaps 已记录）。
4. **能否越过声明的允许根目录？** 能。`../`（前导 `..` 在 normpath 后存活）、绝对路径（`os.path.join(dir, "/abs")` 在 Python 中直接替换为 `/abs`）在 download/list/delete 三条链上均无阻断；delete 链连 normpath 都没有。分隔符变体（Windows `\` / 盘符 `C:`）在 Windows 服务器上同样通过 `os.path.join`。重复解码：Flask 路由变量已解码一次，查询串手写 `.decode('utf-8')` 一次，未发现双重解码放大点（记录为不适用）。
5. **是否有执行在文件访问前的受限根目录检查？** 只有上传链有（`verify_artifact_path` 于 join/copyfile 之前，X01）；download/list/delete 链**没有任何**包含性检查（无 `relative_to`、无 normpath 后包含判断、无固定文件名映射、无白名单）。
6. **normpath 等能否阻断？** 不能仅凭函数名认定：`os.path.normpath` 在 download/list 链上被证实**不阻断**前导 `..`（local_artifact_repo.py:77/86/103）；同一函数在 `path_not_unique`（X02）中配合"norm 与原文一致性比较"才构成有效守卫——这解释了为何同一 API 在 X02 是 sanitizer、在 download 链只是传播节点。`os.path.basename`（upload 的 tail）与 `posixpath.split` 是有效的形态限制。黑名单式 `startswith("..")` 检查仅存在于 `path_not_unique`。
7. **符号链接/TOCTOU？** 源码中不存在任何 symlink 相关处理（无 `islink`/`realpath`/`lexists`），规范化使用 `normpath`（不解链接）——记录为**不适用**。TOCTOU 观察一项：`_send_artifact` 先 `download_artifacts`（内部 `os.path.exists` 检查）再 `send_file` 重新打开路径（handlers.py:438-445），窗口存在但攻击前提（本地可写）不构成服务端穿越主因。
8. **用户是否有意被授权？** `/get-artifact` 等端点的正常功能即"下载 run 的 artifact"；但允许根目录是 run 的 artifact 根，请求中 `../` 逃逸到根之外**不在授权范围内**，故正常文件服务功能不使 tp 流降级。`serve_static_file` 是授权范围内的静态资源服务且被 safe_join 限制 → fp。
9. **测试/固定常量/生成代码？** 候选中无测试文件（Step 2 已排除）；固定常量与包资源路径 6 处标 role=none（`os.devnull`、`index.html` 字面量、`~/.ssh/config`、`pkg_resources.resource_filename`×2、`get_conda_yaml_path()`）；`mlflow-db/` 数据库目录内文件未参与（结构上被排除）。CLI 供路径（sagemaker cli、scoring server `--input-path/--output-path`、deployments cli 等）按本地可信边界标 fp。
10. **完整流还是局部流？** tp 的 9 个 sink 全部具有"不可信 HTTP source → 危险路径参数"的完整流（1.1 节 A/B/C，每条 entry 的 evidence 给出链上各跳的真实代码位置）；其余 276 个 fp sink 只是"本地包装器 → 文件 API"的局部流，无 source 接入。

## 3. 去重、排除与覆盖

- 去重：以（nodeRepr, file, line）/(file, line, callable, argIndex) 检查，0 条完全重复；语义重复（如 send_file 443/445 两分支、copyfile 同一行 arg0/arg1）保留为独立条目以携带各自的 arg_index 语义。
- 排除：标注阶段 0 条整行排除；role=none（13 条）即"不相关"标签化而非删除，保证候选全量可审计。
- 覆盖缺口（沿袭 detection.json）：`querystring_parser`/protobuf 解析库内部不建模（source 放在边界读取处）；动态分发的非 Local 仓库（s3/azure/gcs/dbfs/ftp/databricks）的远端 delete/log 未全部展开（hdfs/sftp 的 mkdir 已按 candidate 标注）；`os.path.join`/`abspath`/`Path` 为传播节点非 sink。

## 4. 面向 Phase 2 的建议（不在本步执行）

1. `MySources`：直接用 19 条 source/tp；二阶 artifact_uri 5 条建议以 candidate 形态纳入并在过滤阶段复核。
2. `MySinks`：9 条 tp sink 的签名（callable+arg_index）应全部生成；fp sink 可选择性生成以保召回（污染路径必须从 source 起流，fp 标签不会引入新告警）。
3. `MySanitizers`：X01/X02 必须生成 `isBarrier`；注意 barrier 只应拦 `verify_artifact_path` 调用点（log 流），不得扩展到 download/list/delete。
4. `MySummaries`：12 条 summary 形参（尤其 `_send_artifact.path`、`LocalArtifactRepository.download_artifacts.artifact_path`、`delete_artifacts.artifact_path`）是连通 source 与 sink 的必要步骤，缺省会丢失全部 tp 路径。
5. 过滤阶段：`PASS1_FP_PATTERNS` 的 startswith/basename 规则会命中 upload 链的 fp；对 delete/download 链不应误杀（其代码中无 startswith 守卫）。

## 5. 复核请求（人工审核门）

按 WORKFLOW §4.5，以下事项建议人工复核后再进入 Phase 2：
- 12 条 candidate（label_stats.md §8）的可达性判定，特别是 hdfs/sftp 部署形态与二阶 artifact_uri。
- K094（copyfile arg1 写侧）与 K032/K033（makedirs）置信 0.65-0.7，属同一下载链的次要 sink，是否与主 sink 一并生成。
- X01/X02 为标注期新增条目（非 Step 2 候选）的接受与否。

## 6. 工件清单

- `iris/labels/labels.json`（343 entries，schema 校验通过：`python -I validate_labels.py` → VALID）
- `iris/labels/labels_raw_pass1.json`（9 批次原始决策、批次元数据、低置信复核记录）
- `iris/labels/label_stats.md`（统计）
- `iris/labels/phase1_review.md`（本报告）
- 辅助脚本（实验目录外层，不属于 iris 产物树）：`extract_context.py`（候选代码上下文提取）、`gen_labels.py`（决策表→labels）、`validate_labels.py`（本地 schema 校验器）
