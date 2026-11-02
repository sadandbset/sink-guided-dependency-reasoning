# Augur Phase 1 Step 3 — 人工审核检查点（Pass 1: Path Traversal）

依据 WORKFLOW.md 4.5（advisory checkpoint）输出。本文档为 Step 3 标注结果的审核载荷，**不进入 Phase 2**。

## 1. 审核范围与执行声明

- 候选：`extraction/sources.csv` 31 行 + `extraction/sinks.csv` 16 行 = 47 行，全部逐条标注，0 行丢弃、0 行去重删除、0 条低于 0.55 置信度阈值需重问。
- 标注执行方：`glm-5.3` 模型（Claude Code CLI 会话内直接推理）。**未调用外部 LLM API，未编造实验结果**；批次（batch-s1/s2/k1/k2，12/19/9/7 条）为该次标注过程的逻辑分批记录。
- 标注前完整读取的真实源码：`guarddog/cli.py`、`scanners/package_scanner.py`、`scanners/project_scanner.py`、`analyzer/analyzer.py`、`analyzer/metadata/typosquatting.py`、`utils/package_info.py`。所有 rationale/evidence 中的行号均与该源码逐一核对。
- `labels.json` 已通过本地 `augur-0.3.0/assets/labels_schema.json`（Draft 2020-12）校验：47 条 entry、pass_id=1、`signature.flow_kind=argument` 条目均带合法 `arg_index`。
- 独立性声明：未读取 PyVul 真值、补丁差异、CVE 公告及仓库根部的 ground-truth 报告（`CVE-Report-GuardDog-Evaluator-PathTraversal.md` 等，见 detection.json `exclusions_applied`）。未修改源码、CodeQL 数据库、Augur 文件及 Phase 1 原始 CSV。

## 2. 按角色计数

| role | 数量 | tp | candidate | fp |
| --- | --- | --- | --- | --- |
| source | 8 | 5 | 3 | 0 |
| sink | 8 | 4 | 4 | 0 |
| sanitizer | 1 | 0 | 1 | 0 |
| summary | 15 | 10 | 5 | 0 |
| none | 15 | 0 | 0 | 15 |

Pass 1 至少存在一个 sink（满足 WORKFLOW 4.4.6 第 2 条）。

## 3. 高风险 sink（按危险度排序）

1. **`shutil.unpack_archive(zippath, unzippedpath)` arg 1 — package_scanner.py:163（tp, 0.80）**
   本代码库的主 CWE-22 汇聚点，两个独立攻击面：
   - **zip-slip（无条件）**：解压从 PyPI 下载的归档（URL 取自被扫描包的 releases 元数据），条目名完全由恶意包作者控制；本代码版本对条目名无任何校验，`.tar.gz` 路径进入 `tarfile.extractall`（Python 3.10+ 基线，未传 extraction filter）。注意 `.zip/.egg/.whl` 路径由 `zipfile.extract` 规范化不安全成员名，条目名穿越仅限 tar 归档。
   - **目的地穿越**：`unzippedpath = zippath.removesuffix(ext)` 为字符串操作（非路径规范化），`zippath = os.path.join(directory, package_name + ext)` 无包含性检查。
2. **`open(zippath, 'wb')` — package_scanner.py:160（tp, 0.75）**：同一条 join 链上的无条件写；CLI `scan <identifier>` 不经 pkg_resources 解析，Windows 下反斜杠分隔符可绕过 `is_local_package`（其正则只匹配 `/`）逃出 base 目录。
3. **`shutil.unpack_archive` arg 0（tp, 0.70）与 `os.remove(zippath)`（tp, 0.65）**：同一未校验路径链的读取/删除面。
4. candidate 级：`open(...,'w')` package_info 写入（name/version 入文件名，但被 `write_package_info=True` 门控，默认 False 且 CLI 不可达）；`invoke_semgrep` arg 1（间接读取：扫描并外泄任意目录内容）；`open(path,'r')` requirements 读取（见第 6 节审核点 R1）。

## 4. 主要 source

- PyPI JSON API 响应（`package_info.py:19/25`，tp）：releases 的 `url/filename` 选择下载归档（zip-slip 起点），`info.version` 可达写路径后缀。
- requirements.txt 内容（`project_scanner.py:232` readlines 及 `:267` 远程响应，tp）：依赖名/版本进入路径构造。
- 归档下载响应（`package_scanner.py:158`，tp；`:161` .read 为 candidate）：zip-slip 的内容侧建模。

## 5. sanitizer 清单

- `tarsafe.open(path).extractall(tmpdirname)`（package_scanner.py:46，candidate, 0.70）：tarsafe==0.0.4 文档化用途为拒绝穿越/绝对/符号链接条目名，目的地为全新 TemporaryDirectory。**库源码不在 CodeQL DB 内，无法据本项目源码验证**，判定依据为锁定版本（requirements.txt/pyproject.toml）的公开文档用途，需人工复核（R2）。
- 其余候选（`os.path.exists`/`isdir`、`removesuffix`、`is_local_package` 正则）均**不**计为 sanitizer：exists/isdir 仅为类型分派不约束路径内容；`removesuffix` 为字符串截断非规范化；`is_local_package` 仅做本地/远程路由（且只识别 `/`）。代码库中不存在 normpath/realpath/basename/relative_to/startswith 包含性检查（已通读全部相关文件确认）。

## 6. 人工审核点（无法确认/需裁决的事项）

| # | 事项 | 涉及条目 | 说明 |
| --- | --- | --- | --- |
| R1 | CLI argv 路径读取是否计为漏洞 | sink-03（0.55） | `guarddog verify <path>` → `open(path,'r')`。本地 CLI 读取操作者指定文件属常规授权使用（类比 `cat`）；但 PyVul 威胁模型假设 CLI 调用由不可信输入驱动。保留 candidate，Phase 2 过滤阶段按 FP 启发式（admin-config path source）或人工裁决。 |
| R2 | tarsafe 净化效力验证 | sink-11（0.70） | tarsafe 0.0.4 源码未入库，无法静态复核其拒绝规则；如需确证，应在 Phase 2 前用本地 pip 安装 tarsafe==0.0.4 复核源码。 |
| R3 | zip-slip 的数据流建模口径 | src-06/28, sink-16 | 归档条目名 → 解压路径的传播发生在归档语义内部，纯程序内 dataflow 不可见；当前以「下载内容为 source + unpack_archive 为 sink」近似。Phase 2 查询结果解释时需注意此近似。 |
| R4 | 门控流（write_package_info） | sink-01, src-04/17/19 | package_info 写路径仅当 `write_package_info=True`（API 形参，CLI 未暴露）时存在；tp/candidate 判定未把该门控当作根目录限制。 |
| R5 | Windows 反斜杠穿越 | sink-02/10/15, src-20 | `is_local_package` 正则仅匹配 `/`；`pkg_resources` 名字文法禁止 `/`，故 requirements.txt 名字路径的穿越受限，但 CLI 直传 identifier（Windows 反斜杠）可逃逸。平台相关，报告阶段应标注。 |
| R6 | 符号链接策略 | 全局 | 代码库无任何 symlink 专项处理（无 lstat、无 symlink 拒绝逻辑）；唯一文档化拒绝 symlink 的是 tarsafe（R2）。按用户要求记录为「不适用/未发现」。 |

## 7. 对十项审查要点的逐条结论

1. **Source 是否真不可信**：仅网络边界（PyPI/GitHub 响应）与文件内容边界（requirements.txt 行）计为 source；内部形参一律标 summary 或 none（`get_package_info(name)`、`download_package(version)` 等 8 条 none/15 条 summary 印证「形参不自动是 Source」）。
2. **路径传播可跟踪性**：package_name/name → `join(directory, name)`（:56）→ `join(directory, package_name+ext)`（:140）→ `removesuffix`（:141）→ `open('wb')`/`unpack_archive`/`os.remove`（:160-164），每步均在真实代码中逐行核实，无一步依赖推测。
3. **Sink 为真实文件访问**：`Path()`、`join()`、`removesuffix` 均未计为 sink（记入 detection.json 传播节点）；sink 仅含 open/unpack_archive/extractall/os.remove/os.listdir/invoke_semgrep。`os.listdir`/`os.path.*` 因路径为内部常量标 none。
4. **越界能力**：`../`、绝对路径、（Windows）反斜杠变体在 join→open/unpack 链上均无阻断；多次解码场景不适用（无 URL 解码入路径的代码）。
5. **受限根目录检查**：**不存在**。无规范化后包含关系检查、无 `relative_to`、无固定文件名映射、无白名单；唯一门控是 `write_package_info` 布尔开关（非路径校验）。
6. **normpath/resolve/basename/startswith/黑名单**：代码库中**均不存在**，无「凭函数名误判 sanitizer」的空间；`tarsafe` 是唯一净化候选（R2）。
7. **符号链接**：不适用（见 R6）。
8. **授权访问**：CLI verify 读操作者指定文件（R1）；本工具为本地扫描 CLI，无 HTTP 文件服务面，不存在「正常文件服务功能」误判场景。
9. **测试/常量/生成文件**：tests/、scripts/evaluator/、guarddog-db/ 已在抽取阶段排除，候选中不含；typosquatting 内部缓存读写（常量路径）标 none/fp。
10. **完整流 vs 局部流**：存在两条完整不可信 source→危险路径 sink 的流：(a) PyPI 归档（src-27/28/03）→ 下载（src-06）→ `unpack_archive`（sink-16，zip-slip，无条件）；(b) CLI identifier / requirements 内容（src-07/12）→ `join` 传播链（src-14/20/24/25）→ `open('wb')`/`os.remove`/`unpack_archive`（sink-02/10/15/16）。`invoke_semgrep` 流为 candidate（间接读取面）。

## 8. 审核决定

按用户指令，本检查点后停止，不生成 Phase 2 的 libraries/queries，不执行 taint 查询。等待人工对 R1–R6（尤其 R1、R2）做出裁决后再进入 Phase 2。
