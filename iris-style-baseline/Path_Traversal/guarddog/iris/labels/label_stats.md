# Augur Phase 1 Step 3 — 标签统计（Pass 1: Path Traversal）

- 项目：guarddog（PyVul 脆弱快照，源码根 `dataset/codeql_databases/path_traversal_dbs/guarddog_vuln`）
- Pass：1（CWE-22 / CWE-23 / CWE-36 / CWE-73，Path Traversal）
- 标注模型：`glm-5.3`（在 Claude Code CLI 会话内直接执行推理；未调用外部 LLM HTTP API，未编造任何实验结果）
- 运行 ID：`guarddog-iris-pass1-step3-20261022`，生成时间：`2026-10-22T07:49:37Z`
- 输入：`extraction/sources.csv`（31 行）、`extraction/sinks.csv`（16 行），共 **47 个候选**
- 输出：`labels.json`（47 条 entry，已通过本地 `augur-0.3.0/assets/labels_schema.json` 校验，Draft 2020-12）、`labels_raw_pass1.json`

## 1. 批次与样本量

| 批次 | 内容 | 样本数 |
| --- | --- | --- |
| batch-s1 | source 候选：调用返回值边界（env 读取、JSON 反序列化、内容读取、requests.get 响应） | 12 |
| batch-s2 | source 候选：形参 / 内部包装函数（taint summary 审查） | 19 |
| batch-k1 | sink 候选：`open` / `os.listdir` / `invoke_semgrep` | 9 |
| batch-k2 | sink 候选：`extractall` / `os.remove` / `os.path` 检查 / `shutil.unpack_archive` | 7 |
| 合计 | | 47 |

置信度阈值 0.55，低于阈值需重新询问的条目：**0 条**（最低值 0.55，未低于阈值）。

## 2. 去重与排除

- 去重键 `(node, location, argIndex)`：47 行全部唯一，**去重删除 0 行**；sources 与 sinks 之间无 node+location 冲突。
- 标注阶段**未丢弃任何行**：判定为与 Pass 1 无关的候选保留为 `role=none / classification=fp` 并附依据（而非删除），保证原始 CSV 全覆盖、可审计。
- `tests/`、`scripts/evaluator/`、嵌套 `guarddog-db/` 在抽取阶段已被排除（见 `exploration/detection.json` 的 `exclusions_applied`），不含候选行，故无标注期排除。
- 形参行的 `arg_index` 沿用 CSV 声明位置索引（方法含 `self`，`self` 为 0），已逐一与真实函数签名核对一致。

## 3. 按角色统计（47 条）

| role | 数量 | 其中 tp | 其中 candidate | 其中 fp |
| --- | --- | --- | --- | --- |
| source | 8 | 5 | 3 | 0 |
| sink | 8 | 4 | 4 | 0 |
| sanitizer | 1 | 0 | 1 | 0 |
| summary | 15 | 10 | 5 | 0 |
| none | 15 | 0 | 0 | 15 |
| 合计 | 47 | 19 | 13 | 15 |

`unknown`：0 条（所有条目均给出明确判定或 candidate + 人工审核点）。

## 4. source（8 条）

| ID | 位置 | 分类 | 置信度 | 说明 |
| --- | --- | --- | --- | --- |
| src-03 | utils/package_info.py:25 `.json()` | tp | 0.75 | PyPI JSON 元数据：`releases[].url/filename` → 下载 URL（zip-slip 起点）、`info.version` → package_info 写入文件名 |
| src-07 | scanners/project_scanner.py:232 `.readlines()` | tp | 0.80 | requirements.txt 行 → 依赖名/版本 → `os.path.join(directory, name)` 路径链 |
| src-27 | utils/package_info.py:19 `requests.get` | tp | 0.75 | PyPI JSON API 响应（不可信包元数据） |
| src-28 | scanners/package_scanner.py:158 `requests.get` | tp | 0.70 | 归档下载响应：条目名经 `shutil.unpack_archive` 落盘（zip-slip） |
| src-30 | scanners/project_scanner.py:267 `requests.get` | tp | 0.70 | 远程 requirements.txt 内容 → 依赖名 → 路径链 |
| src-04 | scanners/project_scanner.py:92 `.json()` | candidate | 0.60 | releases 键 → version → 写路径后缀，仅 `write_package_info=True` 时可达 |
| src-06 | scanners/package_scanner.py:161 `.read()` | candidate | 0.65 | 归档字节 → 条目名传播只能由「内容 source + unpack sink」近似建模 |
| src-29 | scanners/project_scanner.py:92 `requests.get` | candidate | 0.60 | 同 src-04 的门控流 |

## 5. sink（8 条）

| ID | 位置 | 分类 | 置信度 | 说明 |
| --- | --- | --- | --- | --- |
| sink-16 | scanners/package_scanner.py:163 `shutil.unpack_archive` arg1 | tp | 0.80 | **主 CWE-22 sink**：解压目的地由 package_name 派生（`removesuffix` 字符串操作、无规范化），且归档条目名无校验（.tar.gz → `tarfile.extractall` 无 filter） |
| sink-02 | scanners/package_scanner.py:160 `open(zippath,'wb')` | tp | 0.75 | 归档写入：zippath = `join(directory, package_name + ext)`，无任何校验 |
| sink-15 | scanners/package_scanner.py:163 `unpack_archive` arg0 | tp | 0.70 | 归档源路径（同 zippath 链） |
| sink-10 | scanners/package_scanner.py:164 `os.remove(zippath)` | tp | 0.65 | 删除同一路径派生链上的文件 |
| sink-01 | scanners/package_scanner.py:65 `open(...,'w')` | candidate | 0.65 | package_info 写入，name/version 入文件名；`write_package_info` 门控（默认 False，CLI 未暴露） |
| sink-03 | scanners/project_scanner.py:231 `open(path,'r')` | candidate | 0.55 | CLI `verify` argv 路径；本地 CLI 常规授权读取 vs 威胁模型下的任意读，留人工审核 |
| sink-08/09 | analyzer/analyzer.py:159,170 `invoke_semgrep` arg1 | candidate | 0.60 | semgrep 目标路径列表来自 join(directory, name)；间接读取型 sink（扫描/报告任意目录） |

## 6. sanitizer（1 条）

| ID | 位置 | 分类 | 置信度 | 说明 |
| --- | --- | --- | --- | --- |
| sink-11 | scanners/package_scanner.py:46 `tarsafe.open(path).extractall(tmpdirname)` | candidate | 0.70 | tarsafe==0.0.4 为净化式 tar 解包（拒绝穿越/绝对/符号链接条目名），目的地为全新 `TemporaryDirectory`；库源码不在 DB 内，判定依据为锁定版本的文档化用途，需人工复核 |

## 7. summary（15 条，tp 10 / candidate 5）

tp：src-08 `Analyzer.analyze(path)`、src-09 `analyze_sourcecode(path)`、src-10 `PackageScanner.scan_local(path)`、src-11 `RequirementsScanner.scan_local(path)`、src-12 `scan_remote(name)`、src-14 `_scan_remote(name)`、src-20 `download_package(package_name)`、src-24 `download_compressed(zippath)`、src-25 `download_compressed(unzippedpath)`、src-26 `scan_requirements(requirements)`。

candidate：src-15/16 `base_dir`（仅 API 形参、操作者控制）、src-17/19 `version`（写路径仅在 `write_package_info=True` 时可达）、src-21 `directory`。

## 8. none（15 条，fp）

- 环境变量凭据（src-01/02 `getenv`）：仅作 HTTP auth 元组，从不进入路径。
- 固定可信端点内容（src-05/31 typosquatting top-packages）：仅作比较名，写入缓存为常量内部路径。
- `get_package_info(name)`（src-13）：name 仅拼入 PyPI API URL（属 Pass 3 SSRF 范畴），不达文件路径。
- `download_package(version)`（src-18）：仅作 releases 字典键与报错消息。
- URL 形参（src-22/23）：仅进入 `requests.get`（Pass 3）。
- 内部常量路径文件访问（sink-04/05/06/07/14）：typosquatting 资源缓存、analyzer 规则目录等，路径全部由代码常量构成。
- 类型分派检查（sink-12 `os.path.exists`、sink-13 `os.path.isdir`）：不做路径内容约束，非 sanitizer 亦非危险访问（TOCTOU 窗口仅记录为证据）。

## 9. 查询生成要点（供 Phase 2 Step 4 使用）

- Pass 1 的 `MySinks` 需覆盖：`shutil.unpack_archive`（arg 0/1）、`open`（arg 0，w/wb 模式）、`os.remove`（arg 0）、可选 `invoke_semgrep`（arg 1）。
- `MySources`：`requests.get` 返回值、`requests.Response.json`、`io.TextIOWrapper.readlines`、`Response.raw.read`。
- `MySummaries`：上述 10 条 tp 形参传播（scan_local/scan_remote/_scan_remote/download_package/download_compressed/scan_requirements/analyze/analyze_sourcecode）。
- `MySanitizers`：`tarsafe.TarSafe.extractall`（candidate，人工复核后可保留或降级为 none）。
