# Augur Phase 2 Step 4–5 — 查询生成建模报告（Pass 1: Path Traversal）

- 项目：guarddog（PyVul 脆弱快照，源码根 `dataset/codeql_databases/path_traversal_dbs/guarddog_vuln`，DB `guarddog-db`，CodeQL CLI 2.25.1）
- Pass：1（CWE-22 / CWE-23 / CWE-36 / CWE-73）
- 标签来源：`iris/labels/labels.json`（run `guarddog-iris-pass1-step3-20261022`，47 条 entry，Phase 1 人工审核载荷见 `iris/labels/phase1_review.md`）
- 生成文件：`libraries/MySources.qll`、`MySinks.qll`、`MySanitizers.qll`、`MySummaries.qll`、`queries/Pass1_PathTraversal.ql`（模板 `augur-0.3.0/assets/taint_query.ql.tmpl`）
- 生成时间：2026-10-22；生成方：glm-5.3（Claude Code CLI 会话内）
- **编译状态：已通过编译验证**（`codeql query compile iris/queries/Pass1_PathTraversal.ql` → `Done [1/1 comp 15.3s]`，CodeQL CLI 2.25.1 + python-all 7.1.2）。首次编译发现一处错误并已修复，见 §11a；**未执行任何污点分析**（Step 5 的 database analyze 未运行）。所有 QL API 名称逐一对照本地安装的 `codeql/python-all 7.1.2`（配合 `codeql/dataflow 2.1.7`）库源码核验（清单见 §9）。

## 0. 审核状态说明

`iris/labels/review_decision.json` **不存在**（Step 3 后未写入审核决定文件）。本次 Step 4–5 依据已产出的 `labels.json` + `phase1_review.md`（含 6 个人工审核点 R1–R6）作为审核载荷执行；用户指令执行 Step 4–5 即视为放行。标签内容未被读取方修改。发现的两处标签覆盖缺口见 §7（已记录待退回第五步复核，未擅自改标签）。

## 1. 标签 → QLL 谓词映射总表

### 1.1 Source（`MySources::isSource(node, "path_traversal")`，8/8 条全部渲染）

| 标签 ID | 分类/置信 | 谓词 | 匹配方式（API + 位置） | 源码证据 |
| --- | --- | --- | --- | --- |
| src-03 | tp 0.75 | `src03ResponseJson` | MethodCallNode `json` @ package_info.py:25 | `data = response.json()`；`info.version`→写路径后缀、`releases[].url`→下载 zip-slip 起点 |
| src-04 | candidate 0.6 | `src04VersionsJson` | MethodCallNode `json` @ project_scanner.py:92 | `data = requests.get(url).json()`；releases 键→version→写路径（`write_package_info` 门控） |
| src-06 | candidate 0.65 | `src06ArchiveRead` | MethodCallNode `read` @ package_scanner.py:161 | `f.write(response.raw.read())`；归档条目名→unpack_archive（数据流不可见，见 §8） |
| src-07 | tp 0.8 | `src07RequirementsLines` | MethodCallNode `readlines` @ project_scanner.py:232 | `open(path).readlines()`→`scan_requirements`→依赖名 |
| src-27 | tp 0.75 | `src27PackageInfoGet` | `API:requests.get` getACall @ package_info.py:19 | PyPI JSON API 响应 |
| src-28 | tp 0.7 | `src28ArchiveGet` | `API:requests.get` getACall @ package_scanner.py:158 | 归档下载响应（zip-slip 内容源） |
| src-29 | candidate 0.6 | `src29VersionsGet` | `API:requests.get` getACall @ project_scanner.py:92 | versions API 响应 |
| src-30 | tp 0.7 | `src30RemoteRequirementsGet` | `API:requests.get` getACall @ project_scanner.py:267 | 远程 requirements.txt 响应（`resp.content`，传播边 S14） |

`none` 的 15 条候选（env 凭据、typosquatting 固定端点、URL 形参、version 字典键等）**不渲染**：所有 source 谓词均以 (file, line) 位置 + API 形状双重约束，typosquatting.py:68 的 `requests.get(...).json()`（标签 src-05/31, none）等绝不会匹配。

### 1.2 Sink（`MySinks::isSink(node, "path_traversal")`，8/8 条全部渲染）

| 标签 ID | 分类/置信 | 谓词 | 危险参数索引 / 访问类型 | 匹配（API + 位置） |
| --- | --- | --- | --- | --- |
| sink-01 | candidate 0.65 | `sink01PackageInfoWrite` | arg 0，文件写（"w"） | `API:builtin open` @ package_scanner.py:65 |
| sink-02 | tp 0.75 | `sink02ArchiveWrite` | arg 0，文件写（"wb"） | `API:builtin open` @ package_scanner.py:160 |
| sink-03 | candidate 0.55 | `sink03RequirementsRead` | arg 0，文件读（"r"） | `API:builtin open` @ project_scanner.py:231 |
| sink-08 | candidate 0.6 | `sink08SemgrepTargetAll` | arg 1，外部扫描器读取（目标路径列表） | 调用函数名 `invoke_semgrep` @ analyzer.py:159 |
| sink-09 | candidate 0.6 | `sink09SemgrepTargetRule` | arg 1，同上 | 同名 @ analyzer.py:170 |
| sink-10 | tp 0.65 | `sink10ArchiveRemove` | arg 0，文件删除 | `API:os.remove` @ package_scanner.py:164 |
| sink-15 | tp 0.7 | `sink15UnpackArchiveSource` | arg 0，归档读取/解压 | `API:shutil.unpack_archive` @ package_scanner.py:163 |
| sink-16 | tp 0.8 | `sink16UnpackArchiveDestination` | arg 1，归档解压落盘（主 CWE-22 汇聚点） | 同上 |

- 每个谓词取 **路径文本参数节点**（`CallCfgNode.getArg(i)`），绝不取被打开的文件对象节点。
- `invoke_semgrep` 因 `from semgrep.semgrep_main import invoke_semgrep` 直接导入，用调用函数名 `Name` 匹配（避免 API 图对 from-import 的解析歧义）。
- 标签为 `none` 的 7 个文件访问（typosquatting 缓存读写、analyzer 规则目录 listdir、os.path.exists/isdir/getmtime）不渲染——谓词按位置约束，永不匹配。

### 1.3 Sanitizer / Barrier（`MySanitizers::isBarrier(node, "path_traversal")`）

| 标签 ID | 分类/置信 | 谓词 | 屏障节点 |
| --- | --- | --- | --- |
| sink-11 | candidate 0.7 | `sink11TarsafeExtractallBarrier` | package_scanner.py:46 的 `tarsafe.open(path)` 调用节点 与 `.extractall(tmpdirname)` 方法调用节点 |

无其他 barrier：`os.path.exists`（:43）、`os.path.isdir`（:48）标签为 none——它们仅做本地/归档类型分派，不约束路径内容（TOCTOU 窗口仅记录为证据）；`is_local_package`（cli.py:101-103）正则仅做本地/远程路由且只识别 `/`。**代码库中不存在任何允许根目录检查**（§5 详述），故无需建模任何"根目录包含性"屏障。

### 1.4 Summary / 附加传播边（`MySummaries::isAdditionalTaintStep(from, to, "path_traversal")`）

15 条 `role=summary` 标签中：
- **12 条形参传递类**（src-08/09/10/11/12/14/17/19/20/21/24/25：scan_local/scan_remote/_scan_remote/download_package/download_compressed/analyze/analyze_sourcecode 等形参）由 `TaintTracking::Global` 的默认跨过程边（实参→形参、返回值→调用方）**自动实现**，不重复发射，避免双重边。
- **src-26**（requirements 内容→依赖名/版本→scan_remote）与 src-09/25/30 隐含的中间跳变需显式传播边实现，见 §4。

## 2. 各 Source 的外部输入边界与权限/访问条件

| Source | 输入边界 | 谁控制 | 访问/权限条件 |
| --- | --- | --- | --- |
| src-27/03（package_info.py:19/25） | `https://pypi.org/pypi/<name>/json` HTTP 响应体 | 被扫描（可能恶意）的 PyPI 包作者（注册表元数据） | 仅 200 状态码时解析（package_info.py:23）；每次远程扫描必经 |
| src-28/06（package_scanner.py:158/161） | 归档下载响应体（URL 取自 releases 元数据 `file["url"]`） | 恶意包作者（归档条目名/内容） | 无条件（download_compressed 直写盘后解压） |
| src-29/04（project_scanner.py:92） | `https://pypi.org/pypi/<dep>/json` 响应体 | 恶意依赖的作者（releases 键 = 版本串） | requirements.txt 声明的依赖存在时请求 |
| src-30（project_scanner.py:267） | raw.githubusercontent 远程 requirements.txt 响应体 | 被扫描 GitHub 仓库内容 | 200 时解析（:269） |
| src-07（project_scanner.py:232） | CLI `verify <path>` 所指 requirements.txt 文件内容 | 提供该文件的一方（PyVul 威胁模型下不可信） | 操作者有读权限的任意文件 |
| CLI 形参（cli.py:33 `path`、:63 `identifier`/`version`） | **未入标签**（见 §7 G1，不建模） | 操作者/调用方 | — |

sink-03 对应的读取本身是 CLI 常规授权使用（R1，candidate），其标签保留在模型中以服务威胁模型下的审核裁决。

## 3. 各危险 Sink 的真实文件操作与调用关系

| Sink | 真实操作 | 路径来源链（逐行核实） |
| --- | --- | --- |
| sink-16（unpack_archive arg1） | 解压落盘：`.tar.gz`→`tarfile.extractall`（无 filter）；`.zip` 系→`zipfile.extract`（规范化成员名） | `download_package(package_name)` → `zippath=os.path.join(directory, package_name+ext)`(:140) → `unzippedpath=zippath.removesuffix(ext)`(:141) → `download_compressed(url, zippath, unzippedpath)`(:143) → :163 |
| sink-02（open 'wb'） | 下载归档写入 | 同上 zippath 链，:160 |
| sink-15（unpack_archive arg0） | 从该路径读归档并解压 | 同上 zippath，:163 |
| sink-10（os.remove） | 删除归档文件 | 同上 zippath，:164 |
| sink-01（open 'w'） | package_info 元数据写入 | `_scan_remote(name, version)` → `suffix=f"{name}-{version}"`(:64) → `open(os.path.join(results["path"], f'package_info-{suffix}.json'), "w")`(:65)；`results["path"]`=`join(directory, name)`(:56)；门控 `write_package_info=True`（默认 False，CLI 不可达） |
| sink-08/09（invoke_semgrep arg1） | semgrep 读取目标目录内容并回报 | `scan_local(path)`/`_scan_remote` → `analyze(path)` → `analyze_sourcecode(path)` → `targetpath=Path(path)`(:149) → `invoke_semgrep(..., [targetpath], ...)`(:159/:170) |
| sink-03（open 'r'） | 读 requirements 文件 | CLI `verify(path)` → `scan_local(path)` → `open(path)`（project_scanner.py:231） |

## 4. 附加传播边（14 条）及其代码证据

所有边均为具体节点到具体节点（或单一 API 全量匹配 os.path.join），锚定真实 (file, line)：

| ID | 边 | 依据的标签 | 代码证据 |
| --- | --- | --- | --- |
| S1 | `os.path.join(...)` 任一实参 → 调用结果 | src-14/20/21/24/25 | package_scanner.py:55,56,65,140；analyzer.py:29,30,171；纯字符串拼接语义；python-all 无默认模型（非 str.join 方法） |
| S2 | `removesuffix` 接收者 → 结果 | src-25 | package_scanner.py:141；纯字符串截断，不在默认 str 方法污点表 |
| S3 | `x.append(v)` 实参 → x 的创建列表字面量节点 | src-26 | project_scanner.py:67→:57；:198/:201→:195；append 变异接收者列表 |
| S4 | `d[k]=v` 键/值 → d 的创建字典字面量节点 | src-26 | project_scanner.py:160→:98；python-all 仅为字面量构造提供存储步 |
| S5 | `dependencies.items()` 接收者 → 结果 | src-26 | project_scanner.py:196 |
| S6 | `pkg_resources.parse_requirements(req)` 实参 → 返回值 | src-26 | project_scanner.py:101；外部解析器无污点摘要 |
| S7 | `next(parsed)` 实参 → 返回值 | src-26 | project_scanner.py:104 |
| S8 | `data["releases"].keys()` 接收者 → 结果 | src-04/29 | project_scanner.py:93 |
| S9 | `sorted(iterable)` 实参 → 返回值 | src-04/29 | project_scanner.py:93 |
| S10 | `requirement.project_name` 对象 → 属性值 | src-26 | project_scanner.py:122,124,160；默认 attributeReadStep 仅按内容传播 |
| S11 | for 循环整体污点迭代：iterable → 目标 Name 元素 | src-26 | project_scanner.py:59（`for line in requirements`）、:196（`for dependency, versions in dependencies.items()`）；python-all 刻意不提供整对象污点→元素的读步 |
| S12 | `pool.starmap(f, params)` params 实参 → worker 内 `scan_remote(dependency, version)` 调用实参（:190） | src-26 | project_scanner.py:202-203→:190（经 functools.partial :193 包装的 get_package_results_helper :189-191）；进程边界对数据流不可见，两端均为真实节点 |
| S13 | `pathlib.Path(path)` 实参 → 结果 | src-09 | analyzer.py:149；仅锚定此站点（:159/:171 包装的是内部规则目录） |
| S14 | `resp.content` 对象 → 属性值 | src-30 | project_scanner.py:270；后续 `.decode().splitlines()` 由默认 str 方法步覆盖 |

依赖的默认模型（python-all 7.1.2 实测核对）：`+`/`%`（concatStep/stringManipulation）、f-string（Fstring）、下标读（subscriptStep）、列表/元组/字典字面量构造（containerStep）、`yield` 内容存储（yieldStoreStep，配 forReadStep 生成器读）、str 方法 decode/split/splitlines/strip/replace/format/join、跨过程实参→形参/返回→调用方。

**预期可达路径（Step 5 执行前的静态推演，非实测）**：
- src-07/src-30 →（S6,S7,S10,S4,S5,S11,S3,S12）→ `scan_remote(dependency, version)` → `_scan_remote` name → `join`（S1）→ zippath/unzippedpath →（S2）→ **sink-02 / sink-15 / sink-16 / sink-10**；
- src-04/src-29 →（S8,S9,S4,S5,S11,S3,S12）→ version → suffix（f-string）→（S1）→ **sink-01**（注意集合推导 `{v for v in available_versions}` 处迭代整对象污点不传播，见 §8 L4，version 链可能断于该处——sink-01 可能不可达，与其 candidate 定级一致）；
- src-27/src-03 影响 url 选择与版本默认值：url 不入路径（下载目标由 package_name 决定），info.version 默认路径下仅作字典键——不产生 sink 路径（与标签"src-27 为 zip-slip 起点内容源"的定性一致）；
- src-28/src-06（归档内容）与 sink-16 之间**无程序内数据流**（zip-slip 发生在归档语义内部），见 §8 L1。

## 5. 路径连接/解码/规范化、允许根目录与符号链接检查的证据

- **规范化**：全代码库（package_scanner.py / project_scanner.py / analyzer.py / cli.py / package_info.py / typosquatting.py 通读）无 `normpath`、`realpath`、`resolve`、`abspath+包含判断`、`basename`、`startswith` 根目录检查。analyzer.py:215/217 的 `abspath/relpath` 仅用于报告输出，在文件访问之后。typosquatting.py:55 的 `abspath` 只用于内部常量资源路径。
- **允许根目录**：**不存在**。`directory`（`join(dirname(__file__), base_dir)` 或 TemporaryDirectory）从未对 `name`/`package_name`/`version` 做包含性校验；`is_local_package`（cli.py:102，正则 `(.{0,2}\/)+.+`）仅分流本地/远程且只识别 `/`——Windows 下反斜杠分隔的 identifier 可直接进入 `scan_remote → join` 链（phase1_review R5）。
- **路径拼接**：`os.path.join(directory, name)`（:56）、`join(directory, package_name + file_extension)`（:140）无输入过滤；`pkg_resources` 名字文法禁止 `/`，requirements 名字路径受限，但 CLI 直传 identifier 不经解析。
- **URL 解码**：不适用——标签审查（Step 3 十项要点 4）未发现 URL 解码后入路径的代码；`resp.content.decode()` 是字节→文本解码（S14 之后默认步覆盖）。
- **符号链接**：代码库无任何 symlink 专项处理（无 lstat/lexists/链接拒绝）；唯一文档化拒绝 symlink 条目的是 tarsafe（标签 R2，人工复核中）。规范化/校验/使用时序上不存在"先规范化再校验"序列，故不存在时序失效问题——因为两者都不存在。
- **文件访问时机**：package_scanner.py:43 `os.path.exists` 检查与 :46/:49 使用之间存在经典 TOCTOU 窗口（证据记录，不构成屏障）。

## 6. Barrier 有效性分析

- **sink-11（tarsafe）**：对**归档条目名穿越**这一具体机制有效（tarsafe 0.0.4 文档化拒绝 `..`/绝对/符号链接成员名），且目的地为全新 TemporaryDirectory；对**目的地参数穿越**无关（该调用目的地是受控临时目录）；对**归档路径参数本身**（CLI identifier）无作用——但它阻断的是经包装链的传播。证据边界：tarsafe 源码不在 DB 内，判定依据为锁定版本（requirements.txt tarsafe==0.0.4）的公开文档用途，已标 candidate 待人工复核（R2）。当前标签集内无 source→sink 路径穿过这两个节点（CLI 形参未入 source，见 G1），屏障现为"虚设但不误伤"；若 G1 补齐后将成为 scan_local 路径链上的有效屏障。
- **其他候选屏障不成立的原因**（均未建模）：`os.path.exists/isdir` 仅类型分派；`removesuffix` 是截断非规范化（标签明确不视为 sanitizer）；`is_local_package` 仅路由。未把任何函数名机械视为过滤器。

## 7. 发现的标签遗漏（退回第五步复核项，未修改 labels.json）

- **G1（重要）**：CLI click 处理器形参（cli.py:33 `path`、cli.py:63 `identifier`/`version`）**不在 sources.csv/labels.json 中**（detection.json 的 `expected_sites` 曾列出该家族，但抽取 CSV 无 cli.py 行）。后果：标签 source 集合无法实现 phase1_review §7.10(b) 描述的"CLI identifier → join 链 → sink-02/10/15/16"流（Windows 反斜杠变体 R5 亦无法观测）。**建议退回第五步**：要么补充该 source 标签并重跑 Step 3 标注，要么在审核决定中明确记录"CLI 形参按授权使用排除（呼应 R1）"。本次未擅自加入模型。
- **G2**：src-26/09/30 的标签理由断言了中间跳变（pkg_resources 解析、next、容器操作、pathos starmap、functools.partial、pathlib.Path、resp.content）但未逐条列为 summary 标签。这些作为标签的**隐含内容**以证据锚定方式实现于 MySummaries（§4），未新增任何标签语义；如需逐条审计可退回第五步将其显式化为 summary 条目。
- **G3**：无遗漏的 sanitizer/summary 需要补——`none` 标签与源码事实一致。

## 8. CodeQL 局限、动态调用/别名遗漏与诊断路径（不计入正式告警）

| # | 局限 | 影响 | 缓解/诊断建议 |
| --- | --- | --- | --- |
| L1 | zip-slip 本质在归档语义内部（条目名→解压路径），程序内数据流不可见 | src-06/src-28 → sink-16 无数据流路径；主漏洞面不会以 source→sink 告警形式出现 | 以 sink-16 位置告警 + 人工判定（Step 6 过滤阶段结合 labels 的 sink-16 tp 定级）；诊断查询可用 `MySinks::isSink` 单独枚举全部 sink 站点 |
| L2 | `pool.starmap`/`functools.partial` 进程与包装边界不可见 | 无 S12 则依赖名/版本无法到达 scan_remote | 已用 S12 桥接（两端为具体真实节点）；诊断查询可单独验证该边 |
| L3 | API 图按语法解析 dotted 调用，别名导入不区分 | 本项目导入均为直接 import（detection.json 已核实），风险低 | — |
| L4 | 集合推导 `{v for v in available_versions}` 的整对象污点→元素不传播 | src-04/29 的 version 链可能断于 :132-148，sink-01 可能不可达 | 与 sink-01 candidate 定级一致；诊断查询可加一条推导迭代边验证（非正式） |
| L5 | `f.write(response.raw.read())` 的文件内容→解压路径无模型 | 同 L1 | 同 L1 |
| L6 | 动态接收者（`Attribute()` 模块提示）依赖 MethodCallNode 方法名匹配 | `.extractall`/`.json` 等按方法名+位置匹配，本代码库唯一 | 位置约束兜底 |
| L7 | invoke_semgrep 为 semgrep 内部 API，arg 语义由调用点推断 | sink-08/09 arg1 语义依赖人工判断 | 已在标签/注释记录（R 级：candidate） |

**诊断查询建议**（放 `iris/diagnostics/`，不计入正式 Pass 1 告警，本次按"只生成六个文件"未创建）：(a) 逐一枚举 `MySources::isSource`/`MySinks::isSink` 命中节点，核对与 labels 位置一致；(b) 用 `Pass1Flow::partialFlow` 小深度探查每个 source 的可达范围，验证 S1–S14 是否生效；(c) 探索性 source（cli.py CLI 形参）单独跑一遍观察 R5/G1 流（仅诊断）。

## 9. QL API 核验清单（对照本地安装库源码，非凭记忆）

- `codeql/dataflow 2.1.7` `DataFlow.qll:401` `signature module ConfigSig`（isSource/isSink/isBarrier/isAdditionalFlowStep 默认 none()）；`:1122` `module Global<ConfigSig>`；`GlobalFlowSig`（`PathNode`/`flowPath`/`PathGraph`）；`TaintTracking.qll:167/313` `TaintTracking::Global<ConfigSig>`。
- `python-all 7.1.2` `internal/DataFlowPublic.qll`：`Node.asExpr()`、`CallCfgNode.getArg(int)/getFunction()`、`MethodCallNode.getMethodName()/getObject()`、`exprNode(Expr)`；`internal/TaintTrackingPrivate.qll`：concatStep（`+`）、`%`/Fstring/str 方法表（decode/split/splitlines/strip/replace/format/join）、subscriptStep、containerStep（字面量/yield）；`internal/DataFlowPrivate.qll`：forReadStep/attributeReadStep 为**内容**步（确认整对象污点不传元素，故需 S11）。
- `semmle/python/ApiGraphs.qll`：`API::moduleImport/getMember/getReturn/getACall/getParameter/asSink/asSource`；`API::builtin`（Stdlib.qll:1565 同款用法）。
- AST（`import python`）：`Assign.getATarget/getValue`、`Subscript.getObject/getIndex`、`For.getTarget/getIter`、`Attribute.getName/getObject`、`Tuple.getAnElt`、`Name.getId/getVariable`、`Dict/List`、`Expr.getLocation`、`Location.getFile/getStartLine`、`File.getBaseName`。
- 库内同类惯用法参照：`Stdlib.qll` OsOpenCall（`this = os().getMember("open").getACall()` 绑定 CallCfgNode）、`UnsafeShellCommandConstructionCustomizations.qll`（`getArg(_)`、`asExpr().(List)` 链式转型）。

## 10. 实验独立性

- 未读取 PyVul 真值、已知 CVE 行号、修复补丁及仓库根部 ground-truth 报告；未修改源码、CodeQL 数据库、Augur 发布文件与 Phase 1 标签/CSV。
- 本报告与全部 QL 仅由 `labels.json`、真实源码（cli.py、package_scanner.py、project_scanner.py、analyzer.py、typosquatting.py、package_info.py 全文通读）与本地安装的 CodeQL 库源码推导。
- 编译已验证通过（§11a）；污点分析未执行（按指令）；无任何编造的运行结果，§4 的可达性为静态推演并已标注。

## 11. 下一步（Step 5 执行清单）

1. ~~`codeql query compile` 验证四库与查询可编译~~ **已完成**（见 §11a）。
2. 顺序执行：`codeql database analyze guarddog-db iris/queries/Pass1_PathTraversal.ql --format=sarifv2.1.0 --output=iris/results/pass1.sarif`（单 pass，无并行）。
3. 结果过滤用 `filter_and_report.py`，FP 启发式按 WORKFLOW 5.3.2（本 pass 重点：sink-03 CLI 授权使用 R1、tarsafe R2、无根目录限制的 join 链不适用 startswith FP 规则）。

## 11a. 编译验证记录（2026-10-22 修复）

首次 `codeql query compile` 报错，根因与修复：

- **根因**：`from` 是 QL 的保留关键字（查询头 `from … select …` 语法），不能用作谓词参数名。解析器在 `MySummaries.qll:58` 的 `DataFlow::Node from` 处报 `unexpected input 'from' expecting one of: Lowerid`，错误恢复将谓词声明误解析为查询头，级联产生约 30 条 "select clause select conflicts" 二级错误（均指向 `MySummaries.qll` 各 `from =/to =` 绑定行）。
- **修复**：将 `MySummaries.qll` 全部 15 个谓词的参数 `from`/`to` 机械重命名为 `nodeFrom`/`nodeTo`（与 Augur `taint_query.ql.tmpl` 中 `isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo)` 的命名一致），语义零变更。
- **验证**：重命名后重新编译通过（`Done [1/1 comp 15.3s]`），`MySources.qll`、`MySinks.qll`、`MySanitizers.qll` 无错误（它们本就未使用 `from` 作标识符）。
- 附带确认：`joinCall.getArg(_)`（S1）与 `call.getFunction().asExpr().(Name)`（sink-08/09）等函数调用形式均通过编译。
- 污点分析（database analyze）仍未执行，本步骤到此为止。
