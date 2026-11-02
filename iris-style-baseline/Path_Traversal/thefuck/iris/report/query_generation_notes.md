# Pass 1 Path Traversal 污点模型与查询生成说明 (Phase 2 Step 4–5)

- 项目: thefuck 3.30（`thefuck_vuln` 源码树，CodeQL 数据库 `thefuck-db`，创建 sha 6da0bc55）
- Pass: 1（CWE-022 / CWE-023 / CWE-036 / CWE-073，Path Traversal）
- 依据标签: `iris/labels/labels.json`（run `iris-thefuck-pass1-step3-20261023`，模型 glm-5.3，531 entries）
- 本步生成文件: `libraries/MySources.qll`、`libraries/MySinks.qll`、`libraries/MySanitizers.qll`、`libraries/MySummaries.qll`、`queries/Pass1_PathTraversal.ql`、本说明
- 模板: `augur-0.3.0/assets/taint_query.ql.tmpl`（占位符全部替换：`{{QUERY_ID}}`=`py/augur/thefuck/pass1-path-traversal`、`{{CONFIG_NAME}}`=`Pass1Config`、`{{FLOW_MODULE}}`=`Pass1Flow`、`{{PASS_KEY}}`=`path_traversal`、`{{PRECISION}}`=`medium`、CWE 标签 022/023/036/073）
- 生成时未编译；用户随后运行 `codeql query compile --check-only` 暴露一个语法错误并已修复（见 §7a），修复后 check-only 编译通过。正式的 Step 5 分析执行仍在后续轮次。

## 0. 输入与人工审核门状态

- `labels/labels.json` 与 `labels/phase1_review.md`（checkpoint 摘要）已读取，作为已审核标签契约。
- `labels/review_decision.json` **不存在**（Phase 1 Step 3 按任务契约在输出四个文件后停止，未写该可选审计件；WORKFLOW.md §4.5 说明它是可选工件）。本轮以用户指令（执行 Phase 2 Step 4–5）作为人工审核门的放行信号，`phase1_review.md` 的结论与候选项清单作为审核依据。**未发现需要退回 Phase 1 重新审核的标签遗漏或错误**，`labels.json` 未做任何修改（见 §6 的两条已核实局限，均不构成标签缺陷）。
- 源码核对：本轮重读了 `types.py`、`corrector.py`、`conf.py`、`entrypoints/{main,fix_command,shell_logger,not_configured}.py`、`shells/{generic,bash,zsh,tcsh,fish}.py`、`output_readers/{read_log,shell_logger}.py`、`utils.py` 及涉规则模块（Phase 1 已全部读过，本轮针对建模细节复核）。

## 1. 标签 → QLL 谓词渲染契约

渲染规则（对 531 个 entry 的全量处置）：

| 标签角色/判定 | 数量 | 处置 |
| --- | --- | --- |
| source / tp + candidate | 24（3 tp + 21 candidate） | 渲染进 `MySources.qll` |
| sink / tp + candidate | 17（4 tp + 13 candidate） | 渲染进 `MySinks.qll` |
| summary / tp | 3 | 渲染进 `MySummaries.qll` |
| sanitizer | 0 | `MySanitizers.qll` 谓词体为 `none()`（见 §5） |
| source / fp（13 个） | 13 | 不渲染（见下） |
| sink / fp（6 个） | 6 | 不渲染（见下） |
| none / fp | 466 | 不渲染（Phase 1 已判定与本 pass 无关） |

不渲染的 13 个 `source/fp`：`cat_dir.py:9`、`cd_correction.py:39`、`chmod_x.py:8/:9`、`dirty_unzip.py:10`（namelist 仅 len 检查）、`git_add.py:12`、`gradle_wrapper.py:7`、`grep_arguments_order.py:14/:18/:19`、`has_exists_script.py:7`、`ln_s_order.py:17/:22`、`prove_recursively.py:21`（另 `path_from_history.py:18`）——这些 `command.*` 读取在 pass 1 只到达 stat-only 探测（isfile/isdir/exists/access）或仅做字符串匹配，标签本身已记录 fp 依据；渲染它们只会向 `MySources` 注入已判定为误报的源。candidate（env/CLI 34 项）按 IRIS 的保守召回设计全部渲染，交由 Phase 2 Step 6 的上下文triage 做信任裁决。

不渲染的 6 个 `sink/fp`：`fish.py:124`（固定字面量 fish 历史文件 append）、`not_configured.py:42/:62`（tempdir 固定名 tracker）、`not_configured.py:78/:85`（操作者自有字面量 shell 配置文件）、`utils.py:221`（固定文件名 `thefuck` 缓存删除）——路径非攻击者可控，标签已判 fp。

**定位策略**：所有谓词用 `(enclosing module name, 调用/属性形态, 字面量键)` 定位标签站点，不用行号（避免换 commit 漂移；本项目 module 名唯一，每个模块内匹配形态唯一，已逐一核对）。仅当同一名称在同模块出现于已判 `none` 的站点时，用 `inFunction(...)`（如 `side_effect`）排除：`dirty_unzip.py:10` vs `:47`、`dirty_untar.py:32/:36` vs `:42`、`ssh_known_hosts.py:20` vs `:31`。

## 2. Source 标签 → `MySources::isSource` 映射（外部输入边界与权限/访问条件）

统一 pass key `"path_traversal"`；`isSource(node, passKey)` 内 `passKey = "path_traversal"` 门控。每条子谓词注释均标注标签 ID。

| 标签 ID | 位置 | QLL 子谓词 | 外部输入边界 | 权限/访问条件 |
| --- | --- | --- | --- | --- |
| p1-083 (tp) | dirty_untar.py:43 `getnames()` | `archiveEntryNameSource` | tar 归档条目名；归档由失败命令 argv 指定，内容全攻击者可控（恶意归档置于 CWD 即可） | 无任何校验；相对 CWD 解释 |
| p1-086 (tp) | dirty_unzip.py:47 `namelist()`（限 `side_effect`） | `archiveEntryNameSource` | zip 条目名，同上 | 同上；目录仅靠 OSError 静默跳过 |
| p1-352 (tp) | ssh_known_hosts.py:31 `old_cmd.output`（限 `side_effect`） | `commandOutputSource` | 失败命令的终端输出（本工具的核心不可信载荷通道：命令打印远程/文件内容即受攻击者影响） | 无校验；正则 `([^:]+)` 接受绝对路径 |
| p1-113/p1-114 (candidate) | fix_file.py:60/:66 `command.output` | `commandOutputSource` | 同上（输出正则提取 file 名） | pass 1 仅达 `os.path.isfile`（stat-only），主风险在 pass 2 编辑器命令串 |
| p1-082 (candidate) | dirty_untar.py:42 `old_cmd.script_parts`（限 `side_effect`） | `commandScriptPartsSource` | 失败命令 argv → 归档路径选择 | 用户自选归档，条目内容才是载荷（authorized-by-use → candidate） |
| p1-085 (candidate) | dirty_unzip.py:20 `command.script_parts` | `commandScriptPartsSource` | 同上（`.zip` 路径） | 同上 |
| p1-070 (candidate) | conf.py:46 `os.environ.get('XDG_CONFIG_HOME')` | `envPathSource` | 进程环境（交互式 CLI 的本地用户信任级） | 用户自己的 shell 环境；典型单用户模型下 triage 为 fp |
| p1-021/p1-362/p1-410 (candidate) | bash.py:69 / tcsh.py:29 / zsh.py:74 `HISTFILE` | `envPathSource` | 进程环境（用户 shell 导出） | 同上；key 以 `StringLiteral.getText()` 字面匹配，排除同模块 `TF_SHELL_ALIASES` 等 none 读取 |
| p1-109/p1-111 (candidate) | fix_command.py:16/:19 `TF_HISTORY` | `envPathSource` | 别名导出的 shell 历史尾部 → 成为失败命令 script | 同上 |
| p1-337/p1-339 (candidate) | read_log.py:65/:93 `THEFUCK_OUTPUT_LOG`（Subscript） | `envPathSource` | 进程环境（thefuck 自己生成的日志路径） | 同上；`PS1` 读取（none）不匹配 |
| p1-390 (candidate) | utils.py:228 `os.getenv('XDG_CACHE_HOME')` | `envPathSource` | 进程环境 | 同上 |
| p1-014 (candidate) | argument_parser.py:86 `parse_args(arguments)` | `cliSource` | argparse CLI 边界（`main.py:18 parser.parse(sys.argv)`，console_script 入口） | 本地用户 argv；`--shell-logger/-l` 值直达 `os.open(O_CREAT|O_TRUNC)` |
| p1-258/p1-259/p1-260 (candidate) | main.py:30/:32/:38 `known_args.command`/`.shell_logger` | `cliSource` | 同上 | 同上（:38 是 -l 值传递点） |
| p1-107/p1-108/p1-110 (candidate) | fix_command.py:14/:15/:17 `force_command`/`command` | `cliSource` | 失败命令 argv 词 | 同上；`help/version/alias` 布尔旗标（none）名称不匹配 |
| p1-349 (candidate) | entrypoints/shell_logger.py:64 `output` 参数 | `cliEntryParameterSource`（`DataFlow::parameterNode`） | 外部可达 entrypoint 形参（`main.py:38` 以 CLI 值调用） | 本地用户 CLI 值 → `:74 os.open(O_CREAT|O_TRUNC|O_RDWR)` |

明确排除：内部包装器形参一律不作 source（`Settings.init(args)` 仅布尔、`get_loaded_rules(rules_paths)`、`Rule.from_path(path)`、`Cache._get_mtime(path)`、`fix_command(known_args)` 均为标签判 `none`；`shell_logger(output)` 是唯一例外，因其为外部入口形参且标签为 candidate）。

## 3. Sink 标签 → `MySinks::isSink` 映射（文件操作、危险参数索引、访问类型、调用关系）

sink 节点一律取**路径文本**（实参表达式或成员调用的 receiver），绝不取返回的文件/归档对象：

| 标签 ID | 位置 | QLL 子谓词 | 危险参数索引 | 访问类型与调用关系 |
| --- | --- | --- | --- | --- |
| p1-454 (tp) | dirty_untar.py:45 `os.remove(file)` | `osRemoveSink` | arg 0 | 删除；`side_effect` 内 `for file in archive.getnames(): os.remove(file)`，源 p1-083 直达，`..`/绝对路径/分隔符变体原样通过 |
| p1-458 (tp) | dirty_unzip.py:49 `os.remove(file)` | `osRemoveSink` | arg 0 | 删除；同上，源 p1-086 |
| p1-501 (tp) | ssh_known_hosts.py:33 `open(filepath, 'r')` | `builtinOpenSink` | arg 0 | 读；filepath 来自 `old_cmd.output` 正则捕获（源 p1-352）——任意文件读 |
| p1-502 (tp) | ssh_known_hosts.py:36 `open(filepath, 'w')` | `builtinOpenSink` | arg 0 | 写/改写；删行重写同一路径——任意文件修改；:33 的读为 :36 供行内容 |
| p1-498 (candidate) | entrypoints/shell_logger.py:74 `os.open(output, O_CREAT|O_TRUNC|O_RDWR)` | `osOpenSink` | arg 0 | 创建/截断；CLI `-l` 值（源 p1-260/p1-349） |
| p1-495 (candidate) | output_readers/read_log.py:93 `os.open(..., O_RDONLY)` | `osOpenSink` | arg 0 | 只读；`THEFUCK_OUTPUT_LOG`（源 p1-337/p1-339） |
| p1-465 (candidate) | shells/generic.py:60 `io.open(history_file_name, 'r')` | `ioOpenSink` | arg 0 | 只读；HISTFILE env（源 p1-021/p1-362/p1-410）；前置 `:59 isfile` 仅为可用性探测（TOCTOU 形态，见 §4） |
| p1-435 (candidate) | conf.py:39 `settings_path.open(mode='w')` | `pathlibOpenSink` | receiver（标签 arg_index=-1） | 创建/覆盖写；`user_dir.joinpath('settings.py')`，XDG_CONFIG_HOME（源 p1-070） |
| p1-443 (candidate) | conf.py:64 `rules_dir.mkdir(parents=True)` | `pathlibMkdirSink` | receiver | 目录创建；XDG 派生（源 p1-070） |
| p1-444 (candidate) | conf.py:69 `imp.load_source('settings', <path>)` | `loadSourceSink` | arg 1 | 代码/资源加载（patterns.md pass-1 "resource loader" 族）；XDG 派生（源 p1-070） |
| p1-504 (candidate) | types.py:144 `imp.load_source(name, str(path))` | `loadSourceSink` | arg 1 | 同上；glob 目录（bundled/XDG 用户 rules/sys.path `thefuck_contrib_*`，corrector.py:29-35） |
| p1-453 (candidate) | dirty_untar.py:42 `tarfile.TarFile(<path>)` | `archiveOpenSink` | arg 0 | 归档打开；argv 派生路径（源 p1-082），条目内容驱动 p1-454 |
| p1-455/p1-457 (candidate) | dirty_unzip.py:9/:46 `zipfile.ZipFile(<path>, 'r')` | `archiveOpenSink` | arg 0 | 同上（源 p1-085 → p1-458） |
| p1-514/p1-516 (candidate) | utils.py:217/:222 `shelve.open(cache_path)` | `shelveOpenSink` | arg 0 | dbm 缓存打开/创建；XDG_CACHE_HOME 派生（源 p1-390） |
| p1-518 (candidate) | utils.py:233 `os.makedirs(cache_dir)` | `osMakedirsSink` | arg 0 | 目录创建；XDG_CACHE_HOME（源 p1-390） |

## 4. 路径构造/解码/规范化、允许根目录、符号链接证据

- **路径连接/拼接**（真实代码，全部只作传播，不作 sink）：`conf.py:37/62/70 joinpath`、`corrector.py:29-35 joinpath`（含 `sys.path` glob）、`bash.py:46/:76/:78` 与 `zsh.py:51` `os.path.join`（tempdir+字面量/uuid）、`utils.py:66 join`（PATH 遍历）。`dirty_untar._tar_file`/`dirty_unzip._zip_file`/`brew_*` 的 `+` 拼接在 Phase 1 已记录；CodeQL 本地流原生传播字符串拼接。
- **URL 解码**：不存在（无 web 面）——多次解码/解码次序问题不适用。
- **规范化**：`expanduser`（bash/zsh/tcsh/fish/conf/utils/not_configured/generic，及 system/unix.py:53、system/win32.py:39 的 Path monkey-patch）只做 `~` 展开无验证；`utils.py:255 absolute()/as_posix()` 只做缓存键规范化；`os.path.split`（utils.py:59、cd_correction.py:54）做 cwd 步进。全库无 `normpath/realpath/relative_to`。
- **允许根目录**：**不存在任何受限根**。p1-454/p1-458/p1-501/p1-502 的路径参数无 base 包含检查、无白名单、无固定文件名映射（tp 为"任意路径"而非"越界基目录"型）；`workon_doesnt_exists.py:8` 的 `~/.virtualenvs` 字面根只服务其自身 iterdir（none）。
- **符号链接**：全库无 symlink 创建/readlink/跟随策略（Phase 1 guardAndTraversalEvidence 已核实，本轮维持结论）；TOCTOU 形态存在于 `generic.py:59→:60`、`conf.py:38→:39`、`not_configured.py:58→:62`，但均为 env/字面量来源且本地信任，未据此建 barrier 或 tp。
- **`..`/绝对路径/分隔符变体**：dirty_untar.py:43-49 与 dirty_unzip.py:47-53 的条目名原样进入 `os.remove`（无 `..` 拒绝、无分隔符改写、绝对名原样）；ssh 正则 `([^:]+)` 接受绝对路径。

## 5. Barrier 审查结论（每个候选过滤的真实阻断力）

`MySanitizers::isBarrier` 为 `none()`。逐个候选的否定证据（详见 MySanitizers.qll 文件头注释）：

1. 无任何 sink 前存在包含性检查（无 `startswith(base)`/realpath 包含/`relative_to`/固定名映射/白名单）→ 无可建 barrier。
2. `expanduser` 系：扩展 `~`，不校验 `..`/绝对路径 → 非过滤器。
3. `os.path.split`：cwd 步进/名字分离，非 basename 净化 → 非过滤器。
4. `cd_correction.py:56 get_close_matches(cutoff=0.6)`：把自身 listdir 实参约束到真实子目录名，属于隐式限制而非规范化/包含守卫，且不在任何已渲染 source→sink 路径上（其数据源 `command.script_parts` 该读取点为 fp/未渲染）→ 不建模。
5. `generic.py:59`/`conf.py:38`/`not_configured.py:58` 的 stat 前置：可用性探测（check-then-use），不授权、不阻断 → 不建模。
6. 无 URL 解码、无符号链接处理 → 相关 barrier 不适用。

结论：不把 normpath/resolve/basename/前缀判断机械当 sanitizer——本项目中它们根本不存在，存在的包装器（expanduser/split）经源码核实无阻断力。

## 6. 额外传播边、动态调用遗漏与 CodeQL 局限

**已建的 3 条额外边（`MySummaries::isAdditionalTaintStep`，均为标签审核过的 summary/tp）**：

| 标签 ID | 边 | 必要性证据 |
| --- | --- | --- |
| p1-379 | `from_raw_script` 的 `raw_script` 形参 → `Command.__init__` 的 `script` 形参 | `types.py:81 shell.from_shell(script)` 经 `shells/__init__.py` 按 `TF_SHELL` env 在 import 时动态选择 shell 类，静态不可解析；`types.py:77-83` 证明 raw 词→Command script 的真实链路 |
| p1-377 | `__init__` 的 `script` 形参 → `thefuck.rules.*` 内 `command/old_cmd/cmd` 上的 `.script`/`.script_parts` 属性读取 | `types.py:23 self.script = script`、`:37-46 script_parts` 属性；规则模块经 `imp.load_source`（types.py:144）加载并经 `:181/:193/:255` 动态调用（`self.match(command)` 等），CodeQL 无法解析被调函数 |
| p1-378 | `__init__` 的 `output` 形参 → 规则内 `.output` 属性读取 | `types.py:24 self.output = output`，同一动态调用缺口 |

两端均为具体节点（函数形参 / 受限对象名的属性读取），未创建任意节点到任意节点的传播。

**无需自建边（已由本地库核实覆盖）**：

- `re` 结果传播：`ssh_known_hosts.py:28-31` 的 `offending_pattern.findall(old_cmd.output)`（编译后 Pattern 方法）——python-all 7.1.2 `semmle/python/frameworks/Stdlib.qll`（"re" 摘要，行 3107/3344/3377-3381：findall/finditer/split 的结果从被匹配字符串感染）已建模，p1-352→p1-501/p1-502 路径可原生传播。
- for-迭代与元组解包：`for file in archive.getnames()`、`for filepath, lineno in offending` —— 新 dataflow 的本地流步骤（`internal/IterableUnpacking.qll` 等）覆盖。
- `os.remove`/`open` 等 stdlib 调用的参数即污点终点（sink 就在实参节点），无需 sink 侧 summary。

**已知局限（不构成标签缺陷，不需退回第五步重审）**：

1. `cls(expanded, output)`（types.py:83）到 `__init__` 的调用边是否被 CodeQL 解析未验证；即便不解析，p1-379 已把 `raw_script` 形参直接连到 `__init__` 的 `script` 形参，链路闭合。
2. 规则侧动态调用缺口由 p1-377/p1-378 的字段 store→load 边补偿，但规则函数 `match(command)`/`get_new_command(command)` 的 `command` 形参本身未建边——本项目不需要（规则侧读取点已直接是 source），若未来 pass 需要从规则形参出发的流，须先回 Phase 1 补标签。
3. `shells/__init__.py` 的动态 shell 选择影响所有 `shell.*` 调用（split_command/from_shell/get_history/put_to_history）；对 pass 1 的影响仅 `from_shell`（已由 p1-379 覆盖）与 `generic.py:60` 历史读（receiver 为具体变量，不受影响）。
4. 污点模型为标签站点定位（module 名+形态），非 API 图级别解析（项目内 `os`/`os.path`/`tarfile`/`zipfile`/`imp`/`shelve` 均为 bare-name import，API 图无法绑定 stdlib 成员；与 Phase 1 extraction 的 matchKind=ast 结论一致）。

**诊断路径**：本轮未生成 diagnostics 查询（生成期无需调试包装器）。若 Step 5 编译/运行期需调试谓词匹配（例如核对某 module 名或形态匹配是否命中），应写入 `iris/diagnostics/`（目录已存在）单独运行——其结果不计入正式 Pass 1 告警。

## 7. 结构契约与已核实的 API 基础

- `qlpack.yml` 位于 `iris/` 根（已存在，name `iris/thefuck-cwe22`，依赖 `codeql/python-all: "*"`，未改动）；四个库位于 `iris/libraries/`，主查询 `iris/queries/Pass1_PathTraversal.ql`，通过 `import libraries.MySources` 等点号语法引用（pack 根相对路径），四个谓词接口均存在且签名一致：`MySources::isSource(node, passKey)`、`MySinks::isSink(node, passKey)`、`MySanitizers::isBarrier(node, passKey)`、`MySummaries::isAdditionalTaintStep(from, to, passKey)`，统一 pass key `"path_traversal"`。
- 查询骨架完全按 `assets/taint_query.ql.tmpl`：`module Pass1Config implements DataFlow::ConfigSig`（四谓词）→ `module Pass1Flow = TaintTracking::Global<Pass1Config>;` → `import Pass1Flow::PathGraph` → `from Pass1Flow::PathNode source, Pass1Flow::PathNode sink where Pass1Flow::flowPath(source, sink) select sink.getNode(), source, sink, "..."`。
- API 均在本机库核实（python-all 7.1.2 + codeql/dataflow 2.1.6，CodeQL CLI 2.25.1）：`DataFlow::Node`/`exprNode(Expr)`（internal/DataFlowPublic.qll:303，`DataFlowExpr = Expr`）/`parameterNode(Parameter)`（:350）；共享 `ConfigSig`（isSource/isSink/isBarrier/isAdditionalFlowStep，后两者 default `none()`）与 `GlobalFlowSig`（`class PathNode`+`Node getNode()`+`flowPath`+`module PathGraph`）；`Attribute.getName()/getObject()`（Exprs.qll:67-）、`Call.getFunc()/getArg(int)`（Exprs.qll:156）、`Subscript.getObject()/getIndex()`、`Name.getId()`、`Function.getArgByName(string)`（Function.qll:65）、`StringLiteral.getText()`（Exprs.qll:557，无引号值）、`Scope.getEnclosingModule()`（Scope.qll:25，"Modules, Classes and Functions are all Scopes"）。避开了全部已知坑：无 `module` 变量名、无 `AstNode.getFile()`、无 `API::Node`/`DataFlow::Node` 混用、`isBarrier` 显式保留。
- `@precision medium` 的依据：source/sink 全部锚定到审核过的具体站点（结构性高精度），但含 21 个本地信任 candidate 源与 3 条启发式字段边（receiver 变量名约定 `command/old_cmd/cmd`、`thefuck.rules.%` 模块前缀），Step 6 triage 前的原始告警量会包含预期内的候选路径。

## 7a. 编译校验记录（用户触发的 check-only 编译）

- 首次 `codeql query compile --check-only queries/Pass1_PathTraversal.ql`（CodeQL 2.25.1）在 `MySummaries.qll` 报出大量语法/解析错误。**根因**：附加传播边谓词的参数命名为 `from`，而 `from` 是 QL 保留关键字（from/where/select 查询子句），解析器将其当作查询子句开头，其余错误（"library modules cannot contain query clauses"、"select clause conflicts"、"predicate requires a body"）均为级联伪错。`MySources.qll`、`MySinks.qll`、`MySanitizers.qll` 零错误，证明其中全部 API 用法（`DataFlow::exprNode`、`getScope().getEnclosingModule().getName()`、`getScope().(Function)`、`StringLiteral.getText()`、`in [...]` 集合成员判断等）正确。
- 修复：仅重命名 `MySummaries.qll` 的参数 `from`/`to` → `nodeFrom`/`nodeTo`（与模板 `isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo)` 的命名约定一致），语义零改动，标签映射不变。
- 修复后本机复跑 `codeql query compile --check-only`：**通过，无错误无警告**。此次为纯编译检查（无数据库、无 SARIF 输出），不属于 Step 5 的正式分析执行。

## 8. 实验独立性原则

与前序各轮（Phase 1 Step 1–3 及本系列其他项目）一致：未读取 PyVul 真值（THEFUCK-CVE-REPORT.md 等仓库根文件、`path_traversal_sinks.csv`）、未读取已知 CVE 行号、未读取修复补丁；模型只由已审核标签、真实源码与本地 Augur/CodeQL 库推导。本轮未修改源码树、`thefuck-db` 数据库、Augur 安装、Phase 1 原始 CSV 与 `labels.json`；新写入仅上述 6 个文件。读取 `.codeql/packages` 下的 pack 源码仅为核实 API 存在性（与 Phase 1 Step 1 的约束遵守方式相同）。

## 9. 下一步（Step 5 执行计划，本轮不执行）

1. `cd iris && codeql pack install`（依赖已在本地 pack 缓存：python-all 7.1.1/7.1.2）。
2. 先 `codeql query compile` 编译 `queries/Pass1_PathTraversal.ql`（含四库）验证；若谓词形态与行号/module 断言有出入，修正**库文件**（不动标签），必要时写 diagnostics 查询核对。
3. `codeql database analyze "…/thefuck-db" iris/queries/Pass1_PathTraversal.ql --format=sarifv2.1.0 --output=iris/results/pass1.sarif`（单查询串行），随后按 Step 6 过滤与 `labels.json` 对照 triage（candidate 源的单用户信任裁决、fp 源/汇的排除复核）。
