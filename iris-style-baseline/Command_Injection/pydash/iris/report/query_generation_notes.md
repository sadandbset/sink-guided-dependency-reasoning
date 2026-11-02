# Query Generation Notes — Pass 2 (CWE-78) / Phase 2 Step 4–5

生成时间:2026-10-16 · 项目:pydash 5.1.2 · 工具链:CodeQL CLI 2.25.1 + codeql/python-all 7.1.2(自 `~/.codeql/packages` 缓存解析)、共享数据流框架 codeql/dataflow 2.1.7
输入:`iris/labels/labels.json`(Pass 2,run_id `pydash-pass2-cwe78-labeling-20261016`,经人工审核门 `labels/phase1_review.md`)
验证:全部 5 个生成文件 + 1 个诊断查询通过 `codeql query compile` 编译验证(仅编译,未对数据库执行任何分析)。

## 1. 产出文件

| 文件 | 内容 |
| --- | --- |
| `libraries/MySources.qll` | `module MySources { predicate isSource(DataFlow::Node, string passKey) }`,渲染 4 条 source 标签 |
| `libraries/MySinks.qll` | `module MySinks { predicate isSink(DataFlow::Node, string passKey) }`,渲染 14 条 sink 标签(单签名) |
| `libraries/MySanitizers.qll` | `module MySanitizers { predicate isBarrier(DataFlow::Node, string passKey) }`,解析为 `none()` |
| `libraries/MySummaries.qll` | `module MySummaries { predicate isAdditionalTaintStep(DataFlow::Node, DataFlow::Node, string passKey) }`,解析为 `none()` |
| `queries/Pass2_CommandInjection.ql` | 正式路径查询(`@kind path-problem`、`@problem.severity error`、id `py/augur/pydash/pass2-command-injection`) |
| `diagnostics/TaskParamToInvokeRunDiagnostic.ql` | 独立诊断查询(**不计入正式结果**) |

查询结构(与 augur `assets/taint_query.ql.tmpl` 一致):`module Pass2Config implements DataFlow::ConfigSig` 四谓词分别委托 `MySources::isSource` / `MySinks::isSink` / `MySanitizers::isBarrier` / `MySummaries::isAdditionalTaintStep`(passKey 均为 `"command_injection"`);`module Pass2Flow = TaintTracking::Global<Pass2Config>; import Pass2Flow::PathGraph;` 主体 `from Pass2Flow::PathNode source, sink where Pass2Flow::flowPath(source, sink) select sink.getNode(), source, sink, "…"`。导入采用点号语法 `import libraries.MySources` 等,库中模块名与调用点谓词签名逐一匹配。

## 2. 标签 ID ↔ CodeQL 谓词对应关系

### Sources(MySources.qll)

| 标签 ID | 谓词实现 | 匹配逻辑 |
| --- | --- | --- |
| P2-S-401(`test`,param,idx 1,conf 0.90) | `InvokeTaskParameterSource` + `labeledTaskParameter` | tasks.py 模块级 `@task` 函数 `test` 的第 1 个参数 `args`,经 `DataFlow::parameterNode(p)` 取节点 |
| P2-S-405(`docs`,param,idx 2,conf 0.85) | 同上 | `@task` 函数 `docs` 第 2 个参数 `bind` |
| P2-S-406(`docs`,param,idx 3,conf 0.80) | 同上 | `@task` 函数 `docs` 第 3 个参数 `port` |
| P2-S-390(`os.getenv`,return,conf 0.75) | `OsGetenvCallResult` + `isOsGetenvCall` | `os.getenv(...)`(`import os` 属性形式与 `from os import getenv` 名称形式)调用表达式节点,即返回值 |

其余 405 条 source 候选(role=none)按标签判定**不渲染**:`ctx`×13、`quiet`×2、`serve`、387 个 pydash 库 API、`os.environ.get('READTHEDOCS')`、Sphinx `setup(app)`。

### Sinks(MySinks.qll)

| 标签 ID | 谓词实现 | 匹配逻辑 |
| --- | --- | --- |
| P2-K-001 … P2-K-014(`invoke.run`,argument,idx 0) | `InvokeRunShellCommandSink` + `InvokeRunCall` | `InvokeRunCall` 匹配三种形态的 invoke.run 调用;sink 节点 = `this.asExpr() = c.getArg(0)`(第 0 个位置参数 = shell 命令字符串) |

14 条标签共享同一签名(`package=invoke, callable=run, arg_index=0`),按 WORKFLOW 5.1.4 去重为单一谓词臂;各调用点的置信度差异(0.95:污点可达的 L107/L134;0.85–0.90:常量命令)保留在 labels.json,不影响 QL 匹配语义。

### Sanitizers / Summaries

| 类别 | 标签数 | 谓词行为 |
| --- | --- | --- |
| sanitizer | 0 | `isBarrier` → `none()`(WORKFLOW 规则:barrier 挂钩必须存在,可为空) |
| summary | 0 | `isAdditionalTaintStep` → `none()`(同上;不创建无条件污点传播) |

## 3. 每个有效 Source 的源码依据与可控性

| 标签 | 源码证据 | 参数索引与可控性 |
| --- | --- | --- |
| P2-S-401 | `tasks.py:99` `def test(ctx, args=f"{TEST_TARGETS} --cov={PACKAGE_NAME}")` → `tasks.py:107` `run(f"pytest {args}")`;`tasks.py:98` `@task(help={"args": "Override default pytest arguments"})` | idx 1(0 为 `ctx`)。默认值为模块常量,但 `inv test --args "…"` 可整体覆盖,CLI 字符串参数无任何校验/引用/白名单,直接进入 shell 命令字符串 |
| P2-S-405 | `tasks.py:127` `def docs(ctx, serve=False, bind="127.0.0.1", port=8000)` → `tasks.py:134` `run(f"python -m http.server -b {bind} --directory docs/_build/html {port}", hide=True)` | idx 2。默认 `127.0.0.1` 仅为缺省,`inv docs --bind` 可传任意字符串;`if serve:`(idx 1)只做分支与 print,不进入命令 |
| P2-S-406 | 同上 L134 | idx 3。默认 int 8000 仅是缺省值,invoke 不强制类型,CLI 可传 `8000; <cmd>` 类字符串 |
| P2-S-390 | `tasks.py:101` `tox_env_site_packages_dir = os.getenv("TOX_ENV_SITE_PACKAGES_DIR")` → `tasks.py:104-105` `os.path.join(...)` / `args.replace(PACKAGE_SOURCE, tox_env_pkg_src)` → L107 命令 | 返回值。控制该环境变量(tox/CI 场景)即可向命令注入内容;信任边界弱于 CLI 参数(需环境控制权),故置信度 0.75 |

## 4. 每个有效 Sink 的源码依据

`invoke.run` 以 shell 命令字符串执行(等价 `shell=True`),危险参数位置为**第 0 个位置参数**(整个命令字符串)。绑定链:`tasks.py:14` `from invoke import Exit, UnexpectedExit, run as _run, task`;`tasks.py:25` `run = partial(_run, pty=True)`。

| 标签 | 位置 | 实参 | 污点可达 |
| --- | --- | --- | --- |
| P2-K-006 | tasks.py:107 | `f"pytest {args}"` | 是(P2-S-401 / P2-S-390) |
| P2-K-009 | tasks.py:134 | `f"python -m http.server -b {bind} --directory docs/_build/html {port}"` | 是(P2-S-405 / P2-S-406) |
| P2-K-001 | tasks.py:31 | `f"black {LINT_TARGETS}"` | 否(常量拼接) |
| P2-K-002 | tasks.py:37 | `f"isort {LINT_TARGETS}"` | 否 |
| P2-K-003 | tasks.py:43–46 | `f"docformatter -r {LINT_TARGETS} …"` | 否 |
| P2-K-004 | tasks.py:65 | `f"flake8 --format=pylint {LINT_TARGETS}"` | 否 |
| P2-K-005 | tasks.py:71 | `f"pylint {LINT_TARGETS}"` | 否 |
| P2-K-007/008 | tasks.py:129/130 | `"rm -rf docs/_build"` / `"sphinx-build …"`(字面量) | 否 |
| P2-K-010~014 | tasks.py:140/141/147/148/154 | `"rm -rf dist build …"` / `"python -m build"` / `"find …"` / `"rm -rf .tox …"` / `"twine upload dist/*"`(字面量) | 否 |

**命令字符串 vs 参数列表形态的分别建模**:本仓库全部进程执行点均为 invoke.run 的**字符串命令形态**(arg 0 整体危险,已按此建模);仓库内不存在任何 `subprocess.*` / `os.system` / `os.popen` / `pexpect` 调用(grep 验证),即不存在需要按"逐参数位置"建模的非 shell 参数列表形态,故该分支刻意留空而非臆造。`hide=quiet` 等关键字参数仅控制输出,非危险位置。

## 5. Sanitizer / Summary 建模证据

- **Sanitizer(空)证据**:tasks.py 全文无 `shlex.quote`、无白名单、无元字符过滤、无类型强制;`args.replace(PACKAGE_SOURCE, …)`(L105)是对常量子串的普通替换,不构成中和;pydash.predicates 的类型检查不守卫任何命令路径;pydash.strings 的 `escape`(HTML 实体)/`slugify` 等为展示层变换,均非 shell 元字符 sanitizer。因此 `isBarrier` 返回 `none()`,不为"看起来像校验"的代码臆造 barrier。
- **Summary(空)证据**:唯一真实 source→sink 路径为 tasks.py 内的同过程 f-string 插值,Python 数据流原生覆盖;`run = partial(_run, pty=True)` 的别名问题已通过在 `MySinks` 中按调用点语法匹配解决,无需经 invoke 包(源码不在数据库内)的 summary 边;任务间包装调用(fmt/lint/ci)只传递 `ctx` 对象(非 source)。`isAdditionalTaintStep` 返回 `none()`,不创建无条件传播。

## 6. 诊断查询(不计入正式结果)

`diagnostics/TaskParamToInvokeRunDiagnostic.ql`:对 tasks.py 中**所有** `@task` 函数参数,用 `TaintTracking::localTaint(DataFlow::parameterNode(p), MySinks::isSink(...))` 检查局部传播到 invoke.run 命令字符串的情况。预期结果恰为 3 条(`args`→L107、`bind`→L134、`port`→L134):出现额外结果 = 标注遗漏 source;`ctx`/`quiet`/`serve` 无结果 = 复证否定性标注。该查询验证"内部包装器参数不自动等于 Source"的原则,其结果不进入正式漏洞报告(独立目录、非 path-problem 元数据)。

## 7. 未覆盖的 API、动态调用及已知局限

1. **invoke 包源码不在 CodeQL 数据库内**(数据库仅含 28 个项目文件):`invoke.run` 无法按真实 API 解析,`partial` 别名不经 API 图跟踪——已用局部名语法匹配(三形态:局部 `run`/`_run` 限定 tasks.py、点号 `invoke.run(...)` 全局)补偿,见 detection.json coverage_gaps。
2. **`invoke.Context.run` / `ctx.run(...)` / `ctx.sudo(...)` 未建模**:仓库内不存在该调用形态,且无对应标签;为召回而臆造会引入无标签依据的 sink,故未建模(与"不渲染 role=none 标签"原则一致)。
3. **`os.environ['X']` 下标访问未建模**:提取阶段即未覆盖(sources.ql 仅为召回保留 `os.getenv`/`os.environ.get`),仓库内不存在该形态;`os.environ.get` 仅 docs/conf.py:102 一处且已标 none。
4. **`Call.getArg(0)` 不覆盖星号参数前置的调用**(CodeQL 语义:被 `*args` 前置的参数不计入 `getArg(i)`);本仓库所有 `run(...)` 调用均为简单位置参数,不受影响。
5. **动态调用库函数**:`objects.invoke`/`utilities.method`/`attempt` 等 15 个函数存在动态 Python 分发(Phase 1 已注明与 Pass 4 相关),对 CWE-78 判定 none,未生成任何 source/sink/summary。
6. **f-string 形态**:提取查询不分析 f-string(detection.json 已记录);查询侧依赖数据流引擎的 JoinedStr/FormattedValue 传播,无额外建模。
7. **文件匹配基于短文件名** `tasks.py`:若未来同库引入同名文件的其它模块,`invokeTaskFunction`/`InvokeRunCall` 的局部名匹配可能误配;当前数据库内 tasks.py 唯一,且 `run` 被同名调用仅这 14 处。
8. **Pass 1 占位块**:labels.json 中 pass_id=1 为 schema contains 约束所需的空占位,未渲染任何 Pass 1 库内容;所有谓词的 passKey 分发目前仅有 `command_injection` 一个键。

## 8. 建模原则(与其他项目实验一致)

1. **仅渲染有效标签**:role=none 的 405 条候选一律不进入库;不因"名字像"或"类型像"而臆造 source/sink。
2. **签名优先、位置忠实**:source 按标签签名(函数名+文件+参数索引/返回值)匹配;sink 按包/可调用/参数索引匹配,调用点差异记录于标签置信度而非查询语义。
3. **无证据即 none()**:barrier 与 additional flow step 在无具体中和/传播证据时返回 `none()`,绝不引入无条件污点传播或臆造 barrier。
4. **危险参数按实际语义定位**:字符串命令形态取整串(arg 0);参数列表形态按参数位置——本仓库仅存在前者。
5. **内部包装器参数 ≠ source**:`ctx`/`quiet`/`serve` 及 387 个库参数虽是"函数参数",但经审查不构成 CWE-78 输入边界;对内部参数到危险调用的局部传播用独立 diagnostics 查询验证,不并入正式结果。
6. **barrier 挂钩永远存在**:即使为空,`isBarrier` 均接入查询 config(WORKFLOW 硬约束)。
7. **确定性渲染**:库文件由标签表机械生成、带 machine-generated 头注释,批处理顺序与标签 ID 稳定,保证可复现与可审计。

## 9. 状态

Step 4(库生成)与 Step 5 的查询生成已完成并通过编译验证。**未执行** `codeql database analyze`(按实验指令:仅生成文件,不执行正式分析)。后续 Step 5 执行与 Step 6 过滤报告待指令。
