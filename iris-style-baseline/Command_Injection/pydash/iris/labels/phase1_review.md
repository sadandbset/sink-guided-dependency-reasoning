# Phase 1 人工审核门(advisory)— Pass 2 / CWE-78 Command Injection

状态:**待人工审核**(本文件为 Augur WORKFLOW §4.5 CHECKPOINT 审核负载;按实验指令,本步骤到 Step 3 为止,未进入 Phase 2)。

## 1. 标签计数总览

- Pass 2(CWE-077/078/088),423 候选全部处理:**source 4、sink 14、sanitizer 0、summary 0、none 405**;classification:tp 18 / fp 405 / candidate 0。
- 模型:glm-5.3(Claude Code CLI agent,确定性标注);13 批;详见 `label_stats.md`。

## 2. 高风险 sink(API 调用点)

`invoke.run` 以 shell 命令字符串执行(绑定链:`tasks.py:14 from invoke import run as _run` → `tasks.py:25 run = partial(_run, pty=True)`),语义等价 `shell=True`,全部 14 处调用点均标注为 sink。

**污点可达(重点复核)**:

1. `tasks.py:107` — `run(f"pytest {args}")`
   `args` 是 `inv test --args` 的 CLI 字符串参数(默认值 `f"{TEST_TARGETS} --cov={PACKAGE_NAME}"` 亦为常量,但 CLI 可整体覆盖),另叠加 `os.getenv("TOX_ENV_SITE_PACKAGES_DIR")` 派生的 `args.replace(...)` 替换。无任何验证/引用/白名单。
2. `tasks.py:134` — `run(f"python -m http.server -b {bind} --directory docs/_build/html {port}", hide=True)`
   `bind`/`port` 是 `inv docs --bind --port` 的 CLI 参数(`bind="127.0.0.1"`、`port=8000` 仅是默认值,CLI 可传任意字符串)。无验证。

**当前无污点流入(仅 API 级保留)**:`tasks.py:31,37,43,65,71`(f-string 拼接模块常量 `LINT_TARGETS` 等)与 `tasks.py:129,130,140,141,147,148,154`(纯字面量命令,如 `rm -rf docs/_build`、`twine upload dist/*`)。这些是维护者固定命令,信任边界清晰。

## 3. Source 判定依据与边界分析(对应实验指令审查点 1–6)

1. **输入是否在进入处理前被验证/解析,是否真正约束命令参数** — 否。`args`、`bind`、`port` 均未经任何校验直接进入 f-string 命令拼接;`args.replace(PACKAGE_SOURCE, tox_env_pkg_src)` 是普通字符串替换,不构成净化;`os.path.basename(PACKAGE_SOURCE)` 作用于常量,与输入无关。
2. **请求/文件/配置输入是否影响系统命令** — 不涉及请求与文件。仓库为纯数据处理库 + invoke 任务脚本;影响命令的输入仅有:CLI 任务参数(`args`/`bind`/`port`)与环境变量 `TOX_ENV_SITE_PACKAGES_DIR`。`os.environ.get('READTHEDOCS')`(docs/conf.py:102)仅改变 Sphinx 主题选择,判定 none。
3. **subprocess/os 调用形态** — 仓库内无 `subprocess.*`、`os.system`、`os.popen`、`os.exec*`、`pexpect` 直接调用(grep 验证);唯一进程执行面是 `invoke.run` 的**字符串命令 + shell 解析**形态(等价 shell=True),不存在参数列表形态。常量命令与插值命令两类已在标签中区分。
4. **内部函数角色** — pydash 全部 387 个库 API(arrays/chaining/collections/functions/helpers/numerical/objects/predicates/strings/utilities)判定为 **none(普通中间处理/无关)**:纯内存数据变换与高阶函数工具,无进程执行、无外部输入读取(grep 证实无 open()/getenv/sys.argv/requests;strings.py 仅 import urllib.parse 用于 URL 查询串拼装)。其中 `invoke`/`invoke_map`/`attempt`/`method`/`result`/`callit` 等约 15 个函数存在**动态 Python 调用/回调分发**(与 Pass 4 代码注入更相关),已在 rationale 单独注明,但对 CWE-78 仍为 none。任务参数中的 `ctx`(invoke Context 框架对象×13)、`quiet`/`serve`(布尔开关,仅作 hide/分支条件×3)不进入命令字符串,判定 none——即**未将所有输入字段自动认定为 Source**。
5. **配置固定命令与攻击者输入的信任边界** — 存在清晰边界:常量/字面量命令(black、isort、docformatter、flake8、pylint、rm、sphinx-build、build、find、twine)由维护者代码固定,CLI 无法注入;`pytest {args}` 与 `http.server {bind} {port}` 两处跨越 CLI 输入边界,是唯一需要威胁模型裁决的位置。
6. **是否存在阻断危险字符/非法参数的数据检查** — 不存在。全文检查无 shlex.quote、无白名单、无元字符过滤、无类型强制(port 默认 int 但 invoke 不拒绝字符串)。pydash.predicates 的类型检查仅针对内存数据的形状判断,不守卫任何命令路径,故未标为 sanitizer;pydash.strings 的字符串变换(escape/replace/slugify 等)亦非 shell 元字符中和,同样不标为 sanitizer。

## 4. Sanitizer / Summary 列表

- Sanitizer:**空**。Step 4 的 `MySanitizers.qll` 将按 WORKFLOW 规则保留空 `isBarrier`(none())。
- Summary:**空**。CLI 参数 → f-string → run 为同文件直接流,invoke 的 `partial` 别名在 CodeQL 数据流中可由局部绑定解析,无需人工 summary 边。

## 5. 人工审核需求(建议复核项)

| # | 项 | 待决问题 |
| --- | --- | --- |
| R1 | `test.args`(tasks.py:99 → 107) | CLI→shell 直接拼接,数据流确凿(classification=tp)。需人工确认威胁模型:`inv` 是开发机/CI 上的维护者工具,本地可执行 CLI 的"攻击者"是否在威胁模型内(若仅维护者可运行,风险为纵深防御级别而非可远程利用漏洞)。 |
| R2 | `docs.bind/port`(tasks.py:127 → 134) | 同 R1;另注意 `serve` 默认 bind 127.0.0.1 仅影响监听地址,命令注入与监听范围是两个独立问题。 |
| R3 | `os.getenv('TOX_ENV_SITE_PACKAGES_DIR')`(tasks.py:101) | 环境变量→命令,需环境控制权;置信度已下调至 0.75。建议确认 CI/tox 场景中该变量是否可能被不可信来源影响。 |
| R4 | 常量命令的 12 处 sink 条目 | 保留 invoke.run 全调用点为 sink(API 级语义,保守召回)。若人工认为应仅保留污点可达点,可在 Step 4 前裁剪——不影响当前标签。 |
| R5 | 动态分发库函数(objects.invoke 等) | 本 pass 标为 none;若后续运行 Pass 4(代码注入),这批函数应重新作为候选评估。 |
| R6 | labels.json 的 pass_id=1 空占位块 | 因 labels_schema.json `passes.contains` 约束强制存在 pass_id=1;仅为 schema 合规,非标注结果,请勿误读为 Pass 1 结论。 |

## 6. 未决/低置信度项

- 无 classification=candidate/unknown 条目;全部 423 条均给出确定性判定。
- 最低置信度条目:R3(getenv,0.75)与 R2(port,0.80),均因信任边界而非数据流本身,已列入上表人工复核。

## 7. 结论(供审核)

独立 API 标注结论:pydash 对 CWE-78 的真实暴露面**完全收敛于 tasks.py 的 invoke 任务脚本**:一个确定的 source→sink 模式(CLI 参数/环境变量 → f-string → invoke.run 字符串命令),其中 2 个调用点(tasks.py:107、134)污点可达;库本体(src/pydash)与文档配置(docs/conf.py)无任何命令执行面。是否构成可报告漏洞取决于威胁模型(本地 CLI 信任边界),留待人工裁决。
