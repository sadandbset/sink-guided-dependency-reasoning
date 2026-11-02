# Pass 2 (CWE-78 Command Injection) — LLM Candidate Labeling Stats

## 运行信息

| 项 | 值 |
| --- | --- |
| 项目 | pydash 5.1.2 |
| 语言 / 框架 | python / invoke (CLI task runner, detection.json 置信度 0.8) |
| Pass | 2 — Command/Argument Injection (CWE-077 / 078 / 088) |
| LLM 模型(真实使用) | **glm-5.3**(经 Claude Code CLI agent 执行,确定性标注,无采样温度) |
| 批次数 | **13**(B01 sinks·tasks.py,B02 sources·tasks.py,B03 sources·docs/conf.py,B04–B13 十个 pydash 库模块) |
| 处理候选总数 | **423**(sources.csv 409 行 + sinks.csv 14 行,全部处理,无丢弃) |
| 生成时间 | 2026-10-16 (run_id: `pydash-pass2-cwe78-labeling-20261016`) |
| 标注依据 | 逐条对照真实源码:`tasks.py`、`docs/conf.py`、`src/pydash/*.py` 全文/抽查阅读;grep 确认库内无 subprocess/os.system/eval/exec/popen/pexpect;未接触 PyVul 真值、修复提交与外部公告 |

## 标签计数(role)

| role | 数量 | 说明 |
| --- | --- | --- |
| source | 4 | 见下表 |
| sink | 14 | 全部为 `invoke.run`(局部绑定 `run = partial(_run, pty=True)`)调用点,arg_index=0 |
| sanitizer | 0 | 仓库内不存在 shlex.quote / 白名单 / 元字符校验等命令净化逻辑 |
| summary | 0 | 唯一真实流(CLI 参数 → f-string → run)为同文件直接数据流,无需额外 taint step |
| none | 405 | 387 个 pydash 库 API 定义 + 15 个 tasks.py 参数(ctx×13、quiet×2) + docs/conf.py 2 项 + serve 1 项 |
| **合计** | **423** | |

## classification 计数

| classification | 数量 |
| --- | --- |
| tp | 18(4 source + 14 sink) |
| fp | 405(全部 role=none 的候选,判定为提取噪声/非 CWE-78 边界) |
| candidate / unknown | 0(无低置信度未决项;最低置信度 0.75,均高于 0.55 重问阈值) |

## 有效 source 标签(4)

| id | callable | arg_index | 位置 | 置信度 | 流向 |
| --- | --- | --- | --- | --- | --- |
| P2-S-401 | `test` (inv @task param `args`) | 1 | tasks.py:99 | 0.90 | → `run(f"pytest {args}")` @ tasks.py:107 |
| P2-S-405 | `docs` (param `bind`) | 2 | tasks.py:127 | 0.85 | → `run(f"python -m http.server -b {bind} …")` @ tasks.py:134 |
| P2-S-406 | `docs` (param `port`) | 3 | tasks.py:127 | 0.80 | → 同上 tasks.py:134 |
| P2-S-390 | `os.getenv`(return,TOX_ENV_SITE_PACKAGES_DIR) | null | tasks.py:101 | 0.75 | → `args.replace(...)` → tasks.py:107 |

## 有效 sink 标签(14,同一签名 `invoke.run`/arg 0)

| id | 位置 | 命令构造 | 置信度 | 污点可达 |
| --- | --- | --- | --- | --- |
| P2-K-006 | tasks.py:107 | `f"pytest {args}"` | 0.95 | **是**(args 为 CLI 参数 + env 派生值) |
| P2-K-009 | tasks.py:134 | `f"python -m http.server -b {bind} … {port}"` | 0.95 | **是**(bind/port 为 CLI 参数) |
| P2-K-001 | tasks.py:31 | `f"black {LINT_TARGETS}"`(常量) | 0.90 | 否 |
| P2-K-002 | tasks.py:37 | `f"isort {LINT_TARGETS}"`(常量) | 0.90 | 否 |
| P2-K-003 | tasks.py:43 | `f"docformatter -r {LINT_TARGETS} …"`(常量) | 0.90 | 否 |
| P2-K-004 | tasks.py:65 | `f"flake8 --format=pylint {LINT_TARGETS}"`(常量) | 0.90 | 否 |
| P2-K-005 | tasks.py:71 | `f"pylint {LINT_TARGETS}"`(常量) | 0.90 | 否 |
| P2-K-007~014 | tasks.py:129,130,140,141,147,148,154 | 纯字面量命令字符串 | 0.85 | 否 |

## 各批次明细

| batch | 范围 | 候选数 | 判定 |
| --- | --- | --- | --- |
| B01 | tasks.py sink(Call:run) | 14 | sink×14 |
| B02 | tasks.py source(@task 参数 + os.getenv) | 20 | source×4,none×16 |
| B03 | docs/conf.py source | 2 | none×2 |
| B04 | pydash.arrays | 82 | none×82 |
| B05 | pydash.chaining | 9 | none×9 |
| B06 | pydash.collections | 32 | none×32 |
| B07 | pydash.functions | 26 | none×26 |
| B08 | pydash.helpers | 11 | none×11 |
| B09 | pydash.numerical | 27 | none×27 |
| B10 | pydash.objects | 45 | none×45 |
| B11 | pydash.predicates | 44 | none×44 |
| B12 | pydash.strings | 72 | none×72 |
| B13 | pydash.utilities | 39 | none×39 |

## 去重与排除记录

- **无候选被排除或丢弃**:423/423 全部处理并写入 labels.json。
- tests/ 目录在 Step 2 提取阶段即已排除(detection.json `exclusions`),非本步骤行为。
- **签名级去重(记录,不删行)**:14 个 sink 条目共享同一签名(`package=invoke, callable=run, arg_index=0`);为保持与 CSV 的逐行审计对应,labels.json 保留 14 条按调用点条目,Step 4 生成 MySinks.qll 时将去重为单一谓词。
- 库内 `find`/`replace`/`to_string`/`compose_args` 各有两处定义(模块函数 + 方法),按 CSV 原样逐条标注,未合并。

## Schema 合规

- `labels.json` 按 `assets/labels_schema.json`(draft 2020-12)校验通过:字段名、enum(role/classification/flow_kind)、`arg_index ≥ 0 或 null`、`flow_kind=argument` 时 arg_index 必须为非负整数、cwes 模式、id 唯一性、additionalProperties=false 均已检查。
- **注意**:schema 的 `passes.contains` 约束强制要求存在 `pass_id=1` 的 pass 块。本实验为 Pass 2 单遍运行,故 labels.json 中含一个 **entries 为空的 pass_id=1 占位块**(focus 注明 out-of-scope placeholder),已在 metadata.notes 说明。Pass 2 为唯一含标签的 pass。
- CSV 中 `arg_index=-1`(不适用)按 schema 要求转换为 `null`。

## 产出文件

- `labels/labels.json`(schema 合规,423 条 pass2 条目)
- `labels/labels_raw_pass2.json`(13 批原始标注记录,候选 CSV 行逐字保留以供审计)
- `labels/label_stats.md`(本文件)
- `labels/phase1_review.md`(人工审核门文档)
