# Label Statistics — Pass 5 (CWE-89 SQL Injection)

Project: **openadapt** · Language: python · Framework: nicegui (native desktop UI) + python-fire CLI
Run: `openadapt-cwe89-pass5-labeling-20261020` · Model: **glm-5.3** (Claude Code session model, inline labeling) · Generated: 2026-10-20T12:54:16+00:00

## Totals

| Metric | Value |
| --- | --- |
| CSV candidate rows processed | 131 (121 source + 10 sink) |
| Batches | 5 (1 sink batch + 4 source batches) |
| Duplicate rows merged (dedup) | 3 |
| Unique labeled entries in labels.json | 128 |
| Re-asked low-confidence entries | 1 (local_file_picker.py:101, kept candidate @ 0.45) |

## Role distribution (pass 5)

| Role | Count | Share |
| --- | --- | --- |
| source | 16 | 12.5% |
| sink | 3 | 2.3% |
| sanitizer | 1 | 0.8% |
| summary | 1 | 0.8% |
| none | 107 | 83.6% |

## Classification distribution

| Classification | Count |
| --- | --- |
| tp | 6 |
| candidate | 14 |
| fp | 108 |
| unknown | 0 |

## Source entries by CSV flow_kind

| CSV flow_kind | rows | labeled source | labeled summary | labeled none |
| --- | --- | --- | --- | --- |
| config | 45 | 0 | 0 | 45 |
| file | 19 | 3 | 0 | 16 |
| db_read | 19 | 8 | 0 | 11 |
| internal_transfer | 14 | 0 | 1 | 13 |
| cli | 12 | 1 | 0 | 11 |
| env | 4 | 0 | 0 | 4 |
| ui_input | 3 | 3 | 0 | 0 |
| cli_spawn | 1 | 0 | 0 | 1 |
| ui_event | 1 | 1 | 0 | 0 |

## Key entries

**Sinks (tp)**
- `pass5-sink` @ openadapt/crud.py:180 — `connection.execute(sql)` argument 0: raw SQL string execution (conf 0.95)
- `pass5-sink` @ openadapt/crud.py:142 — export_sql f-string: 8 unescaped DB-derived column interpolations into INSERT text (conf 0.90)
- `pass5-sink` @ openadapt/crud.py:150 — create_db wrapper, parameter 1 executed verbatim (conf 0.85)

**Sanitizer**
- `pass5-sink` @ openadapt/crud.py:48 — `db.execute(sa.insert(table), to_insert)` argument 1: bound-parameters channel (conf 0.90, classification fp = safe channel)

**Summary**
- `pass5-src` @ openadapt/crud.py:209 — create_db argument 1 (`sql`) hand-off from export_sql (conf 0.80)

**Sources (tp)** — `recording.task_description` (conf 0.75) and `recording.platform` (conf 0.70) at crud.py:142, directly interpolated unescaped into the raw SQL f-string.
**Sources (candidate)** — the 6 numeric `recording.<column>` reads at crud.py:142 (machine-generated in normal flow, arbitrary after DB import) plus the origin/context rows: record.py:508 `record(task_description)` CLI param; cards.py:44 `ui.input`; cards.py:21 / local_file_picker.py:87 / local_file_picker.py:101 / app/util.py:21-23 import channel.

## Deduplication record

3 source rows merged as identical AST nodes (same file/line/callable/arg_index/flow_kind/receiver):

| File:line | Callable | Note |
| --- | --- | --- |
| openadapt/crud.py:164 | ENV_FILE_PATH | emitted twice by the extraction query (identical row) |
| openadapt/strategies/mixins/openai.py:32 | OPENAI_API_KEY | moduleHint variants (`openai` vs `openadapt.strategies.mixins.openai`) |
| openadapt/strategies/mixins/openai.py:41 | OPENAI_MODEL_NAME | moduleHint variants (same two hints) |

Sink rows contained no duplicates. Details in `labels_raw_pass5.json`.

## Schema compliance

`labels.json` validates against `augur-0.3.0/assets/labels_schema.json` (hand-rolled validator covering
all constraints: required keys, enums, patterns, additionalProperties=false, the argument/arg_index
conditional, and the `passes.contains` pass_id=1 requirement). The pass_id=1 block is a placeholder
with an empty entries list (schema `contains` constraint requires a pass_id=1 item in every document;
Pass 1 was not labeled in this round — pass 5 is the only labeled pass).
