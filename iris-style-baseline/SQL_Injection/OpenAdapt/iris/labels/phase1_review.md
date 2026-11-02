# Phase 1 Step 3 — LLM Candidate Labeling · Human Review Document (Pass 5 / CWE-89 SQL Injection)

**Checkpoint (WORKFLOW.md §4.5, advisory)**: This document is the material for the human review gate. This round covers only Phase 1 Step 3 (candidate labeling) and **does not proceed to Phase 2** (no .qll generation, no taint query execution, no report output).

## 1. Run Overview

| Item | Value |
| --- | --- |
| Project | openadapt (local desktop GUI automation app: nicegui 1.2.16 native-mode UI + python-fire CLI + SQLAlchemy 1.4.43 data layer + alembic) |
| Pass | 5 (CWE-089, SQL Injection) |
| LLM model | **glm-5.3** (the model of this Claude Code session, labeling inline; no external LLM API invoked; deterministic guardrails: fixed confidence values, rule-consistent rationales) |
| Number of batches | 5 (1 sink batch + 4 source batches, batch sizes 10/31/30/30/30) |
| Total processed | **131 CSV candidate rows** (sources.csv 121 rows + sinks.csv 10 rows), all covered, none missed, none excluded |
| Deduplication | 3 duplicate source rows merged (same AST node, see §7) |
| labels.json entries | 128 entries (pass 5) + pass 1 placeholder block (empty entries, see §9) |
| Generated | 2026-10-20 (UTC) |

## 2. Label Distribution

| Role | Count | | Classification | Count |
| --- | --- | --- | --- | --- |
| source | 16 | | tp | 6 |
| sink | 3 | | candidate | 14 |
| sanitizer | 1 | | fp | 108 |
| summary | 1 | | unknown | 0 |
| none | 107 | | | |

Source-side distribution by CSV flow_kind: config 45 rows (all none), file 19 (3 source/16 none), db_read 19 (8 source/11 none), internal_transfer 14 (1 summary/13 none), cli 12 (1 source/11 none), env 4 (all none), ui_input 3 (all source candidate), cli_spawn 1 (none), ui_event 1 (source candidate).

## 3. Confirmed Injection Chain (Core Finding)

```
External input source               DB residence              SQL text                   Execution
─────────────────────────────     ───────────────────     ───────────────────────     ─────────────────
ui.input name (cards.py:44)  ─┐
  └> Popen(...record + name)   │
     └> record(task_description) (record.py:507)
        └> insert_recording    │   Recording row ──────>  export_sql f-string         create_db(recording_id, sql)
           (parameterized       ─┘   (crud.py:139 read)    crud.py:142 (8 columns      (crud.py:209, arg 1)
            ORM write)                                        interpolated, no escaping,   └> connection.execute(sql)
                                                               string columns merely      crud.py:180 ← execution sink
                                                               single-quote wrapped)
on_import of arbitrary bz2 file ────┐
  (app/util.py:20-28 whole-DB replace) └> all recording columns controllable (incl. platform/task_description)
```

- **sink (tp) ×3**: `connection.execute(sql)` @ crud.py:180 (arg 0, raw SQL string, conf 0.95); export_sql f-string @ crud.py:142 (SQL text construction point, conf 0.90); `create_db` wrapper @ crud.py:150 (arg 1 executed as-is, conf 0.85).
- **source (tp) ×2**: `recording.task_description` (conf 0.75) and `recording.platform` (conf 0.70) @ crud.py:142 — read from the DB and inserted directly into the f-string.
- **source (candidate) ×14**: the 6 numeric columns at crud.py:142 (machine-generated values in the normal flow, arbitrary after a DB import); plus origin/context rows (record.py:508, cards.py:44, cards.py:21, local_file_picker.py:87/101, app/util.py:21-23).
- **summary ×1**: crud.py:209 `create_db` arg 1 (`sql`) — the cross-function handoff node from the export_sql return value to the execution point (conf 0.80).
- **sanitizer ×1**: crud.py:48 `db.execute(sa.insert(table), to_insert)` arg 1 — the Core insert bound-parameter channel (classification=fp, i.e. a safe channel; not a vulnerability).

Impact scope note: the injection's execution target is the locally created `recording_{id}.db` from `create_db` (the sql is executed after `alembic upgrade head`); single-quote escaping inside `task_description`/`platform` is genuinely feasible.

## 4. Human Review Priority Items (Low Confidence / Needs Confirmation)

1. **DB round-trip modeling**: The full path from the CLI parameter `record(task_description)` (record.py:508) to the sink crosses a process boundary (Popen) plus a DB round trip, which CodeQL cannot track directly. The current model treats the db_read row at crud.py:142 as the DB-resident-side source (the "DB content reused into SQL" family, python.md §3). If end-to-end tracking is required, Phase 2 must explicitly add a summary edge in MySummaries.qll (already flagged as candidate with rationale in labels).
2. **Import trust boundary**: `on_import` (app/util.py:20-28) overwrites openadapt.db wholesale with a user-selected bz2 file — the strongest attack surface that makes all recording columns (including numeric ones) controllable. This "file → DB → ORM read → SQL text" flow is likewise not directly trackable; labeled source/candidate, **the trust decision needs human confirmation**.
3. `local_file_picker.py:101` LocalFilePicker: used only by the `__main__` demo (the result is only notified, never consumed); kept as candidate (conf 0.45, re-checked once via a re-ask).
4. `share.py:70 send_recording(recording_id)`: this is a **reachability trigger** for the export chain (share send → export_recording → export_sql → create_db), but recording_id itself only flows into the parameterized `filter_by` and a filename, never into SQL text — labeled none/fp. Reviewers are asked to confirm the "trigger ≠ taint source" judgment.

## 5. Point-by-Point Response to the Ten Review Checklist Items

1. **Source authenticity/reachability**: This project has no HTTP/API surface (nicegui native mode; FastAPI/Socket.IO internals are not inside the codebase). The real external boundaries are: ui.input text (cards.py:44), LocalFilePicker file selection, fire CLI parameters (record/replay/share etc.), files/environment (operator level), and the DB contents themselves (the import channel). Internal data-access wrappers such as the `_insert` formal parameter are **not** automatically counted as Sources (13 of the 14 internal_transfer rows are none; only the sql hand-off row of create_db is counted as summary).
2. **HTTP search/filter/sort/pagination inputs into SQL**: not applicable (no HTTP). The equivalent user inputs are the recording name/task_description; confirmed that they enter raw SQL text (the f-string value positions at crud.py:142, escapable even inside the quote wrapping).
3. **SQL text parameters vs. bound-value parameters**: distinguished. crud.py:48 `db.execute(sa.insert(table), to_insert)`: arg 0 is a Core statement object (none), arg 1 is the bound-value list (sanitizer/fp); crud.py:180 `connection.execute(sql)`: arg 0 is a raw SQL string (sink/tp). The mere presence of a query API ≠ a vulnerability — none of the ORM chains (query/filter/order_by/add) were labeled sink.
4. **String concatenation/f-string/%/format into SQL structure**: the only dynamic SQL construction in the entire project is the f-string at crud.py:142 (8 columns interpolated, no escaping); labeled sink/tp with the wrapper propagation evidence retained (export_sql → create_db arg 1 → connection.execute). The other 3 f-strings inside create_db (lines 161/164/169: filename, backup path, env line) are all labeled none/fp.
5. **ORM regular queries vs. raw SQL**: distinguished. `db.query(...).filter_by/.filter/.order_by`, `db.add/commit/refresh`, and the Core insert bound values are all handled as parameterized safe channels (all 45 config rows, 11 irrelevant db_read rows, 13 internal_transfer rows, etc. are none/fp).
6. **Precompiled/bound-parameter blocking**: the bound-parameter channel at crud.py:48 blocks the current data flow (sanitizer label); the project has no case where identifier positions such as table names/column names/ORDER BY are user-influenced (table/column names come from the static models.py). Numbers passed via bound parameters (the _insert channel) are safe behavior.
7. **Valid SQL syntax context handling / strict allow-listing**: there is **no** sanitizer anywhere on the export_sql → create_db → execute chain (no escaping, no allow-listing, no identity validation that could block this flow); HTML escaping/replace()/identity-validation categories are inapplicable and were not mislabeled.
8. **Whether SQL object constructors are used for execution**: `sa.insert(table)` (crud.py:48) is indeed executed as arg 0 of db.execute, but it is a parameterized Core statement (static identifiers, bound values) → labeled none; there is no TextClause/psycopg SQL/Django RawSQL usage (detection.json records absentChannels). Object construction alone is insufficient to establish a vulnerability.
9. **Tests/migrations/constant SQL/admin configuration**: this round's candidates do not come from tests/ (excluded at the extraction stage); the alembic tree has no op.execute/text calls (confirmed by detection.json, not extracted); there is no static constant SQL (the only SQL construction is the dynamic f-string at line 142); operator-level configuration (45 config rows + 4 env rows) is all labeled none/fp and not counted as a formal vulnerability.
10. **Complete data flow vs. local paths**: the complete chain from external source to dangerous SQL text was confirmed (§3): UI/CLI input or imported DB file → Recording.task_description/platform → crud.py:142 f-string → create_db arg 1 → crud.py:180 execution. Local paths through internal_transfer (formal parameters → parameterized execute) were not false-positive-reported as vulnerabilities.

## 6. Sanitizer List

| Location | API | Conclusion |
| --- | --- | --- |
| crud.py:48 arg 1 | `db.execute(sa.insert(table), to_insert)` bound-value position | The only sanitizer label (safe channel, fp). There is no effective sanitizer anywhere on the export chain. |

## 7. Deduplication and Exclusion Records (Rationale)

| CSV row | Location | Rationale |
| --- | --- | --- |
| sources.csv #37 | crud.py:164 `ENV_FILE_PATH` | Exact duplicate of #38 in all columns (same file/line/callable/argIndex/flowKind/receiver — the same AST node double-matched by the query) → merged |
| sources.csv #64 | openai.py:32 `OPENAI_API_KEY` | Same node as #65, a moduleHint variant (`openai` vs `openadapt.strategies.mixins.openai`) → merged, keeping the more precise moduleHint |
| sources.csv #66 | openai.py:41 `OPENAI_MODEL_NAME` | Same as above (#66/#67 moduleHint variants) → merged |

No duplicate sink rows. Beyond these, **there are no exclusions whatsoever**: tests/ and OpenAdapt-db paths were already excluded at the Step 2 extraction stage (see detection.json exclusions), so this round's candidates contain no such rows. All 131 rows have per-row decision records in the 5 batches of `labels_raw_pass5.json` (the 121+10 row coverage check passed).

## 8. Processing Log (Actual Model/Batches/Totals)

- Model: **glm-5.3** (the Claude Code session model, labeling done inline; no external API calls, no temperature parameter applicable — replaced by fixed confidence values and consistency rules).
- Batches: 5 batches — batch 1 (10 sink candidate rows), batches 2-5 (121 source candidate rows, 31/30/30/30).
- Totals: 131 rows processed → 128 unique entries (3 duplicate rows merged) + 1 re-ask re-check (local_file_picker.py:101, conf 0.40→0.45, decision unchanged).
- Role statistics: source 16 / sink 3 / sanitizer 1 / summary 1 / none 107; classification statistics: tp 6 / candidate 14 / fp 108 / unknown 0.

## 9. Schema Compliance Notes

`labels.json` passes validation against all constraints of `augur-0.3.0/assets/labels_schema.json` (required keys, enums, patterns, additionalProperties=false, arg_index must be an integer ≥ 0 when flow_kind=argument, and the `contains` constraint on the `passes` array). **Special note**: the schema's `passes.contains` requires any labels.json to contain an entry with `pass_id=1`; to satisfy validation, a pass 1 (Path Traversal) placeholder block with an empty `entries` array was added to the file — **no labeling at all was done for pass 1 this round**; the only labeled pass is pass 5. This decision is declared in metadata.notes.

## 10. Constraint Compliance Statement

- PyVul ground truth, fix commits, CVE localization, and external vulnerability advisories were not read (sql_sinks.csv and 漏洞审查报告.md in the OpenAdapt_vuln root directory were not opened).
- The source code, CodeQL database, original extraction results (sources.csv/sinks.csv/ql files), and the augur-0.3.0 installation directory were not modified.
- The only new files this round are the four artifacts under `iris/labels/` (labels.json, labels_raw_pass5.json, label_stats.md, phase1_review.md) plus the build script `build_labels_pass5.py` in the working directory (which can reproduce all artifacts).
- References loaded: WORKFLOW.md, references/python.md, references/patterns.md, assets/labels_schema.json; the django/flask/fastapi references were not loaded (the project uses none of those frameworks, consistent with detection.json).

## 11. Conclusion and Next Steps (Pending Human Approval)

Pass 5 labeling is complete: 1 high-confidence SQL injection chain (crud.py:142 → 209 → 180, with DB-resident task_description/platform as the source, and UI/CLI input or an imported DB file as the taint origin), 1 parameterized safe channel (crud.py:48), and 107 none entries. **As required by the task, this round stops here and does not proceed to Phase 2 (Steps 4-6).** If human review approves, Phase 2 should focus on: adding a summary edge for record(task_description)→DB→export_sql, and the final ruling on the import-channel trust decision.
