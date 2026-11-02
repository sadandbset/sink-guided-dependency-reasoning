# Pass 5 (CWE-89 SQL Injection) - Label Statistics

- **Project**: piccolo (piccolo_vuln source tree, CodeQL DB creation sha `e4946d8`)
- **Model**: glm-5.3 (in-context LLM labeling session via Claude Code agent harness; no external LLM API calls)
- **Run ID**: piccolo-iris-pass5-20261021
- **Generated**: 2026-10-20T16:41:12+00:00
- **Language / framework**: python / targ (piccolo CLI); asyncpg + aiosqlite driver layer
- **Batches**: 12 (per-batch scope and row counts in `labels_raw_pass5.json`)

## Coverage

| metric | count |
| --- | --- |
| source CSV candidate rows | 398 |
| sink CSV candidate rows | 221 |
| total candidates covered | 619 |
| label entries (semantic groups) | 42 (20 source-side, 22 sink-side) |
| duplicate CSV rows (covered once, recorded) | 3 |
| candidates left unassigned | 0 |

## Role counts

| role | entries (groups) | rows covered |
| --- | --- | --- |
| source | 9 | 162 |
| sink | 12 | 85 |
| sanitizer | 1 | 2 |
| summary | 7 | 182 |
| none | 13 | 188 |

## Classification counts

| classification | entries | rows |
| --- | --- | --- |
| tp | 20 | 142 |
| fp | 18 | 334 |
| candidate | 4 | 143 |
| unknown | 0 | 0 |

## Label entries

| id | group | role | class | conf | rows | representative location |
| --- | --- | --- | --- | --- | --- | --- |
| p5-src-001 | src-01 | source | fp | 0.75 | 111 | piccolo/apps/migrations/commands/backwards.py:115 |
| p5-src-002 | src-02 | source | fp | 0.70 | 12 | piccolo/apps/migrations/commands/backwards.py:81 |
| p5-src-003 | src-03 | source | fp | 0.65 | 9 | piccolo/conf/apps.py:365 |
| p5-src-004 | src-04 | source | fp | 0.60 | 2 | piccolo/main.py:34 |
| p5-src-005 | src-05 | source | fp | 0.70 | 12 | piccolo/query/base.py:109 |
| p5-src-006 | src-06 | none | fp | 0.85 | 9 | piccolo/apps/schema/commands/graph.py:112 |
| p5-src-007 | src-07 | source | tp | 0.85 | 2 | piccolo/columns/combination.py:112 |
| p5-src-008 | src-08 | source | tp | 0.70 | 12 | piccolo/query/methods/alter.py:364 |
| p5-src-009 | src-09 | summary | tp | 0.70 | 10 | piccolo/engine/base.py:68 |
| p5-src-010 | src-10 | none | fp | 0.80 | 19 | piccolo/engine/base.py:68 |
| p5-src-011 | src-11 | summary | tp | 0.70 | 1 | piccolo/querystring.py:63 |
| p5-src-012 | src-12 | source | tp | 0.60 | 1 | piccolo/query/mixins.py:320 |
| p5-src-013 | src-13 | source | candidate | 0.55 | 1 | piccolo/query/mixins.py:760 |
| p5-src-014 | src-14 | none | fp | 0.85 | 17 | piccolo/columns/base.py:598 |
| p5-src-015 | src-15 | sanitizer | tp | 0.80 | 2 | piccolo/query/mixins.py:303 |
| p5-src-016 | src-16 | none | fp | 0.75 | 4 | piccolo/query/mixins.py:332 |
| p5-src-017 | src-17 | summary | tp | 0.65 | 42 | piccolo/apps/migrations/commands/backwards.py:94 |
| p5-src-018 | src-17b | none | fp | 0.75 | 4 | piccolo/query/methods/objects.py:239 |
| p5-src-019 | src-18 | none | fp | 0.80 | 20 | piccolo/apps/schema/commands/generate.py:478 |
| p5-src-020 | src-19 | summary | candidate | 0.60 | 108 | piccolo/query/methods/alter.py:50 |
| p5-snk-001 | snk-01a | sink | tp | 0.90 | 4 | piccolo/engine/postgres.py:496 |
| p5-snk-002 | snk-01b | sink | tp | 0.85 | 1 | piccolo/engine/postgres.py:59 |
| p5-snk-003 | snk-01c | sink | tp | 0.85 | 3 | piccolo/engine/postgres.py:132 |
| p5-snk-004 | snk-01d | sink | tp | 0.90 | 6 | piccolo/engine/sqlite.py:230 |
| p5-snk-005 | snk-01e | sink | tp | 0.80 | 1 | piccolo/engine/sqlite.py:575 |
| p5-snk-006 | snk-02 | none | fp | 0.85 | 11 | piccolo/engine/sqlite.py:391 |
| p5-snk-007 | snk-03 | none | fp | 0.90 | 1 | piccolo/engine/postgres.py:41 |
| p5-snk-008 | snk-04a | sink | tp | 0.75 | 6 | piccolo/engine/postgres.py:133 |
| p5-snk-009 | snk-04b | summary | tp | 0.65 | 6 | piccolo/engine/postgres.py:131 |
| p5-snk-010 | snk-05 | none | fp | 0.90 | 7 | piccolo/engine/postgres.py:59 |
| p5-snk-011 | snk-06 | sink | tp | 0.80 | 1 | piccolo/engine/postgres.py:544 |
| p5-snk-012 | snk-07 | summary | tp | 0.65 | 9 | piccolo/engine/postgres.py:40 |
| p5-snk-013 | snk-08 | sink | tp | 0.70 | 1 | piccolo/engine/sqlite.py:576 |
| p5-snk-014 | snk-09 | sink | tp | 0.75 | 25 | piccolo/query/methods/alter.py:36 |
| p5-snk-015 | snk-10 | sink | candidate | 0.65 | 9 | piccolo/schema.py:55 |
| p5-snk-016 | snk-11 | none | fp | 0.90 | 2 | piccolo/query/base.py:426 |
| p5-snk-017 | snk-12 | none | fp | 0.75 | 77 | piccolo/columns/base.py:904 |
| p5-snk-018 | snk-13 | sink | candidate | 0.60 | 25 | piccolo/query/methods/create_index.py:50 |
| p5-snk-019 | snk-15 | sink | tp | 0.80 | 3 | piccolo/columns/combination.py:131 |
| p5-snk-020 | snk-16 | summary | tp | 0.60 | 6 | piccolo/apps/schema/commands/generate.py:466 |
| p5-snk-021 | snk-17 | none | fp | 0.90 | 11 | piccolo/apps/schema/commands/generate.py:476 |
| p5-snk-022 | snk-18 | none | fp | 0.85 | 6 | piccolo/apps/schema/commands/generate.py:476 |

## Top modules by candidate rows

- piccolo/apps/schema/commands/generate.py: 71 rows
- piccolo/engine/sqlite.py: 57 rows
- piccolo/query/mixins.py: 46 rows
- piccolo/query/methods/alter.py: 40 rows
- piccolo/columns/column_types.py: 39 rows
- piccolo/engine/postgres.py: 36 rows
- piccolo/query/methods/select.py: 26 rows
- piccolo/columns/base.py: 24 rows
- piccolo/columns/combination.py: 20 rows
- piccolo/table.py: 19 rows
- piccolo/columns/m2m.py: 16 rows
- piccolo/apps/migrations/commands/backwards.py: 13 rows

## Notes

- Dedup: 3 identical duplicate rows (sources.csv table.py:1572 `tablename` x2; sinks.csv combination.py:42 and :50 `BinaryExpr concat` x2 each) are recorded in `labels_raw_pass5.json` and covered by a single label each.
- Excluded noise (role `none`): static PRAGMA/COMMIT/ROLLBACK statements, `cursor.fetch(batch_size)` receiver collision (postgres.py:41), non-SQL error-message f-strings (objects.py:334, query/base.py:426), file-write scaffolding `open()` sites, engine metadata params.
- The bound-parameter channel (`fetch`/`execute`/`cursor` args after SQL text) is labeled `none`/fp, not sink: `QueryString.compile_string` emits `$n`/`?` placeholders (querystring.py:163-192), so bound values never enter SQL text.
- Pass 1 block in `labels.json` is an empty stub present only to satisfy the schema's `passes contains pass_id=1` constraint; no pass-1 labeling was performed.
