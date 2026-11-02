# Phase 1 Step 3 - Human Review Summary (Pass 5, CWE-89 SQL Injection)

Project: **piccolo** (async Python ORM, piccolo_vuln tree @ DB sha `e4946d8`). 
Model: **glm-5.3** (in-context labeling, no external API calls). Run ID: `piccolo-iris-pass5-20261021`.

## 1. Label summary

- 619 candidate rows (398 source + 221 sink) fully covered by 42 semantic groups; 0 unassigned.
- Entry-level roles: source 9, sink 12, sanitizer 1, summary 7, none 13.
- Row-weighted roles: none 188, sanitizer 2, sink 85, source 162, summary 182.
- Classifications: candidate 4, fp 18, tp 20 (entries), candidate 143, fp 334, tp 142 (rows).

## 2. Top high-risk sink APIs (for Phase 2 query generation)

1. **asyncpg `connection.fetch/execute/cursor` - SQL text at arg 0** (snk-01a-e, tp, 0.80-0.90) - the final execution layer; all SQL construction funnels here.
2. **`Engine.run_ddl(ddl)` arg 0** (snk-06, tp, 0.80) - DDL text executed verbatim; every ALTER/CREATE/schema DDL f-string funnels here unparameterized.
3. **Raw-SQL template constructions `QueryString(sql, *args)`** (snk-15, tp, 0.80) - `Table.raw`/`WhereRaw`/`SelectRaw` argument 0 becomes the executed template; the *args ride the safe bound channel.
4. **ALTER DDL f-strings** (snk-09, tp, 0.75) - `RENAME TO {new_name}`, `USING {using_expression}`, `DROP CONSTRAINT IF EXISTS {name}` are UNQUOTED; `RENAME COLUMN`/`ADD COLUMN` quoted-but-unescaped; no identifier allowlist.
5. **Savepoint statement f-strings** (snk-04a, tp, 0.75) - `f'SAVEPOINT {name}'` etc. on both engines, unquoted, caller-supplied names.
6. **Dynamic identifier interpolations** (snk-13, candidate, 0.60) - ORDER BY expression (incl. `OrderByRaw.sql` verbatim), `AS OF SYSTEM TIME '{interval}'`, ON CONFLICT str target, `PRAGMA index_list({tablename})`, DROP/CREATE INDEX names.
7. **`_get_inserted_pk` ROWID SELECT f-string** (snk-08, tp, 0.70) and schema.py DDL (snk-10, candidate, 0.65) - second-order/quoted-unescaped identifier channels.

## 3. Top source APIs

- **ORM raw-SQL text boundary** (src-07, tp, 0.85): `Table.raw(sql, *args)` / `WhereRaw(sql, *args)` argument 1 - the classic channel for embedding-app SQL injection; in-library call sites all pass literal templates (verified generate.py:476-658, table_exists).
- **DDL identifier API params** (src-08, tp, 0.70): `Alter.rename_table/rename_column/set_column_type(using_expression)/drop_constraint/set_schema`, `Savepoint(name)`, `rollback_to(savepoint_name)` - interpolated into DDL/statements with no validation.
- **AsOf interval** (src-12, tp, 0.60) and **on_conflict str target** (src-13, candidate, 0.55) - quote-context channels without escaping.
- **CLI/interactive/env/file boundaries** (src-01..05, fp): local-operator trust (`piccolo` targ CLI entrypoint, prompts, PICCOLO_CONF env, fixture files); every verified SQL-reaching flow from them rides the bound-parameter channel (schema generate `{}` slots, `.where()` bound args, pydantic-validated fixture INSERTs).

## 4. Sanitizers

- **Limit/Offset int guard** (src-15, tp, 0.80): `__post_init__` raises `TypeError` unless `isinstance(number, int)` (mixins.py:92-94, 131-133) before `f' LIMIT {number}'` - a proven type whitelist.
- **QueryString bound-args channel** is the structural mitigation (labeled `none`/fp on both the sink side snk-05 and value-param side src-14): `compile_string` keeps args out of SQL text. No other SQL-context sanitizer exists: no identifier allowlist, no escaping helper anywhere in the library - `template.format`/f-string construction is unguarded everywhere else.

## 5. Unresolved / low-confidence items (need human review)

- src-13 (on_conflict str target, 0.55) and snk-13 (dynamic identifier interpolations, 0.60): channels are real but in-library inputs are metadata- or API-bound; exploitability depends on embedding-app usage.
- src-19 / snk-10 / snk-08 (second-order reflected identifiers, 0.60-0.70): DB-reflected table/column names re-interpolated into PRAGMA/DDL/SELECT text without escaping - a genuine second-order channel; in-library names are predominantly developer-defined.
- src-01 (CLI params, 0.75): conservative-recall source rows with fp classification; whether a Phase 2 query should keep them as taint roots is a review decision (recommendation: keep, filter at reporting).

## 6. Review directives - findings

1. **Source boundary reality**: no HTTP/API surface exists (detection.json confirmed; no web framework imports). External boundaries are CLI/interactive/env/file, all operator-trust; the ORM public API is modeled as the embedding-app trust boundary. Internal wrapper params (engine `_run_*`, `run_querystring`) are labeled `summary`, not source.
2. **Search/filter/sort/pagination into SQL structure**: LIMIT/OFFSET are int-guarded (safe); ORDER BY accepts `OrderByRaw.sql` verbatim and AS OF interpolates a string - both flagged (snk-13); Where filter values stay bound.
3. **SQL text vs bound args distinguished**: yes - sql_text rows (arg 0) vs bound_params rows (arg 1+) labeled separately; bound channel is `none`/fp. `executemany`/`executescript`/Django raw()/RawSQL() do not exist in this codebase (documented absent in detection.json; no Django/SQLAlchemy/psycopg imports).
4. **String building in SQL structure**: f-string/concat/format into QueryString templates and DDL is the dominant construction style; evidence captured per group (alter.py:36/117/188, mixins.py:119/175, sqlite.py:576, etc.).
5. **ORM regular queries vs raw SQL correctly separated**: Where/insert/update values ride bound args (src-14, snk-12); raw channels are src-07/snk-15.
6. **Prepared statements block value flows**: QueryString compilation to `$n`/`?` blocks value injection; identifier/order-by/table-name structure is NOT covered by binding and is flagged separately (snk-13, src-19); no identifier whitelist exists to credit as a sanitizer.
7. **Sanitizer evidence**: only the Limit/Offset isinstance(int) guard qualifies; no HTML-escaping-style false sanitizers were credited.
8. **SQL-object constructors**: QueryString is the only SQL object; its template argument is genuinely executed (via compile + engine) so its construction sites are sinks (snk-15) - object construction alone was not sufficient elsewhere (e.g. `__str__` display interpolation is documented non-executing).
9. **Tests/migrations/static SQL**: extraction excluded /tests/, /piccolo-db/, /piccolo_migrations/; remaining static-literal SQL (PRAGMA, COMMIT/ROLLBACK, generate.py introspection literals) is labeled `none`/fp with evidence; migration machinery identifiers are developer-defined (src-19 summary).
10. **Complete external-to-SQL-text flows**: within the library, no CLI/file/env value reaches SQL text unparameterized (verified); the vulnerable-by-design channels are the ORM API raw/DDL/identifier params, which require an embedding-app flow to complete - consistent with an ORM-library threat model.

## 7. Batch log

- **B01**: 40 rows (15 source, 25 sink) - Postgres engine + engine base: driver execution calls (fetch/execute/cursor), savepoint/transaction wrappers, run_querystring/run_ddl, engine API params.
- **B02**: 57 rows (25 source, 32 sink) - SQLite engine: execute/query+args channels, savepoint/BEGIN/COMMIT statements, PRAGMA literals, _get_inserted_pk ROWID f-string, AsyncBatch.
- **B03**: 20 rows (17 source, 3 sink) - QueryString compiler (placeholder/bound-arg separation) and Table.raw raw-SQL channel + table DDL/insert templates.
- **B04**: 49 rows (15 source, 34 sink) - ALTER DDL statement dataclasses and Alter API methods; SchemaManager DDL classes.
- **B05**: 46 rows (16 source, 30 sink) - Query delegates: Distinct/Limit/AsOf/Offset/OrderBy/Returning/GroupBy/OnConflict/Values/Where plumbing and their templates.
- **B06**: 100 rows (58 source, 42 sink) - Where/WhereRaw/Combinable templates, Column comparison operators, m2m/reference DDL, column_type delegates (Concat/Math/Interval) and array/JSON operators.
- **B07**: 75 rows (45 source, 30 sink) - Query builders: SELECT assembly, INSERT VALUES, UPDATE SET, DELETE FROM, CREATE TABLE/INDEX, PRAGMA index_list, delegate transfers.
- **B08**: 10 rows (9 source, 1 sink) - Query base run loop, table reflection identifiers, pydantic serialization.
- **B09**: 75 rows (51 source, 24 sink) - Schema generate: raw() introspection helpers (literal templates + bound args) and graph output.
- **B10**: 84 rows (84 source, 0 sink) - Migrations app (commands, auto differ/manager/serialisation/snapshot, tables) and user-admin app (commands, BaseUser tables).
- **B11**: 63 rows (63 source, 0 sink) - Remaining CLI apps (fixtures/project/app/asgi/playground/tester/sql_shell), config/env/argv boundaries, setup.py file reads.
- **B12**: 0 rows (0 source, 0 sink) - Reconciliation pass: full 619-row coverage check, duplicate detection, group dedup, schema validation of labels.json.

## 8. Recommendation

Proceed to Phase 2 with the current labels: sources = src-07/08/12/13 (+ conservative src-01..05), sinks = snk-01a-e/06/15/04a/09/10/13/08, barrier = src-15 (limit/offset int guard), summaries = src-09/11/17/19 + snk-04b/07/16. Bind-param findings (snk-05 paths) should be filtered as fp at reporting per WORKFLOW.md heuristics.
