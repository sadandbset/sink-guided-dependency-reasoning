# Augur Phase 1 — Checkpoint Review (Human Review Gate)

**Project:** arches (Django) · **Pass:** 5 — CWE-089 SQL Injection · **Run:** `arches-iris-pass5-20261020` (2026-10-20)
**Scope of this round:** Phase 1 Step 3 only (LLM candidate labeling). No CodeQL query execution, no Phase 2.

## 1. What was reviewed and how

All 2130 CSV candidates (1906 source rows + 224 sink rows) were dispositioned in 5 batches by the in-session LLM (glm-5.3). Before labeling, every SQL-relevant code path was read and verified in the `arches_vuln` tree (sha `75ce8f7`, identical to the CodeQL DB creation sha): `views/concept.py`, `models/concept.py`, `views/api.py` (MVT), `views/search.py`, `search/components/map_filter.py`, `views/etl_manager.py`, all three ETL modules, `models/graph.py`, `datatypes.py`, `index_database.py`, `v3migration.py`, `tasks.py`, `system_metadata.py`, `remover.py`, and the management commands `setup_db`, `export`, `packages`, `etl_template`, `graph`, `updateproject`, `es`, plus `db/migration_operations/extras.py`. Raw SQL channel inventory was cross-checked by grep: `cursor.execute` is the **only** SQL execution channel in project code — `.raw()`, `RawSQL()`, `.extra()`, `from_statement()`, `executemany()`, SQLAlchemy text clauses and psycopg SQL-object composition do **not** occur anywhere in the snapshot.

## 2. Confirmed true-positive flows (request → raw SQL text) — 2 flows, 7 sink entries

### Flow A — `/concepts/paged_dropdown` (unauthenticated, no decorator)

```
request.GET.get("query")                      views/concept.py:383   [source p5-s-*]
  ├─> sql.format(query=query.lower(), ...)    views/concept.py:424   [sink tp p5-k-140]  LOWER(value)='{query}'
  │     └─> cursor.execute(sql)               views/concept.py:426   [sink tp p5-k-141]
  └─> Concept().get_child_collections_hierarchically(…, query=query)   views/concept.py:389  (keyword hand-off)
        └─> Concept.get_child_edges(query=…)  models/concept.py:466  [summary tp]
              ├─> "…like '%%%s%%'" % query.lower()   models/concept.py:635/646  [sink tp p5-k-091]
              ├─> sql.format(…, subquery=…)   models/concept.py:653  [sink tp p5-k-092]
              └─> cursor.execute(sql)         models/concept.py:723  [sink tp p5-k-094]
```

No validation, quoting or escaping is applied to `query` anywhere on either branch. The sibling `conceptid` parameter of the same endpoint is neutralized by the `uuid.UUID` guard at `models/concept.py:503` (sanitizer `p5-x-01`); `page` is `int()`-cast (`p5-x-02`); `limit` is the constant 50.

### Flow B — `/concepts/dropdown` (unauthenticated, no decorator)

```
request.GET.get("conceptid")                  views/concept.py:376   [source p5-s-*]
  └─> Concept().get_e55_domain(conceptid)     views/concept.py:377   [summary tp]
        ├─> "…WHERE d.conceptidfrom = '{0}'".format(conceptid)  models/concept.py:1180-1202  [sink tp p5-k-099]
        └─> cursor.execute(sql)               models/concept.py:1216 [sink tp p5-k-100]
```

**No UUID or format validation exists on this path** — this is the unvalidated counterpart of the `get_child_edges` guard. A single quote in the `conceptid` parameter breaks the string literal.

Both endpoints are registered in `arches/urls.py` (`^concepts/dropdown`, `^concepts/paged_dropdown`) and carry no `@group_required`/`@login_required` decorator (verified at the function definitions).

## 3. Candidate entries requiring human review — 130 (kept for conservative recall)

These are real input-boundary → dynamic-SQL paths at **operator trust level**, not remote-attacker paths; per the task constraints they are NOT counted as confirmed vulnerabilities:

| Path | Input boundary | SQL site | Why not confirmed |
| --- | --- | --- | --- |
| `manage.py export -t <table>` | CLI option | `export.py:55/:61` `SELECT * FROM {0}.format(table)`, `:67` (SQL handed to `pgsql2shp`) | local operator only; no HTTP surface |
| `manage.py packages` | CLI package dir → `.sql` files | `packages.py:611/:623` executes whole file contents verbatim | package files are admin-supplied by design |
| `manage.py v3` / v3 migration | operator data files | `v3migration.py:49/:54` `.format(value)` into `ST_ForceRHR('{0}')` on a direct psycopg2 cursor | v3 export data, operator trust |
| `es` / celery reindexing | ORM/DB content | `index_database.py:314/:319/:343/:370` `valueTypes`/`topConcept` interpolated | DB-derived identifiers, not request data |

Refactor-risk notes (labeled fp but flagged): `models/concept.py:1154/:1160` (`% value.id`) and `datatypes.py:2131/:2138` (`% (tile.pk)`) are injection-shaped %-interpolations whose current inputs are ORM UUID primary keys (cannot carry SQL syntax). They become live sinks if the input type ever changes.

## 4. Rejected (fp) categories — 1072 entries, with reasons

| Category | Count | Reason |
| --- | --- | --- |
| settings/config reads | 445 | operator-level configuration; `settings.LANGUAGE_CODE` does reach `get_child_edges` SQL text but is admin-authored (admin-config heuristic) |
| CLI options with no SQL path + `add_argument` registrations | 305 | command modules contain no dynamic SQL fed by these options; registration sites carry no data |
| constant-SQL `execute` sites (ETL staging, MVT, buffer, tasks, system_metadata, remover, updateproject, etl_template, graph publish/callproc) | 66 sql_text rows | literal SQL text with bound parameters — the companion bound_params rows are labeled sanitizer |
| non-SQL format/fstring/concat (cache keys, log messages, print diagnostics, openpyxl cell writes, bound-param value descriptions, error messages, DSN strings) | 33 | construction expressions that never reach a cursor as SQL text |
| ETL/datatype/ORM internal transfers | 73 | callees execute parameterized SQL only; celery `run_load_task` delegation is a task boundary, not attacker input |
| migration operations (`db/migration_operations/extras.py`) | 17 | identifiers from code-defined operation constructors; migration-file FP heuristic |
| `setup_db` interpolations | ~14 | settings.DATABASES/PG_SUPERUSER (admin config) and Django model metadata; CLI surface is only boolean `--force` |
| DB-derived UUID pk interpolations | 6 | UUID hex cannot carry SQL metacharacters (see §3 risk note) |
| env reads, non-handler params (celery tasks, sample function), non-SQL file reads, dead request input (`depth_limit`, overwritten at `views/concept.py:116`) | rest | no attacker→SQL-text data flow |

## 5. Sanitizers (proven) — 50

- **Bound-parameter channels** (44 rows): every `cursor.execute(sql, params)` / `cursor.callproc(proc, [args])` companion row — values driver-escaped against `%s` placeholders. This is the dominant safe pattern in the codebase (entire ETL pipeline, MVT, buffer, ETL manager).
- **`uuid.UUID` validation** (`models/concept.py:503`) — neutralizes the conceptid slot for `get_child_edges` callers (concept view route param, paged_dropdown conceptid, concept-search `removechildren`). Explicitly does **not** cover the `query` parameter (Flow A) nor `get_e55_domain` (Flow B).
- **Numeric casts** — `int()` (paged_dropdown page), `float()` (buffer width ×2).
- **GEOSGeometry re-parse → WKB hex binding** (buffer geometry ×2, confidence 0.7).

Not credited as sanitizers (per review criteria): auth decorators (`@group_required("RDM Administrator")` on the concept report view — limits who, not what), CSRF middleware, HTML escaping, `replace()` calls, and the empty-string check on `query` at `views/concept.py:384`.

## 6. Coverage & dedup record

2130/2130 CSV rows dispositioned (100%). 51 exact-duplicate rows merged with basis recorded (all 10 CSV columns identical); no distinct candidate was dropped. Test/fixture paths were already excluded at extraction; migration files that survived extraction (migration operations module, `0001_initial` fixture read) were dispositioned fp per the migration heuristic, with evidence retained.

## 7. Reviewer checklist (open items)

1. Confirm Flow A/B endpoint exposure in the deployment under test (are `/concepts/*` routes reachable without authentication in the target instance?).
2. Decide the operator-trust candidates (§3): accept as informational or reject as out-of-scope for remote-attacker threat models.
3. Confirm the `bound_params`-as-sanitizer convention for `MySanitizers.qll` generation (barrier at execute argument-1 nodes) before Phase 2 query generation.
4. Note for Phase 2: the keyword hand-off `query=query` at `views/concept.py:389` is handled by default interprocedural taint tracking; the summary entries (`get_child_edges`, `get_e55_domain`) are belt-and-suspenders.
5. `classification: unknown` is unused this run; no entry carries it.

**Status: labeling complete; awaiting human review approval before Phase 2 (Step 4 library generation).**
