# Phase 1 Review — Pass 5 (CWE-89 SQL Injection) — django

Human review gate (advisory checkpoint, Augur WORKFLOW.md §4.5). This round covered Phase 1
Step 3 (LLM candidate labeling) only. No Phase 2 work (library generation, taint queries,
filtering, reporting) was started.

## 1. Run identity

- run_id: `django-pass5-cwe89-20261020`
- model: **glm-5.3** — in-context labeling performed by the glm-5.3 agent session operating the
  Claude Code harness. No external LLM API calls were made; all decisions derive from code
  evidence read during this session.
- batches: 12 (B01–B12; scope and per-batch input row counts in `labels_raw_pass5.json`)
- candidates processed: **3217** (2609 `extraction/sources.csv` rows + 608 `extraction/sinks.csv`
  rows); 100% row coverage — every row is assigned to exactly one of 41 semantic groups
  (dedup by module-family × callable-role × flow-kind), each group mapped to labeled entries.

## 2. ⚠ Critical scope finding for the reviewer

**The audit target tree and the CodeQL database disagree on Django version.**

- The on-disk source tree at
  `dataset/codeql_databases/sql_injection_dbs/django_vuln` is **stock Django 2.2.4**
  (`git 8687fbe034a`, clean except untracked ground-truth artifacts and `django-db/`).
- The CodeQL database `django-db` was built from sha `eb3699e` and its `src.zip` snapshot is
  **Django 4.2.0-alpha0** (`django/__init__.py VERSION = (4, 2, 0, "alpha", 0)`; includes
  `django/core/cache/backends/redis.py`, which does not exist in 2.2.4).
- All extraction CSV file/line references match the **snapshot**, not the tree (spot-verified:
  `createcachetable.py:120/127`, `utils.py:66–107`, `compiler.py:1395/1657`, `query.py:1284/1670/1995`,
  `expressions.py:1049`, `sql/query.py:85/152`). Several CSV lines point beyond the tree files' EOF
  (e.g. `createcachetable.py` is 108 lines in the tree vs 130 in the snapshot).
- Consequently **all labeling evidence was verified against the DB snapshot (`src.zip`)**, and all
  file:line references in `labels.json` use snapshot numbering. `exploration/detection.json`'s claim
  that the tree and DB snapshot are the same source is incorrect and should be corrected before
  Phase 2, since Phase 2 taint queries will run against `django-db` (4.2.0-alpha0) while any
  tree-based reading would describe 2.2.4 code.

## 3. Label summary (pass 5)

56 entries after dedup (plus one empty pass-1 block present solely to satisfy the schema's
`passes contains pass_id=1` constraint — no pass-1 labeling was performed).

| role | entries | CSV rows covered |
| --- | --- | --- |
| source | 13 | 1116 |
| sink | 16 | 252 |
| sanitizer | 2 | 96 (+ documented) |
| summary | 12 | 667 |
| none | 13 | 1086 |

Classifications: tp 37, fp 13, candidate 6, unknown 0. Schema validation against
`assets/labels_schema.json`: PASS (structural check implementing all constraints, including the
`contains` rule; `jsonschema` was not installable offline).

## 4. Top sink APIs (highest value for Phase 2)

| entry | signature | class | conf | note |
| --- | --- | --- | --- | --- |
| p5-sink-002/003 | `CursorWrapper.execute/executemany` (django.db.backends.utils, param 1) | tp | 0.95/0.9 | central PEP-249 funnel every backend goes through |
| p5-sink-001 | `<obj>.execute` call sites (arg 0) | tp | 0.9 | 220 rows across 46 files — the raw-SQL execution channel |
| p5-sink-013 | `QuerySet.raw` (raw_query, param 1) | tp | 0.9 | public raw-SQL API; **no non-test call sites in snapshot** |
| p5-sink-014 | `QuerySet.extra` (fragments 1/2/4/5) | tp | 0.85 | SQL-fragment injection API |
| p5-sink-015–017 | `RawSQL`/`RawQuery`/`RawQuerySet.__init__` (sql, param 1) | tp | 0.85 | raw-SQL object APIs |
| p5-sink-019 | `BaseDatabaseSchemaEditor.execute` (sql, param 1) | tp | 0.85 | DDL funnel for migrations |
| p5-sink-006–011 | sqlite3/mysql/oracle driver cursor wrappers (param 1) | tp | 0.85 | driver-level execute/executemany |
| p5-sink-004 | `CursorWrapper.callproc` (procname, param 1) | tp | 0.75 | stored-proc name is SQL structure |

Backend wrapper glue (`_execute`, `execute_sql`, `RawQuery._execute_query`) and the DDL/
introspection/creation/migration families are labeled **summary** so Phase 2 flows connect
through the framework layers.

## 5. Top source APIs

| entry | signature | class | conf | note |
| --- | --- | --- | --- | --- |
| p5-src-037–041 | `request.GET/POST/META/COOKIES/FILES` (field) | tp | 0.8–0.9 | HTTP parse boundary (149 rows) |
| p5-src-042/043 | WSGI `environ` / `get_bytes_from_wsgi` | tp | 0.85–0.9 | lowest-trust boundary |
| p5-src-044 | `request.<map>.get/getlist` (return) | tp | 0.9 | highest-signal shape (52 rows) |
| p5-src-046 | handler `request` parameter (param) | tp | 0.85 | 631 rows / 323 framework handlers |
| p5-src-047 | `self.kwargs` URL route params (field) | tp | 0.8 | 30 rows |
| p5-src-048/050 | CLI `options` reads / `sys.argv` | **candidate** | 0.5 | operator-level trust — see §7 |

## 6. Sanitizers (with evidence)

- **p5-san-035 — bound-parameter channel** (`execute` params argument, arg 1 / param 2): tp, 0.85.
  Values passed via `params` are substituted by the driver and cannot alter SQL text
  (`utils.py:66–94`, `compiler.py:1395`, `cache/backends/db.py:143–196`). Recommended `isBarrier`
  for pass 5.
- **p5-san-036 — `quote_name`**: **candidate, 0.4**. Verified implementations
  (sqlite3/postgresql `'"%s"' % name`, mysql `` '`%s`' % name`` — sqlite3/operations.py:189–192)
  do **not** escape embedded quote characters. Safe only for framework-controlled identifier
  character sets; explicitly not trusted as a general barrier. Requires human confirmation
  before being used as `isBarrier` in Phase 2 (recommendation: do **not** treat it as a barrier;
  keep it as documentation only).

## 7. Unresolved / low-confidence items (manual review requested)

1. **CLI boundary (p5-src-048, p5-src-050, p5-sum-029, p5-sum-033 — 6 `candidate` entries):**
   management-command input (`options`, `sys.argv`, `call_command`) is a real input boundary but
   operator-trusted (manage.py runs with DB credentials). The only injection-shaped consumer is
   `createcachetable` (CLI tablename → quote_name'd DDL % interpolation). Confirm threat model:
   if the CLI is never exposed to untrusted callers, these can be downgraded to fp.
2. **Second-order DB-derived identifiers (p5-sum-021, p5-sum-024):** introspection/PRAGMA SQL is
   %-built from `table_name` values that originate from DB introspection itself. quote_name (no
   quote escaping) is the only protection. Worth a targeted manual look if DB content can be
   attacker-influenced (e.g. table names created from user data via migrations).
3. **quote_name as sanitizer** (§6) — decision needed.
4. **Version mismatch (§2)** — resolution needed before Phase 2.

## 8. False positives identified (all evidence retained, none silently dropped)

- Method-name collisions with `cursor.execute`: CLI `BaseCommand.execute`/`ManagementUtility.execute`
  (management/__init__.py:198/446, base.py:402, runserver.py:74, createsuperuser.py:88,
  sqlmigrate.py:38) and Redis `pipeline.execute()` (redis.py:148).
- Error-message string constructions matched by the `sql_percent_format`/`sql_fstring` families
  (management/__init__.py:116/165/185, base.py:411, sql/query.py:149).
- `parser.add_argument` registrations (source-side, 179 rows) and `sqlite3/_functions.register`.
- Framework test infrastructure (`django/test/testcases.py` `_reset_sequences`) — test-only
  reachability.
- `settings`/`os.environ`/`open`/`read` source rows (499/57/36/65): operator-config or non-SQL
  channels for pass 5 (fixture file content reaches the ORM as bound parameters).

## 9. Key semantic conclusions for pass 5

1. **No framework request path feeds raw SQL text in this snapshot.** Request-derived values
   (admin ChangeList `request.GET` filters/search/ordering — validated by form + `int()` parsing
   and `to_field_allowed`, auth views, generic views) flow into ORM `filter()/order_by()` channels
   that compile to parameterized SQL (`compiler.py:1395 cursor.execute(sql, params)`).
2. The genuinely dangerous **API surface** (`QuerySet.raw/extra`, `RawSQL`, `RawQuery(RawQuerySet)`,
   `CursorWrapper.execute(sql)`) is real and labeled tp — it exists for framework *users*; no
   in-framework call site passes request data into it.
3. Dynamic SQL inside the backends is built from quote_name-quoted identifiers, settings/DB-derived
   names, or CLI input (operator/DB trust) — recorded as summary/fp families with per-site evidence.
4. `CursorWrapper` internals note: `SQLiteCursorWrapper.convert_query` and Oracle
   `_fix_for_params` are placeholder-syntax conversions, **not** taint barriers for SQL text.

## 10. Constraints honored

- No PyVul ground truth was consulted: `sql_sinks.csv`, `sql_sinks_new.csv`,
  `enhanced_sql_sinks.csv`, `sql_injection_audit_report.md` (all present, untracked, at the repo
  root) were **not opened**; candidate labels derive only from repository code evidence, the
  loaded references (WORKFLOW.md, patterns.md, python.md, django.md) and the DB source snapshot.
- No modifications to the source tree, the CodeQL database, the original extraction results, or
  the Augur installation. Only `iris/labels/*` artifacts (plus the audit script
  `iris/diagnostics/gen_labels_pass5.py`) were written.
- Dedup policy and per-row group assignment recorded in `labels/labels_raw_pass5.json`
  (41 groups; sum of group rows = 3217 = CSV rows; no row dropped or double-assigned).

## 11. Recommendation

Proceed to Phase 2 **after** resolving §7 items 1 and 4 (CLI threat model; tree vs DB version),
and treating `quote_name` as documentation-only (not a barrier). With the current labels, the
pass-5 taint query will exercise the request → ORM(parameterized) paths and the raw-SQL API
surface; expected outcome is low alert volume with genuine API coverage.
