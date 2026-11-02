# Phase 1 Review — Pass 5 (CWE-89 SQL Injection) — superset

Human review gate (advisory checkpoint, Augur WORKFLOW.md §4.5). This round covered Phase 1
Step 3 (LLM candidate labeling) only. No Phase 2 work (library generation, taint queries,
filtering, reporting) was started.

## 1. Run identity

- run_id: `superset-pass5-cwe89-20261021`
- model: **glm-5.3** — in-context labeling performed by the glm-5.3 agent session operating the
  Claude Code harness. No external LLM API calls were made; all decisions derive from code
  evidence read during this session (spot-verified against the source tree, which matches the
  CodeQL DB snapshot sha `2f468900` per `exploration/detection.json`).
- batches: 12 (B01–B12; scope and per-batch input row counts in `labels_raw_pass5.json`)
- candidates processed: **1742** (1445 `extraction/sources.csv` rows + 297 `extraction/sinks.csv`
  rows); 100% row coverage — every row is assigned to exactly one of **62 semantic groups**
  (dedup by channel-family × callable × flow-kind × provenance; multi-entry groups split rows
  by sub-rule), each group mapped to labeled entries. 66 pass-5 entries total
  (65 row-backed + 1 documented function-level sanitizer).

## 2. Label summary (pass 5)

66 entries after dedup (plus one empty pass-1 block present solely to satisfy the schema's
`passes contains pass_id=1` constraint — no pass-1 labeling was performed).

| role | entries | CSV rows covered |
| --- | --- | --- |
| source | 12 | 646 |
| sink | 24 | 160 |
| sanitizer | 2 | 14 (+ documented function-level) |
| summary | 17 | 339 |
| none | 11 | 583 |

Classifications: tp 45, fp 11, candidate 10, unknown 0. Schema validation against
`assets/labels_schema.json`: PASS (two independent structural checks implementing all
constraints incl. the `contains` rule; `jsonschema` was not installable offline).

## 3. Top sink APIs (highest value for Phase 2)

| entry | signature | class | conf | note |
| --- | --- | --- | --- | --- |
| p5-sink-005 | `BaseEngineSpec.execute` (query, param 2; hive @staticmethod shape param 1 → p5-sink-006) | tp | 0.95 | the universal raw-SQL funnel — `cursor.execute(query)` at base.py:1551, no binding |
| p5-sink-009/010 | `execute_sql_statement` (sql_statement, param 0) / `execute_sql_statements` (rendered_query, param 1) — sql_lab.py:194/375 | tp | 0.95 | SQL Lab execution entry points; rendered user SQL in, execution out |
| p5-sink-007 | `SqlJsonExecutor.execute` (rendered_query, param 2) | tp | 0.9 | sync/async executor API (sql_json_executer.py:52/87/160) |
| p5-sink-008 | `BaseEngineSpec.execute_with_cursor` (sql, param 2) | tp | 0.85 | trino override + `_execute` helper covered |
| p5-sink-004 | engine-spec adapter **call sites** (arg **1** — corrected from the CSV's arg 0) | tp | 0.85 | position-caveat reconciliation from detection.json |
| p5-sink-001/002 | `<obj>.execute` DBAPI cursor/conn/bind and legacy `engine.execute` call sites (arg 0) | tp | 0.9/0.85 | 27 + 9 rows across 14 + 5 files |
| p5-sink-017 | `pd.read_sql_query` (arg 0) | tp | 0.85 | compiled selects with `literal_binds=True` — dialect-escaped literals, not bound |
| p5-sink-011–013 | `select_star` (table_name, param 2/1/1) base/Database/REST handler | tp | 0.75–0.8 | request-derived path identifiers; dialect-quoted in base |
| p5-sink-015/016 | `get_text_clause` / `ExploreMixin.text` / `SqlaTable.text` (clause, param 1) | tp | 0.8 | TextClause factories — clause becomes raw SQL text (colon-escape only) |
| p5-sink-019–022 | engine-spec / query-builder f-string constructions | tp | 0.7–0.8 | see §5 |

## 4. Top source APIs

| entry | signature | class | conf | note |
| --- | --- | --- | --- | --- |
| p5-src-038–041 | `request.args/form/json/files/headers/cookies/data` (field) | tp | 0.8–0.9 | HTTP parse boundary (201 rows) |
| p5-src-043/044 | `request.<map>.get/getlist` (return) / keyed `request.form[...]` reads | tp | 0.9 | highest-signal accessor shapes (83 + 34 rows) |
| p5-src-040 | `request.json` | tp | 0.9 | feeds the SQL Lab `/execute/` flow (sqllab/api.py:300/308) |
| p5-src-045 | `kwargs['rison']` (field) | tp | 0.85 | FAB rison-injected query params (35 rows) — observed consumers end in ORM filters |
| p5-src-046 | @expose handler params (param) | tp | 0.8 | 135 rows; incl. the `select_star` route's `table_name/schema_name` path segments |
| p5-src-051 | `get_sql_results` celery task params (rendered_query, param 2) | tp | 0.75 | broker-mediated SQL-text boundary from the async `/execute/` flow |
| p5-src-047/052 | click CLI params / other celery task params | **candidate** | 0.5 | operator trust / mixed trust — see §7 |

## 5. Sanitizers (with evidence)

- **p5-san-030 — bound-parameter channel** (`execute` argument 1, 14 companion rows): tp, 0.85.
  `cursor.execute(sql, params)` with `params = {"schema": schema}` (presto.py:798/810 — the safe
  contrast to hive's backtick interpolation), trino.py:206, the importer/Core execute sites.
  Recommended `isBarrier` for pass 5. Caveat: on engine-spec adapter rows argument 1 is the SQL
  text (position caveat) — Phase 2 must use the corrected signatures, not the companion row.
- **p5-san-067 — `sanitize_clause` + `validate_adhoc_subquery`** (function-level, not
  row-backed): tp, 0.75. The SQL syntax-context guard applied to every ad-hoc
  WHERE/HAVING/custom-SQL clause before it reaches `self.text()`/`literal_column`
  (models/helpers.py:832-850 `_process_sql_expression`): sqlparse single-statement enforcement,
  paren-balance and comment checks (sql_parse.py:522-549), plus subquery rejection unless the
  `ALLOW_ADHOC_SUBQUERY` feature flag with RLS insertion (models/helpers.py:105-134). This is a
  genuine SQL-structural validation chain (not HTML escaping / simple replace). It does **not**
  escape quote characters — it is a statement-structure barrier, not a value escaper; treat as
  partial barrier and document in Phase 2. `SandboxedEnvironment` (jinja_context.py:448) is the
  template-injection barrier on the same path (recorded in the entry evidence).

## 6. Key semantic findings for pass 5

1. **The SQL Lab `/execute/` flow is a complete request→raw-SQL path — by design.**
   `request.json["sql"]` → `SqlJsonExecutionContext` (sqllab_execution_context.py:76) →
   `SqlQueryRenderImpl` Jinja render in a **SandboxedEnvironment** (query_render.py:61-64) →
   `SqlJsonExecutor.execute(..., rendered_query)` → `get_sql_results` (celery) →
   `execute_sql_statements` → `execute_sql_statement` → `BaseEngineSpec.execute` →
   `cursor.execute`. Marshmallow `ExecutePayloadSchema.load` result is **discarded**
   (validation-only, sqllab/api.py:300); protection is `@protect()` + post-render table-access
   validation (security/manager.py:1799-1869) + `allow_dml`/readonly gating (sql_lab.py:226).
   Labeled tp at the API/channel level; the threat model (authenticated SQL Lab users with
   database access) is a review-gate question, not a labeling question.
2. **The chart-data ad-hoc clause path reaches raw TextClauses.** form_data
   `extras["where"]/["having"]` and custom-SQL columns (charts/data/api.py:221/225 →
   `get_sqla_query`) become `self.text(...)`/`literal_column` fragments ANDed into the executed
   query (helpers.py:1904/1918/1922/1936, :1621) — guarded by `validate_adhoc_subquery` +
   `sanitize_clause` (§5) and `check_datasource_perms`/`raise_for_access`.
3. **Engine-spec adapters interpolate identifiers into executed SQL, with per-site quoting
   quality:** unquoted/under-quoted: hive `SHOW TABLES IN {schema} LIKE '{table}'` /
   `DROP TABLE IF EXISTS {table}` / `CREATE TABLE {table}` (CSV-upload form names, hive.py:199-234),
   hive `SHOW VIEWS IN \`{schema}\`` (:627), gsheets `SELECT GET_METADATA("{table_name}")`
   (REST path param, gsheets.py:117), presto `SHOW CREATE VIEW {schema}.{table}` (:1269), and the
   **CTAS path** `tmp_table_name` from request.json interpolated unquoted into
   `CREATE {method} {full_table_name} AS` (sql_parse.py:436-441, TODO-acknowledged;
   sql_lab.py:240-244) — candidate p5-cand-029; properly quoted: base `select_star`
   (`identifier_preparer.quote`, base.py:1399-1403), presto `_show_columns`
   (`quote_identifier`, presto.py:977-981); bound: presto `get_view_names` (%(schema)s, :794/810).
4. **Cancel-query f-strings are engine-derived (second-order), not request-controlled**:
   `KILL CONNECTION {id}` / `pg_terminate_backend ... WHERE pid='{id}'` etc. get their id from
   `SELECT CONNECTION_ID()`/`pg_backend_pid()` round-tripped through `query.extra`
   (sql_lab.py:461-463/630); request data (`client_id`) only performs an ORM `filter_by` lookup
   (daos/query.py:81). Sinks kept for the shape; no request-source path expected.
5. **The SQLAlchemy Core channel is bound-parameterized throughout**: tags.py, security/manager.py
   (21 sites), importers, dashboard cache-invalidation — Core constructs with `.values()` bound
   params; f-string tag names are bound **values**, never SQL text. `pd.read_sql_query` sites
   compile with `literal_binds=True` (dialect-escaped literal rendering, not bound) with
   column names constrained to dataset columns.
6. **`kwargs['rison']` and most @expose path params terminate in ORM `filter()/order_by()`**
   (base_api.py:595-599, order_column restricted to `order_rel_fields`) — sources are genuine
   input boundaries; no rison value reaches raw SQL text in this snapshot.
7. **Extraction name-collision noise identified and retained as `none`/fp**: 316
   `session.query(...)` ORM rows matched against the `SqlaTable.query` wrapper name
   (documented in detection.json uncoveredCases — the 5 genuine datasource `.query` call sites
   are labeled separately, p5-sum-054); non-SQL f-strings (benchmark script prints, importer
   `dataset_uid`, tag-name f-strings); `sqlparse.format` reformatting; error-message concats.

## 7. Unresolved / low-confidence items (manual review requested)

1. **SQL Lab threat model (p5-src-040/046, p5-src-051, p5-sink-005/007/009/010):** the
   request→cursor.execute path is real and labeled tp; whether executing authenticated users'
   SQL against databases they can access constitutes a vulnerability is a policy decision.
   Recommend the Phase 2 report classify SQL Lab alerts as "by-design feature flow" separately
   from injection findings.
2. **CTAS identifier path (p5-cand-029, conf 0.4):** `tmp_table_name`/`schema` from request.json
   interpolated unquoted (sql_parse.py:436-441, TODO). The .format row itself (sql_lab.py:237)
   builds from int user_id + timestamp, but the request-controlled branch
   (sqllab_execution_context.py:203) feeds the same unquoted construction. Needs a targeted
   manual look.
3. **CLI boundary (p5-src-047) and ORM-glue summaries (p5-sum-036/064, candidate 0.5):** operator
   trust; downgrade to fp if the CLI / importers are never exposed to untrusted callers.
4. **gsheets/presto identifier quoting (p5-sink-019, tp 0.75):** `SELECT GET_METADATA("{table}")`
   (gsheets.py:117) and `SHOW CREATE VIEW {schema}.{table}` (presto.py:1269) have no inner-quote
   escaping — reachable only via the table-browsing API with `@check_datasource_access`; confirm
   whether table-name characters are constrained upstream.
5. **`sanitize_clause` as barrier (p5-san-067):** structural guard only (no quote escaping) —
   decision needed on whether Phase 2 `isBarrier` should include it (recommendation: yes for
   statement-structure, no for value escaping; document both).

## 8. False positives identified (all evidence retained, none silently dropped)

- 316 `session.query` ORM name-collision rows (p5-none-053).
- 17 non-SQL f-string rows: benchmark script messages, importer `dataset_uid`, tag-name f-strings
  that are bound values (p5-none-024).
- 6 concat rows: SQL-expression concats in tags.py and an error message (p5-none-026).
- `sqlparse.format` reformatting (p5-none-028), `_normalize_prequery_result_type` (p5-none-034/066).
- Config/env/file-reader source rows (153/27/45): operator configuration or second-order import
  channels (imported dataset `sql` is stored and executed later — noted for the review gate).
- CLI/dev-script wrapper rows (encrypt/mock_data/benchmark, p5-none-037/065): metadata-derived
  identifiers on operator-only paths.

## 9. Constraints honored

- No PyVul ground truth was consulted: `sql_sinks.csv`, 漏洞审查报告.md and 漏洞补充报告.md at the
  superset_vuln repo root were **not opened** (only listed to be avoided); candidate labels derive
  only from repository code evidence, the loaded references (WORKFLOW.md, patterns.md, python.md,
  flask.md — django.md not loaded, no django imports in the tree) and the DB source snapshot.
- No modifications to the source tree, the CodeQL database, the original extraction results, or
  the Augur installation. Only `iris/labels/*` artifacts (plus the audit script
  `iris/diagnostics/gen_labels_pass5.py`) were written.
- Dedup policy and per-row group assignment recorded in `labels/labels_raw_pass5.json`
  (62 groups; sum of group rows = 1742 = CSV rows; no row dropped or double-assigned; every
  group's rows, distinct-file counts and sample locations preserved).
- All 1742 CSV candidates covered; role/classification statistics in `labels/label_stats.md`.

## 10. Recommendation

Proceed to Phase 2 after resolving §7 items 1 (SQL Lab threat model), 2 (CTAS identifier path)
and 5 (sanitize_clause barrier scope). With the current labels the pass-5 taint query will
exercise: the SQL Lab request→render→execute chain, the chart-data ad-hoc clause path (with the
sanitize_clause barrier candidate), the select_star/CTAS identifier constructions, and the
engine-spec execute funnels — while the session.query/config/env noise families are already
excluded at the label level. Expected outcome: moderate alert volume dominated by the by-design
SQL Lab flow, with the identifier-construction sites as the highest-value manual triage targets.
