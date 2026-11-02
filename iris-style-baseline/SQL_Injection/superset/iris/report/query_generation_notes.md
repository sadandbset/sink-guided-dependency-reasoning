# Query Generation Notes — Pass 5 (CWE-89 SQL Injection) — Step 4–5

Augur Phase 2, Step 4 (generate CodeQL libraries) and Step 5 query file (generation only —
per the task contract nothing was compiled, executed, or run against the database in this
round; a brace/paren-balance and forbidden-pattern sanity check over all five QL files passed,
`diagnostics/ql_sanity_check.py`).

Generated files:

- `iris/libraries/MySources.qll` — `MySources::isSource(node, passKey)`
- `iris/libraries/MySinks.qll` — `MySinks::isSink(node, passKey)`
- `iris/libraries/MySanitizers.qll` — `MySanitizers::isBarrier(node, passKey)`
- `iris/libraries/MySummaries.qll` — `MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, passKey)`
- `iris/queries/Pass5_SQLInjection.ql` — `py/augur/superset/pass5-sql-injection`
  (`@kind path-problem`, `@problem.severity error`, `@tags security`,
  `external/cwe/cwe-089`)

All four libraries and the query use pass key `"sql_injection"` and the modular data-flow
API: `DataFlow::ConfigSig`, `TaintTracking::Global<Pass5Config>`,
`import Pass5Flow::PathGraph`, `flowPath(source, sink)`. `qlpack.yml`
(`iris/superset-cwe89`, dependency `codeql/python-all: "*"`) already sits at the iris root,
so `import libraries.MySources` etc. resolve from `iris/libraries/` and `iris/queries/`.

## 0. Review-gate status and evidence basis

- `labels/review_decision.json` does **not** exist (Phase 1's checkpoint is advisory per
  WORKFLOW.md §4.5, and the Phase 1 round chose not to fabricate it). Per this round's
  instruction, the Pass 5 labels in `labels/labels.json` are treated as the approved
  review outcome. **No label was modified in this round**; every modeling decision below
  cites its label id. Items the Phase 1 review left open (`labels/phase1_review.md` §7)
  are handled conservatively (see §1 "not modeled" entries and §5) rather than by editing
  labels.
- All file:line evidence refers to the **on-disk source tree at
  `dataset/codeql_databases/sql_injection_dbs/superset_vuln`**, which matches the CodeQL
  DB snapshot (sha `2f468900`, per `exploration/detection.json`); the extraction CSV line
  numbers were spot-verified against this tree during Phase 1. The query will run against
  `superset-db`, i.e. the same snapshot the labels describe.
- No PyVul ground truth (`sql_sinks.csv`, `漏洞审查报告.md`, `漏洞补充报告.md` at the repo
  root), fix diffs, or CVE announcements were consulted. Modeling derives only from the
  approved Pass 5 labels and direct source reading of the snapshot (same isolation
  principle as the earlier command-injection and SSRF experiments and the django CWE-89
  run of this series: independent labeling, formal results computed independently, ground
  truth touched only by the later evaluation step, never during model construction).
- API compatibility: the AST/dataflow shapes used are the ones already exercised in this
  project's Phase 1 extraction queries (`sources.ql`/`sinks.ql`), which were written
  against the local pack `codeql/python-all 7.1.x` (CodeQL CLI 2.25.1) and reuse the
  structural shapes proven in the django CWE-89 series run: `AstNode.getLocation().
  getFile().getAbsolutePath()`, `Call.getFunc()/getPositionalArg()/getAKeyword()`,
  `Attribute.getName()/getObject()`, `Subscript.getObject()/getIndex()`,
  `StringLiteral.getText()`, `Function.getAnArg()/getADecorator()`,
  `Parameter.getName()/isSelf()/getPosition()`, `Keyword.getArg()/getValue()`,
  `DataFlow::Node.asExpr()` and module-qualified `DataFlow::parameterNode(Parameter)`.
  The config/flow shape (`module X implements DataFlow::ConfigSig` with
  `isSource/isSink/isBarrier/isAdditionalFlowStep`, then
  `module F = TaintTracking::Global<X>` with `F::PathNode`/`F::flowPath`) mirrors the
  pack's canonical dataflow queries. `bindingset` annotations are used for the string
  parameters of the `matches()`-based helper predicates (the django compile check showed
  QL string primitives do not bind their operands). Not used (avoided per the Phase 1
  compatibility notes): deprecated `StrConst`, a `Decorator` AST class, `AstNode.getFile()`
  (does not exist), `module` as a variable name. No `API::Node` values are assigned to
  `DataFlow::Node` variables and no QL classes are left unbound; every helper keeps its
  variables bound through positive bodies. Per this round's contract,
  `codeql query compile` was **not** run — a full compile check is the first action of
  the execution round.
- Path patterns assume the forward-slash absolute paths stored in this CodeQL database
  (verified against the extraction CSVs). If a future rebuild stores Windows backslash
  paths, the `matches()` patterns in the four libraries need a backslash variant added.

## 1. Label id → QLL predicate mapping

### MySources (`isSource`; all modeled labels are classification tp)

| label id | modeled node | QL class in `MySources` | evidence |
| --- | --- | --- | --- |
| p5-src-038 | `request.args` field read | `RequestFieldRead` | 61 sites across the API layer |
| p5-src-039 | `request.form` field read | `RequestFieldRead` | 70 sites; charts/data/api.py:225 |
| p5-src-040 | `request.json` field read | `RequestFieldRead` | 52 sites; sqllab/api.py:300/:308 (SQL Lab /execute/) |
| p5-src-041 | `request.files/headers/cookies/data` reads | `RequestFieldRead` | 14 sites; sqllab/api.py:306 USER_AGENT |
| p5-src-042 | `request.<field>.to_dict()/items()` results | `RequestWholeMappingCall` | utils/cache.py:93, utils/log.py:50/:52, views/sql_lab/views.py:221 |
| p5-src-043 | `request.<field>.get()/getlist()` results | `RequestAccessorCall` | 83 sites; views/utils.py:165-166 |
| p5-src-044 | `request.<field>[...]` keyed reads | `RequestSubscriptRead` | 34 sites; charts/api.py:1098 |
| p5-src-045 | `kwargs["rison"]` / `kwargs.get("rison")` | `RisonKwargsRead` | 35 sites; views/base_api.py:574, sqllab/api.py:241 |
| p5-src-046 | non-self params of @expose / @app.route handlers | `ExposeHandlerParam` | 135 rows; databases/api.py:811 (select_star table_name), sqllab/api.py:138 (client_id) |
| p5-src-051 | params of the `sql_lab.get_sql_results` celery task (rendered_query at 2) | `CeleryGetSqlResultsParam` | sql_lab.py:156-172; broker boundary reached via .delay (sql_json_executer.py:169-178) |

Not modeled, with reasons (labels unmodified):
- **p5-src-047 (click CLI parameters)** — classification `candidate`; operator-level input
  (the CLI runs with DB credentials; no CLI argument reaches SQL text — verified during
  Phase 1: re_encrypt_secrets passes only the key, set_database_uri stores a URI,
  import commands pass file paths). Stays out of `isSource`; can be re-enabled after a
  fresh human review of the CLI threat model.
- **p5-src-052 (other celery task params)** — classification `candidate`; mixed trust
  (thumbnail tasks pass int ids; cache warmup passes stored second-order payloads;
  fetch_url triggers internal HTTP). Only `get_sql_results` carries SQL text.
- **p5-none-048..053** — `current_app.config`/`app.config`, `os.environ`, `open()`/`read()`
  (second-order import bundles, operator/import-API gated), 316 `session.query` ORM rows
  (name-collision artifact of the extraction), non-SQL internal wrappers — all fp.

**External boundary and controllable range:** every modeled source is externally
attacker-influenced — the raw Flask request state (query string, form bodies, JSON bodies,
files, headers, cookies), FAB route path variables / handler parameters (URL segments such
as `/<int:pk>/select_star/<path:table_name>/`), the rison-decoded query structure injected
into handler kwargs, and the celery broker payload of the SQL Lab execution task. **No
parameter of a function that merely contains a `cursor.execute` call is a source**; taint
must originate at one of the boundaries above. From a tainted `request.<field>` mapping,
standard local flow additionally covers subscript/`.get()` reads not individually
extracted; the accessor/subscript source classes make the key positions explicit anyway.

### MySinks (`isSink`)

**Call-site sinks** — receiver-name discrimination over the audited execute-layer file
universe (the union of the Phase 1 groups G-S01..G-S04; the Phase 1 extraction matched
*all* `<obj>.execute` calls in scope, so this universe is exactly the audited one, and the
labeled fp name-collisions — 316 `session.query` ORM rows, CLI dispatch, non-SQL
f-strings — fall outside by construction):

| label id | API / receiver | dangerous arg | QL class | evidence |
| --- | --- | --- | --- | --- |
| p5-sink-001 | `cursor.execute` / `conn.execute` / `bind.execute` (DBAPI + raw connection + inspector bind) | positional **arg 0** (SQL text) | `RawExecuteSqlTextArgument` | base.py:1551 `cursor.execute(query)`; mysql.py:297 KILL f-string; gsheets.py:117 GET_METADATA f-string; presto.py:810 `execute(sql, params)`; encrypt.py:125/:174 |
| p5-sink-002 | `engine.execute` / `db.engine.execute` (legacy Engine) | positional **arg 0** | `RawExecuteSqlTextArgument` | hive.py:210 `engine.execute(f"DROP TABLE IF EXISTS {str(table)}")`; mock_data.py:287 |
| p5-sink-003 | `session.execute` / `connection.execute` (SQLAlchemy Core) | positional **arg 0** (statement construct) | `CoreExecuteArgument` | tags.py:56, security/manager.py:1157-1161, importers — bound-parameter Core channel; sink kept for recall because a raw string here executes as SQL text |
| p5-sink-004 | `db_engine_spec.execute(cursor, sql)` / `cls.execute(cursor, sql, async_)` / `_sql_json_executor.execute(ctx, rendered_query, log_params)` | positional **arg 1** (CORRECTED — CSV reported arg 0) | `EngineSpecAdapterSqlArgument` | models/core.py:598/:608/:611; base.py:1070; execute.py:156 |
| p5-sink-017 | `pd.read_sql_query(...)` | positional **arg 0** or `sql=` keyword | `ReadSqlQueryStatement` | connectors/sqla/models.py:170/:817, models/helpers.py:1365 (compiled with literal_binds) |

**Definition-side sinks** — the SQL-text / SQL-fragment parameters of the project's own SQL
channel APIs (matched by function name + parameter name + file, mirroring the Phase 1
`sql_api_def` family; positions in the table are the audited ones incl. the self/cls slot):

| label id | API definition | dangerous param (pos) | QL class | evidence |
| --- | --- | --- | --- | --- |
| p5-sink-005 | `BaseEngineSpec.execute` (base.py:1531) / `ImpalaEngineSpec.execute` (impala.py:92) | `query` (2) | `SqlTextDefinitionParameter` | body: `cursor.execute(query)` at base.py:1551 — no binding |
| p5-sink-006 | `HiveEngineSpec.execute` (hive.py:544, @staticmethod) | `query` (1) | `SqlTextDefinitionParameter` | body: `cursor.execute(query, **kwargs)` at hive.py:548 |
| p5-sink-007 | `SqlJsonExecutor.execute` / Synchronous / ASynchronous (sql_json_executer.py:52/:87/:160) | `rendered_query` (2) | `SqlTextDefinitionParameter` | forwarded to `get_sql_results` → `execute_sql_statements` |
| p5-sink-008 | `BaseEngineSpec.execute_with_cursor` (base.py:1057) / Trino override (trino.py:189) | `sql` (2) | `SqlTextDefinitionParameter` | body: `cls.execute(cursor, sql, async_=True)` at base.py:1070 |
| p5-sink-009 | `sql_lab.execute_sql_statement` (sql_lab.py:194) | `sql_statement` (0) | `SqlTextDefinitionParameter` | drives `execute_with_cursor` at sql_lab.py:274 |
| p5-sink-010 | `sql_lab.execute_sql_statements` (sql_lab.py:375) | `rendered_query` (1) | `SqlTextDefinitionParameter` | splits statements (:407-414) → execute_sql_statement |
| p5-sink-015 | `BaseEngineSpec.get_text_clause` (base.py:548) | `clause` (1) | `SqlTextDefinitionParameter` | returns `text(clause)` (:557); colon-escape only |
| p5-sink-016 | `ExploreMixin.text` (helpers.py:1077) / `SqlaTable.text` (models.py:1095) | `clause` (1) | `SqlTextDefinitionParameter` | delegate to `get_text_clause`; feed ad-hoc WHERE/HAVING, RLS, virtual-dataset FROM |
| p5-sink-011 | `BaseEngineSpec.select_star` (base.py:1363; bigquery:631/hive:475/presto:1071 overrides) | `table_name` (2) / `schema` (4) | `SelectStarIdentifierParameter` | `text(quote(schema)+"."+quote(table_name))` at base.py:1399-1405 |
| p5-sink-012 | `Database.select_star` (models/core.py:637) | `table_name` (1) / `schema` (2) | `SelectStarIdentifierParameter` | forwards to the engine spec at models/core.py:649 |
| p5-sink-013 | `DatabaseRestApi.select_star` handler (databases/api.py:811) | `table_name` (1) / `schema_name` | `SelectStarIdentifierParameter` | URL path segments, @protect + @check_datasource_access |

**Construction-node labels get no dedicated sink classes** (documented mapping):
- p5-sink-019/020/021 (engine-spec f-strings) and p5-sink-023/025 — the f-string/concat
  expressions are the **argument-0 expressions of the execute calls** above, so taint
  embedded by interpolation is caught at the execution sink (e.g. mysql.py:297
  `cursor.execute(f"KILL CONNECTION {cancel_query_id}")` → `RawExecuteSqlTextArgument`;
  base.py:1401 `quote(schema)+"."+quote(table_name)` flows into `text(full_table_name)`
  and onward from the select_star identifier parameter).
- p5-sink-022 (query-builder clause f-strings) — flow into `self.text(...)` /
  `get_text_clause(...)` / `literal_column(...)`, caught by the p5-sink-015/016 definition
  parameters; the `process_template` taint edge (MySummaries §1.4) carries the rendered
  fragment.
- p5-cand-027/029 (classification candidate) — no dedicated sink; the CTAS
  `tmp_table_name` path is nevertheless traced by the MySummaries edges (see §1.4) up to
  `as_create_table` whose result feeds the SQL Lab funnel.

**Bound-parameter channels are never sinks**: positional argument 1 / keyword values of
`cursor/conn/bind/engine/session/connection` execute calls are the MySanitizers barrier;
on the adapter sites (`db_engine_spec/cls/_sql_json_executor`) argument 1 is the SQL-text
sink (p5-sink-004), never a bound value — the position caveat from
`labels.json` metadata / detection.json is reconciled exactly this way.

### MySanitizers (`isBarrier`)

| label id | barrier node | QL class | evidence |
| --- | --- | --- | --- |
| p5-san-030 (tp 0.85) | positional arg 1 of cursor/conn/bind/engine execute (DBAPI `parameters` / Engine params) and of session/connection execute (Core executemany `values`), plus keyword values of session/connection/engine execute (SQLAlchemy bound-value keywords) | `BoundParameterArgument` | presto.py:810 `cursor.execute(sql, params)` with `params = {"schema": schema}` (:798 — the safe contrast to hive's backtick interpolation); dashboards importer :149 `session.execute(insert, values)`; tags.py:225-229 `db.session.execute(insert, name=..., type=...)`; mock_data.py:210; hive.py:232-239 `location=` |

Parameter binding is the only sanitizer modeled as a barrier because it is the only one
with proof in this code base: values substituted by the driver / SQLAlchemy compilation
cannot alter SQL text. The barrier applies **only** to the bound-value channel — it never
blocks the SQL-text argument (argument 0 of the same calls is the sink) and never blocks
the adapter argument 1 (excluded receivers).

**Deliberately NOT barriers** (labels unmodified, decisions documented):
- **p5-san-067 (`sanitize_clause` + `validate_adhoc_subquery`, tp 0.75)** — verified
  structural guard (sql_parse.py:522-549 single-statement/paren/comment checks;
  helpers.py:105-134 subquery rejection unless `ALLOW_ADHOC_SUBQUERY`; applied at
  helpers.py:832-850 `_process_sql_expression`). Its own label rationale records that it
  does **not** escape quote characters — it is a statement-structure guard, not a value
  escaper. Modeling it as `isBarrier` would suppress genuine alerts where an ad-hoc clause
  passes the structural check and still injects SQL syntax, so per the Phase 1 review
  recommendation it is documentation-only. Taint that survives the guard still flows into
  the `self.text`/`literal_column` fragment sinks.
- **Jinja `SandboxedEnvironment`** (jinja_context.py:448) — constrains template *code*,
  not the rendered SQL text; the template text passes verbatim into the output
  (jinja_context.py:458-469), so it is not a barrier (and the render propagation is
  explicitly modeled in MySummaries).
- **Identifier quoting** — `engine.dialect.identifier_preparer.quote`
  (base.py:1399-1403) and `quote_identifier` (presto.py:977) wrap identifiers without
  escaping embedded quote characters. Consequence, matching the task's modeling rule: a
  tainted table name / schema name / ORDER BY-like fragment that is interpolated into SQL
  structure still flows into the `select_star` identifier sinks and raises an alert —
  binding does not protect dynamic SQL structure.

### MySummaries (`isAdditionalTaintStep`) — four evidence-backed edge families

The Python data-flow library does not track cross-method object field flow, ORM-model
fields, or external Jinja rendering, so the audited SQL Lab pipeline would be disconnected
without these edges. Each edge was verified against the snapshot and scoped by file+name:

| edge | from → to | necessity / evidence |
| --- | --- | --- |
| (1) `executionContextFieldFlow` | `query_params` param of `SqlJsonExecutionContext.__init__` / `_init_from_query_params` / `CreateTableAsSelect.create_from` (sqllab_execution_context.py:66/:71/:198) → audited context-field reads (`self.sql` etc. in the class file; `execution_context.<field>` / `self._execution_context.<field>` in superset/sqllab/**) | The constructor stores `query_params.get("sql")`… into instance fields (:72-97, :199-209); the command layer reads them cross-method (create_query :169-196, execute.py:127-129/:164, query_render.py:63). Field set = exactly the fields stored from query_params (`query` excluded — set via set_query from the ORM model). |
| (2) `queryModelFieldFlow` | `sql`/`schema`/`tmp_table_name`/`tmp_schema_name` keyword values of the `Query(...)` constructor in create_query (sqllab_execution_context.py:169-186) → matching `.sql` reads in query_render.py / `.tmp_table_name`/`.tmp_schema_name`/`.schema` reads in sql_lab.py | ORM-model fields are not tracked; the render step reads `query_model.sql` back (query_render.py:62) and the CTAS branch reads `query.tmp_table_name` (sql_lab.py:235-244). Connects the audited CTAS candidate path (p5-cand-029) up to `as_create_table`. |
| (3) `parsedQueryFlow` | (3a) argument 0 of `ParsedQuery(...)` constructor calls → `.stripped()` / `.get_statements()` / `.as_create_table()` call results; (3b) `as_create_table(table_name, schema_name=…)` own arguments → its result | `ParsedQuery` (sql_parse.py) stores the parsed statements; `.stripped()` (sql_lab.py:219, query_render.py:62) and `.get_statements()` (sql_lab.py:407-414) rebuild the SQL text; `as_create_table` interpolates `f"{schema_name}.{table_name}"` and the stripped SELECT **unquoted** into `CREATE {method} {full_table_name} AS` (sql_parse.py:436-441, TODO-acknowledged). Method names are distinctive to ParsedQuery. |
| (4) `templateRenderFlow` | argument 0 and keyword values of `process_template(...)` calls → the call result | `BaseTemplateProcessor.process_template(sql, **kwargs)` (jinja_context.py:458-469): `template = self._env.from_string(sql); kwargs.update(self._context); return template.render(context)` — the template text passes verbatim into the rendered output and kwarg values are substituted into it; `NoOpTemplateProcessor.process_template` returns the sql unchanged (:495-497). jinja2 is external to this database, so `.render()` propagation is not modeled by default. Connects the SQL Lab render (query_render.py:61-64) and the ad-hoc clause renders (helpers.py:1904/:1922). |

Summary labels that intentionally get **no** extra edge (standard interprocedural argument
flow already connects them, and the definition-side sinks fire at the API boundary —
adding edges would establish unconditional propagation the source code does not warrant):
p5-sum-014 (apply_limit_to_sql — ordinary return flow), p5-sum-018 (TextClause construction
call sites — argument flow into the p5-sink-015/016 parameters), p5-sum-031 (engine-spec
metadata wrappers), p5-sum-032 (query-builder wrappers), p5-sum-033/035/036 (cache
invalidation / cancel-query / ORM-glue wrappers — terminate in bound-parameter Core
execution or engine-derived ids), p5-sum-054..062 (the call-site hand-off families:
datasource `.query`, `select_star`, `apply_limit_to_sql`, `get_df`, the SQL Lab funnel,
estimate, metadata and query-builder call sites). The celery `.delay` dispatch needs no
edge either: the `get_sql_results` task parameters are modeled directly as a **source**
(p5-src-051), which is the broker boundary.

## 2. Dynamics: construction, identifiers, ORDER BY, ORM, binding

- **f-strings / %-formatting / concatenation / .format()** are not sinks by themselves
  (labels p5-none-024/026/028 document the non-SQL noise). Taint through string
  interpolation is standard CodeQL propagation, so a tainted identifier or clause
  embedded via an f-string reaches the execute-family SQL-text argument sinks
  (`RawExecuteSqlTextArgument` / `EngineSpecAdapterSqlArgument`) at the point of
  execution — e.g. hive.py:199-210 (CSV-upload table/schema), gsheets.py:117,
  presto.py:1269, mysql.py:297.
- **Identifiers / ORDER BY-like structure**: request-derived identifiers enter through
  the `select_star` route path variables (source p5-src-046 → sinks p5-sink-011/012/013)
  and the CTAS `tmp_table_name`/`schema` from request.json (via the MySummaries (1)+(2)
  edges into `as_create_table`, sql_parse.py:436-441 **unquoted**). Downstream dialect
  quoting exists on the select_star path (base.py:1399-1403) but is deliberately **not**
  a barrier (§1 MySanitizers): identifier taint still alerts. The ad-hoc ORDER BY of the
  chart-data path goes through ORM `order_by()` (parameterized) per Phase 1 finding 6 and
  does not reach raw SQL text.
- **ORM vs raw channels are modeled per their real execution semantics**:
  `session.query(...)/filter()/order_by()` (the 316 name-collision rows, label p5-none-053)
  is not a source or sink — it compiles to parameterized SQL. The Core
  `session/connection.execute` channel is a sink at argument 0 with the values/keywords as
  the bound barrier (p5-sink-003 + p5-san-030). The genuinely raw channels — DBAPI
  `cursor.execute` argument 0, the engine-spec adapter argument 1, the legacy
  `engine.execute` argument 0, `pd.read_sql_query` (literal_binds-compiled text), the
  project's SQL-text API definitions — are the modeled sinks.
- **SQLAlchemy `text()` / TextClause** construction is modeled by its real semantics: the
  `text`/`get_text_clause`/`ExploreMixin.text`/`SqlaTable.text` **definitions** are
  fragment-entry sinks (p5-sink-015/016 — the clause becomes raw SQL text of a TextClause
  compiled into executed queries), while the 21 construction call sites (p5-sum-018) need
  no edge because the argument flows into those parameters by ordinary argument flow.
  No Django-style `RawSQL`/`Manager.raw` APIs exist in this project (not a Django code
  base — django.md was never loaded), and `Query.from_statement()` / `exec_driver_sql()`
  have zero call sites (detection.json notObserved).
- **Bound parameters vs SQL text**: `cursor.execute(sql, params)` — `params` (arg 1) is
  the barrier, `sql` (arg 0) is the sink; on the adapter sites argument 1 is the SQL text
  sink (corrected position). `pd.read_sql_query` statements are compiled with
  `literal_binds=True` (dialect-escaped literal rendering — *not* driver binding), which
  is why they remain sinks (p5-sink-017 rationale), with column names constrained to
  dataset-defined columns upstream.
- **The SQL Lab flow is by-design arbitrary SQL under auth** (Phase 1 finding 1): the
  query will report the complete request.json → rendered_query → execute chain. The
  marshmallow `ExecutePayloadSchema.load` result is discarded at sqllab/api.py:300
  (validation-only), so no barrier exists there by design; the post-render table-access
  validation (security/manager.py:1799-1869) is control flow, not data sanitization, and
  is not modeled as a barrier. Threat-model classification of these alerts is a Step 6
  triage concern (phase1_review.md §7 item 1).

## 3. Diagnostics guidance (not part of the formal CWE-89 results)

To verify the wrapper modeling without contaminating formal results, a diagnostics query
can be written as a **separate** `.ql` file (not created this round per the six-file
output contract) reusing the same libraries with a diagnostic-only config, e.g.:

- source = the `SqlTextDefinitionParameter` nodes themselves (i.e. "assume the audited
  wrappers receive tainted SQL") with sink unchanged — verifies edges (1)-(4) and the
  definition-side sink reachability;
- source = `RequestFieldRead` with sink = `EngineSpecAdapterSqlArgument`, to confirm the
  corrected adapter argument index fires on the SQL Lab chain.

Such a query must carry `@problem.severity note` and a distinct `@id`
(e.g. `py/augur/superset/pass5-sql-injection-diag`) and must never be merged into
`results/pass5.sarif`.

## 4. Known limitations

- **Receiver identity is name/shape-based, not type-resolved** (all Phase 1 rows are
  `match_kind ast`): `.execute` matching relies on the audited file universe plus receiver
  base names (`cursor/conn/bind/engine/session/connection/db_engine_spec/cls/
  _sql_json_executor`); `<expr>`-shaped receivers (method chains) did not occur in the
  audited rows, and a same-named non-SQL object inside the scoped files would be matched
  (none exists in the snapshot — the Phase 1 extraction covered every `.execute` call).
- **Marshmallow schema loads are not modeled** (marshmallow is external to the database):
  the chart-data path `ChartDataQueryContextSchema().load(form_data)`
  (charts/data/api.py:432) breaks the request→QueryContext flow, and the QueryContext /
  QueryObject object graph (query_context_processor → get_sqla_query clauses) has no
  field-flow edges. The chart-data ad-hoc clause surface (p5-sink-022) is therefore
  reachable only via the `process_template` edge for the template part, not from the HTTP
  source. If needed, a future round can add verified QueryContext field-flow edges after
  a fresh label review.
- **RLS insertion branch** (sql_lab.py:207-217, feature-flagged) reads
  `parsed_query._parsed[0]` — an unmodeled ParsedQuery field; the main path
  (`parsed_query.stripped()` at :219) is covered by edge (3a).
- **`Query(...)` ORM-model field flow is scoped to create_query** (edge (2) store side);
  other Query construction sites (e.g. DAOs) would need their own verified edges.
- **Edge (3a) is set-based**, not instance-correlated: taint reaching any `ParsedQuery`
  constructor argument may surface at any `.stripped()`/`.get_statements()`/
  `.as_create_table()` result. ParsedQuery instances are short-lived locals and the method
  names are distinctive, so cross-instance leakage would still be SQL text → SQL text.
- **`**kwargs` forwarding** into `BaseEngineSpec.execute(query, **kwargs)` and the
  DBAPI-kwargs path (hive.py:548) is not decomposed (irrelevant: kwargs carry flags, not
  SQL text).
- **Second-order / stored SQL** (imported dataset `sql`, RLS clauses, report schedules,
  imported-dashboard params) has no source in this query (labels p5-none-050, p5-sum-036
  document the storage flows); a future "database content" pass would need its own
  reviewed sources.
- **CLI / celery candidate sources unmodeled** (p5-src-047/052) — see §1; enabling them
  requires a fresh label review, not an edit.
- **Not compiled**: per this round's contract no `codeql query compile` /
  `codeql pack install` / `codeql database analyze` was run. Before Step 6 execution:
  `cd iris && codeql pack install`, then
  `codeql query compile --check-only queries/Pass5_SQLInjection.ql` (expect possible
  mechanical fixes only — the django run of this series needed a `bindingset`
  annotation and a reserved-word rename at this stage, both pre-applied here), then
  `codeql database analyze <superset-db> queries/Pass5_SQLInjection.ql
  --format=sarifv2.1.0 --output=results/pass5.sarif` (sequential, single query).
- **Path separator assumption**: forward-slash `matches()` patterns (see §0).

## 5. Open review items carried into Phase 2 (labels untouched)

1. **SQL Lab threat model** (p5-src-040/046/051, p5-sink-005/007/009/010): the
   request→cursor.execute chain is real and now fully modeled; whether executing
   authenticated users' SQL against databases they can access constitutes a
   vulnerability is a Step 6 triage/policy decision (recommend classifying SQL Lab
   alerts separately from injection findings).
2. **CTAS identifier path** (p5-cand-029): connected via edges (1)+(2)+(3b) up to
   `as_create_table` and the SQL Lab funnel — the Phase 1 review's targeted manual look
   (§7 item 2) can now be answered from the actual Phase 2 path results.
3. **`sanitize_clause` as barrier** (p5-san-067): documentation-only; decision recorded
   in §1 (not a barrier — structural guard, no quote escaping).
4. **CLI/importer trust boundary** (p5-src-047, p5-sum-036/064 candidate labels): sources
   stay unmodeled; flip-on requires a fresh label review.
