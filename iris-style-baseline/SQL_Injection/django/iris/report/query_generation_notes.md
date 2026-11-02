# Query Generation Notes — Pass 5 (CWE-89 SQL Injection) — Step 4–5

Augur Phase 2, Step 4 (generate CodeQL libraries) and Step 5 query file (generation only —
per the task contract nothing was compiled, executed, or run against the database in this
round).

Generated files:

- `iris/libraries/MySources.qll` — `MySources::isSource(node, passKey)`
- `iris/libraries/MySinks.qll` — `MySinks::isSink(node, passKey)`
- `iris/libraries/MySanitizers.qll` — `MySanitizers::isBarrier(node, passKey)`
- `iris/libraries/MySummaries.qll` — `MySummaries::isAdditionalTaintStep(from, to, passKey)`
- `iris/queries/Pass5_SQLInjection.ql` — `py/augur/django/pass5-sql-injection`
  (`@kind path-problem`, `@problem.severity error`, `@tags security`,
  `external/cwe/cwe-089`)

All four libraries and the query use pass key `"sql_injection"` and the modular data-flow
API: `DataFlow::ConfigSig`, `TaintTracking::Global<Pass5Config>`,
`import Pass5Flow::PathGraph`, `flowPath(source, sink)`. `qlpack.yml`
(`iris/django-cwe89`, dependency `codeql/python-all: "*"`) already sits at the iris root,
so `import libraries.MySources` etc. resolve from `iris/libraries/` and
`iris/queries/`.

## 0. Review-gate status and evidence basis

- `labels/review_decision.json` does **not** exist (Phase 1's checkpoint is advisory per
  WORKFLOW.md §4.5, and the Phase 1 round chose not to fabricate it). Per this round's
  instruction, the Pass 5 labels in `labels/labels.json` are treated as the approved
  review outcome. **No label was modified in this round**; every modeling decision below
  cites its label id. Items the Phase 1 review left open (`labels/phase1_review.md` §7)
  are handled conservatively (see §5) rather than by editing labels.
- All file:line evidence refers to the **CodeQL DB source snapshot**
  (`django-db/src.zip`, Django 4.2.0-alpha0, sha eb3699e). The on-disk working tree is
  stock Django 2.2.4 and does **not** match the extraction CSV line numbers (recorded in
  `labels/labels.json` metadata notes and `labels/phase1_review.md` §2). The query will
  run against `django-db`, i.e. against the 4.2.0-alpha0 snapshot the labels describe.
- No PyVul ground truth (`sql_sinks*.csv`, `enhanced_sql_sinks.csv`,
  `sql_injection_audit_report.md`), fix diffs, or CVE announcements were consulted.
  Modeling derives only from the approved Pass 5 labels and direct source reading of the
  snapshot (same isolation principle as the earlier command-injection and SSRF
  experiments: independent labeling, formal results computed independently, ground truth
  touched only by the later evaluation step, never during model construction).
- API compatibility was checked against the local pack actually used for this project:
  `codeql/python-all 7.1.2` under `C:\Users\lzh\.codeql\packages\codeql\python-all`
  (CodeQL CLI 2.25.1 at `E:\codeql`). Verified to exist and used:
  `DataFlow::Node.asExpr()` (DataFlowPublic.qll:200/299),
  `DataFlow::parameterNode(Parameter)` (DataFlowPublic.qll:352; module-qualified
  spelling required, as in the library's own Websockets.qll:69),
  `Call.getPositionalArg/getFunc/getAKeyword`, `Keyword.getArg()/getValue()`
  (AstGenerated.qll:1907-1915), `Attribute.getName()/getObject()`,
  `Parameter.getName()/isSelf()`, `Function.getArg/getAnArg/getName()`,
  `AstNode.getLocation().getFile()`, `File.getAbsolutePath()`. The config/flow shape
  (`module X implements DataFlow::ConfigSig` with
  `isSource/isSink/isBarrier/isAdditionalFlowStep`, then
  `module F = TaintTracking::Global<X>` with `F::PathNode`/`F::flowPath`) mirrors the
  pack's own canonical queries (e.g. semmle/python/security/dataflow/
  CommandInjectionQuery.qll:17-28, WeakSensitiveDataHashingQuery.qll:84-99), and
  `private class X extends DataFlow::Node` inside a module mirrors
  Websockets.qll:19. Type checks confirmed: `Function extends Function_, Scope, AstNode`
  (Function.qll:10), `Expr extends Expr_, AstNode` (Exprs.qll:8), `Parameter <: Name`
  (Function.qll `asName()`), so all `AstNode`-typed helper predicates accept
  Call/Attribute/Parameter/Function arguments. Not used (avoided per the
  Phase 1 compatibility notes): deprecated `StrConst`, a `Decorator` AST class,
  `AstNode.getFile()` (does not exist), and `module` as a variable name. A brace/paren
  balance and forbidden-pattern sanity check over all five QL files passed
  (`diagnostics/ql_sanity_check.py`). A full `codeql query compile --check-only`
  (CodeQL CLI 2.25.1, pack resolved from the local user pack cache) was subsequently
  run against `queries/Pass5_SQLInjection.ql` and passes with **zero errors and zero
  warnings**; two defects found by that compile check were fixed in the libraries (no
  label or query-semantics changes):
  1. `from` is a reserved QL keyword — the additional-taint-step parameters in
     `MySummaries.qll` were renamed `from`/`to` → `nodeFrom`/`nodeTo` (the original
     parse failure cascaded into all the cross-file "p is not bound" / phantom-select
     errors in the first compile attempt);
  2. QL string primitives (`matches`, `+`) do not bind their operands, so the helper
     predicates taking a plain `string` parameter (`excludedPath(string p)`,
     `fileIs(AstNode n, string relPath)`) needed `bindingset[p]` / `bindingset[relPath]`
     annotations (all call sites pass bound strings).
- Path patterns assume the forward-slash absolute paths stored in this CodeQL database
  (verified against the extraction CSVs, e.g.
  `C:/Users/.../django_vuln/django/db/backends/utils.py`). If a future rebuild of the
  database stores Windows backslash paths, the `matches()` patterns in the four libraries
  need a backslash variant added.

## 1. Label id → QLL predicate mapping

### MySources (`isSource`, all label classification tp)

| label id | modeled node | QL class in `MySources` | snapshot evidence |
| --- | --- | --- | --- |
| p5-src-037 | `request.GET` field read | `HttpRequestFieldRead` | admin/views/main.py:95-112 |
| p5-src-038 | `request.POST` field read | `HttpRequestFieldRead` | admin/options.py:1548 |
| p5-src-039 | `request.META` field read | `HttpRequestFieldRead` | middleware/csrf.py:261-262 |
| p5-src-040 | `request.COOKIES` field read | `HttpRequestFieldRead` | middleware/cache.py:94 |
| p5-src-041 | `request.FILES` field read | `HttpRequestFieldRead` | views/generic/edit.py:52 |
| p5-src-042 | WSGI `environ` attr read (non-`os`) | `WsgiEnvironRead` | core/handlers/wsgi.py (`self.environ`, :144 context) |
| p5-src-043 | `get_bytes_from_wsgi(...)` result | `GetBytesFromWsgiCall` | core/handlers/wsgi.py:159/:180 |
| p5-src-044 | `request.<map>.get/getlist()` result | `QueryDictAccessorCall` | admin/views/main.py:106, middleware/common.py:41 |
| p5-src-045 | `request.<map>.items/copy/urlencode()` result | `WholeMappingCall` | admin/views/main.py:112 |
| p5-src-046 | handler `request` parameter (by name) | `HandlerRequestParam` | auth/admin.py:117 (`add_view(self, request, ...)`), 631 rows/323 handlers |
| p5-src-047 | `self.kwargs` (URL route params) | `UrlKwargsRead` | views/generic/detail.py:34-35 |

Not modeled, with reasons (labels unmodified):
- p5-src-048 (CLI `options`), p5-src-050 (`sys.argv`) — classification `candidate`;
  operator-level input (manage.py runs with DB credentials). Per the Phase 1 review §7
  recommendation these stay out of `isSource`. They can be re-enabled after a fresh
  human review of the CLI threat model without touching the labels.
- p5-none-049..054 — `add_argument` registrations, `open`, `read`, `os.environ`,
  `settings.<ATTR>` — all fp for pass 5.

**External boundary and controllable range:** every modeled source sits on the
HTTP/WSGI request boundary — the raw environ dict, the parsed QueryDict
(GET/POST/COOKIES/FILES/META), URL route parameters, and the request object itself
entering each handler. From a tainted `request` object, standard local attribute flow
additionally covers subscript/attribute reads not individually extracted
(`request.META['SCRIPT_NAME']`, `request.GET['year']`, `request.headers`-style access on
`request.*`). No parameter of a function that merely *contains* a `cursor.execute` call
is a source; taint must originate at the boundary above.

### MySinks (`isSink`)

| label id | API / receiver | dangerous arg | QL class | snapshot evidence |
| --- | --- | --- | --- | --- |
| p5-sink-001 | `<cursor|schema_editor|conn|self>.execute/.executemany/.callproc` call | positional arg **0** (SQL text; procname for callproc) | `ExecuteSqlTextArgument` | compiler.py:1395/:1657; base/schema.py:199; base/base.py:370 |
| p5-sink-002/003 | `CursorWrapper.execute/executemany(sql, ...)` (also `CursorDebugWrapper` subclasses, deduped) | parameter **`sql`** (param 1 after `self`) | `SqlTextDefinitionParameter` | backends/utils.py:66/:71/:101/:105 |
| p5-sink-004 | `CursorWrapper.callproc(procname, params, kparams)` | parameter **`procname`** (SQL structure) + call-site arg 0 | `SqlTextDefinitionParameter` + `ExecuteSqlTextArgument` | backends/utils.py:48-64 |
| p5-sink-006/007 | `SQLiteCursorWrapper.execute/executemany(query, ...)` | parameter **`query`** | `SqlTextDefinitionParameter` | sqlite3/base.py:353/:359 |
| p5-sink-008/009 | mysql `CursorWrapper.execute/executemany(query, args)` | parameter **`query`** | `SqlTextDefinitionParameter` | mysql/base.py:72/:83 |
| p5-sink-010/011 | oracle `FormatStylePlaceholderCursor.execute/executemany(query, ...)` | parameter **`query`** | `SqlTextDefinitionParameter` | oracle/base.py:552/:558 |
| p5-sink-013 | `QuerySet.raw(raw_query, params, ...)` | parameter **`raw_query`** | `RawSqlApiParameter` | models/query.py:1284 |
| p5-sink-014 | `QuerySet.extra(select, where, params, tables, order_by, select_params)` | params **`select`/`where`/`tables`/`order_by`** | `RawSqlApiParameter` | models/query.py:1670-1684 |
| p5-sink-015 | `RawSQL.__init__(sql, params, ...)` | parameter **`sql`** | `RawSqlApiParameter` | models/expressions.py:1049 (`as_sql` embeds it verbatim: expressions.py:1058-1059) |
| p5-sink-016 | `RawQuery.__init__(sql, using, params)` | parameter **`sql`** | `RawSqlApiParameter` | models/sql/query.py:85 (executed at :152) |
| p5-sink-017 | `RawQuerySet.__init__(raw_query, ...)` | parameter **`raw_query`** | `RawSqlApiParameter` | models/query.py:1995-2009 |
| p5-sink-019 | `BaseDatabaseSchemaEditor.execute(sql, params)` | parameter **`sql`** (param 1 after `self`) | `SqlTextDefinitionParameter` | backends/base/schema.py:170-199 |

Execution evidence (why these are the real SQL execution channel):
- `CursorWrapper.execute(sql, params)` → `_execute_with_wrappers` → `_execute` →
  `self.cursor.execute(sql, params)` (utils.py:66-89): the central PEP-249 funnel every
  backend goes through; `CursorDebugWrapper` only adds logging (utils.py:97-107).
- ORM endpoint `cursor.execute(sql, params)` (compiler.py:1395/:1657) — SQL text +
  bound pair produced by `as_sql()`.
- DDL funnel `BaseDatabaseSchemaEditor.execute` → `cursor.execute(sql, params)`
  (base/schema.py:199) with 60+ `self.execute(...)` call sites across the backend schema
  editors; `collect_sql` mode additionally interpolates `quote_value`'d params into the
  recorded text (base/schema.py:193).
- Driver-level wrappers: `SQLiteCursorWrapper.execute` converts `%s`→`?` placeholders and
  calls `Database.Cursor.execute(self, query, params)` (sqlite3/base.py:353-361);
  mysql `CursorWrapper.execute` forwards `(query, args)` (mysql/base.py:72-75);
  oracle `FormatStylePlaceholderCursor.execute` rewrites `:name` placeholders via
  `_fix_for_params` and calls the cx_Oracle driver (oracle/base.py:552-556).
- Raw API chain: `QuerySet.raw` → `RawQuerySet` → `sql.RawQuery(sql=...)` →
  `RawQuery._execute_query` → `connection.cursor().execute(self.sql, params)`
  (models/query.py:1284-1295, 2009; models/sql/query.py:152).

**Call-site scoping (name-collision control):** `SqlExecuteCall` (used by
`ExecuteSqlTextArgument` and the sanitizer) matches only inside the audited SQL
execution layer — `django/db/**`, `django/contrib/gis/db/**`,
`django/contrib/postgres/**`, `django/core/cache/backends/db.py` — which is exactly the
file universe of the 220 approved call-site rows. The approved fp rows therefore fall
outside the sink automatically:
- CLI dispatch: `command.execute(...)` (core/management/__init__.py:198),
  `utility.execute()` (:446), `self.execute(*args, **cmd_options)`
  (core/management/base.py:402), `super().execute(...)` (runserver.py:74,
  createsuperuser.py:88, sqlmigrate.py:38) — labels p5-none-028.
- Redis pipeline: `pipeline.execute()` (core/cache/backends/redis.py:148) — p5-none-030.
- sqlite function registration `register` (sqlite3/_functions.py:40) — p5-none-031.
- Framework test infra `django/test/testcases.py` — p5-none-056.

**Unbound-`self` idiom:** driver-level calls such as
`Database.Cursor.execute(self, query, params)` (sqlite3/base.py:355/357/361,
oracle/base.py:556/570) pass the receiver explicitly, so their *positional* argument 0 is
`self`, not SQL. `SqlExecuteCall` excludes calls whose argument 0 is the literal name
`self`; those sites are instead covered by the definition-side wrapper-parameter sinks
above. This also prevents the bound-parameter barrier from wrongly blocking argument 1
(the SQL text in this idiom).

### MySanitizers (`isBarrier`)

| label id | barrier node | QL class | evidence |
| --- | --- | --- | --- |
| p5-san-035 (tp) | call-site bound-parameter: positional arg 1 of execute-family calls, or keyword `params`/`param_list`/`args`/`kparams` | `BoundParameterArgument` | compiler.py:1395; cache/backends/db.py:151/:172/:185/:196 (`[key]`, `[exp, key]`); migrations/special.py:129 (`params=params`) |
| p5-san-035 (tp) | definition-side bound-parameter: `params`/`param_list`/`args`/`kparams` params of the execute-family wrappers | `BoundParameterDefinitionParameter` | utils.py:66/:71/:48; base/schema.py:170; mysql/base.py:72 |

Parameter binding is the only sanitizer modeled as a barrier, because it is the only one
with proof in this code base: values in the `params` channel are substituted by the DB
driver and cannot alter SQL text. The barrier blocks taint **only** at the bound-value
channel — it never blocks the SQL-text argument (arg 0 / `sql`/`query` parameters), so
dynamically built SQL structure remains fully checked.

**quote_name is deliberately NOT a barrier** (label p5-san-036, classification
`candidate`): the verified implementations wrap the identifier without escaping embedded
quotes — sqlite3/operations.py:189-192 `'"%s"' % name`, mysql/operations.py `` '`%s`' % name``,
postgresql/operations.py same shape. It is adequate only for framework-controlled
identifier character sets (model field names, introspected table names). Consequence,
matching the task's modeling rule: a tainted table name, column name or ORDER BY fragment
that is %-interpolated into SQL text (e.g. `"PRAGMA table_info(%s)" % quote_name(x)` at
sqlite3/introspection.py:94, `"SHOW INDEX FROM %s" % quote_name(table_name)` at
mysql/introspection.py:310, createcachetable.py:100-127 DDL) still flows into the
SQL-text sink and raises an alert — binding does not protect dynamic SQL structure.

### MySummaries (`isAdditionalTaintStep`)

| label id | edge | necessity |
| --- | --- | --- |
| p5-sum-018 | `RawQuery.__init__` parameter `sql` (sql/query.py:85) → `self.sql` attribute reads in class RawQuery (:87 store; :101/:132/:133 reads; **:152** the executed SQL text) | Cross-method attribute flow is not connected by the default Python dataflow library; without this edge the raw()-chain sinks would be unreachable from `__init__`-side taint. Scoped to `django/db/models/sql/query.py` where every `self.sql` occurrence was verified to belong to `RawQuery`. |

All other summary-labeled families (p5-sum-005, -012, -020..-024, -029, -032..-034)
intentionally receive **no** extra edge: their parameter→execute propagation is ordinary
interprocedural argument flow already modeled by the library (e.g.
`_execute(sql, params)` → `self.cursor.execute(sql, params)`; `execute_sql` →
`cursor.execute(sql, params)`), and the CLI-dispatch family (p5-sum-029) has no source in
this query. Creating edges for them would establish unconditional propagation the source
code does not warrant.

## 2. Dynamics: construction, identifiers, ORDER BY, ORM, binding

- **%-formatting / f-strings / concatenation** are not sinks themselves (labels
  p5-none-027). Taint through `"..." % x`, f-strings and `+` is standard CodeQL string
  taint propagation, so a tainted identifier embedded via `%` into a PRAGMA/SHOW/DDL
  template reaches the execute-family SQL-text sink at the point of execution
  (e.g. sqlite3/base.py:236-238 `check_constraints`, sqlite3/introspection.py:94/:313,
  mysql/introspection.py:310, base/creation.py:186 `CREATE DATABASE %(dbname)s`).
- **ORDER BY / identifiers**: the only request-derived ordering in the framework
  (admin ChangeList, admin/views/main.py) is `int()`-parsed and `to_field_allowed`-checked
  and reaches the DB through `QuerySet.order_by()/filter()` — the ORM channel below —
  not through string construction. Identifier interpolation sites reached by taint would
  alert because quote_name is not a barrier.
- **ORM calls** (`filter`, `exclude`, `order_by`, `Q`) are intentionally NOT sinks: they
  compile to parameterized SQL at compiler.py:1395 (labels: "djangoOrm ... NOT a raw-SQL
  sink"). The ORM's own raw surface — `raw`, `extra`, `RawSQL`, `RawQuery`,
  `RawQuerySet` — is modeled per its real execution semantics (verbatim SQL text with a
  separate bound channel; `extra`'s `params`/`select_params` and `raw`'s `params` are
  excluded as bound channels, its `select/where/tables/order_by` fragments are sinks).
- **SQLite `convert_query` and Oracle `_fix_for_params`** are placeholder-syntax
  conversions (%s→?, :name normalization), not taint barriers — the SQL text parameter
  stays a sink.
- **Bound parameters** are the barrier (§1). Values passed as params never reach a
  SQL-text sink node.

## 3. Diagnostics guidance (not part of the formal CWE-89 results)

To verify the wrapper modeling without contaminating formal results, a diagnostics query
can be written as a **separate** `.ql` file (not created this round per the six-file
output contract) reusing the same libraries with a diagnostic-only config, e.g.:

- source = the `Parameter` node of every audited wrapper definition (`SqlTextDefinitionParameter`
  itself, i.e. "assume the wrapper receives tainted SQL"), sink = unchanged; or
- source = `MySummaries`/`MySinks` call-site nodes, sink = the driver-level
  `Database.Cursor.execute` calls, to confirm the unbound-`self` handling.

Such a query must carry `@problem.severity note`/warning and a distinct `@id`
(e.g. `py/augur/django/pass5-sql-injection-diag`) and must never be merged into
`results/pass5.sarif`.

## 4. Known limitations

- **Receiver identity is name/shape-based, not type-resolved** (all extraction rows are
  `match_kind ast`): `.execute` matching relies on the audited path scoping, plus the
  `self`-argument exclusion; a non-cursor object with an `execute` method inside the
  scoped paths would be matched (none exists in the snapshot — verified in Phase 1).
- **Attribute flow approximation for `RawQuery.sql`** (MySummaries): the edge is scoped
  by file + attribute name + receiver `self`, justified by the verified uniqueness in
  `django/db/models/sql/query.py`; if that file changes in a future snapshot, the scope
  must be re-verified.
- **`Manager.raw()` / `Manager.extra()`**: QuerySet methods are copied onto `Manager` at
  runtime (models/manager.py); with no static call sites in the snapshot, only the
  QuerySet definitions are modeled — downstream application code calling
  `Model.objects.raw(...)` inside this DB would not resolve to the QuerySet parameter
  without an API-graph model.
- **No API-graph (`semmle.python.ApiGraphs`) modeling**: every candidate row is
  `match_kind ast`; the labels and the libraries therefore use syntactic matching
  (function/parameter/file scope), consistent with the extraction contract.
- **`**options`/`*args` forwarding** (e.g. `call_command(**options)` → `handle(**options)`)
  is not modeled — irrelevant here because the CLI family is not a source.
- **Second-order DB-derived identifiers** (introspection `table_name` values, labels
  p5-sum-021/-024 candidate-level) have no source in this query; if a future pass adds
  "database content" sources, the introspection wrappers already propagate to the sinks
  through ordinary argument flow.
- **Path separator assumption**: forward-slash `matches()` patterns (see §0).
- **Not executed**: `codeql query compile --check-only` passes (see §0); what remains
  unexecuted is `codeql pack install` (dependency resolution used the local pack cache
  during the check) and the actual `codeql database analyze` run. Before Step 6
  execution: `cd iris && codeql pack install`, then
  `codeql database analyze <db> queries/Pass5_SQLInjection.ql --format=sarifv2.1.0
  --output=results/pass5.sarif` (sequential, single query).

## 5. Open review items carried into Phase 2 (labels untouched)

1. CLI threat model (p5-src-048/-050, p5-sum-029, p5-sum-033): sources remain
   unmodeled; flip-on requires a fresh label review, not an edit.
2. quote_name as sanitizer (p5-san-036): documentation-only; not a barrier.
3. Tree-vs-DB version mismatch (tree 2.2.4 vs DB snapshot 4.2.0-alpha0): the query
   targets the DB snapshot; any re-extraction should re-run Phase 1 against a matching
   tree.
