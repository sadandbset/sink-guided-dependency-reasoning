# Query Generation Notes - Phase 2 Step 4-5 (Pass 5, CWE-89 SQL Injection)

- **Project**: piccolo (piccolo_vuln source tree, CodeQL DB `piccolo-db`, creation sha `e4946d8`)
- **Labels**: `iris/labels/labels.json` (run `piccolo-iris-pass5-20261021`, 42 entries; raw per-row audit in `labels_raw_pass5.json`)
- **Generated**: `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass5_SQLInjection.ql`
- **API basis**: `codeql/python-all 7.1.2` + `codeql/dataflow 2.1.7` from the local user pack cache; every AST/data-flow API used was verified against those pack sources (see §7). Modular data flow only: `DataFlow::ConfigSig`, `TaintTracking::Global`, `PathGraph`, `flowPath`.
- **Status**: `codeql query compile --check-only` (CLI 2.25.1) now completes with **no errors and no warnings** for `queries/Pass5_SQLInjection.ql`. The first compile attempt surfaced three QL-language pitfalls, all fixed without any semantic change to the model (details in §9): (1) `from`/`to` are QL query-clause keywords and cannot be predicate parameter names (renamed `fromNode`/`toNode` in `MySummaries`); (2) a block comment containing the text `piccolo/apps/*/commands/*.py` was terminated early by the embedded `*/` (comment text reworded to `<app>`); (3) `string.matches(...)` does not bind its receiver, so the `excludedPath(string path)` helper's parameter was never bound - it was reworked into `excludedNode(AstNode n)` whose `matches` receivers are bound `normalizedPath(n)` function results (the same idiom the Phase 1 queries use). The query has NOT been executed against the database yet (no taint analysis run, no results produced).

## 1. Review gate status

The instruction premise is that Step 5 (human review) approved the labels. The review record for this run is
`iris/labels/phase1_review.md` (checkpoint summary with an explicit Phase 2 recommendation: "Proceed to Phase 2
with the current labels: sources = src-07/08/12/13 (+ conservative src-01..05), sinks = snk-01a-e/06/15/04a/09/10/13/08,
barrier = src-15, summaries = src-09/11/17/19 + snk-04b/07/16"). **No `labels/review_decision.json` exists in the
workspace** (it was not among the Step 3 deliverables). This is recorded as a documentation gap; no label was modified
to compensate, and per the "do not modify reviewed labels" rule the QLLs were built strictly from `labels.json`
as-is. If a formal `review_decision.json` is required for the audit trail, it should be written by the reviewer
before Phase 2 execution - not by this generation step.

## 2. Label entry -> QLL predicate mapping

All 42 reviewed Pass 5 entries and where they are (or are deliberately not) implemented. Predicate names are
`MySources::isSource` / `MySinks::isSink` / `MySanitizers::isBarrier` / `MySummaries::isAdditionalTaintStep`,
each gated on pass key `"sql_injection"`. `role=none` entries are not modeled by design (they are the documented
safe/noise families); `role=summary` entries map either to default inter-procedural taint (no explicit step needed)
or to the three explicit steps in `MySummaries`.

### 2.1 Sources (`MySources.qll`)

| Label ID | Role/Class | Reviewed location | Implementation |
| --- | --- | --- | --- |
| p5-src-001 | source/fp | `piccolo/apps/migrations/commands/backwards.py:115` (111 rows) | `cliCommandBoundary` - parameters of module-level functions in `piccolo/apps/*/commands/*.py` |
| p5-src-002 | source/fp | `backwards.py:81` (12 rows) | `interactiveInputBoundary` - `input()` call results |
| p5-src-003 | source/fp | `piccolo/conf/apps.py:365` (9 rows) | `environmentBoundary` - `os.environ` attribute reads + `os.environ.get()` results |
| p5-src-004 | source/fp | `piccolo/main.py:34` (2 rows) | `argvBoundary` - `sys.argv` attribute reads |
| p5-src-005 | source/fp | `piccolo/query/base.py:109` (12 rows) | `fileReadBoundary` - `open()` / `load_json` / `load_json_string` call results (library + `setup.py`) |
| p5-src-006 | none/fp | graph.py:112 | not modeled (file-write scaffolding) |
| **p5-src-007** | source/tp | `piccolo/columns/combination.py:112` + `piccolo/table.py:964` (2 rows) | `ormRawSqlTextBoundary` - `sql` parameter of `Table.raw` (table.py) and `WhereRaw.__init__` (combination.py) |
| **p5-src-008** | source/tp | `piccolo/query/methods/alter.py:364` (12 rows) | `ddlIdentifierBoundary` - Alter `rename_table/rename_column/set_column_type/drop_constraint/set_schema` params; `Savepoint.__init__(name)`; `rollback_to(savepoint_name)` (postgres.py/sqlite.py) |
| p5-src-009 | summary/tp | `piccolo/engine/base.py:68` | default inter-procedural taint: `run_querystring`/`run_ddl`/`_run_*` parameters flow to the engine execution calls through normal call/return steps - no explicit extra step required |
| p5-src-010 | none/fp | engine/base.py:68 | not modeled (args/in_pool/query_type/table metadata params) |
| p5-src-011 | summary/tp | `piccolo/querystring.py:63` | partially default: taint in a `QueryString` template is caught at the construction sinks (p5-snk-019); the object-to-compiled-string hop is a documented limitation (§7) |
| **p5-src-012** | source/tp | `piccolo/query/mixins.py:320` | `asOfIntervalBoundary` - `interval` param of `AsOfDelegate.as_of` |
| **p5-src-013** | source/candidate | `piccolo/query/mixins.py:760` | `onConflictTargetBoundary` - `target` param of `OnConflictDelegate.on_conflict` |
| p5-src-014 | none/fp | `piccolo/columns/base.py:598` | not modeled (Where values ride the bound-parameter channel - the reviewed safe behavior) |
| **p5-src-015** | sanitizer/tp | `piccolo/query/mixins.py:303` | `MySanitizers::isBarrier` - argument 0 of `Limit(...)`/`Offset(...)` construction |
| p5-src-016 | none/fp | mixins.py:332 | not modeled (output shaping / Column metadata) |
| p5-src-017 | summary/tp | backwards.py:94 (42 rows) | default inter-procedural taint (delegate pass-through calls); no explicit step |
| p5-src-018 | none/fp | objects.py:239 | not modeled (int-guarded limit/offset transfers) |
| p5-src-019 | none/fp | generate.py:478 | not modeled (literal templates + bound raw args) |
| p5-src-020 | summary/candidate | alter.py:50 (120 rows) | partially covered: reflected/developer identifier reads reach the f-string sinks through the explicit `ctorArgToFieldRead`/`propertyReadHop` steps for the labeled dataclasses; a dedicated reflection-input step was not added (no reflection source row exists, §7) |

### 2.2 Sinks (`MySinks.qll`)

| Label ID | Role/Class | Reviewed location | Implementation |
| --- | --- | --- | --- |
| **p5-snk-001** | sink/tp | `piccolo/engine/postgres.py:496` | `engineSqlTextSink` - asyncpg `connection.fetch(query, *args)`, SQL text at arg 0 (postgres.py:496,508,531,553) |
| **p5-snk-002** | sink/tp | postgres.py:59 | `engineSqlTextSink` - asyncpg `connection.cursor(template, *template_args)`, arg 0 |
| **p5-snk-003** | sink/tp | postgres.py:132 | `engineSqlTextSink` - asyncpg `connection.execute(stmt)`, arg 0 (132,137,239) |
| **p5-snk-004** | sink/tp | `piccolo/engine/sqlite.py:230` | `engineSqlTextSink` - aiosqlite `connection.execute(query, args)`, arg 0 (230,312,317,416,595,623) |
| **p5-snk-005** | sink/tp | sqlite.py:575 | `engineSqlTextSink` - aiosqlite `cursor.execute(stmt)`, arg 0 (receiver `cursor`) |
| p5-snk-006 | none/fp | sqlite.py:391 | not modeled (BEGIN enum / COMMIT / ROLLBACK / PRAGMA statics; they can never carry taint since the text argument is a literal) |
| p5-snk-007 | none/fp | postgres.py:41 | explicitly excluded via the receiver rule: `fetch`/`cursor` sinks require receiver `connection`/`conn`, so `self.cursor.fetch(self.batch_size)` (batch size, not SQL) cannot match |
| **p5-snk-008** | sink/tp | postgres.py:133 | `savepointStatementFstringSink` - f-strings in engine `rollback_to`/`release`/`savepoint` functions (postgres.py:133,138,239; sqlite.py:313,318,416) |
| p5-snk-009 | summary/tp | postgres.py:131 | default inter-procedural taint (name param -> f-string -> execute inside the same wrapper) |
| p5-snk-010 | none/fp | postgres.py:59 | not modeled (asyncpg bound `*template_args`) |
| **p5-snk-011** | sink/tp | postgres.py:544 | `runDdlTextSink` - `.run_ddl(ddl)` arg 0 (call sites: `query/base.py` DDL.run `engine.run_ddl(...)`; `schema.py:24` `self.db.run_ddl(self.ddl, ...)`) |
| p5-snk-012 | summary/tp | postgres.py:40 | default inter-procedural taint |
| **p5-snk-013** | sink/tp | sqlite.py:576 | `rowidLookupFstringSink` - f-strings inside `_get_inserted_pk` (sqlite.py:575-577) |
| **p5-snk-014** | sink/tp | `piccolo/query/methods/alter.py:36` | `alterDdlFstringSink` - all alter.py DDL f-strings (labels cover 26 rows: 36,63,70,83,90,114,117,131,143,151,152,164,166,177,188,211-250,266,269,576) |
| **p5-snk-015** | sink/candidate | `piccolo/schema.py:55` | `schemaDdlFstringSink` - all schema.py DDL f-strings (56,80,83,102,124,126) |
| p5-snk-016 | none/fp | query/base.py:426 | not modeled (error-message f-string, receiver-collision noise) |
| p5-snk-017 | none/fp | `piccolo/columns/base.py:904` | not modeled (quoted Column metadata DDL; values stay bound - reviewed safe family snk-012) |
| **p5-snk-018** | sink/candidate | `piccolo/query/methods/create_index.py:50` | `dynamicIdentifierFstringSink` - f-strings in AsOf/OrderBy/OnConflictItem/OnConflict classes (mixins.py), create_index.py, and `sqlite_querystrings`/`default_querystrings` (indexes.py:31 PRAGMA index_list, drop_index.py:38) |
| **p5-snk-019** | sink/tp | `piccolo/columns/combination.py:131` | `rawSqlTemplateSink` - `QueryString(sql, *args)` arg 0 inside `Table.raw` (table.py:979), `WhereRaw.__init__` (combination.py:131), `SelectRaw.__init__` (select.py:58) |
| p5-snk-020 | summary/tp | generate.py:466 | default inter-procedural taint (helpers pass CLI schema_name into raw()'s bound args - verified safe, no SQL-text path) |
| p5-snk-021 | none/fp | generate.py:476 | not modeled (raw bound args) |
| p5-snk-022 | none/fp | generate.py:476 | not modeled (raw literal templates) |

### 2.3 Sanitizers (`MySanitizers.qll`)

| Label ID | Implementation |
| --- | --- |
| **p5-src-015** | `isBarrier`: argument 0 of any `Limit(...)`/`Offset(...)` construction in the library. Evidence: `__post_init__` raises `TypeError` unless `isinstance(number, int)` (mixins.py:92-94, 131-133) before `f" LIMIT {number}"` / `f" OFFSET {number}"` (mixins.py:98,137). This is the only reviewed sanitizer; there is no identifier allowlist or SQL-context escaping anywhere in the library, so no other barrier was invented. |

No entry was labeled `role=sanitizer` other than p5-src-015; the QueryString bound-argument channel (labels
p5-src-014 / p5-snk-010 / p5-snk-021) is the structural mitigation but was reviewed as `none` (not sanitizer), and
it is enforced structurally instead: **only argument 0 (SQL text) of execution calls is a sink**, so values in the
bound channel can never be reported.

## 3. SQL execution sinks - API, receiver, argument index, execution evidence

All sink signatures, receivers and dangerous argument positions were taken from the reviewed labels and re-verified
against the source tree:

| API (as called) | File:line | Receiver (object of the method attribute) | Dangerous arg | Execution evidence |
| --- | --- | --- | --- | --- |
| `connection.fetch(query, *args)` | postgres.py:496, 508 | local `connection` (Name) | 0 | `_run_in_pool`/`_run_in_new_connection` pass the compiled QueryString output to asyncpg `fetch` |
| `connection.fetch(query, *args)` | postgres.py:531 | local `connection` | 0 | `run_querystring` -> `connection.fetch(query, *args)` after `compile_string()` |
| `connection.fetch(ddl)` | postgres.py:553 | local `connection` | 0 | `run_ddl` executes the DDL text verbatim |
| `connection.cursor(template, *template_args)` | postgres.py:59 | `self.connection` (Attribute) | 0 | `AsyncBatch.__aenter__` opens a server-side cursor with the compiled template |
| `connection.execute(f"...")` | postgres.py:132, 137, 239 | `self.transaction.connection` (Attribute, name `connection`) | 0 | ROLLBACK TO / RELEASE / SAVEPOINT statements built by unquoted f-strings |
| `connection.execute(query, args)` | sqlite.py:595, 623 | local `connection` | 0 (arg 1 = bound params, NOT a sink) | aiosqlite `execute(query, args)` - the final SQLite execution layer |
| `connection.execute(...)` | sqlite.py:230, 312, 317, 416 | `self.connection` / `self.transaction.connection` | 0 | AsyncBatch template / savepoint statements |
| `cursor.execute(f"...")` | sqlite.py:575 | param `cursor` (Name) | 0 | `_get_inserted_pk` ROWID lookup with dynamic table/column names |
| `.run_ddl(ddl)` | query/base.py DDL.run, schema.py:24 | `engine` / `self.db` | 0 | funnels every ALTER/CREATE/SCHEMA DDL f-string into `Engine.run_ddl` -> `fetch`/`execute` |
| `QueryString(sql, *args)` | table.py:979, combination.py:131, select.py:58 | - (class call) | 0 | the raw API's `sql` string becomes the compiled template; `*args` are bound |

Receiver-name rule (`connection`/`conn` for fetch/cursor; `connection`/`conn`/`cursor` for execute) is derived from
the reviewed label evidence and simultaneously excludes the one documented receiver collision
(`self.cursor.fetch(self.batch_size)`, postgres.py:41, label p5-snk-007). Engine sinks are file-scoped to
`piccolo/engine/postgres.py` and `piccolo/engine/sqlite.py` - the only two engine files with reviewed sink rows
(no sink rows exist for `cockroach.py`; it is therefore not matched, avoiding unlabeled sink fabrication).

## 4. Sources - external boundary, controllable scope, propagation chains

**Threat model (from the reviewed labels)**: piccolo is an ORM library with **no HTTP surface** (verified in
`exploration/detection.json`: no web-framework imports). The reviewed external boundaries are:

1. **ORM public API (the embedding-application trust boundary, `api_param` family)**:
   - `Table.raw(sql, *args)` / `WhereRaw(sql, *args)` argument 1 (p5-src-007): the caller's string is executed as
     SQL text. Controllable scope: the entire SQL statement. Chain: `sql` param -> `QueryString(sql, *args)`
     arg 0 (sink p5-snk-019, 1 local step) -> compiled template -> engine `fetch/execute` (default steps).
     In-library call sites all pass literal templates, so alerts on this channel mean "an embedding app passed
     attacker-influenced SQL text here".
   - Alter DDL identifier params (p5-src-008): `new_name`, `column`, `old_column`, `new_column`,
     `using_expression`, `constraint_name`, `schema_name`, Savepoint `name`/`savepoint_name`. Controllable scope:
     SQL identifiers/expressions inside DDL and SAVEPOINT statements - `RENAME TO {new_name}` (alter.py:36,
     unquoted), `USING {using_expression}` (alter.py:117, verbatim), `DROP CONSTRAINT IF EXISTS {name}`
     (alter.py:188, unquoted), `f'SAVEPOINT {name}'` (postgres.py:239, unquoted). Chains run through the
     `MySummaries` steps (§6).
   - `as_of` interval (p5-src-012): string interpolated inside single quotes, no escaping (mixins.py:119).
   - `on_conflict` target (p5-src-013): str target interpolated quoted-but-unescaped (mixins.py:659).
2. **Local CLI/interactive/env/file boundaries (p5-src-001..005, fp-classified conservative rows)**: targ CLI
   argv -> module-level command functions; `input()` prompts; `os.environ`/`sys.argv`; file reads
   (`open`, `load_json`). Operator-level trust; **every library-internal flow from these boundaries was verified
   during labeling to ride the bound-parameter channel** (schema generate `{}` slots at generate.py:476-658,
   `.where()` bound args at migrations/tables.py:23-25, pydantic-validated fixture INSERT values), so they are not
   expected to produce findings - they are kept as taint roots for conservative recall and for catching any
   missed external flow in future snapshots.

No engine-internal wrapper parameter was made a source (labels mark them `summary`, p5-src-009) - in particular,
the parameters of the functions containing `cursor.execute`/`fetch` are NOT sources, per the generation rules.

## 5. SQL construction, identifiers, ORDER BY, parameter binding, ORM, sanitizers - evidence

- **Parameter binding (the safe channel)**: `QueryString.compile_string` (querystring.py:163-192) splits the
  template on `{}` and emits `$1..$n` (postgres/cockroach) or `?` (sqlite) placeholders; args stay separate.
  Model consequence: bound channels (`fetch(query, *args)` args 1+, `execute(query, args)` arg 1, `cursor`
  template args 1+) are excluded from sinks; Where/comparison values (label p5-src-014) are not sources;
  `QueryString.__str__` (querystring.py:93-122) is display-only and never executed - not modeled.
- **Dynamic SQL text construction**: the library builds SQL text by f-strings/`+=`/`.format`. The dangerous
  construction points reviewed as sinks: alter.py DDL (26 rows), schema.py DDL, engine savepoint statements,
  `_get_inserted_pk` ROWID lookup, AsOf/OrderBy/OnConflict templates, PRAGMA index_list, DROP/CREATE INDEX names.
  Guarded constructions (label p5-snk-017 and the snk-012 family: LIMIT/OFFSET ints, DISTINCT ON / RETURNING /
  GROUP BY quoted Column names, INSERT/UPDATE/DELETE bound VALUES, CREATE TABLE metadata, column_types operator
  templates) are **not** sinks.
- **Identifiers / ORDER BY as SQL structure**: binding does NOT protect SQL structure. The reviewed labels flag
  exactly these: `Alter` identifiers, `OrderByRaw.sql` (accepted verbatim in `OrderBy.querystring`,
  mixins.py:170-177 - sink modeled via p5-snk-018, though no reviewed source label feeds it in-library),
  `PRAGMA index_list({tablename})` unquoted (indexes.py:31), DROP INDEX names (drop_index.py:38), and the
  second-order reflected identifiers (`src-19`/`snk-08`: sqlite.py:575-577). **No identifier allowlist or safe
  identifier API exists anywhere in the library** - confirmed by grep during labeling - so none was credited.
- **ORM regular queries vs raw SQL**: Where/insert/update values ride bound args (p5-src-014, safe); the raw
  channels are `Table.raw`/`WhereRaw`/`SelectRaw` (p5-src-007 + p5-snk-019 pair). Django `raw()`/`RawSQL()`,
  SQLAlchemy `text()`, psycopg SQL objects do **not exist** in this codebase (no imports; documented absent in
  detection.json) - nothing was modeled for them, modeling is based on real execution semantics (asyncpg/aiosqlite
  call sites), not name resemblance.
- **Sanitizer**: only the Limit/Offset `isinstance(int)` guard (p5-src-015) is proven-effective; HTML-escaping or
  simple `replace()` do not appear in any SQL path.

## 6. Custom summaries - necessity and design

Three additional taint steps in `MySummaries.qll`, each conditional and code-evidenced:

1. **`ctorArgToFieldRead`** (needed by p5-src-008/012/013 -> p5-snk-008/009/014/018): `@dataclass`-generated
   `__init__`s store constructor arguments into fields with no visible AST store, and the `ddl`/`querystring`/
   `target_string` properties interpolate `self.<field>` into SQL text. The step connects a construction-site
   argument (keyword matched by field name, or positional) to the `self.<field>` read inside the same class (or
   its same-file one-level base). Documented bounded over-approximation: a positional argument may connect to any
   declared field of that class (needed for `RenameColumn(column, new_name)`, alter.py:388; the classes have <= 4
   fields and both fields land in the same DDL f-string).
2. **`initParamToFieldRead`** (needed by p5-src-008 Savepoint `__init__(name)` source): `Savepoint` has an
   explicit `__init__` (`self.name = name`), but the reads happen in other methods (`rollback_to`/`release`).
   Cross-method self-field flow is not default, so the `__init__` parameter is connected to `self.<field>` reads
   in the class.
3. **`propertyReadHop`** (needed by p5-src-008 `rename_column(column)`): property invocation is not tracked by
   default data flow; `AlterColumnStatement.column_name` (`@property`, reads `self.column`, alter.py:45-52) ->
   `self.column_name` read in `RenameColumn.ddl` (alter.py:63). Restricted to `@property`-decorated functions
   (`Function.getADecorator()` returning `Name "property"`) within the same-file class hierarchy.

Engine-internal carriers (labels p5-src-009/p5-snk-009/012) needed **no** extra step: global taint tracking already
propagates parameter -> use inter-procedurally (`run_ddl(ddl)` -> `connection.fetch(ddl)` inside the same wrapper).

## 7. Uncovered APIs, dynamic dispatch, CodeQL limitations

- **Attribute-chain metadata reads**: `SetColumnType.ddl` reads `self.old_column._meta.db_column_name` /
  `self.new_column.column_type` (alter.py:112-114) - receiver taint through attribute chains is not established,
  so the `old_column`/`new_column` param paths stop at the chain; only the `using_expression` path completes.
  Not papered over with an unconditional receiver-propagation edge.
- **`QueryString` object -> compiled string**: taint entering a `QueryString` template at a non-raw construction
  site (e.g. select.py:825 assembly) is not tracked onto the compiled output; the raw channel is instead caught at
  the p5-snk-019 construction sinks. Labels p5-src-011/017 (delegate plumbing) rely on default steps where they
  exist.
- **Reflection (second-order) flows**: `TableStorage.reflect`/schema-generate results become `_meta.tablename`/
  `_meta.db_column_name` and are re-interpolated (PRAGMA index_list, ROWID lookup, FROM clauses) - the label
  family p5-src-020 is `summary/candidate` and has **no source row** (reflection results are not parameters), so
  no reflection-input step was created; the sinks (p5-snk-013/018) are modeled and will fire if a taint root ever
  reaches them.
- **Dynamic dispatch**: asyncpg/aiosqlite are LazyLoader locals, and `connection`/`cursor` objects are dynamically
  typed - sinks are matched at the AST call level (receiver-name + file scope from the reviewed label evidence),
  exactly as in Phase 1. FrozenQuery `__getattr__` proxying and keyword-argument transfers noted in
  `detection.json` `uncoveredCases` remain untracked.
- **`OrderByRaw(sql)` / `SelectRaw(sql)` have no reviewed source label** (dataclass fields were not extracted as
  parameters), so the ORDER BY / SelectRaw sinks are modeled (p5-snk-018/019) but currently source-less; a future
  re-labeling could add them.
- **API verification** (pack 7.1.2): `DataFlow::parameterNode`, `Node.asExpr()`, `DataFlow::ParameterNode`,
  `TaintTracking::Global<ConfigSig>`, `<Flow>::PathGraph` / `flowPath` (codeql/dataflow 2.1.7), `Call.getFunc/
  getArg/getAnArg/getAKeyword`, `Keyword.getArg/getValue`, `Attribute.getName/getObject`, `Name.getId`,
  `Fstring.getAValue` + `FormattedValue.getValue`, `Class.getName/getMethod/getABase`, `Function.getName/
  getScope/getAnArg/getADecorator`, `Parameter.getName`, `AstNode.getLocation/getScope/contains`,
  `AnnAssign.getTarget` - all confirmed present; no deprecated `StrConst`/`AstNode.getFile()`/`Decorator` class
  was used; `module` is never used as a variable name; `API::Node` is not used at all (AST -> DataFlow conversion
  only, so no API-graph/data-flow mixing).

## 8. Diagnostics

A separate diagnostics query was **not** generated (not among the required deliverables). The internal-wrapper
verification the instructions ask for is covered by: (a) the label audit trail (every engine wrapper's
parameter-use pair was reviewed in Step 3), and (b) the explicit `MySummaries` steps, which are the only places
where internal propagation was declared. If a `diagnostics/` check is wanted before the formal run, a query
selecting `Pass5Config`-independent raw edges (e.g. `ctorArgToFieldRead` pairs without source/sink constraints)
can be added under `iris/diagnostics/` - its results must not be counted as CWE-89 findings.

## 9. Compile-check round and QL pitfalls (post-generation fix log)

The experimenter ran `codeql query compile --check-only` on the generated files. The reported errors had three
root causes, all in QL syntax/semantics (not in the taint model); fixing them changed no source, sink, barrier,
or flow-step semantics:

1. **`from` / `to` are QL keywords** (query-clause syntax `from ... select ... where`). Using them as predicate
   parameter names in `MySummaries.qll` derailed the parser ("library modules cannot contain query clauses",
   cascading unresolvable-predicate and select-clause-conflict errors). Parameters renamed to
   `fromNode` / `toNode`; the query calls `MySummaries::isAdditionalTaintStep` positionally, so nothing else
   changed.
2. **`*/` inside a block comment terminates it early.** The `cliCommandBoundary` doc comment contained
   `piccolo/apps/*/commands/*.py`; the embedded `*/` closed the comment and `commands` was parsed as an
   annotation. Comment text reworded to `piccolo/apps/<app>/commands/*.py`.
3. **`matches` does not bind its receiver.** `private predicate excludedPath(string path) { path.matches(...) }`
   left the parameter unbound ("'path' is not bound to a value"). Reworked into
   `private predicate excludedNode(AstNode n) { normalizedPath(n).matches(...) }` - the receiver is now a bound
   function result, the same idiom the (successfully compiled and executed) Phase 1 extraction queries use.
   All call sites updated; the excluded-path set is unchanged (`/tests/`, `/piccolo-db/`, `/piccolo-safe-db/`,
   `/piccolo_migrations/`, `/docs/`).

After the fixes: `codeql query compile --check-only` -> `Done [1/1]`, no diagnostics.

## 10. Isolation and consistency principles

- Labels were treated as read-only; no label was changed during generation. Where a label could not be
  implemented faithfully (e.g. p5-src-011 partial, attribute-chain limitation), the shortfall is recorded here
  (§7) rather than patched by inventing edges or sources.
- **No PyVul ground truth, fix commits, or CVE advisories were read**; generation is based solely on the
  reviewed labels, `exploration/detection.json`, and first-party piccolo source in the tree matching the DB sha
  `e4946d8`.
- No source file, CodeQL database, Phase 1 artifact, or Augur file was modified.
- Consistent with the earlier command-injection and SSRF experiment rounds: independent labeling -> library
  generation from reviewed labels only -> formal results produced solely by the pass query
  (`queries/Pass5_SQLInjection.ql`, `@kind path-problem`, `@problem.severity error`,
  `@id py/augur/piccolo/pass5-sql-injection`, CWE-089 tag); bind-parameter findings would be filtered at Step 6
  reporting per the WORKFLOW.md SQL heuristics.
- Expected behavior of the formal query on this snapshot (prediction, to be confirmed when the query is run):
  findings on the raw-SQL channel pair (p5-src-007 -> p5-snk-019: `Table.raw`/`WhereRaw` template argument),
  the Alter/Savepoint DDL identifier channels (p5-src-008 -> p5-snk-008/014 via the summary steps), the AS OF
  interval (p5-src-012 -> p5-snk-018) and the ON CONFLICT target (p5-src-013 -> p5-snk-018); **no** findings from
  the CLI/env/file boundaries (bound-parameter channel) - matching the reviewed expectation that no library-side
  external input reaches SQL text unparameterized.
