# Query Generation Notes — postgraas_server, Pass 5 (CWE-89)

**Augur Phase 2 Step 4–5** · generated 2026-10-21 · run `postgraas-server-iris-pass5-20261021`
**Generated files** (this round is generation-only — no compile, no query execution, no database
analysis):

| File | Content |
| --- | --- |
| `libraries/MySources.qll` | formal taint sources, pass key `sql_injection` |
| `libraries/MySinks.qll` | raw-SQL execution sinks, pass key `sql_injection` |
| `libraries/MySanitizers.qll` | barrier predicate, resolves to `none()` |
| `libraries/MySummaries.qll` | 8 evidence-pinned additional taint-step families |
| `queries/Pass5_SQLInjection.ql` | formal path query (`@kind path-problem`, id `py/augur/postgraas_server/pass5-sql-injection`) |

Pack: `iris/qlpack.yml` (`iris/postgraas-server-cwe89`, `codeql/python-all: "*"`, pack root =
`iris/` — hence `import libraries.MySources` dot syntax). Target toolchain: CodeQL CLI 2.25.1,
python-all 7.1.x (per `exploration/detection.json` toolchain notes).

## 0. Review gate record

`labels/labels.json` (80 entries; run `postgraas-server-iris-pass5-20261021`) is the reviewed input.
`labels/review_decision.json` **does not exist as a file** — no written review-decision artifact was
produced in Phase 1. The human approval recorded for this run is the Phase 2 instruction itself
(2026-10-21: "第 5 步人工审核通过的 labels/labels.json … 生成 CodeQL 污点模型与路径查询"), which
names the label set as review-passed. Per the Phase 1 review (`labels/phase1_review.md` §5), two
threat-model questions were left open (second-order DB-content source; pg_cluster deployment
precondition) — see §6 below for how they affect rendering. **No label was modified**; if rendering
needs deviate from labels, the deviation is recorded here (§1) rather than by editing labels.json.

Rendering rule (consistent with the maltrail pass-2 formal/diagnostics convention, adapted to this
round's single-pass-key mandate): the formal pass key `sql_injection` renders classification `tp`
entries only. The 5 `candidate` entries are not rendered (a diagnostics variant would admit them;
none is generated this round — it is not in the task's file list).

## 1. Label ID → QLL predicate mapping (all reviewed tp entries)

### 1.1 Sources (5 tp entries)

| Label | Location | Rendering |
| --- | --- | --- |
| p5-e-033 | management_resources.py:133 `args = parser.parse_args()` (POST) | `MySources::isSource` — `reqparseSource`: `parser.parse_args()` call result, file+receiver+line pinned |
| p5-e-028 | management_resources.py:74 `args = parser.parse_args()` (DELETE) | `MySources::isSource` — same predicate, line 74 |
| p5-e-045 | postgres_cluster_driver.py:19 `check_db_or_user_exists(db_name, ...)` param 0 | **deliberately NOT rendered as a source** — parameter of a function containing `cursor.execute` (Phase 2 directive). Its attacker-reachability is realized from parse_args via the summary edges in §1.3; the label itself is unchanged in labels.json |
| p5-e-046 | postgres_cluster_driver.py:19 param 1 (`db_user`) | same as p5-e-045 |
| p5-e-048 | postgres_cluster_driver.py:30 `create_postgres_db(connection_dict, ...)` param 0 | same as p5-e-045 |

Rationale for the non-rendering: these three labels record the SQL-layer trust boundary, but
modeling them as taint sources would only produce internal param→execute paths without external
origin. The full attacker chain (external boundary → wrappers → SQL text) is modeled instead, so
every formal alert carries the true external source in its path.

### 1.2 Sinks (8 tp entries)

| Label | Location | Rendering |
| --- | --- | --- |
| p5-e-068 | driver :22 `cur.execute("SELECT 1 FROM pg_database WHERE datname='{}';".format(db_name))` | `MySinks::isSink`, lines [22,24,43,44,50,52,65,75], arg 0 |
| p5-e-069 | driver :24 `cur.execute("SELECT 1 FROM pg_roles WHERE rolname='{}';".format(db_user))` | same |
| p5-e-071 | driver :43 `cur.execute(create_role)` (template :36 CREATE USER … '{db_pwd}') | same |
| p5-e-072 | driver :44 `cur.execute(grant_role)` (template :38 GRANT {db_username} …) | same |
| p5-e-073 | driver :50 `cur.execute(create_database)` (template :41 CREATE DATABASE {db_name} OWNER {db_username}) | same |
| p5-e-074 | driver :52 `cur.execute(drop_role)` (template :37, error-cleanup path) | same |
| p5-e-076 | driver :65 `cur.execute('DROP DATABASE "{}";'.format(db_name))` | rendered but inert in the formal graph (its only origin is the candidate delete path, §6) |
| p5-e-078 | driver :75 `cur.execute('DROP USER "{}";'.format(get_normalized_username(username)))` | same as p5-e-076 |

Rejected sink labels not rendered: p5-e-079 (`prometheus_app.py:40` — static literal SQL, fp) and
all 10 `orm_query` rows (fp — ORM bound-parameter channel).

### 1.3 Summaries (17 tp entries)

| Label | Location | Rendering |
| --- | --- | --- |
| p5-e-003 | backends/postgres_cluster/__init__.py:9 `create(self, entity, connection_info)` param 1 | native call flow (param → `pgcd.create_postgres_db(connection_info)` at :11) — no extra edge emitted |
| p5-e-004 | backends :11 `create_postgres_db(connection_info, self.config)` arg 0 | native (ordinary resolvable call, arg → param) — no extra edge |
| p5-e-041 | management_resources.py:158 `exists(db_entry)` arg 0 | `backendDispatchStep` — :158 arg 0 → `PGClusterBackend.exists` entity param (position 1) |
| p5-e-043 | management_resources.py:164 `create(db_entry, db_credentials)` arg 1 | `backendDispatchStep` — :164 arg 1 → `PGClusterBackend.create` connection_info param (position 2); plus `dispatchDictElementStep` — the `args[...]` dict-literal values at :143-145 → the same parameter (element-to-container taint is not default-modeled) |
| p5-e-036 | management_resources.py:152 `db_name=args['db_name']` (DBInstance kwarg) | `dbInstanceFieldStoreStep` — DBInstance(:150) keyword values → constructor call result (object taint) |
| p5-e-037 | management_resources.py:153 `username=db_credentials['db_username']` | same predicate |
| p5-e-006 | backends :16 `delete(self, entity)` param 0 | `pgClusterFieldStep` — entity param → `entity.db_name`/`entity.username` loads at :18/:19 (delete branch; inert in the formal graph) |
| p5-e-007 | backends :18 `pgcd.delete_database(entity.db_name, ...)` arg 0 | covered by `pgClusterFieldStep` (the attribute-load node is the step target; arg→param onward is native) |
| p5-e-009 | backends :19 `pgcd.delete_user(entity.username, ...)` arg 0 | same |
| p5-e-011 | backends :26 `exists(self, entity)` param 0 | `pgClusterFieldStep` (exists branch — live via the :158 dispatch) |
| p5-e-012 / p5-e-013 | backends :27 `pgcd.check_db_or_user_exists(entity.db_name, entity.username, ...)` args 0/1 | covered by `pgClusterFieldStep` |
| p5-e-050 | driver :56 `get_normalized_username(username)` param 0 | `getNormalizedUsernameStep` — param → the returned `username.split('@')[0]` expression (:57) |
| p5-e-067 | driver :19 `check_db_or_user_exists` (internal_sql_wrapper) | `driverFormatConstructionStep` — db_name param → :22 `.format` result; db_user param → :24 `.format` result |
| p5-e-070 | driver :30 `create_postgres_db` (internal_sql_wrapper) | `connectionDictStep` — connection_dict param → element reads (:31 ×2, :38) and `.format` template results (:36/:37/:38/:41) |
| p5-e-075 | driver :60 `delete_database` (internal_sql_wrapper) | `driverFormatConstructionStep` — db_name param → :65 `.format` result (inert formally) |
| p5-e-077 | driver :70 `delete_user` (internal_sql_wrapper) | `driverFormatConstructionStep` — username param → :75 `.format` result (inert formally) |

One enabling edge has **no label of its own**: `reqparseFieldStep` (parse_args call result →
`args[...]` element reads within the same handler, line-range-pinned :74→[75..113] and
:133→[134..180]). It is the necessary bridge for the two rendered sources — the per-field
reqparse gap is documented in `exploration/detection.json` uncoveredCases ("reqparse per-field
rows… field names are visible in the source context"). Evidence: `args = parser.parse_args()`
followed by `args['db_name']` etc. in the same functions.

Candidate summary labels not rendered (per §0 rule): p5-e-030 (:95 `exists(entity)` dispatch),
p5-e-031 (:107 `delete(entity)` dispatch) — delete-handler dispatch sites whose taint origin is
also candidate. The 45 fp/none entries are rejected labels and are not rendered anywhere.

## 2. Sink modeling evidence (API, receiver, argument index)

- **API**: psycopg2 DB-API `cursor.execute(query)`; **receiver**: `cur` — the local cursor from
  `with con.cursor() as cur` in every driver function (driver :21, :35, :63, :73); **dangerous
  argument**: positional index 0 — the SQL query text. All 8 sink nodes are
  `DataFlow::exprNode(c.getPositionalArg(0))`.
- **Execution evidence** per site (each label's first evidence string is the verbatim line):
  :22/:24 interpolate `db_name`/`db_user` directly inside the execute argument; :43/:44/:50/:52
  execute the variables `create_role`/`grant_role`/`create_database`/`drop_role` built at :36-:41
  with `str.format` + `**connection_dict`; :65/:75 format `db_name`/normalized `username` inside
  the execute argument.
- **Bound-parameter discipline**: no `execute` call in the snapshot passes a second positional
  argument — there is no `execute(query, params)` shape anywhere, so no bound value can be
  mis-modeled as SQL text (and conversely: the absence of the binding channel is the
  vulnerability). The sink predicate matches argument 0 only and would continue to do so if a
  parameterized form were introduced; the prometheus site (`cursor.execute(sql)`, receiver
  `cursor`, static literal) is excluded by file+line+receiver pinning.
- **No other raw-SQL execution API exists** in the snapshot: no `executemany`, no SQLAlchemy
  `text()`/`from_statement()`/`engine.execute()`, no Django `raw()`/`RawSQL()`/`extra()`, no
  `callproc`. Nothing was modeled by name alone for absent APIs.

## 3. Source modeling evidence (boundary, controllability, chain)

- **Boundary**: flask-restful `reqparse.RequestParser().parse_args()` at the two REST resources
  registered in create_app.py:37-38. POST collects `postgraas_instance_name`/`db_name`/
  `db_username`/`db_pwd` (all `required=True, type=str` — coercion only, no validation); DELETE
  collects `db_pwd`. The endpoints carry **no authentication**; any client reaching the service
  controls these values verbatim.
- **Controllable scope**: full string content of the four POST fields and `db_pwd`. What reaches
  SQL text: `db_name`, `db_username`, `db_pwd` (via `db_credentials`); `postgraas_instance_name`
  never enters SQL text (docker container naming / ORM filter only — label p5-e-035 rejected).
  `db_pwd` from DELETE flows to `psycopg2.connect(password=…)` — a credential channel, not SQL
  text (label rationale documented; source kept for recall).
- **Propagated chain (source-side evidence)**: `parse_args` → `args['db_name']` etc.
  (`reqparseFieldStep`) → `db_credentials` dict literal :142-148 (`dispatchDictElementStep` across
  the :164 dispatch) → `PGClusterBackend.create` connection_info → `pgcd.create_postgres_db`
  connection_dict (native) → templates/driver sinks; and `args['db_name']` → DBInstance kwarg
  :152 (`dbInstanceFieldStoreStep`) → db_entry object → :158 dispatch
  (`backendDispatchStep`) → `entity` param → `entity.db_name`/`entity.username`
  (`pgClusterFieldStep`) → `check_db_or_user_exists` → SELECT sinks.

## 4. SQL construction, identifier handling, binding, ORM, sanitizer evidence

- **Dynamic construction**: all 8 statements are `str.format` products (labels merged the
  `sql_format_call` extraction rows into the execute entries). No f-string / `%` / concatenation
  SQL exists in non-test code. The `**connection_dict` unpacking into `.format` (driver :36/:37/
  :41) and the param-at-call-site form (:22/:24/:65/:75) are both covered by pinned edges
  (`connectionDictStep`, `driverFormatConstructionStep`).
- **Identifier/structural positions**: `db_name` and `db_username` are interpolated as
  **identifiers** (CREATE DATABASE {db_name}, GRANT {db_username}, DROP DATABASE/USER "{}") and
  `db_pwd` inside a **string literal** ('{db_pwd}') — unquoted, so a single quote breaks out. The
  double-quote quoting at :38/:65/:75 is partial identifier quoting only; no whitelist and no
  safe identifier API (psycopg2 `sql.Identifier` etc.) exists → **not a barrier** (documented in
  MySanitizers.qll header). No ORDER BY / column-name user control exists in the snapshot.
- **Parameter binding**: none (see §2). ORM (flask-sqlalchemy) is parameterized and rejected as a
  sink channel; it is a separate safe channel, not a sanitizer on the driver path.
- **Sanitizers**: confirmed set empty — `MySanitizers::isBarrier` resolves to `none()`
  (WORKFLOW.md 5.2.3: the mandatory barrier hook exists and never blocks unconditionally).

## 5. Custom summary necessity and CodeQL limitations

Each emitted edge family models a propagation that is (a) proven by source text and (b) **not**
covered by CodeQL default flow:

1. `reqparseFieldStep` — elements of the parser-returned dict (container content, no default step).
2. `backendDispatchStep` / `dispatchDictElementStep` — `current_app.postgraas_backend.<m>(...)`
   resolves at runtime via the BACKENDS dict (`backends/__init__.py:4/:14`); default call tracking
   cannot bind it to `PGClusterBackend`. Dict element→container taint is also not default-modeled.
3. `dbInstanceFieldStoreStep` + `pgClusterFieldStep` — object-field taint through the
   `DBInstance(...)` constructor (`__init__` self-assignments at management_resources.py:37-44)
   and later `entity.<field>` reads; not default-modeled for untyped objects.
4. `connectionDictStep` — parameter dict element reads and `**`-unpacking into `.format`.
5. `getNormalizedUsernameStep` / `driverFormatConstructionStep` — same-line param → SQL-text
   hops; the latter also removes the dependency on the default library's `str.format` flow-summary
   coverage, which **cannot be compile-verified in this generation-only round** (documented
   assumption; if the pack does model `.format` arg→result, the edges are redundant but harmless —
   same sources, same sinks, same line-pinned evidence).

**Assumptions relying on native flow** (to re-check at first compile): (i) the relative-import
alias call `pgcd.create_postgres_db(...)` (backends :11) resolves for interprocedural arg→param
flow; (ii) `str.format` arg→result is modeled by the default taint library (hedged by
`driverFormatConstructionStep`/`connectionDictStep`); (iii) `Function.getAnArg()` +
`Parameter.getPosition()` semantics (position 0-based with `self` at 0 on methods — the labels'
arg_index plus one on methods, equal on module-level functions).

**Uncovered / deliberately not modeled**: the docker backend (no SQL channel); `<int:id>` route
params (int-typed, ORM-bound only); operator config/CLI/secrets (not attacker-controlled); the
prometheus static SQL; ORM channel. **Diagnostics**: no diagnostics query is generated this round
(it is not in the task's file list). If wrapper-internal verification is wanted later, add
`Pass5_SQLInjection_diagnostics.ql` with pass key `sql_injection_diagnostics` that additionally
admits the 5 candidate labels (p5-e-029/:030/:031/:051/:053) — its paths must not be counted as
formal CWE-89 findings (maltrail pass-2 precedent).

## 6. Expected formal reachability (to verify at Step 5)

From the two parse_args sources, the summary edges complete these paths:

- POST create path → `connection_dict` param → check SELECTs (:22, :24) and the CREATE USER /
  GRANT / CREATE DATABASE / DROP ROLE sinks (:43, :44, :50, :52) — via `dispatchDictElementStep`
  → native wrapper call → `connectionDictStep` (+ `driverFormatConstructionStep`).
- POST exists path → DBInstance field stores → :158 dispatch → `entity.db_name`/`entity.username`
  → check SELECTs (:22, :24) — via `dbInstanceFieldStoreStep` → `backendDispatchStep` →
  `pgClusterFieldStep`.

Sinks :65 (DROP DATABASE) and :75 (DROP USER) match the sink predicate but have **no formal source
path**: their taint origin (query.get:76 → :107 dispatch, the second-order delete path) is
classification `candidate` and excluded from the formal key — the two open threat-model questions
from `labels/phase1_review.md` §5. Alerts for :65/:75 would appear only under the diagnostics key.
The DELETE-handler parse_args (:74) reaches no sink (db_pwd → connect credentials) — also
expected, not a modeling gap.

## 8. Compile check record (post-generation fix, 2026-10-21)

The generation round deliberately deferred compilation; the user then ran
`codeql query compile --check-only` and hit a parse-error cascade in `MySummaries.qll`. Root
cause: the private step predicates had used `from`/`to` as parameter names — `from` is a
reserved QL keyword (`from` clause), so the parser failed at `MySummaries.qll:122` and every
downstream error (select/where clause complaints, unresolved `reqparseFieldStep/2` etc.,
`DataFlow::` type failures) was cascade noise from that single token. Fix: renamed the
parameters to `nodeFrom`/`nodeTo` throughout the private predicates (the public
`isAdditionalTaintStep` already used `nodeFrom`/`nodeTo`). No modeling or label content
changed — the edges, pins and evidence are untouched.

Post-fix compile check: `codeql query compile --check-only queries/Pass5_SQLInjection.ql`
**passes** (`Done [1/1]`). The API assumptions of §5 that were unverifiable at generation time
are now at least type/arity-verified: `Function.getAnArg()` + `Parameter.getPosition()`,
`Call.getAKeyword()` + `Keyword.getValue()`, `Call.getPositionalArg(int)`,
`getLocation().getFile().getRelativePath()`, `getStartLine()`, the `Attribute`/`Subscript`/`Name`
casts and the `module Pass5Flow = TaintTracking::Global<Pass5Config>; import
Pass5Flow::PathGraph` shape all resolve against python-all 7.x.

One remaining warning is intentionally kept: `The @id property should be a valid query
identifier` — the mandated id `py/augur/postgraas_server/pass5-sql-injection` contains an
underscore, which the identifier grammar dislikes. The id stays exactly as the task contract
specifies; per WORKFLOW.md §8.4 this is a non-blocking naming warning (the query compiles and
runs).

## 9. Isolation principles (series-consistent)

- Labeling (Phase 1 Step 3) was performed independently of PyVul ground truth; this generation
  step renders only those reviewed labels. No PyVul vulnerability ground truth, fix diffs, CVE
  descriptions or external advisories were consulted at any point; `CVE申请报告.md` at the source
  tree root was never opened; the `postgraas_server-db` / `postgraas_server-safe-db` directories
  were not traversed.
- Formal results, when Step 5 runs, will come exclusively from
  `queries/Pass5_SQLInjection.ql` with the reviewed label set; a tp label or a formal alert is an
  API-role/judgment statement, **not** PyVul ground-truth confirmation, and must not be compared
  against or tuned toward any ground-truth artifact before the final report is frozen.
- The source tree, the CodeQL databases, the Phase 1 artifacts (labels, extraction, exploration)
  and the Augur installation were not modified. Files written this round: the four
  `libraries/*.qll`, `queries/Pass5_SQLInjection.ql`, and this file.
