# Query Generation Notes — Pass 5 (CWE-89 SQL Injection), RTX

**Augur Phase 2, Step 4–5** · Run `rtx-cwe89-pass5-labeling-20261021` · 2026-10-21

Generated files (this round; not compiled or executed, per instructions):

- `libraries/MySources.qll` — `MySources::isSource(DataFlow::Node, string passKey)`
- `libraries/MySinks.qll` — `MySinks::isSink(DataFlow::Node, string passKey)`
- `libraries/MySanitizers.qll` — `MySanitizers::isBarrier(DataFlow::Node, string passKey)`
- `libraries/MySummaries.qll` — `MySummaries::isAdditionalTaintStep(DataFlow::Node, DataFlow::Node, string passKey)`
- `queries/Pass5_SQLInjection.ql` — `module Pass5Config implements DataFlow::ConfigSig`, `module Pass5Flow = TaintTracking::Global<Pass5Config>`, `import Pass5Flow::PathGraph`, `flowPath(source, sink)`

All five artifacts use the pass key **`"sql_injection"`** exclusively. `qlpack.yml`
(`iris/rtx-cwe89`, dependency `codeql/python-all: "*"`) sits at the iris root, so the query uses
`import libraries.MySources`-style dotted imports against `iris/libraries/*.qll`.

## 0. Review-gate status

- `labels/review_decision.json` **does not exist** in `iris/labels/`. WORKFLOW.md §4.5 declares it
  an optional audit artifact, not a gate; the Phase-1 checkpoint summary exists
  (`labels/phase1_review.md`, incl. §5 human-review items). The operator's instruction to proceed
  with Phase 2 Step 4–5 on the basis of `labels/labels.json` is treated as the interactive-mode
  checkpoint approval. No label was modified in this round; all libraries are built strictly from
  the reviewed `labels.json` entries (11 tp sources, 11 tp sinks, 9 candidate sinks, 7 sanitizers,
  13 tp summaries).

## 1. Approved label → QLL predicate mapping

### 1.1 MySources.qll (`isSource`)

| Label ID | Location (source root: `dataset/codeql_databases/sql_injection_dbs/rtx_vuln/`) | QLL branch |
| --- | --- | --- |
| pass5-src-120 | `code/UI/OpenAPI/python-flask-server/openapi_server/controllers/asyncquery_controller.py:11` | `openApiHandlerBodyParam` — `request_body` param (pos 0) of `asyncquery()` |
| pass5-src-121 | `code/UI/OpenAPI/python-flask-server/KG2/openapi_server/controllers/asyncquery_controller.py:11` | `openApiHandlerBodyParam` (same branch, KG2 variant) |
| pass5-src-122 | `code/UI/OpenAPI/python-flask-server/openapi_server/controllers/query_controller.py:75` | `openApiHandlerBodyParam` — `request_body` param (pos 0) of `query()` |
| pass5-src-123 | `code/UI/OpenAPI/python-flask-server/KG2/openapi_server/controllers/query_controller.py:75` | `openApiHandlerBodyParam` (same branch, KG2 variant) |
| pass5-src-240 | `openapi_server/controllers/asyncquery_controller.py:24` | `requestJsonBodyCall` — `connexion.request.get_json()` call node |
| pass5-src-241 | `KG2/openapi_server/controllers/asyncquery_controller.py:24` | `requestJsonBodyCall` (same branch, KG2 variant) |
| pass5-src-242 | `openapi_server/controllers/query_controller.py:88` | `requestJsonBodyCall` — `connexion.request.get_json()` call node |
| pass5-src-243 | `KG2/openapi_server/controllers/query_controller.py:88` | `requestJsonBodyCall` (same branch, KG2 variant) |
| pass5-src-253 | `code/autocomplete/server.py:101` | `tornadoNodeslikeArguments` — `self.get_argument("limit")` call node in `nodesLikeSearch` |
| pass5-src-254 | `code/autocomplete/server.py:102` | `tornadoNodeslikeArguments` — `self.get_argument("word")` call node |
| pass5-src-255 | `code/autocomplete/server.py:103` | `tornadoNodeslikeArguments` — `self.get_argument("callback")` call node |

Matching technique: basename (`File.getShortName()`) + start line + callee attribute name +
(`get_json`: request-object shape from the extraction query's proven `RequestJsonCall` pattern;
body params: function name + parameter name/position via `Function.getArg`/`Parameter.(Name).getId()`).
Node construction: `DataFlow::parameterNode(p)` for parameters, `source.asExpr() = c` for call
results. The two server variants share basenames and line numbers, so one branch covers each
reviewed pair.

Not modeled (reviewed `source/fp`, 33 entries): `x-forwarded-for` headers (→ ORM bound insert of
`remote_address`), `get_status`/`get_logs`/`get_response`/`post_response`/`meta_knowledge_graph`/
`pubmed_mesh_ngd` params (→ ORM filters, named binds, file reads, HTTP lookups), entity `q`/`body`
(→ bound `?` lookups in `get_normalizer_results`), dead `/auto`,`/fuzzy`,`/autofuzzy`
`get_argument` calls (`rtxcomplete.prefix/fuzzy/autofuzzy` absent from this snapshot), and
`translate` (endpoint disabled, 501). None of these channels can reach a modeled sink, so modeling
them would only add cost, not recall.

### 1.2 MySinks.qll (`isSink`)

| Label ID | Location | QLL branch | Receiver / arg index |
| --- | --- | --- | --- |
| pass5-sink-055 | `code/autocomplete/rtxcomplete.py:49` | `rtxcompleteExecuteArg0` | module-global `cursor` (created in `load()`, rtxcomplete.py:25) · **arg 0** |
| pass5-sink-056 | `rtxcomplete.py:76` | `rtxcompleteExecuteArg0` | module-global `cursor` · **arg 0** |
| pass5-sink-057 | `rtxcomplete.py:88` | `rtxcompleteExecuteArg0` | module-global `cursor` · **arg 0** |
| pass5-sink-059 | `rtxcomplete.py:112` | `rtxcompleteExecuteArg0` | module-global `cursor` · **arg 0** (%-format SQL text) |
| pass5-sink-001 | `code/ARAX/ARAXQuery/Overlay/predictor/predictor.py:65` | `predictorGraphCurieLookup` | `self.graph_cur` · **arg 0** |
| pass5-sink-063 | `predictor.py:328` | `predictorDtdLookups` | local `cursor` (= `self.connection.cursor()`) · **arg 0** |
| pass5-sink-064 | `predictor.py:348` | `predictorDtdLookups` | local `cursor` · **arg 0** |
| pass5-sink-065 | `predictor.py:350` | `predictorDtdLookups` | local `cursor` · **arg 0** (tuple-repr IN list) |
| pass5-sink-066 | `predictor.py:370` | `predictorDtdLookups` | local `cursor` · **arg 0** |
| pass5-sink-067 | `predictor.py:372` | `predictorDtdLookups` | local `cursor` · **arg 0** (tuple-repr IN list) |
| pass5-sink-054 | `code/ARAX/ARAXQuery/Overlay/fisher_exact_test.py:579` | `fisherCategoryCountLookup` | local `cursor` · **arg 0** |
| pass5-sink-128 (candidate) | `code/ARAX/KnowledgeSources/COHD_local/scripts/COHDIndex.py:983` | `cohdPairBranchLookups` | local `cursor` · **arg 0** |
| pass5-sink-129 (candidate) | `COHDIndex.py:986` | `cohdPairBranchLookups` | local `cursor` · **arg 0** |
| pass5-sink-130 (candidate) | `COHDIndex.py:1007` | `cohdPairBranchLookups` | local `cursor` · **arg 0** |
| pass5-sink-131 (candidate) | `COHDIndex.py:1021` | `cohdPairBranchLookups` | local `cursor` · **arg 0** |
| pass5-sink-132 (candidate) | `COHDIndex.py:1023` | `cohdPairBranchLookups` | local `cursor` · **arg 0** |
| pass5-sink-133 (candidate) | `COHDIndex.py:1027` | `cohdPairBranchLookups` | local `cursor` · **arg 0** |
| pass5-sink-134 (candidate) | `COHDIndex.py:1029` | `cohdPairBranchLookups` | local `cursor` · **arg 0** |
| pass5-sink-135 (candidate) | `COHDIndex.py:1051` | `cohdPairBranchLookups` | local `cursor` · **arg 0** |
| pass5-sink-136 (candidate) | `COHDIndex.py:1053` | `cohdPairBranchLookups` | local `cursor` · **arg 0** |

**SQL execution API and evidence** — all sinks are DB-API `cursor.execute(query)` on sqlite3
connections:

- rtxcomplete.py:24 `conn = sqlite3.connect(database_name)`; :25 `cursor = conn.cursor()`; sinks
  at :49/:76/:88 are f-strings embedding `floor/ceiling/word/word_part/fragment_id` inside
  double-quoted SQL string literals, :112 is a `%`-format embedding `word`. Execution:
  `cursor.execute(...)` then `cursor.fetchall()`.
- predictor.py:88-89 `conn = sqlite3.connect(...)`; `self.graph_cur = conn.cursor()`; :65
  `row = self.graph_cur.execute(f"select * from GRAPH where curie='{curie_name}'")`; DTD db:
  `cursor = self.connection.cursor()` at :324/:343/:365, `cursor.execute(f"... '{disease}' ...")`.
- fisher_exact_test.py:571-572 `connection = sqlite3.connect(self.sqlite_file_path)`;
  `cursor = connection.cursor()`; :575-579 `sql_query = f"SELECT C.count FROM category_counts AS
  C WHERE C.category = '{node_type}'"` → `cursor.execute(sql_query)`.
- COHDIndex.py:561/875/1185 etc. `cursor = self.connection.cursor()` (connection from
  `sqlite3.connect(self.database_path)`); pair-branch executes e.g. :1023
  `f"... where concept_pair_id in {tuple(set(concept_id_pair1))};"`.

**Sink discipline (bind vs. text):** only the *query-text* argument (positional **argument 0**) is
a sink node (`sink.asExpr() = c.getArg(0)`). The bound-values argument (`execute(sql, (v,))`
second parameter) is never matched — reviewed parameterized call sites (node_synonymizer
:1747-:2320, rtxcomplete :106/:127, all ETL scripts, `sqlalchemy.text()` at
ARAX_query_tracker.py:283/:288/:291 whose user value goes through `.params(n=...)`) are excluded
by construction because their labels are role `none`/fp and no branch matches them.

### 1.3 MySanitizers.qll (`isBarrier`)

| Label ID | Location | QLL branch | Barrier node |
| --- | --- | --- | --- |
| pass5-san-001 | `rtxcomplete.py:34` | `intCastLimit` | `int(requested_limit)` call node |
| pass5-san-002 | `node_synonymizer.py:1931` (+1608/1952/2038 per label evidence) | `synonymizerQuoteDoubling` | `re.sub(r"'","''",…)` call nodes |
| pass5-san-003 | `ARAX_decorator.py:67` (+149) | `decoratorQuoteDoubling` | `.replace("'","''")` call nodes |
| pass5-san-004 | `fisher_exact_test.py:456` | `fisherQuoteDoubling` | `.replace("'","''")` call node |
| pass5-san-005 | `compute_ngd.py:346` | `ngdQuoteExclusion` | the `f"'{curie}'"` Fstring node (quote-exclusion comprehension) |
| pass5-san-006 | `COHDIndex.py:554` (guard :550-558; identical at :864-872, :1096-1104, :1174-1182, :1495-1509) | `cohdDatasetIdWhitelist` | `dataset_id` parameter nodes of the 5 verified guarded functions |
| pass5-san-007 | `ARAX_query_tracker.py:284` (+288/291) | `trackerNamedBind` | `.params(n=…)` call nodes |

Why these are valid SQL-context sanitizers: single-quote doubling is the correct escape for SQLite
single-quoted string literals — the exact SQL context of every guarded interpolation
(`IN ('...','...')` lists, `= '...'` predicates); the compute_ngd comprehension admits only values
that cannot contain the literal terminator; `int()` enforces a numeric type before the LIMIT
interpolation; the COHD guard is a value whitelist {1,2,3}; `.params()` is SQLAlchemy's named-bind
channel. Reviewed-and-rejected non-sanitizers are documented in the QLL header: COHD
`isinstance(int/list)` guards (list elements still reach tuple-repr interpolation — hence the
pair-branch sinks stay `candidate`, not sanitized) and fisher `convert_string_*` (re-casing, not a
whitelist — sink :579 stays tp).

san-006 is a control-flow value whitelist, not an expression barrier; it is modeled on the guarded
functions' `dataset_id` parameter nodes and is currently dormant (no modeled source reaches that
channel — the dataset_id candidates were labeled `none/fp`).

### 1.4 MySummaries.qll (`isAdditionalTaintStep`)

| Label ID(s) | Location | Edge |
| --- | --- | --- |
| pass5-src-253, -254, -255 (from) → pass5-src-147, -167 (to) | `server.py:101/102/103` → `rtxcomplete.py:29` | **Edge A** `tornadoWordHandoff`: get_argument call nodes → `word`/`requested_limit` params of `get_nodes_like` (models server.py:104) |
| pass5-src-240, -241 (from) → pass5-src-066 (to) | `asyncquery_controller.py:24` (both server variants) → `ARAX_query.py:216` | **Edge B1** `asyncqueryJsonToAraxEntry`: get_json node → `query` param of `query_return_message` (models asyncquery_controller.py:34) |
| pass5-src-159 (`openapi_server/controllers/query_controller.py:71`), pass5-src-160 (`KG2/.../query_controller.py:71`), pass5-src-161 (openapi :23), pass5-src-162 (KG2 :23), pass5-src-163 (openapi :61), pass5-src-164 (KG2 :61) (from) → pass5-src-065 (`ARAX_query.py:100`), pass5-src-066 (`ARAX_query.py:216`) (to) | `query_controller.py:23/61/71` → `ARAX_query.py:100/216` | **Edge B2** `controllerQueryDictToAraxEntry`: `query_dict` params of the three plumbing functions → `query` params of the ARAX entries (models query_controller.py:43 indirect `query_runner(query_dict)` call + :62/:72) |
| pass5-src-065, -066 (from) → pass5-src-053 (`node_synonymizer.py:1899`), -054 (:1905 `curies`), -064 (:1905 `names`) (to) | `ARAX_query.py:100/216` → `node_synonymizer.py:1899/1905` | **Edge C** `araxEntryToSynonymizerHub`: pipeline-entry `query` params → `curies`/`names` params of `get_canonical_curies`/`get_equivalent_nodes` |

Every edge is conditional (a specific from-node ↔ specific to-node pair) — no unconditional
propagation relation exists anywhere in the library. The three `summary/fp` entries
(`get_normalizer_results` entities, `get_concepts_by_first_word` entities,
`load_curie_to_pmids_data` canonicalized_curies) intentionally receive no edges: their channels
end in bound-parameter lookups or the quote-filtered interpolation, which cannot reach a modeled
sink.

## 2. Source boundaries, controllable scope and propagation chains

1. **Autocomplete chain (strongest)**: `GET /nodeslike` → `self.get_argument("word"/"limit"/"callback")`
   (server.py:101-103; the attacker fully controls these query strings) → **Edge A** →
   `get_nodes_like(word, requested_limit)` → `word` is interpolated unescaped into the f-strings at
   rtxcomplete.py:49/:76/:88 and the %-format at :112 (double-quote breakout). `limit` is int-cast
   (barrier san-001). Expected finding: source server.py:102 → sink rtxcomplete.py:49 (etc.).
2. **ARAX pipeline chain**: `POST /query`/`POST /asyncquery` body (`request_body` param and
   `get_json()` read; TRAPI query graph — qnode ids, curies, categories — plus
   `operations.actions` DSL strings) → **Edges B1/B2** → `ARAXQuery.query_return_message/query_return_stream`
   `query` param → **Edge C** → NodeSynonymizer canonicalization hub → IN-list SQL at :1987/:2048,
   where the quote-doubling barrier (san-002) cuts the path — matching the reviewed escaped/fp
   classification. The unescaped pipeline sinks (predictor :65/:328-372, fisher :579) are modeled
   as sinks but **no reviewed summary edge reaches their input parameters** (see §5 gap).

## 3. SQL-text construction, identifier handling, binding, ORM, sanitizers — evidence

- **Dynamic construction**: f-strings (rtxcomplete, predictor, fisher, COHD, node_synonymizer
  IN-lists), one `%`-format (rtxcomplete.py:112), `str.join` of escaped elements
  (node_synonymizer.py:1610/1935, ARAX_decorator.py:68/150), tuple-repr interpolation
  (`in {tuple(set(...))}` — predictor.py:350/372, COHDIndex.py:567 etc.).
- **Identifier/structural positions**: rtxcomplete interpolates `word` into a `LIKE "…"` literal
  and `requested_limit` into `LIMIT` (numeric position, int-cast); fisher interpolates `node_type`
  into a category predicate; COHD interpolates pair strings into a `concept_pair_id` predicate/IN
  list. No user-controlled table or column names and no user-controlled ORDER BY exist on live
  paths: table names in node_synonymizer/KGNodeIndex come from validated `kg_name`→hardcoded
  `kg2`/`kg1node` prefixes (labels `none/fp`), and COHD identifiers are type-guarded. The
  whitelist for `dataset_id` is barrier-modeled (san-006); no identifier whitelist is needed for
  the modeled tp sinks because none of them interpolates identifiers.
- **Parameter binding**: `cursor.execute(sql, (v,))` / `executemany(sql, rows)` throughout
  NodeSynonymizer access methods, KGNodeIndex, kg2c, GraphSage, ngd build, create_load_db,
  record_kg2c, rtxcomplete inserts — all role `none`, excluded from `isSink`.
- **ORM semantics**: SQLAlchemy appears as (a) declarative ORM `session.query/filter/add` in
  ARAX_query_tracker, ResponseCache, RTXFeedback — bound channels, not sinks; (b) one raw-SQL
  fragment family via `sqlalchemy.text()` at ARAX_query_tracker.py:283/:288/:291 — static SQL text
  with the `:n` named bind supplied through `.params(n=last_n_hours)` (san-007); `text()` object
  construction alone is not a sink per the reviewed labels. No Django, no psycopg, no RawSQL
  exist in this codebase (detection.json); neo4j Cypher is out of CWE-89 scope.
- **Sanitizers**: see §1.3; each barrier is anchored to the exact neutralizing expression.

## 4. Custom-summary necessity, dynamic calls, CodeQL limitations

- **Indirect call through a function-valued parameter** (query_controller.py:43
  `query_runner(query_dict)` with `_run_query_and_return_json_generator_*` passed at :107/:115):
  default taint tracking does not reliably resolve this — Edge B2.
- **Cross-module imports via sys.path manipulation** (`import rtxcomplete` from a sibling file;
  `from ARAX_query import ARAXQuery` across the ARAX tree): import resolution across the flat,
  non-package layout is uncertain — Edges A and B1.
- **DSL/TRAPI string parsing** (ActionsParser over `operations.actions`, query-graph dict
  traversal in expand/overlay): fundamentally beyond default data flow — Edge C carries reviewed
  taint from the pipeline entry to the canonicalization hub only.
- **Process boundary** (fork in `run_query_dict_in_child_process`): taint through the fork/pipe
  plumbing is approximated by Edge B2 from the plumbing parameter nodes; the actual pipe write/read
  is not modeled (the child executes in-process for analysis purposes).
- **API::Node vs DataFlow::Node**: this round's libraries are pure AST/dataflow — no API-graph
  nodes are used, so no `API::Node`↔`DataFlow::Node` conversion is required. (The Phase-1
  extraction queries used `API::CallNode` only to *report* module hints.)
- **Uncovered APIs / known under-reporting**: see §5.

## 5. Deficiencies recorded (no label modified — would require Step-5 re-review)

1. **predictor.py:65/:328-372 and fisher_exact_test.py:579 sinks have no inbound reviewed summary
   edge.** The Phase-1 candidates for their input parameters (e.g. `curie_name` of `get_feature`,
   sources.csv row → `pass5-src-135`-family) were labeled `none/fp` as internal parameters, and
   no summary label exists for `size_of_given_type_in_KP`'s `node_type` or the DTD list params.
   Consequently the formal query is expected to under-report these three tp sink families: they
   will only light up if CodeQL resolves the real ARAX pipeline call chain interprocedurally
   (unlikely through the DSL parsing). Adding edges `ARAX entry query → get_feature curie_name /
   DTD list params / size_of_given_type_in_KP node_type` would require new reviewed summary
   labels — i.e. returning to Step 5 for re-review, per the no-label-modification rule.
2. **COHD pair-branch sinks are second-order** (labels `candidate`, conf 0.55): the live input is
   produced by the trusted cohd.io REST API; findings there must be triaged with the
   `labels/phase1_review.md` §5 question (can cohd.io return crafted identifiers?) rather than
   reported as confirmed first-order injection.
3. **ARAXDecorator/node_synonymizer escaped sinks** (sink/fp) are reachable through Edge C but are
   cut by barriers — if the barrier lines ever regress, these would surface as findings, which is
   the intended conservative behavior.
4. **Diagnostics query**: none generated this round. The wrapper chains that needed verification
   (`query_controller` fork plumbing, `rtxcomplete.get_nodes_like` hand-off) are covered by the
   modeled summary edges, and no additional wrapper ambiguity was identified that would justify a
   separate `iris/diagnostics` query; any future diagnostic query must keep its paths out of the
   formal CWE-89 results (it would live under `iris/diagnostics/`, never `iris/queries/`).

## 6. Isolation principles (consistent with the prior command-injection and SSRF experiments)

- Labeling (Phase 1) and library/query generation (Phase 2 Step 4–5) were performed **independently
  of PyVul ground truth, fix commits and CVE advisories** — none were read; no vulnerability
  location was taken from external material. The formal CWE-89 results will come exclusively from
  `queries/Pass5_SQLInjection.ql` executed against `rtx-db` in a later step; the `labels.json` and
  these libraries remain an independent, auditable artifact chain (label ID → QLL branch → source
  line documented above).
- No source file, CodeQL database, extraction result, or Phase-1 label was modified. The generated
  files add only `iris/libraries/*.qll`, `iris/queries/Pass5_SQLInjection.ql` and this note.
- Query metadata: `@kind path-problem`, `@problem.severity error`, `@tags security`,
  `external/cwe/cwe-089`, id `py/augur/rtx/pass5-sql-injection`, precision `medium` (justified by
  the reviewed summary-edge approximations of the DSL pipeline; line-anchored sink/source matching
  is exact).

## 7. Verification performed (static, no compilation per instructions)

- API existence checked against the locally installed packs (`codeql/python-all 7.1.2`,
  `codeql/dataflow 2.1.7`): `DataFlow::parameterNode(Parameter)`, `Node.asExpr()`,
  `Function.getArg(int)`, `Parameter.(Name).getId()`, `Fstring` (Exprs.qll), `AstNode`,
  `File.getShortName()`, `getLocation().getStartLine()`, `DataFlow::ConfigSig` with
  `isAdditionalFlowStep(Node, Node)` (default `none()`), `TaintTracking::Global<Config>`,
  `PathGraph`/`flowPath` (template-prescribed). The AST-shape patterns mirror the Phase-1
  extraction queries that already ran on this exact toolchain (CodeQL CLI 2.25.1).
- Per WORKFLOW.md §3 rule 6, `isBarrier` is a real predicate delegating to `MySanitizers`
  (non-empty here); `MySummaries::isAdditionalTaintStep` contains only conditional reviewed edges,
  never `none()`-masked unconditional propagation.
- Python-specific pitfalls honored: no `Decorator` AST class, no deprecated `StrConst`, no use of
  `module` as a variable name, no unbound/invalid QL classes, no `API::Node`/`DataFlow::Node`
  mixing.
- Compilation and execution of the query are **deferred** to Step 5 of the formal run, per this
  round's instructions.
