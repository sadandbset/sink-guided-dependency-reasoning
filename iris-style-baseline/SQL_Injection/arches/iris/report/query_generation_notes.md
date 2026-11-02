# Augur Phase 2 — Step 4/5 Query Generation Notes

**Project:** arches (Arches 7.1.0-beta, Django) · **Pass:** 5 — CWE-089 SQL Injection
**Generated:** 2026-10-20 · **Run:** `arches-iris-pass5-20261020` · **Model:** glm-5.3 (in-session)
**Source tree:** `arches_vuln` @ sha `75ce8f7cb9c08caf608569797a40ca9be585b182` (= CodeQL DB `arches-db` creation sha)
**Toolchain basis:** CodeQL CLI 2.25.1, `codeql/python-all` 7.1.2 (local pack cache) — every AST/data-flow API used in the generated files was verified against the pack sources before writing; no query was compiled or executed in this round (per the task contract: generation only).

## 0. Inputs and review-gate status

- Label input: `iris/labels/labels.json` pass 5 (2085 entries; 895 source, 18 sink, 50 sanitizer, 45 summary, 1077 none), used **unmodified** — no label was edited during library generation (task constraint; had a change been needed, the deficiency would have been recorded and the label returned to Step-5 review instead).
- `labels/review_decision.json` was **not present** on disk when this step started. The human review gate was cleared by the operator's explicit instruction to execute Phase 2 Step 4–5 on the reviewed labels; this is recorded here because the WORKFLOW.md §4.5 optional audit artifact was never written. If a `review_decision.json` is desired for the audit trail, it should be added with this step's timestamp as the approval record.
- Pass-key policy: the four QLLs and the main query uniformly dispatch on `"sql_injection"` (single key, per the task directive). Unlike the maltrail pass-2 run, no separate `_diagnostics` pass key was introduced this round; the operator-trust `candidate` label entries are admitted under the formal key for conservative recall and are explicitly flagged for Step-6 triage (see §2.4).

## 1. Label ID → QLL predicate correspondence

### 1.1 MySources.qll (`MySources::isSource(n, "sql_injection")`)

| Label family (role/class, count) | Label IDs | QLL predicate | Node shape |
| --- | --- | --- | --- |
| http_request attr loads, source/tp, 292 | p5-s-0018 … p5-s-1312 (interleaved with other families by sort order; e.g. p5-s-0900/:0904/:0906 at views/concept.py:376/:382/:383) | `requestStateSource` | `request.GET/POST/FILES/META/body` Attribute expr (`GET`,`POST`,`FILES`,`META`,`body` on receiver Name `request`) |
| request_param reads, source/tp, 240 | p5-s-0030 … p5-s-1311 (e.g. p5-s-0901/:0905/:0907/:0909, p5-s-0914/:0915) | `requestParamReadSource` | `request.<dict>.get(key)` Call result + `request.<dict>[key]` Subscript |
| http_body deserializer args, source/tp, 22 | p5-s-0443 … p5-s-1142 | covered by `requestStateSource` | the reviewed node is the `request.body` Attribute (deserializer argument 0) — same expression node |
| param (handler params), source/tp, 235 | p5-s-0273 … p5-s-1309 (151 functions; table in `reviewedHandlerParameter`) | `handlerEntryParamSource` | reviewed non-`self` `Parameter` nodes, matched by (file, parameter line) — the labels record the parameter's own line (multi-line signatures, e.g. views/resource.py:131-136, give consecutive lines) |
| cli options, source/candidate, 80 | p5-s-1457 … p5-s-1807 | `cliOptionsSource` | `options["…"]` Subscript in export.py [43,44], packages.py [60 lines], v3.py [14 lines] |
| file open/read, source/candidate, 26 | p5-s-0429 … p5-s-1819 | `fileInputSource` | `open(...)` builtin Call / `<f>.read()` method Call in packages.py:609/610/621/622, v3.py [12 lines], v3migration.py [10 lines] |

Rejected label families (role `none`, fp) were **not** modeled: settings reads (445), env reads (16), `add_argument` registrations (123), non-SQL CLI options (~305), non-handler params (14), non-SQL file reads (70) — the rationale for each rejection is in `labels/phase1_review.md` §4.

### 1.2 MySinks.qll (`MySinks::isSink(n, "sql_injection")`)

| Label (id, class) | Site | QLL predicate / branch | Sink node |
| --- | --- | --- | --- |
| p5-k-141 tp | views/concept.py:426 `cursor.execute(sql)` | `reviewedExecuteSqlText` | positional arg 0 (`sql`) |
| p5-k-094 tp | models/concept.py:723 `cursor.execute(sql)` | `reviewedExecuteSqlText` | positional arg 0 |
| p5-k-100 tp | models/concept.py:1216 `cursor.execute(sql)` | `reviewedExecuteSqlText` | positional arg 0 |
| p5-k-140 tp | views/concept.py:424 `sql.format(query=query.lower(), …)` | `reviewedSqlConstruction` | format Call node + its args |
| p5-k-092 tp | models/concept.py:653 `sql.format(…, subquery=…)` | `reviewedSqlConstruction` | format Call node + its args |
| p5-k-099 tp | models/concept.py:1180 `"…'{0}'".format(conceptid)` | `reviewedSqlConstruction` | format Call node + its args |
| p5-k-091 tp | models/concept.py:635 `"…like '%%%s%%'" % query.lower()` | `reviewedSqlConstruction` | BinaryExpr(Mod) node + operands |
| p5-k-183/185 cand. | export.py:55/:61 `cursor.execute("SELECT…{0}".format(table))` | `reviewedExecuteSqlText` | positional arg 0 |
| p5-k-182/184/187 cand. | export.py:55/:61/:67 `.format(table …)` constructions | `reviewedSqlConstruction` | format Call node + its args |
| p5-k-193/195 cand. | packages.py:611/:623 `cursor.execute(sql)` (sql = `f.read()`) | `reviewedExecuteSqlText` | positional arg 0 |
| p5-k-130 cand. | v3migration.py:54 `self.dbcursor.execute(sql)` | `reviewedExecuteSqlText` | positional arg 0 |
| p5-k-129 cand. | v3migration.py:49 `ST_ForceRHR('{0}')` template `.format(value)` | `reviewedSqlConstruction` | format Call node + its args |
| p5-k-116/118 cand. | index_database.py:343/:370 `cursor.execute(sql)` | `reviewedExecuteSqlText` | positional arg 0 |
| (general channel, label-backed family) | all reviewed django.db execute sites (incl. the 66 fp rows — no flow, constant text) | `djangoCursorExecuteSqlText` | API-graph-bound `connection.cursor().execute` argument 0 |

Label wrapper rows p5-k-088 (get_child_edges :483), p5-k-098 (get_e55_domain :1172), p5-k-139 (paged_dropdown :381), p5-k-113 (index_concepts :278), p5-k-128 (fix_v3_value :33), p5-k-181 (shapefile :46) are function-level summary labels — they map to MySummaries call-site edges + default intra-procedural flow (§4), not to sink predicates.

### 1.3 MySanitizers.qll (`MySanitizers::isBarrier(n, "sql_injection")`)

| Label | Site | QLL predicate | Barrier node |
| --- | --- | --- | --- |
| 44 bound_params rows (tp; ETL 33, MVT 2, buffer 2, etl_manager 3, graph 3, etl_template 1, datatypes 1, index_database 1) | every reviewed `execute(sql, params)` / `callproc(proc, [args])` site | `boundParamsBarrier` | positional argument 1 (the params tuple/list) |
| p5-x-02 | views/concept.py:385 `int(request.GET.get("page", 1))` | `reviewedTransformBarrier` | the int() Call node |
| p5-x-03 / p5-x-04 | views/search.py:456 / map_filter.py:83 `float(width)` | `reviewedTransformBarrier` | the float() Call node |
| p5-x-05 / p5-x-06 | views/search.py:453 / map_filter.py:80 `GEOSGeometry(geojson, srid=4326)` | `reviewedTransformBarrier` | the GEOSGeometry Call node |
| p5-x-01 | models/concept.py:504 `uuid.UUID(conceptid)` guard | `reviewedTransformBarrier` | the uuid.UUID Call node (guard-shape caveat below) |

### 1.4 MySummaries.qll (`MySummaries::isAdditionalTaintStep(from, to, "sql_injection")`)

| Labels | Call site → callee parameter | QLL predicate |
| --- | --- | --- |
| p5-s-0902 (tp) | views/concept.py:377 `Concept().get_e55_domain(conceptid)` → `conceptid` param | `getE55DomainStep` |
| p5-k-088 chain (tp) | views/concept.py:389 `…get_child_collections_hierarchically(conceptid, …, query=query)` → `conceptid` + keyword `query` params | `getChildCollectionsHierarchicallyStep` |
| p5-s-0105/0106/0107 + p5-k-088 (tp) | models/concept.py:466 `self.get_child_edges(…, query=query, …)` → positional params + keyword `query` | `getChildEdgesStep` |
| p5-s-0108…0125 (tp) | models/concept.py:472/476/480 `self.get_child_edges(…)` → 6 positional params each | `getChildEdgesStep` |
| p5-s-0100/0102/0103/0132/0882/0883 (tp) | models/concept.py:64/246/252/1306, views/concept.py:262/267 `…get(args[0])` → Concept.get `id` (models/concept.py:108) | `conceptGraphLoaderStep` |
| p5-s-1266/1267/1268 (tp) | views/search.py:445 `_buffer(geometry, width, unit)` → params (module fn, positions 0-2) | `bufferStep` |
| p5-s-0220/0221/0222 (tp) | map_filter.py:40 `_buffer(feature_geom, width, unit)` → params | `bufferStep` |
| p5-s-1688/1689/1693/1694 (cand.) | packages.py:910/:960 `load_sql(package_location, …)` → params | `packageSqlStep` |
| p5-s-1690 (cand.) | packages.py:944 `load_resource_views(package_location)` → param | `packageSqlStep` |
| p5-k-181 (cand.) | export.py:44 `self.shapefile(dest=…, table=…)` → keyword params | `shapefileStep` |
| p5-k-128 (cand.) | v3migration.py:327 `fix_v3_value(dp[1], …)` → `value` param | `fixV3ValueStep` |

## 2. Sink semantics evidence

### 2.1 Execution API, receiver, dangerous argument index

`cursor.execute(query[, params])` is the **only** SQL execution channel in the project (74 sites); plus 2 `callproc` sites with constant procedure names (not sinks, per labels). Dangerous argument = **positional argument 0 (query text)**. Argument 1 is the bound-parameter channel — never a sink, always a barrier (`MySanitizers.boundParamsBarrier`). This implements the task directive "区分 cursor.execute(query, params) 中已绑定参数值与动态拼接的 query".

Receivers, verified per pinned site: `cursor` (django.db `connection.cursor()` — views/concept.py:425, models/concept.py:722/1215, export, packages, index_database), `self.dbcursor` (direct psycopg2 connection opened in `DataValueConverter.__init__`, v3migration.py:30-31). The general channel (`djangoCursorExecuteSqlText`) binds the receiver through API graphs — `API::moduleImport("django").getMember("db").getMember("connection").getMember("cursor").getReturn().getMember("execute").getACall()` — the same idiom as the stock PEP249/Django framework models (`semmle/python/frameworks/Django.qll` `DjangoDbConnection`, `Pep249.qll` `DefaultDatabaseCursor`/`ExecuteMethodCall`), so it is receiver-accurate rather than name-only inference. The v3migration psycopg2 cursor is deliberately **not** in the general channel (psycopg2 has no framework model here); it is covered by its pinned site.

Execution evidence for the tp sites (verbatim, from the tree):
- `views/concept.py:424-426`: `sql = sql.format(query=query.lower(), …)` → `cursor = connection.cursor()` → `cursor.execute(sql)` — `query` = `request.GET.get("query")` at :383.
- `models/concept.py:639-646 + 653 + 723`: `WHERE LOWER(values.value) like '%%%s%%'` `% query.lower()` (subquery) → `sql.format(…, subquery=subquery, …)` → `cursor.execute(sql)`.
- `models/concept.py:1186 + 1200-1202 + 1216`: `WHERE d.conceptidfrom = '{0}'` … `.format(conceptid)` → `cursor.execute(sql)` — `conceptid` = `request.GET.get("conceptid")` at views/concept.py:376, **no uuid validation on this path**.

### 2.2 Dynamic SQL construction, identifiers, ORDER BY

- Construction forms modeled: `%`-formatting (BinaryExpr `Mod`, p5-k-091) and `str.format(...)` template calls (7 pinned sites). Both are default CodeQL taint steps (`TaintTrackingPrivate.qll` `stringManipulation`/Mod clauses flow operands/arguments into the construction result), so the construction-node sinks are reachable; the argument/operand nodes are also matched so a path ends at the site under either encoding.
- **Identifier/structural slots (task directive)**: the operator-trust candidate paths are exactly the identifier-interpolation cases — `export.py` interpolates the CLI `-t/--table` value into `SELECT * FROM {0}` (table name, no whitelist — flagged candidate, not tp); `index_database.py` interpolates ORM-derived `valueTypes`/`topConcept` into CTE/IN-list positions (DB-content, no whitelist — candidate); `get_e55_domain` interpolates `conceptid` into a WHERE literal (remote-attacker value — tp). No ORDER BY / column-name interpolation from request data exists in the snapshot.
- No safe-identifier API (e.g. psycopg2 `quote_ident`) is used anywhere in the project — so no such sanitizer was modeled; bound parameters protect only value slots, and none of the tp/candidate structural slots are bound.

### 2.3 Parameter binding, ORM, absent channels

- Bound-parameter barrier covers all 44 reviewed `execute(sql, params)` / `callproc(proc, [args])` sites — the entire ETL staging pipeline, MVT (`api.py:264/:316`), buffer endpoints, ETL manager, graph command, etl_template, datatypes:1320, index_database:402. Values on argument 1 are driver-escaped; this is the proven parameterization evidence.
- Django ORM (`filter`/`exclude`/`Q`/`objects.get`) compiles to parameterized SQL and contains **zero** raw channels in this snapshot — verified by grep: `Manager.raw()`, `RawSQL()`, `QuerySet.extra()`, `from_statement()`, `executemany()`, `executescript()`, sqlite3 and SQLAlchemy `text()` do **not** occur. Nothing was modeled for them (no name-based inference, per the task directive); the MySinks header records this so Step 6 can cross-check.
- `callproc` argument 0 (procedure name) is constant at both sites ("__arches_slugify") → not a sink (labels fp); the argument-1 list is a barrier.

### 2.4 Candidate (operator-trust) entries under the formal key

The reviewed labels classified these as `candidate` (kept for conservative recall, human review requested). They are admitted under `"sql_injection"` this round per the approved labels: `export.py:55/:61/:67` (CLI table identifier), `packages.py:611/:623` (verbatim execution of operator `.sql` package files), `v3migration.py:49/:54` (v3 migration data into `ST_ForceRHR('{0}')`), `index_database.py:343/:370` (ORM-derived identifiers), plus their 106 source-side candidates (CLI `options[...]` / operator file reads) and 8 summary candidates. **Expected outcome:** alerts on these paths indicate operator-trust-level injection-shaped flows, not remote-attacker vulnerabilities; they must be triaged at Step 6 (filter/report) and by the human reviewer. This is the conservative-recall trade-off the labels chose; it is recorded here so the formal result is not over-read.

## 3. Source boundary evidence

| Family | External boundary | Attacker-controllable scope | Verified propagation chain into SQL |
| --- | --- | --- | --- |
| request state + param reads | Django HTTP request (`request.GET/POST/FILES/META/body`, `.get()`, `[...]`) on routes registered in `arches/urls.py` | full request content; `/concepts/paged_dropdown` and `/concepts/dropdown` have **no auth decorator** (verified at the function definitions; `@group_required("RDM Administrator")` exists only on the concept report view) | (A) `request.GET.get("query")` [:383] → `sql.format` [:424] → `execute` [:426]; and → `get_child_collections_hierarchically(query=)` [:389] → `get_child_edges` → `%` LIKE [:635/:646] → `format` [:653] → `execute` [:723]. (B) `request.GET.get("conceptid")` [:376] → `get_e55_domain` [:377] → `.format` [:1180-1202] → `execute` [:1216] |
| handler params | URL route parameters + request objects of the 151 reviewed view/context-processor/decorator/pagination functions | route segments (conceptid, nodeid, zoom, x, y, …) | MVT route params → bound parameters only (safe); concept() route conceptid → `get_child_edges` conceptid slot (uuid-guarded); concept-search `removechildren` → same uuid-guarded slot |
| http_body | `request.body` JSON via `JSONDeserializer().deserialize` | full JSON payload | no body→dynamic-SQL path exists in the snapshot (all body-fed SQL is bound-parameter; documented CodeQL decoding gap in §5) |
| CLI options (candidate) | `manage.py export/packages/v3` operator CLI | operator-supplied table names / package paths | `options["table"]` [:43/:44] → `shapefile(table=…)` [:44] → `.format` [:55/:61/:67] → `execute` [:55/:61]; `options[…]` → `load_sql(package_location, …)` [:910/:960] → `f.read()` [:610] → `execute` [:611] |
| file input (candidate) | operator package `.sql` files, v3 migration data files | file contents (operator trust) | `open().read()` [:610] → `cursor.execute(sql)` [:611]; v3 file data → `fix_v3_value(dp[1])` [:327] → `.format(value)` [:49] → `self.dbcursor.execute` [:54] |

Directive compliance: no parameter was made a source merely because its function contains `cursor.execute` — the model-layer helpers (`get_child_edges`, `get_e55_domain`, `_buffer`, `load_sql`, `shapefile`, `fix_v3_value`) enter the flow through MySummaries edges from real source nodes, never as sources themselves. The `request` object parameter is included per the labels (low-yield: attribute reads of a tainted object are not a default taint step); the operative request-taint nodes are the request-state/param-read families.

## 4. Custom summary necessity

- Python's default global taint tracking already propagates plain Python call arguments (positional **and** keyword) to callee parameters and models `%`-formatting, `str.format`, `str.lower`, concatenation and f-strings as taint steps (verified in `TaintTrackingPrivate.qll`). The reviewed summary edges are therefore mostly **redundant belt-and-suspenders**; they were still encoded because (a) they are exactly the reviewed label content, (b) method resolution on freshly-constructed instances (`Concept().get_e55_domain(…)`, `Concept().get(…)`) or instance attributes (`self.dt_converter.fix_v3_value(…)`) can fail to resolve in edge cases, and the pinned edges guarantee the two confirmed chains connect, and (c) the keyword hand-offs (`query=` at views/concept.py:389 and models/concept.py:466, `dest=`/`table=` at export.py:44) were explicitly noted as extraction gaps in `exploration/detection.json` `uncoveredCases` — the edges close those gaps deterministically.
- Every edge is conditional (bound to call-site file+line, target function name+file+def-line, and a specific argument/keyword→parameter mapping) — no unconditional propagation relation exists anywhere in MySummaries. Labels with role `none` (ETL transfers, celery delegation, setup_db transfers) intentionally have **no** edges.
- Function-level wrapper labels (p5-k-088/098/139/113/128/181) have no node-pair encoding; their semantics is realized by default intra-procedural flow + the call-site edges above (mapping table in §1.4).
- A diagnostics query (e.g. selecting the pinned sink sites and summary edges to verify library binding before Step 5 execution) was **not** generated this round because the task's output list is closed; it can be added on request — its results must not enter the formal CWE-89 findings (it would select `MySinks`/`MySummaries` hits directly rather than path problems).

## 5. Uncovered APIs, dynamic calls, CodeQL limitations

1. **uuid.UUID guard shape (p5-x-01)**: `get_child_edges` validates `conceptid` via `uuid.UUID(conceptid)` but then interpolates the *original* variable — a validation guard, not a transformation. The barrier (on the `uuid.UUID(...)` call node) therefore does **not** prune the conceptid-slot path; CodeQL will report the `paged_dropdown conceptid → get_child_edges` path even though that slot is guarded in reality. Known residual over-report, documented: the same sink remains genuinely reachable via the unvalidated `query` parameter, so the alert is a true positive either way; the guard would only matter for path-level triage.
2. **Decoding gaps**: `open(fh) → json.load(fh)` / `JSONDeserializer().deserialize(request.body)` argument-to-return decoding is not a default taint step (json.load is modeled only as a `Decoding::Range` concept, not as a taint step). Taint starting at an `open()`/`request.body` node does not reach decoded container elements. No reviewed label requires such a step (no body/file→dynamic-SQL path exists), so none was added — consequence: the v3 candidate chain may only partially connect (the `read()`-node sources and the v3migration.py:327 edge still work where the value flows directly).
3. **`self.dbcursor` (psycopg2)**: covered by the pinned site only; if future code adds psycopg2 execute sites, they need either pinned sites or a psycopg2 API model.
4. **Receiver-name tolerance in `boundParamsBarrier`**: any `<obj>.execute(...)/.callproc(...)` argument-1 node is barriered. All 76 `.execute/.callproc` sites in the snapshot are DB cursors (verified in Phase 1), so no false pruning is expected; a same-named non-DB method with a second positional argument would be wrongly barriered — accepted tolerance, same as the Phase-1 extraction.
5. **Location pinning**: sink/summary/barrier/candidate-source predicates pin (file, line) against sha `75ce8f7`. Line numbers agree 1:1 between the labels, the CSVs and the tree (Phase-1 verification; 150/150 spot-check). Any source change invalidates the pins — regenerate from labels after re-extraction.
6. **Django-dispatch (urls.py) not modeled**: handler parameters are matched from the reviewed label table, not from route registration; the stock `DjangoRouteHandler` framework modeling was not imported (label-faithful minimal surface). Route-param→view binding is therefore not re-derived by CodeQL; it was established in Phase 1.
7. **Multi-line call matching**: `Call.getLocation().getStartLine()` is the *expression start* (e.g. the `.format` call at models/concept.py:1180 spans :1180-1202 because its receiver string literal starts at :1180) — consistent with how the Phase-1 extraction recorded the same sites.

## 6. Isolation principles (consistent with the prior experiments)

- **Independent labeling → formal results**: the labels were produced in Phase 1 from repository evidence + language/framework references only; this step mechanically renders those labels into CodeQL predicates without consulting any ground truth. No PyVul vulnerability truth (`sql_sinks.csv`, `sql_safe_sinks.csv`, 漏洞审查报告.md, 分析结果test.md), no fix commits/diffs, no CVE descriptions and no external advisories were read in either phase (same policy as the maltrail pass-2 and the SSRF experiment series).
- **API-label tp ≠ vulnerability TP**: `classification: tp` in labels.json means "genuinely holds the assigned role" (a real source/sink site), not a confirmed vulnerability; the two confirmed vulnerability chains (§3) and the operator-trust candidates (§2.4) are separated in every artifact.
- **Formal result scope**: only `queries/Pass5_SQLInjection.ql` (path-problem, `@problem.severity error`, `@tags security external/cwe/cwe-089`, id `py/augur/arches/pass5-sql-injection`) produces formal CWE-89 findings; no diagnostics channel exists this round.
- **Nothing outside the 6 listed artifacts was written**: source tree, CodeQL database, extraction results, labels and the Augur installation are untouched. Compilation/execution is deferred to Step 5 proper (next round: `codeql database analyze` against `arches-db`).

## 7. Step-5 execution contract (for the next round)

1. `cd iris && codeql pack install` (pack `iris/arches-cwe89`, dependency `codeql/python-all: "*"`, resolvable from the local user pack cache — 7.1.2 present).
2. Compile first: `codeql query compile queries/Pass5_SQLInjection.ql --database <arches-db path>` to catch any API drift; the expected findings are the two confirmed chains (§3) plus operator-trust candidate paths.
3. Run sequentially, one query at a time: `codeql database analyze <arches-db> queries/Pass5_SQLInjection.ql --format=sarifv2.1.0 --output=results/pass5.sarif`; append runtime/alert counts to `results/run_log.md`.
4. Then Step 6: `python scripts/filter_and_report.py --input-dir iris/results --labels iris/labels/labels.json --output report/iris_report.md` with the pass-5 heuristics (parameterized queries → FP; operator-trust candidates → human review).
