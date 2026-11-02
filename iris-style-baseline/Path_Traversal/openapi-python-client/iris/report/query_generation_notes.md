# Augur Phase 2 Step 4–5 — Query Generation Notes (Pass 1: Path Traversal)

- **Target**: openapi-python-client 0.5.2 (`openapi-python-client_vuln`, CodeQL DB snapshot d6970d6)
- **Pass**: 1 — Path Traversal (CWE-022 / CWE-023 / CWE-036 / CWE-073), pass key `"path_traversal"`
- **Label basis**: `iris/labels/labels.json` (88 entries; run `openapi-python-client-pass1-labeling-20261022`, model glm-5.3), generated in Phase 1 Step 3
- **Generated files**: `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass1_PathTraversal.ql` (qlpack `iris/openapi-python-client-cwe22` at the iris root, dependency `codeql/python-all: "*"`, resolved against the local pack cache: python-all 7.1.1 / 7.1.2, codeql.dataflow 2.1.3/2.1.6/2.1.7)
- **Toolchain API verification**: every API used was re-verified against the installed library sources before generation — `DataFlow::ConfigSig` (`isSource`/`isSink`/`isBarrier`/`isAdditionalFlowStep`, codeql/dataflow 2.1.7 `DataFlow.qll:401-436`), `TaintTracking::Global<Config>` + `PathGraph` + `flowPath` (generic `TaintTracking.qll:167/313`, exported through `semmle.python.dataflow.new.TaintTracking`), `DataFlow::exprNode(Expr)` (`DataFlowPublic.qll:303`, the canonical Expr→Node conversion used throughout `Concepts.qll`), and the default-taint-step inventory of `TaintTrackingPrivate.qll` (concatStep covers `+` only — **not** `/`; stringManipulation covers `replace`/`lower`/`split` and f-string interpolation; containerStep covers literal stores only). AST shapes (Call/Attribute/Name casts, `getAKeyword`, `BinaryExpr`/Div, `AnnAssign`/`AssignStmt`, Location API) reuse the exact patterns already compiled and executed by `extraction/sources.ql` / `extraction/sinks.ql` on this database.
- **Compile validation** (performed after generation, at the user's request — see §8): `codeql query compile --check-only -- queries/Pass1_PathTraversal.ql` (CLI 2.25.1, pack-cache resolution, no `--additional-packs`) completes with **`Done [1/1]`, 0 errors, 0 warnings**. This is a compile check only — no database analysis (`codeql database analyze`) has been executed; that belongs to the Step 5 run phase.

## 0. Review-gate status (read before trusting the model)

`labels/review_decision.json` **does not exist**: Phase 1 ended at the advisory checkpoint (WORKFLOW.md §4.5) with `labels/phase1_review.md` as the review payload, and no approval artifact was ever written. Consequence for this step, applied consistently below:

- Only labels with `classification: "tp"` are compiled into the active source/sink models (they are the reviewed-and-confirmed set; `phase1_review.md` documents the evidence per entry).
- The 10 `candidate` rows (8 config-content sources S05/S07/S18–S23; 2 subprocess-cwd sinks K13/K14) are **excluded** and listed in section 6 with the exact conditions under which they should be added — this is a Step-5 review decision, not a query-generation decision, so no label was modified.

## 1. Label ID → QLL predicate mapping

### MySources.qll — `isSource(DataFlow::Node, string passKey)` (12 of 12 tp source labels)

| Label | Location | QL shape (all AST-level, module-restricted) | Source evidence |
| --- | --- | --- | --- |
| S01 (http_fetch, 0.90) | `__init__.py:71` | `Call` with `getFunc().(Attribute).getName()="get"`, qualifier `Name "httpx"`, in generator core module; node = `exprNode(call)` | `:71-72 response = httpx.get(url); yaml_bytes = response.content` |
| S02 (http_content, 0.95) | `__init__.py:72` | `Attribute "content"` on `Name "response"`, generator core; node = `exprNode(attr)` | `:72` — remote body → `yaml_bytes` → `:80 safe_load` |
| S03 (doc_read, 0.80) | `__init__.py:76` | `Call read_bytes` on `Name "path"`, generator core; node = `exprNode(call)` (return value, not the receiver) | `:76 yaml_bytes = path.read_bytes()` → `:80` |
| S04 (yaml_load, 0.95) | `__init__.py:80` | `Call safe_load` on `Name "yaml"`, generator core (the config.py:34 call is a *different*, candidate label); node = `exprNode(call)` | `:80 return yaml.safe_load(yaml_bytes)` |
| S06 (openapi_field, 0.95) | `__init__.py:94` | `Attribute "title"` on `Name "openapi"`, generator core | `:94 …f"{openapi.title.replace(' ', '-').lower()}-client"` → `:95 Path.cwd() / self.project_name` |
| S10/S11 (name_field, 0.90) | `__init__.py:196/:203` | `Attribute "module_name"` whose object is `Attribute "reference"` on a `Name`, generator core | `:196/:203 models_dir / f"{…module_name}.py"` |
| S24 (openapi_field, 0.95) | `parser/openapi.py:51` | `Attribute "tags"` on `Name "operation"`, parser module | `:51 tag = (operation.tags or ["default"])[0]` (see §5 — not connected to sinks) |
| S25/S26 (openapi_field, 0.85) | `parser/openapi.py:230/:271` | `Attribute "title"` on `Name "data"`, parser module | `:230 Reference.from_ref(data.title or name)`, `:271 EnumProperty(…, title=data.title or name, …)` |
| S27 (parse_obj, 0.85) | `parser/openapi.py:300` | `Call parse_obj` on `Attribute "OpenAPI"` on `Name "oai"`, parser module; node = `exprNode(call)` | `:300 openapi = oai.OpenAPI.parse_obj(d)`; fields consumed at `:310-313` |
| S28 (openapi_field, 0.90) | `parser/openapi.py:311` | `Attribute "title"` on `Attribute "info"` on `Name "openapi"`, parser module | `:311 title=openapi.info.title` → `GeneratorData.title` |

Excluded from the model: S05, S07, S18–S23 (candidate — operator-trust config content, §6) and S08, S09, S12–S17, S29, S30 (role `none`/fp — content-only fields and operator-trust CLI parameters).

### MySinks.qll — `isSink(DataFlow::Node, string passKey)` (21 of 21 tp sink labels)

| Labels | API & path position (arg index) | Sites | Access type & call relationship |
| --- | --- | --- | --- |
| K17 K19 K21 K23 K25 K30 K35 K37 K41 K45 K47 (file_write, 0.85) | `Path.write_text` — dangerous path is the **receiver** (arg_index null; argument 0 is the written *content* and is deliberately not the sink node) | `__init__.py :151 :154 :160 :172 :181 :192 :208 :214 :220 :225 :229` | File **create/write** (jinja template output). Called from `Project.build()`/`update()` via `_create_package`/`_build_metadata`/`_build_models`/`_build_api`; every receiver is a pathlib join of the title-derived `project_dir`/`package_dir`/`models_dir`/`api_dir` base (path escapes via the base). |
| K32 K34 (file_write, 0.95) | `Path.write_text` receiver | `:197 :204` | File create/write whose **file name** is the remote-derived `module_name` (`models_dir / f"{…}.py"`): separators/`..` survive snake_case; leading `/` makes the join absolute. |
| K49 K51 (file_write, 0.95) | `Path.write_text` receiver | `:235 :237` | File create/write named by the **raw** `operation.tags[0]` — zero transformation between document and file name. |
| K10 K15 K27 K39 K43 (dir_create, 0.90) | `Path.mkdir` receiver | `:109 :146 :186 :218 :223` | Directory **create** at the title/config-derived `project_dir`/`package_dir`/`models_dir`/`api_dir`; `build()` (:109) and the package/模型/api sub-builders. |
| K12 (dir_delete, 0.95) | `shutil.rmtree` — **argument 0** | `:125` | Recursive directory **delete** of `package_dir` in `Project.update()`; sole guard is `is_dir()` (:122, existence only). Highest impact. |

Excluded: K05/K56 (`read_bytes`/`read_text` receivers — operator-authorized reads, fp), K08 (`Path.cwd()` — base acquisition, not a file access), K11 (`is_dir` — stat, not an effect), K13/K14 (`subprocess.run` keyword `cwd` — candidate, §6), and the 20 `path_join` rows (see MySummaries).

### MySanitizers.qll — `isBarrier(DataFlow::Node, string passKey)` → `none()`

Zero sanitizer labels exist, and no barrier is invented (evidence in §3).

### MySummaries.qll — `isAdditionalTaintStep(Node, Node, string passKey)` (2 explicit edge families)

| Labels | Edge modeled | Why explicit |
| --- | --- | --- |
| K07 K09 K16 K18 K20 K22 K24 K26 K28 K29 K31 K33 K36 K38 K40 K42 K44 K46 K48 K50 (the 20 `/` joins, tp) | each operand (left base / right appended component) → the `BinaryExpr` result, restricted to `__init__.py` | Default taint steps propagate `+` (concatStep) but **not** `/` (Div) — without this edge no tainted operand reaches any sink receiver. All 20 Div exprs in the module are pathlib joins (grep: no arithmetic division in the file). |
| K06 (`Project.__init__`, tp) | value stored to `self.project_name/package_name/project_dir/package_dir` (AnnAssign :94/:95/:97/:98) → any read `self.<attr>` in the same module | Cross-method object-state flow is not default; this is the labeled object boundary that carries the title-derived names from `__init__` into `build()`/`update()`/`_create_package()`/`_build_models()`/`_build_api()`. Scope precision: the four attribute names are assigned only in `Project.__init__` and read only in Project methods within this module (grep-verified; `Config` writes differently-named class attributes). |

Default-covered summaries (mapped, no edge emitted): K01–K04, K52–K55 (CLI/wrapper param propagation — default interprocedural argument/return flow), K57/K58 (`snake_case`/`pascal_case` — parameter→return through `re.sub`/`stringcase` calls; unresolved external calls get the library's speculative arg→result step for potential library calls). F-string interpolation and `.replace()`/`.lower()`/`.split()` on tainted strings are default `stringManipulation` steps (`TaintTrackingPrivate.qll:97-166`, f-strings via `Fstring.getAValue()`).

## 2. Source external-input boundaries and access conditions

| Source | Trust boundary | Attacker control / preconditions |
| --- | --- | --- |
| S01/S02 (`httpx.get` return, `response.content`) | Network response body of the `--url` OpenAPI document fetch | Whoever controls the `--url` endpoint controls the full document bytes. The URL *value* itself is operator-selected (Pass 3 SSRF material, not modeled here). Fetching external specs is the tool's core use case. |
| S03 (`path.read_bytes` return) | File *content* of the operator-selected `--path` document | The operator picks the file, but the document is typically third-party-authored (downloaded spec) — same content trust as the URL case. The path *value* is operator-trust and is not a source. |
| S04 (`yaml.safe_load` return) | The document parse boundary | Every document field (title/version/paths/tags/schema names) enters here. `safe_load` is safe *deserialization* (Pass 6); the parsed values remain untrusted *names* for path construction. |
| S06/S10/S11/S24/S25/S26/S27/S28 | Use-site/parse-site anchors of remote document fields | No privilege checks exist anywhere on the path from document field to filesystem name — any document author reaches the sinks. |

Not sources (documented): CLI entry parameters (S12–S17, fp — the invoking user is the same trust domain as their own `--url/--path/--config` choices); config file content (S05/S07/S18–S23, candidate — see §6).

## 3. Containment / canonicalization / root / symlink evidence (why no barrier)

Grep over `openapi_python_client/` (this audit): **zero** occurrences of `os.path.*`, `resolve(`, `relative_to`, `startswith`, `basename`, `normpath`, `abspath`, `realpath`, `open(`, `zipfile/tarfile/extract`, `os.environ/os.getenv`. Specifically:

- **Path joining**: only the pathlib `/` operator (20 sites, all in `__init__.py`). pathlib `/` semantics *preserve* `..` segments and replace the base entirely when the right operand is absolute — the join amplifies rather than contains.
- **Decoding**: no `unquote`/`urllib.parse`/percent-decoding anywhere; single-stage name flow (document field → string reshaping → file name), so no decode-re-encode bypass surface exists (also none needed — nothing is filtered in the first place).
- **Normalization order**: no normalization happens at all, so there is no normalize-before-validate ordering question; equally, no validation exists to be bypassed.
- **Allowed root**: none is ever declared or checked. The only implicit root is `Path.cwd()` (`:95`); an absolute or `..`-bearing `project_name`/`package_name`/`module_name`/`tag` escapes it. The `FileExistsError` catch (`:110`) and `is_dir()` (`:122`) are *existence* checks (the latter TOCTOU-shaped: check at `:122`, recursive delete at `:125`, nothing in between).
- **Separators**: `replace(' ', '-')` + `lower()` (`:94`) touch spaces and case only; `snake_case`/`pascal_case` (`utils.py:6/:12`, regex + stringcase) reshape case/underscores only — `/`, `\` and `..` survive; the tag reaches the filename completely raw.
- **Symlinks**: no symlink handling exists in the audited code (pathlib `mkdir`/`write_text` and `shutil.rmtree` follow symlinks by default); recorded as *not applicable* rather than as a defense.

**Barrier verdict**: `MySanitizers::isBarrier` is `none()` — no mechanism in this implementation can be *proven* to block any traversal mechanism (leading `/`, `..` chains, absolute paths, Windows drive letters, separator variants), so none is credited.

## 4. Additional propagation edges — necessity proof

Only two edge families were added (see §1 table); both are label-rendered, scope-restricted, and each is *necessary*:

1. **`/` join edge** — the default library's `concatStep` handles `+` only (`TaintTrackingPrivate.qll:77-85`); without the Div edge, `Path.cwd() / self.project_name` (`:95`) would cut every source→sink path.
2. **Project field-flow edge (K06)** — cross-method instance-attribute flow is not default; without it, the title-derived names stored in `Project.__init__` (`:94-:98`) could never reach the receivers in `build()`/`update()`/`_build_*()`.

Everything else that the labels describe as propagation is default: interprocedural argument/return flow (the CLI wrapper chain), speculative arg→result for unresolved external calls (`re.sub`, `stringcase.*`), f-string interpolation, and string-method receiver→result.

Expected connected flows (for the Step-5 run to validate): **S06 → all 21 sinks** (title → project root escape, via the `/` edge + field-flow edge), **S10 → K32** and **S11 → K34** (name-controlled module writes, via f-string + `/` edge). S01–S04/S27 terminate at the pydantic/dataclass boundary (§5); S24 is not connected (§5); S25/S26 flow into `Reference.from_ref` but stop at the `Reference(...)` dataclass constructor — redundant anchors only.

## 5. Known limitations, dynamic-call/alias gaps, and diagnostics (NOT formal Pass 1 results)

1. **Tag path not connected (label-side gap, feedback to Step 5)**: source S24 (`operation.tags`, `openapi.py:51`, tp 0.95) cannot reach sinks K49/K51 with the reviewed label set: the chain `tag → EndpointCollection(tag=…) → endpoints_by_tag.setdefault → GeneratorData(endpoint_collections_by_tag=…) → Project(openapi=…) → self.openapi.endpoint_collections_by_tag.items() → for tag, collection … → f"{tag}.py"` crosses four boundaries no reviewed label bridges (dataclass constructor kwargs→object, dict setdefault, chained attribute read of a tainted object, `.items()` iteration). Modeling those would be unconditional cross-function pollution (forbidden), so the gap is recorded instead: **the reviewed labels lack a use-site anchor for the tag family analogous to S10/S11 for module names.** Recommended re-review at Step 5: add a source label at the `tag` loop-variable read inside the `:234/:236` f-strings (or a labeled summary for the `endpoint_collections_by_tag` object chain). Mitigation already in the model: K49/K51 still alert via the S06 title path (the `api_dir` base is title-derived), so the vulnerable *sites* are not missed — only the tag-specific *path explanation* is.
2. **Parse-side document sources terminate early**: S01–S04/S27 taint the `yaml.safe_load`/`parse_obj` results, but `GeneratorData(title=openapi.info.title, …)` (`openapi.py:310-317`) is a dataclass constructor call whose kwargs do not flow to the constructed object under default steps. This is why the labels redundantly anchor the title at the use site (S06) and parse-side copy (S28); the S27/S28 paths are recall insurance, not alert producers. Same for `Reference(class_name=…, module_name=…)` (`reference.py:30`) vs the S10/S11 use-site anchors.
3. **Speculative-taint dependency**: the `snake_case`/`pascal_case` propagation (K57/K58) relies on the library's speculative step for unresolved external calls (`stringcase`, `re` are not in the database). This is a CodeQL approximation, not a guarantee; it affects no expected alert (the module-name flows are anchored by S10/S11).
4. **`match_kind "ast"`**: all source/sink/summary matching is syntax-level (external libraries httpx/yaml/pydantic/pathlib/shutil are not in the database); the name+qualifier+module-restriction shapes are exact for this snapshot (site lists in the QLL headers match the extraction CSVs one-to-one) but would need re-review on a different version.
5. **Diagnostics query (do not count as formal Pass 1 alerts)** — to be run only if the Step-5 review wants wrapper/anchor debugging, e.g.:

   ```ql
   /** @id py/augur/openapi-python-client/pass1-diagnostics */
   import python
   import semmle.python.dataflow.new.DataFlow
   import semmle.python.dataflow.new.TaintTracking
   import libraries.MySources
   import libraries.MySinks
   // (a) do the modeled sources/sinks exist at the expected sites, and which
   //     pairs already connect with LOCAL taint only (same function)?
   from DataFlow::Node src, DataFlow::Node snk
   where libraries.MySources::isSource(src, "path_traversal")
     and libraries.MySinks::isSink(snk, "path_traversal")
     and TaintTracking::localTaint(src, snk)
   select snk, src, "locally connected pair"
   ```

   (sketch only — not a generated file; `TaintTracking::localTaint`/`localTaintStep` are the documented local-taint entry points of `semmle.python.dataflow.new.TaintTracking`. The intended diagnostics are: (a) source/sink existence counts vs the extraction CSV site lists, (b) the unconnected S24 tag chain, (c) whether the `f"{tag}.py"` join at `:234/:236` would connect if a use-site tag source existed). Any output of such a query is diagnostic only.

## 6. Excluded candidate labels — exact conditions for inclusion (Step-5 review decision)

| Labels | What they model | Inclusion condition |
| --- | --- | --- |
| S05, S07, S18–S23 (8 source rows) | `--config` file content → `project_name_override`/`package_name_override` (→ `Path.cwd()/…` and the `rmtree` target) and `class_overrides` → `Reference.module_name` | Add to `MySources` iff the review decides a shared/committed `--config` consumed in CI is inside the attacker model (labels' confidence 0.50–0.55, marked MANUAL REVIEW POINT). If config is fully operator-trusted, downgrade to fp in Step 3 instead. |
| K13, K14 (2 sink rows) | `subprocess.run("isort ." / "black .", cwd=self.project_dir)` — isort/black rewrite files under the title-derived cwd (keyword argument, no positional index) | Add a keyword-`cwd` sink shape to `MySinks` iff the review counts indirect file effects scoped by a tainted `cwd` as Pass 1 material. |

No change to `labels.json` was made in either direction — both groups are recorded here as the review's open items, per the rule that label gaps go back to Step 5, not into the query.

## 7. Compile-error analysis and fix (post-generation, user-initiated)

The user ran `codeql query compile --check-only "--additional-packs=$env:PACK" -- queries/Pass1_PathTraversal.ql` (CLI 2.25.1) on the initially generated files and hit a burst of parse errors at query lines 43/47/51/55 ("unexpected input 'MySources' expecting one of: '(', Lowerid", "could not resolve module MySources", cascading "predicate requires a body" / "module does not declare isSink/1"). Root cause and fix:

1. **Invalid qualification syntax**: the initial query called the library predicates as `libraries.MySources::isSource(...)`. In QL, import paths use dots (`import libraries.MySources`) but *name qualification* must use `::` exclusively — a mixed `dotted.path::name` reference is not parseable. (The Augur template's single `{{SOURCE_MODULE}}` placeholder cannot express both the dotted import line and the short module reference — the same template limitation was hit and documented by the django and gradio projects in this series.)
2. **Fix applied**: each library file now declares its public predicate inside a module named after the file (`module MySources { predicate isSource(...) }`, etc.; the private scope helpers moved inside the module as well), and the query references them as `MySources::isSource(source, "path_traversal")`, `MySinks::isSink(...)`, `MySanitizers::isBarrier(...)`, `MySummaries::isAdditionalTaintStep(...)` — exactly the interface the task contract specifies. No predicate signature, matching logic, label mapping or evidence changed; only the module wrapping and the call syntax. The library files themselves had produced **zero** errors in the user's compile (all reported errors were in the `.ql` file), confirming the AST/dataflow API usage of §"Toolchain API verification" independently of my library-source reading.
3. **Pack resolution note**: passing the whole user pack cache (`--additional-packs=C:/Users/lzh/.codeql/packages`) makes CodeQL fail with "Referenced pack found in multiple locations" (two python-all versions 7.1.1/7.1.2 etc. coexist in the cache). Resolution: compile **without** `--additional-packs` — plain pack-cache resolution picks the pinned/latest versions (7.1.2 family) and compiles cleanly; the same was observed in the sibling projects. (A `codeql pack install` in the iris root would pin versions in a `codeql-pack.lock.yml` if reproducible pinning is later required; it was not needed for this check.)

After the fix, `codeql query compile --check-only -- queries/Pass1_PathTraversal.ql` reports `Done [1/1]` with no errors and no warnings.

## 8. Experiment independence

Consistent with the whole series: no PyVul ground truth, no known CVE line numbers, no fix/patch or vulnerability-report material was consulted at any point; the repo-root audit-looking artifacts (`VULNERABILITY_AUDIT_REPORT.md`, `path_traversal_sinks.csv`) remain unread. The source tree, CodeQL database, Phase 1 CSVs and `labels.json` are unmodified — this step only added the six files listed at the top (plus this report). The `/tests/`, `/end_to_end_tests/` and `/openapi-python-client-db/` trees are structurally outside every predicate (module-path restrictions to `openapi_python_client/__init__.py` and `openapi_python_client/parser/openapi.py`).
