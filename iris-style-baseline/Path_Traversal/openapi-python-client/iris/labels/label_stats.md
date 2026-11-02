# Augur Phase 1 Step 3 — Label Statistics (Pass 1: Path Traversal)

- **Target**: openapi-python-client 0.5.2 (`openapi-python-client_vuln` source tree)
- **Pass**: 1 — Path Traversal (CWE-022 / CWE-023 / CWE-036 / CWE-073)
- **LLM model**: glm-5.3 (LLM API labeling via Claude Code CLI, temperature 0, JSON-only output)
- **Run ID**: `openapi-python-client-pass1-labeling-20261022`
- **Schema validation**: `labels.json` validated locally against `augur-0.3.0/assets/labels_schema.json` (jsonschema 4.26.0, Draft 2020-12) — **PASS**

## Candidate coverage

| Candidate set | Rows in CSV | Labeled | Dropped | Exact duplicates |
| --- | --- | --- | --- | --- |
| `extraction/sources.csv` | 30 | 30 | 0 | 0 |
| `extraction/sinks.csv` | 58 | 58 | 0 | 0 |
| **Total** | **88** | **88** | **0** | **0** |

No rows were excluded: the Phase 1 extraction queries had already filtered `/tests/`, `/end_to_end_tests/` and `/openapi-python-client-db/`, so every emitted row sits inside the `openapi_python_client` package (`__init__.py`, `cli.py`, `config.py`, `parser/openapi.py`, `utils.py`) and each was individually labeled. Deduplication was verified by exact key `(file, line, callable, flowKind, receiver, argIndex)` — no duplicate rows exist; near-duplicate rows (e.g. `title` read at `__init__.py:94` vs `:99`, `class_overrides` at `config.py:21` vs `:24`) were kept separate because they sit on genuinely different flows (path-relevant vs content-only; loop guard vs iteration source).

## Batches (7, stable sizes 11/12/7/15/19/17/7)

| Batch | Scope | Rows |
| --- | --- | --- |
| B1 | sources: `__init__.py` (http_fetch / content / doc_read / yaml_load / name fields) | 11 |
| B2 | sources: `cli.py` + `config.py` (CLI params, config fields, config load) | 12 |
| B3 | sources: `parser/openapi.py` (tags, titles, parse_obj, info fields) | 7 |
| B4 | sinks: `__init__.py` API defs, document fetch, core FS ops (mkdir / rmtree / is_dir / subprocess) | 15 |
| B5 | sinks: `__init__.py` joins + write_text / mkdir (package, metadata, models) | 19 |
| B6 | sinks: `__init__.py` remaining joins + writes (client / api / async_api, raw-tag modules) | 17 |
| B7 | sinks: `cli.py` / `config.py` / `utils.py` (API defs, read_text, snake_case / pascal_case) | 7 |

Per-batch raw records (every CSV row plus its label, rationale and evidence) are preserved in `labels_raw_pass1.json`.

## Labels by role × classification

| role | tp | candidate | fp | total |
| --- | --- | --- | --- | --- |
| source | 12 | 8 | 10 (labeled `none`) | 30 |
| sink | 21 | 2 | 4 (labeled `none`) | 27 |
| summary | 31 | 0 | 0 | 31 |
| sanitizer | 0 | 0 | 0 | 0 |
| **total** | **64** | **10** | **14** | **88** |

Notes: `role: none` entries carry `classification: fp` (the API exists but is judged irrelevant or operator-trust for Pass 1). Confidence range 0.50–0.95; entries below the 0.55 re-ask threshold are the intentionally retained human-review items (config-content sources at 0.50–0.55 and subprocess-cwd sinks at 0.55), recorded as `candidate` rather than re-asked, per the audit-trail policy.

## Top source labels (highest confidence)

| ID | API | Location | Confidence |
| --- | --- | --- | --- |
| S02 | `httpx.Response.content` | `__init__.py:72` | 0.95 |
| S04 | `yaml.safe_load` return (document parse boundary) | `__init__.py:80` | 0.95 |
| S06 | `GeneratorData.title` → `project_name` | `__init__.py:94` | 0.95 |
| S24 | `oai.Operation.tags` (raw tag) | `parser/openapi.py:51` | 0.95 |
| S10 / S11 | `Reference.module_name` (model / enum) | `__init__.py:196 / :203` | 0.90 |
| S01 | `httpx.get` return | `__init__.py:71` | 0.90 |
| S28 | `openapi.info.title` | `parser/openapi.py:311` | 0.90 |
| S27 | `oai.OpenAPI.parse_obj` return | `parser/openapi.py:300` | 0.85 |
| S25 / S26 | `oai.Schema.title` (model / enum) | `parser/openapi.py:230 / :271` | 0.85 |
| S03 | `Path.read_bytes` return (document content) | `__init__.py:76` | 0.80 |

## Top sink labels (highest confidence / impact)

| ID | API | Location | Tainted path channel | Confidence |
| --- | --- | --- | --- | --- |
| K12 | `shutil.rmtree` (arg 0) | `__init__.py:125` | `package_dir` — title/config-derived base, recursive delete | 0.95 |
| K32 / K34 | `Path.write_text` | `__init__.py:197 / :204` | file **name** = remote `module_name` (snake_case preserves `/`, `..`) | 0.95 |
| K49 / K51 | `Path.write_text` | `__init__.py:235 / :237` | file **name** = completely raw remote `tag` | 0.95 |
| K10 / K15 / K27 / K39 / K43 | `Path.mkdir` | `:109 / :146 / :186 / :218 / :223` | title/config-derived base directory | 0.90 |
| 15× `Path.write_text` (base-tainted) | `:151 :154 :160 :172 :181 :192 :208 :214 :220 :225 :229` + the name-controlled four | `__init__.py` | project/package/models/api base escapes CWD | 0.85 |

## Sanitizers

**None labeled.** Verified by grep over `openapi_python_client/`: zero `os.path.*`, `resolve()`, `relative_to()`, `startswith()`, `basename()`, `normpath()`, `abspath()`, `realpath()`, `open()`, archive or environment-variable usage. The only name shaping — `replace(' ', '-')` / `lower()` (`__init__.py:94`), `snake_case` / `pascal_case` (`utils.py:6/:12`, case + whitespace conversion only) — does not strip `/`, `\` or `..`; `is_dir()` (`:122`) is an existence check, not containment; the `class_overrides` map (`parser/reference.py:27`) is a name-substitution mechanism, not a path guard.

## Summaries (31)

- CLI/wrapper propagation: `_process_config`, `cli`, `generate`, `update`, `_get_document`, `_get_project_for_url_or_path`, `create_new_client`, `update_existing_client` (param → file-read / wrapper chain).
- Object boundary: `Project.__init__` (param `openapi` → `self.project_dir` / `self.package_dir` fields consumed by `build()`/`update()`).
- 20 pathlib `/` joins (tainted right component at `:95 :98 :196 :203 :234 :236` modeled as `argument`/0; tainted base with literal component at the other 14 sites modeled as `receiver`).
- Name reshaping: `snake_case`, `pascal_case` (explicitly *not* sanitizers — taint-propagating steps).

## Items retained for human review (candidate, 10)

| IDs | API | Question |
| --- | --- | --- |
| S05, S07, S18–S23 (8 source rows) | `--config`-derived fields (`project_name_override`, `package_name_override`, `class_overrides`, `yaml.safe_load(config)`, `path.read_text(config)`) | Is a shared/committed `--config` file inside the attacker model (CI scenario)? If config is fully operator-trusted, downgrade these to `none`/`fp`. |
| K13, K14 (2 sink rows) | `subprocess.run(..., cwd=project_dir)` (isort/black) | Should indirect file effects scoped by a tainted `cwd` count as a Pass 1 sink? |

## Interpretation for Phase 2

- Source model to render in `MySources.qll`: the document-content boundaries (httpx get/content, yaml.safe_load, read_bytes, parse_obj) plus the remote name fields (`title`, `tags`, `module_name`, `Schema.title`).
- Sink model in `MySinks.qll`: `write_text`/`mkdir` receivers, `rmtree` arg 0, optionally the two `subprocess.run` cwd keyword sites.
- `MySanitizers.qll`: empty (`none()` fallback), matching WORKFLOW.md §5.2.3.
- `MySummaries.qll`: the 31 summary steps, of which `Project.__init__` and the six tainted-component joins are the load-bearing ones for alert generation.
