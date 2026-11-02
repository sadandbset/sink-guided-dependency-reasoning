# Phase 1 Review — LLM Candidate Labeling (Pass 1: Path Traversal)

Augur 0.3.0 · Phase 1 Step 3 · target: **openapi-python-client 0.5.2** (`openapi-python-client_vuln`)
Pass 1 = CWE-022 / CWE-023 / CWE-036 / CWE-073 (Path Traversal)
Labels: `labels.json` (88 entries, schema-valid) · raw record: `labels_raw_pass1.json` · stats: `label_stats.md`
Independence: no PyVul ground truth, no patch/CVE information, no repo-root audit artifacts were consulted; only `extraction/*.csv`, `exploration/detection.json`, the Augur `WORKFLOW.md`, `references/python.md`, `references/patterns.md`, `assets/labels_schema.json` and the real source tree.

## 1. Result at a glance

| | |
| --- | --- |
| Candidates processed | 88 / 88 (30 sources + 58 sinks; 0 dropped, 0 duplicates) |
| LLM / batches | glm-5.3, temperature 0, 7 batches (11/12/7/15/19/17/7) |
| source / sink / summary / sanitizer / none | 30 (12 tp, 8 candidate) / 23 (21 tp, 2 candidate) / 31 (all tp) / 0 / 14 (fp) |
| Sanitizers found | **none** (verified — see §3.5) |
| Open review items | 10 (8 config-content sources, 2 subprocess-cwd sinks) |

## 2. The dominant vulnerability narrative (verified against source)

openapi-python-client is a typer CLI that turns an OpenAPI document — fetched over HTTP (`--url`) or read locally (`--path`) — into a generated Python client tree under the process CWD. The document content is the genuine untrusted boundary (consuming third-party specs is the tool's entire purpose), and three document-controlled names become **filesystem paths with no containment of any kind**:

1. **`info.title` → project root** — `__init__.py:94-95`:
   `project_name = project_name_override or f"{openapi.title.replace(' ', '-').lower()}-client"` → `project_dir = Path.cwd() / project_name`. The shaping is cosmetic: `../`, `/`, `\` and Windows drive prefixes survive, and a leading `/` makes the pathlib `/` join discard the CWD base entirely. Every subsequent `mkdir` (`:109 :146 :186 :218 :223`), all 15 `write_text` sites, `shutil.rmtree(package_dir)` (`:125`) and the `subprocess.run(..., cwd=project_dir)` formatter channel (`:133/:136`) inherit the escape.
2. **schema title / `$ref` leaf → model/enum module file names** — `parser/openapi.py:230/:271` → `Reference.from_ref` → `snake_case(pascal_case(...))` → `__init__.py:196/:203` `models_dir / f"{module_name}.py"`. `snake_case`/`pascal_case` (`utils.py:6/:12`) only reshape case and whitespace; separators and `..` survive.
3. **`operation.tags[0]` → endpoint module file names, completely raw** — `parser/openapi.py:51` → `__init__.py:234/:236` `api_dir / f"{tag}.py"` / `async_api_dir / f"{tag}.py"`. No transformation of any kind.

The highest-impact sink is `shutil.rmtree(self.package_dir)` at `:125` (update command): check-then-delete with only an `is_dir()` existence guard (`:122`) and a title/config-derived path.

## 3. The ten review questions, answered with evidence

1. **Real untrusted source?** Yes for the document content: `httpx.get` return / `response.content` (`:71/:72`), `yaml.safe_load` (`:80`), `path.read_bytes` return (`:76`), `parse_obj` return (`openapi.py:300`) and the derived name fields (`title`, `tags`, `Schema.title`, `module_name`). No — deliberately — for CLI option values (`--url`, `--path`, `--config`): a local CLI's own options are operator-trust; a `typer` handler parameter is not automatically a source. The `--config` file *content* rows were kept as `candidate` (0.50–0.55) rather than decided, since a shared/committed config in CI changes the answer.
2. **Traceable propagation to file APIs?** Yes, each step was read in the real code: document bytes → `yaml.safe_load` → `GeneratorData.from_dict` → `oai.OpenAPI.parse_obj` (external pydantic boundary, bridged by labeling the call return *and* the use-site field reads) → `GeneratorData.title` → `Project.__init__` `project_name`/`project_dir` (cross-method field flow bridged by a summary) → `Path.cwd() / project_name` → `mkdir`/`write_text`/`rmtree`/subprocess `cwd`. The tag and module_name chains are analogous and shorter.
3. **Sink = actual file effect?** Only `Path.write_text` (15), `Path.mkdir` (5), `shutil.rmtree` (1) and the two `subprocess.run(cwd=…)` formatter channels (kept as `candidate`) were labeled sink. `Path(...)` construction, the 20 pathlib `/` joins, `Path.cwd()`, and `is_dir()` were *not* treated as sinks — joins are summary propagation steps per the rubric.
4. **Can the path escape?** Yes: `../` segments in title/tag/module_name (multiple segments, repeatedly, no normalization anywhere); absolute paths via a leading `/` (pathlib `/` join replaces the base) and Windows drive letters; the raw tag even permits an absolute name directly. No URL decoding exists in the package, so double-decoding is not applicable; no allowlist root is ever declared or enforced.
5. **Real root check before file access?** None. Verified by grep: no `os.path.*`, `resolve`, `relative_to`, `startswith`, `basename`, `normpath` anywhere in `openapi_python_client/`. The only guards are `FileExistsError` handling on `project_dir.mkdir()` (`:110`, existence) and `is_dir()` before `rmtree` (`:122`, existence — TOCTOU-shaped).
6. **Could name reshaping block it?** No: `replace(' ', '-')` + `lower()` (`:94`) is cosmetic; `snake_case`/`pascal_case` are regex case/whitespace + stringcase conversions that do not strip `/` or `..`. Function names alone were not credited as sanitization — no sanitizer was labeled.
7. **Symlinks / timing?** No symlink handling exists in the audited code (pathlib `mkdir`/`write_text`/`rmtree` follow links by default); recorded as **not applicable**. The one timing issue is the `is_dir` → `rmtree` check-then-act window, noted on K12/K11.
8. **Authorized file access?** Yes for the operator's own choices — and only those: `path.read_bytes()` of the `--path` document and `path.read_text()` of the `--config` file are real reads of operator-selected files (labeled `none`/`fp` as sinks). But the *remote document author* is not the operator: paths chosen by `info.title`/`tags`/schema titles are not user-authorized, so the generation flow is not "normal file service".
9. **Tests / constants / generated files?** Not present in the candidate set: the extraction queries already excluded `/tests/`, `/end_to_end_tests/` (golden-master client, fastapi fixture) and the nested CodeQL DB; all 88 rows are package code. `Path.cwd()` is a fixed base (labeled `none`), and the literal template names (`env.get_template(...)`) are constants not emitted as candidates.
10. **Complete untrusted-source → dangerous-path flows?** Yes — three complete flows (title→root, schema title/ref→module name, tag→endpoint module name) run from a content boundary to real file effects. The remaining local flows (CLI param → wrapper → operator-chosen read) were deliberately modeled as summaries with `none`/`fp` source/sink endpoints, not as vulnerability paths.

## 4. Manual review points (blocking nothing, but decide before Phase 2)

- **Config trust (S05, S07, S18–S23)**: if the `--config` file is considered fully operator-trusted in the deployment model, downgrade these 8 source rows to `none`/`fp` — the tp flows then rely solely on the document content. If shared configs are in scope (CI), keep them; `project_name_override` then reaches `Path.cwd()/…` and `package_name_override` reaches the `rmtree` target.
- **subprocess cwd (K13, K14)**: `isort`/`black` run with `cwd=project_dir` rewrite files under the title-derived directory — an indirect file-effect channel via a keyword argument. Confirm whether this should participate in the Pass 1 sink model or be handled as context-only.
- **Recall redundancy**: `parse_obj` return (S27) and the use-site field reads (S06/S24/S25/S26/S28) intentionally double-cover the pydantic boundary; if query volume is a concern, the field-read sources alone suffice.

## 5. Phase 2 readiness

- `labels.json` passes `assets/labels_schema.json` (Draft 2020-12; `pass_id: 1`, `focus: "Path Traversal"`, `cwes: ["022","023","036","073"]`, 88 entries with `id/role/classification/confidence/signature/rationale` and optional `location/evidence`).
- Pass 1 has 21 tp sinks (+2 candidate) — the "at least one sink per enabled pass" quality bar is met.
- `MySanitizers.qll` will legitimately be empty (`none()` fallback per WORKFLOW.md §5.2.3): no proven containment exists in this codebase.
- The load-bearing summaries for alert generation are `Project.__init__` (param → `project_dir`/`package_dir` fields), the six tainted-component `/` joins (`:95 :98 :196 :203 :234 :236`), and `snake_case`/`pascal_case`.

**Status: Phase 1 Step 3 complete. Stopping here per instructions — no Phase 2 work (library generation, taint queries, analysis) was started.**
