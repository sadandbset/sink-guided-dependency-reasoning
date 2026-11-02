# Augur Phase 1 Step 3 — Label Statistics (Pass 1: Path Traversal)

Project: pyramid 2.0.1 (`pyramid_vuln` CodeQL database) · Language: python · Framework: pyramid
Run ID: `pyramid-pass1-pathtraversal-20261023` · Generated: 2026-10-23
Labeling LLM: **glm-5.3 (Claude Code CLI)**, single deterministic pass (low-temperature equivalent)
Artifacts: `labels.json` (schema-valid against `augur-0.3.0/assets/labels_schema.json`), `labels_raw_pass1.json`

## 1. Candidate coverage and batching

| Input | Rows | Labeled | Coverage |
| --- | ---: | ---: | --- |
| `extraction/sources.csv` | 252 | 252 | 100% |
| `extraction/sinks.csv` | 55 | 55 | 100% |
| CSV candidates total | **307** | **307** | 100% |
| Analyst-added sanitizer/summary entries (code review, not in CSV) | — | 8 | — |
| **Total entries in labels.json** | | **315** | |

Batches (contiguous CSV row blocks, reviewed in one pass each; no re-ask needed):

| Batch | Scope | Candidates |
| ---: | --- | ---: |
| 1 | request field / environ attribute reads + env_config (sources.csv rows 1–52) | 52 |
| 2 | CLI argparse values, asset spec param, environ subscripts (rows 53–108) | 56 |
| 3 | subscripts, `getattr`, CLI argv params, `.get` lookups, settings lookups (rows 109–172) | 64 |
| 4 | `http_request_param` view/request-entry params, `wsgi_environ_param`, `config_asset_spec_param` (rows 173–252) | 80 |
| 5 | sinks: pkg_resources + `open` + `exists` (sinks.csv rows 1–28) | 28 |
| 6 | sinks: isdir/listdir/realpath/isfile/`self.pkg_resources`/getmtime/getsize/FileResponse/static aliases (rows 29–55) | 27 |
| 7 | analyst-added sanitizer/summary entries | 8 |

## 2. Label counts by role

| Role | Source rows (S) | Sink rows (K) | Added (A) | Total |
| --- | ---: | ---: | ---: | ---: |
| source | 153 | 0 | 0 | **153** |
| sink | 0 | 51 | 0 | **51** |
| sanitizer | 0 | 0 | 2 | **2** |
| summary | 1 | 0 | 6 | **7** |
| none | 98 | 4 | 0 | **102** |
| **Total** | **252** | **55** | **8** | **315** |

Classification: `tp` 208 · `fp` 106 · `candidate` 1 · `unknown` 0.
Confidence: min 0.55, max 0.98, mean 0.816. No entry below the 0.55 re-ask threshold; one entry exactly at 0.55 (`K023`) is flagged `candidate` for human review.

## 3. Dedup and exclusions

- **Dedup**: 0 duplicate `(role, callable, flow_kind, arg_index, file, line)` signatures across all 315 entries (asserted programmatically during generation); every CSV row maps to exactly one entry. Near-duplicate CSV rows (same callable, different file/line — e.g. the six `pkg_resources.resource_exists` rows in `config/assets.py:228–253`) are kept as distinct entries because they are distinct call sites with distinct argument variables.
- **Exclusions (`role=none`, `classification=fp`)** with rationale recorded per entry:
  - CLI boundary (≈74 rows): `argv` params of `main()`/`P*Command.__init__`, `self.args.*` argparse reads — operator-controlled console scripts, not HTTP attackers.
  - Operator/deployment config (5 rows): `os.environ.get('PYTHONSTARTUP')`, `settings.get(...)` ini lookups.
  - Config-time asset specs / override prefixes / `root_dir` / `manifest_spec` (16 rows): developer/operator boundary; they are the **base** side joined with request-derived paths, so the request side remains the tainted one.
  - CLI-simulated requests (5 rows): pviews/prequest rows whose "request" comes from `Request.blank(operator URL)`.
  - Non-reads / non-attacker dict entries (6 rows): environ write targets (`REMOTE_USER_TOKENS` etc.), `environ['wsgi.file_wrapper']` (server-provided hook).
  - Constant argument (1 row): `pkg_resources.resource_filename(package.__name__, '')` at `path.py:71` — empty-string literal.
  - Canonicalization-only rows (3 rows): `os.path.realpath` at `i18n.py:192/198/201` — resolves symlinks, performs no dangerous access itself, and is explicitly **not** treated as a sanitizer (no `..` rejection, no containment).
- No test/fixture, generated-code, or CodeQL-database-directory rows exist in the CSVs (extraction already excluded `testing.py`, `config/testing.py`, `interfaces.py`, and the nested `pyramid-db` tree — re-verified: all candidate paths are under `src/pyramid/`).

## 4. Top high-risk sink entries (by confidence)

| ID | Callable | Location | Conf | Classification |
| --- | --- | --- | --- | --- |
| K050 | `FileResponse` (arg 0) | static.py:112 | 0.95 | tp |
| K022 | `open` (arg 0) | i18n.py:203 | 0.90 | tp |
| K025 | `open` (arg 0) | response.py:57 | 0.90 | tp |
| K034 | `os.listdir` (arg 0) | i18n.py:200 | 0.85 | tp |
| K052 | `isdir` (os.path alias, arg 0) | static.py:153 | 0.85 | tp |
| K054 | `resource_filename` (pkg_resources alias, arg 1) | static.py:168 | 0.85 | tp |
| K055 | `exists` (os.path alias, arg 0) | static.py:170 | 0.85 | tp |
| K029 | `os.path.isdir` (arg 0) | i18n.py:193 | 0.80 | tp |
| K047/K048 | `getmtime`/`getsize` | response.py:55/56 | 0.80 | tp |

## 5. Top source entries (by confidence)

| ID | Callable / field | Location | Conf | Note |
| --- | --- | --- | --- | --- |
| S037 | `request.path_info` | static.py:133 | 0.98 | static-view file-selection path (guarded) |
| S230 | `static_view.__call__(request)` | static.py:104 | 0.98 | static-file view entry |
| S014/S147 | `request.cookies` / `.get` | i18n.py:137 | 0.95 | `_LOCALE_` cookie → locale path chain |
| S024/S155 | `request.params` / `.get` | i18n.py:135 | 0.95 | `_LOCALE_` param → locale path chain |
| S026 | `request.locale_name` | i18n.py:166 | 0.95 | negotiated locale → unsanitized join |
| S126 | `getattr(request,'_LOCALE_')` | i18n.py:133 | 0.95 | locale attribute chain |
| S030/S163/S164 | `matchdict` / `.get('traverse'/'subpath')` | traversal.py:597/601/608 | 0.95 | URL-decoded route path segments |
| S036 | `request.path_info` | traversal.py:620 | 0.95 | traversal path |
| S038 | `request.path_info` | urldispatch.py:75 | 0.95 | route matching |
| S045 | `request.subpath` | static.py:131 | 0.95 | use_subpath static file path |
| S202–S204 | WSGI `environ` params | router.py:193/262, httpexceptions.py:336 | 0.95 | outermost untrusted boundary |

## 6. Sanitizers and summaries (analyst-added, A001–A008)

- **Sanitizers**: `_secure_path` (static.py:276, conf 0.95) — rejects `..`/`.`/empty elements and elements containing `/` or `os.sep` before the docroot join; `split_path_info` (traversal.py:510, conf 0.90) — lexical `..` resolution during URL path splitting.
- **Summaries**: `traversal_path_info`, `static_view.get_resource_name`, `default_locale_negotiator`, `make_localizer`, `LocalizerRequestMixin.localizer`, `call_app_with_subpath_as_path_info` — propagation steps needed to model the two end-to-end request→path chains.
- `os.path.realpath` (i18n.py:192/198/201) is deliberately **not** labeled a sanitizer: it canonicalizes/resolves symlinks but performs no containment check.

## 7. Quality checks (WORKFLOW 4.4.6)

1. `labels.json` validated against `assets/labels_schema.json` (jsonschema 4.26.0, Draft 2020-12 + format checker) — **valid**.
2. Pass 1 has 51 sink entries and 153 source entries (non-empty).
3. Duplicate signature check — **0 duplicates**.
4. `flow_kind=argument` entries all carry an integer `arg_index` ≥ 0 — **verified** (matches extraction CSV arg indices; CSV `-1` mapped to `null` for `field`/`return` rows).
