# Augur Phase 1 Step 3 — Label Statistics (fides, Pass 1: Path Traversal)

- **Run ID:** `iris-fides-pathtraversal-pass1-20261022`
- **Generated:** 2026-10-22 (UTC)
- **Model:** `glm-5.3` (Claude Code CLI harness) — single interactive labeling session executing the Augur Step 3 contract; 13 batches, 0 re-asks
- **Language / framework:** python / FastAPI 0.89.1 (+ Starlette ASGI; CLI: Click) — references loaded: `python.md`, `patterns.md`, `fastapi.md`
- **Pass:** 1 — Path Traversal (CWE-022, 023, 036, 073)
- **Schema:** `labels.json` validated against local Augur `assets/labels_schema.json` (draft 2020-12, `Draft202012Validator` + format checker) — **VALID**
- **Source candidates processed:** 83/83 (`extraction/sources.csv`)
- **Sink candidates processed:** 121/121 (`extraction/sinks.csv`)
- **Total entries:** 204/204 — every candidate received exactly one label (ids `src-001..src-083`, `sink-001..sink-121` in CSV order)

## Batches

Labeling was performed against the real `fides_vuln` source tree (database creation
sha `1212eadf`; every flow claim below was verified by reading the cited code) in
13 stable batches (dedup key `file+line+node+callable`; one decision per candidate):

| Batch | Scope | Candidates |
| --- | --- | --- |
| S1 | `os.getenv` environment reads (operator/deployment-trust review) | 11 |
| S2 | Click CLI option/argument params (operator-trust review) | 17 |
| S3 | request-field reads in `main.py` middlewares / `api/middleware.py` (logging/analytics/audit review) | 21 |
| S4 | the catch-all route boundary (`read_other_paths` request param + `path_params["catchall"]`) | 2 |
| S5 | SaaS authentication strategy `request.headers`/`request.url` reads (outbound-auth, Pass 3 territory) | 13 |
| S6 | endpoint/schema request `headers`/`body`/`client` reads (content-type gating, OAuth, consent reporting) | 18 |
| S7 | `register_custom_connector_template` raw zip body param (upload boundary review) | 1 |
| K1 | sink candidates in `api/ui.py` + `api/main.py` static-serving chain (the catch-all route) | 15 |
| K2 | sink candidates in `app_setup`, `connector_registry_service`, `saas_config_endpoints` zip, `saas_util` loaders, `consent_util` startup loaders | 22 |
| K3 | sink candidates in `dsr_report_builder`, `get_email_template`, `tasks/storage`, `db/samples`, `db/database` | 29 |
| K4 | sink candidates in `src/fides/config/*` (config file management) | 23 |
| K5 | sink candidates in `src/fides/core/*` + `src/fides/cli` (manifest/credentials/CLI plumbing) | 26 |
| K6 | `graph/traversal.py` "parents" rows + `override_implementations/__init__` (extraction-heuristic misfires) | 6 |

## Role counts

| Role | Sources | Sinks | Total |
| --- | --- | --- | --- |
| source | 3 (1 tp, 2 fp) | 0 | **3** |
| sink | 0 | 2 (2 tp) | **2** |
| sanitizer | 0 | 2 (0 tp — both REJECTED) | **2** |
| summary | 0 | 1 (1 tp) | **1** |
| none | 79 | 117 | **196** |

## Classification counts

| Classification | Count | Meaning |
| --- | --- | --- |
| tp | 4 | confirmed real for the labeled role in this pass (1 source, 2 sinks, 1 summary) |
| candidate | 0 | nothing was left unconfirmable — every decision is grounded in read code |
| fp | 200 | not relevant for Pass 1 (labeled `none`, or real boundary of the wrong pass / rejected sanitizer) |

- Average confidence: **0.888**
- Entries below the 0.55 re-ask threshold: **0** (lowest-confidence entries: `src-043` 0.60, `sink-063` 0.65, `src-068` 0.80 — all deliberately reduced-confidence fp/tp decisions with recorded rationale, not uncertainty about the code)

## Dedup and exclusions

- **Dedup:** 0 duplicate rows by `file+line+node+callable+flowKind+argIndex`; 0 removed.
  Several rows share a file+line (e.g. `dataset_endpoints.py:309` `get` vs `headers`;
  `dsr_report_builder.py:17` `resolve`/`parent`/`Path`) but differ by node/callable — kept as distinct candidates.
- **Exclusions:** 0 rows excluded. Extraction had already scoped candidates to `%/src/fides/%`
  and filtered `fides-db` out; no test/migration rows appear in the CSVs. Heuristic misfires
  (`graph/traversal.py` data-graph `parents`) were labeled `none/fp` on their own merits rather
  than dropped, keeping the audit trail complete.

## Confirmed Pass 1 chain (CWE-22 arbitrary file read)

| # | ID | Location | Role | Conf. | Step |
| --- | --- | --- | --- | --- | --- |
| 1 | src-044 | `src/fides/api/main.py:160` | source/tp | 0.95 | `request.path_params["catchall"]` — percent-decoded URL remainder of `@app.get("/{catchall:path}")`, attacker-controlled incl. `..`/`/` (e.g. `GET /..%2F..%2F..%2Fetc%2Fpasswd`) |
| 2 | sink-097 | `src/fides/api/ui.py:32` | summary/tp | 0.90 | `get_path_to_admin_ui_file(path)` → `package_path / ADMIN_UI_DIRECTORY / path` (ui.py:42, pathlib `/` keeps `..` lexically); called at main.py:167 when `match_route` has no match (traversal payloads never match — map regex classes contain no dots) |
| 3 | sink-063 | `src/fides/api/main.py:170` | sink/tp | 0.65 | `ui_file.is_file()` — secondary sink: OS-level existence/fstype oracle outside the UI root (resolves the `..` at stat time) and gate for step 4 |
| 4 | sink-064 | `src/fides/api/main.py:180` | sink/tp | 0.95 | `FileResponse(ui_file)` — **primary sink**: starlette opens and streams the escaped path to the client; bounded only by webserver process read permissions |

**Sanitizers: 0 confirmed.** The only guard on the chain,
`path_is_in_ui_directory` (`ui.py:134-141`, `ui_directory in path.parents`), is labeled
**sanitizer/fp** (entries sink-106/sink-107): it is a *lexical* containment check on the
*unresolved* `Path`, and pathlib keeps `..` as an ordinary component, so the lexical parents
of `<ui_dir>/../../../etc/passwd` still contain `<ui_dir>` exactly. Verified semantics:

```python
ui = Path("/fides/src/fides/ui-build/static/admin")
ui in (ui / ".." / ".." / ".." / "etc" / "passwd").parents   # -> True  (guard PASSES)
```

The guard therefore passes for precisely the payloads that escape at OS level, and only
rejects the absolute-path replacement case — which the route already makes unreachable (the
router strips the leading `/`). It must **not** be rendered as `isBarrier` in Phase 2.
No other candidate on the chain (or anywhere in the tree) provides real neutralization: no
`resolve()` + containment, no `relative_to` on resolved paths, no `..` rejection, no
basename extraction. Symlink concerns: no symlink creation or link-following policy exists
in the audited code and the packaged admin-UI directory is not attacker-writable —
symlink/TOCTOU not applicable (recorded as not observed).

## Rejected candidate families (rationale summary)

| Family | Rows | Verdict |
| --- | --- | --- |
| `os.getenv` env reads | 11 (S1) | operator/deployment trust; no request data influences env in this codebase |
| Click CLI params (`--manifests-dir`, `--output-filename`, `--keyfile-path`, `--fides-dir`, `--env-file`, `--input-filename`) | 17 (S2) | operator-trust CLI (python.md §3 scopes CLI sources to service-mode tools); matching core/cli sink rows (K4/K5) inherit the same verdict |
| middleware/audit request fields (`url`, `headers.get`, `method`, `body`, `scope`) | 21+18 (S3/S6) | consumed only for logging, analytics events, audit-log DB records, consent reporting — never a filesystem path |
| SaaS auth strategy `request.headers`/`request.url` | 13 (S5) | build *outbound* auth requests — Pass 3 (SSRF) territory, no path flow |
| zip upload body `file: bytes` (saas_config_endpoints.py:363) + in-memory `ZipFile`/`read`/`writestr` | 4 (S7/K2) | genuine untrusted boundary, but zip handling is 100% in-memory (BytesIO); `info.filename` only used for `endswith` suffix classification — no extract-to-disk anywhere in the tree → Pass 4 carry-over (`.py` member reaches RestrictedPython `exec`), not Pass 1 |
| fixed-constant file APIs (app_setup, consent_util, saas_util loaders, connector_registry, samples, database, dsr_report_builder, get_email_template, storage uuid-keyed writes, deploy) | ~70 (K2/K3) | module/package/boot-time constants; `upload_to_local` writes `<fixed dir>/<server-generated uuid>.<ext>` |
| config file management (`get_config`, `load_file`, `toml.load`, `update_config_file`, `create_config_file`, `replace_config_value`) | 23 (K4) | operator `.fides/fides.toml` via CLI `--config` / `FIDES__CONFIG_PATH` env / fixed search list |
| `graph/traversal.py` `parents` rows | 4 (K6) | extraction-heuristic misfire: `TraversalNode.parents` is data-graph adjacency (`Dict[CollectionAddress, ...]`), no filesystem semantics |
| `match_route` (ui.py:108) | 1 (K1) | user string is only a `re.fullmatch` selector over the boot-time packaged-file map (patterns without dots); the returned `Path` always comes from the trusted map — no taint propagation, and its containment effect is incomplete (caller falls back to the vulnerable join) |

## Notes

- `labels.json` metadata carries the full batch/dedup/trust-model/sanitizer-warning notes;
  `labels_raw_pass1.json` preserves every candidate row verbatim with its per-row decision
  (audit artifact per WORKFLOW.md §7.3).
- Phase 2 instruction recorded in labels: render only `classification=tp` entries into
  `MySources/MySinks/MySummaries`; a `MySummaries` taint step for pathlib `__truediv__`
  (`package_path / ADMIN_UI_DIRECTORY / path`, ui.py:42) is required — the `/` BinaryExpr is
  not extractable at AST level (detection.json `uncoveredCases`).
- No PyVul ground truth, patch diffs, CVE publications, or the vulnerability reports present
  in the source-tree root (`FIDES-VULNERABILITY-REPORT.md`, `path_traversal_*.md/csv`) were
  consulted. Source tree, CodeQL database, Augur installation, and the Phase 1 CSVs were not
  modified.
