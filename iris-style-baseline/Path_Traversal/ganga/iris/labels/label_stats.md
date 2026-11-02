# Augur Phase 1 Step 3 — Label Statistics (ganga, Pass 1: Path Traversal)

- **Run ID:** `iris-ganga-pathtraversal-pass1-20261022`
- **Generated:** 2026-10-22 (UTC)
- **Model:** `glm-5.3 (Claude Code CLI harness)` — single interactive labeling session executing the Augur Step 3 contract; 13 batches, 0 re-asks
- **Language / framework:** python / Flask (GangaGUI `gui` + unauthenticated localhost `internal` apps; CLI: optparse; Ganga 8.4.2) — references loaded: `python.md`, `patterns.md`, `flask.md`
- **Pass:** 1 — Path Traversal (CWE-022, 023, 036, 073)
- **Schema:** `labels.json` validated against local Augur `assets/labels_schema.json` with `jsonschema` `Draft202012Validator` + `FormatChecker` (authoritative check, 0 errors) and re-checked under `python -I` with a self-contained draft-2020-12 subset validator — **VALID**
- **Source candidates processed:** 111/111 CSV rows → 102 unique after dedup (`extraction/sources.csv`)
- **Sink candidates processed:** 907/907 CSV rows → 900 unique after dedup (`extraction/sinks.csv`)
- **Total entries:** 1002 — every unique candidate received exactly one label (ids `src-001..src-102`, `sink-001..sink-900` in deduplicated CSV order)

## Batches

Labeling was performed against the real `ganga_vuln` source tree (Ganga 8.4.2,
database creation sha `0c0f9e33`; every flow claim below was verified by reading the
cited code) in 13 stable batches (dedup key `file+line+node+callable+flowKind+argIndex`;
one decision per candidate):

| Batch | Scope | Candidates |
| --- | --- | --- |
| S1 | source candidates: os.environ.get/os.getenv environment reads (operator/deployment trust review) | 16 |
| S2 | source candidates: GangaGUI/api/routes.py request.args/request.json reads (internal API: export/load/runfile path params + job/template filters) | 33 |
| S3 | source candidates: GangaGUI/gui/routes.py request.form reads (login, config-data/runfile-data/edited-job-info content channels, pagination filters) | 12 |
| S4 | source candidates: GangaGUI/gui/routes.py multipart uploads (loadfile/runfile fixed-path channels + the storagefile traversal channel) | 9 |
| S5 | source candidates: the two Flask path-converter route params (job_browse.path, storage_page.path) | 2 |
| S6 | source candidates: gui request.json/X-Access-Token/pagination query params (incl. the job_action dynamic-dispatch candidate) | 30 |
| K1 | sink candidates: GangaGUI/gui/routes.py (the two browser flows, the upload branch, fixed-path content writes, allowed_file) | 54 |
| K2 | sink candidates: GangaGUI gui/config.py + start.py bootstrap, GangaCore Persistency export/load chains, GPIFunctions, Runtime.getScriptPath, Utility/files | 43 |
| K3 | sink candidates: archive families (tarfile open/extractall: Sandbox, WNSandbox, GaudiExecMerger, job_tools, plugin tar rows) | 31 |
| K4 | sink candidates: GangaCore core (bootstrap, GangaRepository, FileWorkspace, SessionLock, GPIDev, Utility, Lib/LCG, Sandbox create) | 335 |
| K5 | sink candidates: GangaAtlas plugin tree (Athena, ATLASDataset, DQ2, scripts) | 163 |
| K6 | sink candidates: GangaLHCb plugin tree (GaudiExec, applications, RTHandlers, mergers, datasets) | 65 |
| K7 | sink candidates: remaining plugins/scripts (GangaDirac, GangaPanda, GangaNA62, GangaND280, GangaGaudi, GangaSNOplus, GangaSuperB, GangaSAGA, GangaRobot, GangaTutorial, GangaService, GangaRelease tools) | 209 |

## Role counts

| Role | Sources | Sinks | Total |
| --- | --- | --- | --- |
| source | 17 | 0 | **17** |
| sink | 0 | 12 | **12** |
| sanitizer | 0 | 2 | **2** |
| summary | 0 | 8 | **8** |
| none | 85 | 878 | **963** |

## Classification counts

| Classification | Count | Meaning |
| --- | --- | --- |
| tp | 27 | confirmed real for the labeled role in this pass (6 source, 21 sink/summary/sanitizer entries) |
| candidate | 1 | unconfirmable at AST level — the job_action dynamic-dispatch row (manual review point) |
| fp | 974 | not relevant for Pass 1 (operator-trust boundaries, filter params, fixed-path plumbing, wrong-pass channels, rejected sanitizer) |

- Average confidence: **0.896**
- Entries below the 0.55 re-ask threshold: **1** (the single 0.5 entry is `src-079` — an
  explicit "cannot confirm" decision on the job_action dynamic dispatch, not uncertainty that a
  re-ask would resolve)

## Dedup and exclusions

- **Dedup:** 16 exact duplicate rows removed (identical by
  `file+line+node+callable+flowKind+argIndex`, first occurrence kept; CodeQL decode artifacts —
  9 source rows: the repeated `request.json`/`request.args.get` rows at api/routes.py:86/:139/:259/
  :447/:718 and gui/routes.py:408/:467/:710/:1048; 7 sink rows: Athena.py:591 listdir ×3, :649 ×2,
  gui/routes.py:651/:778/:779 dirname ×2, GangaGUI/start.py:20 dirname ×2). The removed rows are
  preserved verbatim in `labels_raw_pass1.json` (duplicates section). Rows that share file+line
  but differ in node/flowKind (e.g. `request.json` Attribute vs `request.json.get` at
  gui/routes.py:1188/:1189) were kept as distinct candidates.
- **Exclusions:** 0 rows excluded from labeling. Extraction had already scoped candidates to
  `%/ganga/%` (excluding `ganga-db`, the `GangaTest`/`test`/`old_test`/`testlib` trees and the two
  stray test modules), so no test/migration rows appear in the CSVs. Extraction-heuristic noise
  was labeled `none/fp` on its own merits rather than dropped, keeping the audit trail complete.

## Confirmed Pass 1 chains (CWE-22)

All four chains were traced step-by-step in the real source; every row below is labeled tp in
`labels.json` (see `phase1_review.md` for the full tables):

1. **Job browser read** (`/job/<int:job_id>/browse/<path:path>`): `job_browse` path param
   (`src-065`) → `os.path.join(job_base_dir, path)` (sink-778) → `exists`/`isfile` →
   **`send_file(abs_path)` (primary)** / `listdir`.
2. **Storage browser read** (`/storage/<path:path>`): `storage_page` path param (src-069) →
   `join(STORAGE_FOLDER, path)` → `exists`/`isfile` → **`send_file` (primary)** / `listdir`.
3. **Storage upload write** (POST `/storage/<path:path>`): route path → `join` →
   `join(abs_path, secure_filename(filename))` (the *directory* component is unsanitized) →
   **`storagefile.save(save_path)` (primary write)**.
4. **Internal-API export write / load read** (no auth, localhost): `request.args.get('path')`
   (src-016, src-045) → GPI `export`/`load` → `fullpath`/`getScriptPath` →
   **`open(filepath, mode)` (write)** / **`open(filepath)` (read)**.

**Sanitizers:** 1 confirmed (`secure_filename`, gui/routes.py:953 — filename component only);
1 rejected (`allowed_file`, :1799 — extension allowlist on fixed-path channels only).
