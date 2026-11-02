# Augur Phase 1 Step 3 — Human Review Summary (fides, Pass 1: Path Traversal)

Run `iris-fides-pathtraversal-pass1-20261022` · 2026-10-22 · model `glm-5.3` ·
204/204 candidates labeled (83 sources + 121 sinks) in 13 batches · `labels.json`
schema-VALID against local Augur `assets/labels_schema.json`.
This is the advisory CHECKPOINT artifact for Step 3; Phase 2 has **not** been started.

## 1. Scope and trust model

fides (ethyca-fides, tree on main after 2.15.0, database sha `1212eadf`) is a
privacy-engineering platform with a **FastAPI 0.89.1 webserver** (`src/fides/api`,
~176 route registrations), a **Click CLI** (`src/fides/cli`), and Celery workers.
The Pass 1 attacker is the **remote HTTP client of the webserver**. The labeling
reflects three trust tiers:

1. **Remote request boundary (untrusted):** the catch-all route path parameter, request
   headers/body/url fields, the raw zip upload body. Only one of these reaches a
   filesystem path in this codebase — the catch-all path (§2).
2. **Operator/deployment trust:** Click CLI options (17 source rows), `os.getenv` env
   reads (11 rows), the `.fides/fides.toml` config-file management sinks, credentials
   files. The invoking operator choosing their own input/output files is not a Pass 1
   vulnerability; `references/python.md` §3 scopes CLI-arg sources to *service-mode* tools.
3. **Packaged/boot-time constants:** `data/saas` template tree, privacy-notice YAML,
   sample project resources, alembic migration paths, DSR/email template assets —
   trusted bundled content, never request-derived.

## 2. Confirmed source→sink chain (all steps verified in real code)

**C1 — catch-all static-file route arbitrary file read (CWE-22):**

| Step | Code | Evidence |
| --- | --- | --- |
| source | `path = request.path_params["catchall"]` — `main.py:160` | handler of `@app.get("/{catchall:path}")` (`main.py:154`). Starlette percent-decodes the path, so `GET /..%2F..%2F..%2Fetc%2Fpasswd` yields `../../etc/passwd`; the leading `/` is stripped so the value is always relative |
| selector | `match_route(get_ui_file_map(), path)` — `main.py:163` | safe branch: boot-time map from `ui_path.glob("*.html")` (`ui.py:82`); regex classes `[a-zA-Z10-9-_/]+` contain **no dots**, so traversal payloads never match and the flow always falls through |
| join | `get_path_to_admin_ui_file(path)` — `main.py:167` → `ui.py:32-42` | `package_path / ADMIN_UI_DIRECTORY / path` — a pathlib `__truediv__` chain that keeps `..` segments **lexically** (labeled summary/tp) |
| check | `ui_file.is_file()` — `main.py:170` | OS resolves the `..` at stat time: existence oracle outside the UI root + precondition for the read (labeled sink/tp, secondary, conf 0.65) |
| guard | `path_is_in_ui_directory(ui_file)` — `main.py:171` → `ui.py:134-141` | **bypassable** (see §3); labeled sanitizer/fp |
| sink | `FileResponse(ui_file)` — `main.py:180` | starlette opens and streams the escaped file; primary sink (conf 0.95), bounded only by webserver process read permissions |

Impact: unauthenticated-for-content arbitrary file read (subject to route-level auth —
the catch-all registers no scope dependency; `main.py:154` has none) limited to files
readable by the webserver process and passing `is_file()`.

## 3. Guard analysis (why the containment fails)

`path_is_in_ui_directory` returns `ui_directory in path.parents` on the **unresolved**
`Path`. pathlib treats `..` as an ordinary component when enumerating parents, so the
lexical parents of `<ui_dir>/../../../etc/passwd` still contain `<ui_dir>` exactly:

```python
ui = Path("/fides/src/fides/ui-build/static/admin")
ui in (ui / ".." / ".." / ".." / "etc" / "passwd").parents   # True  -> guard PASSES
```

The guard only rejects the absolute-path replacement case (`base / "/abs"` → `/abs`),
which the router already makes unreachable (leading `/` stripped). Both guard rows
(`sink-106`, `sink-107`) are labeled **sanitizer/fp** with an explicit instruction:
**do not emit them as `isBarrier` in Phase 2** — that would suppress the confirmed
finding. No other neutralization exists on the chain or anywhere else in the tree
(no `resolve()` + `relative_to`, no `..` rejection, no basename, no symlink policy —
symlink/TOCTOU recorded as not applicable: the packaged admin-UI directory is not
attacker-writable and no symlink creation exists in the audited code).

## 4. Rejected candidate families (dedup/exclusions)

- **Dedup:** 0 duplicates (key `file+line+node+callable+flowKind+argIndex`), 0 rows
  removed, 0 rows excluded; all 204 rows labeled and auditable in
  `labels_raw_pass1.json`.
- **CLI/env/config/credentials** (S1, S2, K4, K5): operator-trust — see §1 tier 2.
- **Middleware/endpoint request fields** (S3, S6): logging, analytics, audit-log and
  consent-reporting DB records; no path flow.
- **SaaS auth strategies** (S5): outbound auth request construction — Pass 3 territory.
- **Zip handling** (S7 + K2 zip rows): 100% in-memory (`ZipFile(BytesIO(file))`,
  `zip_file.read(info)`); `info.filename` only used for `endswith` suffix matching; no
  extract-to-disk anywhere in the tree.
- **Fixed-constant file APIs** (K2/K3): packaged templates, notices, samples, alembic
  paths, DSR/email assets; `upload_to_local` writes
  `<LOCAL_FIDES_UPLOAD_DIRECTORY>/<privacy_request.id>.<ext>` with a server-generated
  uuid key (`storage_uploader_service.py:67-75`).
- **`graph/traversal.py` `parents` rows** (K6): extraction-heuristic misfire —
  data-graph adjacency, no filesystem semantics.
- **`match_route`** (K1): regex selector over a trusted map; returns map paths only.

## 5. Manual-review points carried into the checkpoint

| Item | Entry | Question for the reviewer |
| --- | --- | --- |
| Secondary sink decision | `sink-063` (`main.py:170` `is_file`, conf 0.65) | keep `is_file` as a modeled sink (existence oracle) or drop to keep the query focused on `FileResponse`? It also fires on the safe `match_route` branch. |
| Whole-`Request` param | `src-043` (`main.py:155`, conf 0.60, source/fp) | rejected to avoid over-tainting (python.md §7.4); the precise subscript `src-044` is the tp anchor — confirm this modeling choice. |
| Zip upload body | `src-068` (`saas_config_endpoints.py:363`, source/fp) | genuine untrusted boundary, wrong pass: no path flow, but `.py` members reach RestrictedPython `exec` (`connector_registry_service.py:445-478`, gated by `security.allow_custom_connector_functions`) — **flag for the Pass 4 round**, plus note the endpoint is scope-gated (`CONNECTOR_TEMPLATE_REGISTER`). |
| Sanitizer rendering | `sink-106`/`sink-107` (sanitizer/fp) | MUST NOT become `isBarrier` in Phase 2 (would suppress C1). |
| Missing taint step | (not a CSV row) | `MySummaries` needs a pathlib `__truediv__` step for `package_path / ADMIN_UI_DIRECTORY / path` (`ui.py:42`) — the `/` BinaryExpr is not AST-extractable (detection.json `uncoveredCases`). |

## 6. Phase 2 handoff instructions (recorded in labels.json notes)

1. Render **only `classification=tp`** entries into `MySources`/`MySinks`/`MySummaries`
   (1 source, 2 sinks, 1 summary); the sanitizer/fp and source/fp entries document
   rejected candidates and must not generate predicates.
2. Add the pathlib `__truediv__` summary step (§5) or the source→sink flow across
   `get_path_to_admin_ui_file` will not connect.
3. Keep `isBarrier` defined but empty (`none()`) — no confirmed sanitizer exists.

## 7. Independence statement

Labels were produced by independent code reading only. No PyVul ground truth, patch
diffs, CVE publications, or the vulnerability reports present in the source-tree root
(`FIDES-VULNERABILITY-REPORT.md`, `path_traversal_full_audit_report.md`,
`path_traversal_priority_analysis*.md`, `path_traversal_sinks*.csv`) were opened. The
source tree, CodeQL database (`fides-db`), Augur installation, and the Phase 1 CSVs were
not modified; the only writes were `iris/labels/*` (plus the deterministic build script
`build_labels.py` in the same directory).
