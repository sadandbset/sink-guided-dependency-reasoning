# Phase 1 Step 3 — Human Review Packet (Pass 3, CWE-918 SSRF)

Project: **dtale (D-Tale)**, snapshot git `063423aa`, DB `dtale-db` (creation sha matches the checkout).
Pass: **3 — Server-Side Request Forgery (CWE-918)**. Generated: 2026-10-20. Model: **glm-5.3** (in-session LLM labeling; per-row verdicts recorded in `labels_raw_pass3.json`).

---

## 1. Scope and coverage

| item | count |
| --- | --- |
| CSV candidate rows (must cover) | **241** = sources.csv 198 + sinks.csv 43 |
| Raw per-row verdicts (`labels_raw_pass3.json`) | 241 (100% coverage, incl. `api`+`ast` double matches) |
| LLM labeling batches | 9 (family batches; location-sensitive rows reviewed line-by-line) |
| Deduplicated entries (`labels.json` pass 3) | 232 CSV-derived + 1 supplemental review entry = **233** |
| Duplicate rows collapsed | 9 (same `requests.get` AST node matched by both `api` (API-graph) and `ast` (syntax) extraction) |

Dedup key: `(file, line, callable, role, flow_kind, arg_index, module)`. Every collapsed row keeps its own verdict in `labels_raw_pass3.json`; no row was silently dropped. `labels.json` additionally carries an empty pass-1 placeholder block required by the `labels_schema.json` `passes contains pass_id 1` constraint (no pass-1 labeling was performed in this run).

Schema validation: `labels.json` validated against `assets/labels_schema.json` (jsonschema) — **PASS**.

## 2. Label distribution

| role | classification | count |
| --- | --- | --- |
| source | tp | 2 |
| source | candidate | 4 |
| sink | tp | 1 |
| sink | candidate | 1 |
| summary | candidate | 8 |
| none | fp | 217 |
| **total** | | **233** |

Raw-row distribution (before dedup): none 223 · source 6 · summary 8 · sink 4.
Confidence buckets (entries): high (≥0.75) 45 · mid (0.55–0.74) 188 · low (<0.55) 0 — the bulk `none` entries carry 0.65–0.85.

Rows per batch: batch-01-http_query_arg 137 · batch-02-request-dict-json 12 · batch-03-request-form-files 12 · batch-04-cli_arg 26 · batch-05-env-config 11 · batch-06-sink-requests-get 18 · batch-07-sink-funnel-wrappers 13 · batch-08-sink-url-parse 12 · batch-09-supplemental 1 (off-CSV `is_url` review decision).

## 3. Methodology

1. Read `WORKFLOW.md`, `references/python.md`, `references/patterns.md`, `assets/labels_schema.json` (plus the pass-1/2 artifacts: `detection.json`, both extraction CSVs and `.ql` queries).
2. Family-level triage of both CSVs (flow-kind / callable / module histograms).
3. **Line-by-line source review** of every location-sensitive candidate in the `dtale_vuln` tree: the `/web-upload` route (views.py:3921-3974), `/upload` (3885-3918), `/datasets` (3977-3985), `build_csv_kwargs` (3868-3882), `handle_path`/`is_url` (clickutils.py:230-247), all four loaders (`csv/json/excel/parquet_loader.py`), `datasets.py` (all `load_zip` callers), `kill`/`is_up` and all their call sites (views.py:327/:383/:478, app.py:271/:550/:560/:812), the reaper closure (app.py:258-276), the auth gate (auth.py:37-51, global_state.py:38), the CLI option machinery (script.py, loaders/__init__.py:121-160, clickutils.py:74-96), the docs demo apps (`docs/embedded_dtale/app.py`, `docs/streamlit/script_baseball.py`, `script_columns_and_code.py`), and the `urllib` shims (utils.py:45-56, charts.py:86-98/:199).
4. Sampled confirmation of the bulk families (136 generic `get_*_arg` chart/grid/dataframe call sites in views.py / column_analysis.py / query.py / utils.py): the read values feed sorting, filtering, chart-type and settings processing on the in-memory dataframe; the tree contains exactly five `requests.get` call sites, none reachable from these values.
5. Deterministic rendering into the schema-conformant `labels.json` (validated).

## 4. Operator review concerns — how each was resolved

1. **Real entry points at trust boundaries (not every internal param).** The Flask surface is unauthenticated by default: `global_state.py:38 AUTH_SETTINGS = {'active': False, ...}` and `auth.py:40-41` `requires_auth` returns `f(...)` unchanged when auth is inactive (gate installed via `@app.before_request` app.py:457-458). Only rows reading actual HTTP request data (`request.args`/`json`/`form`/`files`), the CLI `click.option` boundary, env/config reads were ever considered as sources; internal forwarding parameters (`handle_path` `path`/`kwargs`, loader `path`/`proxy`, `load_zip` `url`) were **not** labeled sources — they are covered as summary steps on the sink side (concern 9).
2. **Which inputs actually reach the network URL.** Exactly one web flow: `/web-upload` (views.py:3921, unauthenticated) reads `url` and `proxy` from the query string (views.py:3930-3931) and forwards them to `load_csv`/`load_json`/`load_excel`/`load_parquet` → `handle_path` → `requests.get(path, proxies={http:proxy, https:proxy})` (clickutils.py:244, :240-243). These two reads are the only `source/tp` entries (conf 0.9). The `type` parameter (views.py:3929) is dispatch-only (equality-compared, never propagates) → none/fp. The `/datasets` `dataset` parameter (views.py:3980) dispatches `getattr(datasets, dataset)()` onto functions with hardcoded GitHub URLs → none/fp 0.65 (fixed-target dispatch).
3. **Internal wrappers — real propagation and reachability.** The chain `web_upload → loader_func/load_file(**kwargs) → handle_path(path, kwargs) → requests.get` is entirely first-party and verified; it is modeled with 8 `summary/candidate` entries (handle_path function + 3 loader handle_path call sites + 3 loader wrappers + load_zip). `load_zip` itself currently carries no taint (all callers pass literals, conf 0.55). `kill`/`is_up`/reaper wrappers were verified to receive only internal `DtaleData` instance URLs → none/fp.
4. **Dangerous URL argument positions.** `requests.get` is the only HTTP-client API in the tree (requests.post/Session, httpx, aiohttp, urllib.request.urlopen/urlretrieve have zero call sites — verified, see detection.json `uncoveredCases`). URL is positional argument 0 at every site; arg_index 0 recorded on all `arg` rows. `urllib.parse.urlencode/parse_qsl/quote/unquote` (12 rows) are pure string processing → none/fp 0.8, not sinks.
5. **Sanitizer evidence.** **No sanitizer was labeled.** `is_url()` (clickutils.py:234-235) only checks the `http://`/`https://` prefix — it blocks cross-protocol targets (file:/data:) but leaves host, port, path, userinfo and redirects fully attacker-controlled, so it does **not** block the SSRF path; recorded as a supplemental `none/fp` entry (`p3-sup-0001`) so the decision is auditable. No host allow-list, private-IP/DNS-resolver check or redirect control exists anywhere on the funnel path.
6. **Non-sanitizers.** `auth.requires_auth` is route-level access control (and disabled by default) — not a data sanitizer and not emitted; `authenticate()` (credentials comparison) → auth.py form rows none/fp 0.85. HTML escaping / general format validation do not appear on any URL path.
7. **Fixed vs attacker-changeable targets.** Fixed/internal-target fetches are labeled none/fp and kept out of the sink library: `kill()` (views.py:196, own `/shutdown`), `is_up()` (views.py:210, own `/health`), reaper `requests.get(self.shutdown_url)` (app.py:272), `load_zip` callers (hardcoded GitHub literals; the `requests.get` at datasets.py:40 itself stays `sink/candidate` since the URL position is genuine), docs demo apps (fixed host `www.baseball-reference.com`; string concatenation cannot override the host), streamlit example (hardcoded `http://localhost:8501` literal). The CLI `--host`/`--port` bootstrap options only feed `build_url` for those internal lifecycle URLs (admin-configured-URL class).
8. **file:/data: and cross-protocol.** No file: or data: URL fetching exists in the tree; `is_url`'s scheme check would in fact block them at the funnel. No local-file-read CWE was folded into pass 3. `/upload` file ingestion (request.files rows) is local pandas parsing → none/fp 0.75.
9. **External source vs internal wrapper parameter.** The five `get_*_arg` wrappers (defined utils.py:114-204 on `r.args.get`) are the real HTTP boundary — only their call sites were extracted as source candidates. The 137 generic call sites read true attacker data but feed no network path → `none/fp` (documented, not silently dropped); recall is preserved because the source signature emitted for the two `/web-upload` entries (`dtale.utils.get_str_arg`, return position) matches every wrapper call site in Phase 2, where only the `/web-upload` flow can reach the sink. CLI loader-option constructors (loaders/__init__.py:137/:149/:157, clickutils.py:91) are genuine argv boundaries with real propagation → `source/candidate` 0.6/0.55 (local-operator attacker model — weaker than the web twin; expected FP at filter stage).

## 5. Top entries for human attention

- **Sink (tp, 0.95):** `requests.get` at `dtale/cli/clickutils.py:244` inside `handle_path` — shared fetch funnel, URL at arg 0, proxy injected as requests proxies; reachable from the unauthenticated `/web-upload` route with `url`+`proxy`.
- **Sources (tp, 0.9):** `get_str_arg(request, "url")` views.py:3930, `get_str_arg(request, "proxy")` views.py:3931.
- **Candidate sink (0.6):** `requests.get` at `dtale/datasets.py:40` (`load_zip`) — genuine URL position, hardcoded callers only.
- **Candidate sources (0.55-0.6):** CLI loader option constructors (4 entries) — real CLI→funnel propagation, local-operator trust boundary.
- **Summary steps (0.55-0.75):** handle_path + csv/json/excel loader wrappers + load_zip — the propagation chain for the pass-3 flow query.

Unresolved / needs human eyes: none below the 0.55 confidence threshold; the 4 CLI candidate sources and the `datasets.py:40` candidate sink are the items where the reviewer should decide whether the local-CLI / fixed-literal-caller postures justify dropping them before Phase 2 (they were kept for recall).

## 6. Notable non-findings (documented, not labeled)

- pandas IO URL fetching (`pd.read_csv/read_json/read_excel` after `handle_path`, and `pd.read_parquet` receiving the raw path at parquet_loader.py:33 from the `/web-upload` parquet branch views.py:3969) — library-internal fetch behavior, not provable from this tree; recorded as a coverage gap in `detection.json`, not emitted.
- dash callback inputs (35+ `@app.callback` sites) — no path to network I/O in this tree; not extracted.
- `flask_ngrok` tunnel startup (app.py:764) — subprocess side effect without a URL argument; not emitted.

## 7. Constraints honored

- No PyVul ground truth, fix commits or external CVE descriptions consulted; the pre-existing `ssrf_*` / `dtale_ssrf_*` analysis artifacts in the source root were not opened.
- Source tree, CodeQL database, extraction CSVs and the Augur installation were not modified.
- Only `labels/labels.json`, `labels/labels_raw_pass3.json`, `labels/label_stats.md`, `labels/phase1_review.md` were produced. **Phase 2 was not started** (no libraries, queries, taint runs or reports) — the run stops here per instruction.
