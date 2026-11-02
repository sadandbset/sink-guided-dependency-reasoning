# Pass 3 (CWE-918 SSRF) Label Statistics — mindsdb

- **Run ID:** `mindsdb-ssrf-pass3-labeling-20261020`
- **Generated:** 2026-10-20T03:28:26Z
- **LLM model:** glm-5.3 (Z.ai GLM), labeled in-session via Claude Code CLI (agentic labeling; single low-variance pass per batch + one low-confidence re-verification batch)
- **Labeling batches:** 11 (B1–B10 semantic clusters + B11 low-confidence re-verification; see `labels_raw_pass3.json`)
- **Schema:** `labels.json` validated against `augur-0.3.0/assets/labels_schema.json` with `jsonschema` 4.26.0 (Draft 2020-12) — **PASS**
- **Deterministic renderer:** `labels/build_labels_pass3.py` (rerunnable; all semantic decisions encoded after direct source reading via four parallel evidence-gathering passes over the mindsdb tree)

## Candidate coverage

| Input | Rows |
| --- | --- |
| `extraction/sources.csv` source candidates | 136 |
| `extraction/sinks.csv` sink candidates | 93 |
| **Total candidates labeled** | **229** |
| Unmapped / skipped | 0 |

Every CSV row produced exactly one label entry (`P3-S-0001..0136`, `P3-K-0001..0093`). No candidate was dropped.
No duplicate rows exist in either CSV (each `file:line[:arg_index]` is unique), so no dedup was needed; the two
`request.json` attribute rows of the same body (e.g. databases.py:28+31) are kept as mirrored entries with
per-row rationales, mirroring the extraction rows.

## Label distribution — all 229 entries

| Role | Count |
| --- | --- |
| source | 134 |
| sink | 93 |
| summary | 0 |
| sanitizer | 0 |
| none | 2 |

| Classification | Count |
| --- | --- |
| tp | 51 |
| candidate | 18 |
| fp | 160 |
| unknown | 0 |

Mean confidence 0.757 (min 0.45, max 0.95).

## Sources (136 entries): role × classification

| Role | tp | candidate | fp |
| --- | --- | --- | --- |
| source (request fields / SQL text / connection-args boundaries) | 14 | 13 | 107 |
| none (operator env-var boundaries: REGISTRY_URL, MINDSDB_EXECUTOR_URL) | 0 | 0 | 2 |

- **source + tp (14):** the SQL-text boundaries — `request.json['query']` of POST /api/sql/query
  (`sql.py:29`), POST /api/analysis/query (`analysis.py:46`), `MysqlProxy.process_query(sql)`
  (`mysql_proxy.py:522`, also serving the HTTP endpoints via FakeMysqlProxy), `PostgresProxyHandler.process_query(sql)`
  (`postgres_proxy.py:253`); the files-API URL upload — `request.json`/`request.stream` of
  PUT /api/files/<name> (`file.py:83`/`:73`, feeding `requests.get(url)`); the integration connection-args
  boundaries — POST/PUT /api/databases bodies (`databases.py:28/31/71/76`) and the POST tables body
  (`databases.py:132/134`, arbitrary SELECT re-executed via process_query); the immediate test-connection
  boundary — PUT /config/integrations params (`config.py:112/113`, `create_tmp_handler(...).check_connection()`).
- **source + candidate (13):** second-order stored-connection-args / stored-SQL bodies (chatbots `db_params`
  → integration_controller.add ×4; config integrations modify ×2; models CreatePredictor `using` args ×2;
  views stored query text ×4; sql.py:30 `context` dict).
- **source + fp (107):** genuine untrusted request-field boundaries whose values were verified NOT to reach
  outbound URLs (agent/model/skill metadata bodies, login credentials, log filter args, tab storage, telemetry
  toggles, Content-Type parser discriminators, ctx header metadata ×41) plus all 66 flask_restx Resource
  path-parameter rows (project/agent/chatbot/config-name/database/table/file/handler/model/skill/view name
  lookups). Role keeps the boundary semantics; classification marks them pass-3-irrelevant so Phase 2 library
  generation can exclude them.
- **none + fp (2):** `os.environ.get('REGISTRY_URL'/'MINDSDB_EXECUTOR_URL')` — operator-configured environment
  (admin-config FP heuristic), never request input.

## Sinks (93 entries): classification

| Classification | Count |
| --- | --- |
| tp (attacker-reachable host at the URL argument) | 37 |
| candidate (second-order / dead-code-leaning) | 5 |
| fp (fixed-literal / config / OAuth / env URL) | 51 |

**tp sinks by family (37):**

| Family | Sites |
| --- | --- |
| REST files API URL fetch | file.py:99 (requests.head, cloud-only), file.py:116 (requests.get, any caller) |
| SQL executor plumbing | functions.py:33 (download_file, PATH-type connection args), urlcrawl_helpers.py:102 (web-crawl Session.get) |
| connection-data host/port handlers | dremio ×5, eventstoredb ×4, frappe ×4, pinot ×4, strapi ×3 |
| `using`-arg / query-time handlers | mlflow ×2, ray_serve ×2, clipdrop.py:33, stabilityai.py:111, twitter.py:162 |
| connection-arg full-URL handlers | sap_erp api.py:55, lightdash api.py:21, scylla.py:54, rag settings.py:400, gmail.py:319, google_oauth_utilities.py:67 |

**candidate sinks (5):** file_handler.py:386 (`_fetch_url` — controllable in design, no production caller found in this
snapshot), lightwood functions.py:155 (`data['train_url']` — no setter/caller found, legacy remote-training flow),
eventstoredb.py:118/165 (`link['uri']` response-supplied absolute URLs), frappe_client.py:70 (redirect
`Location` fetch, `allow_redirects=False`).

**fp sinks (51):** fixed provider hosts with user input confined to path/query/headers (airtable ×2, npm ×2,
pypi ×6, aqicn, clipdrop.py:19, coinbase, discord ×3, hackernews ×5, instatus ×3, intercom ×2, monkeylearn,
oilpriceapi, ollama ×5 (hardcoded localhost/registry), pirateweather, shopify ×2, stabilityai.py:80,
tripadvisor ×2, sharepoint (graph.microsoft.com/login.microsoftonline.com), zipcodebase); config/OAuth hosts
(auth namespace ×3, utilities/auth ×2); literal S3/IMDS URLs (gui.py:24, initialize.py:71, functions.py:86,
utilities/auth.py:19); env-derived URLs (session_controller.py:121, handler_helpers.py:48).

## Batch sizes

| Batch | Scope | Entries |
| --- | --- | --- |
| B1 | SQL execution boundaries + core plumbing sinks | 14 |
| B2 | files API URL-upload cluster | 6 |
| B3 | integration connection-args source boundaries | 14 |
| B4 | connection-data-host handler sinks | 31 |
| B5 | query-time / USING-arg handler sinks | 8 |
| B6 | fixed-provider-host handler sinks (part 1) | 26 |
| B7 | fixed-provider-host handler sinks (part 2) | 13 |
| B8 | config/env/literal support-code fetch sites + env sources | 12 |
| B9 | bulk request-field sources (metadata/storage-only) | 39 |
| B10 | bulk Resource path-parameter sources | 66 |
| B11 | low-confidence (<0.55) re-verification | 5 ids re-examined (no new entries) |

## Phase 2 library input

Entries with `classification` in (`tp`, `candidate`) — 69 total (14 source-tp, 13 source-candidate, 37 sink-tp,
5 sink-candidate) — are the intended input for `MySources.qll` / `MySinks.qll`. All 160 `fp` entries should be
excluded from library generation and retained for audit/filtering only (admin-configured URL sinks and
metadata-only request boundaries, per the SSRF false-positive heuristics). `MySummaries.qll` has no CSV-derived
entries (see below); `MySanitizers.qll` should use the `none()` fallback.

## Sanitizers

**Zero sanitizer entries.** No CSV candidate is a sanitizing API for pass 3. Concrete mitigations found in the
code are documented inside the relevant entries' rationale/evidence instead; none is sufficient:

- `functions.py:23-31` (download_file) — non-empty-scheme check only: accepts ANY non-empty scheme and any host.
- `file_handler.py:347-354` — http/https-only scheme check, but no host restriction (and the path has no
  production caller in this snapshot).
- `scylla_handler.py:89` — `startswith(('http://','https://'))` scheme check only.
- `clipdrop` `image_extension_check` — URL-suffix check only (host unrestricted).
- `urlcrawl_helpers.py:132` — same-domain filter applies only to response-derived hrefs; the domain itself is
  derived from the attacker-supplied initial URL.
- `eventstoredb_handler` — isinstance checks on `tls`/`port` only; `host` is unvalidated.
- `oilpriceapi` — whitelist on `by_type`/`by_code` query params only (host is a literal anyway).
- No host allow-list, no private-IP/DNS-resolution check, and no redirect control exists anywhere under
  `mindsdb/` (zero `ipaddress`/`is_private` uses; `requests` follows redirects by default at every sink).

## Summary entries

**Zero.** The extraction deliberately excluded internal wrapper URL parameters
(`download_file(url)`, `_fetch_url(url)`, `get_all_website_links(url)`, `registry(url, ...)` — see
`exploration/detection.json` coverage_gaps) and extracted the earliest untrusted boundaries instead, so no
additional taint-propagation steps are required from the CSV candidates. Phase 2 may still need summary edges
for flows that cross the sqlalchemy `Integration` connection-args persistence (request body → DB → handler
`connect()`), which is outside CSV-candidate scope and is flagged in `phase1_review.md` §6.

## Low-confidence entries (< 0.55)

5 entries (ids in `labels_raw_pass3.json` → `low_confidence_reverification`): `P3-K-0046`
(lightwood `train_url` 0.45, dead-code-leaning), `P3-K-0038` (file_handler `_fetch_url` 0.5, no production
caller), `P3-S-0118` (sql.py:30 `context` dict 0.5), `P3-S-0133/0134` (PUT/POST views stored query 0.5).
Each was re-examined against the source in B11 and kept as `candidate` (no verified direct fetch path → not
promoted; plausible design/second-order path remains → not demoted).

## Conformance notes

- A `pass_id: 1` stub block with **zero entries** is present in `labels.json` solely to satisfy the schema's
  `contains` clause (the schema requires an array element with `pass_id == 1`); Pass 1 is out of scope for
  this run. The Augur consumer (`scripts/filter_and_report.py::summarize_labels`) iterates passes and does not
  depend on pass 1.
- `arg_index` is `null` for `field`/`return` flow kinds. For the three sink rows whose CSV `arg_index` is `-1`
  with `flow_kind: argument` (schema requires an integer ≥ 0): `sap_erp_handler/api.py:55` and
  `lightdash_handler/api.py:21` (both `requests.request(**kwargs)` wrappers where the URL arrives via the
  `url=` keyword) carry `arg_index: 1` — requests.request's URL position; `intercom_handler.py:63`
  (`requests.get(url=self._baseUrl)`) carries `arg_index: 0`. Recorded in each entry's rationale.
- `urllib.request.urlopen`/`urlretrieve`, `httpx`, `aiohttp`, `http.client` are not used anywhere in the
  `mindsdb/` tree (verified during extraction); `requests` is the only outbound HTTP surface, and
  `urljoin`/`urlparse` were never treated as sinks (extraction excluded them; labeling confirms).
