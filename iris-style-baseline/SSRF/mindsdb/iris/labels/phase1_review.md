# Phase 1 Step 3 Review — LLM Candidate Labeling, Pass 3 (CWE-918 SSRF), mindsdb

**Status:** Step 3 complete. This document is the advisory checkpoint payload (WORKFLOW.md §4.5) for human
review before Phase 2. Per instructions, Phase 2 was NOT started.

- Artifacts: `labels/labels.json` (schema-valid), `labels/labels_raw_pass3.json`, `labels/label_stats.md`,
  deterministic renderer `labels/build_labels_pass3.py`.
- Model: glm-5.3 (Z.ai GLM), in-session via Claude Code CLI. Batches: 11 (B1–B10 + B11 re-verification).
  Candidates labeled: 229/229 (136 sources + 93 sinks), 0 skipped, 0 duplicates.
- Evidence base: direct reading of the mindsdb sources (Flask + flask_restx REST layer, MySQL/Postgres wire
  proxies, ~45 integration handlers) via four parallel evidence-gathering passes, plus `request.*`-row-level
  tracing of all 22 namespace modules. No PyVul ground truth, CVE descriptions, fix commits, or pre-existing
  SSRF analysis artifacts in the repo root were consulted.

## 1. Label counts by pass and role

See `label_stats.md` for full tables. Summary: source 134 (tp 14 / candidate 13 / fp 107), sink 93
(tp 37 / candidate 5 / fp 51), none 2 (env boundaries), summary 0, sanitizer 0.

## 2. Top high-risk sink APIs (tp)

| Sink | Location | Why |
| --- | --- | --- |
| `requests.get(url, stream=True)` | `api/http/namespaces/file.py:116` | PUT /api/files/<name> with `source_type=='url'`: `url = data['source']` passed verbatim (request.json or multipart stream); no scheme/host validation |
| `requests.get(url)` | `mysql_proxy/utilities/functions.py:33` | `download_file` of PATH-type `{'url': ...}` connection args from `CREATE DATABASE ... WITH PARAMETERS` — SQL-caller-chosen full URL; non-empty-scheme check only |
| `session.get(url)` | `web_handler/urlcrawl_helpers.py:102` | web-crawl transport; initial URL from `SELECT ... FROM web WHERE url='...'` / native query; https:// auto-prepended; same-domain filter covers only discovered hrefs |
| `requests.get(url)` | `rag_handler/settings.py:400` | `CREATE MODEL ... USING url='...'` → `url_to_documents` fetch, no validation |
| dremio `requests.post/request` ×5 | `dremio_handler.py:71,127,138,143,146` | `base_url = http://{connection_data['host']}:{port}` — host/port from CREATE DATABASE args; credentials POSTed to attacker host |
| pinot `requests.get` ×4 | `pinot_handler.py:185,188,211,214` | `host`/`controller_port`/`scheme` connection args; InvalidScheme branch prepends user scheme |
| frappe `requests.get/post` ×4 | `frappe_client.py:34,59,91,108` | `domain` connection arg = entire scheme://host; Authorization token forwarded |
| eventstoredb ×4, strapi ×3, mlflow ×2, ray_serve ×2, scylla, sap_erp, lightdash, gmail, google_oauth, clipdrop:33, twitter:162, stabilityai:111 | see `label_stats.md` | all fetch hosts/URLs chosen via connection args, `using` args, or SQL row/WHERE values |

Top candidate (second-order / unproven) sinks: eventstoredb `link['uri']` fetches (:118/:165), frappe redirect
`Location` fetch (:70), file_handler `_fetch_url` (:386, no production caller in this snapshot), lightwood
`train_url` (:155, no setter/caller found).

## 3. Top source APIs (tp / key candidates)

- **Direct (tp):** `request.json['query']` of POST /api/sql/query (`sql.py:29`) and POST /api/analysis/query
  (`analysis.py:46`); `MysqlProxy.process_query(sql)` (`mysql_proxy.py:522`) and
  `PostgresProxyHandler.process_query(sql)` (`postgres_proxy.py:253`) — the shared arbitrary-SQL channel
  (also reached from the HTTP endpoints via FakeMysqlProxy); `request.json`/`request.stream` of
  PUT /api/files/<name> (`file.py:83`/`:73`); POST/PUT /api/databases bodies (`databases.py:28/31/71/76`) and
  the tables body's arbitrary SELECT (`databases.py:132/134`); PUT /config/integrations params
  (`config.py:112/113` — immediate `create_tmp_handler(...).check_connection()`).
- **Second-order (candidate):** chatbots `db_params` (×4) and config integrations modify (×2) → stored
  connection args; models CreatePredictor `using` args (×2) → `ml_handler.learn`; views stored query text
  (×4) executed later; sql.py:30 `context` dict.

## 4. Sanitizer list

**Empty** — no candidate is a valid SSRF sanitizer, and no sufficient mitigation exists in the tree: the only
URL checks found are scheme-shaped (download_file non-empty scheme; file_handler/scylla http/https;
clipdrop extension suffix), plus a crawl same-domain filter that derives its domain from the attacker URL.
No host allow-list, no private-IP/DNS check, no redirect control; `requests` follows redirects by default at
every sink. See `label_stats.md` §Sanitizers.

## 5. Answers to the nine review directives

1. **Untrusted boundaries verified.** All extracted sources are real entry points, not internal wrapper
   params: `request.*` attribute reads inside `@ns_conf.route` flask_restx Resource methods; Resource method
   path parameters (route variables); wire-protocol `sql` parameters; the two env reads are explicitly labeled
   `none` (operator-trusted). Reachability: `before_request` (initialize.py:251-266) protects the
   `/api/...` namespaces **only when `config['auth']['http_auth_enabled']` is True**; with the common
   self-hosted default (disabled), `/api/sql/query`, `/api/files`, `/api/databases` are reachable
   unauthenticated. With auth enabled, any logged-in user (check_auth compares session username to config
   credentials) reaches them; the MySQL/Postgres wire paths apply their own protocol auth first. The
   `requests.head` size pre-check in file.py is cloud-only; the `requests.get` at :116 runs for any caller.
2. **Inputs that can influence outbound URLs.** (a) PUT /api/files body `source` (direct fetch);
   (b) `request.json['query']` / wire-protocol SQL (CREATE DATABASE ... WITH PARAMETERS `{'url':...}` →
   download_file; CREATE MODEL/ML_ENGINE `using` args → rag/mlflow/ray_serve/gmail/youtube fetches;
   SELECT ... FROM web WHERE url → crawl); (c) POST/PUT /api/databases `parameters` and chatbots `db_params`
   → stored connection args → dremio/pinot/strapi/eventstoredb/frappe/sap_erp/lightdash/scylla hosts;
   (d) query-time values: clipdrop/stabilityai `image_url`, twitter `media_url` INSERT column, native-query
   ids; (e) config integrations `test` params (immediate check_connection). Ordinary metadata bodies
   (agents/models/skills/views-PUT/tabs/login/log filters) were verified NOT to reach outbound URLs (fp).
3. **Real propagation chains verified end-to-end in code:** request body → FakeMysqlProxy.process_query →
   Executor.query_execute → executor_commands PATH-args → download_file → requests.get; request body →
   integration_controller.add → sqlalchemy Integration row → handler connect() → connection_data hosts →
   requests; PUT files body → data['source'] → requests.get → save_file; web WHERE url → get_all_websites →
   session.get (+ urljoin of response hrefs); CREATE MODEL using → RAGHandlerParameters → url_to_documents →
   requests.get; chatbot db_params → integration_controller.add → (deferred connect). The sqlalchemy
   persistence hop is a DB relay (documented in detection.json) that Phase 2 taint tracking will need a
   summary edge for (see §6).
4. **Dangerous argument positions.** URL is positional argument 0 for all `requests.get/post/put/delete/head`
   and `requests.Session.get`; positional argument 1 for `requests.request` (method first) — verified per
   site. The three keyword/kwargs cases (`sap_erp api.py:55` and `lightdash api.py:21` via
   `requests.request(**kwargs)`, `intercom_handler.py:63` via `requests.get(url=...)`) are recorded with
   `arg_index` 1/1/0 plus rationale notes, as the schema requires an integer for `flow_kind: argument`.
   `urljoin`/`urlparse` were never treated as sinks (extraction excluded them; labeling confirms: they are
   parse/validation helpers, and their checks are not host-restricting).
5. **Sanitizer sufficiency.** No scheme allow-list that restricts to safe hosts, no fixed-host whitelist that
   users cannot extend (the only fixed hosts are compile-time literals on the fp sites), no redirect control
   (`allow_redirects` unset everywhere except frappe_client.py:63/70), no DNS-resolution/private-IP
   restriction anywhere. The scheme checks that exist (download_file, file_handler, scylla) do not block
   internal-network HTTP fetches; download_file's non-empty-scheme check even permits non-http schemes
   (recorded as a cross-protocol concern, not merged into CWE-918 verdicts).
6. **Auth ≠ sanitizer.** The before_request gate and wire-protocol auth are recorded as reachability facts
   in rationales, never as sanitizers; the cloud `user_class` check gates only the file-size pre-check, not
   the fetch; no HTML escaping or format validation appears on any URL path.
7. **Fixed vs attacker-changeable URLs.** 51 sink sites carry literal/config/OAuth/env URL bases (fixed
   provider hosts with user input confined to path/query/headers; S3/IMDS literals; config auth servers;
   REGISTRY_URL/MINDSDB_EXECUTOR_URL env) — labeled `fp` with provenance in each rationale. 37 tp + 5
   candidate sinks carry user-influenceable hosts/URLs.
8. **file:/data: not merged.** No file:/data: fetching exists in this tree: file_handler restricts to
   http/https; scylla requires http/https prefix; download_file only requires a non-empty scheme (its
   scheme permissiveness is recorded in that entry's rationale as a separate cross-protocol concern).
   No CWE-918 verdict relies on file:/data: semantics.
9. **Internal wrapper params → not auto-sources.** The extraction excluded internal helper URL params
   (download_file/_fetch_url/get_all_website_links/registry); the labeled sources are the earliest external
   boundaries (request fields, route variables, wire SQL, `using`/connection args, env — env explicitly
   demoted to `none`). No internal wrapper parameter was promoted to a formal vulnerability source.

## 6. Unresolved / low-confidence items (human attention before Phase 2)

- 5 entries below 0.55 (re-verified in B11, all kept `candidate`): lightwood `train_url` (0.45 — no setter or
  caller found; legacy remote-training flow), file_handler `_fetch_url` (0.5 — no production caller of
  `_get_file_path` in this snapshot; the live URL-fetch path is the files API), sql.py:30 `context` dict
  (0.5), PUT/POST views stored query (0.5 ×2 — deferred executor path).
- **sqlalchemy persistence hop:** request body → `Integration` row → handler `connect()` spans a DB write;
  Phase 2 needs a summary edge (or path acceptance) for the stored-connection-args chains to surface
  (databases.py:28/71 → dremio/pinot/strapi/eventstoredb/frappe/sap_erp/lightdash/gmail/scylla sinks).
- **model_storage replay:** mlflow/ray_serve `predict_url` is read back from `model_storage.json_get('args')`
  at predict time — same DB-relay concern as above.
- **Second-order URL construction:** web-crawl href joining and eventstoredb `link['uri']` fetches build
  follow-up URLs from response content; kept as candidate sinks, may need `MySummaries.qll` edges if Phase 2
  should model them.
- **Jira/Shopify SDK flows:** jira `jira_url` and shopify `shop_url` connection args are consumed inside
  third-party SDKs (network I/O outside this database); the boundary is captured via the source entries, but
  the fetch sites are invisible — documented in detection.json coverage_gaps, not labeled as sinks.

## 7. Known limitations

- 107 request-field/path-parameter boundaries are labeled `source/fp`: real untrusted boundaries whose
  values provably do not reach outbound URLs in this snapshot. Phase 2 library generation must use
  `classification in (tp, candidate)` only, otherwise alert volume will explode.
- `labels.json` contains an empty `pass_id: 1` stub block required by the schema's `contains` clause;
  documented in `label_stats.md` §Conformance notes.
- Handler reachability assumes the standard integrated deployment (handlers registered via the executor).
  In modular/gRPC deployment some handler flows differ (documented in detection.json), but no tp label
  depends on the gRPC path.
- Confidence values are the labeling LLM's self-assessed certainty of the provenance trace, not exploit
  likelihood.

## 8. Suggested Phase 2 entry set

- `MySources.qll`: 14 tp + 13 candidate source entries (SQL-text boundaries, files-API body, databases
  bodies, config integrations test params; chatbots/models/views second-order bodies).
- `MySinks.qll`: 37 tp + 5 candidate sink entries (by signature; fp sites excluded).
- `MySummaries.qll`: no CSV-derived entries; consider hand-added edges for the sqlalchemy
  connection-args relay and model_storage replay (§6).
- `MySanitizers.qll`: empty (`none()` fallback) — no valid sanitizer was identified.
