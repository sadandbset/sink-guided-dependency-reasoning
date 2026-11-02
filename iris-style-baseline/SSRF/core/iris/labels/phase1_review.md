# Phase 1 Step 3 — Human Review Packet (Pass 3, CWE-918 SSRF)

Project: **core (Home Assistant core)**, snapshot git `e2dd7f2` (2023-08-29), DB `core-db` (creation sha matches).
Pass: **3 — Server-Side Request Forgery (CWE-918)**. Generated: 2026-10-19. Model: **glm-5.3** (in-session LLM labeling).

---

## 1. Scope and coverage

| item | count |
| --- | --- |
| CSV candidate rows (must cover) | **4778** = sources.csv 3010 + sinks.csv 1768 |
| Raw per-row verdicts (`labels_raw_pass3.json`) | 4778 (100% coverage, incl. `api`+`ast` double matches) |
| LLM labeling batches | 16 (family batches + per-row source review of location-sensitive families) |
| Deduplicated entries (`labels.json` pass 3) | 3989 CSV-derived + 9 supplemental sanitizer entries = **3998** |
| Duplicate rows collapsed | 789 (same AST node matched by both `api` and `ast` extraction, or repeated family matches — e.g. `arg` family 184 rows → 92 unique sites; `internal_client_getter` 1233 → ~618 unique) |

Dedup key: `(file, line, callable, role, flow_kind, arg_index, module)`. Every collapsed row keeps its own verdict in `labels_raw_pass3.json`; no row was silently dropped.

Label distribution (deduplicated entries): source/tp 1468 · none/fp 2346 · summary/candidate 155 · sink/tp 13 · sink/candidate 7 · sanitizer/tp 9.

## 2. Methodology

1. Read WORKFLOW.md, references/python.md, references/patterns.md, assets/labels_schema.json.
2. Family-level analysis of both CSVs (flow-kind, callable, module histograms).
3. **Per-row source-code review** for the location-sensitive families: `arg` (92 unique sites), `session_arg` (77), `http_handler_param` (154), `webhook_handler` (46), `request_json`/`request_post` (45) — each row's actual code line plus enclosing-class evidence (`requires_auth`, `@require_admin`) was inspected in the `core_vuln` tree.
4. Targeted call-chain tracing: downloader, rest_command, rest, blueprint importer, hassio ingress/handler, auth/indieauth → login_flow → onboarding, color_extractor, discord/slack/signal_messenger/pushsafer/nfandroidtv/xmpp/telegram_bot notify, mobile_app notify, cast helpers, media_player, generic/mjpeg camera, config_entry_oauth2_flow, system_health, webhook component.
5. Family-level rules for the bulk families (config_flow 1320, service_data 742, websocket_msg 316, request_attr 144, mqtt_payload 113, template_render 90, internal_client_getter 1233, internal_fetch_wrapper 156, url_build 96, env 15, config_file 25), each grounded in sampled source reads.
6. Deterministic rendering into the schema-conformant `labels.json` (validated against `assets/labels_schema.json`).

## 3. Operator review concerns — how each was resolved

1. **Real entry points at trust boundaries (not every internal param)** — every `http_handler_param` / `webhook_handler` / `request_*` row was classified by the *actual* auth posture of its enclosing view: `requires_auth=False` → unauthenticated boundary (conf 0.8); default `requires_auth=True` → authenticated-user boundary (conf 0.65); `@require_admin`-gated views → **none/fp** (admin-only input, trusted). Internal helpers that merely take a `webhook_id` parameter (no request) are labeled none/fp. Config-flow `user_input` (1320 rows) is admin-gated (REST flow views and websocket flow commands use `require_admin`, components/config/config_entries.py:141–237) → none/fp.
2. **Form/query/JSON/message fields reaching outbound URLs** — verified concretely: service data → `downloader` URL fetch; notify attachment URLs (pushsafer, nfandroidtv, xmpp, telegram_bot, discord, slack, signal_messenger, color_extractor); websocket `msg["url"]` → blueprint importer fetches; login-flow `client_id` → indieauth fetch.
3. **URL-parse / wrapper propagation** — wrappers need no summary edges (CodeQL inter-procedural call/return covers them); URL construction (`yarl.URL`, `urljoin`, `URL.build`) is labeled **summary** (argument → result), never sink. Render calls (`Template.async_render(variables=...)`) are labeled **summary** so rest_command's `variables=service.data` → `request_url` propagation survives.
4. **Dangerous argument positions** — `urllib.request.urlopen` has **zero** call sites in the tree (verified during exploration); the real sinks are `requests.{get,post,...}` (arg 0, occasionally arg 1 for `request(method, url)` / `stream("get", url)`), session methods `.get/.post/.request/.ws_connect` (arg 0 / arg 1), and `getattr(websession, method)(request_url)` (arg 0). All sink entries carry the exact arg index. `urljoin`/`urlparse` are *not* sinks.
5. **Real sanitizers** — 9 entries: `hass.config.is_allowed_external_url` (4 sites: color_extractor:106, discord:74, slack:181, signal_messenger:139) — a **default-deny** URL allow-list (`allowlist_external_urls` config, empty by default) that genuinely blocks the guarded fetches; blueprint importer host guards (5 sites: prefix/regex allow-lists confining imports to raw.githubusercontent.com / github.com / community.home-assistant.io / gist.github.com→api.github.com / *.home-assistant.io). Login/auth gates, HTML escaping and schema format checks were **not** counted as sanitizers. Webhook `local_only`+`is_local` is a *sender-origin* gate (documented in rationales, not a sanitizer entry).
6. **Auth ≠ sanitizer** — authentication levels are recorded in source rationales as attacker-model bounds (unauthenticated / authenticated-any-user / admin), not as SSRF barriers. e.g. the authenticated-only boundaries still leave downloader/notify-URL SSRF paths open to any non-admin HA user.
7. **Fixed vs attacker-changeable targets** — fixed vendor endpoints, YAML-config URLs, device-reported URLs, supervisor-fixed-host proxies (hassio handler:534, ingress) and admin config templates are all labeled none/fp or candidate with explicit rationale; only rows whose URL argument is input-derived are sink/tp.
8. **file:/data: schemes** — no `file:`/`data:` outbound-request paths found in the pass-3 sink set (one `data:` base64 embed in pushsafer is response formatting, not a fetch target; local file reads in notify components are path-traversal concerns, out of pass-3 scope and excluded).
9. **External sources vs local diagnostic wrappers** — the extraction contained diagnostic-only shapes (sqlalchemy `session.get`, `internal_client_getter` factories, wrapper defs, `msg["id"]/["type"]` routing keys); all are labeled none/fp with reasons and excluded from MySources/MySinks generation.

## 4. Key findings for review

### 4.1 sink/tp (13) — genuine fetches of input-derived URLs

| location | arg | source of URL | boundary | notes |
| --- | --- | --- | --- | --- |
| components/downloader/__init__.py:81 `requests.get` | 0 | `service.data[ATTR_URL]` | authenticated any user | `cv.url` format check only; strongest candidate |
| components/telegram_bot/__init__.py:310 `requests.get` | 0 | service data `ATTR_URL` (send_file) | authenticated any user | no allow-list |
| components/pushsafer/notify.py:157/159 | 0 | notify `picture1.url` | authenticated | no allow-list (local_path is path-checked, url is not) |
| components/nfandroidtv/notify.py:183/186 | 0 | notify image/icon `url` | authenticated | no URL allow-list |
| components/xmpp/notify.py:270 | 0 | notify message url | authenticated | no allow-list |
| components/signal_messenger/notify.py:143 | 0 | notify attachment urls | authenticated | **guarded** by default-deny allow-list (sanitizer p3-san-04) |
| components/blueprint/importer.py:155/168/192/237 | 0 | websocket `msg["url"]` | authenticated | **host allow-listed** (sanitizers p3-san-05..09); gist fetch host fixed to api.github.com |
| components/auth/indieauth.py:95 `session.get` | 0 | login-flow/onboarding `client_id` | **unauthenticated-origin** | format checks only; internal IPs *explicitly allowed* (indieauth.py:195–212); 10 kB read cap; fetch occurs in the client_id/redirect_uri host-mismatch branch (login_flow.py:218, onboarding/views.py:249) |

### 4.2 sink/candidate (7)

- hassio/ingress.py:134/159 — supervisor proxy: outgoing **host fixed**; attacker controls method/path/query/content only (ingress-authenticated). Not arbitrary-host SSRF; retained for review.
- mobile_app/notify.py:168 — POST to `push_url` from device-registration `app_data` (webhook-updatable; requires webhook secret + authenticated notify call).
- cast/helpers.py:252 — playlist fetch; URL ultimately from media resolution (`media_content_id`), `_is_url` is format-only.
- media_player/__init__.py:1262 — generic `async_fetch_image` (artwork/browse URLs).
- helpers/config_entry_oauth2_flow.py:523 — parameterized OAuth2 session request wrapper (in-tree callers fixed/config).
- rest_command/__init__.py:121 — `getattr(websession, method)(request_url)` where `request_url = template.async_render(variables=service.data)`: template body is admin YAML; host control requires a variable in scheme/host position of the admin template.

### 4.3 Boundary conditions recorded (not vulnerabilities claimed)

- `downloader`, notify-attachment and telegram_bot paths require an **authenticated** HA user (any, incl. non-admin).
- The indieauth path is unauthenticated-origin but only fires after a successful login-flow completion or during the onboarding window.
- All four `is_allowed_external_url` sites default-deny unless the admin configures `allowlist_external_urls`.
- No finding presumes exploitability; Phase 2 taint results + this packet go to human triage.

## 5. Schema conformance notes

- `labels.json` validated against `assets/labels_schema.json` (strict field-set, enum, pattern and `argument → arg_index ≥ 0` checks; `jsonschema` package unavailable in the environment, an equivalent strict validator was run — PASS).
- The schema's `passes.contains` requires a block with `pass_id: 1`; this run is pass 3 only, so `pass 1` is present as an **empty placeholder** with no entries and an explanatory `focus`/note. It carries no labels.
- CSV flow kinds were mapped to the schema enum: `param` (handler/config-flow/webhook params), `field` (request/msg/payload attribute reads), `return` (json()/post()/render/getter results), `argument` (+ exact index) for sink call arguments, `unknown` for ctor rows; CSV `-1` → `null`.

## 6. Recommended Phase 2 handling (advisory, not executed)

- MySources: all source/tp entries; keep the boundary level (unauth/auth) metadata available for filtering.
- MySinks: the 13 tp + 7 candidate sink signatures; exclude none/fp rows from generation.
- MySanitizers: the 9 sanitizer entries (`is_allowed_external_url` arg 0; blueprint `startswith`/`match` guards).
- MySummaries: template-render rows (variables → result) and url_build rows (arg 0 → result).
- FP heuristics already encoded at label time: admin-config URLs, fixed endpoints, `internal_client_getter`/`session_ctor`/wrapper rows, `script/` tooling, websocket routing keys.

## 7. Constraints honored

- No PyVul ground truth, fix commits or external CVE descriptions consulted; only the `core_vuln` source tree, the extraction CSVs and Augur references were used.
- No modification of project source, CodeQL DB, original CSVs or Augur tool files (read-only). Only `iris/labels/*` was written (plus the offline scratch/audit folder `label_work/` outside `iris/`).
- Per operator instruction: generation stops here; **Phase 2 is not started**.
