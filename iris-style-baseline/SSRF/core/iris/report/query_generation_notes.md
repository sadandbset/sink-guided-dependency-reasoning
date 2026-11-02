# Query Generation Notes — Pass 3 (CWE-918 SSRF), Phase 2 Step 4–5

Project: **core (Home Assistant core)**, snapshot git `e2dd7f2` (2023-08-29), DB `core-db`.
Generated: 2026-10-19. Labeling model (Phase 1 Step 3): glm-5.3, 16 batches, reviewed packet `iris/labels/phase1_review.md`.
Generated files: `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass3_SSRF.ql`. No CodeQL execution was performed in this step (per operator instruction; compilation deferred to the analysis step).

---

## 1. Label ID ↔ QLL predicate mapping

### MySources.qll — `isSource(DataFlow::Node, string passKey)` ("ssrf")

The 1468 reviewed source/tp entries fall into 7 structural families; each family is implemented as one predicate that generalizes the reviewed locations to the same code shape (this is signature-level rendering per WORKFLOW 5.1.1, not a label change):

| label family (entry count) | predicate | matching shape | propagation basis |
| --- | --- | --- | --- |
| service_data (723) | `serviceDataRead` | attribute read `service.data` / `call.data` | `hass.services` handlers; service calls reachable by any authenticated HA user (REST `APIDomainServicesView`, WebSocket commands) |
| websocket_msg (287 of 316; 29 routing-key rows are none) | `websocketMsgRead` | `msg["<key>"]` subscript / `msg.get("<key>")` call, keys `id`/`type` excluded | `@websocket_api` handlers; authenticated session (auth phase in `components/websocket_api`) |
| http_handler_param (129 of 154; 25 admin-gated rows are none) | `handlerRequestParam` | `request` parameter of functions named get/post/put/delete/patch/head/options/_handle, `@require_admin`-decorated functions excluded | aiohttp `HomeAssistantView` handlers; auth level per view (see §2) |
| request_attr (144) | `requestFieldRead` | `request.query/remote/headers/path/content/query_string/match_info` | direct attacker-supplied request metadata at the HTTP boundary |
| request_json (33) + request_post (12) | `requestBodyRead` | `await request.json()` / `await request.post()` results | full request body |
| mqtt_payload (113) | `mqttPayloadRead` | `msg.payload` attribute read | MQTT subscription callbacks; external device-bus input (broker access required) |
| webhook_handler (24 of 46; 22 internal-helper rows are none) | `webhookHandlerParam` | `request` parameter of a function that also has a `webhook_id` parameter | dispatched by `WebhookView` (`requires_auth=False`, `/api/webhook/{webhook_id}`) |

Deliberately **not** sources: config_flow `user_input` (1320 rows, admin-gated), env (15), config_file (25), template_render (90 — summary role), and all internal network-wrapper parameters (fetch wrappers, client getters), per the reviewed none/fp labels.

### MySinks.qll — `isSink(DataFlow::Node, string passKey)` and `getSinkAlertMessage(...)`

All 20 reviewed sink entries (13 tp + 7 candidate) are **location-pinned** to the exact reviewed call site and argument position (`urlArgAt(sink, fileSuffix, line, argIndex)` via `Call.getArg(i)`); no generic `requests.get` signature is emitted because the other 72 reviewed requests-family sites are fixed/config URLs.

| label id | call site | API | arg | scope (embedded in getSinkAlertMessage) |
| --- | --- | --- | --- | --- |
| p3-snk-3603 | components/downloader/__init__.py:81 | `requests.get` | 0 | full URL, any authenticated user (service data, `cv.url` only) |
| p3-snk-3601 | components/telegram_bot/__init__.py:310 | `requests.get` | 0 | full URL, authenticated (service data ATTR_URL) |
| p3-snk-3639/3640 | components/pushsafer/notify.py:157/159 | `requests.get` | 0 | full URL, authenticated (notify attachment) |
| p3-snk-3646/3647 | components/nfandroidtv/notify.py:183/186 | `requests.get` | 0 | full URL, authenticated (notify image/icon) |
| p3-snk-3650 | components/xmpp/notify.py:270 | `requests.get` | 0 | full URL, authenticated (notify upload url) |
| p3-snk-3641 | components/signal_messenger/notify.py:143 | `requests.get` | 0 | full URL, guarded by default-deny allow-list |
| p3-snk-3734 | components/auth/indieauth.py:95 | aiohttp `session.get` | 0 | full URL incl. host, unauthenticated-origin client_id |
| p3-snk-3730/3731/3732/3733 | components/blueprint/importer.py:155/168/192/237 | aiohttp `session.get` | 0 | host-restricted (community / raw.githubusercontent / fixed api.github.com gist id / *.home-assistant.io) |
| p3-snk-3735/3736 | components/hassio/ingress.py:134/159 | `ws_connect` / `request` | 0/1 | fixed supervisor host, path/query only |
| p3-snk-3749 | components/mobile_app/notify.py:168 | aiohttp `post` | 0 | registrant-chosen push_url |
| p3-snk-3725 | components/cast/helpers.py:252 | aiohttp `session.get` | 0 | full URL via media resolution |
| p3-snk-3693 | components/media_player/__init__.py:1262 | aiohttp `session.get` | 0 | full URL via media browse/artwork |
| p3-snk-3717 | helpers/config_entry_oauth2_flow.py:523 | `session.request` | 1 | parameterized wrapper, in-tree callers fixed |
| p3-snk-3831 | components/rest_command/__init__.py:121 | `getattr(websession, method)(url,…)` | 0 | template-rendered URL (admin template + service data variables) |

The query's select message is the return value of `MySinks::getSinkAlertMessage(sink, "ssrf")` (a `string` function), which embeds the reviewed scope of each sink, so full-URL control, host-restricted, and path-only control are reported with distinct descriptions rather than one uniform severity.

### MySanitizers.qll — `isBarrier(DataFlow::Node, string passKey)`

9 reviewed sanitizer entries, modeled as the checked-URL argument (arg 0) of the guard call at each pinned site:
- p3-san-01..04 — `hass.config.is_allowed_external_url(url)` at color_extractor:106, discord:74, slack:181, signal_messenger:139 (default-deny URL allow-list backed by `allowlist_external_urls`).
- p3-san-05..09 — blueprint importer host guards at :65 (`startswith` raw.githubusercontent), :68 (`GITHUB_FILE_PATTERN.match`), :81 (`COMMUNITY_TOPIC_PATTERN.match`), :185 (`startswith` gist), :236 (`WEBSITE_PATTERN.match`).

### MySummaries.qll — `isAdditionalTaintStep(from, to, passKey)`

- template_render labels (90) → `templateRenderStep`: every argument (positional or keyword value) of a `.render(...)`/`.async_render(...)` call flows to the call result.
- url_build labels (65) → `urlConstructionStep`: argument 0 of `yarl.URL(x)` / `URL(x)` / `URL.build(...)` / `urljoin(...)` / `<module>.urljoin(...)` flows to the result.

## 2. Source trust boundaries and propagation basis

- **Unauthenticated HTTP**: webhook handlers (`WebhookView`, `requires_auth=False`, `cors_allowed=True`, dispatch at `components/webhook/__init__.py:182`); requires_auth=False views (OAuth callbacks, auth/login-flow, onboarding, emulated_hue LAN API with `is_local` sender check, hassio views). Relevant reviewed path: login-flow `client_id` → `verify_redirect_uri` → `fetch_redirect_uris` fetch (p3-snk-3734).
- **Authenticated any-user** (incl. non-admin): REST/WebSocket API and service calls (`components/api/__init__.py:330`, websocket command handlers) — the boundary for service_data and websocket_msg sources, i.e. the downloader/notify/blueprint paths.
- **External device bus**: MQTT `msg.payload` (broker credentials/LAN position required) — retained for recall, lower confidence (0.55).
- No internal wrapper parameter (fetch wrappers, client getters, OAuth2 session helpers) was promoted to a source to force path connectivity, per the reviewed none labels.

## 3. Sinks: real network request APIs, argument indices, call sites

Real network I/O APIs used by the sink set: `requests.get/post` (sync), aiohttp `ClientSession.get/post/request/ws_connect` (async, via the shared `async_get_clientsession` funnel or direct session), and the dynamic-dispatch call `getattr(websession, method)(request_url, …)`. Argument indices are the URL positions verified in source (0 for get/post/ws_connect/getattr; 1 for `request(method, url)` at ingress:159 and oauth2:523 — `Call.getArg(i)` is positional-only, which matches these sites because the URL is passed positionally there). `urllib.request.urlopen` / `urlretrieve` have zero call sites in the tree (verified in Phase 1 exploration) and are therefore absent from the model. `yarl.URL`, `URL.build`, `urljoin`, `urlparse` are modeled as taint-preserving steps only, never sinks.

## 4. Scheme / fixed targets / redirects / private addresses / sanitizer handling

- **URL scheme limits**: no reviewed site enforces an http/https scheme allow-list except indieauth's format checks (`scheme in ("http","https")`, no dot segments, no fragment — `_parse_client_id`, indieauth.py:151–175). `cv.url` voluptuous validation on service fields is URL-shape only (documented in labels as non-sanitizing).
- **Fixed targets**: the 72 fixed/config requests.* sites, vendor endpoints, supervisor host (`f"http://{self._ip}{command}"` handler:534; ingress `http://{host}/ingress/...`) — all excluded from sinks or scope-labeled as fixed-host (ingress rows).
- **Redirects**: `allow_redirects=False` at ingress:159 (scope notes); `follow_redirects=True` at generic camera / rest data sites (those are admin-config fp rows, not sinks). No redirect-based sanitizer exists in the tree.
- **Private addresses**: `is_allowed_external_url` is the only effective host restriction (default-deny). **No private-IP/DNS-pinning sanitizer exists anywhere in the reviewed sink paths**; indieauth *deliberately permits* internal IPs in client_id (indieauth.py:195–212) — this is why the indieauth sink carries the highest full-URL scope.
- **Effective sanitizers**: modeled per §1; their barrier placement limitation is recorded in §6.
- **file:/data: schemes**: no `file:`/`data:` outbound request path exists in the sink set; local-path notify handling is path-traversal scope, excluded from pass 3.

## 5. Summary / custom propagation edges — source-code basis

- `templateRenderStep` — basis: `components/rest_command/__init__.py:97–121` renders `template_url` with `variables=service.data` and fetches the result; `Template.async_render(variables=…)` is the documented interpolation point (rendered output carries variable taint). Keyword arguments are included via `Call.getANamedArg().getValue()`.
- `urlConstructionStep` — basis: URL normalization between input and fetch: `blueprint/importer.py:174` (`yarl.URL(import_url)`), `helpers/network.py:65`, `components/media_player/browse_media.py:63` (`parsed.join(yarl.URL(signed_path))`), urljoin uses under sigfox/blueprint. Only argument 0 is modeled because the reviewed labels pin arg index 0 (gap recorded in §6).
- Wrapper functions are *not* given custom edges: standard inter-procedural call/return data flow already connects e.g. `ws_import_blueprint` → `fetch_blueprint_from_github_url(url)` → `session.get(import_url)`; the reviewed wrapper labels (role=none) explicitly rely on this.

## 6. Uncovered APIs, dynamic calls, and CodeQL analysis limitations

1. **Barrier-guard limitation (most important)**: the installed new-dataflow `ConfigSig` (codeql/dataflow 2.1.7, used by python-all 7.1.2) has no `isBarrierGuard` concept. `isBarrier` removes a node from the flow graph, but the guard's checked-URL argument and the fetch-site URL argument are distinct AST nodes, so branch-sensitive pruning of `if not allowed(url): return` cannot be expressed. The modeled barriers mark the guard sites and prune flows through the checked argument itself; guarded sinks (signal_messenger, blueprint) remain reachable and are triaged via their scope strings. **Recommendation for re-review**: if pruning is required, either extend labels with a sanitized-output modeling decision or move the guard knowledge into Phase 2 result filtering.
2. **Dynamic dispatch**: `getattr(websession, method)(request_url, …)` is covered only at the pinned rest_command site (p3-snk-3831); other dynamically-dispatched fetches (rest/switch:206, microsoft_face) are reviewed none/fp (config/fixed URLs). Unresolvable dynamic fetches elsewhere are a general recall gap.
3. **Structural source generalization**: name-based matching (`service`/`call`, `request`, `msg`) can match non-boundary variables with the same names (e.g., a local `request` in unrelated code); this is the documented ast-matchKind trade-off from Phase 1. The admin-gating exclusion for handler params is decorator-based (`@require_admin` on the method) and may miss class-level or policy-based gating — residual false positives possible for admin-gated handlers.
4. **urljoin argument 1** (joined relative URL) not modeled — labels pin arg 0 only. **Label gap; requires re-review**, not silently widened.
5. **`URL.build` keyword arguments** (host=, scheme=) are not covered (labels pin positional arg 0).
6. **Uncovered sinks by design**: `urllib.request.urlopen` (absent), httpx module-level calls (absent), responses of proxied streams (`async_aiohttp_proxy_web`), and all fixed/config-URL sites (reviewed fp).
7. **Path separator assumption**: sink/barrier location pinning uses `matches()` with a *string-literal* forward-slash pattern per site (QL binding rules require literal match patterns); the DB's `getAbsolutePath()` demonstrably uses forward slashes (Phase 1 CSV output), but a re-run on a backslash-format DB would need the backslash variant added per site.
8. **Compile status**: after the fix log in section 9, `codeql query compile --check-only queries/Pass3_SSRF.ql` (CLI 2.25.1, python-all 7.1.2 from the pack cache) completes cleanly ("Done", no errors or warnings).
9. **No diagnostics query was needed**: `urlopen`/`urlretrieve` have zero call sites, so no internal-helper-to-urlopen reachability check is required; no diagnostic paths are mixed into the formal CWE-918 alerts.

## 7. Label review state and gaps requiring re-review (labels were NOT modified)

- **`labels/review_decision.json` does not exist.** Phase 1 wrote the optional review packet (`phase1_review.md`) but no decision artifact; the operator prompt for this step referenced it. **Action requested**: record the human review outcome (approved / changes) before or alongside the Step 5 execution run; this step proceeded on `labels.json` + `phase1_review.md` as-is.
- Label gaps found during generation (recorded, not silently fixed): urljoin arg-1 taint (§6.4), `URL.build` kwargs (§6.5), possible class-level admin gating not visible to the handler-param exclusion (§6.3), and the sanitizer pruning semantics decision (§6.1). Each needs a label re-review decision, after which the QLLs can be regenerated from the updated labels.

## 8. Reproducibility and independent-evaluation principles (same as the prior CWE-78 experiment)

- Inputs are fixed and recorded: extraction CSVs (`iris/extraction/*.csv`), reviewed labels (`iris/labels/labels.json`, raw per-row verdicts in `labels_raw_pass3.json`), and the source snapshot (git `e2dd7f2`, DB sha match). The four QLL files and the query are deterministic renders of the label set — no ad-hoc hand-picked signatures beyond the reviewed entries.
- No PyVul ground truth, fix commits, or known-CVE locations were consulted at any point; sink/source decisions cite only in-tree source evidence (file:line in the rationales and in these notes).
- Project source, the CodeQL database, the Phase 1 CSVs, and the reviewed labels were not modified. Only `iris/libraries/*.qll`, `iris/queries/Pass3_SSRF.ql`, and this report were written.
- Execution contract for the next step: `codeql pack install` (already provisioned in Phase 1), then run `queries/Pass3_SSRF.ql` alone against `core-db` (sequential, no parallel DB access), decode results, and apply the WORKFLOW 5.3.2 SSRF FP heuristics during filtering — the label-level FP classes (fixed endpoints, admin-config URLs, client factories) are already excluded from the model, so remaining triage focuses on the boundary conditions in the scope strings.

## 9. Compile fix log (2026-10-19, after the operator's first `codeql query compile`)

The operator ran `codeql query compile --check-only queries/Pass3_SSRF.ql` (CLI 2.25.1) and
hit a parse-error flood. Root causes and fixes (all syntax/API-level; **the taint model
itself — sources, sinks, barriers, summary steps, pass key, and all reviewed label
mappings — is unchanged**):

1. **Early comment termination** (`MySinks.qll` header): the comment text
   "requests.*/session.*" contained the character sequence `*/`, terminating the
   `/** ... */` header comment at line 5 — everything after it was parsed as QL code,
   producing the bulk of the error flood (token recognition errors, "predicate requires
   a body", "unknown annotation", cascading select-clause conflicts). Fixed by rewording
   the comment ("every other requests and session-method location").
2. **QL keyword as parameter name** (`MySummaries.qll`): `isAdditionalTaintStep(DataFlow::Node from, ...)`
   used `from`, a reserved QL keyword, breaking the whole module (the "library modules
   cannot contain query clauses" / "select clause" cascade). Renamed to `nodeFrom`/`nodeTo`
   (matching the WORKFLOW.md template placeholders).
3. **Non-literal `matches()` pattern** (`MySinks.qll`/`MySanitizers.qll`):
   `path.matches("%" + fileSuffix)` — QL's `matches()` binding rules do not accept a
   concatenated pattern expression ("'fileSuffix' is not bound to a value"). Fixed by
   inlining a string-literal pattern at every pinned site
   (`matches("%/homeassistant/components/...")`), the same idiom the Phase 1 extraction
   queries used successfully.
4. **Predicate arity mismatch** (query): `getSinkScope` was a 3-argument predicate called
   with 2 arguments. Replaced by the `string` function `getSinkAlertMessage(sink, passKey)`
   returning the full alert message (scope embedded) as the query's message column; this
   also removed string concatenation from the select clause.
5. **Type error on keyword arguments** (`MySummaries.qll`): `Call.getANamedArg()` returns
   `DictItem`, which has no `getValue()`; the typed accessor is `Call.getAKeyword()`
   (returns `Keyword` with `getValue()`). Swapped in the second compile round.
6. Cosmetic: QLDoc-style `/*** ... ***/` banner comments (which begin with `/**`) produced
   "QLDoc comment is not attached" warnings; converted to plain `/* ... */` banners.

Verification: `codeql query compile --check-only queries/Pass3_SSRF.ql` now reports
`Done [1/1]` with no errors and no warnings (resolution from the local pack cache
`C:/Users/lzh/.codeql/packages`, codeql/python-all 7.1.2). No labels, project source, or
database files were modified while fixing.
