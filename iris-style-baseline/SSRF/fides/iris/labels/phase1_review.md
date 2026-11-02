# Phase 1 Review Gate — fides, Pass 3 (SSRF / CWE-918/099/610)

- run_id: `fides-iris-pass3-step3-20261020`
- LLM model: glm-5.3 (Z.ai GLM), in-session labeling via Claude Code CLI after reading the real
  fides sources; 9 semantic batches (`pass3-S1..S5` sources, `pass3-K1..K4` sinks); single pass per
  batch; no re-ask loop (low-confidence entries flagged below instead)
- candidates: 140 source rows (`extraction/sources.csv`) + 50 sink rows (`extraction/sinks.csv`) = **190**, all labeled 1:1
  (no duplicates found, none removed; every row carries a rationale)
- outputs: `labels.json` (schema-valid against `assets/labels_schema.json`, Pass 1 kept as an empty
  placeholder to satisfy the schema's `contains pass_id 1` constraint), `labels_raw_pass3.json`
  (per-batch audit artifact with raw CSV rows, rubric, deviations, coverage notes), `label_stats.md`

**No end-to-end SSRF vulnerability verdict is claimed at this stage; nothing in Phase 2 has been run.**

## 1. Label distribution

| role | count | of which tp / candidate / fp |
| --- | --- | --- |
| source | 26 | 0 tp / 26 candidate / 0 fp |
| sink | 30 | 23 tp / 7 candidate / 0 fp |
| sanitizer | 0 | — |
| summary | 1 | 0 tp / 1 candidate |
| none | 133 | 133 fp |

Sources: 26 source + 1 summary + 113 none. Sinks: 30 sink + 20 none.
Mean confidence 0.718; 13 entries below the 0.55 re-ask threshold (see §6).

## 2. Top high-risk sink APIs (classification tp — the transport genuinely issues the request)

| sink | location | URL provenance |
| --- | --- | --- |
| `requests.post(url=config.url)` | `http_connector.py:48` | `HttpsSchema.url` from `ConnectionConfig.secrets` (PUT CONNECTION_SECRETS body) — full URL, no validation |
| `requests.Session.send(prepared_request)` | `authenticated_client.py:207` | `url = f"{self.uri}{path}"`; `self.uri` = `build_uri()` host from saas config + secrets placeholders |
| `httpx.post(f"{self.uri}...LOGIN")`, `httpx.Client.send` | `fides_client.py:59/125/227/271` | `FidesConnectorSchema.uri` from ConnectionConfig secrets |
| `httpx.AsyncClient.get(url)` | `request_service.py:108/113` | `server_url` = FidesClient `self.uri` |
| `AuthenticatedClient.send` wrappers | `saas_connector.py:137/287/436/539`, `oauth2_base.py:92`, overrides (braze:36, domo:40, friendbuy:33, mailchimp:58/97, twilio:41/80) | same build_uri base; oauth2 token-request host |
| `requests.post(url=f"https://{domain}/...")` | `friendbuy_nextgen.py:53`, `heap.py:49` | `domain` read straight from secrets — HOST position |

Candidate sinks (7): constructor surrogate URI arguments (`AuthenticatedClient.__init__` at
`oauth2_base.py:74` / `saas_connector.py:154`, `FidesClient.__init__` at `fides_connector.py:58`) —
no I/O in the constructor but the URI shapes every later request; host-pinned fetches with
config-derived paths (mailgun `message_dispatch_service.py:471/492/512`, yotpo `:45`).

## 3. Top source APIs (all classification candidate — privilege-gated web boundary)

`ConnectionConfig.secrets` reads feeding URL host/path/query positions: `http_connector.py:26/43`
(url), `fides_connector.py:51` (uri), `saas_connector.py:145` (host placeholders), `:55`
(get_saas_config → client_config host), `:74/134/221/312/403`, `saas_query_config.py:232/388/399`,
`oauth2_base.py:65/77/89`, `api_key`/`query_param` strategies (query-param value positions),
`friendbuy_nextgen:46` / `heap:43` (domain → host), `yotpo:42` (store_id → path);
`MessagingConfig.details` reads feeding mailgun URL paths (`:463/467/472/493/513`).

Boundary reachability (instruction point 1): these values enter via
`PUT /api/v1/connection/{key}/secrets` (scope `CONNECTION_CREATE_OR_UPDATE`,
`connection_endpoints.py:199-231`, `verify=True` fetches the stored URL immediately),
`PUT /api/v1/connection/{key}/saas_config`, and the messaging config routes (scope
`MESSAGING_CREATE_OR_UPDATE`). All are OAuth client-scope gated (privileged operators/API clients),
which is why source classifications stay `candidate` rather than `tp`; the Phase 2 "admin-configured
URLs → FP" heuristic applies at triage time. Nothing was auto-labeled from internal function params:
CLI/env/toml values (`config.cli.server_url`, `--org-url`) and all 40 S1/S2 wrapper/header rows are
`none`.

## 4. Sanitizers

None labeled. Verified against source: `HttpsSchema.url` is a plain `str`
(`connections_secrets_https.py:14`) with no URL validation; no scheme allow-list, host whitelist,
private-IP blocking or redirect control exists on any outbound path in `src/fides` (grep for
scheme/allowlist/whitelist/ipaddress/validators found hits only in config/CORS/logging settings, not
the connector layer). requests Session follows redirects by default. OAuth scopes are an
authentication gate, not a sanitizer, and were not labeled as one (instruction point 6).

## 5. Key judgment notes per the review instructions

1. **Untrusted boundaries**: only the OAuth-scope-gated config bodies and (path-only) privacy-request
   identity data are web-reachable inputs; CLI/env configuration is operator-trusted (`none`, 40 rows).
2. **Body/params → URL**: confirmed flows listed in §2/§3. Privacy-request identity values reach SaaS
   request *paths* via `saas_query_config.py:393-396` — observed in source but not extracted as CSV
   candidates, so documented in `labels_raw_pass3.json` coverage notes rather than invented as labels.
3. **Wrapper propagation**: `build_uri()` → `AuthenticatedClient.uri` → `Request(url=f-string)` is a
   field-mediated flow; modeled via the three constructor surrogate sinks plus the
   `connector_registry_service.py:439` summary step (config-to-config propagation).
4. **Sink accuracy**: `urllib.request.urlopen`/`urlretrieve` are not used anywhere in `src/`
   (parse-only urllib); every extracted sink position was verified against the real call sites.
   `urljoin/urlparse` sites were never treated as sinks.
5. **Fixed vs attacker-shapeable targets** (instruction 7): `none` for CLI-config fetches
   (`core/api.py`, `core/user.py`, `cli/utils.py`), fixed literals (mandrillapp `:418`,
   adobelogin `:74`), okta SDK (orgUrl from `--org-url`, I/O inside the SDK package); `candidate`
   for host-pinned mailgun/yotpo; attacker-shapeable host/URL kept as tp sinks.
6. **Non-HTTP schemes** (instruction 8): no `file:`/`data:` usage exists; DB-protocol connection
   strings (mongodb://, sqlalchemy URIs) are labeled `none` and recorded as cross-protocol adjacency,
   not CWE-918. OAuth authorization URLs built only to be *returned* to the client
   (`oauth2_authorization_code.py:99/107/112`) are `none` (returned-URL family); the Referer header
   flow (`saas_config_endpoints.py:267`) is stored for post-callback browser redirect — an
   open-redirect (CWE-601) family concern, out of pass-3 scope.

## 6. Unresolved / low-confidence items (13, confidence < 0.55 — human attention requested)

- `api_key:39` and `query_param:34` (0.50) — secrets-derived query-param **value** appended to
  request URLs; host stays fixed by the saas config. Keep or drop?
- `saas_connector.py:74/134/221/312/403`, `saas_query_config.py:388` (0.50) — secrets feeding
  SaaS request path/query placeholders and the second-order pagination strategy.
- mailgun sinks `message_dispatch_service.py:471/492/512` and yotpo `:45` (0.50) — host-pinned
  fetches with config-derived path segments only.
- `connector_registry_service.py:439` (0.50) — summary step for config-template propagation.

Open reachability questions for the reviewer: (a) whether holders of
`CONNECTION_CREATE_OR_UPDATE` / `MESSAGING_CREATE_OR_UPDATE` client scopes should be treated as
untrusted for your threat model (this single decision promotes or demotes all 26 source candidates);
(b) whether the identity-data → SaaS request path flow (coverage note) should get a Phase 2 summary
model; (c) whether the pagination `next_link` second-order URL flow should be in scope.

## 7. Recommendation

Proceed to Phase 2 (Step 4: library generation) with the current labels: the pass-3 library will
contain 26 source predicates, 30 sink predicates, 1 summary step and an empty (documented) sanitizer
set. The 13 low-confidence candidates above can be pruned at the review gate without affecting the
core transport sinks.

---
*Deviations recorded: `FidesClient.__init__` at `fides_connector.py:58` CSV `arg_index -1` (uri=
keyword) normalized to `0` (first parameter). Pre-existing root-level vulnerability-analysis
artifacts in the source tree were not read; no ground truth, CVE descriptions or fix commits were
consulted.*
