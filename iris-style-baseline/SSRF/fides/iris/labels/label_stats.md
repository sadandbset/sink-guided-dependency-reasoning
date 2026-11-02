# Pass 3 (SSRF / CWE-918) Label Statistics - fides

- run_id: `fides-iris-pass3-step3-20261020`
- generated_at: 2026-10-20T01:10:55Z
- model: glm-5.3 (Z.ai GLM), labeled in-session via Claude Code CLI (see `labels_raw_pass3.json`)
- batches: 9 (pass3-S1..S5 for sources, pass3-K1..K4 for sinks), single pass per batch, no re-ask loop
- input candidates: 140 source rows (`extraction/sources.csv`) + 50 sink rows (`extraction/sinks.csv`) = 190
- labeled entries: 190 (1:1 row coverage; no duplicates found, none removed; no candidates left uncovered)

## Distribution by role (all entries)

| role | count |
| --- | --- |
| source | 26 |
| sink | 30 |
| sanitizer | 0 |
| summary | 1 |
| none | 133 |

## Distribution by classification

| classification | count |
| --- | --- |
| tp | 23 |
| candidate | 34 |
| fp | 133 |
| unknown | 0 |

## Sources (140 rows)

| role | count |
| --- | --- |
| source (all classification candidate, conf 0.5-0.65) | 26 |
| summary | 1 |
| none | 113 |

Source-role sites (26): ConnectionConfig.secrets / get_saas_config reads feeding outbound URL host/path/query
positions in http_connector, fides_connector, saas_connector, saas_query_config, oauth2_base, api_key/query_param
strategies and the friendbuy/heap/yotpo overrides; plus 5 MessagingConfig.details reads feeding mailgun URL path
segments.

## Sinks (50 rows)

| role | count |
| --- | --- |
| sink / tp | 23 |
| sink / candidate | 7 |
| none | 20 |

Top transport sinks (tp): requests.Session.send (authenticated_client.py:207), requests.post (http_connector.py:48),
httpx.post/Client.send (fides_client.py:59/125/227/271), httpx.AsyncClient.get (request_service.py:108/113),
AuthenticatedClient.send wrapper sites (saas_connector 137/287/436/539, oauth2_base:92, 7 override functions),
requests.post with secrets-derived host (friendbuy_nextgen:53, heap:49).
Candidate sinks: AuthenticatedClient/FidesClient constructor surrogate URI argument (oauth2_base:74,
saas_connector:154, fides_connector:58), host-pinned mailgun fetches (message_dispatch_service.py:471/492/512),
yotpo token fetch (fixed host, store_id path).

## Sanitizers

None labeled: no sanitizer candidates in the CSVs, and verification found no scheme/host allow-list, private-IP
blocking or redirect control on any outbound path (HttpsSchema.url is a plain `str`,
`connections_secrets_https.py:14`).

## Confidence

- mean confidence: 0.728
- entries with confidence < 0.55 (flagged for human review gate): 13 -> src-005, src-024, src-026, src-079, src-080, src-082, src-083, src-084, src-086, snk-017, snk-030, snk-031, snk-032

## Batch map

| batch | rows | content |
| --- | --- | --- |
| pass3-S1 | 40 | CLI/env/toml trusted-boundary sources (all none) |
| pass3-S2 | 12 | request.headers reads in the API layer (all none) |
| pass3-S3 | 39 | ConnectionConfig.secrets / saas config / auth strategies (21 source-candidate, 1 summary, 17 none) |
| pass3-S4 | 23 | MessagingConfig details/secrets (5 source-candidate, 18 none) |
| pass3-S5 | 26 | DB-protocol connector secrets (all none) |
| pass3-K1 | 17 | CLI-side requests calls, operator-configured URL (all none) |
| pass3-K2 | 23 | server-side HTTP transport sinks (all sink/tp) |
| pass3-K3 | 7 | constructor surrogate + host-pinned sinks (all sink/candidate) |
| pass3-K4 | 3 | fixed-literal-URL / SDK-internal fetches (all none) |
