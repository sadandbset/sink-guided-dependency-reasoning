# Pass 3 (CWE-918 SSRF) label statistics - core (Home Assistant)

- generated: 2026-10-19T00:00:00  
- model: glm-5.3 (in-session LLM labeling by the analysis agent)  
- labeling mode: 16 semantic batches over family groups + per-row source review of location-sensitive families
- candidate rows: 4778 total = sources.csv 3010 + sinks.csv 1768
- raw verdicts (labels_raw_pass3.json): 4778 rows (every CSV row covered, incl. api/ast duplicates)
- deduplicated entries (labels.json pass 3): 3998 (+9 supplemental sanitizer entries included in the count)
- duplicate rows collapsed during dedup: 789 (same node matched by both 'api' and 'ast' extraction, or repeated family matches)

## Label distribution (labels.json entries)

| role | classification | count |
| --- | --- | --- |
| none | fp | 2346 |
| sanitizer | tp | 9 |
| sink | candidate | 7 |
| sink | tp | 13 |
| source | tp | 1468 |
| summary | candidate | 155 |
| **total** | | 3998 |

## By role

- none: 2346
- source: 1468
- summary: 155
- sink: 20
- sanitizer: 9

## Confidence buckets (entries)

- high(>=0.75): 2335
- mid(0.55-0.74): 1660
- low(<0.55): 3

## Raw-row distribution (per CSV row, before dedup)

- none: 3054
- source: 1510
- summary: 186
- sink: 28

## Rows per batch

- batch-01-config_flow: 1320
- batch-02-service_data: 742
- batch-03-websocket_msg: 316
- batch-04-http_param: 154
- batch-05-request_attr: 144
- batch-06-mqtt_payload: 113
- batch-07-template_render: 90
- batch-08-webhook: 46
- batch-09-json_post: 45
- batch-10-env-configfile: 40
- batch-11-client-getter: 1252
- batch-12-requests-arg: 184
- batch-13-session_arg: 77
- batch-14-urlbuild-getattr: 99
- batch-15-wrappers: 156

## Highlights

- Confirmed sink/tp (attacker-influenced URL position): downloader service URL (downloader/__init__.py:81), telegram_bot file URL, pushsafer/nfandroidtv/xmpp notify attachment URLs, signal_messenger attachments (allow-listed), blueprint importer fetches (host allow-listed), auth/indieauth client_id fetch (unauthenticated-origin, internal IPs explicitly allowed).
- Candidate sinks: hassio ingress fixed-host proxy (x2), mobile_app push_url, cast playlist fetch, media_player async_fetch_image, oauth2 session request wrapper, rest_command dynamic dispatch.
- Sanitizers (supplemental entries): hass.config.is_allowed_external_url (4 sites, default-deny allow-list) and blueprint importer host guards (5 sites).
- Dominant FP classes: admin-config URLs (config_flow user_input x1320 rows), fixed vendor endpoints, internal client factories (x1233 rows), developer tooling under script/.
