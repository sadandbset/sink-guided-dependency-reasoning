# Label Statistics - Pass 3 (SSRF), matrix-sydent

- Run: `sydent-ssrf-pass3-20261020`
- Model: glm-5.3 (temperature 0, JSON-only responses)
- Generated: 2026-10-20T00:00:00Z
- Candidates: 139 total = 122 sources (sources.csv rows 2-123) + 17 sinks (sinks.csv rows 2-18); all rows labeled, none dropped

## Role distribution (all candidates)

| role | count |
| --- | --- |
| source | 112 |
| sink | 16 |
| sanitizer | 0 |
| summary | 2 |
| none | 9 |

Sources: 122 rows -> source 112, none 8, summary 2, sink 0, sanitizer 0
Sinks: 17 rows -> sink 16, none 1, summary 0, sanitizer 0

## Classification distribution

| classification | count |
| --- | --- |
| tp | 102 |
| fp | 18 |
| candidate | 19 |
| unknown | 0 |

## Confidence distribution

| bucket | count |
| --- | --- |
| high(>=0.8) | 115 |
| medium(0.55-0.79) | 24 |
| low(<0.55) | 0 |

## Batches

7 batches: pass3-batch1..6 (sources, sizes 21/21/20/20/20/20), pass3-batch7 (sinks, 17). No entry was re-asked (no label below the 0.55 re-ask threshold); 19 entries carry classification candidate/unknown and are flagged for human review.

## Key SSRF-relevant chains (role=source/sink, classification=tp)

1. `/account/register` (unauthenticated, public v2): `args['matrix_server_name']` (registerservlet.py:50) -> `is_valid_hostname` (form-only) -> `matrix://%s/_matrix/federation/v1/openid/userinfo` -> `FederationHttpClient.get_json` (registerservlet.py:59, sink) -> `MatrixFederationAgent.request` (matrixfederationagent.py:176) -> SRV (srvresolver.py:125) + `.well-known` (matrixfederationagent.py:322) -> `HostnameEndpoint` (:366).
2. `/3pid/bind` (v1 default-enabled, unauthenticated): `args['mxid']` (threepidbindservlet.py:45) -> `ThreepidBinder._notify` mxid server part -> `matrix://%s/_matrix/federation/v1/3pid/onbind` -> `post_json_get_nothing` (threepid/bind.py:162, sink).
3. `/3pid/unbind` X-Matrix path (unauthenticated header): `getRawHeaders('Authorization')` (verifier.py:194) -> `origin` -> `is_valid_hostname` -> `_getKeysForServer` -> `matrix://%s/_matrix/key/v2/server/` (verifier.py:80, sink); the key fetch happens BEFORE the signature verification at verifier.py:211.

## Not sanitizers (documented, not labeled)

- `is_valid_hostname` (stringutils.py:39): hostname form + port-range check only; admits IP literals, localhost, private ranges, explicit ports. Applied at registerservlet.py:52, bind.py:146, verifier.py:208 - does not block any SSRF path.
- `is_valid_client_secret` (stringutils.py:27): alphanumeric format check on client_secret; unrelated to URL control.
- `authV2` / X-Matrix signature verification / replication mutual TLS: caller authentication, not URL neutralization (rubric: auth is not an SSRF sanitizer). Note the X-Matrix signature check runs AFTER the key-fetch request in the verifier chain.
- `next_link` `startswith('file:///')` rejection (emailservlet.py:65/:106): open-redirect guard (Pass 9); msisdnservlet.py:129 redirect has no such check.

## Exclusions / deduplication

None: every CSV row received exactly one label entry. Non-CWE-918 observations (open redirect, local template path selection via `brand`, SMTP recipient control) are recorded in rationale fields and routed to their own passes.
