# Phase 1 Step 3 - Human Review Payload (Pass 3 / CWE-918)

- run_id: `calibre-web-iris-pass3-step3-20261019`
- generated_at: 2026-10-19T18:16:00Z (UTC)
- model: glm-5.3 (Z.ai GLM), labeled in-session via Claude Code CLI; single-pass batches; temperature unset (harness default). Deviations from the WORKFLOW.md 4.4.3/7.3 prompt contract (session model labeled directly instead of separate strict-JSON completions) are recorded in `labels_raw_pass3.json` → `deviations`.
- scope: Pass 3 only (CWE-918/099/610, CWE-918 primary). Pass 1 exists in `labels.json` as an empty placeholder required by the schema.
- ground-truth isolation: no PyVul vulnerability truth files in the source tree (`ssrf_sinks.csv`, `ssrf_sinks.json`, `ssrf_vulnerability_report.md`) were consulted. All rationale is derived from the calibre-web sources themselves; every non-trivial candidate was verified against the real code.

## 1. Label counts by pass and role

| pass | entries | source | sink | sanitizer | summary | none |
| --- | --- | --- | --- | --- | --- | --- |
| 1 (placeholder, out of scope) | 0 | - | - | - | - | - |
| 3 (SSRF) | 199 | 11 | 13 | 0 | 4 | 171 |

Classification: 10 tp, 18 candidate, 171 fp, 0 unknown.

All 181 `sources.csv` rows and 18 `sinks.csv` rows produced exactly one entry (199/199 row parity across 9 batches; two exact duplicate CSV rows for `cps/cli.py:77` retained with identical labels).

**Reading of the counts**: `tp`/`candidate` never asserts a confirmed vulnerability — `tp` only means the API genuinely plays its labeled role for pass 3 (a real request-boundary source or a real URL-argument sink fed by request data). No end-to-end SSRF verdict is claimed at this stage.

## 2. Top high-risk sink APIs

| id | signature | class | conf | why it matters |
| --- | --- | --- | --- | --- |
| snk-007 | `requests.get` arg 0 @ `cps/helper.py:740` | tp | 0.85 | The concrete outbound fetch inside `save_cover_from_url(url, book_path)`; `url` is the POST-form `cover_url` value supplied by the caller. The only guard (cps/helper.py:734-739) is conditional on `cli.allow_localhost`, checks only the first `getaddrinfo` result, and does not disable redirect following — a public URL that 302-redirects to an internal address, or DNS rebinding, bypasses it. |
| snk-004 | `helper.save_cover_from_url` arg 0 @ `cps/editbooks.py:808` | tp | 0.85 | Wrapper call passing `to_save["cover_url"]` verbatim; reachable on POST `/admin/book/<id>` by any authenticated user with edit + upload role (route `@login_required_if_no_ano` + `@edit_required`, plus `current_user.role_upload()` at line 802). |
| snk-008 | `requests.request` arg 1 (url=) @ `cps/kobo.py:96` | candidate | 0.60 | Kobo store proxy: URL host pinned to `KOBO_STOREAPI_URL` (kobo.py:55), path suffix derived from `request.full_path`; forwards ALL inbound headers (minus Host) and the raw body; `allow_redirects=False`. Partial CWE-918 shape (path control + verbatim header forwarding on a fixed host). Enabled only when the admin sets `config.config_kobo_proxy`; note that several funneling routes (e.g. `/v1/products/*` at kobo.py:1014) carry no `@requires_kobo_auth`. |
| snk-009/010/011 | `make_request_to_kobo_store` @ kobo.py:114/330/1059 | candidate | 0.50-0.55 | Wrapper invocations of the same proxy (non-GET misc requests, sync merge, init); network I/O happens at kobo.py:94 inside the wrapper. |
| snk-013 | `requests.get` arg 0 @ `cps/metadata_provider/lubimyczytac.py:203` | candidate | 0.60 | Second-order SSRF shape: fetches `match.url` = `BASE_URL + book_url` where `book_url` is an `@href` scraped from the earlier lubimyczytac search response. Host pinned by concatenation; path steerable only by a malicious/compromised remote. |
| snk-001/002/003/005/006/012 | provider fetches (amazon/comicvine/google/gdrive/lubimyczytac) | candidate | 0.50-0.60 | Fixed-host search fetches with request-derived query text (quote-encoded everywhere except amazon.py:110's raw query-param embedding); gdriveutils fetches a Drive-API-provided `downloadUrl` for the admin-configured account. Kept for recall; contextual triage should treat host-pinned fetches as likely FP. |

End-to-end flows the labels encode:

1. **cover-url flow (primary)**: `request.form.to_dict()` (editbooks.py:778) → `to_save["cover_url"]` (801/805/808, src-063..066) → **`helper.save_cover_from_url`** (snk-004) → **`requests.get`** (snk-007, helper.py:740).
2. **kobo proxy flow**: `request.full_path` (kobo.py:69, src-087) → `get_store_url_for_current_request()` return (96/110, summary steps) → **`requests.request`** (snk-008) via `make_request_to_kobo_store` (snk-009/010/011); headers/body forwarded from src-088/src-090.
3. **metadata-search flow**: `request.get_json`/`request.form.to_dict` (search_metadata.py:92/119, src-139/141/142) → `provider.search()` dispatch (summary steps 140/143) → provider `requests.get`/`Session.get` sinks (snk-001..003/006/012/013).
4. **second-order flow**: lubimyczytac search response → `MetaRecord.url` (src-102) → `requests.get(match.url)` (snk-013).

Rejected sink candidates (role=none, 5 entries): `scholarly.search_pubs` (arg 0 is a quote-encoded search phrase, not a URL; requests happen inside the scholarly library to library-chosen endpoints) and the four `cps/updater.py` fetches (constant `_REPOSITORY_API_URL` or GitHub-API-echoed `zipball_url`/`parent_commit['url']`; operator-triggered background thread; no web-user influence on the target).

## 3. Top broad source APIs

| id | signature | class | conf | note |
| --- | --- | --- | --- | --- |
| src-064/065/066 | `cover_url` @ editbooks.py:801/805/808 | tp | 0.85 | The attacker-supplied cover URL materialized from the form dict — root of the primary SSRF-shaped flow. |
| src-063 | `request.form.to_dict` @ editbooks.py:778 | tp | 0.80 | Form boundary of edit_book containing `cover_url`. |
| src-087 | `request.full_path` @ kobo.py:69 | tp | 0.80 | Raw request path of `/kobo/<auth_token>/...`, partitioned and concatenated onto the store URL. |
| src-141/142 | `request.form.to_dict(.get)` @ search_metadata.py:119 | tp | 0.75-0.80 | `/metadata/search` 'query' boundary (any authenticated user). |
| src-139 | `request.get_json` @ search_metadata.py:92 | tp | 0.75 | `/metadata/provider` JSON body whose `query` field is dispatched to provider.search. |
| src-088/090 | `request.headers`/`request.get_data` @ kobo.py:89/98 | candidate | 0.55 | Forwarded verbatim into the outbound store request (headers/body positions, not the URL). |
| src-102 | `MetaRecord.url` @ lubimyczytac.py:203 | candidate | 0.55 | Second-order network-derived URL re-fetched at the same line. |

Rejected source families (role=none, 171 entries), each with a per-row auditable rationale:

- operator environment variables (FLASK_DEBUG, SECRET_KEY, CALIBRE_DBPATH/PORT/UNIX_SOCKET) and all 19 `cps/cli.py` argparse flags (including `-l/--allow-localhost`, which toggles the helper.py guard — sanitizer-relevant, not a tainted source);
- all 33 `cps/admin.py` request inputs — `@admin_required` configuration surface (config/user/mail/domain forms, user-table listing params, pathchooser filesystem browse) with verified absence of any path into the 18 extracted outbound-fetch URLs;
- all 29 `cps/opds.py` and 31 `cps/web.py` request inputs — pagination/sort/search parameters, auth and profile forms, log-only headers; all consumed by local DB queries or templates;
- book-upload file objects (editbooks.py), book merge/convert JSON bodies, Kobo device sync payloads (request.json), shelf management forms, gdrive OAuth/webhook payloads, remotelogin tokens, usermanagement auth headers, jinjia pagination args;
- open-redirect family (redirect.py:43/51, web.py:1606 `next`) — CWE-601 territory guarded by `is_safe_url` same-origin check, explicitly kept out of CWE-918;
- oauth_bb referrer (dead `if ... != ...: pass` comparison).

## 4. Sanitizer list

None labeled — the extraction CSVs contained no sanitizer-shaped candidates. Advisory for Phase 2 (recorded in `labels_raw_pass3.json` deviations and `label_stats.md`):

- `cps/helper.py:734-739`: partial localhost guard — conditional (`cli.allow_localhost`), first-`getaddrinfo`-result only, redirects not covered. NOT sufficient as a CWE-918 barrier.
- `cps/redirect.py:36-39`: `is_safe_url()` same-origin check — genuine, but for CWE-601 (open redirect), not CWE-918.
- provider-side `quote()` token encoding on fixed-host base URLs — prevents scheme/host breakout in the metadata-search flow.

## 5. Unresolved / low-confidence items (confidence <= 0.55)

Strictly below the 0.55 WORKFLOW threshold: `snk-005` (0.50) and `snk-010` (0.50). Boundary entries at 0.55:

| id | signature | role | conf | concern |
| --- | --- | --- | --- | --- |
| snk-005 | `Get_Http_Object.request` @ gdriveutils.py:626 | sink | 0.50 | `downloadUrl` comes from Drive API metadata for the admin-configured account (second-order, no web input); reviewer should decide whether to keep it in `MySinks.qll` for recall. |
| snk-010 | `make_request_to_kobo_store` @ kobo.py:330 | sink | 0.50 | Sync-time store merge; requires kobo auth + `config_kobo_proxy`; host pinned. |
| snk-009/011 | `make_request_to_kobo_store` @ kobo.py:114/1059 | sink | 0.55 | Wrapper-invocation sinks; network I/O is at kobo.py:94. |
| snk-001/002 | `requests.Session.get` @ amazon.py:53/110 | sink | 0.55 | Host pinned; 53 uses an unencoded response-derived href, 110 embeds the raw query into the query string. |
| src-088 | `request.headers` @ kobo.py:89 | source | 0.55 | Verbatim header forwarding into the outbound request (header-injection shape rather than URL control). |
| src-090 | `request.get_data` @ kobo.py:98 | source | 0.55 | Outbound body forwarding only. |
| src-102 | `MetaRecord.url` @ lubimyczytac.py:203 | source | 0.55 | Second-order response-derived URL. |

## 6. Review decision guidance

Per WORKFLOW.md 4.5 this is the advisory checkpoint before Phase 2 (Step 4 library generation). Recommended reviewer actions:

1. Confirm the sink set (section 2): in particular whether the host-pinned candidate sinks (kobo proxy, metadata providers, gdrive) should carry into `MySinks.qll` for recall, and whether the low-confidence `snk-005`/`snk-010` should be dropped.
2. Confirm the `summary` labeling of `get_store_url_for_current_request` (kobo.py:96/110) and the `provider.search` dispatch sites (search_metadata.py:109/128) as additional taint steps — these are what make the kobo-proxy and metadata-search paths reachable by taint tracking.
3. Decide whether the 0.55-boundary sources (kobo header/body forwarding, second-order `MetaRecord.url`) should be kept for conservative recall or dropped to reduce alert volume.
4. Note that no sanitizer library content will be generated (`MySanitizers.qll` falls back to `none()`), and `isBarrier` must still be emitted per WORKFLOW.md 3.6. The helper.py localhost guard is partial and should NOT be treated as a barrier without a reviewer decision.
5. Decide the treatment of `file:`/`data:`/cross-protocol concerns: none were observed in this source tree (no code path constructs such URLs for network loading); urllib.request.urlopen/urlretrieve/httpx are not used anywhere in `cps/`.

Status: **awaiting human review** — this run stops after Step 3 as instructed; Phase 2 was not started.
