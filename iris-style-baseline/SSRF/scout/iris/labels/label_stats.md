# Scout — Pass 3 (SSRF) Label Statistics

- **Run**: `scout-iris-pass3-step3-20261020` (Augur Phase 1, Step 3 — LLM API Candidate Labeling)
- **Generated**: 2026-10-20
- **Project**: scout (Clinical-Genomics/scout snapshot; CodeQL DB sha `51a838dd1df58dbb965cd39f6f146a5243ba207a`)
- **Language / framework**: Python / Flask (+ requests, urllib.request as outbound HTTP clients)
- **CWE scope**: Pass 3 only — CWE-918 (primary), CWE-099, CWE-610
- **LLM model**: glm-5.3 (Z.ai GLM), labeled in-session via Claude Code CLI; single labeling pass, temperature unset (harness default)

## Candidate coverage

| Input | Rows | Labeled | Deduplicated / excluded |
| --- | --- | --- | --- |
| `extraction/sources.csv` | 29 | 29 | 0 (all locations unique) |
| `extraction/sinks.csv` | 44 | 44 | 0 (all locations unique) |
| **Total** | **73** | **73** | **0** |

Batching: 4 batches — S1 (source rows 1–15), S2 (source rows 16–29), K1 (sink rows 1–22), K2 (sink rows 23–44). No entry fell below the 0.55 re-ask threshold, so no re-ask round was run.

## Label distribution (73 entries)

| role | count | of which tp | candidate | unknown | fp |
| --- | --- | --- | --- | --- | --- |
| source | 3 | 2 | 1 | 0 | 0 |
| sink | 21 | 2 | 18 | 1 | 0 |
| sanitizer | 0 | 0 | 0 | 0 | 0 |
| summary | 0 | 0 | 0 | 0 | 0 |
| none | 49 | 0 | 0 | 0 | 49 |
| **total** | **73** | **4** | **19** | **1** | **49** |

Combined role/classification: `source/tp` 2, `source/candidate` 1, `sink/tp` 2, `sink/candidate` 18, `sink/unknown` 1, `none/fp` 49.

Confidence range: 0.45–0.95 (mean ≈ 0.78).

## Confirmed labels (role genuinely played — NOT vulnerability verdicts)

### Sources (3)

| id | location | callable | kind | conf. | note |
| --- | --- | --- | --- | --- | --- |
| src-025 | `scout/server/blueprints/alignviewers/views.py:34` | `remote_cors.remote_url` (param 0) | source/tp | 0.95 | `<path:remote_url>` route variable → `requests.request(url=remote_url)` verbatim; any authenticated user; no scheme/host validation, `allow_redirects=True` |
| src-020 | `scout/server/blueprints/cases/views.py:225` | `request.url_root` | source/tp | 0.80 | Host-header-derived base URL → `requests.post(base_url + "reports/report")` (controllers.py:94); authenticated user with case access; requires chanjo integration enabled |
| src-004 | `scout/server/blueprints/cases/controllers.py:544` | `flask.url_for` (`_external=True`) | source/candidate | 0.60 | Host/SERVER_NAME-derived absolute URL → `requests.post` (548/554); candidate pending SERVER_NAME deployment check |

### Sinks (21)

| id | location | callable | kind | conf. | note |
| --- | --- | --- | --- | --- | --- |
| snk-044 | `scout/server/blueprints/alignviewers/views.py:42` | `requests.request` (url = arg 1) | sink/tp | 0.95 | remote CORS proxy transport; full attacker-chosen target; forwards headers/body/cookies |
| snk-004 | `scout/server/blueprints/cases/controllers.py:94` | `requests.post` (arg 0) | sink/tp | 0.85 | chanjo coverage report POST to `request.url_root`-derived host |
| snk-005/006 | `cases/controllers.py:548/554` | `requests.post` (arg 0) | sink/candidate | 0.60 | `url_for(_external=True)`-derived chanjo MT-stats POST |
| snk-025–032 | `scout/utils/scout_requests.py:34/36/59/61/85/87/89/110` | `requests.post/get/delete` (arg 0) | sink/candidate | 0.55 | final I/O of the shared HTTP wrappers; all audited callers pass admin-config/constant URLs — recall only |
| snk-014 | `scout/utils/ensembl_rest_clients.py:81` | `requests.get` (arg 0) | sink/candidate | 0.55 | constant Ensembl host; path = genomic coords (DB) via web-reachable liftover |
| snk-018 | `scout/server/extensions/loqus_extension.py:242` | `api_get` (arg 0) | sink/candidate | 0.50 | admin LoqusDB host + DB variant coords in path/query (web-reachable variant pages) |
| snk-024 | `scout/adapter/mongo/rank_model.py:23` | `requests.get` (arg 0) | sink/candidate | 0.50 | config-pinned github raw host + case version path segment (web-reachable) |
| snk-042 | `scout/utils/scout_requests.py:438` | `get_request` (arg 0) | sink/candidate | 0.50 | constant eutils.ncbi host + refseq id query (web-reachable via variant controllers:659) |
| snk-013 / 010 / 011 | `cases/controllers.py:1257/1163/1206` | `MatchMaker.match_external / patient_delete / patient_matches` | sink/candidate | 0.50/0.45 | admin MME_URL host + server-issued patient/node ids in path |
| snk-033 | `scout/utils/scout_requests.py:141` | `urllib.request.urlopen` (arg 0) | sink/candidate | 0.45 | ftp branch of fetch_resource; constant ftp URLs only; no file:/data: fetch exists in scout |
| snk-007 | `cases/controllers.py:837` | `query_phenomizer.query` | sink/unknown | 0.50 | network I/O inside external package (not in DB); URL position unverifiable — human review |

### Sanitizers

None labeled. No scheme allowlist, host whitelist, redirect control, DNS-resolution check or private-IP blocking exists on any outbound path in scout. The only scheme check (`url.startswith("ftp")` in `fetch_resource`) is a transport dispatch, not a barrier. Login (`before_request check_user`), `institute_and_case` ownership and the `beacon_submitter` role check gate *who* can trigger requests but never constrain the outbound URL, so none qualifies as a CWE-918 sanitizer.

### Summaries

None needed: both confirmed flows propagate via direct parameter passing and standard interprocedural taint steps (route param → `url` keyword; `request.url_root` → function parameter → string concatenation → `requests.post` arg 0).

## Excluded candidates (role `none`, 49 entries — summary of reasons)

- **Admin-config URL provenance (16)**: `Beacon.beacon_url` (3), `MatchMaker.host` (6), `loqus_settings.get_api_url` (7) — BEACON_URL / MME_URL / LOQUSDB_SETTINGS deployment configuration; fixed per deployment, never request-derived.
- **Body-only request data (3)**: `request.form` at views.py:93 (Beacon add — form → JSON POST body on fixed admin URL), sink rows for the same flow (beacon:131/180, views:93 add_variants, controllers:894 Rerunner, controllers:1124/1241 MatchMaker body-only wrappers).
- **DB-only request.form reads (4)**: views.py:469/472/631/796 — event/comment/causative/share handlers writing to MongoDB, no outbound request.
- **Forwarded-but-not-URL request data (3)**: `request.headers`/`request.get_data`/`request.cookies` in remote_cors — land in outbound header/body/cookie positions, not the URL (impact amplifiers of src-025, documented in rationales).
- **Non-SSRF node (1)**: `request.headers` at alignviewers:77 — Range header for local partial file streaming.
- **Constrained route param (1)**: `matchmaker_match.target` — validated against connected MME node ids; host pinned.
- **Constant/CLI-URL fetch sites (12)**: panel.py PanelApp, scout_requests HPO/OMIM/HGNC/ExAC fetchers, fetch_resource internal delegation, ensembl biomart (CLI-only), loqus constant-path calls, matchmaker internal dispatch.

## Notes

- `labels.json` also contains an empty Pass 1 placeholder block required by the schema's `contains pass_id: 1` constraint (same convention as the earlier SSRF runs).
- Schema normalizations (CSV argIndex −1 → positional URL index etc.) are recorded in `labels_raw_pass3.json` → `deviations`.
- Labeling used only the scout source tree, the extraction CSVs and `exploration/detection.json`; no ground truth, fix commits or CVE descriptions were consulted.
