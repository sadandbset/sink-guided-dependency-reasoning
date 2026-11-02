# Phase 1 Step 3 - Label Statistics (Pass 3 / CWE-918)

- run_id: `calibre-web-iris-pass3-step3-20261019`
- generated_at: 2026-10-19T18:16:00Z (UTC, script run timestamp)
- model: glm-5.3 (Z.ai GLM), in-session labeling via Claude Code CLI; single-pass batches; temperature unset (harness default)
- scope: Pass 3 only (CWE-918/099/610; CWE-918 primary); Pass 1 is an empty placeholder in labels.json (schema `contains pass_id 1` constraint)
- ground truth isolation: `ssrf_sinks.csv`, `ssrf_sinks.json`, `ssrf_vulnerability_report.md` in the source root were NOT read; every rationale is derived from the calibre-web sources themselves

## Candidate accounting

| input | rows | entries emitted |
| --- | --- | --- |
| extraction/sources.csv | 181 | 181 |
| extraction/sinks.csv | 18 | 18 |
| **total** | **199** | **199** |

Every CSV row produced exactly one label entry; entries with `role=none` carry an auditable exclusion rationale. Two pairs of exact duplicate CSV rows (sources.csv rows 45/47 `args.k` and 46/48 `args.c`, both `cps/cli.py:77`) were retained as separate entries with identical labels for row parity; the duplication is recorded in `labels_raw_pass3.json` → `deviations`.

## Batch integrity

| batch | csv rows | entries |
| --- | --- | --- |
| pass3-S1 (env + cli) | 28 | 28 |
| pass3-S2 (admin.py) | 33 | 33 |
| pass3-S3 (editbooks.py) | 20 | 20 |
| pass3-S4 (kobo.py) | 13 | 13 |
| pass3-S5 (metadata-search boundary) | 6 | 6 |
| pass3-S6 (opds.py) | 29 | 29 |
| pass3-S7 (web.py) | 31 | 31 |
| pass3-S8 (misc modules) | 21 | 21 |
| pass3-K1 (sinks.csv) | 18 | 18 |

Row/entry parity across all batches: OK (199/199)

## Role counts (pass 3)

| role | count |
| --- | --- |
| source | 11 |
| sink | 13 |
| sanitizer | 0 |
| summary | 4 |
| none | 171 |

## Classification counts (pass 3)

| classification | count |
| --- | --- |
| tp | 10 |
| candidate | 18 |
| fp | 171 |
| unknown | 0 |

`tp` means the labeled role is genuinely played by the API for this pass (e.g. `requests.get` at `cps/helper.py:740` really fetches the attacker-supplied `cover_url` form value). It does **not** mean a confirmed exploitable vulnerability.

## Role x classification

| role | tp | candidate | fp | unknown |
| --- | --- | --- | --- | --- |
| source | 8 | 3 | 0 | 0 |
| sink | 2 | 11 | 0 | 0 |
| sanitizer | 0 | 0 | 0 | 0 |
| summary | 0 | 4 | 0 | 0 |
| none | 0 | 0 | 171 | 0 |

## Confidence distribution

| band | count |
| --- | --- |
| >=0.8 | 121 |
| 0.7-0.79 | 62 |
| 0.6-0.69 | 7 |
| 0.5-0.59 | 9 |
| <0.5 | 0 |

## Entries per module and role

| file | source | sink | summary | none |
| --- | --- | --- | --- | --- |
| cps/__init__.py | 0 | 0 | 0 | 2 |
| cps/admin.py | 0 | 0 | 0 | 33 |
| cps/cli.py | 0 | 0 | 0 | 19 |
| cps/config_sql.py | 0 | 0 | 0 | 1 |
| cps/constants.py | 0 | 0 | 0 | 3 |
| cps/editbooks.py | 4 | 1 | 0 | 16 |
| cps/gdrive.py | 0 | 0 | 0 | 7 |
| cps/gdriveutils.py | 0 | 1 | 0 | 0 |
| cps/helper.py | 0 | 1 | 0 | 0 |
| cps/jinjia.py | 0 | 0 | 0 | 1 |
| cps/kobo.py | 3 | 4 | 2 | 8 |
| cps/logger.py | 0 | 0 | 0 | 2 |
| cps/metadata_provider/amazon.py | 0 | 2 | 0 | 0 |
| cps/metadata_provider/comicvine.py | 0 | 1 | 0 | 0 |
| cps/metadata_provider/google.py | 0 | 1 | 0 | 0 |
| cps/metadata_provider/lubimyczytac.py | 1 | 2 | 0 | 0 |
| cps/metadata_provider/scholar.py | 0 | 0 | 0 | 1 |
| cps/oauth_bb.py | 0 | 0 | 0 | 2 |
| cps/opds.py | 0 | 0 | 0 | 29 |
| cps/redirect.py | 0 | 0 | 0 | 3 |
| cps/remotelogin.py | 0 | 0 | 0 | 2 |
| cps/search_metadata.py | 3 | 0 | 2 | 0 |
| cps/server.py | 0 | 0 | 0 | 1 |
| cps/shelf.py | 0 | 0 | 0 | 4 |
| cps/updater.py | 0 | 0 | 0 | 4 |
| cps/usermanagement.py | 0 | 0 | 0 | 2 |
| cps/web.py | 0 | 0 | 0 | 31 |

## Sink entries (all 18 CSV sink candidates)

| id | signature | role/class | conf | location |
| --- | --- | --- | --- | --- |
| snk-004 | `helper.save_cover_from_url` (arg 0, argument) | sink/tp | 0.85 | cps/editbooks.py:808 |
| snk-007 | `requests.get` (arg 0, argument) | sink/tp | 0.85 | cps/helper.py:740 |
| snk-003 | `requests.get` (arg 0, argument) | sink/candidate | 0.60 | cps/metadata_provider/comicvine.py:49 |
| snk-006 | `requests.get` (arg 0, argument) | sink/candidate | 0.60 | cps/metadata_provider/google.py:48 |
| snk-008 | `requests.request` (arg 1, argument) | sink/candidate | 0.60 | cps/kobo.py:96 |
| snk-012 | `requests.get` (arg 0, argument) | sink/candidate | 0.60 | cps/metadata_provider/lubimyczytac.py:115 |
| snk-013 | `requests.get` (arg 0, argument) | sink/candidate | 0.60 | cps/metadata_provider/lubimyczytac.py:203 |
| snk-001 | `requests.Session.get` (arg 0, argument) | sink/candidate | 0.55 | cps/metadata_provider/amazon.py:53 |
| snk-002 | `requests.Session.get` (arg 0, argument) | sink/candidate | 0.55 | cps/metadata_provider/amazon.py:110 |
| snk-009 | `make_request_to_kobo_store` (unknown flow) | sink/candidate | 0.55 | cps/kobo.py:114 |
| snk-011 | `make_request_to_kobo_store` (unknown flow) | sink/candidate | 0.55 | cps/kobo.py:1059 |
| snk-005 | `Get_Http_Object.request` (arg 0, argument) | sink/candidate | 0.50 | cps/gdriveutils.py:626 |
| snk-010 | `make_request_to_kobo_store` (unknown flow) | sink/candidate | 0.50 | cps/kobo.py:330 |
| snk-014 | `scholarly.search_pubs` (arg 0) | none/fp | 0.60 | cps/metadata_provider/scholar.py:47 |
| snk-015 | `requests.get` (arg 0) | none/fp | 0.75 | cps/updater.py:76 |
| snk-016 | `requests.get` (arg 0) | none/fp | 0.70 | cps/updater.py:352 |
| snk-017 | `requests.get` (arg 0) | none/fp | 0.75 | cps/updater.py:378 |
| snk-018 | `requests.get` (arg 0) | none/fp | 0.80 | cps/updater.py:613 |

## Source entries with classification=tp

- `src-063` `request.form.to_dict` (cps/editbooks.py:778), conf 0.80 - form dict containing `cover_url`
- `src-064` `cover_url` (cps/editbooks.py:801), conf 0.85
- `src-065` `cover_url` (cps/editbooks.py:805), conf 0.85
- `src-066` `cover_url` (cps/editbooks.py:808), conf 0.85
- `src-087` `request.full_path` (cps/kobo.py:69), conf 0.80 - Kobo proxy path suffix
- `src-139` `request.get_json` (cps/search_metadata.py:92), conf 0.75
- `src-141` `request.form.to_dict().get` (cps/search_metadata.py:119), conf 0.80
- `src-142` `request.form.to_dict` (cps/search_metadata.py:119), conf 0.75

## Low-confidence entries (<0.55): 2

- `snk-005` `Get_Http_Object.request` (cps/gdriveutils.py:626), role sink, conf 0.50
- `snk-010` `make_request_to_kobo_store` (cps/kobo.py:330), role sink, conf 0.50

At the 0.55 boundary (listed for reviewer attention): `src-088` (request.headers → outbound headers), `src-090` (request.get_data → outbound body), `src-102` (MetaRecord.url second-order), `snk-001`, `snk-002`, `snk-009`, `snk-011`.

## Sanitizers

No sanitizer entries were labeled: neither extraction CSV contained a sanitizer-shaped candidate. Advisory for Phase 2 (NOT labels, recorded here and in `labels_raw_pass3.json` deviations):

- `cps/helper.py:734-739` - partial localhost guard in `save_cover_from_url`: skipped entirely when `cli.allow_localhost` is set (`cps/cli.py:88`), inspects only the FIRST `socket.getaddrinfo` result (DNS rebinding bypass), and `requests.get` still follows redirects by default (`allow_redirects` not disabled), so a public URL redirecting to an internal target bypasses it. Insufficient as a CWE-918 barrier.
- `cps/redirect.py:36-39` - `is_safe_url()` same-origin check (scheme http/https + netloc equality against `request.host_url`) - a genuine sanitizer, but for open redirect (CWE-601/Pass 9), not for CWE-918 fetch targets.
- Metadata providers apply `urllib.parse.quote()` to search tokens (google.py:46, comicvine.py:47, lubimyczytac.py:144, scholar.py:45) and concatenate onto fixed-host base URLs - encoding prevents scheme/host breakout; amazon.py:110-113 embeds the query unencoded but after the fixed `https://www.amazon.com/s?k=` prefix (query-parameter injection only).

## Quality checks (WORKFLOW.md 4.4.6)

1. Schema validation: PASS - all 199 entries validated against `assets/labels_schema.json` with jsonschema Draft 2020-12 + FormatChecker (enums, required keys, arg_index/flow_kind coupling, confidence range, CWE patterns, pass-1 containment, no additional properties, id uniqueness).
2. Every enabled pass has at least one sink: PASS for pass 3 (13 sink entries); pass 1 is an out-of-scope placeholder with empty entries.
3. Duplicates: two exact duplicate CSV row pairs (cli.py:77) retained with identical labels and recorded in deviations; entry ids are unique.
4. Argument index bounds: all `flow_kind=argument` entries carry integer `arg_index >= 0` (0 or 1). Normalizations recorded: kobo.py:96 `requests.request` url= keyword (CSV arg_index -1) → arg_index 1; `make_request_to_kobo_store` flow_kind 'call' → 'unknown' (schema enum).
