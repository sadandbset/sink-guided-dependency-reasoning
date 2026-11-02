# Pass 3 (CWE-918 SSRF) label statistics - dtale (D-Tale)

- generated: 2026-10-20T00:00:00  
- model: glm-5.3 (in-session LLM labeling by the analysis agent)  
- labeling mode: 9 semantic batches over family groups; location-sensitive rows (the /web-upload entry point, /datasets dispatch, docs demo apps, kill/is_up/reaper internal fetches) reviewed line-by-line against the dtale_vuln tree  
- candidate rows: 241 total = sources.csv 198 + sinks.csv 43  
- raw verdicts (labels_raw_pass3.json): 241 rows (every CSV row covered, incl. api/ast double matches)  
- deduplicated entries (labels.json pass 3): 233 (232 CSV-derived + 1 supplemental is_url entry)  
- duplicate rows collapsed during dedup: 9 (same requests.get node matched by both 'api' and 'ast' extraction)  

## Label distribution (labels.json entries)

| role | classification | count |
| --- | --- | --- |
| none | fp | 217 |
| summary | candidate | 8 |
| source | candidate | 4 |
| source | tp | 2 |
| sink | candidate | 1 |
| sink | tp | 1 |
| **total** | | **233** |

## By role

- source: 6
- sink: 2
- sanitizer: 0
- summary: 8
- none: 217

## Confidence buckets (entries)

- high(>=0.75): 45
- mid(0.55-0.74): 188
- low(<0.55): 0

## Raw-row distribution (per CSV row, before dedup)

- source: 6
- sink: 4
- sanitizer: 0
- summary: 8
- none: 223

## Rows per batch

- batch-01-http_query_arg: 137
- batch-02-request-dict-json: 12
- batch-03-request-form-files: 12
- batch-04-cli_arg: 26
- batch-05-env-config: 11
- batch-06-sink-requests-get: 18
- batch-07-sink-funnel-wrappers: 13
- batch-08-sink-url-parse: 12
- batch-09-supplemental: 1 (off-CSV review decision: is_url rejected as sanitizer)

## Highlights

- Confirmed sink/tp: requests.get at dtale/cli/clickutils.py:244 inside handle_path - the shared remote-fetch funnel, URL at positional argument 0, reachable from the UNAUTHENTICATED /web-upload route via url+proxy query parameters (views.py:3921/:3930-3931 -> csv/json/excel loaders -> handle_path). Only guard is the is_url() http(s) prefix check: scheme restricted, host/port/path fully attacker-controlled.
- Confirmed sources/tp: get_str_arg(request, 'url') views.py:3930 and get_str_arg(request, 'proxy') views.py:3931 (proxy additionally controls the requests proxies mapping, clickutils.py:240-243).
- Candidate sources: the CLI loader option constructors (loaders/__init__.py:137/:149/:157 setup_loader_options, clickutils.py:91 legacy loader_options) - real CLI-boundary -> requests.get propagation, local-operator attacker model.
- Candidate sink: requests.get at datasets.py:40 (load_zip) - genuine URL position, but all in-tree callers pass hardcoded GitHub literals; /datasets dispatches fixed function names only.
- Summary steps: handle_path funnel (function + 3 loader call sites) and the csv/json/excel loader wrappers - the propagation chain from /web-upload into the funnel.
- Sanitizers: NONE labeled. is_url (scheme-prefix gate) reviewed and REJECTED as an SSRF sanitizer (no host/port/IP/redirect restriction); auth.requires_auth is access control, off by default (global_state.py:38), not a data sanitizer; documented in phase1_review.md.
- Dominant FP classes: chart/grid/dataframe query parameters with no network path (~130 rows), internal lifecycle fetches (kill/is_up/reaper on operator-configured instance URLs), docs/ demonstration scripts with fixed baseball-reference host, env/config deployment reads, CLI bootstrap options.
