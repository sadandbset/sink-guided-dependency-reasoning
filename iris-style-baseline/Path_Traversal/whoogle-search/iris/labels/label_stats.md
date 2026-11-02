# Label Statistics — Pass 1 (Path Traversal) — whoogle-search

- Run ID: `iris-whoogle-search-pass1-20261023`
- Generated: 2026-10-23
- Model: `glm-5.3` (inline session LLM, Claude Code CLI; deterministic labeling, no external endpoint)
- Project: whoogle-search 0.8.3 (Flask 2.3.2 + waitress, Python)
- Schema: validated OK against `augur-0.3.0/assets/labels_schema.json` (jsonschema 4.x)

## 1. Candidate coverage

| Input | Rows | Labeled entries | Dedup merged |
| --- | --- | --- | --- |
| `extraction/sources.csv` | 176 | 175 | 1 (exact duplicate: routes.py:318 session Subscript, both Subscript nodes of the nested `session['config']['tor']` expression) |
| `extraction/sinks.csv` | 77 | 74 | 3 (cross-CSV: `misc.py:10` `gen_file_hash` path/static_file and `bangs.py:8` `gen_bangs_json` bangs_file — the `file_api_def` rows duplicate the param rows already labeled from sources.csv) |
| **Total** | **253** | **249** | **4** |

All 253 candidate rows were processed; none were skipped silently (every row either produced an entry or has an explicit dedup-log entry in `labels_raw_pass1.json`).

## 2. Role distribution

| Role | Count | Notes |
| --- | --- | --- |
| source | 81 | 59 tp, 22 candidate |
| sink | 7 | 2 tp, 4 candidate, 1 fp |
| summary | 22 | 2 tp, 20 candidate |
| sanitizer | 0 | none exist in this codebase (see §6) |
| none | 139 | all fp (env/CLI operator input, constant-path plumbing, probes, in-memory buffers) |

## 3. Classification distribution

| Classification | Count |
| --- | --- |
| tp | 63 |
| candidate | 46 |
| fp | 140 |
| unknown | 0 |

## 4. Batches

| Batch | Scope | Candidate rows | Entries |
| --- | --- | --- | --- |
| B1 | sources.csv routes.py (request layer, session, alias, env/cli, url_decode) | 98 | 98 |
| B2 | sources.csv search.py / misc.py / request.py / filter.py | 47 | 47 |
| B3 | sources.csv config.py / results.py / version.py / app/__init__.py / bangs.py | 30 | 30 |
| B4 | sinks.csv routes.py (config/session/bangs/send_file channels) | 17 | 17 |
| B5 | sinks.csv app/__init__.py / bangs.py / config.py / misc.py / request.py / widgets.py / update-translations.py | 57 | 57 |
| **Total** | 5 batches | 249 | 249 |

## 5. Entries by file

| File | Total | source | sink | summary | none |
| --- | --- | --- | --- | --- | --- |
| app/routes.py | 115 | 61 | 4 | 7 | 43 |
| app/__init__.py | 51 | 0 | 0 | 0 | 51 |
| app/utils/misc.py | 16 | 6 | 1 | 5 | 4 |
| app/request.py | 16 | 0 | 1 | 3 | 12 |
| app/utils/search.py | 16 | 14 | 0 | 1 | 1 |
| app/models/config.py | 15 | 0 | 0 | 1 | 14 |
| app/utils/results.py | 9 | 0 | 0 | 0 | 9 |
| app/filter.py | 4 | 0 | 0 | 4 | 0 |
| app/utils/bangs.py | 2 | 0 | 1 | 1 | 0 |
| app/version.py | 2 | 0 | 0 | 0 | 2 |
| app/utils/widgets.py | 2 | 0 | 0 | 0 | 2 |
| misc/update-translations.py | 1 | 0 | 0 | 0 | 1 |

## 6. Key findings

- **Sink (tp, 0.97)**: `open()` at `app/routes.py:430` — PUT /config arbitrary-file **read**: `config_pkl = os.path.join(app.config['CONFIG_PATH'], request.args.get('name'))` then `pickle.load(open(config_pkl,'rb'))`.
- **Sink (tp, 0.97)**: `open()` at `app/routes.py:445` — POST /config arbitrary-file **write**: `pickle.dump(config_data, open(os.path.join(app.config['CONFIG_PATH'], request.args.get('name')),'wb'))`.
- **Source (tp, 0.97)**: `request.args.get('name')` at `app/routes.py:429` and `:447` — the only request input that reaches a file API; no validation of any kind between read and open.
- **Summary (tp, 0.9)**: `os.path.join` at `app/routes.py:427` and `:445` (arg index 1 = attacker-controlled component) — taint-preserving path construction feeding the two sinks.
- **Sanitizers: 0 entries.** No base-dir containment, no `..` rejection, no basename-only extraction, no `startswith`/`relative_to`/realpath-canonicalize check exists anywhere in `app/` (verified by reading the source tree). `os.path.exists` (routes.py:431), `os.path.getsize` (routes.py:100), `os.path.isfile` (request.py:48) are existence probes, not containment — the routes.py:431 row is recorded as the check-then-open (TOCTOU) companion of the read sink.
- Second-order (candidate) chains: session-file maintenance `os.listdir → os.path.join → open/pickle.load → os.remove` (routes.py:93–120) — directory-content-driven, not direct request input; `gen_file_hash`/`gen_bangs_json` parameter paths with only constant internal callers; tor-conf `open()` from env.
- Auth context: `/config` is behind `@auth_required`, but auth is **optional** — when `WHOOGLE_USER`/`WHOOGLE_PASS` are unset (the default) every request passes (routes.py:64-69), so the route is reachable unauthenticated on a default deployment; `CONFIG_DISABLE` can disable config writes.

## 7. Confidence distribution

| Bucket | Count |
| --- | --- |
| >= 0.9 | 47 |
| 0.75–0.89 | 152 |
| 0.6–0.74 | 28 |
| 0.55–0.59 | 22 (all second-order/session/alias candidates kept for recall with manual-review notes) |
| < 0.55 | 0 (no re-ask threshold triggers) |

## 8. Flow-kind mapping used

CSV flowKinds were mapped to the schema enum: request-layer attribute reads / session subscripts / CLI field reads → `field`; `.get()`/`getenv`/`unquote`/`to_dict`/`parse_args` call values → `return` (tainted return); internal helper parameters → `param` (arg_index = true position incl. `self` slot); sink call arguments → `argument` (arg_index = dangerous path argument position — 1 for the two tainted joins, 0 otherwise; the extraction CSV had argIndex uniformly 0, the label arg_index records the judged dangerous position).

## 9. Exclusions / non-counts

- `test/` and `whoogle-search-db/` were already excluded at extraction (per `exploration/detection.json`); no rows from them were labeled.
- `misc/update-translations.py:39` (dev CLI script, literal f-string path) labeled `none`/fp — not counted as traversal.
- No ground truth (PyVul truth, patch diffs, CVE reports, `path_traversal_sinks.csv`) was consulted.
