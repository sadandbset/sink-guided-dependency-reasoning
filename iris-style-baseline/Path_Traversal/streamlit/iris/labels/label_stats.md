# Pass 1 Label Statistics — Path Traversal (streamlit)

- **Run ID:** `streamlit-pathtraversal-pass1-20261023`
- **Generated:** 2026-10-23T12:28:01Z
- **Model:** glm-5.3 (assistant model, Claude Code CLI — in-session labeling, no external LLM API calls)
- **Project:** streamlit 1.11.0 (`lib/streamlit/`, CodeQL DB `streamlit-db`)
- **Framework:** Tornado (primary, confidence 1.0 — no matching `references/tornado.md` in Augur 0.3.0; shapes derived from repo evidence)
- **Pass:** 1 — Path Traversal (CWE-22, CWE-23, CWE-36, CWE-73)

## Input candidates

| Input | Rows | Labeled |
| --- | --- | --- |
| `extraction/sources.csv` | 24 | 24 (100%) |
| `extraction/sinks.csv` | 33 | 33 (100%) |
| **Total** | **57** | **57** |

## Labeling process

- **Batches:** 4 (raw per-batch decisions with the original CSV rows preserved in `labels_raw_pass1.json`)
  - Batch 1 — HTTP request-boundary source candidates (17)
  - Batch 2 — local-boundary source candidates: env vars + CLI (7)
  - Batch 3 — request/app-API-facing sink candidates (8)
  - Batch 4 — internal storage/config/watcher sink candidates (25)
- **Dedup:** no exact duplicate rows exist in either CSV (all `nodeRepr` rows differ in file:line). Signature-level near-duplicates (`open` argument 0 at 17 sites, `os.remove` argument 0 at 4 sites, `self.get_argument` at 2 sites, `os.stat` at 2 sites, `glob` receiver at 2 sites) were deliberately **retained as distinct entries** because per-site classification differs (tp / candidate / fp); Step 4 library generation must deduplicate by `(module, callable, arg_index, flow_kind)`.
- **Exclusions:** no candidate was dropped; `role=none` (16 entries) is the exclusion mechanism, each with a code-anchored rationale. Sites whose path argument is a compile-time constant (`os.devnull`, `/etc/machine-id`, `/var/lib/dbus/machine-id`) were given `role=none` because no data flow into the path is possible even in principle; sites with operator-config-derived but variable paths were kept `role=sink` with `classification=fp`.
- **Schema:** `labels.json` validates against local `augur-0.3.0/assets/labels_schema.json` (jsonschema 4.26.0, draft 2020-12). CSV `flow_kind` normalization: `arg`→`argument` (argIndex ≥ 0), keyword-controlled `arg` (argIndex −1) → `unknown`/null, call-return `field` rows (`self.get_argument`, `self._require_arg`) → `return`.

## Role distribution (57 entries)

| Role | Count | Share |
| --- | --- | --- |
| source | 11 | 19.3% |
| sink | 30 | 52.6% |
| sanitizer | 0 | 0% |
| summary | 0 | 0% |
| none | 16 | 28.1% |

## Classification distribution

| Classification | Count | Notes |
| --- | --- | --- |
| tp | 6 | 5 sources + 1 sink |
| candidate | 10 | 6 sources + 4 sinks (manual review points) |
| fp | 41 | 13 source-role `none` + 3 sink-role `none` + 25 sink sites with no untrusted path control |

## Sources (11 `role=source`)

| ID | Site | Classification | Conf | Path-relevance |
| --- | --- | --- | --- | --- |
| src-012 | `ComponentRequestHandler.get(path)` — components.py:310 | **tp** | 0.97 | `/component/(.*)` capture → `os.path.join(component_root, filename)` → `open(abspath,'rb')`; no containment — the key source |
| src-007 | `self.request.body` — upload_file_request_handler.py:115 | tp | 0.90 | multipart POST body boundary (uploads stay in memory) |
| src-009 | `self.request.headers` — upload_file_request_handler.py:114 | tp | 0.85 | Content-Type drives multipart parsing |
| src-016 | `StaticFileHandler.parse_url_path(url_path)` — routes.py:64 | tp | 0.80 | static route path; disk read + containment in tornado library (out of DB) |
| src-022 | `file['filename']` — upload_file_request_handler.py:144 | tp | 0.80 | client path-shaped upload name; in-memory, exposed to app scripts |
| src-019 | `self._require_arg(args, "sessionId")` :121 | candidate | 0.70 | session-validated; in-memory key use |
| src-020 | `self._require_arg(args, "widgetId")` :122 | candidate | 0.70 | in-memory key use |
| src-010 | `self.get_argument("title")` — routes.py:129 | candidate | 0.65 | unquote_plus + clean_filename → response header only |
| src-008 | `self.request.headers` (Accept) — stats.py:116 | candidate | 0.60 | literal comparison only |
| src-011 | `self.get_argument("hash")` — routes.py:298 | candidate | 0.60 | in-memory cache lookup key |
| src-018 | `on_message(payload)` — server.py:774 | candidate | 0.60 | BackMsg protobuf; needs Phase 2 modeling |

## Sinks (30 `role=sink`)

| ID | Site | Classification | Conf | Why |
| --- | --- | --- | --- | --- |
| sink-009 | `open(abspath, 'rb')` — components.py:325 | **tp** | 0.97 | the component-route disk read; pairs with src-012 — only complete in-DB flow |
| sink-010 | `open(image,'rb')` — elements/image.py:339 | candidate | 0.70 | st.image path; source side in app scripts (out of DB) |
| sink-015 | `open(data,'rb')` — elements/media.py:184 | candidate | 0.70 | st.audio/st.video path; same |
| sink-014 | `open(main_script_path,'wb')` — cli.py:75 | candidate | 0.60 | CLI-operator input; Windows `rsplit('/')` backslash caveat |
| sink-011 | `open(image)` — elements/image.py:415 | candidate | 0.65 | SVG read; same as sink-010 |
| 25 others | caching/credentials/secrets/config/watcher/source_util/file_util/server ops | fp | 0.80–0.95 | fixed operator paths, hashed cache keys, or mkdtemp-random dirs — no untrusted path control |

## Sanitizers

**0 entries.** No extracted candidate is a validation/neutralization function. Repo-side sanitizers observed during labeling are not CSV candidates and are recorded in `phase1_review.md` (clean_filename, `_is_valid_session_id`, tornado library-side `validate_absolute_path`, page-name allowlist).

## Quality checks (WORKFLOW 4.4.6)

1. Schema validation: **PASS** (jsonschema draft 2020-12, `assets/labels_schema.json`).
2. Pass 1 has ≥ 1 sink: **yes** — 30 sink entries, 1 tp (`sink-009`).
3. Duplicates: none at row level; signature-level dedup deferred to Step 4 (documented above).
4. Argument index bounds: all `flow_kind=argument` entries carry `arg_index=0` (valid, in bounds for the call sites); `param` entries carry the positional index of the tainted parameter (self=0, path=1); keyword-controlled/receiver/field/return entries carry `arg_index=null` per schema.
5. Complete source→sink flow in DB: **1** — `src-012` → `sink-009` (`ComponentRequestHandler.get` → `open`, components.py:310→325).
