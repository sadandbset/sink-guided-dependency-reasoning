# Pass 1 (Path Traversal) Label Statistics

- **Run ID:** `pretalx-pathtraversal-pass1-20261022`
- **Generated:** 2026-10-22
- **Project:** pretalx v2.3.1post0 (CodeQL DB `pretalx_vuln`, CLI 2.25.1, 508 source files)
- **Language / framework:** Python / Django (confidence 1.0, `exploration/detection.json`)
- **LLM model:** `glm-5.3` (in-session labeling; every candidate reviewed against the real source tree at `dataset/codeql_databases/path_traversal_dbs/pretalx_vuln/src`; no external API calls, no simulated results)
- **Pass scope:** Pass 1 only — Path Traversal, CWE-22 / CWE-23 / CWE-36 / CWE-73

## 1. Input candidates

| Input | Rows | Labeled | Skipped |
| --- | --- | --- | --- |
| `extraction/sources.csv` | 634 | 634 | 0 |
| `extraction/sinks.csv` | 33 | 33 | 0 |
| **Total** | **667** | **667** | **0** |

Batch policy: 12 batches — 11 source batches of 60 (last batch 34) + 1 sink batch of 33.
Per-row audit trail with batch assignment in `labels/labels_raw_pass1.json`
(batches `SRC-B01`…`SRC-B11`, `SNK-B01`).

**Duplicates:** exact duplicates are rows sharing file+line+callable+nodeRepr+argIndex — **none exist**. The 135 co-located row groups (same handler, same line) are *distinct parameters/nodes* of that handler (e.g. `question_move(event, pk, up)` yields 3 candidates) and were labeled individually. Signature-level deduplication (667 rows → 97 unique `signature+role` tuples) is deferred to Phase 2 Step 4 library generation, as prescribed by WORKFLOW.md 5.1.4.

**Re-ask policy:** 14 entries were labeled with confidence < 0.55 and were re-reviewed in a verification pass (`rechecked: true` in the raw file); no labels changed after re-review.

## 2. Label counts

### 2.1 Overall

| role | count | | classification | count |
| --- | --- | --- | --- | --- |
| source | 562 | | tp | 468 |
| sink | 25 | | fp | 182 |
| sanitizer | 0 | | candidate | 17 |
| summary | 0 | | unknown | 0 |
| none | 80 | | | |

### 2.2 Source candidates by extraction family (634 rows)

| family | rows | role/classification | conf. | basis |
| --- | ---: | --- | --- | --- |
| `request_query` (GET) | 144 | source/tp | 0.75 | direct attacker-controlled query input; unvalidated at read time |
| `form_cleaned_data` | 106 | source/tp | 0.60 | second-order: POST/FILES values after form validation (no path semantics enforced) |
| `http_route_param` | 76 | 48 source/fp, 4 source/tp, 1 source/candidate, 23 none/fp | 0.6–0.8 | see 2.3 |
| `request_form` (POST) | 66 | source/tp | 0.75 | direct attacker-controlled form input |
| `request_session` | 47 | source/tp | 0.55 | second-order: user-entered values round-tripped through the server-side session |
| `env_config` (os.environ/os.getenv) | 41 | none/fp | 0.75 | operator/deployment configuration, not attacker-controlled |
| `route_kwarg_get` | 36 | 12 source/tp, 24 source/fp | 0.65–0.8 | URL kwargs; int/slug-converter keys → fp |
| `request_headers` (headers/META/COOKIES) | 35 | source/tp | 0.70 | direct attacker-controlled request metadata |
| `http_path` (path/path_info) | 29 | source/tp | 0.70 | attacker-controlled (decoded) URL path |
| `route_kwarg` | 23 | 8 source/tp, 15 source/fp | 0.6–0.75 | URL kwargs; int/slug-converter keys → fp |
| `request_files` (FILES) | 12 | source/tp | 0.80 | multipart upload filenames — most path-relevant input family |
| `resolver_match` | 8 | none/fp | 0.70 | framework routing metadata object, not attacker content |
| `session_data` (cfp_session.get) | 6 | source/candidate | 0.50 | session round-trip feeding `FileSystemStorage.open` (flow.py:258-262) |
| `request_body` | 3 | source/tp | 0.70 | raw request body |
| `form_files` | 2 | source/tp | 0.70 | uploaded settings file whose `.name` reaches `default_storage.save` |

### 2.3 `http_route_param` breakdown (76 rows)

| param kind | rows | label | basis |
| --- | ---: | --- | --- |
| `pk`/`user_pk`/`talkid`/`roomid` | 25 | source/fp | `<int:…>` converter restricts to `[0-9]+`; traversal payload impossible |
| `event` | 21 | source/fp | `<slug:event>` converter (no separators, no dots) |
| `version`/`locale` (widget int routes) | 8 | source/fp | `v<int:version>` / `(?P<locale>[a-z]{2})` route regexes |
| `version` (str routes: `schedule/v/<version>`) | 4 | source/tp | plain str converter; attacker-controlled segment |
| `path` (get_static) | 1 | source/candidate | raw join → open with no containment; currently literal-bound (see §4) |
| internal params (`up`, `draft`, `steps`, `response`, `view`, `obj`, `fallback`, `ignore_next`, `query`, `warn`, `form_name`, `form_param`, `url`, `content_type`) | 17 + 6 | none/fp | passed by framework callers / internal call sites with constants — an internal parameter is not automatically a source |

### 2.4 Sink candidates (33 rows)

| classification | rows | entries |
| --- | ---: | --- |
| sink/candidate | 10 | export command write/read/mkdir, get_static open/FileResponse, cfp storage open/save, settings storage save/delete |
| sink/fp | 15 | event-slug-derived export paths, storage writes with literal/checksum names, FileResponse(FieldFile), schedule zip download |
| none/fp | 8 | BytesIO/NamedTemporaryFile (no filesystem path), literal static reads, test settings, makemessages dev tooling |

Sanitizer labels: **0** — pretalx's own source contains no path canonicalization/containment code (grep-verified in `exploration/detection.json`: no safe_join, get_valid_filename, basename, abspath, normpath, realpath or relative_to anywhere in `src/pretalx`). The only name validation is Django-internal (`Storage.get_valid_name`, `safe_join`; Django `~=3.2.0` pinned at `src/setup.py:101`) and therefore unverifiable inside this DB — recorded as evidence caveats on the affected sink entries instead of sanitizer labels.
Summary labels: **0** — no internal path-propagating wrapper APIs were extracted as candidates; second-order propagation (forms, session) is modeled at the source side.

## 3. Low-confidence entries (re-asked, < 0.55)

14 entries: `P1-S-0629`…`P1-S-0634` (cfp session `cfp_session.get` reads, 0.5), `P1-K-0008` (export mkdir, 0.45), `P1-K-0012`/`P1-K-0013` (export open write/read, 0.5), `P1-K-0016` (storage.open, 0.45), `P1-K-0030`/`P1-K-0031` (storage.save, 0.5), `P1-K-0032`/`P1-K-0033` (storage.delete, 0.45).

## 4. Top review-worthy entries (all `candidate`)

| id | location | role | flow summary |
| --- | --- | --- | --- |
| P1-S-0056 / P1-K-0010 / P1-K-0020 | `common/views.py:48/56/55` (get_static) | source/sink/sink | urlconfig-injected `path` → `BASE_DIR/'pretalx/static'/path` → `exists()` → `open(path,'rb')` → FileResponse. **No canonicalization, no containment, no `..` rejection**; docstring admits traversal potential; shipped route binds a literal (`agenda/urls.py:124-131`) so reachability requires a (plugin) urlconfig binding a URL variable. |
| P1-K-0012 / P1-K-0013 / P1-K-0008 | `export_schedule_html.py:121/134/119` | sink | `Path(destination)/url.lstrip('/')` → `open(path,'wb')`; `STATIC_ROOT/url[len(STATIC_URL):]` → `open(local_path,'rb')`; `path.parent.mkdir(parents=True)`. Raw pathlib joins, `..` not stripped — would escape the export root. URL set is app-generated; user rich-text is bleach-cleaned (no script/img/link), leaving organiser-uploaded CSS / plugin exporters as the injection vector; operator-triggered. |
| P1-K-0031 / P1-K-0030 | `cfp/flow.py:266` / `common/mixins/forms.py:450` | sink | client multipart filename (flow) / `get_new_filename` embedding the raw name as a path component (forms.py:470-479) → `Storage.save` under MEDIA_ROOT. Expected blocked by Django-internal basename + `safe_join`; unverifiable in this DB. |
| P1-S-0629…0634 + P1-K-0016 | `cfp/flow.py` | source/sink | session `files['tmp_name']` → `FileSystemStorage.open(tmp_name)`; tmp_name is server-generated and session-signed, but the chain feeds a file-open API directly. |
| P1-K-0032 / P1-K-0033 | `common/mixins/forms.py:445/461` | sink | `default_storage.delete(fname.name)` with DB-stored (second-order) storage names. |

## 5. Exclusions applied (with basis)

- `src/tests/**`, `src/pretalx/**/migrations/**`, `pretalx-db/**`, repo-root config/docs — already excluded during extraction (Augur noise policy; see `detection.json`).
- In-label `none`/fp families and their justification: `env_config` (operator boundary), `resolver_match` (framework metadata), internal handler parameters (not input boundaries), `content_type` literal, test-settings/dev-tooling/makemessages sink rows, BytesIO/NamedTemporaryFile call sites (no filesystem path).
- No candidate was dropped from `labels.json`; every `none`/fp row is retained with its rationale for audit.

## 6. Schema validation

`labels.json` was validated against `iris_tools/augur-0.3.0/assets/labels_schema.json` (all constraints checked: required fields, enums for role/classification/flow_kind, `arg_index` integer ≥ 0 when `flow_kind == "argument"`, CWE patterns, per-entry `additionalProperties: false`, unique ids) — **667/667 entries valid**. `jsonschema` is not installed locally, so the validation was executed as an equivalent constraint check scripted from the schema file.
