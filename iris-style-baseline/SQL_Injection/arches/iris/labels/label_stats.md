# Augur Phase 1 Step 3 — Label Statistics

**Project:** arches (Arches 7.1.0-beta, Django) · **Pass:** 5 (CWE-089, SQL Injection) · **Language:** python
**Model:** glm-5.3 (in-session agent LLM; no external LLM API calls) · **Run:** `arches-iris-pass5-20261020` (2026-10-20)
**Source tree:** `arches_vuln` @ sha `75ce8f7cb9c08caf608569797a40ca9be585b182` (= CodeQL DB `arches-db` creation sha)

## 1. Candidate coverage

| Input | Rows | Dispositioned | Merged (exact CSV duplicates) | Entries written |
| --- | --- | --- | --- | --- |
| `extraction/sources.csv` | 1906 | 1906 | 49 (41 duplicate groups) | 1857 |
| `extraction/sinks.csv` | 224 | 224 | 2 (`etl_template.py:117` fstring ×2, `setup_db.py:86` concat ×2) | 222 |
| Code-evidence sanitizers (not in CSVs) | — | — | — | 6 |
| **Total** | **2130** | **2130 (100%)** | **51** | **2085** |

Duplicate-merge basis: all ten CSV columns identical (same AST node / file / line / flowKind / callable). Every merge is recorded per-row in `labels_raw_pass5.json`. Deduplication and exclusions never dropped a *distinct* candidate.

## 2. Role × classification (pass 5)

| role | tp | candidate | fp | unknown | total |
| --- | --- | --- | --- | --- | --- |
| source | 789 | 106 | 0 | 0 | 895 |
| sink | 7 | 11 | 0 | 0 | 18 |
| sanitizer | 50 | 0 | 0 | 0 | 50 |
| summary | 37 | 8 | 0 | 0 | 45 |
| none | 0 | 5 | 1072 | 0 | 1077 |
| **total** | **883** | **130** | **1072** | **0** | **2085** |

Classification semantics: `tp` = confirmed genuine for the assigned role (API-level truth, **not** vulnerability ground truth); `fp` = rejected candidate; `candidate` = plausible but unresolved trust boundary, human review requested; `unknown` = unused this run.

Confidence distribution: ≥0.8 → 1941 entries; 0.6–0.79 → 34; 0.5–0.59 → 110.

## 3. By extraction family

| Family (CSV `flowKind`) | source/tp | source/candidate | none/fp | sink/tp | sink/candidate | sanitizer/tp | summary/tp | summary/candidate | none/candidate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| http_request (attribute loads) | 292 | | | | | | | | |
| request_param (`request.*.get()`) | 240 | | | | | | | | |
| http_body (`deserialize(request.body)`) | 22 | | | | | | | | |
| param (handler parameters) | 235 | | 14 | | | | | | |
| cli (options / add_argument) | | 80 | 305 | | | | | | |
| config (settings reads) | | | 445 | | | | | | |
| env | | | 16 | | | | | | |
| file (open/read) | | 26 | 70 | | | | | | |
| internal_transfer | | | 73 | | | | 34 | 5 | |
| sink: sql_text (execute/callproc arg 0) | | | | 3 | 7 | | | | |
| sink: bound_params (execute/callproc arg 1) | | | | | | 44 | | | |
| sink: sql_percent_format | | | | 1 | | | | | 1 |
| sink: sql_format_call | | | | 3 | 4 | | | | 2 |
| sink: sql_fstring / sql_concat | | | | | | | | | (11 fp) |
| sink: internal_sql_wrapper (function rows) | | | | | | | 3 | 3 | 2 |
| extra sanitizers (code evidence) | | | | | | 6 | | | |

## 4. Confirmed pass-5 sink entries (role=sink, classification=tp) — 7

| id | site | confidence |
| --- | --- | --- |
| p5-k-091 | `arches/app/models/concept.py:635` — `%%%s%%' % query.lower()` (get_child_edges LIKE subquery) | 0.90 |
| p5-k-092 | `arches/app/models/concept.py:653` — `sql.format(...)` assembling the tainted subquery | 0.85 |
| p5-k-094 | `arches/app/models/concept.py:723` — `cursor.execute(sql)` | 0.95 |
| p5-k-099 | `arches/app/models/concept.py:1180` — `'{0}'.format(conceptid)` (get_e55_domain, unvalidated) | 0.90 |
| p5-k-100 | `arches/app/models/concept.py:1216` — `cursor.execute(sql)` | 0.95 |
| p5-k-140 | `arches/app/views/concept.py:424` — `sql.format(query=query.lower(), ...)` (paged_dropdown) | 0.90 |
| p5-k-141 | `arches/app/views/concept.py:426` — `cursor.execute(sql)` | 0.95 |

## 5. Sanitizer entries (role=sanitizer, classification=tp) — 50

- 44 × `cursor.execute`/`cursor.callproc` **bound-parameter channel rows** (argument index 1) across the ETL staging pipeline (`branch_csv_importer`, `import_single_csv`, `base_import_module`), MVT (`api.py:264/:316`), buffer endpoints (`search.py:465`, `map_filter.py:92`), ETL manager, `graph.py` publish + callproc, `etl_template`, `datatypes.py:1320`, `index_database.py:402`.
- 6 code-evidence entries added beyond the CSVs:
  - `p5-x-01` `uuid.UUID` validation — `models/concept.py:503` (conceptid slot of get_child_edges; **does not cover** the `query` param or get_e55_domain)
  - `p5-x-02` `int()` cast — `views/concept.py:385` (paged_dropdown page)
  - `p5-x-03`/`p5-x-04` `float()` casts — `views/search.py:456`, `map_filter.py:83` (buffer width)
  - `p5-x-05`/`p5-x-06` `GEOSGeometry` re-parse → WKB-hex binding — `views/search.py:453`, `map_filter.py:80`

## 6. Candidate (human-review) entries — 130

- 106 source-side: CLI `options[...]` reads in `packages` (64), `v3` (14), `export` (2) + file `open()/read()` rows feeding executed SQL (packages `.sql` files 4, v3 migration data 22).
- 18 sink-side: `export.py:55/:61/:67` (CLI table identifier), `packages.py:611/:623` (verbatim package SQL execution), `v3migration.py:49/:54` (v3 data → `ST_ForceRHR` SQL), `index_database.py:343/:370` (ORM-derived identifiers).
- 8 summary-side + 5 none-side: wrapper/function rows on the same operator-trust paths.

## 7. Batches (LLM processing record)

| Batch | Scope | Candidate rows |
| --- | --- | --- |
| B1 | all sink rows (execute/callproc, SQL construction exprs, SQL wrapper functions), 20 modules, every site read in the tree | 224 |
| B2 | HTTP-boundary source rows (http_request, request_param, http_body, param) | 811 |
| B3 | internal_transfer rows | 112 |
| B4 | cli rows | 409 |
| B5 | config / env / file rows | 574 |
| | **total processed** | **2130** |

Model: glm-5.3; labeling performed in-session (no external API calls, no temperature setting applicable); decisions materialized deterministically by `labels/scripts/make_labels_pass5.py`; full per-row audit trail in `labels_raw_pass5.json`.

## 8. Quality checks

1. `labels.json` validated against `assets/labels_schema.json` (required keys, enums, patterns, arg_index rules, additionalProperties key sets, pass_id-1 `contains`): **0 errors** (pass 1 stub with 0 entries present solely to satisfy the schema `contains` clause; pass 1 was not labeled).
2. Pass 5 has ≥1 sink (7 confirmed + 11 candidates). ✓
3. Duplicates removed (51 rows) and recorded. ✓
4. Argument indices verified in bounds where available (execute arg 0/1; internal_transfer positional indices 0–9 as extracted). ✓
5. Every entry's first evidence string is the verbatim source line at its location, re-read from the tree at generation time. ✓
