# Pass 5 (CWE-89 SQL Injection) Label Statistics — RTX

- **Run**: `rtx-cwe89-pass5-labeling-20261021` (Augur 0.3.0, Phase 1 Step 3)
- **Model**: glm-5.3 (Claude Code session model performing inline labeling; no external LLM API call)
- **Generated**: 2026-10-21 (UTC)
- **Schema**: validated against `augur-0.3.0/assets/labels_schema.json` → PASS

## 1. Coverage

| Input | Rows | Labeled | Excluded |
| --- | --- | --- | --- |
| `extraction/sources.csv` (source + intermediate rows) | 255 | 255 | 0 |
| `extraction/sinks.csv` | 413 | 413 | 0 |
| **CSV total** | **668** | **668** | **0** |
| Extra sanitizer entries (code evidence, not CSV rows) | — | 7 | — |
| **Entries in `labels.json`** | | **675** | |

- Every CSV row is labeled exactly once (asserted by `generate_labels_pass5.py`).
- No exact `(file, line, node, callable)` duplicates were found in either CSV.
- The `UI/OpenAPI/python-flask-server/KG2/...` controller rows are a parallel deployment copy of the
  non-KG2 controllers (different files, identical code); they were labeled with identical decisions
  and **not** merged.
- The pass_id 1 block in `labels.json` is a schema-compatibility placeholder with zero entries
  (`labels_schema.json` `passes.contains` requires a pass_id=1 item); only pass 5 was labeled.

## 2. Batches (5 inline batches by the session model)

| Batch | Scope | CSV rows | Entries |
| --- | --- | --- | --- |
| 1 | autocomplete service (tornado server.py, rtxcomplete.py, create_load_db.py) | 37 | 37 |
| 2 | OpenAPI front-end (connexion controllers incl. KG2 variant, ARAX_query_tracker) | 52 | 52 |
| 3 | ARAX pipeline data layer (node_synonymizer, ARAX_decorator, predictor, fisher_exact_test, compute_ngd, ARAX_query) | 84 | 84 |
| 4 | COHD local index (COHDIndex.py) | 302 | 302 |
| 5 | offline CLI/ETL/build scripts + 7 code-evidence sanitizer entries | 193 | 200 |
| **Total** | | **668** | **675** |

## 3. Role × classification cross-tab

| role \ classification | tp | candidate | fp | total |
| --- | --- | --- | --- | --- |
| source | 11 | 0 | 33 | 44 |
| sink | 11 | 9 | 228 | 248 |
| summary | 13 | 0 | 3 | 16 |
| sanitizer | 0 | 0 | 7 | 7 |
| none | 0 | 0 | 360 | 360 |
| **total** | **35** | **9** | **631** | **675** |

Confidence bands: `>=0.8`: 367 · `0.65–0.79`: 78 · `<0.65`: 230.

## 4. True positives (35)

### 4.1 Sources (11)

| Entry | Location | Boundary |
| --- | --- | --- |
| pass5-src-120/121 | asyncquery_controller.py:11 (both server variants) | POST /asyncquery `request_body` |
| pass5-src-122/123 | query_controller.py:75 (both server variants) | POST /query `request_body` |
| pass5-src-240/241 | asyncquery_controller.py:24 (both variants) | `connexion.request.get_json()` |
| pass5-src-242/243 | query_controller.py:88 (both variants) | `connexion.request.get_json()` |
| pass5-src-253/254/255 | autocomplete/server.py:101/102/103 | GET /nodeslike `limit`/`word`/`callback` via `get_argument` |

### 4.2 Sinks (11)

| Entry | Location | Pattern |
| --- | --- | --- |
| pass5-sink-055/056/057/059 | rtxcomplete.py:49/76/88/112 | unescaped f-string/%-format SQL with HTTP `word` (double-quoted literal breakout) |
| pass5-sink-001 | predictor.py:65 | `f"select * from GRAPH where curie='{curie_name}'"` — no escaping |
| pass5-sink-063..067 | predictor.py:328/348/350/370/372 | unescaped disease/drug interpolation (incl. tuple-repr IN) |
| pass5-sink-054 | fisher_exact_test.py:579 | `f"WHERE C.category = '{node_type}'"` — user qnode category, reformat only, no whitelist |

### 4.3 Summary steps (13)

- `ARAX_query.py:100/216` `query` param (pipeline entry) — 2
- `node_synonymizer.py:1899/1905` `curies`/`names` of get_equivalent_nodes/get_canonical_curies — 3
- `rtxcomplete.py:29` `word`/`requested_limit` of get_nodes_like — 2
- `query_controller.py:23/61/71` `query_dict` fork/generator plumbing (both server variants) — 6

### Confirmed end-to-end attacker→SQL-text flows

1. `GET /nodeslike` → `get_argument("word")` (server.py:102) → `rtxcomplete.get_nodes_like` →
   f-string SQL at rtxcomplete.py:49/76/88 and %-format at :112. `word` is not escaped anywhere;
   `limit` is neutralized by `int()` (rtxcomplete.py:34).
2. `POST /query` / `POST /asyncquery` JSON body → `ARAXQuery.query_return_message/query_return_stream`
   → overlays → `predictor.get_feature` (predictor.py:65) and DTD prob lookups
   (predictor.py:328/348/350/370/372) — curies fall back to raw user curies when the NodeSynonymizer
   has no canonical form; and `fisher_exact_test.size_of_given_type_in_KP` (:579) with
   `node_type` taken from user qnode `categories` (fisher_exact_test.py:102 → :331).

## 5. Candidates pending human review (9)

All in COHDIndex.py `get_paired_concept_freq` pair-branch — lines 983, 986, 1007, 1021, 1023, 1027,
1029, 1051, 1053: unescaped `concept_pair_id` interpolation whose only live caller
(overlay_clinical_info.py:176-178) passes `"omop1_omop2"` strings produced by the trusted cohd.io
mapping API (second-order; currently numeric). Verify cohd.io cannot return crafted identifiers;
parameterization recommended.

## 6. Sanitizers (7, code-evidence entries)

| Entry | Location | Mechanism |
| --- | --- | --- |
| pass5-san-001 | rtxcomplete.py:34 | `int(requested_limit)` cast |
| pass5-san-002 | node_synonymizer.py:1931 (+1608/1952/2038) | `re.sub("'","''")` SQLite quote doubling |
| pass5-san-003 | ARAX_decorator.py:67 (+149) | `.replace("'","''")` |
| pass5-san-004 | fisher_exact_test.py:456 | `.replace("'","''")` (conditional) |
| pass5-san-005 | compute_ngd.py:346 | quote-exclusion filter (curies containing `'` dropped) |
| pass5-san-006 | COHDIndex.py:554 | `dataset_id ∈ {1,2,3}` whitelist (representative) |
| pass5-san-007 | ARAX_query_tracker.py:284 | `.params(n=last_n_hours)` named bind channel |

## 7. Bulk fp groups (largest)

| Group | Rows | Reason |
| --- | --- | --- |
| COHDIndex non-pair f-string sinks | ~221 | isinstance int/list guards, dataset_id whitelist, CLI/ETL-only callers |
| offline CLI/ETL sinks (kg2c, GraphSage, ngd build, KGNodeIndex, create_load_db, record_kg2c) | ~90 | static DDL / `?`-bound values / ETL-internal interpolations |
| argparse / sys.argv / os.environ sources | ~75 | operator-controlled offline entry points (detection.json cli_env) |
| node_synonymizer parameterized sinks | ~35 | static table prefix + bound `?` values |
| COHD internal params / comprehension vars | ~60 | internal propagation, no external boundary |
| dead tornado handlers (auto/fuzzy/autofuzzy) | 9 | `rtxcomplete.prefix/fuzzy/autofuzzy` undefined in this snapshot |

## 8. Model / determinism

- Model: **glm-5.3** (inline session labeling; no external LLM API invoked).
- Deterministic materialization: `labels/generate_labels_pass5.py` (rule tables mirroring the
  per-group code review; fixed confidences; one decision per CSV row).
- Raw per-row audit trail: `labels/labels_raw_pass5.json` (5 batches, per-row rationale keys,
  full rationale text + evidence map).
