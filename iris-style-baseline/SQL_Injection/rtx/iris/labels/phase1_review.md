# Phase 1 Review — Pass 5 (CWE-89 SQL Injection), RTX

**Status**: Phase 1 Step 3 (LLM candidate labeling) complete. Phase 2 (library generation, taint
queries, report) intentionally **not started** per instructions.

- Run: `rtx-cwe89-pass5-labeling-20261021` · Model: **glm-5.3** (Claude Code session model, inline
  labeling; no external LLM API call) · Date: 2026-10-21
- Coverage: 668/668 CSV candidates labeled (255 source-side + 413 sink-side) + 7 code-evidence
  sanitizer entries = 675 entries; schema-validated against `assets/labels_schema.json` (PASS)
- Batches: 5 (autocomplete 37 · OpenAPI front-end 52 · ARAX data layer 84 · COHD 302 ·
  offline CLI/ETL 193+7)
- Artifacts: `labels.json`, `labels_raw_pass5.json`, `label_stats.md`, `generate_labels_pass5.py`
  (deterministic materialization of the reviewed decisions)

## 1. Label summary

| role | tp | candidate | fp | total |
| --- | --- | --- | --- | --- |
| source | 11 | 0 | 33 | 44 |
| sink | 11 | 9 | 228 | 248 |
| summary | 13 | 0 | 3 | 16 |
| sanitizer | 0 | 0 | 7 | 7 |
| none | 0 | 0 | 360 | 360 |

## 2. Top high-risk sinks (recommended Phase 2 focus)

1. **rtxcomplete.py:49/76/88/112** — `cursor.execute(f"... term LIKE \"{word}%%\" ... LIMIT {limit}")`
   with the raw HTTP `word` from `GET /nodeslike` (server.py:101-104 → get_nodes_like). No escaping
   anywhere on the word channel; a double quote breaks the SQL string literal. Fully
   attacker-controlled; **strongest finding** (conf 0.85). `limit` is neutralized by `int()`
   (rtxcomplete.py:34).
2. **predictor.py:65** — `f"select * from GRAPH where curie='{curie_name}'"`, unescaped. Reached
   from `POST /query`/`/asyncquery` via the ARAX Overlay/DTD pipeline; curies fall back to raw
   user-supplied curies when NodeSynonymizer has no canonical form (conf 0.85).
3. **predictor.py:328/348/350/370/372** — DTD probability lookups with unescaped disease/drug
   interpolation, including tuple-repr IN lists (conf 0.75).
4. **fisher_exact_test.py:579** — `f"WHERE C.category = '{node_type}'"`; `node_type` is the user's
   qnode `categories` value (fisher_exact_test.py:102 → :331); `convert_string_to_snake_case` /
   `convert_string_biolinkformat` (:617-650) only re-case the string — **not a whitelist** (conf 0.75).

## 3. Sources feeding those sinks

- `POST /query` / `POST /asyncquery` `request_body` + `connexion.request.get_json()`
  (query_controller.py:75/88, asyncquery_controller.py:11/24, both server variants) — the TRAPI
  query graph (qnode ids, curies, categories) drives the overlays that reach the sinks above.
- `GET /nodeslike` `word`/`limit`/`callback` (autocomplete/server.py:101-103).
- Header `x-forwarded-for` sources are real boundaries but only reach ORM bound parameters
  (`remote_address` in the query tracker) — labeled source/fp.

## 4. Sanitizers (7)

`int()` cast (rtxcomplete.py:34); SQLite single-quote doubling `re.sub("'","''")` /
`.replace("'","''")` (node_synonymizer.py:1931 family, ARAX_decorator.py:67/149,
fisher_exact_test.py:456); quote-exclusion (compute_ngd.py:346); COHD `dataset_id∈{1,2,3}`
whitelist + isinstance type guards; `.params(n=...)` named binds (ARAX_query_tracker.py:284/288/291).
All are context-appropriate for the SQLite string-literal positions they guard — the escaped
IN-list sinks (node_synonymizer.py:1987/2048, ARAX_decorator.py:72/154, fisher:468, compute_ngd:347)
are labeled **sink/fp**, i.e. reachable from HTTP but neutralized.

## 5. Unresolved / human-review items

| Item | Entries | Question |
| --- | --- | --- |
| COHD pair-branch SQL | 9 sinks (COHDIndex.py:983-1053), conf 0.55 | second-order via trusted cohd.io mapping API (`overlay_clinical_info.py:176-178` → `get_concept_ids` → remote API). Confirm the API cannot return crafted `omop_concept_id` values; parameterize. |
| fisher:579 upstream validation | 1 sink | does TRAPI/connexion schema validation or ARAX reject non-biolink qnode `categories` before they reach `size_of_given_type_in_KP`? Code path shows none (reformat-only). |
| predictor curie fallback | 6 sinks | verify at runtime that raw user curies (not just canonicalized ones) reach `get_feature`/DTD lookups when normalization misses. |
| dynamic dispatch gap | — | `rtxcomplete.prefix/fuzzy/autofuzzy` handlers reference functions absent from this snapshot; only `/nodeslike` is a live SQL path (detection.json). |

## 6. Exclusions & dedup record

- **No rows excluded**; all 668 CSV candidates labeled. Offline CLI/ETL entries are labeled
  `none/fp` (operator-controlled; detection.json `cli_env` exclusion) with evidence retained —
  they are not counted as vulnerabilities (per review rule 9: tests/migrations/static-SQL/admin
  configs must not auto-count).
- **No exact duplicates** found (`(file, line, node, callable)`); the KG2 controller variant rows
  are a parallel deployment copy (different files) labeled identically, not merged.
- **Not sinks for this pass**: neo4j Cypher `session.run` (out of CWE-89 scope), SQLAlchemy ORM
  `session.query/filter/add` (bound), `requests` HTTP calls, logging.
- **Reference loading**: `references/python.md`, `references/patterns.md`, `references/flask.md`
  (connexion/Flask front-end detected, conf 0.85); Django reference **not** loaded (no Django
  usage, detection.json confidence 0.0); Tornado has no reference file.

## 7. Honest model & process record

- The labeling LLM is the session model **glm-5.3** running inside Claude Code. No external LLM API
  was invoked and no model name is fabricated.
- Decisions were derived by reading the actual rtx sources (file list in
  `labels_raw_pass5.json.labeling_inputs`), then materialized deterministically via
  `generate_labels_pass5.py`; the raw file records per-row decisions with rationale keys and full
  rationale texts. One rule bug (boolean precedence misrouting
  `return_all_categories` → summary) was caught during self-check and fixed before finalization;
  final counts reflect the corrected state.
- No ground-truth, fix-commit, CVE or external advisory material was consulted; no source,
  database, extraction or Augur file was modified.

**Next step (not executed)**: human review of §5, then Phase 1 checkpoint approval before
Phase 2 Step 4 (generate `MySources/MySinks/MySanitizers/MySummaries.qll`).
