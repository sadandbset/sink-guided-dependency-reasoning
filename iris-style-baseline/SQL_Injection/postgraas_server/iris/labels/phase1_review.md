# Phase 1 Review — postgraas_server, Pass 5 (CWE-89 SQL Injection)

**Checkpoint:** end of Phase 1 Step 3 (LLM API candidate labeling), before Phase 2.
**Run ID:** `postgraas-server-iris-pass5-20261021` · Generated 2026-10-21 · Model: glm-5.3
(in-session labeling; no external LLM API calls) · Artifacts: `labels/labels.json` (schema-valid),
`labels/labels_raw_pass5.json`, `labels/label_stats.md`, `labels/scripts/build_labels.py`.

**Decision recorded for this round: STOP after Phase 1.** Per the task contract, no library
generation, no pass-query execution, and no Phase 2 work was started.

---

## 1. Label counts by pass and role

Pass 5 (CWE-89), 80 entries from 88 CSV candidate rows (56 sources + 32 sinks; 8 sink rows merged):

| Role | tp | candidate | fp | total |
| --- | ---: | ---: | ---: | ---: |
| source | 5 | 3 | 0 | 8 |
| sink | 8 | 0 | 1 | 9 |
| sanitizer | 0 | 0 | 0 | 0 |
| summary | 17 | 2 | 0 | 19 |
| none | 0 | 0 | 44 | 44 |
| **total** | **30** | **5** | **45** | **80** |

(A `pass_id=1` stub with zero entries is present in `labels.json` solely to satisfy the schema's
`contains` constraint; pass 1 was not labeled in this run.)

## 2. Top high-risk sink APIs

All 8 confirmed sinks are `cursor.execute` sites at argument 0 (the SQL text) in
`postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py`; every statement is built
with `str.format` and executed with **no bound parameters**:

| Entry | Line | Statement (template) | Reached from |
| --- | --- | --- | --- |
| p5-e-068 | :22 | `SELECT 1 FROM pg_database WHERE datname='{}'` (db_name) | POST create path / DELETE exists path |
| p5-e-069 | :24 | `SELECT 1 FROM pg_roles WHERE rolname='{}'` (db_user) | same |
| p5-e-071 | :43 | `CREATE USER {db_username} WITH PASSWORD '{db_pwd}'` | POST create path (unquoted!) |
| p5-e-072 | :44 | `GRANT {db_username} TO "{postgraas_user}"` | POST create path (db_username unquoted) |
| p5-e-073 | :50 | `CREATE DATABASE {db_name} OWNER {db_username}` | POST create path |
| p5-e-074 | :52 | `DROP ROLE {db_username}` | error-cleanup path only |
| p5-e-076 | :65 | `DROP DATABASE "{db_name}"` | DELETE path (second-order) |
| p5-e-078 | :75 | `DROP USER "{username}"` | DELETE path (second-order) |

The one rejected sink-family site (`prometheus_app.py:40`) executes a static literal and is marked
`sink/fp`.

## 3. Top source APIs

- `reqparse.RequestParser().parse_args()` — `management_resources.py:133` (POST, p5-e-033, 0.95)
  and `:74` (DELETE, p5-e-028, 0.85). No authentication on either REST endpoint; `type=str`
  coercion only.
- Driver SQL-layer params — `check_db_or_user_exists(db_name|db_user)` (driver :19, p5-e-045/046),
  `create_postgres_db(connection_dict)` (:30, p5-e-048): attacker-derived values (first-order from
  POST) that flow unescaped into `.format` SQL text.

## 4. Sanitizer list

**Empty — no sanitizer labels.** No bound parameters anywhere in the driver; no input validation on
the POST args; `get_normalized_username` is an `@`-split, not SQL sanitization; the double-quote
quoting in the GRANT/DROP templates is partial identifier quoting (breakout via `"` in the value);
CREATE USER/CREATE DATABASE templates interpolate raw values. The only parameterized SQL in the
project is the SQLAlchemy ORM channel, which is why every `orm_query` candidate was rejected
(`none/fp`), per the instruction that ORM regular queries with bound parameters must be
distinguished from raw SQL.

## 5. Unresolved / low-confidence items (human review requested)

5 `candidate` entries, all on the second-order delete path, all 0.7 confidence:

1. **p5-e-029** `DBInstance.query.get(id)` (`management_resources.py:76`) — DB-content-as-source
   threat model: a prior POST persisted attacker-controlled `db_name`/`username`; a later DELETE
   feeds them into DROP DATABASE/DROP USER.
2. **p5-e-051** `delete_database(db_name)` (driver :60) — same persisted-taint origin.
3. **p5-e-053** `delete_user(username)` (driver :70) — same.
4. **p5-e-030** `current_app.postgraas_backend.exists(entity)` (:95) — dynamic dispatch
   (pg_cluster vs docker) + second-order origin.
5. **p5-e-031** `current_app.postgraas_backend.delete(entity)` (:107) — same.

Two reviewer questions to settle before Phase 2:

- **Threat model:** accept DB-persisted attacker data as a taint source (second-order SQL
  injection)? The IRIS convention (python.md source families) supports it; the chain is
  code-verified end-to-end.
- **Deployment precondition:** the SQL channel exists only when the operator selects the
  `pg_cluster` backend (`BACKENDS` dict, `backends/__init__.py:4`; default is `docker`). The labels
  document this condition per-entry but do not demote entries for it — confirm this is the intended
  reading for this vulnerable snapshot.

No entries fell below the 0.55 re-ask threshold.

## 6. Coverage, merging and exclusions

- **All 88 CSV rows dispositioned** (56/56 source rows, 32/32 sink rows); `labels_raw_pass5.json`
  carries a per-row disposition with the entry id; `build_labels.py` fails loudly on any uncovered
  key.
- **Merging (8 rows):** each `sql_format_call` construction node (driver :22/:24/:36/:37/:38/:41/
  :65/:75) was merged into the `cursor.execute` entry of the same SQL statement — same-statement
  facets of one sink, mirroring the maltrail pass-2 merge convention. Merge provenance is recorded
  in each entry's evidence ("merged: sinks.csv rows …").
- **No supplementary out-of-CSV entries** were invented.
- Test files, the two CodeQL database directories inside the tree, and docs/ were already excluded
  at extraction time; the exclusions were honored (no label references any of them).

## 7. Full attack-chain summary (for the reviewer)

Within one request (first-order, tp):

```
POST /api/v2/postgraas_instances
  parse_args (management_resources.py:133)         [source, p5-e-033]
  -> db_credentials dict (:142-148)
  -> current_app.postgraas_backend.create(db_entry, db_credentials)  (:164)  [summary, p5-e-043]
     (BACKENDS dispatch; pg_cluster selected => PGClusterBackend)
  -> PGClusterBackend.create(entity, connection_info)  (backends :9)         [summary, p5-e-003]
  -> pgcd.create_postgres_db(connection_info, config)  (backends :11)        [summary, p5-e-004]
  -> create_postgres_db(connection_dict, config)      (driver :30)           [source, p5-e-048]
  -> check_db_or_user_exists(connection_dict["db_name"], ...)               [source, p5-e-045/046]
     -> cur.execute("... datname='{}'".format(db_name))   (driver :22)       [sink, p5-e-068]
  -> CREATE USER/GRANT/CREATE DATABASE/DROP ROLE .format templates           [sinks, p5-e-071..074]
```

Across requests (second-order, candidate):

```
POST (as above) -> DBInstance(db_name=..., username=...) (:150-157)
  -> session.add/commit (:175-176)                       [none/fp: ORM bound, write side]
  ... later DELETE /api/v2/postgraas_instances/<int:id> ...
  -> DBInstance.query.get(id) (:76)                      [source candidate, p5-e-029]
  -> backend.delete(entity) (:107)                       [summary candidate, p5-e-031]
  -> pgcd.delete_database(entity.db_name) / delete_user(entity.username)
  -> DROP DATABASE "{}" (driver :65) / DROP USER "{}" (driver :75)          [sinks, p5-e-076/078]
```

## 8. Constraint compliance

- No PyVul ground truth, fix commits, CVE descriptions or external advisories were consulted;
  `CVE申请报告.md` at the tree root was not opened; both CodeQL DB directories inside the tree were
  not traversed.
- The source tree, extraction artifacts, and the Augur installation were not modified; only the
  files under `iris/labels/` were written.
- Model identity, batch count (4), total processed rows (88) and role statistics are recorded in
  `labels.json` metadata and `labels_raw_pass5.json`; nothing was fabricated.

## 9. Recommended next steps (Phase 2, not started)

1. Resolve the two reviewer questions above (second-order source model; pg_cluster precondition).
2. Step 4: render `MySources.qll` / `MySinks.qll` / `MySummaries.qll` from the tp + candidate
   entries (sinks: the 8 `execute` argument-0 signatures; summaries: the 19 wrapper/field steps;
   `MySanitizers.qll` empty with `none()` fallback).
3. Step 5: generate and sequentially run `queries/Pass5_SQLInjection.ql` against
   `postgraas_server-db`.
