# Label Statistics — postgraas_server, Pass 5 (CWE-89)

**Run ID:** `postgraas-server-iris-pass5-20261021` · Generated 2026-10-21
**Snapshot:** source tree and CodeQL database both at sha `bd4f1b88e7008a3abd4dbe05c26e7b20bbb99649`
(sourceLocationPrefix == tree; every CSV line number matches the current source file). Each entry's
first evidence string is the verbatim source line at its location, pulled from the tree at
generation time by `labels/scripts/build_labels.py`; remaining evidence strings are verbatim lines
or clearly marked merge notes.

## Labeling session

| Item | Value |
| --- | --- |
| Model | glm-5.3 (in-session labeling by the agent's underlying LLM; no external LLM API calls) |
| Batches | 4 (batch-1 management_resources.py 19 rows · batch-2 postgres_cluster backend+driver 25 · batch-3 docker/configuration/exceptions/prometheus 12 · batch-4 all sinks 32) |
| Candidate rows processed | 88 (sources.csv 56 + sinks.csv 32) — **all rows dispositioned** |
| Rows merged into sibling entries | 8 (the sql_format_call construction nodes at postgres_cluster_driver.py:22/:24/:36/:37/:38/:41/:65/:75 merged into the `cursor.execute` entry of the same SQL statement) |
| Supplementary (out-of-CSV) entries | 0 |
| Final label entries | 80 |
| Re-ask threshold | 0.55 — entries below threshold: 0 (minimum confidence used: 0.7, the second-order delete-path candidates) |

## Entries by role × classification

| Role | tp | candidate | fp | total |
| --- | ---: | ---: | ---: | ---: |
| source | 5 | 3 | 0 | 8 |
| sink | 8 | 0 | 1 | 9 |
| sanitizer | 0 | 0 | 0 | 0 |
| summary | 17 | 2 | 0 | 19 |
| none | 0 | 0 | 44 | 44 |
| **total** | **30** | **5** | **45** | **80** |

Accept / reject / unresolved by label entry: **accepted (tp) 30 · rejected (fp) 45 · unresolved
(candidate, human review) 5**. By raw CSV row (88 rows, before merging): **tp 38 · fp 45 ·
candidate 5** — the exact per-row verdicts are in `labels/labels_raw_pass5.json`
(`source_row_dispositions` + `sink_row_dispositions`).

## Confirmed (tp) sinks — 8 sites, all in the pg_cluster driver

| # | Entry | Site | Confidence |
| --- | --- | --- | --- |
| 1 | p5-e-068 | `postgres_cluster_driver.py:22` `cur.execute("SELECT 1 FROM pg_database WHERE datname='{}';".format(db_name))` | 0.90 |
| 2 | p5-e-069 | `postgres_cluster_driver.py:24` `cur.execute("SELECT 1 FROM pg_roles WHERE rolname='{}';".format(db_user))` | 0.90 |
| 3 | p5-e-071 | `postgres_cluster_driver.py:43` `cur.execute(create_role)` — `CREATE USER {db_username} WITH PASSWORD '{db_pwd}';` (template :36) | 0.90 |
| 4 | p5-e-072 | `postgres_cluster_driver.py:44` `cur.execute(grant_role)` — `GRANT {db_username} TO "{postgraas_user}";` (template :38) | 0.90 |
| 5 | p5-e-073 | `postgres_cluster_driver.py:50` `cur.execute(create_database)` — `CREATE DATABASE {db_name} OWNER {db_username};` (template :41) | 0.90 |
| 6 | p5-e-074 | `postgres_cluster_driver.py:52` `cur.execute(drop_role)` — `DROP ROLE {db_username};` (template :37, error-cleanup path) | 0.85 |
| 7 | p5-e-076 | `postgres_cluster_driver.py:65` `cur.execute('''DROP DATABASE "{}";'''.format(db_name))` | 0.85 |
| 8 | p5-e-078 | `postgres_cluster_driver.py:75` `cur.execute('''DROP USER "{}";'''.format(get_normalized_username(username)))` | 0.85 |

Argument 0 (the SQL text) is the dangerous parameter at every site. Every statement is assembled
with `str.format` and executed with **no bound parameters** (no `execute` call in the project passes
a second argument). Sites 1–6 are reached first-order from the POST handler within one request;
sites 7–8 are reached from the DELETE handler with DB-persisted values (second-order). The
double-quote quoting in the DROP templates is partial identifier quoting, not a sanitizer — a `"`
in the value terminates the identifier.

Rejected (fp) sink: `prometheus_app.py:40` `cursor.execute(sql)` (p5-e-079, 0.9) — the SQL text is
the static literal `"SELECT count(*) FROM pg_database WHERE datistemplate = false;"`, and only
operator config enters `do_count_query`; the API family is the same DB-API execute channel, but no
attacker data can reach this site's SQL text.

## Confirmed (tp) sources — 5 entries

- `reqparse.RequestParser().parse_args()` of the **POST** collection handler
  (`management_resources.py:133`, p5-e-033, 0.95) — postgraas_instance_name / db_name / db_username /
  db_pwd, all required `str` with type coercion only; db_name / db_username / db_pwd flow into
  `db_credentials` (:142-148) → `backend.create` (:164) → `pgcd.create_postgres_db` → the
  CREATE USER / GRANT / CREATE DATABASE / DROP ROLE templates. No authentication on the endpoint.
  This is the primary external CWE-89 boundary.
- `reqparse.RequestParser().parse_args()` of the **DELETE** item handler
  (`management_resources.py:74`, p5-e-028, 0.85) — `args['db_pwd']` is genuine attacker-controlled
  request data; in this snapshot it flows to `psycopg2.connect(password=...)` (:81-87), the
  connection-credential channel, not SQL text; kept as source for pass-5 recall.
- Driver SQL-layer parameters: `check_db_or_user_exists(db_name)` and `check_db_or_user_exists(db_user)`
  (`postgres_cluster_driver.py:19`, p5-e-045/p5-e-046, 0.9) and `create_postgres_db(connection_dict)`
  (`:30`, p5-e-048, 0.9) — the values are demonstrably attacker-derived (first-order from the POST
  request via `connection_dict`/`db_entry` fields); they flow unescaped into `.format` SQL text.
  Conditional on the operator selecting the `pg_cluster` backend (BACKENDS dict,
  `backends/__init__.py:4`; default `docker`).

## Candidate (unresolved) sources — 3 entries + 2 summary entries

The second-order **delete path**: a prior POST persists attacker-controlled `db_name`/`username`
into the meta DB (`management_resources.py:150-157`, `session.add`/`commit` :175-176); a later
DELETE reads the row and feeds `entity.db_name`/`entity.username` into `DROP DATABASE`/`DROP USER`.

- `DBInstance.query.get(id)` in the delete handler (`management_resources.py:76`, p5-e-029, 0.7) —
  db_content source; the DB-content-as-source threat model deserves human confirmation.
- `delete_database(db_name)` (`postgres_cluster_driver.py:60`, p5-e-051, 0.7) and
  `delete_user(username)` (`:70`, p5-e-053, 0.7) — driver params fed by the same persisted values.
- Dynamic-dispatch steps `current_app.postgraas_backend.exists(entity)` (:95, p5-e-030) and
  `.delete(entity)` (:107, p5-e-031), both 0.7 — dispatch (pg_cluster vs docker) plus second-order
  origin; kept for conservative recall.

The chain itself is code-verified end-to-end; the open question is only the threat-model call
(persisted taint + operator backend choice), hence `candidate` rather than `fp`.

## Summary entries — 19

The propagation glue between the HTTP boundary and the SQL text (flask.md pass-5 reminder: raw SQL
formatting helpers need summary edges):

- **Backend wrapper params** (PGClusterBackend): `create` connection_info (:9), `delete` entity
  (:16), `exists` entity (:26) — the wrapper layer over the dynamic `current_app.postgraas_backend`
  dispatch.
- **pgcd call args** (backends/postgres_cluster/__init__.py :11/:18/:19/:27) — entity attribute
  reads (`entity.db_name`/`entity.username`) into the driver; object-field taint steps needed.
- **Handler-side dispatch args** (management_resources.py :158/:164) and **DBInstance constructor
  kwargs** (:152/:153) — field-store steps from POST args into `entity.db_name`/`entity.username`.
- **Driver helpers** (internal_sql_wrapper rows): `check_db_or_user_exists` (:19),
  `create_postgres_db` (:30), `delete_database` (:60), `delete_user` (:70) — param → dict-element →
  `.format` → execute-arg steps.
- `get_normalized_username` (driver :56) — taint-through helper (`split('@')[0]`), the edge that
  lets the DROP USER sink at :75 see tainted input.

## Sanitizers

None. No sanitizer entry was created: no DB-API bound parameters exist anywhere in the driver (no
execute call passes a second argument); `reqparse type=str` is type coercion only;
`get_normalized_username` (driver :56-57) splits at `@` and does not remove quote characters; the
double-quote quoting in the GRANT/DROP templates (:38/:65/:75) is partial identifier quoting that a
`"` in the value breaks out of; the CREATE USER / CREATE DATABASE templates (:36/:41) interpolate
the raw values unquoted.

## Rejected (fp) — 45 entries, main families

| Family | Entries | Reason |
| --- | ---: | --- |
| ORM channel (orm_query sink rows + db_content source rows whose results never reach SQL) | 14 | flask-sqlalchemy generates parameterized SQL with bound values; no raw SQL / text() / engine.execute in the ORM usage; values passed as bound parameters are safe behavior for pass 5 |
| Operator config (backend `config` params, application.cfg / /secrets open + json.load, run_server CLI options) | 15 | application.cfg and /secrets are operator-authored, read at startup; click options belong to the local operator; the remote HTTP client cannot write any of them |
| DockerBackend wrapper params | 5 | docker backend talks to the docker daemon API only; the pg_cluster driver is the project's only SQL channel |
| `<int:id>` route params (get :67 / delete :71) | 2 | flask int converter: non-integer segments 404 at routing; an int cannot carry SQL syntax; only reaches the bound ORM `query.get` |
| PGClusterBackend/`create` entity param, dispatch `create` db_entry arg, unused DBInstance kwargs | 6 | `entity` is unused inside `PGClusterBackend.create` (only connection_info reaches the driver); `password=""` literal; hostname/port from operator config; `postgraas_instance_name` never enters SQL text |
| PostgraasApiException message param; prometheus `do_count_query` wrapper | 2 | internal exception-message channel; wrapper around a static-literal SQL with only operator config entering |
| Driver `config` api_params (`_create_pg_connection` etc.) | included above | operator master-connection config; `psycopg2.connect` kwargs are a credential channel, not SQL text |

(Exact per-row verdicts: `labels/labels_raw_pass5.json`; counts are reproducible via
`labels/scripts/build_labels.py`.)

## Schema conformance

`labels/labels.json` was checked against
`iris_tools/augur-0.3.0/assets/labels_schema.json` (the schema exists; no structure was invented):
top-level keys, metadata required fields, passes/contains pass_id=1 stub (pass 1 Path Traversal has
zero entries and was NOT labeled in this run), entry required fields, role/classification/flow_kind
enums, additionalProperties=false, and the flow_kind="argument" ⇒ integer arg_index coupling all
pass (`jsonschema` is not installed in this environment; the equivalent checks run in
`build_labels.py` and in a post-build verification pass).

Extraction families map onto the schema flow_kind enum as: http_request / db_content / config_file /
config_load → `return`; route_param / api_param / wrapper_param / cli → `param`; internal_transfer →
`argument`; DBInstance constructor kwargs → `field`; orm_query (rejected rows) → `unknown`.

## Constraint compliance

- No PyVul vulnerability ground truth, fix commits, CVE descriptions or external security advisories
  were consulted; the `CVE申请报告.md` file at the source-tree root was deliberately not opened;
  `postgraas_server-db` / `postgraas_server-safe-db` were not traversed. Labels were derived only
  from the candidate CSVs and the source tree.
- classification=tp here means "confirmed genuine for the assigned API role in pass 5" — it is NOT
  the final vulnerability ground-truth TP.
- No CodeQL compile/run/decode was executed in this step; no source, database or Augur installation
  file was modified. Files written: `labels/labels.json`, `labels/labels_raw_pass5.json`,
  `labels/label_stats.md`, `labels/phase1_review.md`, `labels/scripts/build_labels.py`.

## Regeneration

```
cd C:\Users\lzh\Desktop\github\PyVul-main\iris_manual\SQL_Injection\postgraas_server\iris
python -I labels/scripts/build_labels.py    # rebuilds labels.json + labels_raw_pass5.json
```

The script reads `extraction/sources.csv` / `extraction/sinks.csv` and the postgraas_server_vuln
tree; every evidence string is a verbatim line pulled from the tree at generation time, so a stale
line number fails visibly rather than producing a fabricated citation.
