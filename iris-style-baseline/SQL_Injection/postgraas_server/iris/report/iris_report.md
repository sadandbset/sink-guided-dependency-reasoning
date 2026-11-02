# Augur IRIS Report

Generated at: `2026-10-21T03:09:31.686084+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 5 | SQL Injection | 8 | 9 | 0 | 19 | 44 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 5 | SQL Injection | 8 | 0 | 8 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass5` `postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py:22` `py/augur/postgraas_server/pass5-sql-injection`: SQL injection: attacker-controlled request value (reqparse argument of the postgraas REST API) flows into the SQL query text of a cursor.execute call in the pg_cluster driver, which assembles every statement with str.format and uses no bound parameters.
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py:24` `py/augur/postgraas_server/pass5-sql-injection`: SQL injection: attacker-controlled request value (reqparse argument of the postgraas REST API) flows into the SQL query text of a cursor.execute call in the pg_cluster driver, which assembles every statement with str.format and uses no bound parameters.
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py:43` `py/augur/postgraas_server/pass5-sql-injection`: SQL injection: attacker-controlled request value (reqparse argument of the postgraas REST API) flows into the SQL query text of a cursor.execute call in the pg_cluster driver, which assembles every statement with str.format and uses no bound parameters.
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py:44` `py/augur/postgraas_server/pass5-sql-injection`: SQL injection: attacker-controlled request value (reqparse argument of the postgraas REST API) flows into the SQL query text of a cursor.execute call in the pg_cluster driver, which assembles every statement with str.format and uses no bound parameters.
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py:50` `py/augur/postgraas_server/pass5-sql-injection`: SQL injection: attacker-controlled request value (reqparse argument of the postgraas REST API) flows into the SQL query text of a cursor.execute call in the pg_cluster driver, which assembles every statement with str.format and uses no bound parameters.
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py:52` `py/augur/postgraas_server/pass5-sql-injection`: SQL injection: attacker-controlled request value (reqparse argument of the postgraas REST API) flows into the SQL query text of a cursor.execute call in the pg_cluster driver, which assembles every statement with str.format and uses no bound parameters.
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py:65` `py/augur/postgraas_server/pass5-sql-injection`: SQL injection: attacker-controlled request value (reqparse argument of the postgraas REST API) flows into the SQL query text of a cursor.execute call in the pg_cluster driver, which assembles every statement with str.format and uses no bound parameters.
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py:75` `py/augur/postgraas_server/pass5-sql-injection`: SQL injection: attacker-controlled request value (reqparse argument of the postgraas REST API) flows into the SQL query text of a cursor.execute call in the pg_cluster driver, which assembles every statement with str.format and uses no bound parameters.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
