# Augur IRIS Report

Generated at: `2026-10-21T08:46:29.808719+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 5 | SQL Injection | 12 | 24 | 2 | 17 | 11 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 5 | SQL Injection | 10 | 0 | 10 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass5` `superset/databases/api.py:812` `py/augur/superset/pass5-sql-injection`: This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `superset/databases/api.py:812` `py/augur/superset/pass5-sql-injection`: This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `superset/db_engine_specs/base.py:1551` `py/augur/superset/pass5-sql-injection`: This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `superset/models/core.py:639` `py/augur/superset/pass5-sql-injection`: This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `superset/models/core.py:640` `py/augur/superset/pass5-sql-injection`: This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `superset/db_engine_specs/postgres.py:312` `py/augur/superset/pass5-sql-injection`: This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `superset/db_engine_specs/presto.py:347` `py/augur/superset/pass5-sql-injection`: This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `superset/sql_validators/presto_db.py:76` `py/augur/superset/pass5-sql-injection`: This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `superset/sql_lab.py:195` `py/augur/superset/pass5-sql-injection`: This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `superset/sql_lab.py:378` `py/augur/superset/pass5-sql-injection`: This data originates from an attacker-controlled input boundary (Flask request state, FAB route/handler parameter, rison query, or the SQL Lab celery payload) and flows into SQL text or an SQL structure fragment that is executed verbatim by a database API. If the attacker-controlled value is not confined to a bound parameter, this is a SQL injection (CWE-89).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
