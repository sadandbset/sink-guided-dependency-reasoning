# Augur IRIS Report

Generated at: `2026-10-20T15:41:22.211799+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 5 | SQL Injection | 895 | 18 | 50 | 45 | 1077 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 5 | SQL Injection | 23 | 0 | 23 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass5` `arches/app/models/concept.py:646` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/models/concept.py:635` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/models/concept.py:654` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/models/concept.py:660` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/models/concept.py:653` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/models/concept.py:723` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/models/concept.py:1201` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/models/concept.py:1180` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/models/concept.py:1216` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/views/concept.py:424` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/views/concept.py:424` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/views/concept.py:426` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/management/commands/export.py:55` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/management/commands/export.py:55` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/management/commands/export.py:61` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/management/commands/export.py:61` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/management/commands/export.py:67` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/management/commands/export.py:67` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/management/commands/packages.py:611` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/management/commands/packages.py:623` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/utils/v3migration.py:52` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/utils/v3migration.py:49` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `arches/app/utils/v3migration.py:54` `py/augur/arches/pass5-sql-injection`: SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
SQL injection: attacker-influenced value flows into raw SQL query text executed by a database cursor (dynamic SQL construction via %-formatting or str.format, not a bound parameter).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
