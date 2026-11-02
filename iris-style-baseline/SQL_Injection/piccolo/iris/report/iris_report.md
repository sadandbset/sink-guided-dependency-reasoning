# Augur IRIS Report

Generated at: `2026-10-21T02:47:27.981528+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 5 | SQL Injection | 9 | 12 | 1 | 7 | 13 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 5 | SQL Injection | 18 | 0 | 18 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass5` `piccolo/query/methods/alter.py:36` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/query/methods/alter.py:63` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/query/methods/alter.py:117` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/query/methods/alter.py:188` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/query/methods/alter.py:250` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/columns/combination.py:131` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/query/mixins.py:119` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/query/mixins.py:659` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/query/mixins.py:706` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/engine/postgres.py:133` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/engine/postgres.py:133` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/engine/postgres.py:138` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/engine/postgres.py:138` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/engine/sqlite.py:313` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/engine/sqlite.py:313` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/engine/sqlite.py:318` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/engine/sqlite.py:318` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `piccolo/table.py:979` `py/augur/piccolo/pass5-sql-injection`: Untrusted input reaches SQL text that is executed verbatim (CWE-89).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
