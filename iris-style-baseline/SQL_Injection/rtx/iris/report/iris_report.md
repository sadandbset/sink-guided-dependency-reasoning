# Augur IRIS Report

Generated at: `2026-10-21T03:07:53.061858+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 5 | SQL Injection | 44 | 248 | 7 | 16 | 360 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 5 | SQL Injection | 4 | 0 | 4 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass5` `code/autocomplete/rtxcomplete.py:76` `py/augur/rtx/pass5-sql-injection`: SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup).
SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup).
SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `code/autocomplete/rtxcomplete.py:49` `py/augur/rtx/pass5-sql-injection`: SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup).
SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup).
SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `code/autocomplete/rtxcomplete.py:112` `py/augur/rtx/pass5-sql-injection`: SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup).
SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup).
SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `code/autocomplete/rtxcomplete.py:88` `py/augur/rtx/pass5-sql-injection`: SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup).
SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup).
SQL injection (CWE-89): untrusted data from an HTTP input boundary flows into raw SQL text executed by a sqlite3 cursor.execute() call (autocomplete / ARAX overlay / COHD lookup).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
