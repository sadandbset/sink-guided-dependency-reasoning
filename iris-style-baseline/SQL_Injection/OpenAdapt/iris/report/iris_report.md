# Augur IRIS Report

Generated at: `2026-10-20T16:05:23.184343+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 5 | SQL Injection | 16 | 3 | 1 | 1 | 107 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 5 | SQL Injection | 3 | 0 | 3 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass5` `openadapt/crud.py:142` `py/augur/openadapt/pass5-sql-injection`: SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `openadapt/crud.py:150` `py/augur/openadapt/pass5-sql-injection`: SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
  - Reason: no explicit FP/TP heuristic matched
- `pass5` `openadapt/crud.py:180` `py/augur/openadapt/pass5-sql-injection`: SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
SQL injection (CWE-89): untrusted data flows into raw SQL text that is executed by the recording export chain (export_sql -> create_db -> connection.execute).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
