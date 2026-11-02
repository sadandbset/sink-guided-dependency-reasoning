# Augur IRIS Report

Generated at: `2026-10-22T12:12:22.239909+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 24 | 292 | 2 | 12 | 13 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 5 | 0 | 5 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `mlflow/store/artifact/hdfs_artifact_repo.py:235` `py/augur/mlflow/pass1-path-traversal`: Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mlflow/store/artifact/local_artifact_repo.py:38` `py/augur/mlflow/pass1-path-traversal`: Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mlflow/store/artifact/local_artifact_repo.py:38` `py/augur/mlflow/pass1-path-traversal`: Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mlflow/store/artifact/local_artifact_repo.py:104` `py/augur/mlflow/pass1-path-traversal`: Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mlflow/store/artifact/local_artifact_repo.py:112` `py/augur/mlflow/pass1-path-traversal`: Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
