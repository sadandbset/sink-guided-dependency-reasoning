# Augur Phase 1 Step 3 - Label Statistics (Pass 2 / CWE-078)

- run_id: `autogluon-pass2-phase1-20261012`
- generated_at: 2026-10-12T02:56:26Z
- model: glm-5.3
- language: python, project: autogluon, framework: null

## Coverage

| Input | Rows | Labeled | Merged duplicates |
| --- | --- | --- | --- |
| sinks.csv | 12 | 12 | 0 |
| sources.csv | 6451 | 6451 (6448 unique entries + 3 merged dup rows) | 3 |
| supplementary (context review) | - | 3 | - |
| **total pass-2 entries** | | **6463** | |

Batches recorded in `labels_raw_pass2.json`: 37 (1 sink batch + 36 source batches).
No candidate row was silently dropped; duplicate rows are kept as merged records.

## Counts by role

| role | count |
| --- | --- |
| source | 7 |
| sink | 2 |
| sanitizer | 0 |
| summary | 1 |
| none | 6453 |

## Counts by classification

| classification | count |
| --- | --- |
| tp | 2 |
| fp | 6453 |
| candidate | 8 |
| unknown | 0 |

## Important sinks

| id | signature | location | class | conf |
| --- | --- | --- | --- | --- |
| p2-sink-002 | subprocess.check_output(arg 0) | core/src/autogluon/core/utils/sync_remote.py:50 | tp | 0.90 |
| p2-sink-003 | subprocess.check_output(arg 0) | core/src/autogluon/core/utils/sync_remote.py:52 | tp | 0.90 |

All other command-execution call sites (Popen with fixed literal lists in `core/src/autogluon/core/utils/sync_remote.py:16`, nine `tests/test_check_style.py` copies, and the fixed nvidia-smi command at `core/src/autogluon/core/utils/utils.py:890`) were labeled role=none/fp: shell is not enabled and arguments are fixed literals.

## Labeled sources

| id | signature | location | class | conf |
| --- | --- | --- | --- | --- |
| p2-src-0971 | main (arg 0) | examples/automm/distillation/automm_distillation.py:19 | candidate | 0.45 |
| p2-src-1912 | main (arg 0) | examples/automm/tabular_dl/example_tabular.py:55 | candidate | 0.45 |
| p2-src-2326 | main (arg 0) | examples/text_prediction/generate_submission.py:24 | candidate | 0.45 |
| p2-src-4091 | main (arg 0) | examples/text_prediction/prepare_glue.py:614 | candidate | 0.45 |
| p2-src-4863 | sync_training_processes (arg 0) | core/src/autogluon/core/utils/sync_remote.py:46 | candidate | 0.50 |
| p2-supp-001 | environ.__getitem__ (arg -) | core/src/autogluon/core/utils/sync_remote.py:13 | candidate | 0.50 |
| p2-supp-002 | environ.__getitem__ (arg -) | core/src/autogluon/core/utils/sync_remote.py:14 | candidate | 0.50 |

## Sanitizers

None labeled. Grep for `shlex` over the whole repository returns no matches; no allow-list validation or quoting exists on the two shell=True call sites. Per the rubric, sanitizers are only marked with concrete evidence.

## Summaries

- `p2-supp-003` (core/src/autogluon/core/utils/utils.py:878, class=candidate, conf=0.55) - command-output wrapper.

## Low-confidence items (confidence < 0.55)

- `p2-src-4863` source/candidate conf=0.50 - core/src/autogluon/core/utils/sync_remote.py:46
- `p2-supp-001` source/candidate conf=0.50 - core/src/autogluon/core/utils/sync_remote.py:13
- `p2-supp-002` source/candidate conf=0.50 - core/src/autogluon/core/utils/sync_remote.py:14
- `p2-src-0971` source/candidate conf=0.45 - examples/automm/distillation/automm_distillation.py:19
- `p2-src-1912` source/candidate conf=0.45 - examples/automm/tabular_dl/example_tabular.py:55
- `p2-src-2326` source/candidate conf=0.45 - examples/text_prediction/generate_submission.py:24
- `p2-src-4091` source/candidate conf=0.45 - examples/text_prediction/prepare_glue.py:614

## Coverage justification

- Command-execution API universe verified by both the CodeQL sink extraction and a repository-wide grep for `subprocess|os.system|os.popen|pexpect|create_subprocess|os.exec|pty.spawn`: only `sync_remote.py`, `utils.py`, and nine test_check_style.py copies contain real calls (the tab_transformer hit is a docstring mention).
- The `shell=True` grep confirms sync_remote.py:50 and :52 are the only shell-enabled command executions in the repository.
- Callers verified: `sync_training_processes` is called only by `sagemaker_setup` (fixed literal 'dask-scheduler'); `get_gpu_free_memory` is called only with no arguments from `version_utils.py:104` and `presets_configs.py:226`.
