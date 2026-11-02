# Label Statistics - Pass 1 (Path Traversal)

- Run: `iris-thefuck-pass1-step3-20261023`
- Generated: 2026-10-23T13:32:22.663851+00:00
- Model: `glm-5.3` (in-session LLM labeling; temperature-free deterministic render of the reviewed decisions)
- Inputs: `extraction/sources.csv` (420 rows), `extraction/sinks.csv` (139 rows) -> **531 label entries**
- Dedup: 23 duplicate rows within a CSV collapsed; 5 nodes matched by both queries merged into single decisions

## Counts by role x classification

| role | tp | candidate | fp | unknown | total |
| --- | --- | --- | --- | --- | --- |
| source | 3 | 21 | 15 | 0 | 39 |
| sink | 4 | 13 | 6 | 0 | 23 |
| sanitizer | 0 | 0 | 0 | 0 | 0 |
| summary | 3 | 0 | 0 | 0 | 3 |
| none | 0 | 0 | 466 | 0 | 466 |

## Batches (real review batches executed this run)

| batch | scope | rows |
| --- | --- | --- |
| S1 | boundary sources: env_path/env_content/cli/param rows (entrypoints, shells, output_readers, conf, utils, types) | 33 |
| S2 | archive_entry_name sources (dirty_untar/dirty_unzip side effects) | 3 |
| S3 | command_output attribute reads across thefuck/rules | 262 |
| S4 | command_script attribute reads across thefuck/rules | 122 |
| K1 | sink rows: file_open/file_remove/file_mkdir | 19 |
| K2 | sink rows: archive_open/code_load/socket_connect | 6 |
| K3 | sink rows: file_stat/file_read | 41 |
| K4 | sink rows: path_ctor/path_join/path_wrapper/file_api_def | 73 |

## Dedup / exclusion rationale

1. **Within-CSV duplicates** (23 rows): identical (file, line, callable, family) rows produced by multi-pattern matches (e.g. `apt_get.py:39`, `sudo.py:29`, `docker_not_command.py:11`, the pathlib/os.path double matches of `expanduser`) collapse into one entry.
2. **Cross-CSV merges** (5 nodes): `conf.py:17 init`, `corrector.py:8 get_loaded_rules`, `entrypoints/shell_logger.py:64 shell_logger`, `types.py:131 Rule.from_path`, `utils.py:240 Cache._get_mtime` appear in both CSVs (param source + file_api_def sink); each carries one merged decision.
3. **Role-none policy**: `Path(...)` construction, `join`/`joinpath`, `expanduser`/`split`/`absolute` wrappers, and stat-only probes (`isfile`/`isdir`/`exists`/`getsize`/`getmtime`/`access`) are not dangerous file accesses per the pass-1 sink contract, so they are labeled `none`/`fp` with per-site evidence; the actual open/remove/mkdir/archive/code-load sites carry the sink labels.
4. **No test/fixture rows**: extraction already excluded `tests/` and `thefuck-db/`; `rules/test.py.py` is a shipped rule module (its single `command.output` read is matching-only -> none/fp).
5. **Sanitizers**: zero entries - no containment/canonicalization/'..' rejection exists anywhere in the package (see phase1_review.md Q5/Q6).

## High-confidence findings carried to the checkpoint

| entry | location | role | class | conf |
| --- | --- | --- | --- | --- |
| p1-014 | `thefuck/argument_parser.py:86` | source | candidate | 0.70 |
| p1-021 | `thefuck/shells/bash.py:69` | source | candidate | 0.65 |
| p1-070 | `thefuck/conf.py:46` | source | candidate | 0.70 |
| p1-082 | `thefuck/rules/dirty_untar.py:42` | source | candidate | 0.65 |
| p1-083 | `thefuck/rules/dirty_untar.py:43` | source | tp | 0.95 |
| p1-085 | `thefuck/rules/dirty_unzip.py:20` | source | candidate | 0.65 |
| p1-086 | `thefuck/rules/dirty_unzip.py:47` | source | tp | 0.95 |
| p1-260 | `thefuck/entrypoints/main.py:38` | source | candidate | 0.65 |
| p1-339 | `thefuck/output_readers/read_log.py:93` | source | candidate | 0.65 |
| p1-352 | `thefuck/rules/ssh_known_hosts.py:31` | source | tp | 0.85 |
| p1-362 | `thefuck/shells/tcsh.py:29` | source | candidate | 0.65 |
| p1-377 | `thefuck/types.py:16` | summary | tp | 0.70 |
| p1-378 | `thefuck/types.py:16` | summary | tp | 0.70 |
| p1-379 | `thefuck/types.py:69` | summary | tp | 0.70 |
| p1-390 | `thefuck/utils.py:228` | source | candidate | 0.65 |
| p1-410 | `thefuck/shells/zsh.py:74` | source | candidate | 0.65 |
| p1-454 | `thefuck/rules/dirty_untar.py:45` | sink | tp | 0.95 |
| p1-458 | `thefuck/rules/dirty_unzip.py:49` | sink | tp | 0.95 |
| p1-498 | `thefuck/entrypoints/shell_logger.py:74` | sink | candidate | 0.65 |
| p1-501 | `thefuck/rules/ssh_known_hosts.py:33` | sink | tp | 0.90 |
| p1-502 | `thefuck/rules/ssh_known_hosts.py:36` | sink | tp | 0.90 |

