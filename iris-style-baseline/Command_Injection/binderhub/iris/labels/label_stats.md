# Phase 1 Step 3 - Label Statistics (Pass 2 / CWE-78)

- run_id: `binderhub-iris-pass2-step3-20261014`
- generated_at: 2026-10-14T11:03:24Z
- model: glm-5.3 (Z.ai GLM), in-session labeling via Claude Code CLI; single-pass batches
- scope: Pass 2 only (CWE-077/078/088; CWE-78 primary); Pass 1 is an empty placeholder in labels.json

## Candidate accounting

| input | rows | entries emitted |
| --- | --- | --- |
| extraction/sources.csv | 74 | 74 |
| extraction/sinks.csv | 10 | 10 |
| **total** | **84** | **84** |

Every CSV row produced exactly one label entry; entries with `role=none` carry an auditable exclusion rationale. One duplicate CSV row (sources.csv rows 7/8, `request.headers` at `binderhub/base.py:93`) was consolidated into `src-007`, with `src-008` retained as a none/fp marker.

## Batch integrity

| batch | csv rows | entries |
| --- | --- | --- |
| pass2-S1 | 11 | 11 |
| pass2-S2 | 20 | 20 |
| pass2-S3 | 17 | 17 |
| pass2-S4 | 26 | 26 |
| pass2-K1 | 10 | 10 |

Row/entry parity across all batches: OK

## Role counts (pass 2)

| role | count |
| --- | --- |
| source | 29 |
| sink | 5 |
| sanitizer | 0 |
| summary | 25 |
| none | 25 |

## Classification counts (pass 2)

| classification | count |
| --- | --- |
| tp | 8 |
| candidate | 51 |
| fp | 25 |
| unknown | 0 |

`tp` means the labeled role is genuinely played by the API for this pass (e.g. `subprocess.run` at `repoproviders.py:488` really is a command-execution sink fed by request data). It does **not** mean a confirmed exploitable vulnerability.

## Role x classification

| role | tp | candidate | fp | unknown |
| --- | --- | --- | --- | --- |
| source | 5 | 24 | 0 | 0 |
| sink | 3 | 2 | 0 | 0 |
| sanitizer | 0 | 0 | 0 | 0 |
| summary | 0 | 25 | 0 | 0 |
| none | 0 | 0 | 25 | 0 |

## Confidence distribution

| band | count |
| --- | --- |
| >=0.8 | 26 |
| 0.7-0.79 | 15 |
| 0.6-0.69 | 29 |
| 0.5-0.59 | 14 |
| <0.5 | 0 |

## Entries per module and role

| file | source | sink | summary | none |
| --- | --- | --- | --- | --- |
| binderhub/app.py | 0 | 0 | 0 | 4 |
| binderhub/base.py | 7 | 0 | 0 | 1 |
| binderhub/build.py | 0 | 4 | 0 | 2 |
| binderhub/builder.py | 9 | 0 | 8 | 4 |
| binderhub/health.py | 0 | 0 | 0 | 2 |
| binderhub/launcher.py | 0 | 0 | 0 | 4 |
| binderhub/main.py | 8 | 0 | 1 | 0 |
| binderhub/registry.py | 0 | 0 | 0 | 3 |
| binderhub/repoproviders.py | 5 | 1 | 16 | 5 |

## Sink entries (all)

| id | signature | role/class | conf | location |
| --- | --- | --- | --- | --- |
| snk-010 | `subprocess.run` (arg 0, argument) | sink/tp | 0.85 | binderhub/repoproviders.py:488 |
| snk-004 | `V1Container.args` (arg None, field) | sink/tp | 0.8 | binderhub/build.py:343 |
| snk-005 | `create_namespaced_pod` (arg 1, argument) | sink/tp | 0.75 | binderhub/build.py:376 |
| snk-003 | `get_cmd` (arg None, return) | sink/candidate | 0.7 | binderhub/build.py:343 |
| snk-002 | `V1EnvVar.value` (arg None, field) | sink/candidate | 0.5 | binderhub/build.py:325 |

## Source entries with classification=tp

- `src-010` `request.path` (binderhub/base.py:155), conf 0.85
- `src-011` `request.path` (binderhub/base.py:156), conf 0.85
- `src-015` `get` (binderhub/builder.py:223), conf 0.9
- `src-016` `get` (binderhub/builder.py:223), conf 0.9
- `src-017` `get_spec_from_request` (binderhub/builder.py:239), conf 0.85

## Low-confidence entries (<0.55): 2

- `src-058` `get_repo_url` (binderhub/repoproviders.py:433), role summary, conf 0.5
- `snk-002` `V1EnvVar.value` (binderhub/build.py:325), role sink, conf 0.5

## Sanitizers

No sanitizer entries were labeled: neither extraction CSV contained a sanitizer-shaped candidate. Advisory for the next extraction pass: `RepoProvider.sha1_validate` (SHA-1 format enforcement on refs), `_safe_build_slug`/`_generate_build_name` (escapism escaping of build names) and `tokenize_spec` (spec structure check) are sanitizer-shaped helpers present in the source. Note that `sha1_validate` validates the *resolved output* of `git ls-remote`, not its inputs, and the list-form subprocess invocation itself is the shell-metacharacter defense at `repoproviders.py:488`.

## Quality checks (WORKFLOW.md 4.4.6)

1. Schema validation: PASS (structural validation of all 84 entries against `assets/labels_schema.json` constraints: enums, required keys, arg_index/flow_kind coupling, confidence range, CWE patterns, pass-1 containment, id uniqueness, no additional properties).
2. Every enabled pass has at least one sink: PASS for pass 2 (5 sink entries); pass 1 is an out-of-scope placeholder with empty entries.
3. Duplicates: one exact duplicate CSV row consolidated (see Candidate accounting); entry ids are unique.
4. Argument index bounds: all `flow_kind=argument` entries carry integer arg_index >= 0 (0 or 1); keyword-position sinks were normalized to `flow_kind=field` with arg_index null per the recorded deviation.

