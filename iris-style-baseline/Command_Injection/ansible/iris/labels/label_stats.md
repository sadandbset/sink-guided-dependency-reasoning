# Augur Phase 1 Step 3 — Label Statistics (Pass 2, CWE-78, Ansible)

- **Run**: `ansible-iris-manual-phase1-step3-pass2-cwe78`, 2026-10-14
- **Model**: `glm-5.3` (Claude Code CLI agent session, lead + 8 fork subagents, same model)
- **Labeling mode**: deterministic single-pass LLM judgment against the real source tree
  `dataset/codeql_databases/ansible_vuln` (read-only). No sampling temperature applies
  (CLI agent reasoning, not a temperature-sampled API completion). No fabricated sources:
  every rationale cites file:line evidence read during this run.
- **Inputs**: `iris/extraction/sources.csv` (1249 rows), `iris/extraction/sinks.csv` (416 rows),
  `iris/exploration/detection.json`, `WORKFLOW.md`, `references/python.md`, `references/patterns.md`,
  `assets/labels_schema.json`.

## 1. Accounting (no candidate skipped)

| item | count |
|---|---|
| Candidate rows in CSVs | **1665** (1249 sources + 416 sinks) |
| Rows labeled (entries in `labels_raw_pass2.json`) | **1665** — 100% |
| Rows excluded / dropped | **0** (no exclusions; every row has an entry, incl. `fp`/`none`/`unknown`) |
| Batches | **8** (S1–S4 sources, K1–K4 sinks) |
| Deduplicated signature-level entries in `labels.json` | **54** (53 groups from the 1665 rows + 1 sanitizer added by lead labeler) |
| Duplicate rows removed by dedup | 1665 − 53 = **1612** row-level collapses into signature groups |

Batch sizes: S1 561 (module_params), S2 363 (cli_args), S3 283 (task_args/env/stdin),
S4 42 (remote/deserialized), K1 323 (run_command), K2 38 (subprocess), K3 40 (action/connection layer),
K4 15 (pexpect + wrappers). Per-batch judgment files: `iris/labels/_work/out_*.jsonl`; rubric: `iris/labels/_work/rubric.md`.

## 2. Role statistics

### Per-row (labels_raw_pass2.json, 1665 entries)

| role | count | share |
|---|---|---|
| source | 1249 | 74.9% |
| sink | 387 | 23.2% |
| summary | 22 | 1.3% |
| none | 7 | 0.4% |
| sanitizer | 0 (from CSVs; 1 added entry) | — |

### Deduplicated (labels.json, 54 entries)

| role | count |
|---|---|
| source | 17 |
| sink | 15 |
| summary | 18 |
| none | 3 |
| sanitizer | 1 (added, `shlex_quote`) |

Note: `Connection/exec_command` legitimately appears in three roles — sink (arg 0, call sites),
source (return, remote output), summary (param passthrough in subclass definitions).

## 3. Classification statistics (per-row)

| classification | count | share |
|---|---|---|
| tp | 654 | 39.3% |
| candidate | 963 | 57.8% |
| fp | 44 | 2.6% |
| unknown | 4 | 0.2% |

Role × class: source/tp 566, source/candidate 656, source/fp 24, source/unknown 3;
sink/tp 66, sink/candidate 307, sink/fp 13, sink/unknown 1; summary/tp 22; none/fp 7.

## 4. Confidence distribution (per-row)

| bucket | count |
|---|---|
| ≥ 0.85 | 20 |
| 0.70–0.84 | 767 |
| 0.55–0.69 | 746 |
| < 0.55 | 132 |

Low-confidence (<0.55) rows: 73 source/candidate, 51 sink/candidate, 4 source/fp, 3 source/unknown,
1 sink/unknown. No re-ask pass was run (threshold re-asks per WORKFLOW 4.4.4 are advisory; the
low-confidence entries are retained with explicit `candidate`/`unknown` classifications and evidence
rather than resampled — documented for the review gate).

## 5. Family-level results (per-row averages)

| API family | rows | avg conf | dominant judgment |
|---|---|---|---|
| AnsibleModule.params | 510 | 0.75 | source/tp — module-side input boundary (controller/playbook data via `_load_params`) |
| ansible.context.CLIARGS | 332 | 0.57 | source/candidate — local-admin CLI args, weak boundary |
| AnsibleModule.run_command | 323 | 0.61 | sink — 33/34 `use_unsafe_shell=True` sites tp (shell=True), argv-mode sites candidate (CWE-88 surface) |
| task.args | 182 | 0.68 | source/candidate — controller-side playbook data; raw/reboot/script paths tp |
| os.environ / os.getenv | 84 | 0.52 | source/candidate — local env; PAGER→shell path tp |
| AnsibleModule ctor | 49 | 0.60 | source/candidate — object carries parsed external input |
| json.loads / json.load | 33 | 0.69 | source — 22 tp on remote/network/external payload origins, 10 candidate (local/IPC), 1 candidate (caller-dependent) |
| sys.argv / sys.stdin | 48 | 0.56 | source/candidate; module-args channel rows tp |
| subprocess.Popen/call/check_call | 38 | 0.60 | sink — 9 tp (shell=True / dynamic shell), 17 candidate, 12 fp (fixed literals) |
| exec_command family | 29 | 0.71 | sink arg0 tp / source return tp / summary defs tp |
| _low_level_execute_command | 19 | 0.79 | sink arg0 tp (remote shell via connection layer) |
| pexpect.run/_run/spawn | 3 | 0.57 | sink/candidate — argv semantics, no shell (CWE-88 surface) |
| internal wrappers (12 defs) | 12 | 0.75 | summary/tp — direct param→exec passthrough |

## 6. Verification coverage (per-row)

| depth | rows | meaning |
|---|---|---|
| full | 500 | call/definition site read ± context; arg/param origin traced |
| sampled | 382 | site read within a bulk family (≥15–20% sampling per family, spread across files) |
| file | 709 | containing file's context confirmed (grep/read of the file's API usage inventory) |
| region | 74 | function-level verification where CSV anchors drifted ±5–23 lines |

All 1665 rows carry a rationale; all 260 unique files in the CSVs were context-checked at least once.

## 7. Audit notes

1. **CSV line drift**: extraction CSV line numbers come from CodeQL DB coordinates, which are offset
   0–33 lines from the on-disk tree for some files (DB built from a slightly different revision).
   Agents matched sites semantically (per-file grep of the API usage) and recorded actual on-disk
   lines in `evidence`; `location.line` preserves the original CSV coordinate for traceability to the
   extraction step. One row (K-174, hostname.py:544) could not be reconciled and is `unknown`.
2. **Sanitizer entry**: `shlex_quote` (P2-SAN-001) is the single sanitizer; it was added by the lead
   labeler from source reading (basic.py:1915-1916, action/__init__.py:1037), not from the candidate
   CSVs — flagged as such in metadata notes and in its rationale.
3. **Schema**: both `labels.json` and `labels_raw_pass2.json` pass a hand-rolled validation of all
   `assets/labels_schema.json` constraints (required fields, enums, confidence range, arg_index
   constraints for `argument` flow_kind, pass_id 1 presence). Pass 1 is an empty-entries placeholder
   per user instruction (schema `contains` requires pass_id 1).
4. **No ground truth consulted**: PyVul ground truth / fix commits were not read; the source tree and
   databases were not modified.
