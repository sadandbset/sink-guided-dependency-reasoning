# Label Statistics - Augur Phase 1 Step 3 (Pass 2, CWE-78)

- run_id: `abilian-devtools-iris-pass2-step3-20261014`
- generated_at: 2026-10-14T07:25:10+00:00 (re-verified re-run of the 02:24:37+00:00 emission: every labeling decision independently re-checked against the DB snapshot, then regenerated via `gen_labels_pass2.py`; decisions unchanged)
- model: `glm-5.3`
- project: `abilian-devtools`
- candidate rows processed: 2 sink + 0 source = **2** (both mapped 1:1, none silently dropped) + **1 supplementary** entry from an analyzed extraction gap
- label entries emitted: **3**

## Evidence source (important)

All labeling evidence was taken from the **CodeQL DB creation-time source snapshot** (`abilian-devtools-db/src.zip`), because the extraction CSV rows match it exactly (`run` @ main.py:14, `os.system` @ main.py:16) while the on-disk `src/` tree in `abilian-devtools_vuln` has diverged (no `os.system`; `shlex.split` + `subprocess.Popen` list-form at different lines). Phase 2 taint queries run against the DB, so the DB snapshot is the authoritative analysis target. No ground-truth/fix-report files (vulnerability review report, `cmd_sinks*.csv`, safe-db, git history) were read.

## Entries by role

| role | count |
| --- | --- |
| source | 1 |
| sink | 2 |
| sanitizer | 0 |
| summary | 0 |
| none | 0 |

## Entries by classification

| classification | count |
| --- | --- |
| tp | 3 |
| fp | 0 |
| candidate | 0 |
| unknown | 0 |

## Sinks (tp)

- `system` (os), arg 0, shell-interpreted command string @ src/abilian/devtools/main.py:16 - conf 0.9
- `run` (abilian.devtools.main), param 0 -> `os.system(cmd)` wrapper @ src/abilian/devtools/main.py:14 - conf 0.85

## Sources (tp)

- `check` (abilian.devtools.main), param 0 - `args: list[str]` of the `@app.command()` handler `adt check <names>` @ src/abilian/devtools/main.py:22 - conf 0.8 (**supplementary**, not a CSV row: `sources.csv` is empty, see below)

## Sanitizers

None labeled. `Path(arg).exists()` (main.py:26) is an existence filter, not command sanitization - an existing attacker-named file (e.g. containing `;` or `$(...)`) still passes it and is interpolated unquoted into the shell command. `MySanitizers.qll` in Phase 2 should use the `none()` fallback per WORKFLOW.md 5.2.3.

## Source CSV is empty - extraction gap

`extraction/sources.csv` has 0 rows. Root cause: `sources.ql`'s `isTyperHandler` binds `f.getADecorator()` to an `Attribute`, but every handler here is decorated with a **Call** expression (`@app.command()`, `@app.command("security-check")`, `@app.callback()`), so the binding never matches and zero source rows are emitted. The `typer.Argument`/`typer.Option` and `sys.argv` families also yield no rows (unused in this codebase). Compensated by supplementary entry `p2-supp-001`; `MySources.qll` must source Typer command-handler parameters in Phase 2 or the pass-2 query has no source and produces zero paths.

## Batch / re-ask policy

- `sinks-01` (2 rows): both sink candidates, all `run()` call sites and the args -> args_str -> f-string chain reviewed.
- `sources-01` (0 rows): empty-CSV root-cause analysis + supplementary entry.
- `recheck-01`: no entry below the 0.55 threshold; minimum emitted confidence is 0.8.

## Deduplication

- DR-1: no exact duplicate rows in either CSV; nothing dropped silently.
- DR-2/DR-3: each sink signature occurs at exactly one site; no merge decisions arose.
- DR-4: non-CSV supplementary entries use the `p2-supp-*` id prefix and are flagged for reviewer attention.
- DR-5: source-side families that yielded 0 rows are documented (not deleted).
- Full per-row audit trail: `labels/labels_raw_pass2.json`.
