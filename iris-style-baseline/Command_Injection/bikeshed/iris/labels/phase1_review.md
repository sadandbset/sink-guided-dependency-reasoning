# Phase 1 Review - Augur Step 3 LLM Labeling (Pass 2, CWE-78)

- **run_id:** `bikeshed-iris-pass2-step3-20261013`
- **generated_at:** 2026-10-13
- **model used for labeling:** `glm-5.3` (via Claude Code CLI)
- **scope:** Pass 2 only, narrowed to CWE-78 (Augur's default Pass 2 set 077/078/088 was narrowed per experiment scope). Pass 1 block in `labels.json` is an empty, schema-required compatibility placeholder — **no CWE-22 analysis was performed**.
- **status:** ⏸ **STOPPED at the human review gate.** Phase 2 (library/query generation, taint runs) will not start until this review is approved. No `review_decision.json` was written — that is the reviewer's call.

## 1. Label counts by pass and role

| pass | entries | source | sink | sanitizer | summary | none |
| --- | --- | --- | --- | --- | --- | --- |
| 1 (placeholder) | 0 | - | - | - | - | - |
| 2 (CWE-78) | 49 | 14 | 20 | 0 | 3 | 12 |

By classification: **15 tp**, **10 candidate**, **24 fp**, 0 unknown.

Candidate rows processed: 153 source + 26 sink = **179**, all mapped to entries (audit trail in `labels_raw_pass2.json`; dedup rules DR-1…DR-5; nothing silently dropped).

## 2. Top high-risk sinks (role=sink, classification=tp)

| API | site | why it matters |
| --- | --- | --- |
| `subprocess.Popen` arg 0, `shell=True` | `bikeshed/inlineTags/__init__.py:14` | **The canonical CWE-78 chain of this codebase.** `command = doc.md.inlineTagCommands[tag]` — the "Inline Tag Command" metadata value parsed from the external spec input (file / `-` stdin / `https:` URL) via `metadata.parse`. `innerHTML(el)` is additionally piped to the command's stdin. |
| `processTags(doc)` wrapper | `bikeshed/inlineTags/__init__.py:7` | param-level wrapper sink of the above. |
| `os.system` arg 0 | `bikeshed/cli.py:669` | `bikeshed profile --root/--leaf/--svg` CLI values formatted into a shell pipeline; f-string quoting (`--root="…"`) does not prevent shell breakout. |
| `os.system` arg 0 | `bikeshed/cli.py:675` | same pattern, `/tmp` + `xdot` variant. |
| `handleProfile(options)` wrapper | `bikeshed/cli.py:665` | CLI options → os.system strings. |

**Sink ≠ vulnerability.** Per the labeling standard, `classification=tp` on a sink means attacker-influenced data demonstrably flows toward the dangerous *argument position* (the command string), not that an exploitable vulnerability is confirmed. Exploitability depends on deployment: for the Popen chain, the spec input is third-party document content (processing an untrusted `.bs`/`.src.html` file, e.g. in CI, is the realistic threat); for `handleProfile`, the CLI user is local. Also note `shell=True` vs. argument-list form was checked at every site (see §5).

## 3. Top broad source APIs

| API | classification | note |
| --- | --- | --- |
| `InputSource.read` family (stdin / file / https URL, `bikeshed/InputSource.py:118-169`) | tp | the true external boundary of the tool; spec content reaches `md.inlineTagCommands` |
| `argparse.ArgumentParser.add_argument` (75 merged sites) | candidate | broad by construction — declares the whole CLI surface; see the modeling caveat in §7 |
| `requests.get` (`InputSource.py:137`) | tp | only as the URL spec-input fetch; the other 12 `requests.get` sites were refuted (fp) for CWE-78 |

## 4. Sanitizer list

**None.** No sanitizer API was extracted or observed. The only neutralization evidence in the codebase is the argument-list, no-shell invocation `subprocess.check_output(["git", "remote", "-v"], cwd=…)` at `bikeshed/metadata.py:1169` (recorded as `p2-sink-012`, role=none). Phase 2 must keep the mandatory `isBarrier` predicate with `none()` fallback per WORKFLOW.md 5.2.3.

## 5. Refuted sink candidacies (fp) — distinguishing dangerous parameters from proven risk

All of these are command-execution APIs (so the *argument position* is genuinely dangerous in general), but at these specific sites the command argument is provably untainted:

- `bikeshed/boilerplate.py:36,49` — literal `git remote -v` / `git log` commands, `cwd=config.scriptPath()` (install dir).
- `bikeshed/boilerplate.py:92,103` — literal `git rev-parse HEAD` / `hg parent`; `cwd=doc.inputSource.directory()` is document-derived, **but cwd is not the command argument** (residual git-config-in-attacker-repo risk is outside CWE-78 argument injection).
- `release.py:14,65,80,81,109,117,122,128` — all literal commands (`git diff --stat`, `git log`, `rm -r build dist`, `python setup.py sdist bdist_wheel`, `git add …`, `git push`, `git remote -v`).
- `addBikeshedVersion` / `addSpecVersion` / `getSpecRepository` / `createRelease` / `inBikeshedRoot` wrappers — parameters never flow into command strings; `getSpecRepository` additionally uses the safe list-form (see §4).

Retained as **candidate** (local-file interpolation into `shell=True` strings, not external input): `release.py:83,97` (secrets.json → twine `--password`), `release.py:121` (`semver.txt` → `git commit -m` f-string; paired source candidate `release.py:23`).

## 6. Unresolved / low-confidence items (candidate classification, for reviewer attention)

- `p2-src-008` argparse `add_argument` family (conf 0.60) — broad CLI source; see §7 caveat.
- `p2-src-009` `parse_args` return (fonts.py:218, conf 0.60) — CLI value materialization point, no command route observed at this site.
- `p2-src-010/011/012` fonts stdin/file, issuelist open (conf 0.55) — external reads with no observed command route; issuelist was re-checked once after falling below 0.55 per WORKFLOW 4.4.4.
- `p2-src-013/014` + `p2-sink-018/019/022` — the release.py local-file → shell interpolation pairs (conf 0.55-0.60).
- `p2-sum-002` `metadata.fromCommandLine` (conf 0.70) — `--md-Inline-Tag-Command=…` on the CLI can set an inline tag command; CLI user is local, so exploitability is deployment-dependent.

## 7. Quality checks and known gaps

1. **Schema validation:** `labels.json` PASSES the local `assets/labels_schema.json` (validated by the embedded draft-2020-12-subset validator in `gen_labels_pass2.py`; the `jsonschema` package is not installed in this environment). The schema's `contains` constraint forces a `pass_id: 1` entry — satisfied by the empty placeholder.
2. **At least one sink per enabled pass:** Pass 2 has 5 tp sinks (incl. wrappers). ✔
3. **Duplicates removed / merges documented:** DR-1 (75 add_argument rows), DR-2 (12 requests.get rows), DR-3 (45 internal open() rows); sink rows deliberately not merged (DR-4); no exact duplicate rows existed (DR-5). Full per-row mapping in `labels_raw_pass2.json`. ✔
4. **Argument index bounds:** all `flow_kind=argument` entries carry `arg_index=0` (the command-string parameter for `Popen/os.system/check_output/check_call/call`), matching the CSV. ✔
5. **Extraction completeness cross-check:** an independent repo-wide grep for `subprocess|os.system|os.popen|Popen|pexpect` confirms the sink CSV covers every command-execution site; no `os.popen`/`pexpect` usage exists. ✔
6. **Known extraction gap (Phase 2 must compensate):** `cli.py:432` `argparser.parse_known_args()` — the point where CLI values materialize — was **not** extracted as a source candidate. `MySources.qll` must map the add_argument decision onto parsed option values (e.g. `parse_args`/`parse_known_args` returns or handler `options` parameters) or the `handleProfile` path will never fire.
7. **Threat-model note:** Bikeshed is a local CLI tool. "External input" here means (a) spec document content (file/stdin/https URL — third-party content, the realistic CWE-78 vector), and (b) CLI arguments (local user; attacker-relevant only when bikeshed is invoked on untrusted input in CI/service-like contexts). Source labels reflect this split (spec boundary = tp, CLI surface = candidate).

## 8. Labeling standard (AutoGluon-consistent, applied independently)

Roles per WORKFLOW.md 7.1 rubric + references/python.md: `source` = externally controllable input boundary; `sink` = command-execution API with its dangerous argument position identified, wrappers only when the parameter can reach the command argument; `sanitizer` only with concrete neutralization evidence (none found); `summary` = taint-propagating internal helper; `none` = unrelated. `classification` records evidence strength (tp / fp / candidate), never a vulnerability verdict. Conservative recall was preferred for boundary candidates; over-broad internal-parameter sources were avoided per references/python.md §7.4. AutoGluon's own workspace/labels were not read — only the shared standard was reproduced.

## 9. Reproducibility

Artifacts: `labels.json` (schema-valid), `labels_raw_pass2.json` (179-row audit trail + batches + dedup rules), `label_stats.md`, `phase1_review.md`, generator `gen_labels_pass2.py` (deterministic: fixed decision tables, no LLM call at generation time — the LLM decisions are the reviewed tables above).

**Next step (blocked):** human review of this document → `review_decision.json` → Phase 2 Step 4 (generate `MySources/MySinks/MySanitizers/MySummaries.qll`).
