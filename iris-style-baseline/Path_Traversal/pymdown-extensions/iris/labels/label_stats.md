# Augur Phase 1 Step 3 — Label Statistics (Pass 1: Path Traversal)

- **Project:** pymdown-extensions (vuln snapshot, `pymdownx` 9.11.0 final)
- **Run ID:** `pymdown-extensions-iris-phase1-step3-pass1`
- **Generated:** 2026-10-23T01:24:35Z
- **LLM model:** `glm-5.3` (labeling performed in-context by the session LLM via the Claude Code CLI harness; one deterministic pass per batch plus one re-ask round for sub-threshold entries)
- **Language / framework:** python / none (no web framework — host-library boundary: Python-Markdown extension architecture)
- **Pass:** 1 — CWE-022 / CWE-023 / CWE-036 / CWE-073 (Path Traversal)
- **Schema validation:** `labels.json` **PASSED** local validation against `augur-0.3.0/assets/labels_schema.json` (Draft 2020-12 + format checker)

## Input coverage

| Input | Candidate rows | Entries emitted | Note |
| --- | --- | --- | --- |
| `iris/extraction/sources.csv` | 15 | 14 | 1 exact duplicate row pair deduplicated |
| `iris/extraction/sinks.csv` | 59 | 59 | no duplicates found |
| **Total** | **74** | **73** | every candidate row processed; none skipped |

**Deduplication (1):** sources.csv rows 13–14 are identical rows for the two `m.group('snippet')`
calls of the inline conditional on `pymdownx/snippets.py:258` (same location, same role, same
downstream flow) → merged into entry `p1-s12`.

## Batches (5)

| Batch | Scope | CSV rows | Entries |
| --- | --- | --- | --- |
| batch-1 | Source candidates (all files) | 15 | 14 |
| batch-2 | Sinks in `pymdownx/b64.py` | 8 | 8 |
| batch-3 | Sinks in `pymdownx/snippets.py` + `pymdownx/util.py` | 15 | 15 |
| batch-4 | Sinks in `pymdownx/pathconverter.py` + `run_tests.py` | 11 | 11 |
| batch-5 | Sinks in `tools/` + `hatch_build.py` (dev/build tooling) | 25 | 25 |

Re-ask round (batch policy threshold < 0.55): `p1-k09` (ZipFile, 0.5→0.55, kept sink/candidate),
`p1-k19` (basename sanitizer, 0.5→0.55, kept sanitizer/candidate). No entry remains below 0.55.

## Label counts by role

| Role | Count | Entries |
| --- | --- | --- |
| source | 7 | `p1-s01`, `p1-s02`, `p1-s03`, `p1-s11`, `p1-s12`, `p1-s13`, `p1-s14` |
| sink | 4 | `p1-k08` (b64 open), `p1-k55` (snippets codecs.open) — tp; `p1-k09`, `p1-k10` (gen_emoji archive) — candidate |
| summary | 13 | b64 decode/join chain (k01–k05), snippets resolution chain (k45, k48, k52, k54), util helpers (k56–k59) |
| sanitizer | 1 | `p1-k19` (gen_emoji.py:66 `basename`) — candidate, scoped to the dev-tool download path only |
| none | 48 | pathconverter (10), run_tests (3), tools fixed-constant paths (14), dev/tool gates and oracles, b64/snippets stat gates |
| **Total** | **73** | |

## Label counts by classification

| Classification | Count |
| --- | --- |
| tp | 20 (5 sources, 2 sinks, 13 summaries) |
| fp | 48 |
| candidate | 5 (`p1-s03`, `p1-s11`, `p1-k09`, `p1-k10`, `p1-k19`) |
| unknown | 0 |

## Entries by file

| File | Entries | Roles present |
| --- | --- | --- |
| pymdownx/snippets.py | 16 | source 4, sink 1, summary 4, none 7 |
| tools/gen_emoji.py | 14 | source 1 (cand.), sink 2 (cand.), sanitizer 1 (cand.), none 10 |
| pymdownx/pathconverter.py | 13 | none 13 |
| pymdownx/b64.py | 10 | source 2, sink 1, summary 5, none 2 |
| pymdownx/util.py | 4 | summary 4 |
| tools/gen_gemoji.py | 4 | none 4 |
| tools/gen_twemoji.py | 4 | none 4 |
| tools/gen_emoji1.py | 3 | none 3 |
| run_tests.py | 3 | none 3 |
| tools/gen_joypixels.py | 1 | none 1 |
| hatch_build.py | 1 | none 1 |

## Confidence

- Range 0.55–0.95, mean 0.862.
- Confirmed-tp sink confidence: 0.95 (`p1-k08`, `p1-k55`); confirmed-tp sources 0.9–0.95.

## Top high-risk findings feeding Phase 2

1. **Snippets include traversal (tp):** `snippets.py:258`/`:276` (source) → `get_snippet_path`
   (`:155`) → `os.path.join` (`:162`/`:170`) → `codecs.open` (`:311`, sink) — no containment,
   no `..`/absolute rejection; nested includes recurse (`:333-341`).
2. **B64 img-src traversal (tp):** `b64.py:73` (source) → `util.parse_url`/`util.url2path` →
   `os.path.join`/`normpath` (`:80`, absolute branch `:78`) → `open` (`:86`, sink) — absolute
   `file://`/`c:/`/UNC/leading-`/` forms read outside `base_path` by construction; entity and
   percent decoding happens **before** the join.
3. **gen_emoji zip-slip (candidate, human review):** GitHub API `zipball_url` (`:112`) →
   `basename`+`.zip` write (`:66`/`:73`) → `ZipFile`/`extractall` (`:44`/`:45`) with no member
   validation; semi-trusted source, maintainer dev tool.

## Sanitizer verdict

**None for the two library pipelines.** No base-directory containment, no `..` rejection, no
absolute-path rejection exists anywhere between the Markdown-born path and the file read in
`snippets.py` or `b64.py`. `normpath`, `url2path`/`url2pathname`, `parse_url` and `html.unescape`
are decode/propagation steps (labeled `summary`) that widen, not narrow, the attack surface.
The only sanitizer label (`gen_emoji.py:66` basename) is conditional and does not protect the
`extractall` at `:45`.

## Exclusion / none rationale summary

- **pathconverter.py (10 sink rows + 3 source rows → none):** verified pure string rewriting; no
  filesystem API in the module; output is rewritten link text.
- **run_tests.py / hatch_build.py (none):** trusted operator CLI / build-hook paths; deliberate
  authorized access; no untrusted boundary.
- **tools/gen_emoji1, gen_gemoji, gen_joypixels, gen_twemoji (none):** all paths are fixed
  literals or `__file__`/hardcoded-repo-name derivatives; no attacker input.
- **file_stat gates (`exists`/`isdir`/`isfile`) and `splitext` (none):** oracles and type probes,
  not read/write/delete; TOCTOU windows noted in rationales.
- **`snippets.py:167` basename (none):** applied to the operator `base` entry, never to the
  attacker path — function name alone is not sanitizer evidence.
- **tests/ and `pymdown-extensions-db/`:** already excluded at extraction time (noise rule); no
  label entries exist for them.

## Human-review queue (classification = candidate)

| ID | Location | Question |
| --- | --- | --- |
| `p1-s03` | tools/gen_emoji.py:112 | Is the GitHub API `zipball_url` trusted enough to drop the source? |
| `p1-s11` | pymdownx/snippets.py:210 | Keep the internal recursive `parse_snippets` param as a source, or rely on `run()` only? |
| `p1-k09` | tools/gen_emoji.py:44 | Keep `ZipFile` open as a (conservative) sink? |
| `p1-k10` | tools/gen_emoji.py:45 | Confirm/refute the zip-slip reachability given the semi-trusted source |
| `p1-k19` | tools/gen_emoji.py:66 | Accept `basename`+'.zip' as a sanitizer for the download-write path? |

## Quality checks (per WORKFLOW.md 4.4.6)

1. Schema validation: **passed** (see above).
2. Pass 1 has ≥ 1 sink: yes — 2 confirmed tp sinks (`p1-k08`, `p1-k55`) + 2 candidate sinks.
3. Obvious duplicates removed: yes (1 dedup, recorded in `labels_raw_pass1.json`).
4. Argument index bounds verified: all `flow_kind=argument` entries carry integer `arg_index ≥ 0`
   from the extraction CSV contract; `param` rows carry parameter positions including the `self`
   slot; `return`/`field` rows use `arg_index: null`.

## Artifacts

- `iris/labels/labels.json` (schema-valid)
- `iris/labels/labels_raw_pass1.json` (per-batch raw decisions, dedup + re-ask audit trail)
- `iris/labels/label_stats.md` (this file)
- `iris/labels/phase1_review.md` (review against the 10-point checklist)
- `build_labels.py` (deterministic renderer of the LLM decisions, kept at the workspace parent for
  auditability; writes only into `iris/labels/`)
