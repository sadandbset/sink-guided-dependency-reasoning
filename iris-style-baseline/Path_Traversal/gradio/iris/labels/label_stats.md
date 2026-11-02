# Augur Phase 1 Step 3 — Label Statistics (Pass 1: Path Traversal)

- **Run ID:** `gradio-pathtraversal-pass1-20261022`
- **Project:** gradio 2.5.0 (path_traversal corpus, `gradio/` package scope)
- **Language / framework:** Python / Flask (gradio serves its UI through Flask; no gradio-specific reference exists, `references/flask.md` was the matching framework reference)
- **Labeling model:** glm-5.3 (in-session LLM API candidate labeling via Claude Code CLI; every candidate traced against the real sources in `gradio_vuln`)
- **Schema:** `labels.json` validated locally against `augur-0.3.0/assets/labels_schema.json` (Draft 2020-12 + format checker) — **VALID**
- **Generated:** 2026-10-22

## 1. Candidate coverage

| Input | Rows | Labeled | Exact duplicates removed |
| --- | --- | --- | --- |
| `extraction/sources.csv` | 64 | 64 | 0 |
| `extraction/sinks.csv` | 50 | 50 | 0 |
| **Total** | **114** | **114** | **0** |

Duplicate check key: `(nodeRepr, receiver, filePath, line, argIndex)`. Distinct class overrides of the same callable (e.g. the 19 `save_flagged` rows) are distinct API signatures and were all retained. No rows were dropped; every candidate received a role.

Batches (5 total, stable sizes, no re-asks — no entry fell below the 0.55 confidence threshold after code tracing):

| Batch | Scope | Samples |
| --- | --- | --- |
| 1 | sources.csv rows 1–19 (`save_flagged` family) | 19 |
| 2 | sources.csv rows 20–44 (`restore_flagged`, `save_flagged_file`, `preprocess` family) | 25 |
| 3 | sources.csv rows 45–64 (`process_single_file`, `process`/`interpret`, `flag_data`, `queue.push`, request accessors, route params) | 20 |
| 4 | sinks.csv rows 1–25 (FFmpeg, `NamedTemporaryFile` family, image/plot/audio writes, dir ops, `shutil.move`) | 25 |
| 5 | sinks.csv rows 26–50 (`open()` family, `send_file`, `getsize`, `AudioSegment.from_file`, `shutil.copy2`, `os.remove`) | 25 |

## 2. Label counts

### By role (all 114 entries)

| Role | Count |
| --- | --- |
| source | 39 |
| sink | 17 |
| sanitizer | 0 |
| summary | 0 |
| none | 58 |

### By role × classification

| Role | tp | fp | candidate | unknown |
| --- | --- | --- | --- | --- |
| source | 38 | 25 | 1 | 0 |
| sink | 15 | 33 | 2 | 0 |
| none (role) | — | 58 (all fp) | — | — |
| **Total** | **53** | **58** | **3** | **0** |

The 58 `none`/fp entries break down as: fixed-constant paths (`VERSION_FILE`, `JSON_PATH`, `DB_FILE`, `log_fp`), BytesIO targets (PIL/matplotlib/`send_file`), `tempfile` calls with literal or absent prefix/suffix, developer-configuration paths (`css`, `examples`, `flagging_dir`, component labels), auth-only form fields, `json.dumps`-only flagging/restore overrides, and the `enable_sharing` route param (stored to config only).

### Confidence distribution

| Group | ≥ 0.8 | 0.6–0.79 | < 0.6 |
| --- | --- | --- | --- |
| Sources (64) | 22 | 41 | 1 |
| Sinks (50) | 39 | 9 | 2 |

The only sub-0.6 entries are the three `candidate` classifications (S51 0.50, K25 0.55, K45 0.55) — uncertainty labels for human review, not low model confidence.

## 3. Top high-risk sinks (pass 1)

| ID | API | Location | Conf. | Why |
| --- | --- | --- | --- | --- |
| K41 | `open` arg 0 | gradio/inputs.py:1180 | 0.95 | `open(file_name, 'rb')` where `file_name = f['name']` (client-supplied) whenever the **client-settable `is_example`** flag is true and File type is `bytes` — arbitrary file read returned into the response pipeline |
| K47 | `shutil.copy2` arg 0 | gradio/processing_utils.py:168 | 0.95 | `create_tmp_copy_of_file(file_path)` copies the client-supplied `name` when `is_example` is true (inputs.py:917, 1001, 1175) |
| K35 | `open` arg 0 | gradio/networking.py:382 | 0.90 | `/file/<path:path>` route variable joined under `app.cwd`; **`secure_filename` (line 380) is not imported** — unresolved name, not a working barrier |
| K44 | `send_file` arg 0 | gradio/networking.py:388 | 0.90 | Same route variable into `send_file(os.path.join(app.cwd, path))` |
| K42 | `send_file` arg 0 | gradio/networking.py:143 | 0.85 | `/static/<path:path>` sink; `safe_join` containment is an effective barrier here (expect sanitized-FP filtering) |
| K03/K04 | `tempfile.NamedTemporaryFile` | gradio/processing_utils.py:149,151 | 0.80 | In the flagging flow the prefix/suffix derive from the client data-URI header without separator filtering — a suffix containing path separators can redirect file creation outside the temp dir |
| K02 | `FFmpeg` | gradio/inputs.py:926 | 0.75 | Subprocess file read/write on temp-derived paths whose prefix/extension come from the client `name` |

## 4. Top source boundaries (pass 1)

| ID | Boundary | Location | Conf. | Why |
| --- | --- | --- | --- | --- |
| S43 / S45 | `File.preprocess` / `process_single_file` | gradio/inputs.py:1161 / 1171 | 0.95 | Request dict carries client `name` + client-settable `is_example` → direct path use |
| S64 | `file(path)` route param | gradio/networking.py:379 | 0.90 | URL path variable → `os.path.join(app.cwd, path)`; sanitizer unresolved |
| S54 | `request.json["data"]` | gradio/networking.py:192 | 0.90 | Root `/api/predict` payload → `Interface.process` → component preprocess path flows |
| S46 | `Interface.process(raw_input)` | gradio/interface.py:363 | 0.90 | Internal dispatch boundary for the same flow |
| S62 | `static_resource(path)` route param | gradio/networking.py:139 | 0.90 | URL path variable → `safe_join` (sanitized at sink) |
| S33 / S42 | `Audio/Video.preprocess(x)` | gradio/inputs.py:989 / 906 | 0.90 | Same `name`/`is_example` pattern as File |
| S03–S06, S10–S13, S30 | `save_flagged` / `save_flagged_file` `data` | inputs/outputs/component | 0.75–0.80 | Flagged request base64 reaching the temp-file write path (suffix edge) |
| S31–S44 (scalar ones) | `preprocess(x)` overrides | gradio/inputs.py | 0.60 | Genuine request boundary, no path use in package — kept for conservative recall |

## 5. Sanitizers

**0 sanitizer entries.** The Phase 1 candidate CSVs contain no sanitizer API candidates. Call-site barriers verified in source and documented in entry evidence / `phase1_review.md`:

- `safe_join(STATIC_PATH_LIB, path)` — werkzeug containment, **effective** (networking.py:143)
- `secure_filename(path)` — **not imported** in networking.py (only `safe_join` from `werkzeug.security`), unresolved name, **must not be modeled as a barrier**
- `os.path.basename` in `create_tmp_copy_of_file` / `decode_base64_to_file` — strips separators, effective for prefix/extension, but **not** applied to the mime-header extension in the `file_path=None` flagging flow
- component.py:52 label charset filter (`alnum` + `._- `) — excludes separators, effective for the flagging dir name

`MySanitizers.qll` should be generated with the `none()` fallback unless the human reviewer adds `safe_join` (and an imported-and-working `secure_filename`) as sanitizer signatures at Step 4.

## 6. Summaries

**0 summary entries.** Standard CodeQL call-edge data flow covers the observed wrapper propagation (`decode_base64_to_file`, `create_tmp_copy_of_file`, `encode_*`, `flag_data`). The wrapper list in `exploration/detection.json` is preserved in `phase1_review.md` as a Step 4 fallback if recall is low.

## 7. Unresolved / human-review entries

| ID | Entry | Issue |
| --- | --- | --- |
| S51 | `flag_data` param `flag_index` | request JSON used as CSV row index; not a path parameter; relevance unclear |
| K25 | `shutil.move` arg 1 (component.py:65) | destination index-based, but extension ultimately derives from the client data-URI header (see K03 edge) |
| K45 | `os.path.getsize` (outputs.py:545) | genuine stat-read position, but `y` is the predict function's return, not request-derived in gradio's own flow |

Plus the two exploitability questions (not label uncertainty): whether the `/file` route's `secure_filename` NameError blocks the flow at runtime, and whether the tempfile-suffix injection is reachable end-to-end (see `phase1_review.md`).
