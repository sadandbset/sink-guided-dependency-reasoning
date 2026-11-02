# Pass 2 (CWE-78 Command/Argument Injection) — Label Statistics

Project: yt-dlp (source tree `dataset/codeql_databases/yt-dlp_vuln`, sha 61bdf15)
Workspace: `iris_manual/yt-dlp/iris`
Step: Augur Phase 1 Step 3 — LLM API candidate labeling
Date: 2026-10-19

## LLM run accounting

| Item | Value |
| --- | --- |
| Model actually used | `glm-5.3` operating as the Claude Code CLI agent (LLM API labeling; deterministic single pass, temperature-0 semantics) |
| Batches | 14 (B1–B14, see table below) |
| Candidates processed | **7204 rows — all rows of both CSVs** (sources.csv 7034 + sinks.csv 170) |
| Re-ask passes | 0 (low-confidence rows were resolved by direct source inspection and are flagged for human review instead) |
| Ground truth consulted | none (no PyVul truth files, no fix commits, no external advisories) |

## Batch table

| Batch | Scope | Rows |
| --- | --- | --- |
| B1 | source: remote decode/fetch boundaries (json.loads/load, read, recv, urlopen, _download_* returns) | 3033 |
| B2 | source: decoder/parse helpers labeled as taint steps (summaries) | 921 |
| B3 | source: extractor entry points and internal plumbing params | 1923 |
| B4 | source: downloader/postprocessor entry params (real_download, PP run, parse_cmd) | 57 |
| B5 | source: CLI option definitions and opts.<attr> reads | 826 |
| B6 | source: config/env boundaries (get_param, _configuration_args, environ, read_file, read_stdin) | 205 |
| B7 | source: file inputs (open, load_cookies, extract_cookies_from_browser) | 64 |
| B8 | source: CLI entry argv params (parseOpts, _real_main, main, parse_options) | 5 |
| B9 | sink: shell=True string-command sites (ExecPP --exec, --netrc-cmd, updater atexit) | 13 |
| B10 | sink: Popen wrapper/call sites, version probes, xattr, keyring helpers, bidi workaround | 17 |
| B11 | sink: external downloaders, ffmpeg/AtomicParsley argv builders | 14 |
| B12 | sink: rtmp/rtsp/openload/sponskrub/updater/devscripts/setup sites | 18 |
| B13 | sink: test-file rows (site-level FP) | 25 |
| B14 | sink: command/argv construction expressions (cmd_format/cmd_build/percent_format/list_concat, os.replace) | 83 |
| **Total** | | **7204** |

## Per-row (raw) label distribution — `labels_raw_pass2.json`

| Role | Rows |
| --- | --- |
| source | 5211 |
| summary | 925 |
| none | 985 |
| sink | 83 |
| sanitizer | 0 |

| Classification | Rows |
| --- | --- |
| candidate | 5884 |
| fp | 1320 |
| unknown | 0 |
| tp | 0 |

- production rows: 6803; test-file rows: 343; devscript/build rows: 58 (both site-level fp, per the global test-file heuristic).
- needs_human_review (confidence < 0.55): **97 rows** — all construction-expression and flag/selector candidates judged low-value; listed per-row in the raw artifact.
- No row was left unlabeled and no row was dropped from the raw artifact.

## Deduplicated entries — `labels.json` (pass 2 block)

| Role | Entries |
| --- | --- |
| source | 81 |
| sink | 18 |
| summary | 19 |
| none | 62 (documented FP/covered-wrapper decisions) |
| sanitizer | 0 |
| **Total** | **180** |

Schema validation: `assets/labels_schema.json` (draft 2020-12) — **PASS** (validated with the `jsonschema` package).

## Deduplication and exclusion accounting

All 7204 rows are handled; the following reductions to 180 entries are recorded:

1. **Call-site / definition merging (8189 → distinct signatures).** Families whose
   per-extractor call sites collapse to one declaring signature, e.g.:
   - `_real_extract` param rows: 1727 → 1 entry (`InfoExtractor._real_extract`, param 0)
   - `_download_json` / `_download_webpage` call sites: 1222 / 1140 → 1 entry each
   - `_parse_json` parse call sites + definition rows: 412 → 1 entry
   - `get_param` reads: 146 → 1 entry; `read`: 145 → 1; `recv`: 21 → 1; `open`: 58 → 1
   - `json.loads`: 190 rows (95 `api` + 95 `ast` rows overlapping the same sites) → 1 entry
2. **api/ast duplicate pairs in sinks.csv** (subprocess.call/Popen/run at exec.py:31,
   rtsp.py:27, setup.py:119, devscripts/utils.py:46, generate_aes_testdata.py:25 and the
   test files) merged into single site records.
3. **Test/dev-only signatures excluded from labels.json entries (36 rows, 19 signatures)**
   — no production call sites exist, so nothing to model; rows remain labeled (fp) in the
   raw artifact: `subprocess.Popen` (test_overwrites/test_verbose_output/generate_aes_testdata,
   14 rows), `subprocess.check_call` (4), `subprocess.run` (4, setup.py + devscripts),
   `run_process`, `openssl_encode`, setup.py `run`, `Test*` wrapper functions (8),
   devscript `opts` reads (3). The production exec surface uses the `yt_dlp.utils.Popen`
   wrapper and `subprocess.call` only.
4. **Non-command CLI option reads excluded from entries: 361 rows across 175 option
   attributes** (flags, selectors, credentials, display options — e.g. `verbose`,
   `quiet`, `simulate`, `format`, `retries`, `username`, `password`, `writethumbnail`).
   These opts.<attr> reads have no path into command construction for pass 2 and are
   labeled role=none/fp in the raw artifact; the command-relevant 42 attributes are
   retained as source entries.
5. **Role=none "covered" wrapper entries** retained deliberately (8 wrappers:
   `YoutubeDL.__init__`, `ExecPP.run`, `SponSkrubPP.run`, `EmbedThumbnailPP.run`,
   `_get_netrc_login_info`, `RtspFD.real_download`, `Updater.restart`,
   `PhantomJSwrapper.execute`): their exec APIs are labeled as sinks directly and their
   entry parameters are labeled as sources, so a wrapper-level sink would only create
   trivial self-paths.
6. **Display/debug formatting rows** (YoutubeDL.py:3907–3995 debug header, ffmpeg
   to_screen/write_debug strings, error-message strings) → role none/fp.

## notes

- `arg_index` convention: 0-based positional index **excluding** `self`/`cls` for
  `param` flow kinds, and 0-based call-argument index for `argument` flow kinds.
- The `atexit.register` sink uses `arg_index: 1` (the command-string position); the
  CSV row carried `argIndex: 0` because it marked the `Popen` callable argument.
- `labels.json` contains an empty pass_id 1 block solely to satisfy the schema's
  `passes.contains {pass_id: 1}` constraint; no pass-1 labeling was performed
  (scope was pass 2 / CWE-78 only).
- Build script: `labels/build_labels_pass2.py` (decision table + mechanical expansion;
  rerunnable, regenerates both JSON artifacts deterministically).
