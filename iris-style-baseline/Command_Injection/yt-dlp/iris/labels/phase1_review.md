# Phase 1 Review — Pass 2 (CWE-78 Command/Argument Injection), yt-dlp

Human review gate summary (Augur Phase 1 Step 3 → checkpoint). This run was executed
in manual-step mode per operator instruction: **it stops here and does not enter
Phase 2.**

Artifacts: `labels/labels.json` (schema-valid, 180 entries), `labels/label_stats.md`,
`labels/labels_raw_pass2.json` (7204 per-row records), build script
`labels/build_labels_pass2.py`.

## 1. Label counts (pass 2)

| Role | Raw rows | Dedup entries |
| --- | --- | --- |
| source | 5211 | 81 |
| sink | 83 | 18 |
| summary | 925 | 19 |
| sanitizer | 0 | 0 |
| none | 985 | 62 |

Classifications: 5884 candidate / 1320 fp / 0 unknown / 0 tp. **No candidate was
labeled `tp`** — per instruction, no subprocess call was auto-confirmed as a
vulnerability; every site awaits the Phase 2 taint run and path triage.

## 2. Top high-risk sink APIs (priority for Phase 2)

1. `subprocess.call` argument 0 — `postprocessor/exec.py:31`,
   `subprocess.call(encodeArgument(cmd), shell=True)`. The `--exec` /
   `--exec-before-download` command string, %-formatted from **remote info_dict
   fields** (`escape_outtmpl(tmpl) % tmpl_dict` at exec.py:17/30). Shell quoting
   exists only for `%(field)q` conversions and the legacy `{}` placeholder
   (`compat_shlex_quote` at exec.py:24); fields substituted without `q` land
   unquoted in the shell string. Confidence 0.9.
2. `yt_dlp.utils.Popen.run` argument 0 — 19 production sites; includes the second
   shell=True site `extractor/common.py:1311` (`--netrc-cmd`, with
   `netrc_machine` substituted via **unquoted** `str.replace` at common.py:1309).
   Confidence 0.85.
3. `yt_dlp.utils.Popen` constructor argument 0 — aria2c/ffmpeg/rtmpdump argv
   lists built from remote-derived URLs, headers, rtmp fields and filenames
   (`downloader/external.py:395/625`, `downloader/rtmp.py:27`). No shell —
   argument-injection surface only. Confidence 0.8.
4. Wrapper-parameter sinks: `ExternalFD._call_process` (param 0), `FFmpegFD._call_downloader`
   (param 1 — `downloader_options.ffmpeg_args` from extractors, URLs without a `--`
   guard at external.py:578), `real_run_ffmpeg` (param 0), `run_rtmpdump` (param 0),
   `write_xattr` (param 2 — remote metadata value). Confidence 0.55–0.7.
5. `atexit.register` argument 1 — `update.py:376`, Windows updater delayed delete,
   `shell=True` f-string embedding `old_filename` (the program's own binary path —
   program-controlled, not attacker-controlled). Kept as candidate for audit,
   confidence 0.55.

Only these 3 shell=True string-command sites exist in the whole tree: exec.py:31,
common.py:1311, update.py:376. No `os.system` / `os.popen` / `os.exec*` / `os.spawn*`
/ `pexpect` call exists anywhere (verified by extraction; nothing was auto-labeled
from those families).

## 3. Top broad source APIs

- `InfoExtractor._real_extract` param 0 (url) — 1727 rows → 1 entry, confidence 0.6.
- `_download_json` / `_download_webpage` / `_download_xml` / `*_handle` / `_request_webpage`
  returns — 2600+ rows → 9 entries, confidence 0.7–0.85 (factory-generated boundaries).
- `json.loads` / `json.load` returns — 206 rows → 2 entries, confidence 0.75–0.8.
- generic `.read()` returns — 145 rows → 1 entry, confidence 0.6 (receiver-ambiguous;
  network-response, file and stream reads are not syntactically distinguishable —
  this is exactly why it was **not** blanket-labeled at higher confidence).
- `get_param` returns (config/CLI values incl. `netrc_cmd`) — 146 rows → 1 entry.
- Downloader/PP entry params (`real_download` params 0/1, `PostProcessor.run` param 0) —
  recall boundaries, confidence 0.6.

## 4. Sanitizer list

**Empty — no sanitizer entries.** No candidate demonstrated concrete neutralization
of command-injection taint. Observed partial mitigations (recorded, not labeled
sanitizers):

- `exec.py:24` `compat_shlex_quote(filepath)` — quotes only the legacy `{}`
  placeholder, not the outtmpl-substituted fields.
- `--` separators before attacker-influenced positional values
  (`downloader/external.py:223`, `sponskrub.py:83`) — block option injection from
  URLs but sanitize nothing.
- `shlex.split` (`sponskrub.py:81`, `Config.read_file` `_utils.py:4866`) — avoids
  shell-string interpretation by producing argv tokens; the *content* of the tokens
  is untouched.
- `options.py:314-315` CLI alias callback quotes values before argv injection.
- `update.py:82` `re.fullmatch('[0-9a-f]+', ...)` validates the git command's
  *output*, not its input.

`MySanitizers.qll` in Phase 2 should use the `none()` fallback.

## 5. Answers to the six review directives

1. **Does network data pass validation/decryption/protocol parsing before reaching
   plugins, and does that restrict command parameters?** Network bytes enter via
   `urlh.read()` → `__decode_webpage` (charset decode, common.py:970-976) →
   `json.loads` / `_parse_json` / regex extraction / base64 / zlib / manifest
   parsers. None of these steps restricts command-relevant characters: decoding
   and parsing are modeled as **summary** (taint-preserving) steps precisely
   because they do not neutralize. `__check_blocked` (common.py:993) checks for
   geo-block text only.
2. **Can external input, files, config or request params reach system commands?**
   Yes, on two distinct edges: (a) remote metadata → info_dict fields → ExecPP
   outtmpl %-format → `subprocess.call(shell=True)`; remote values → filenames →
   ffmpeg/external-downloader/rtmp argv; remote `http_headers`/cookies →
   `--header`/`--cookie` argv; (b) local config (`--exec`, `--netrc-cmd`,
   `--sponskrub-args`, external-downloader/postprocessor args, `--ffmpeg-location`)
   → command templates and argv (documented features; see item 5).
3. **subprocess/os API argument shapes:** three shapes were distinguished rather
   than blanket-labeled: `shell=True` **string commands** (3 sites, highest
   priority), **argv lists** with remote-derived values (Popen wrapper sites,
   argument-injection surface only), and **fixed constants** (bidiv/fribidi,
   git rev-parse, dbus-send/kwallet-query/security keyring, dev build scripts —
   labeled site-level fp). `os.*` exec APIs are absent from the tree.
4. **Internal functions:** `_real_extract` (param 0) / `real_download` (params 0/1) /
   `PostProcessor.run` (param 0) = **source** (recall boundaries for remote-derived
   data); `_call_process`, `_call_downloader`, `real_run_ffmpeg`, `run_rtmpdump`,
   `write_xattr`, `get_audio_codec`, `get_metadata_object` = **sink** (their
   command-relevant parameters); `_parse_json`, `_search_json(_ld)`,
   `_search_regex(_html)`, `js_to_json`, `parse_qs/unquote*`, `b64decode`,
   `decompress`, `expand_path/expandvars`, `parse_cmd`, the two command-string
   `replace` sites = **summary**; `_request_webpage`/`_webpage_read_content`/
   `_download_webpage_handle` params, `_perform_login` (credentials → HTTP auth
   only), `urlopen` req params = ordinary plumbing (**none**).
5. **Trust boundary between config-file fixed commands and attacker input:** the
   boundary is clear and was respected in the labels. Command *templates*
   (`--exec`, `--netrc-cmd`, tool args) are local-trust values the user configures
   — labeled source only to model the config→command edge, never as attacker
   data. The attacker-controlled side is the remote metadata substituted into
   those templates. `extractor/common.py:1309` is the weak seam: `netrc_machine`
   is inserted into the shell string with a bare, unquoted `str.replace`.
6. **Data checks blocking dangerous characters/illegal arguments:** none found on
   any command path. No allowlist, escaping or character filtering exists between
   the remote metadata and the exec sinks; only the partial mitigations listed in
   §4 (per-placeholder quoting, `--` separators, shlex tokenization).

Also per directive: not all network message fields were auto-labeled source
(`read` capped at 0.6 with receiver-ambiguity rationale; `_perform_login`
credentials, response-handle plumbing params and `PhantomJSwrapper.execute`
labeled none; the openload JS travels via temp **file**, not argv), and not all
subprocess calls were treated as confirmed vulnerabilities (0 `tp` labels; 62
fp-classified entries).

## 6. Unresolved / low-confidence items for the reviewer

- 97 raw rows with confidence < 0.55 (flagged `needs_human_review` in
  `labels_raw_pass2.json`): mostly argv-construction expressions (0.5), flag
  selectors (`useid` 0.4, `outtmpl_na_placeholder` 0.4, `autonumber_*` 0.45) and
  the `atexit.register` updater site (0.55). No `unknown` classifications remain.
- Specific items worth a human decision before Phase 2:
  - `update.py:376` atexec shell string — benign-by-construction per current
    reading (program-controlled path); confirm.
  - `FFmpegFD` argv at external.py:578 passes `fmt['url']` **without** a `--`
    guard (unlike CurlFD/AxelFD/WgetFD at :223/:239/:266) — argument-injection
    candidate to watch in the taint run.
  - `downloader_options.ffmpeg_args` (extractor-supplied, remote-derived) flows
    directly into the ffmpeg child argv — same class of exposure.
  - `write_xattr` passes remote metadata `value`/`path` into setfattr/xattr argv.
- Model/batch accounting: model `glm-5.3` (Claude Code CLI agent), 14 batches,
  7204 rows processed, 0 re-ask passes — see `label_stats.md`.

## 7. Phase 2 readiness notes (informational — not executed)

- `MySinks.qll` can be generated from the 18 sink entries; the three shell=True
  sites are the natural `@precision high` subset, the argv-list sites `low/medium`.
- `MySources.qll` from the 81 source entries; the broad `_real_extract` /
  `_download_*` boundaries will produce high alert volume — the summary entries
  (19) are required for realistic propagation.
- `MySanitizers.qll`: `none()` fallback (empty sanitizer set).
- Pass 1 block in `labels.json` is a schema-compliance stub (empty entries); it
  must not be used to generate pass-1 queries.
