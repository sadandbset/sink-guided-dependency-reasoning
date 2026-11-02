# Phase 1 Review — Pass 2 (CWE-78 Command/Argument Injection), transformers

Human-review checkpoint payload (Augur WORKFLOW.md §4.5). Labeling model: **glm-5.3**
(Claude Code CLI harness), 9 batches, 1087 candidate rows processed.
Raw audit: `labels/labels_raw_pass2.json`; effective labels: `labels/labels.json`
(schema validation: PASS (jsonschema 4.26.0 against assets/labels_schema.json)).

## 1. Label counts

- Rows: {'source': 1029, 'summary': 3, 'none': 30, 'sink': 25} by role; {'candidate': 997, 'tp': 51, 'fp': 39} by classification.
- Effective entries: 38 — source 30, sink 5,
  summary 3, sanitizer 0.

## 2. Top high-risk sink APIs

| Sink | Site | Judgment |
| --- | --- | --- |
| `subprocess.Popen(" ".join(cmd_line), shell=True)` | onnx/__main__.py:59 | **tp (0.8)** — only shell=True site in the package; CLI values (`--model`, `--task`, `--framework`, output path) interpolated unquoted; no shlex.quote anywhere. Exploitability hinges on the trust boundary over CLI args (local user vs wrapper service). |
| `subprocess.Popen(ffmpeg_command)` in `_ffmpeg_stream` | audio_utils.py:221 | candidate (0.6) — caller-built argv list; an input path/device string sits in an argv element: argument-position injection shape only (no shell). |
| `subprocess.check_output(command)` in `run_command` | testing_utils.py:1991 | candidate (0.5) — generic command-list executor, argv form, test helper. |
| `subprocess.run("git config ...")` | commands/lfs.py:87/90 | fp — constant command text; external influence limited to `cwd=` (path semantics). |
| `subprocess.check_output(["git", "--version"])` etc. | user.py:159/165, import_utils.py:570 | fp — fixed argv probes. |

## 3. Top broad source APIs

| Source | Coverage | Notes |
| --- | --- | --- |
| `argparse.parse_args` | 204 rows (2 installed entries + ~201 dev-script mains) | CLI boundary; entry points: transformers_cli.py:47, onnx/__main__.py:232. |
| `json.load` / `json.loads` | 404 rows | Hub-downloaded config/preprocessor JSON (untrusted-repo scenario) + 2 lfs stdin protocol sites (tp). |
| `os.environ` / `os.getenv` | 206 rows | Cache paths, feature flags, integration vars; no observed command flow (recall only). |
| `requests.get/post/put/head` | 80 rows | Network response boundary; lfs URLs taken from stdin JSON (request-target influence). |
| `huggingface_hub.hf_hub_download` / `cached_download` | 89 rows | Hub file content boundary. |
| `sys.stdin` / `sys.argv` | 7 rows | External stdin protocol + raw CLI args (tp). |

## 4. Sanitizer list

Empty — see label_stats.md §Sanitizers. Phase 2 `isBarrier` will resolve to `none()`.

## 5. Unresolved / low-confidence items (manual review requested)

1. **onnx/__main__.py:59 (conf 0.8, classification tp)**: the construction is unambiguously
   dangerous (shell=True + unquoted interpolation); whether the *vulnerability* holds depends on
   the deployment trust boundary over `transformers.onnx` CLI arguments. Needs a human call after
   taint analysis.
2. **audio_utils.py:244 `f"audio={microphone_name}"` (conf 0.4, candidate)**: ffmpeg-parsed
   microphone device name flows into the `ffmpeg -i` input of `ffmpeg_microphone` (lines 75-82).
   Device names come from local hardware enumeration — no external attacker control identified;
   review if the threat model includes attacker-named capture devices.
3. **~201 dev conversion-script `parse_args` mains** (merged into one signature entry): local
   maintenance scripts; recommend the Phase 2 test/dev-script FP heuristic also cover
   `models/**/convert_*.py`.
4. **`_ffmpeg_stream` argv (audio_utils.py:221)**: if pipelines are exposed as a service, the
   input filename reaching the ffmpeg argv is an argument-injection surface (e.g. a value
   beginning with `-`); confirm the deployment context.

## 6. Review directives (per task brief)

1. **Network/protocol data before plugin entry**: the git-lfs stdin protocol JSON
   (lfs.py:107/165) is envelope-validated (event/type checks in `read_msg`) but its values
   (oid, path, action.href, action.header) are not content-validated; they flow into
   `requests.put/post` targets and file reads only — **no path from the stdin protocol into any
   command string exists in this snapshot**, so the lfs source does not pair with the lfs
   subprocess sinks.
2. **Mobile notifications / files / config / request params affecting commands**: not
   applicable (the tree is the HuggingFace transformers ML library — see detection.json
   runNote). The analogs are: hub-downloaded config JSON (feeds config objects, no command
   flow observed), environment variables (caches/flags/integrations, no command flow observed),
   and local microphone device enumeration (item 2 above).
3. **subprocess/os call shapes**: one `shell=True` site (onnx/__main__.py:59, joined string);
   lfs uses constant strings via `.split()` without shell; all other sites are argv lists
   (fixed probes, ffmpeg argv, test helpers). No `os.system`/`os.popen` in src/transformers.
4. **Internal function roles**: CLI handler `__init__` params -> source (handler boundary);
   dynamic dispatch `args.func(args)` / `service.run()` and `read_msg()` -> summary; exec
   wrappers (`ffmpeg_read`, `_ffmpeg_stream`, `run_command`, `is_ninja_available`, ...) ->
   redundant (none) because the inner exec call is labeled directly; pure display f-strings ->
   none.
5. **Fixed commands vs attacker input (trust boundary)**: lfs `git config` commands are fully
   constant (module-level `LFS_MULTIPART_UPLOAD_COMMAND`); the external value is `cwd=` only.
   In `export_with_optimum` the fixed part is `sys.executable -m optimum.exporters.onnx`, while
   the interpolated values are CLI-derived — a clear boundary violation only if CLI args are
   attacker-controlled (see item 1).
6. **Dangerous-character / argument validation**: none exists — no shlex.quote/pipes.quote at
   any exec site; argv-list form is the only structural mitigation.

## 7. Pipeline bookkeeping

- Pass 1 entry in labels.json is a schema-compatibility placeholder (labels_schema.json
  `passes/contains` requires a pass_id 1 entry); path traversal was not analyzed in this run.
- Constraints honored: no PyVul ground truth, vulnerability fix commits, or external security
  advisories were consulted; project source, the CodeQL database, and Step 1-2 extraction
  artifacts were not modified. Only `iris/labels/*` files were written.
- Next step (Phase 2, NOT started per instructions): generate MySources/MySinks/MySanitizers/
  MySummaries from labels.json and run the Pass 2 taint query.
