# Phase 1 Step 3 Review - LLM Candidate Labeling (Pass 1: Path Traversal)

## 1. Run summary

| item | value |
| --- | --- |
| project | thefuck 3.30 (`thefuck_vuln` source tree, CodeQL db `thefuck-db`) |
| pass | 1 - CWE-022/023/036/073 Path Traversal |
| model | glm-5.3 (in-session LLM labeling) |
| run id | iris-thefuck-pass1-step3-20261023 |
| generated | 2026-10-23T13:32:22.663851+00:00 |
| candidates processed | 420 source rows + 139 sink rows = **559 rows, all processed** |
| batches | 8 (S1-S4 source families, K1-K4 sink families), sample counts in label_stats.md |
| label entries | 531 (source 39, sink 23, summary 3, none 466, sanitizer 0) |
| schema | labels.json validated against `augur-0.3.0/assets/labels_schema.json` (structure, enums, arg_index rules, pass_id=1) |

Ground truth (PyVul truth files, patch diffs, CVE reports) was NOT consulted; labels derive only from the real source code, the Phase 1 extraction artifacts, and the Augur references (WORKFLOW.md, references/python.md, references/patterns.md; no framework reference matched - thefuck has no web surface).

## 2. Answers to the ten review questions

### Q1 - Are sources truly untrusted boundaries?

thefuck is a standalone CLI; there is no URL/route/request/multipart surface. Labeled boundaries: (a) **archive entry names** (`dirty_untar.py:43 getnames()`, `dirty_unzip.py:47 namelist()`) - fully attacker-controlled once a crafted archive is named on the command line -> `source/tp`; (b) **command.output / command.script_parts** - the failed command's terminal output/argv, the tool's payload channel, attacker-influenceable when the failed command displayed attacker content -> `source/tp` for ssh_known_hosts.py:31, `candidate` for the archive-path feeds, and `fp/none` for the other 366 rows of the 384 command_output/command_script reads (matching/rewriting only - verified: no filesystem API in those modules); (c) **CLI argv** (`argument_parser.py:86 parse_args`, `main.py:30/32/38`, `fix_command.py:14-19`) and **env** (`conf.py:46 XDG_CONFIG_HOME`, `utils.py:228 XDG_CACHE_HOME`, `bash.py:69`/`zsh.py:74`/`tcsh.py:29 HISTFILE`, `read_log.py:65/93 THEFUCK_OUTPUT_LOG`, `fix_command.py:16/19 TF_HISTORY`) - real process boundaries but local-user trust -> `candidate`, deferred to the human trust decision. Internal function parameters were NOT auto-labeled as sources: `Settings.init(args)` (booleans only), `get_loaded_rules(rules_paths)`, `Rule.from_path(path)`, `Cache._get_mtime(path)`, `fix_command(known_args)` are `none`; only the entrypoint param `shell_logger(output)` (the -l CLI value) is `candidate`.

### Q2 - Can the user path be traced step-by-step into the file API?

Yes for every labeled flow, with no URL decoding anywhere (no web surface):
- CLI/env -> `fix_command._get_raw_command` -> `types.Command.from_raw_script` -> `Command.script`/`script_parts` (modeled as `summary/tp` entries because rule modules are loaded with `imp.load_source` and invoked dynamically, which CodeQL cannot resolve) -> `dirty_untar._tar_file`/`dirty_unzip._zip_file` -> `tarfile.TarFile`/`zipfile.ZipFile` -> entry names -> `os.remove`.
- `command.output` -> `ssh_known_hosts` regex `([^:]+)` -> `open(filepath, 'r'/'w')`.
- env -> `Path(XDG_CONFIG_HOME, 'thefuck')` -> `.joinpath('settings.py')` -> `.open('w')` / `mkdir` / `imp.load_source`; `XDG_CACHE_HOME` -> `makedirs` / `shelve.open` / `os.remove`; `HISTFILE` -> `io.open` (generic.py:60); `THEFUCK_OUTPUT_LOG` -> `os.open` (read_log.py:93); CLI `-l` -> `os.open(O_CREAT|O_TRUNC|O_RDWR)` (shell_logger.py:74).

### Q3 - Are sinks actual file operations?

Only real file accesses carry the `sink` role: `open/os.open/shelve.open` (read/write/create/truncate), `os.remove`, `os.makedirs/.mkdir`, `tarfile.TarFile`/`zipfile.ZipFile` (archive open whose entry names reach `os.remove`), and `imp.load_source` (resource loader per patterns.md pass-1 sink family). `Path(...)`, `join`/`joinpath`, `expanduser`/`split`/`absolute`, string concatenation and stat-only probes (`isfile`/`isdir`/`exists`/`getsize`/`getmtime`/`access`/`listdir`/`iterdir` enumeration) are labeled `none` per the contract - e.g. `git_add.py:13 Path(pathspec).exists()`, `cat_dir.py:9 os.path.isdir`, `gradle_wrapper.py:9 os.path.isfile('gradlew')` (literal).

### Q4 - Can the path escape a declared allowed root?

No allowed root is declared anywhere - which makes the tp cases *arbitrary-path* issues rather than classic base-escape: `dirty_untar.py:45` / `dirty_unzip.py:49` pass tar/zip entry names verbatim to `os.remove` (relative to CWD), so `../` segments, absolute names, drive letters and mixed/repeated separators all survive; only directories are skipped (via the OSError handler). `ssh_known_hosts.py:31-36` captures `([^:]+)` from command output and opens it directly - absolute paths accepted. No URL decoding exists, so decode-variant bypasses are N/A. `cd_correction.py:39-58` splits on `os.sep` and re-joins close-matched real directory names, so it cannot leave the set of existing directories.

### Q5 - Is there a real restricted-root check executed before file access?

No. Zero containment checks exist before any labeled sink: no `startswith(base)`, no `abspath/realpath` containment, no `relative_to()`, no fixed-filename mapping, no whitelist. The only pre-checks are existence stats (`generic.py:59` before `:60`, `conf.py:38` before `:39`, `not_configured.py:58` before `:62`) - availability probes, not authorization.

### Q6 - Do normpath/resolve/basename/startswith/blacklists block anything here?

None are present, so nothing qualifies as a sanitizer: `expanduser` (labeled `none`, a wrapper) expands `~` rather than validating; `os.path.split` uses are cwd walking, not basename extraction. One implicit limiter is noted but NOT labeled sanitizer: `cd_correction.py:56` `get_close_matches(directory, _get_sub_dirs(cwd), cutoff=0.6)` constrains listdir arguments to names of real subdirectories - it is not a canonicalize/containment guard and cannot serve as an `isBarrier` for the labeled sinks.

### Q7 - Symlinks and TOCTOU?

Not applicable: no symlink creation, no `readlink`, no symlink-following policy anywhere in the package. Check-then-use shapes exist (`os.path.isfile` before `io.open` in generic.py:59-60; `is_file` before `open('w')` in conf.py:38-39; `exists` before `open('r')` in not_configured.py:58-62) but their paths are env/literal-origin with local trust, so no pass-1 tp is based on TOCTOU.

### Q8 - Is the user authorized for the chosen file?

For the local-trust flows, yes by definition: the CLI argv, HISTFILE, XDG_* and TF_HISTORY are the interactive user's own values (labeled `candidate`, fp at triage under a single-user threat model). The tp flows do NOT rely on user authorization: archive entry names and command-output regex captures are third-party-controlled content, and the operations (delete / rewrite a line) are not a legitimate file-serving feature.

### Q9 - Tests, fixed constants, generated files?

Extraction already excluded `tests/` and `thefuck-db/`. Constant/literal sites are labeled `fp`: `utils.py:15 open(os.devnull)`, `gradle_wrapper.py:9 isfile('gradlew')`, shell-config literals (`~/.bashrc` etc. at not_configured.py:78/85), tempdir+uuid log paths (bash.py:46, zsh.py:51), `fish.py:124` fixed history append, brew-prefix-derived listdirs. `rules/test.py.py` is a shipped rule module, not a test fixture; its output read is matching-only (`none`).

### Q10 - Complete untrusted-source-to-dangerous-argument flows vs partial flows?

Complete flows (labeled): archive entry name -> `os.remove` (tp, x2); command.output -> `open r/w` (tp, ssh_known_hosts); env/CLI -> open/create/mkdir/code-load (candidate, local trust). Partial wrapper flows are explicitly `none`: all `file_api_def` wrapper params (`_tar_file`, `_zip_file`, `_search`, `_get_actual_file`, `_get_destination`, `_get_brew_commands`, `_get_directory_names_only`), and the `Command.__init__`/`from_raw_script` constructor edges are `summary` steps (dynamic rule invocation is unresolvable by CodeQL, so MySummaries must add the store/load edge).

## 3. Top high-risk sinks (for the checkpoint)

| id | location | role | class | conf | why |
| --- | --- | --- | --- | --- | --- |
| p1-454 | `thefuck/rules/dirty_untar.py:45` | sink | tp | 0.95 | os.remove(file) per tar entry name taken verbatim from archive.getnames() with no validation: '..' segments escape the CWD, absolute paths are passed as-is, separator variants are not rewritten; only directories are silently skipped (OSError). |
| p1-458 | `thefuck/rules/dirty_unzip.py:49` | sink | tp | 0.95 | os.remove(file) per zip entry name taken verbatim from archive.namelist() with no validation ('..'/absolute/mixed-separator names accepted, CWD-relative; directories skipped only via the OSError handler). |
| p1-501 | `thefuck/rules/ssh_known_hosts.py:33` | sink | tp | 0.90 | open(filepath, 'r') where filepath is regex-extracted from the failed command's terminal output ('Offending ... in ([^:]+)'): arbitrary file read at an output-derived path with no validation (tp contingent on attacker-influenced command output, which is this tool's untrusted payload channel). |
| p1-502 | `thefuck/rules/ssh_known_hosts.py:36` | sink | tp | 0.90 | open(filepath, 'w') rewrites the output-regex-derived file with one line deleted: arbitrary file modification at an unvalidated path (read at :33 supplies the lines). |

Paired sources: `dirty_untar.py:43 getnames()` (p1 source/tp 0.95), `dirty_unzip.py:47 namelist()` (source/tp 0.95), `ssh_known_hosts.py:31 old_cmd.output` (source/tp 0.85).

## 4. Candidate items deferred to human review (trust decision)

34 entries are `candidate` - all local-trust boundary flows (env/CLI -> file ops) plus `fix_file.py:60/66` (output-regex path reaches only a stat in pass 1). Under a single-local-user threat model these triage to fp; under a model where the alias runs in a shared/CI shell or env is injected by a wrapper, `shell_logger.py:74` (create/truncate at CLI path), `conf.py:39/:69`, `types.py:144` (code load from XDG dir) and `generic.py:60` deserve a second look. Lowest-confidence entries: fix_file.py:60/66 (0.50), conf.py:64 mkdir (0.50), utils.py:233 makedirs (0.55).

## 5. Quality checks

- labels.json passes the local schema validation (structure, enums, argument-index rules, pass_id=1).
- All 559 CSV rows processed; 531 label entries after dedup (23 within-CSV duplicates, 5 cross-CSV merged nodes); every decision has a code-grounded rationale and evidence.
- Pass 1 has 23 sink entries (>= 1 required). No sanitizer entries: MySanitizers must render `none()`.
- 3 `summary` entries (types.py Command edges) are required for realistic propagation into the dynamically invoked rules.

## 6. Stop statement

Phase 1 Step 3 is complete. Per the task contract this run STOPS here: no Phase 2 (no library generation, no taint query execution, no report). No source files, CodeQL database files, Augur installation files, or Phase 1 raw CSVs were modified.
