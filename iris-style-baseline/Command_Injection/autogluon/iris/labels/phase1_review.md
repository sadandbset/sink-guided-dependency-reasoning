# Augur Phase 1 Step 3 - Phase 1 Review (human checkpoint)

**Status: awaiting human review of `labels.json`. Phase 2 was NOT started.**

## Methodology

1. Read WORKFLOW.md Step 3, references/python.md, references/patterns.md, and assets/labels_schema.json.
2. Read all 12 sinks.csv rows and the surrounding source code of every call site; read the 14 sources.csv rows of the sink-containing module (core/src/autogluon/core/utils/sync_remote.py) in full, plus utils.py around its sink, one test_check_style.py copy, the CI/batch/submit-job.py CLI script, and a CLI example script.
3. Verified the command-execution API universe with repository-wide greps (subprocess, os.system, os.popen, pexpect, asyncio.create_subprocess_*, os.exec*, pty.spawn, shlex, shell=True) and verified all callers of the two non-test sink functions.
4. Classified the remaining 6448 unique parameter candidates by rule: a parameter is a pass-2 source only if it is an external input boundary (CLI main(args) fed by argparse) or reaches a command-execution call. AutoGluon library src has no HTTP handlers; the only argparse scripts live under examples/ and CI/. Library src contains no command-execution call sites outside sync_remote.py/utils.py, so no other parameter can reach a pass-2 sink.
5. Ground-truth/vulnerability-report files in the dataset directory (confirmed_vulns.json, CVE reports, cmd_sinks.csv, etc.) were NOT used.

## Key findings for review

### Real CWE-78 sink (2 entries, tp)
- `core/src/autogluon/core/utils/sync_remote.py:50` and `:52` - `subprocess.check_output(f'ps -elf | grep "{proccess_id_string}"', encoding='utf-8', shell=True)` (entries `p2-sink-002`, `p2-sink-003`).
- These are the only `shell=True` command executions in the entire repository.
- Exploitability caveat: the only in-repo caller passes the fixed literal `'dask-scheduler'`, and the module `__all__` exports only `sagemaker_setup`. A path would require an out-of-repo caller of `sync_training_processes` or of the unexported module functions. The sink shape itself (shell=True + string interpolation) is nonetheless a true CWE-78 sink position.

### Ruled out (none/fp)
- `subprocess.Popen(['/usr/sbin/sshd', '-D'])` (sync_remote.py:16): fixed literal list, no shell.
- `subprocess.check_output(COMMAND.split())` (utils.py:890): fixed nvidia-smi literal, list form, no shell.
- Nine `tests/test_check_style.py` copies: test files, fixed flake8 literal list, no shell.
- ~6440 other parameter candidates: no external-attacker-control evidence and no path to a command-execution API (see methodology step 4).

### Manual confirmation queue
| entry | item | why it needs eyes |
| --- | --- | --- |
| p2-src-4863 (sync_training_processes.proccess_id_string) | source/candidate 0.50 | only realistic taint entry into the shell=True sink; attacker control requires out-of-repo caller |
| p2-supp-001/002 | os.environ SM_CURRENT_HOST / SM_HOSTS, source/candidate 0.50 | supplementary entries not present in sources.csv; decide whether to keep env-var sources in MySources for Phase 2 |
| p2-supp-003 | get_gpu_free_memory, summary/candidate 0.55 | command-output wrapper; decide whether output taint should flow in Phase 2 |
| 4x main(args) CLI entries | source/candidate 0.45 | genuine argparse boundaries in examples/, but no path to any command sink; low review priority |
| p2-sink-002/003 | sink/tp 0.90 | confirm the exploitability caveat is acceptable for the pass-2 query |

### Sanitizers
None found (no shlex/quote/allow-list anywhere in the repository).

## Open questions
1. Should `sync_training_processes.proccess_id_string` (param 0) stay a source candidate, or should the pass-2 query instead source only the env reads (SM_CURRENT_HOST/SM_HOSTS) and CLI args?
2. `sagemaker_setup` is not invoked anywhere in the repository (only exported via `__all__`); it is presumably called by SageMaker training infrastructure. Confirm the intended threat model (platform-controlled env vs. external attacker).
3. Are the 9 test-file sink rows worth keeping as role=none entries, or should they be dropped entirely in Step 4 library generation? (Currently retained for audit.)

## Next step
After approval, run Step 4 (generate MySources/MySinks/MySanitizers/MySummaries from these labels). Phase 2 has NOT been started.

