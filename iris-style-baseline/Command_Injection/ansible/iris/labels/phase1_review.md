# Augur Phase 1 — Human Review Gate (Step 3 output, Pass 2 / CWE-78, Ansible)

Status: **Step 3 (LLM candidate labeling) complete; pipeline intentionally halted here per user
instruction — Step 4 (library generation) and taint analysis not started.**

- Run: `ansible-iris-manual-phase1-step3-pass2-cwe78` (2026-10-14), model `glm-5.3` (Claude Code
  CLI agent, lead + 8 fork subagents). Labels: `labels.json` (54 deduplicated entries, schema-valid),
  `labels_raw_pass2.json` (all 1665 per-row labels). Full stats: `label_stats.md`.
- All 1665 candidate rows (1249 sources, 416 sinks) from `iris/extraction/*.csv` were labeled —
  zero rows skipped or excluded; `fp`/`none`/`unknown` are explicit labeled outcomes, not omissions.

## 1. Label counts by pass and role

Per-row: source 1249 / sink 387 / summary 22 / none 7 (fp — abstract `super().exec_command` no-op
edges and non-boundary writes). Deduplicated: source 17 / sink 15 / summary 18 / none 3 / sanitizer 1.
Classifications per-row: tp 654, candidate 963, fp 44, unknown 4.

## 2. Top high-risk sink APIs / paths (strongest CWE-78 review candidates)

Execution semantics were verified against source, not assumed:

1. **`service_facts.py:172/227` (K-297, K-300)** — `service_name` parsed from remote
   `chkconfig`/`systemctl` output is interpolated into `run_command(..., use_unsafe_shell=True)`
   (shell=True per basic.py:1912-1927). Live remote-output→shell taint path; the most
   vulnerability-shaped candidate in the set (not merely designed-feature command execution).
2. **`plugins/action/raw.py:42` (K-272)** — `self._task.args.get('_raw_params')` passed directly as
   `cmd` to `_low_level_execute_command` → remote shell. Textbook task-args→remote-shell shape;
   also the designed behavior of the `raw` action.
3. **`executor/interpreter_discovery.py:96` (K-208)** — `found_interpreters[0]`, derived from
   `json.loads` of remote stdout (S-agent verified), executed as a command — remote-data→command reuse.
4. **`plugins/lookup/lines.py:56`, `pipe.py:70`** — `Popen(term, shell=True)` with playbook lookup
   `terms` (designed feature of lookup plugins; genuine shell semantics).
5. **`reboot.py:222/264`** — task-arg `boot_time_command`/`test_command` (type-checked only) →
   `_low_level_execute_command`.
6. **`action/__init__.py:1112` (K-19)** — controller-side module bootstrap command via
   `build_module_command` into `_low_level_execute_command` (principal controller-side sink).
7. **`cli/__init__.py:434→439`** — `os.environ['PAGER']` → `Popen(cmd, shell=True)` via
   `pager_pipe` (local-admin trust, real shell semantics).
8. **`rpm_key.py:206` / `cron.py:266,317`** — `use_unsafe_shell=True` sites where module params
   reach the shell string; cron interpolations are `shlex_quote`d (cron.py:517-531), rpm_key list
   callers are per-element quoted (basic.py:1915-1916) — sanitizer-present candidates.
9. **`ssh.py:1221/1231`** — `dd if=%s`/`dd of=%s` unquoted path interpolation into remote commands.
10. **`git.py` set_git_ssh (S-550..)** — module param `ssh_opts` exported as `GIT_SSH_OPTS`, expanded
    unquoted (`BASEOPTS=$GIT_SSH_OPTS`) under `/bin/sh` in the wrapper script — env-mediated
    module-param→shell interpretation.
11. **`modules/expect.py:150→202`** — `module.params['command']` → `pexpect.run` (argv semantics, no
    shell — CWE-88 surface, kept as candidate).
12. **`async_wrapper.main()` argv channel** — `wrapped_module`+`argsfile` from `sys.argv` form the
    executed command.

The dominant sink API is `AnsibleModule.run_command` (323 rows): 34 `use_unsafe_shell=True`
(shell=True) sites — 33 tp + 1 unknown; 288 argv/shlex-mode sites (candidate; CWE-88 argument
injection at most, since basic.py:1937-1941 shlex-splits and runs without a shell).

## 3. Top broad source APIs

- `AnsibleModule.params` (510 reads, tp 0.75) — module-side boundary; controller/playbook data via
  `_load_params` (basic.py:370-417: stdin/argv → `json.loads` → `ANSIBLE_MODULE_ARGS`).
- `ansible.context.CLIARGS` (332 reads, candidate 0.57) — local-admin CLI input; command-relevant
  keys (`module_args`, `extra_vars`, `url`, ...) raised to 0.6; `ansible-pull` builds its
  ansible-playbook command from CLIARGS with inconsistent quoting (extra_vars quoted, `-a/-l/-t`
  raw), executed via argv-only `run_cmd`.
- `task.args` (182 reads, candidate 0.68) — controller-side playbook data; 12 tp raises where args
  provably become executed commands (raw/reboot/script/async).
- `json.loads` (33) — strongest attacker model: 22 tp (remote command output, galaxy/launchpad API
  responses, collection artifacts), 10 candidate (local/IPC), 1 caller-dependent.
- env (84) / sys.argv (31) / sys.stdin (17) — candidate boundaries; module-channel rows tp.

## 4. Sanitizers

- `shlex_quote` (`ansible.module_utils.six.moves`, P2-SAN-001, tp 0.75) — the only proven CWE-78
  sanitizer: basic.py:1916 (per-element quoting before shell join) and action/__init__.py:1037
  (module args quoted into the module command line). Added by lead labeler from source reading,
  not from candidate CSVs. `shlex.split`+argv execution (run_command default mode) was judged a
  sanitizer *pattern*, not a sanitizer API — those call sites remain labeled sink/candidate.

## 5. Unresolved / low-confidence items (for reviewer attention)

- 132 rows < 0.55 confidence (mostly bulk candidate-class source families: env/CLIARGS reads and
  argv-mode sinks). No re-ask pass was run; entries retain explicit candidate classifications.
- 4 `unknown` rows: K-174 (hostname.py:544 — CSV line unreconcilable with the file's actual
  `use_unsafe_shell` site), S-176/S-177 (basic.py env rows landing in stderr-processing region),
  S-1207 (yum.py proxy-loop ambiguity).
- CSV→tree line drift (0–33 lines on some files): `location.line` keeps CSV coordinates; actual
  on-disk lines are in each entry's `evidence` (DB and tree differ slightly in revision).
- 2 CSV duplicate rows flagged by the K1 agent (K-96/97, K-98/99) — kept as separate entries to
  preserve 1:1 row accounting; harmless for Phase 2 (identical signatures collapse in qll generation).
- `winrm.py:473` (K-374) is WinRM `Protocol.run_command` (name-collision match, not
  `AnsibleModule.run_command`) — kept sink/candidate 0.5 with an explicit note.

## 6. Trust-model decisions embedded in the labels (per user rubric)

1. Admin-authored playbook/config vs remote input: `module.params`/`task.args` are boundaries
   (galaxy-sourced roles make them attacker-reachable) but rationales state the trust level;
   remote-output sources (`json.loads` on exec output, `exec_command` returns) are the strongest
   attacker model and dominate the tp set.
2. `module.params` trust: source/tp — real input boundary even though the usual author is privileged.
3. `run_command` execution semantics: `use_unsafe_shell=True`+string → shell=True (tp);
   default string → shlex.split + argv + expandvars (candidate, CWE-88-adjacent); list → argv only
   (candidate, weakest).
4. Local vs remote shell: `Connection.exec_command`/`_low_level_execute_command` execute remotely by
   design — injection still yields CWE-78 on the target; local `Popen(shell=True)` sites
   (lookups, pager) judged on arg0 provenance.
5. Designed feature ≠ vulnerability: command/shell/raw functionality labeled sink/tp with the
   feature caveat in the rationale — findings are review candidates, per detection.json's
   design_caution; the `service_facts` output→shell path is the clearest non-designed-feature case.
6. Parameter control/concatenation/validation noted per-row: quoting via `shlex_quote` (cron,
   rpm_key), type-checks only (reboot), raw interpolation (service_facts, ssh dd, git wrapper).

## 7. Next step (pending approval — NOT executed in this run)

Step 4 (generate `MySources/MySinks/MySanitizers/MySummaries.qll` from `labels.json`) per
WORKFLOW.md §5.1. Recommended review focus before approval: the `service_facts.py` path, the
`raw`/`reboot` task-arg paths, and whether argv-mode run_command sinks (288 rows, candidate) should
be kept in the sink set for the CWE-78-restricted pass or demoted to reduce noise.
