# Augur IRIS Report

Generated at: `2026-10-14T09:08:05.646180+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 17 | 15 | 1 | 18 | 3 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 15 | 0 | 13 | 2 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `lib/ansible/cli/__init__.py:434` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `lib/ansible/plugins/action/__init__.py:1112` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `lib/ansible/plugins/action/__init__.py:1264` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `lib/ansible/modules/command.py:346` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `lib/ansible/executor/interpreter_discovery.py:68` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `lib/ansible/executor/interpreter_discovery.py:96` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `lib/ansible/plugins/action/raw.py:42` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `lib/ansible/plugins/action/reboot.py:222` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `lib/ansible/plugins/action/reboot.py:264` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `lib/ansible/plugins/action/reboot.py:333` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `lib/ansible/modules/rpm_key.py:206` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `hacking/test-module.py:232` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `lib/ansible/modules/user.py:596` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

- `pass2` `test/support/integration/plugins/modules/postgresql_db.py:453` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: test file heuristic
- `pass2` `test/support/integration/plugins/modules/postgresql_db.py:497` `py/augur/ansible/pass2-command-injection`: Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
Untrusted input flows from a remote, playbook, CLI, or environment source into a command execution sink.
  - Reason: test file heuristic
