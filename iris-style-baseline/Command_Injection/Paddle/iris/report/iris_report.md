# Augur IRIS Report

Generated at: `2026-10-15T23:34:35.379920+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 11 | 13 | 0 | 2 | 3 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 10 | 0 | 10 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `python/paddle/utils/cpp_extension/extension_utils.py:1325` `py/augur/Paddle/pass2-command-injection`: Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `python/paddle/utils/cpp_extension/extension_utils.py:1379` `py/augur/Paddle/pass2-command-injection`: Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `python/paddle/utils/cpp_extension/extension_utils.py:1390` `py/augur/Paddle/pass2-command-injection`: Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `python/paddle/utils/cpp_extension/extension_utils.py:1393` `py/augur/Paddle/pass2-command-injection`: Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `python/paddle/utils/cpp_extension/extension_utils.py:1399` `py/augur/Paddle/pass2-command-injection`: Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `python/paddle/utils/cpp_extension/extension_utils.py:1409` `py/augur/Paddle/pass2-command-injection`: Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `python/paddle/utils/cpp_extension/extension_utils.py:1409` `py/augur/Paddle/pass2-command-injection`: Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `python/paddle/utils/cpp_extension/extension_utils.py:1434` `py/augur/Paddle/pass2-command-injection`: Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `python/paddle/utils/cpp_extension/extension_utils.py:1434` `py/augur/Paddle/pass2-command-injection`: Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `python/paddle/utils/cpp_extension/extension_utils.py:1441` `py/augur/Paddle/pass2-command-injection`: Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
Command injection (candidate, needs review): attacker-influenced CLI argument, environment value, config value or peer data flows unquoted into a shell command string or process argument list executed by the Paddle distributed tooling.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
