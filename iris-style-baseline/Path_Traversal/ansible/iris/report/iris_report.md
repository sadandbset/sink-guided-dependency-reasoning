# Augur IRIS Report

Generated at: `2026-10-21T13:30:12.292838+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 34 | 198 | 7 | 49 | 151 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 37 | 0 | 37 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `lib/ansible/plugins/action/win_copy.py:270` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/action/__init__.py:415` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/action/__init__.py:430` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/action/__init__.py:840` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/template/__init__.py:99` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/template/__init__.py:101` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/action/ce_template.py:63` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/action/ce_template.py:64` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/action/ce_template.py:67` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/action/fetch.py:168` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/action/fetch.py:172` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/action/fetch.py:172` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/action/fetch.py:175` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/file.py:72` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/fileglob.py:63` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/filetree.py:131` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/filetree.py:140` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/filetree.py:186` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/utils/hashing.py:62` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/executor/module_common.py:1111` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/executor/module_common.py:1127` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/executor/module_common.py:1118` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/executor/module_common.py:1040` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/action/network.py:111` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/action/network.py:112` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/password.py:172` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/password.py:258` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/password.py:260` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/password.py:261` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/password.py:274` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/password.py:275` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/password.py:297` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/utils/path.py:65` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/utils/path.py:85` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/utils/path.py:87` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/galaxy/role.py:330` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `lib/ansible/plugins/lookup/template.py:79` `py/augur/ansible/pass1-path-traversal`: Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
