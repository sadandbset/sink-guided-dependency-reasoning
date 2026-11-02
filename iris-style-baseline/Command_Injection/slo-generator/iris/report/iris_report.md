# Augur IRIS Report

Generated at: `2026-10-16T08:15:25.771677+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 29 | 14 | 0 | 67 | 161 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 12 | 0 | 6 | 6 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `slo_generator/compute.py:119` `py/augur/slo-generator/pass2-command-injection`: Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `slo_generator/report.py:203` `py/augur/slo-generator/pass2-command-injection`: Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `slo_generator/report.py:204` `py/augur/slo-generator/pass2-command-injection`: Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `slo_generator/report.py:216` `py/augur/slo-generator/pass2-command-injection`: Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `slo_generator/utils.py:337` `py/augur/slo-generator/pass2-command-injection`: Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `slo_generator/utils.py:337` `py/augur/slo-generator/pass2-command-injection`: Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

- `pass2` `slo_generator/migrations/migrator.py:78` `py/augur/slo-generator/pass2-command-injection`: Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
  - Reason: migration file heuristic
- `pass2` `slo_generator/migrations/migrator.py:88` `py/augur/slo-generator/pass2-command-injection`: Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
  - Reason: migration file heuristic
- `pass2` `slo_generator/migrations/migrator.py:140` `py/augur/slo-generator/pass2-command-injection`: Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
  - Reason: migration file heuristic
- `pass2` `slo_generator/migrations/migrator.py:142` `py/augur/slo-generator/pass2-command-injection`: Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
  - Reason: migration file heuristic
- `pass2` `slo_generator/migrations/migrator.py:229` `py/augur/slo-generator/pass2-command-injection`: Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
  - Reason: migration file heuristic
- `pass2` `slo_generator/migrations/migrator.py:264` `py/augur/slo-generator/pass2-command-injection`: Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate).
  - Reason: migration file heuristic

---

## Analyst Addendum (v2 remediation rerun — NOT generated by filter_and_report.py)

This report was regenerated from `results_v2/pass2.sarif` after the v2 post-triage
remediation (source labels S226/S227 + sink labels K043/K044; see
`labels/labels.json` metadata notes and `report/query_generation_notes.md` §9).

The two alerts below are the alerts added by the remediation. They are the
project's real vulnerability (unsafe YAML deserialization;
`yaml.load(conf, Loader=yaml.Loader)` with ruamel.yaml's unsafe full loader →
arbitrary Python object construction → code execution), at exactly the two
lines changed by the upstream fix (google/slo-generator PR #173, commit
36318be: `yaml.Loader` → `yaml.SafeLoader`):

- `slo_generator/migrations/migrator.py:229` — `exporters_v1tov2`, taint path
  `open(exp_path)` (line 228) → `conf` → `yaml.load(conf, Loader=yaml.Loader)`
  — **analyst verdict: likely_tp** (unsafe-by-construction sink; matches the
  fix commit location exactly)
- `slo_generator/migrations/migrator.py:264` — `ebp_v1tov2`, taint path
  `open(ebp_path)` (line 263) → `conf` → `yaml.load(conf, Loader=yaml.Loader)`
  — **analyst verdict: likely_tp** (same)

They are listed above as "migration file heuristic" likely-FP only because
`filter_and_report.py` applies the path-based `_is_test_or_migration` heuristic
before any content-based pattern. **Tool-level improvement suggestion:** the
migration/test path heuristic should not pre-empt unsafe-deserialization
evidence — run pass-6-style unsafe-loader TP patterns (`yaml.load` with
`Loader=yaml.Loader/UnsafeLoader/FullLoader`, `pickle.loads`, ...) before the
path heuristics, or exempt findings whose sink is an unsafe deserialization
call. The shared augur script was deliberately left unmodified in this run;
this addendum documents the divergence.

Ground-truth hit status for this rerun: **hit** (2/2 vulnerable lines covered,
recall 1/1 for the project's known vulnerability; see
`report/llm_triage.json` → `v2_rerun`).
