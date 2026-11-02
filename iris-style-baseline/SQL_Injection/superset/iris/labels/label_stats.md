# Pass 5 (CWE-89 SQL Injection) Label Statistics

- run_id: `superset-pass5-cwe89-20261021`
- generated_at: 2026-10-21T08:10:31+00:00
- model: **glm-5.3** (in-context labeling by the glm-5.3 agent session operating the Claude Code harness; no external LLM API calls)
- batches: **12** (B01-B12; scope and row counts in `labels_raw_pass5.json`)
- total candidates processed: **1742** (1445 source rows + 297 sink rows from extraction CSVs)
- 100% row coverage: every CSV row is assigned to exactly one of 62 semantic groups
- labels.json entries after dedup: **66** (pass 5) + 1 empty pass-1 block required by the schema `contains` constraint

## Entries by role (pass 5)

| role | entries |
| --- | --- |
| source | 12 |
| sink | 24 |
| sanitizer | 2 |
| summary | 17 |
| none | 11 |

## Entries by classification

| classification | entries |
| --- | --- |
| tp | 45 |
| fp | 11 |
| candidate | 10 |
| unknown | 0 |

## Candidate rows by assigned label role

| role | CSV rows covered |
| --- | --- |
| source | 646 |
| sink | 160 |
| sanitizer | 14 |
| summary | 339 |
| none | 583 |

## Group overview

| group | csv | rows | files | entries |
| --- | --- | --- | --- | --- |
| G-P16 | sources | 316 | 99 | p5-none-053 |
| G-P11 | sources | 153 | 71 | p5-none-048 |
| G-P09 | sources | 135 | 33 | p5-src-046 |
| G-P10 | sources | 129 | 10 | p5-src-047 |
| G-P27 | sources | 118 | 7 | p5-sum-064 |
| G-P06 | sources | 83 | 24 | p5-src-043 |
| G-P02 | sources | 70 | 14 | p5-src-039 |
| G-P01 | sources | 61 | 22 | p5-src-038 |
| G-P03 | sources | 52 | 21 | p5-src-040 |
| G-P13 | sources | 45 | 19 | p5-none-050 |
| G-S03 | sinks | 43 | 7 | p5-sink-003 |
| G-P08 | sources | 35 | 19 | p5-src-045 |
| G-P07 | sources | 34 | 12 | p5-src-044 |
| G-P18 | sources | 34 | 8 | p5-sum-055 |
| G-P24 | sources | 29 | 9 | p5-sum-061 |
| G-P12 | sources | 27 | 6 | p5-none-049 |
| G-S01 | sinks | 27 | 14 | p5-sink-001 |
| G-SW4 | sinks | 25 | 6 | p5-sum-036 |
| G-S14 | sinks | 21 | 5 | p5-sum-018 |
| G-P15 | sources | 20 | 4 | p5-src-052 |
| G-S18 | sinks | 17 | 4 | p5-none-024 |
| G-SW2 | sinks | 17 | 8 | p5-sum-032 |
| G-P20 | sources | 15 | 7 | p5-sum-057 |
| G-SW1 | sinks | 15 | 9 | p5-sum-031 |
| G-P04 | sources | 14 | 13 | p5-src-041 |
| G-P21 | sources | 14 | 1 | p5-sum-058 |
| G-S21 | sinks | 14 | 10 | p5-san-030 |
| G-S09 | sinks | 12 | 6 | p5-sink-011, p5-sink-012, p5-sink-013 |
| G-P25 | sources | 11 | 4 | p5-sum-062 |
| G-S04 | sinks | 10 | 7 | p5-sink-004 |
| G-S15a | sinks | 10 | 3 | p5-sink-019 |
| G-SW3 | sinks | 10 | 6 | p5-sum-035 |
| G-P14 | sources | 9 | 1 | p5-src-051 |
| G-P19 | sources | 9 | 4 | p5-sum-056 |
| G-S02 | sinks | 9 | 5 | p5-sink-002 |
| G-P28 | sources | 7 | 1 | p5-none-065 |
| G-S16 | sinks | 7 | 2 | p5-sink-022 |
| G-P23 | sources | 6 | 2 | p5-sum-060 |
| G-P29 | sources | 6 | 2 | p5-none-066 |
| G-S15b | sinks | 6 | 6 | p5-sink-020 |
| G-S19b | sinks | 6 | 2 | p5-none-026 |
| G-P17 | sources | 5 | 4 | p5-sum-054 |
| G-P05 | sources | 4 | 3 | p5-src-042 |
| G-P22 | sources | 4 | 2 | p5-sum-059 |
| G-S07 | sinks | 4 | 2 | p5-sink-008 |
| G-S08 | sinks | 4 | 1 | p5-sink-009, p5-sink-010 |
| G-S12 | sinks | 4 | 2 | p5-sink-016 |
| G-S17 | sinks | 4 | 2 | p5-sink-023 |
| G-S05a | sinks | 3 | 2 | p5-sink-005 |
| G-S06 | sinks | 3 | 1 | p5-sink-007 |
| G-S10 | sinks | 3 | 2 | p5-sum-014 |
| G-S13 | sinks | 3 | 2 | p5-sink-017 |
| G-S15c | sinks | 3 | 3 | p5-sink-021 |
| G-SW2b | sinks | 3 | 2 | p5-sum-033 |
| G-SW5 | sinks | 3 | 2 | p5-none-037 |
| G-S05b | sinks | 2 | 1 | p5-sink-006 |
| G-S11 | sinks | 2 | 1 | p5-sink-015 |
| G-S19c | sinks | 2 | 1 | p5-cand-027 |
| G-SW2c | sinks | 2 | 2 | p5-none-034 |
| G-S19a | sinks | 1 | 1 | p5-sink-025 |
| G-S20a | sinks | 1 | 1 | p5-none-028 |
| G-S20b | sinks | 1 | 1 | p5-cand-029 |

## Source CSV flow-kind counts

| flow_kind | rows |
| --- | --- |
| internal_transfer | 574 |
| http_request | 201 |
| config | 153 |
| request_param | 152 |
| param | 135 |
| cli | 129 |
| file | 45 |
| task_param | 29 |
| env | 27 |

## Sink CSV flow-kind counts

| flow_kind | rows |
| --- | --- |
| sql_text | 118 |
| internal_sql_wrapper | 86 |
| sql_fstring | 47 |
| sql_text_clause | 21 |
| bound_params | 14 |
| sql_concat | 9 |
| sql_format_call | 2 |

Schema validation against `assets/labels_schema.json`: PASS (structural check implementing all constraints incl. the `contains` rule; run in diagnostics/gen_labels_pass5.py).

Note: entry `p5-san-067` (sanitize_clause/validate_adhoc_subquery) is a documented function-level sanitizer with no backing CSV row; all other 65 entries cover the 1742 CSV rows via the groups above.
