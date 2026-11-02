# Pass 5 (CWE-89 SQL Injection) Label Statistics

- run_id: `django-pass5-cwe89-20261020`
- generated_at: 2026-10-20T11:39:27+00:00
- model: **glm-5.3** (in-context labeling by the glm-5.3 agent session operating the Claude Code harness; no external LLM API calls)
- batches: **12** (B01-B12; scope and row counts in `labels_raw_pass5.json`)
- total candidates processed: **3217** (2609 source rows + 608 sink rows from extraction CSVs)
- 100% row coverage: every CSV row is assigned to exactly one of 41 semantic groups
- labels.json entries after dedup: **56** (pass 5) + 1 empty pass-1 block required by the schema `contains` constraint

## Entries by role (pass 5)

| role | entries |
| --- | --- |
| source | 13 |
| sink | 16 |
| sanitizer | 2 |
| summary | 12 |
| none | 13 |

## Entries by classification

| classification | entries |
| --- | --- |
| tp | 37 |
| fp | 13 |
| candidate | 6 |
| unknown | 0 |

## Candidate rows by assigned label role

| role | CSV rows covered |
| --- | --- |
| source | 1116 |
| sink | 254 |
| sanitizer | 94 |
| summary | 667 |
| none | 1086 |

## Group overview

| group | csv | rows | files | entry |
| --- | --- | --- | --- | --- |
| P5-handler-request | sources | 631 | 79 | p5-src-046 |
| P13-settings | sources | 499 | 144 | p5-none-054 |
| G9-schema-summary | sinks+sources | 240 | 17 | p5-sum-020 |
| G1-execute-callsite | sinks | 220 | 46 | p5-sink-001 |
| P7-cli-options | sources | 204 | 42 | p5-src-048 |
| P8-addargument-fp | sources | 179 | 37 | p5-none-049 |
| G23-migration-ops | sinks+sources | 177 | 11 | p5-sum-034 |
| P1-request-field | sources | 149 | 27 | p5-src-037, p5-src-038, p5-src-039, p5-src-040, p5-src-041 |
| P15-internal-other | sources | 115 | 43 | p5-none-055 |
| G15-sql-construction | sinks | 103 | 30 | p5-none-027 |
| GB-boundparams-san | sinks | 94 | 25 | p5-san-035 |
| G10-introspection-summary | sinks+sources | 78 | 17 | p5-sum-021 |
| P11-file-read | sources | 65 | 32 | p5-none-052 |
| G11-creation-summary | sinks+sources | 57 | 8 | p5-sum-022 |
| P12-os-environ | sources | 57 | 19 | p5-none-053 |
| P3-request-get | sources | 52 | 24 | p5-src-044 |
| P10-file-open | sources | 36 | 22 | p5-none-051 |
| P6-url-kwargs | sources | 30 | 8 | p5-src-047 |
| G20-cache-summary | sinks+sources | 27 | 2 | p5-sum-032 |
| P2-wsgi-environ | sources | 27 | 5 | p5-src-042, p5-src-043 |
| G12-ops-summary | sinks+sources | 25 | 9 | p5-sum-023 |
| G13a-connstate | sinks+sources | 22 | 9 | p5-sum-024 |
| G17-cli-dispatch | sinks+sources | 17 | 7 | p5-sum-029 |
| G13b-static-fp | sinks | 13 | 10 | p5-none-025 |
| P4-map-ops | sources | 13 | 5 | p5-src-045 |
| G21-mgmtsql-summary | sinks+sources | 12 | 6 | p5-sum-033 |
| G6-compiler | sinks+sources | 10 | 2 | p5-sum-012 |
| P9-cli-argv | sources | 10 | 4 | p5-src-050 |
| G16-cliexecute-fp | sinks | 9 | 5 | p5-none-028 |
| G7-orm-raw-apis | sinks | 9 | 3 | p5-sink-013, p5-sink-014, p5-sink-015, p5-sink-016, p5-sink-017, p5-sum-018 |
| G2a-cursorwrapper-def | sinks | 6 | 1 | p5-sink-002, p5-sink-003 |
| G14-msg-fp | sinks | 5 | 3 | p5-none-026 |
| G2b-callproc | sinks | 5 | 1 | p5-sink-004 |
| G3-sqlite-wrapper | sinks | 4 | 1 | p5-sink-006, p5-sink-007 |
| G4-mysql-wrapper | sinks | 4 | 1 | p5-sink-008, p5-sink-009 |
| G5-oracle-wrapper | sinks | 4 | 1 | p5-sink-010, p5-sink-011 |
| G18-redis-fp | sinks | 2 | 1 | p5-none-030 |
| G24-testinfra-fp | sinks | 2 | 1 | p5-none-056 |
| G2c-wrapper-glue | sinks | 2 | 1 | p5-sum-005 |
| G8-schemaeditor-execute | sinks | 2 | 1 | p5-sink-019 |
| G19-register-fp | sinks | 1 | 1 | p5-none-031 |

## Source CSV family counts

| flow_kind | rows |
| --- | --- |
| param | 661 |
| internal_transfer | 657 |
| config | 499 |
| cli | 393 |
| http_request | 175 |
| file | 101 |
| request_param | 66 |
| env | 57 |

## Sink CSV flow-kind counts

| flow_kind | rows |
| --- | --- |
| sql_text | 251 |
| internal_sql_wrapper | 155 |
| sql_percent_format | 99 |
| bound_params | 94 |
| sql_concat | 5 |
| sql_fstring | 3 |
| sql_format_call | 1 |
