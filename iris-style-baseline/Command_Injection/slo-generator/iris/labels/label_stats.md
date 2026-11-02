# Label Statistics - Pass 2 (CWE-78 Command Injection)

- Project: slo-generator (source tree: dataset/codeql_databases/slo-generator_vuln)
- Run: `slo-generator-iris-pass2-cwe78-20261016`
- Generated: 2026-10-16T04:23:30+00:00
- LLM model: glm-5.3 (Claude Code CLI agent, single deterministic pass)
- Batches: 10 (b01-b07 source candidates by module family, b08-b10 sink candidates)
- Total CSV candidates processed: 267 (sources.csv: 225 rows, sinks.csv: 42 rows) - all processed one-to-one, none dropped

## Role counts (Pass 2)

| role | count |
| --- | --- |
| source | 27 |
| sink | 12 |
| sanitizer | 0 |
| summary | 67 |
| none | 161 |

## Classification counts

| classification | count |
| --- | --- |
| tp | 6 |
| fp | 161 |
| candidate | 90 |
| unknown | 10 |

## Confidence distribution

| bucket | count |
| --- | --- |
| >=0.75 | 83 |
| 0.65-0.74 | 29 |
| 0.55-0.64 | 112 |
| 0.45-0.54 | 42 |
| <0.45 | 1 |

## Schema flow_kind mapping (from extraction CSV flowKind)

| flow_kind (schema) | count |
| --- | --- |
| argument | 40 |
| field | 101 |
| param | 66 |
| return | 15 |
| unknown | 45 |

## Candidates by module

| module | candidates |
| --- | --- |
| base.py:exporters | 11 |
| bigquery.py:exporters | 6 |
| cli.py:slo_generator | 46 |
| cloud_monitoring.py:backends | 8 |
| cloud_monitoring.py:exporters | 1 |
| cloud_service_monitoring.py:backends | 18 |
| compute.py:slo_generator | 9 |
| constants.py:slo_generator | 8 |
| custom_backend.py:custom | 6 |
| custom_exporter.py:custom | 2 |
| datadog.py:backends | 10 |
| datadog.py:exporters | 1 |
| dynatrace.py:backends | 16 |
| dynatrace.py:exporters | 1 |
| elasticsearch.py:backends | 4 |
| main.py:api | 25 |
| migrator.py:migrations | 35 |
| prometheus.py:backends | 16 |
| prometheus.py:exporters | 1 |
| pubsub.py:exporters | 3 |
| report.py:slo_generator | 8 |
| setup.py:slo-generator_vuln | 2 |
| utils.py:slo_generator | 30 |

## Deduplication / exclusion accounting

- All 267 CSV rows carry an entry in labels.json; no row was removed.
- 17 rows are labeled `none`/`fp` as same-location extraction noise (duplicates/base expressions of a primary row; each rationale names its primary row):
  - os.environ attribute-vs-subscript / .get base-expression pairs: S042, S044, S046, S077, S087, S089, S091, S093, S131, S133, S135, S181, S183
  - request.data attribute vs base64.b64decode at the same line: S140, S149
  - Path.open() handle expression vs .read() at the same line: S163, S215
- 5 rows matched the assignment LHS (subscript target) of `os.environ[...] = value` writes as reads - the write side is recorded in sinks.csv (K007-K009, K029-K030): S041, S043, S045, S180, S182
- Total same-location noise rows: 22 (17 duplicate/base + 5 write-LHS); none removed from labels.json.
- Excluded from candidate scope earlier (Step 2, not re-processed here): tests/unit/**, logging-only helpers.

## Low-confidence entries flagged for manual review (confidence < 0.55)

- `K010` summary/unknown conf=0.40 - cloud_monitoring.py:234 - get_aggregation wrapper (cloud_monitoring.py:234): aligner/reducer params flow into an enum member lookup via getattr (lines 254/256); the selected member is a field value, never invoked - weak propagation edge retained for recall.
- `S012` source/unknown conf=0.45 - bigquery.py:166 - json.loads on a BigQuery API response: remote-service data decode boundary (remote_data family). Decoded rows feed SLO report data only; no observed route into command or name-resolution boundaries. Retained at low confidence for recall.
- `S078` source/unknown conf=0.45 - cloud_service_monitoring.py:683 - json.loads on a Cloud Service Monitoring API response: remote-service decode boundary; decoded SLO data feeds comparison logic; no route into command or name-resolution boundaries; low-confidence recall entry.
- `S096` summary/unknown conf=0.45 - custom_backend.py:28 - samples/custom CustomBackend.good_bad_ratio(slo_config): documented plugin-sample target of the dispatched backend interface; body ignores the arguments (returns constants). Kept as a propagation edge with low confidence.
- `S099` summary/unknown conf=0.45 - custom_backend.py:41 - samples/custom CustomBackend.query_sli(slo_config): plugin-sample dispatched interface; body ignores arguments.
- `S100` summary/unknown conf=0.45 - custom_exporter.py:26 - samples/custom CustomMetricExporter.export_metric(data): plugin-sample dispatched interface; body only logs the data.
- `S101` summary/unknown conf=0.45 - custom_exporter.py:44 - samples/custom CustomSLOExporter.export(data, **config): plugin-sample dispatched interface; body only logs the data.
- `S125` source/unknown conf=0.45 - dynatrace.py:339 - json.loads inside DynatraceClient.to_json: decode of the Dynatrace HTTP API response; remote-service data boundary feeding report values; no route to command/name-resolution boundaries; low-confidence recall entry.
- `S193` source/unknown conf=0.45 - prometheus.py:151 - json.loads on the Prometheus API response (prometheus.py:151): remote-service decode boundary; decoded metric values feed the report; no route to command/name-resolution boundaries; low-confidence recall entry.
- `K015` summary/unknown conf=0.45 - dynatrace.py:274 - DynatraceClient.request wrapper (dynatrace.py:274): URL construction from backend config plus requests invocation; HTTP surface (SSRF pass scope), no command semantics.
- `S006` summary/candidate conf=0.50 - base.py:225 - Abstract dispatched exporter method: request-derived metric dict enters child-class bodies (Datadog/Prometheus/... exporters). Bodies call monitoring APIs only; summary edge carries taint into dynamically dispatched plugin bodies.
- `S007` summary/candidate conf=0.50 - bigquery.py:37 - BigqueryExporter.export(data): request-derived report data propagated into BigQuery client calls; no command execution inside.
- `S038` source/candidate conf=0.50 - cli.py:133 - CLI --config (envvar CONFIG_PATH) value: operator-controlled path whose file content supplies backends/exporters class names; written to os.environ['CONFIG_PATH'] (cli.py:137) and read back by api/main.py:33.
- `S040` source/candidate conf=0.50 - cli.py:133 - --target value (default run_compute, envvar-routed): CLI/env-supplied function name handed to the Functions Framework dispatcher (cli.py:140-143 ctx.invoke(_cli, target=target, ...)); selects which module-level function in api/main.py receives requests; operator-controlled, framework resolves the name within that module.
- `S057` summary/candidate conf=0.50 - cloud_monitoring.py:46 - slo_config param of the dynamically dispatched CloudMonitoring backend method: request-derived config carried into the backend body; body builds Cloud Monitoring API filter objects only, no process execution.
- `S060` summary/candidate conf=0.50 - cloud_monitoring.py:36 - CloudMonitoringExporter.export_metric(data): request-derived metric data into the dispatched exporter body; body uses the Cloud Monitoring API only.
- `S063` summary/candidate conf=0.50 - cloud_service_monitoring.py:61 - slo_config param of the dispatched CloudServiceMonitoring backend method; request-derived config into the backend body (API object construction only).
- `S104` summary/candidate conf=0.50 - datadog.py:45 - slo_config param of the dispatched Datadog backend method; request-derived config into the backend body (Datadog API queries only).
- `S108` summary/candidate conf=0.50 - datadog.py:80 - slo_config param of the dispatched Datadog query_sli method; same plugin-interface propagation as S104.
- `S112` summary/candidate conf=0.50 - datadog.py:42 - DatadogExporter.export_metric(data): request-derived metric data into the dispatched exporter body; Datadog API calls only.
- `S113` summary/candidate conf=0.50 - dynatrace.py:42 - DynatraceExporter.export_metric(data): request-derived metric data into the dispatched exporter body; Dynatrace API calls only.
- `S116` summary/candidate conf=0.50 - dynatrace.py:43 - slo_config param of the dispatched Dynatrace query_sli method; request-derived config into the backend body (Dynatrace API calls only).
- `S120` summary/candidate conf=0.50 - dynatrace.py:64 - slo_config param of the dispatched Dynatrace good_bad_ratio method; same plugin-interface propagation.
- `S128` summary/candidate conf=0.50 - elasticsearch.py:44 - slo_config param of the dispatched Elasticsearch backend method; request-derived config into the backend body (ES query body only).
- `S130` source/candidate conf=0.50 - main.py:33 - os.environ['CONFIG_PATH'] module-level read (api/main.py:33): deployment/operator-controlled path selecting the global config file whose backends/exporters entries (incl. class names) feed the import chain; distinct trust boundary from request data (membership-checked in utils.get_backend/get_exporters).
- `S132` source/candidate conf=0.50 - main.py:34 - os.environ.get('EXPORTERS_PATH') read (api/main.py:34): operator-controlled exporter-config path; file content feeds the exporter entries used by get_exporters (allowlist-checked).
- `S152` summary/candidate conf=0.50 - main.py:106 - slo_report['exporters'] read (api/main.py:106): request-controlled exporter *names*; utils.get_exporters (utils.py:220-223) validates membership against the trusted global config entries, so the class strings themselves come from the trusted config - documented trust boundary, not a direct class-name injection path.
- `S153` summary/candidate conf=0.50 - main.py:108 - get_exporters(config, spec) call (api/main.py:108): request-selected names resolved against trusted config entries (allowlist).
- `S164` source/candidate conf=0.50 - migrator.py:118 - yaml.util.load_yaml_guess_indent(slo_config_str) (migrator.py:118): decode of the migration input file; parsed dict feeds version detection (curver used in the getattr name at migrator.py:139) and the v1->v2 transformation.
- `S186` summary/candidate conf=0.50 - prometheus.py:43 - slo_config param of the dispatched Prometheus query_sli method; request-derived config into the backend body (Prometheus HTTP client only).
- `S190` summary/candidate conf=0.50 - prometheus.py:61 - slo_config param of the dispatched Prometheus good_bad_ratio method; same plugin-interface propagation.
- `S194` summary/candidate conf=0.50 - prometheus.py:37 - PrometheusExporter.export_metric(data): request-derived metric data into the dispatched exporter body; Prometheus client only.
- `S195` summary/candidate conf=0.50 - pubsub.py:34 - PubsubExporter.export(data): request-derived report data serialized and published to a Pub/Sub topic; no command execution.
- `S204` source/candidate conf=0.50 - utils.py:45 - os.environ as the ${VAR} substitution context (load_configs ctx default, utils.py:45): environment values are interpolated into config content (utils.py:132 full_value.replace) - operator-controlled boundary feeding config strings.
- `S207` source/candidate conf=0.50 - utils.py:63 - os.environ as the load_config ctx default (utils.py:63): same ${VAR} substitution context as S204.
- `S213` source/candidate conf=0.50 - utils.py:103 - os.environ as the parse_config ctx default (utils.py:103): ${VAR} substitution context; env values become config string content.
- `S214` source/candidate conf=0.50 - utils.py:132 - ctx[var] subscript (utils.py:132) inside replace_env_vars: environment variable value substituted into config content; operator-controlled values are interpolated into the parsed config.
- `K020` sink/candidate conf=0.50 - migrator.py:78 - getattr(sys.modules[__name__], f"ebp_v1to{version}") (migrator.py:78): function name built from the fixed 'v1' and the CLI --version value; the resolved member is invoked at migrator.py:79. Selection is bounded to attributes of the migrator module; local-operator input; no value allowlist.
- `K021` summary/candidate conf=0.50 - migrator.py:78 - f-string f"ebp_{curver}to{version}" (migrator.py:78): name construction feeding the getattr at the same line (sink K020); taint propagates through interpolation.
- `K022` sink/candidate conf=0.50 - migrator.py:79 - ebp_func(...) invocation (migrator.py:79): calls the name-resolved migration function with CLI-derived ebp paths.
- `K023` sink/candidate conf=0.50 - migrator.py:87 - getattr(sys.modules[__name__], f"exporters_v1to{version}") (migrator.py:87): same shape as K020; name from fixed 'v1' + CLI --version; invoked at migrator.py:89.
- `K024` summary/candidate conf=0.50 - migrator.py:88 - f-string name construction (migrator.py:88) feeding the getattr at line 87 (sink K023).
- `K025` sink/candidate conf=0.50 - migrator.py:89 - exporters_func(...) invocation (migrator.py:89): calls the name-resolved migration function.

## Key sink entries (argument-injection-shaped dispatch chain; zero OS command-execution APIs exist)

- `K014` conf=0.60 - compute.py:119 - instance().export(data, **config)
- `K020` conf=0.50 - migrator.py:78 - getattr(sys.modules[__name__], f"ebp_v1to{version}")
- `K022` conf=0.50 - migrator.py:79 - ebp_func(...) invocation
- `K023` conf=0.50 - migrator.py:87 - getattr(sys.modules[__name__], f"exporters_v1to{version}")
- `K025` conf=0.50 - migrator.py:89 - exporters_func(...) invocation
- `K026` conf=0.55 - migrator.py:139 - getattr(sys.modules[__name__], f"slo_config_{curver}to{version}")
- `K028` conf=0.55 - migrator.py:141 - slo_func(...) invocation
- `K032` conf=0.60 - report.py:203 - cls(client=client, **backend_cfg)
- `K033` conf=0.70 - report.py:204 - getattr(instance, method)
- `K034` conf=0.65 - report.py:216 - method(self.timestamp, self.window, config)
- `K041` conf=0.60 - utils.py:337 - getattr(importlib.import_module(package), name) - name argument
- `K042` conf=0.65 - utils.py:337 - importlib.import_module(package)

## Source entries

- `S012` unknown conf=0.45 - bigquery.py:166
- `S023` candidate conf=0.60 - cli.py:77
- `S024` candidate conf=0.60 - cli.py:77
- `S038` candidate conf=0.50 - cli.py:133
- `S040` candidate conf=0.50 - cli.py:133
- `S078` unknown conf=0.45 - cloud_service_monitoring.py:683
- `S125` unknown conf=0.45 - dynatrace.py:339
- `S130` candidate conf=0.50 - main.py:33
- `S132` candidate conf=0.50 - main.py:34
- `S136` tp conf=0.90 - main.py:41
- `S137` tp conf=0.90 - main.py:54
- `S139` tp conf=0.85 - main.py:59
- `S145` tp conf=0.85 - main.py:80
- `S146` tp conf=0.85 - main.py:92
- `S147` candidate conf=0.60 - main.py:94
- `S148` tp conf=0.80 - main.py:94
- `S159` candidate conf=0.65 - migrator.py:48
- `S162` candidate conf=0.55 - migrator.py:117
- `S164` candidate conf=0.50 - migrator.py:118
- `S193` unknown conf=0.45 - prometheus.py:151
- `S204` candidate conf=0.50 - utils.py:45
- `S207` candidate conf=0.50 - utils.py:63
- `S213` candidate conf=0.50 - utils.py:103
- `S214` candidate conf=0.50 - utils.py:132
- `S216` candidate conf=0.55 - utils.py:142
- `S217` candidate conf=0.60 - utils.py:145
- `S224` candidate conf=0.55 - utils.py:450

---

## v2 Post-triage Remediation Addendum (2026-10-16)

4 entries were added after the v1 run (driven by the independent LLM path review
in `report/llm_triage.json` and the operator-supplied fix-commit reference; see
`labels/labels.json` metadata notes):

| id | role | classification | confidence | location |
| --- | --- | --- | --- | --- |
| S226 | source | candidate | 0.55 | migrator.py:228 open(exp_path) |
| S227 | source | candidate | 0.55 | migrator.py:263 open(ebp_path) |
| K043 | sink | tp | 0.85 | migrator.py:229 yaml.load(Loader=yaml.Loader) |
| K044 | sink | tp | 0.85 | migrator.py:264 yaml.load(Loader=yaml.Loader) |

Updated role counts: source 29, sink 14 (total entries 271). Rerun outcome:
`results_v2/pass2.sarif` = 12 alerts (original 10 + migrator.py:229/264, the two
lines changed by upstream fix commit 36318be) — the project's real vulnerability
is now hit. See `report/query_generation_notes.md` §9 and
`report/iris_report_v2.md`.
