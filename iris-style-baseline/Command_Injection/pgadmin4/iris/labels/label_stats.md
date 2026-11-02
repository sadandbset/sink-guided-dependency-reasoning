# Label Statistics — pgadmin4, Pass 2 (CWE-78)

**Run ID:** `pgadmin4-iris-pass2-20261016` · Generated 2026-10-16
**Snapshot:** source tree and CodeQL database both at sha `61fa8b1` (sourceLocationPrefix ==
tree; every CSV line number was re-checked against the source file). Each entry's first
evidence string is the verbatim source line at its location, pulled from the tree at
generation time by `labels/scripts/build_labels.py`; remaining evidence strings are verbatim
lines or clearly marked cross-reference notes.

## Labeling session

| Item | Value |
| --- | --- |
| Model | glm-5.3 (in-session labeling by the agent's underlying LLM; no external LLM API calls) |
| Batches | 8 (batch-1 all sinks 60 rows · batch-2 flask request state 699 · batch-3 request field reads 46 · batch-4 json decode request-family 386 · batch-5 json decode other families 216 · batch-6 handler params 239 · batch-7 config reads 423 · batch-8 env 61 + cli 72 + internal_transfer 7) |
| Candidate rows processed | 2209 (sources.csv 2149 + sinks.csv 60) — **all rows dispositioned** |
| Rows merged into sibling entries | 504 (api+ast extraction facets of one call site; duplicate AST nodes at one line; sink-side arg-ast/arg-api/shell_true/cmd_format/wrapper/construction facets of one exec site) |
| Supplementary (out-of-CSV) entries | 0 |
| Final label entries | 1705 |
| Re-ask threshold | 0.55 — entries below threshold: 0 (minimum confidence used: 0.55, remote-API/upgrade-check response decodes) |

## Entries by role × classification

| Role | tp | candidate | fp | total |
| --- | ---: | ---: | ---: | ---: |
| source | 1068 | 24 | 0 | 1092 |
| sink | 2 | 5 | 10 | 17 |
| sanitizer | 0 | 0 | 0 | 0 |
| summary | 20 | 0 | 0 | 20 |
| none | 0 | 0 | 576 | 576 |
| **total** | **1090** | **29** | **586** | **1705** |

Accept / reject / unresolved by label entry: **accepted (tp) 1090 · rejected (fp) 586 ·
unresolved (candidate, human review) 29**. By raw CSV row (2209 rows, before merging):
**tp 1527 (1493 source + 7 sink + 27 summary) · fp 616 · candidate 66** — the exact
per-row verdicts are in `labels/labels_raw_pass2.json`
(`source_row_dispositions` + `sink_row_dispositions`).

## Confirmed (tp) sinks — 2 sites

| # | Entry | Site | Confidence |
| --- | --- | --- | --- |
| 1 | p2-e-1677 | `pgadmin/misc/__init__.py:274` `subprocess.getoutput(r'"{0}" --version'.format(full_path.replace('"', '""')))` inside `validate_binary_path` | 0.75 |
| 2 | p2-e-1698 | `pgadmin/misc/bgprocess/process_executor.py:330` `Popen(command, stdout=PIPE, stderr=PIPE, **kwargs)` with `kwargs['shell'] = True if _IS_WIN else False` inside `execute()` | 0.85 |

1. **misc/__init__.py:274** — argument 0 is a shell-interpreted string (getoutput always
   shells out) whose `full_path` derives from `data['utility_path']` of the
   `validate_binary_path` POST body (`request.data` → `json.loads` at :249-:253 →
   `replace_binary_path` at :258). Partial mitigations only: double-quote doubling, the
   operand sits inside double quotes, and `os.path.exists(binary_path)` at :268 confines
   the path to an existing filesystem entry — non-quote shell metacharacters are not
   blocked. tp means "genuine request-reachable command-execution sink", not a confirmed
   vulnerability; exploitability review requested.
2. **process_executor.py:330** — `command = argv[1:]` is the BatchProcess command list
   (`[self.cmd] + self.args`) handed over from the web process; on Windows it is
   shell-interpreted (`shell=True`), on POSIX it runs argv-list mode. The args originate
   from request JSON at the BatchProcess construction sites (backup/restore/maintenance/
   import_export/views/cloud). The only shell-relevant protection is
   `escape_dquotes_process_arg` (`bgprocess/__init__.py:157`, wraps only arguments that
   already start **and** end with a double quote in `#DQ#` markers, stripped again at
   :414) — double-quote handling, not shell quoting. The strongest command-reachable
   sink of the project; the inter-process handoff is covered by the
   `process_executor.py:414 sys.argv` source label (p2-e-1551) so the executor-side half
   of the chain is traceable.

## Candidate (unresolved) sinks — 5 sites

| Entry | Site | Conf. | Why unresolved |
| --- | --- | --- | --- |
| p2-e-1694 | `pgadmin/utils/passexec.py:36` `subprocess.run(self.cmd, shell=True)` | 0.60 | `self.cmd` = stored `passexec_cmd` (server API, `servers/__init__.py:1195`); double-gated by the SERVER_MODE `NotImplementedError` at :26-28 and desktop-mode single-user trust principal. |
| p2-e-1697 | `pgadmin/utils/master_password.py:140` `subprocess.Popen(command, shell=True)` | 0.60 | `command` = `config.MASTER_PASSWORD_HOOK` with `%u` → `current_user.username` (:41-:43); admin template + external-auth username, admin-gated feature; username charset control per auth source needs review. |
| p2-e-1684 | `pgadmin/tools/psql/__init__.py:182` `subprocess.Popen(connection_data)` | 0.60 | argv-LIST mode, no shell: socket-supplied db name reaches the connection string of the user's own psql session (argument-level surface only; intended /pty feature). |
| p2-e-1685 | `pgadmin/tools/psql/__init__.py:237` `process.write(r'"{0}" "{1}" 2>>&1'.format(...))` | 0.65 | dynamically formatted command typed into the running cmd.exe shell; socket-derived db name in operand, dquotes but no metachar escaping; the same socket client can already type arbitrary shell input into the terminal by design (own-session boundary question). |
| p2-e-1683 | `pgadmin/utils/__init__.py:375` `subprocess.getoutput('"{0}" --version'.format(full_path))` | 0.65 | shell probe with **no** dquote escaping (twin of the misc/:274 site); operand is the second-order binary-path preference (stored via the preferences API), not direct request data. |

Rejected (fp) sinks — 10 entries: static-literal commands
(`generate_keywords.py:20/:21` `os.popen('pg_config ...')`, `javascript_bundler.py:63`
`call(['yarn','run','bundle:dev'])`, `psql/__init__.py:235` `PtyProcess.spawn('cmd.exe')`)
and 6 message-formatting rows matched by the wrapper-scope cmd_format rule
(master_password:147/:153, process_executor:300/:360, processes.py:392/:394).

## Confirmed (tp) sources — 1068 entries

- Flask request-proxy state reads (552): `request.data` / `form` / `args` / `json` /
  `values` / `files` / `cookies` / `headers` / `environ` / `get_json` across 82 files,
  including the file_manager `req` alias and the browser `request_object` parameter
  convention (top files: sqleditor 133, debugger 64, erd 30, schema_diff 26,
  file_manager 23).
- Request field reads (22): `request.args/form/headers.get(...)` and subscripts.
- json request-body decodes (193 entries / 386 rows): `json.loads(request.data)` /
  `request.form['data']` / `req[key]` / request-assigned variables (backup:401,
  restore:135, import_export:241, maintenance:183, cloud:135/:247, preferences:191,
  misc:170/:187/:253, sqleditor ×12 …).
- json request-field decodes (59 entries / 118 rows): the browser-module
  `for k, v in request.args/form.items(): data[k] = json.loads(v)` idiom and its
  `data['cols']` / `data['coll_inherits']` / `val` variants.
- Handler entry params (239): URL path params of @blueprint.route handlers plus the four
  @sio.on /pty socket handler payloads (`start_process`/`socket_input`/`resize`/
  `server_disconnect` `data`).
- User import-file decodes (2): `import_export_servers/__init__.py:130` and
  `utils/__init__.py:613` — user-supplied import files whose content becomes server
  registration data (incl. `passexec_cmd`).
- Executor command transport (1): `process_executor.py:414` `sys.argv` — the inter-process
  BatchProcess command handoff (pairs with the :330 sink).
- (internal_transfer → summary, listed below.)

## Candidate (unresolved) sources — 24 entries

- Remote cloud-provider REST API response decodes (19): `resp.content` /
  `token_resp.content` in `misc/cloud/biganimal` (17) and `pgacloud/providers/biganimal`
  (2) — hardcoded provider endpoints over TLS, content produced by the remote provider;
  no path into a command string in this snapshot.
- Upgrade-check response (1): `browser/__init__.py:441` `json.loads(urlopen(...).read())`
  of `config.UPGRADE_CHECK_URL`.
- Cloud-deploy child stdout log (1): `processes.py:547` — second-order provider-derived
  'instance' JSON returned through the executor's log.
- Binary-path preference values (3): `servers/types.py:83/:198/:229` — second-order
  request data (preferences API) feeding `set_binary_path`/`get_utility_path` toward the
  `utils/__init__.py:375` getoutput probe; DB round-trip breaks direct taint.

All retained pending a threat-model decision (compromised provider account / network
position; preference-writing user as the CWE-78 adversary).

## Summary entries — 20

- BatchProcess constructions carrying request-derived args (10): backup:456/:465,
  restore:384, maintenance:238, import_export:326, views:2258 (`--command SQL` from
  request data), cloud rds:306, azure:690, biganimal:525, google:297.
- BatchProcess pipeline transport (3): `processes.py:330` (start(), both Popen calls +
  wrapper), `processes.py:381` (get_process_output), `process_executor.py:493`
  (Windows detached re-exec) — argv-list, fixed executables; the shell exec is the
  executor :330 sink.
- Utility-path propagation (6): `set_binary_path` ×3 (types.py:77 preference-derived,
  :246/:250 config-default), `replace_binary_path` ×3 (misc:258 request-derived,
  utils:363, types:184 preference-derived).
- psql argv construction (1): `get_connection_str` (psql:302) — socket db name → the
  :182 Popen / :237 cmd.exe write.

## Sanitizers

None. No sanitizer entry was created: `escape_dquotes_process_arg`
(`bgprocess/__init__.py:157`) only wraps arguments that already start and end with a
double quote in `#DQ#` markers and is stripped again in the executor (:414) — not shell
quoting; the double-quote doubling in `misc/__init__.py:275` is partial escaping recorded
in that sink entry's rationale, not modeled as a barrier; `os.path.exists` checks
(misc:268, utils:338) verify existence, not shell safety; `PasswordExec.get`'s
SERVER_MODE `NotImplementedError` (passexec.py:26-28) is a deployment-mode gate recorded
in the sink rationale; no `shlex.quote` / `pipes.quote` / `shlex.join` exists anywhere in
the project source.

## Rejected (fp) — 576 entries / 603 raw rows, main families

| Family | Entries (raw rows) | Reason |
| --- | ---: | --- |
| config.<NAME> reads | 421 (423) | local web/config.py + PGADMIN_CONFIG_* env overrides of the launching admin (evaluate_config.py:109-110, config.py:913); web client cannot write config values (maltrail/dcnnt-py config precedent). MASTER_PASSWORD_HOOK / DEFAULT_BINARY_PATHS rows carry tailored rationales pointing at their sink chains. |
| json loads non-request | 25 (46) | server-generated internal responses (schema_diff:408/:758, constraints:198), flask test-client helper (server_utils:31), local templates (acls ×5, vacuum_fields, themes), local credential file (google:94 + pgacloud google:37), executor status file (processes:662), DB rows (dashboard:417, query_history:124, p.desc ×4 sites), stored settings (import_export:216/:368, settings:195), psql:169 app-written env decode. |
| CLI | 71 (71) | setup.py / pgacloud provider argparse + pkg/win32/replace.py dev script argv — local admin CLI. (The 72nd cli row, process_executor.py:414 sys.argv, is the tp command-transport source, not fp.) |
| env | 57 (61) | os.environ of the locally launched server; process_executor PROCID/OUTDIR/PGPASSWORD internal handoff; psql:121/:123/:131 are env **write** targets the AST shape matched. |
| sink-side | 10 (13) | static-literal commands ×4 sites + message-formatting rows. |
| BatchProcess no-arg constructions | 2 (2) | `BatchProcess(id=pid)` / acknowledge — pid lookup only, no command data. |

## Schema conformance

`labels/labels.json` was checked against
`iris_tools/augur-0.3.0/assets/labels_schema.json` by
`labels/scripts/validate_labels.py` (the schema exists; no structure was invented; the
jsonschema package is not installed in this environment, so the constraints are
re-implemented literally): top-level keys, metadata required fields + language enum,
passes length + `contains` pass_id=1 stub (pass 1 Path Traversal has zero entries and
was NOT labeled in this run), entry required fields, role/classification/flow_kind
enums, confidence range, the flow_kind="argument" ⇒ integer arg_index coupling,
additionalProperties=false on every object, unique entry ids, and location file
existence all pass.

Extraction families map onto the schema flow_kind enum as: http_request /
request_param / config / cli / env attribute loads → `field`; json decode returns →
`return`; handler parameters → `param`; data-handing calls and sink command arguments →
`argument`.

## Constraint compliance

- No PyVul vulnerability ground truth (`CVE_application_report.md`,
  `vulnerability_audit_report.md`, `cmd_sinks*.csv`, the `第一审查` file,
  `pgadmin4-db/cmd_sinks.csv`) was read; no CVE description or patch diff was consulted;
  labels were derived only from the candidate CSVs and the pgadmin4_vuln source tree.
- classification=tp here means "confirmed genuine for the assigned API role in pass 2" —
  it is NOT the final vulnerability ground-truth TP; none of the exec sites is presumed
  vulnerable (the BatchProcess/psql/passexec/master-hook features are the product's
  intended command features, recorded for labeling only).
- No CodeQL compile/run/decode was executed in this step; no source, database or Augur
  installation file was modified. Files written: `labels/labels.json`,
  `labels/labels_raw_pass2.json`, `labels/label_stats.md`,
  `labels/phase1_review.md`, `labels/scripts/{analyze_candidates.py, build_labels.py,
  validate_labels.py}`.

## Regeneration

```
cd C:\Users\lzh\Desktop\github\PyVul-main\iris_manual\pgadmin4\iris
python -I labels/scripts/build_labels.py      # rebuilds labels.json + labels_raw_pass2.json
python -I labels/scripts/validate_labels.py   # schema conformance check
```

The script reads `extraction/sources.csv` / `extraction/sinks.csv` and the pgadmin4_vuln
tree; every evidence string is a verbatim line pulled from the tree at generation time,
so a stale line number fails visibly rather than producing a fabricated citation.
