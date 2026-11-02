# Label Statistics — maltrail, Pass 2 (CWE-78)

**Run ID:** `maltrail-iris-pass2-20261015` · Generated 2026-10-15
**Snapshot:** source tree and CodeQL database both at sha `bb4d24b0` (sourceLocationPrefix ==
tree; every CSV line number matches the current source file). Each entry's first evidence
string is the verbatim source line at its location, pulled from the tree at generation time
by `labels/scripts/build_labels.py`; remaining evidence strings are verbatim lines or clearly
marked cross-reference notes.

## Labeling session

| Item | Value |
| --- | --- |
| Model | glm-5.3 (in-session labeling by the agent's underlying LLM; no external LLM API calls) |
| Batches | 5 (batch-1 core/httpd.py 107 rows · batch-2 sensor.py 154 · batch-3 core/* 200 · batch-4 feeds/plugins/static/custom/six 155 · batch-5 all sinks 51) |
| Candidate rows processed | 667 (sources.csv 616 + sinks.csv 51) — **all rows dispositioned** |
| Rows merged into sibling entries | 116 (source-side duplicate AST nodes at one line + retrieve_content return/internal_transfer facets; sink-side arg-ast/arg-api/shell_true/cmd_format/wrapper facets of one subprocess call site) |
| Supplementary (out-of-CSV) entries | 0 |
| Final label entries | 551 |
| Re-ask threshold | 0.55 — entries below threshold: 0 (minimum confidence used: 0.5, remote-derived trail/ipcat file reads) |

## Entries by role × classification

| Role | tp | candidate | fp | total |
| --- | ---: | ---: | ---: | ---: |
| source | 80 | 78 | 0 | 158 |
| sink | 1 | 1 | 28 | 30 |
| sanitizer | 0 | 0 | 0 | 0 |
| summary | 46 | 0 | 0 | 46 |
| none | 0 | 0 | 317 | 317 |
| **total** | **127** | **79** | **345** | **551** |

Accept / reject / unresolved by label entry: **accepted (tp) 127 · rejected (fp) 345 ·
unresolved (candidate, human review) 79**. By raw CSV row (667 rows, before merging):
**tp 140 · fp 385 · candidate 142** — the exact per-row verdicts are in
`labels/labels_raw_pass2.json` (`source_row_dispositions` + `sink_row_dispositions`).

## Confirmed (tp) sink — 1 site

| # | Entry | Site | Confidence |
| --- | --- | --- | --- |
| 1 | p2-e-522 | `core/httpd.py:399` `subprocess.check_output("logger ... %s password for %s from %s port %s" % (..., params.get("username"), self.client_address[0], self.client_address[1]), stderr=subprocess.STDOUT, shell=True)` | 0.95 |

Argument 0 (the command string) is the dangerous parameter; `shell=True` routes it through
/bin/sh; the `%`-format substitution values are the request parameter `username` (decoded by
`parse_qs`, read at :320/:334) and the client socket address. No quoting/escaping exists on
the path, and the site executes for failed logins too (:397 `if not IS_WIN:` is outside the
`if valid:` block), so the login check is not a gate. Merged rows: arg (ast), arg (api),
shell_true, cmd_format, internal_exec_wrapper (`_login`).

Candidate sink (diagnostics only): `sensor.py:1037`
`subprocess.Popen("schedtool ... %02x %d" % (affinity, os.getpid()), shell=True)` (p2-e-525,
0.60) — genuine shell execution with a dynamically formatted command, but both substitution
values are internally derived; manual review requested.

Rejected (fp) sinks — 28 entries: the six static-literal
`subprocess.check_output("sysctl hw"/"vmstat -s"/"free -b"/"top -n 1"/grep/ps, shell=True)`
sites (core/settings.py:202/:208/:214/:220, sensor.py:1031/:1032) and 22 message-formatting
rows matched by the wrapper-scope cmd_format rule (httpd.py:349/:395 cookie/response text;
sensor.py:915-:1043 init diagnostics).

## Confirmed (tp) sources — 80 entries

- HTTP request state on `ReqHandler` (29): `self.path` (:125/:156/:194), `self.data`
  (:131/:232), `self.headers` + `self.headers.get()` + `self.headers[...]`
  (:162/:206/:229/:237/:257/:546/:547/:647), `self.rfile`(+`.read()`) (:230/:707/:708),
  `self.client_address` (:244/:388/:399)
- Request param reads (14): `params.get("username"/"hash"/"nonce"/"address"/"callback"/"date"/"from"/"to")`
  (:137/:138/:320/:321/:322/:332/:334/:399/:435/:439/:441/:507/:666/:672)
- Request decode (3): `parse_qs` (:131/:134), `unquote_plus` (:231)
- Handler entry params (9): `_login/_logout/_whoami/_check_ip/_trails/_ping/_fail2ban/
  _events/_counts` (arg 1 = params dict, dispatched from :147; `_format` was rejected)
- Packet boundary (19, sensor.py): `_cap.next()` (:1169), `packet_handler` args
  (:1092 ×3), `_process_packet` args (:274 ×4), `struct.unpack` (×7), `unquote` (×4)
- Plugin/event boundary (6): `plugin(event_tuple, packet)` args (plugins/peek.py:14,
  plugins/strings.py:14), `log_event(event_tuple, packet)` args 0/1 (core/log.py:134)

## Candidate (unresolved) sources — 78 entries

- Remote feed/update content (67): `retrieve_content(__url__)` call sites (54 feed files +
  core/common.py:64/:220 recursion + core/update.py:89/:186), `urlopen(...).read()` /
  response decodes inside `retrieve_content` (core/common.py:50/:51/:59/:61,
  core/update.py:354)
- Second-order network-derived event-log reads (8): core/httpd.py:483/:516/:531/:532/:563/
  :638/:694/:695 (`_fail2ban`/`_events`/`_counts`)
- Remote-derived trail/ipcat files (3): core/httpd.py:451, core/common.py:245,
  core/update.py:368

All retained pending a threat-model decision: the feed/URL endpoints are hardcoded, but
much of the content travels over plain HTTP and originates from remote servers; no path from
any of this content to a command string exists in the snapshot.

## Summary entries — 46

- `log_event(...)` calls (40, sensor.py:198-:841 + core/log.py:127): packet-derived event
  tuples → event log write + plugin dispatch (core/log.py:221-223)
- Dynamic handler dispatch `getattr(self, "_%s" % path)(params)` (core/httpd.py:147, 0.85):
  the taint step connecting the parse_qs sources to the handler-parameter sources and the
  :399 sink
- `_process_packet(packet, ...)` call (sensor.py:1144)
- Multiprocessing buffer transport (core/parallel.py:37/:38/:97, `read_block`): shared-memory
  packet blocks read worker-side

## Sanitizers

None. No sanitizer entry was created: the login validity check (core/httpd.py:320-336) does
not gate the :399 sink (it executes for failed logins too), the `".." in dates` guard
(httpd.py:509) is a path-domain (pass 1) check, and no quoting/escaping construct
(`shlex.quote` etc.) exists anywhere in the snapshot.

## Rejected (fp) — 345 entries / 385 raw rows, main families

| Family | Raw rows | Reason |
| --- | ---: | --- |
| config.<NAME> reads | 237 | AttribDict filled from locally authored maltrail.conf, MALTRAIL_* env overrides and CLI options of the launching admin; remote client/traffic cannot write config values (dcnnt-py ConfigLoader precedent). The 238th config row (core/common.py:245, the TRAILS_FILE read inside `load_trails`) is a candidate, not fp — see candidate sources |
| CLI (sys.argv / optparse / options.X / getattr(options)) | 46 | controlled by the local user launching the process, not the remote attacker |
| env (os.environ / os.environ.get) | 10 | local process environment (MALTRAIL_*, $VAR interpolation, SUDO_UID/GID) |
| local trusted file/glob reads | 34 | whitelists/ua/worst_asn/cdn/bogon, /proc, dmesg.boot, static HTML, config file, log output handles (write side), devnull, profiling output, trail directory listings |
| sink-side (message formatting + static commands) | 41 | 6 static-literal subprocess sites + 22 wrapper-scope message-format rows (28 entries after merging) |
| non-boundary params | 8 | `load_trails(quiet)`, `read_config(config_file)` (local file), `log_event` skip flags ×2, `_format` content-tag params, `retrieve_content` params ×3 |
| `read_config` call sites | 3 | local config file via -c CLI option |
| vendored thirdparty/six | 5 | six lazy-module internals, outside the input boundary |
| intra-host UDP pipeline | 1 | core/log.py:249 `self.request` (LOG_SERVER sensor→server, content already covered by sensor-side sources) |

(Exact per-row verdicts: `labels/labels_raw_pass2.json`; counts are reproducible via
`labels/scripts/build_labels.py`.)

## Schema conformance

`labels/labels.json` was checked against
`iris_tools/augur-0.3.0/assets/labels_schema.json` (the schema exists; no structure was
invented): top-level keys, metadata required fields, passes/contains pass_id=1 stub (pass 1
Path Traversal has zero entries and was NOT labeled in this run), entry required fields,
role/classification/flow_kind enums, additionalProperties=false, and the
flow_kind="argument" ⇒ integer arg_index coupling all pass.

Extraction families map onto the schema flow_kind enum as: http_request / request_param /
config / cli / env attribute loads → `field`; decode & network returns → `return`; handler
parameters → `param`; data-handing calls and sink command arguments → `argument`.

## Constraint compliance

- No PyVul vulnerability ground truth (`cmd_sinks*.csv`, `confirmed_vulns.json`,
  `CVE申请报告.md`, `vulnerability_analysis_report.md`, `maltrail-safe-db`) was read; no
  CVE description or patch diff was consulted; labels were derived only from the candidate
  CSVs and the source tree.
- classification=tp here means "confirmed genuine for the assigned API role in pass 2" — it
  is NOT the final vulnerability ground-truth TP.
- No CodeQL compile/run/decode was executed in this step; no source, database or Augur
  installation file was modified. Files written: `labels/labels.json`,
  `labels/labels_raw_pass2.json`, `labels/label_stats.md`,
  `labels/scripts/build_labels.py`.

## Regeneration

```
cd C:\Users\lzh\Desktop\github\PyVul-main\iris_manual\maltrail\iris
python -I labels/scripts/build_labels.py    # rebuilds labels.json + labels_raw_pass2.json
```

The script reads `extraction/sources.csv` / `extraction/sinks.csv` and the maltrail_vuln
tree; every evidence string is a verbatim line pulled from the tree at generation time, so a
stale line number fails visibly rather than producing a fabricated citation.
