# Query Generation Notes — maltrail, Pass 2 (CWE-78)

**Augur 0.3.0 · Phase 2 Step 4–5** · Run `maltrail-iris-pass2-20261015` · Generated 2026-10-15
**Inputs:** `iris/labels/labels.json` (human-reviewed, 551 entries: 80 tp source / 1 tp sink / 0 sanitizer / 46 tp summary / 78 candidate source + 1 candidate sink / 345 fp) and the source tree at `dataset/codeql_databases/maltrail_vuln` (sha bb4d24b0, identical to the CodeQL database snapshot — tree, DB and CSV line numbers agree 1:1).
**Outputs:** `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass2_CommandInjection.ql` (formal), plus the supplementary `diagnostics/Pass2_CommandInjectionDiagnostics.ql` (candidate labels only; NOT a formal result).
**Toolchain:** CodeQL CLI 2.25.1, `codeql/python-all` resolved from the local pack cache via `iris/qlpack.yml` (name `iris/maltrail-cwe78`). Per the task directive, **only files were generated — no CodeQL compile or analysis was executed in this step**; every QL idiom used (API-graph call conversion `cn.getNode().getNode().(Call)`, `shellTrueCall` keyword check, `DataFlow::exprNode`/`parameterNode` conversions, `Function.getArg`/`getPositionalArg`, `getRelativePath()` pinning) is reused verbatim from this project's compile-verified Phase-1 extraction queries and the compile-verified dcnnt-py / langchain Phase-2 artifacts. `codeql query compile` / `codeql database analyze` are deferred to the run step.

**Threat model (from the reviewed labels):** any client that reaches the reporting-server port controls the request line, headers, POST body (parse_qs-decoded parameters) and the client socket address; the sensor side additionally treats monitored wire traffic as attacker-influenced. The single confirmed sink — the `logger` shell command in `ReqHandler._login` — interpolates `params.get("username")` and `self.client_address` into a `shell=True` string with no quoting anywhere on the path, and executes for **failed** logins too (`if not IS_WIN:` at :397 is outside `if valid:`), so authentication is not a gate.

---

## 1. Label ID → CodeQL predicate mapping

All library predicates take `(DataFlow::Node, string passKey)` (summaries: `(DataFlow::Node, DataFlow::Node, string passKey)`). Pass-key dispatch (WORKFLOW.md 5.1.5):

| Pass key | Entry classifications admitted | Used by |
| --- | --- | --- |
| `command_injection` | `tp` only | `queries/Pass2_CommandInjection.ql` (formal) |
| `command_injection_diagnostics` | `tp` + `candidate` | `diagnostics/Pass2_CommandInjectionDiagnostics.ql` (NOT formal) |

Rationale: labels.json defines `candidate` as "plausible but unresolved, human review requested". Pending-review items must not become formal findings; they are preserved in the diagnostics query so recall is not lost (mirrors the task directive: candidate/diagnostic paths and internal-wrapper propagation checks belong in diagnostics, never in the formal result set).

### 1.1 MySources::isSource(node, passKey)

| Source family (predicate) | Label IDs (all `source`/tp) | Matching shape |
| --- | --- | --- |
| request state — `self.<attr>` | p2-e-054 (path :125), 062 (:156), 070 (:194), 056 (data :131), 078 (:232), 067 (headers :162), 072 (:206), 074 (:229), 076 (rfile :230), 080 (:237), 084 (:257), 131 (:546), 132 (:547), 136 (:647), 081 (client_address :244), 101 (:388), 103 (:399), 145/146/148 (request :706/:707/:708), 147 (rfile :707) | `self.{path,data,headers,rfile,client_address,request}` attribute node, file-pinned to `core/httpd.py` |
| request state — header/body calls | p2-e-066/071/073/079/083/130/135 (`self.headers.get(...)` :162/:206/:229/:237/:257/:546/:647), p2-e-075 (`self.rfile.read(n)` :230) | attr-call result, receiver `self.headers`/`self.rfile` |
| request decode | p2-e-055/057 (parse_qs :131/:134), p2-e-077 (unquote_plus :231) | `_urllib.parse.parse_qs/unquote_plus` call result, file-pinned to `core/httpd.py` |
| request param reads | p2-e-092/093/094/096/097 (username/hash/nonce :320/:321/:322/:332/:334), 102 (:399), 108/109/110 (address/callback :435/:439/:441), 124 (date :507), 138/139 (from/to :666/:672), 058/059 (params[key] :137/:138) | `params.get("k")` call result; `params[key]` subscript node |
| handler entry params | p2-e-091 `_login`:317, 105 `_logout`:406, 106 `_whoami`:412, 107 `_check_ip`:422, 112 `_trails`:446, 116 `_ping`:453, 117 `_fail2ban`:460, 123 `_events`:496, 137 `_counts`:652 — **arg 1** | parameter node (position 1) of the 9 `_%s`-dispatched ReqHandler methods |
| packet boundary (sensor.py) | p2-e-327 `_cap.next()`:1169; p2-e-323/324/325 packet_handler args 0/1/2 (:1092); p2-e-227/228/229/230 `_process_packet` args 0–3 (:274); p2-e-235/236/237/270/272/273/279 `struct.unpack` arg 1 (:331/:341/:350/:654/:681/:702/:758); p2-e-256/258/260/261 `unquote` arg 0 (:486/:528/:554/:555) | call-result / argument / parameter nodes, file-pinned to `sensor.py` |
| plugin/event boundary | p2-e-210/211 plugin args 0/1 (plugins/peek.py:14), p2-e-471/472 (plugins/strings.py:14), p2-e-166/167 log_event args 0/1 (core/log.py:134) | parameter nodes, file+name pinned |
| candidate — remote feed (diagnostics only) | 67 entries: retrieve_content call sites (54 feed files + core/common.py:64/:220 + core/update.py:89/:186), urlopen/resp.read/ex.read (core/common.py:50/:51/:59/:61), urlopen (core/update.py:354) | `retrieve_content(...)` bare-name + API-graph call result; location-pinned lines |
| candidate — second-order files (diagnostics only) | 11 entries: core/httpd.py:451 (trails), :483/:516/:531/:532/:563/:638/:694/:695 (event-log reads), core/common.py:245 (load_trails), core/update.py:368 (ipcat CSV) | location-pinned `open(...)` / `<f>.read()` call results |

Family 3's AST shape (`params.get(...)` / `params[key]` in `core/httpd.py`) matches exactly the 12 labeled `.get` lines plus the 2 subscript lines — verified by grep against the tree; no other `params.` uses exist in the file. The `struct.unpack`-arg-1 shape matches exactly the 7 unpack calls in sensor.py, and the `.next()` shape exactly the one `_cap.next()` site. The `unquote`/`unquote_plus` split is by file: `unquote_plus` occurs only in core/httpd.py (:231), `unquote` only in sensor.py (:486/:528/:554/:555).

**Deliberately NOT sources (label fp, documented not dropped):** `config.<NAME>` reads (237 rows — locally authored maltrail.conf / env overrides / CLI options of the launching admin), CLI input (sys.argv / optparse / options.X — local user), os.environ reads, local trusted file/glob reads, the intra-host UDP `self.request` row in core/log.py, and `_format`'s content-tag params (the tenth `_%s`-callable — rejected; also excluded from the dispatch step below).

### 1.2 MySinks::isSink(node, passKey)

| Label ID | Site | Verdict | Formal key |
| --- | --- | --- | --- |
| **p2-e-522** | **`core/httpd.py:399` `subprocess.check_output("logger ... %s password for %s from %s port %s" % (..., params.get("username"), self.client_address[0], self.client_address[1]), stderr=subprocess.STDOUT, shell=True)` arg 0** | **tp 0.95** | **yes (location- + shell=True-pinned)** |
| p2-e-525 | `sensor.py:1037` `subprocess.Popen("schedtool ... 0x%02x %d" % (affinity, os.getpid()), shell=True)` arg 0 | candidate 0.60 | diagnostics only |

Matching shape: command argument = **positional arg 0** of a `subprocess.{call,check_call,check_output,run,Popen}` call, resolved via API graphs (alias-aware; the exact idiom used by this project's Phase-1 extraction sinks.ql) with a `subprocess.<member>` AST fallback. For the formal key the tp site is additionally **location-pinned** (`core/httpd.py:399`) and required to pass `shell=True` (redundant with the label's merged shell_true row) so the candidate site and the six rejected static-literal sites cannot leak into formal results. The diagnostics key admits every subprocess site unpinned (all 8 in the repo: httpd.py:399, sensor.py:1031/:1032/:1037, core/settings.py:202/:208/:214/:220).

Shell vs non-shell modeling (task directive): **every** subprocess invocation in this repository passes a shell command *string* with `shell=True` (8/8). Arg 0 is the dangerous argument in that shape; for a future non-shell argv-list invocation the dangerous argument is the argv list, also at arg 0 — modeled uniformly, distinction recorded in the library header instead of duplicated predicates.

### 1.3 MySanitizers::isBarrier(node, passKey)

| Label ID | API | Verdict | Model |
| --- | --- | --- | --- |
| (none) | — | — | **`none()`** — zero sanitizer entries of any classification exist in labels.json |

Evidence (label_stats.md "Sanitizers"): (1) the login validity check (httpd.py:320-336) does **not** gate the :399 sink — the `if not IS_WIN:` guard at :397 is outside `if valid:` and the "Failed" branch interpolates the same `params.get("username")`; (2) the `".." in dates` guard (:509) is a path-domain (pass 1) check; (3) no `shlex`/`pipes` import or any escaping helper exists anywhere in the snapshot. Modeling a non-existent barrier would be evidence-free and could suppress the real path; the predicate resolves to `none()` (WORKFLOW.md 5.2.3: always exists, never blocks unconditionally).

### 1.4 MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, passKey)

| Label IDs | Step | Formal key |
| --- | --- | --- |
| p2-e-060 (httpd.py:147) | **dynamic dispatch**: `getattr(self, "_%s" % path)(params)` — taint on arg 0 (`params`) → `params` parameter (position 1) of the 9 reviewed `_%s` handler methods | yes (both keys) |
| p2-e-165 (core/log.py:127) + 40 sensor.py sites (:198-:841) | `log_event(event_tuple, packet)` call args 0/1 → log_event parameters 0/1 (core/log.py:134) | yes (both keys) |
| p2-e-326 (sensor.py:1144) | `_process_packet(packet, sec, usec, ip_offset)` call args 0–3 → _process_packet parameters (sensor.py:274) | yes (both keys) |
| p2-e-202/203/204 (core/parallel.py:37/:38), p2-e-209 (:97) | **shared-memory transport**: taint on the `buffer` receiver → `.read()` result (raw packet block); taint on `struct.unpack` operand arg 1 → unpacked result | yes (both keys) |

Rejected `summary`/`none` labels correctly excluded: the 22 message-formatting rows (httpd.py:349/:395 cookie/response text, sensor.py init diagnostics) and the wrapper-scope cmd_format rows of the rejected static-literal subprocess sites — string construction only, no propagation semantics.

**Internal-wrapper directive compliance:** `log_event`/`_process_packet`/`plugin` parameters are labeled tp *sources* only because Phase 1 explicitly reviewed them as attacker-influenced boundaries ("crossing an internal API boundary", evidence: the sensor call chain feeding them) — they were not auto-promoted from wrapper-hood. The tenth wrapper callable, `_format` (content-tag params), was reviewed and **rejected**; it appears in neither the source families nor the dispatch step. Any verification of wrapper-internal propagation for the unresolved candidate set is the diagnostics query's job, never the formal result.

---

## 2. Source evidence for every effective source/sink

All line numbers verified against the source tree (`maltrail_vuln` @ bb4d24b0 — same state as the database).

**The formal source→sink chain (HTTP side):**

- `core/httpd.py:125` `path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")` (p2-e-054) — raw request line from the socketserver machinery.
- `core/httpd.py:228-232` (do_POST) `length = self.headers.get(HTTP_HEADER.CONTENT_LENGTH)` (p2-e-073); `data = self.rfile.read(int(length)).decode(UNICODE_ENCODING)` (p2-e-075/076); `data = _urllib.parse.unquote_plus(data)` (p2-e-077); `self.data = data` (p2-e-078).
- `core/httpd.py:131/:134` `params.update(_urllib.parse.parse_qs(self.data))` / `params.update(_urllib.parse.parse_qs(query))` (p2-e-055/056/057) — the params dict is pure client input.
- `core/httpd.py:147` `content = getattr(self, "_%s" % path)(params)` (p2-e-060) — dynamic dispatch of the decoded params into the handler.
- `core/httpd.py:317` `def _login(self, params):` (p2-e-091) → `:320` `if params.get("username") and params.get("hash") and params.get("nonce"):` (p2-e-092/093/094) and `:334` `params.get("hash") == hashlib.sha256(...)` (p2-e-097) — no validation or escaping on the values.
- `core/httpd.py:388/:399` `self.client_address[0]` / `[1]` (p2-e-101/102/103) — the client socket address tuple.
- **Sink `core/httpd.py:397-399`** — `if not IS_WIN:` (outside `if valid:`) → `subprocess.check_output("logger -p auth.info -t \"%s[%d]\" \"%s password for %s from %s port %s\"" % (NAME.lower(), os.getpid(), "Accepted" if valid else "Failed", params.get("username"), self.client_address[0], self.client_address[1]), stderr=subprocess.STDOUT, shell=True)` (p2-e-522). The `%`-format operator propagates argument taint to the formatted string natively (python-all 7.x string-formatting modeling), completing source → format → sink.

Supporting request-state sources (same file, verified): `self.headers.get(...)` :162/:206/:229/:237/:257/:546/:647, `self.headers[HTTP_HEADER.RANGE]` :547, `self.path` :156/:194, `params[key]` :137/:138, remaining handler params (:406/:412/:422/:446/:453/:460/:496/:652) and their `params.get` reads (:435/:439/:441/:507/:666/:672). SSL wrapper (`SSLReqHandler.setup` :706-708): `self.connection = self.request`, `self.rfile = socket._fileobject(self.request, ...)` — the SSL socket is the upstream of the same request-state boundary.

**Sensor-side sources (no path to a command sink exists in this snapshot — kept for completeness of the packet→log/plugin chain, per the labels):** `sensor.py:1169` `(header, packet) = _cap.next()` (p2-e-327, pcapy); `sensor.py:1092` `def packet_handler(datalink, header, packet)` (p2-e-323/324/325); `sensor.py:274` `def _process_packet(packet, sec, usec, ip_offset)` (p2-e-227-230); `struct.unpack` data args :331/:341/:350/:654/:681/:702/:758 (p2-e-235-279, header-field extraction from the raw buffer); `unquote` data args :486/:528/:554/:555 (p2-e-256-261, captured HTTP request fields). **Plugin/event boundary:** `plugins/peek.py:14` / `plugins/strings.py:14` `def plugin(event_tuple, packet=None)` (p2-e-210/211/471/472), invoked from `core/log.py:221-223` `_(event_tuple, packet)` over `config.plugin_functions`; `core/log.py:134` `def log_event(event_tuple, packet=None, ...)` (p2-e-166/167) fed by the 41 call sites (sensor.py:198-:841, core/log.py:127).

**Candidate sink (diagnostics only):** `sensor.py:1031-1037` — affinity parsed from `subprocess.check_output("grep -c ^processor /proc/cpuinfo" / ps-pipeline)` output (:1031/:1032, both all-literal commands → fp), then `subprocess.Popen("schedtool -n -2 -M 2 -p 10 -a 0x%02x %d" % (affinity, os.getpid()), shell=True)` (:1037) — dynamic format, internally derived values (p2-e-525, candidate 0.60).

---

## 3. Parameter indices and controllability decisions

Index convention (labels.json metadata + extraction contract): **0-based position in the function definition with `self` counted at 0** — `Parameter.getPosition()` / `Function.getArg(n)` in CodeQL Python returns exactly this, so label `arg_index` maps 1:1 to `functionParamAt(node, path, name, position)`.

| Function | Index | Label | Controllability judgment |
| --- | --- | --- | --- |
| `_login`/`_logout`/`_whoami`/`_check_ip`/`_trails`/`_ping`/`_fail2ban`/`_events`/`_counts` | 1 | p2-e-091/105/106/107/112/116/117/123/137 tp | params dict from parse_qs-decoded client input, dispatched at :147 — attacker-controlled |
| `_format` | 1 | rejected (fp) | content-tag template values — internal, excluded from sources and dispatch step |
| `log_event` | 0 / 1 | p2-e-166/167 tp | event tuple / raw packet bytes derived from captured wire traffic |
| `packet_handler` | 0 / 1 / 2 | p2-e-323/324/325 tp | datalink / header / packet from the pcapy callback — wire data |
| `_process_packet` | 0 / 1 / 2 / 3 | p2-e-227/228/229/230 tp | packet bytes / timestamps / offset — wire data |
| `plugin` (peek, strings) | 0 / 1 | p2-e-210/211/471/472 tp | event tuple / packet bytes at the plugin dispatch boundary |
| `struct.unpack` (sensor.py) | 1 | p2-e-235/236/237/270/272/273/279 tp | the data operand (arg 0 is the constant format string) |
| `unquote` (sensor.py) | 0 | p2-e-256/258/260/261 tp | the URL-encoded wire field |
| subprocess family | 0 | p2-e-522 tp / p2-e-525 candidate | the shell command string (all 8 sites are shell=True strings) |

Sink argument index 0 is uniform across `call`/`check_call`/`run`/`Popen`/`check_output`; no `os.spawn*`/`os.system`/`exec`/`eval` sites exist in the snapshot (verified — sinks.csv contains only the 8 subprocess rows), so no predicates were emitted for them.

---

## 4. Sanitizer and summary modeling evidence

**Sanitizer set — empty:** no `shlex`/`pipes` import, no `quote`/`escape` call, and no other metacharacter-neutralizing construct exists anywhere in the snapshot; the login check and the `".." in dates` guard are documented non-barriers (§1.3). `MySanitizers::isBarrier` therefore resolves to `none()` for both pass keys — never an unconditional block.

**Summaries (46 tp):**
- *dispatchStep (p2-e-060, 0.85)* — evidenced by `httpd.py:146-147` `if hasattr(self, "_%s" % path): content = getattr(self, "_%s" % path)(params)`: the call target is computed from the request path, so CodeQL cannot natively link the argument to the handler parameters. The step is location-pinned to :147 and only fans into the 9 reviewed handler names (the same set as the handler-param source family); `_format` is deliberately excluded. This is the load-bearing edge of the formal chain — though each handler's `params` is *also* a direct source, so the formal result does not depend on it.
- *logEventStep (41 labels, 0.7)* — evidenced by the 41 call sites and `core/log.py:134`'s signature; `log_event` writes the event log (`os.write(handle, event...)` :175) and dispatches plugins (:221-223). Statically resolvable calls, so the step is label-mandated redundancy over native propagation (same policy as dcnnt-py's `format` step).
- *processPacketStep (p2-e-326, 0.75)* — `sensor.py:1144` `_process_packet(packet, sec, usec, ip_offset)`, the only direct call site; also native-redundant.
- *parallelBufferStep (p2-e-202/203/204/209, 0.7)* — evidenced by `core/parallel.py:37-38` (`buffer.read(2)` / `buffer.read(length)` inside `read_block`) and `:97` (`struct.unpack("=III", content[:12])` inside `worker`), with the write side at `sensor.py:1135-1142` (`write_block(buffer, ...)`) — the shared-memory transport carrying wire data into worker processes. Both steps are strictly conditional on call shape; no unconditional propagation is created anywhere.

---

## 5. Uncovered APIs, dynamic calls, and known limitations

1. **Dynamic handler dispatch (`getattr`)** — the invoked method is computed from the request path; native resolution is impossible. Modeled by `dispatchStep` (§4). Over-approximation is bounded to the 9 reviewed handler names.
2. **Plugin dispatch (`config.plugin_functions`)** — `core/log.py:221-223` `_(event_tuple, packet)` iterates functions loaded from `-p` CLI values (dynamic import). Recall does not depend on resolving it: the plugin `event_tuple`/`packet` parameters are direct sources (p2-e-210/211/471/472).
3. **Multiprocessing function-reference call** — `core/parallel.py:57/:99` `worker(buffer, ..., process_packet)` calls `_process_packet` through a function-value parameter, which CodeQL does not resolve. The `parallelBufferStep` covers buffer→block, and `_process_packet`'s parameters are themselves direct sources (p2-e-227-230), so the worker path's recall does not depend on the unresolved edge.
4. **Candidate sources have no sink path in this snapshot** — the Phase-1 review verified no path from remote-feed content or second-order event-log reads to any command string; they are diagnostics-only recall seeds pending the threat-model decision on hardcoded-plain-HTTP feed endpoints.
5. **`_login` authentication** — deliberately NOT a barrier (executes for failed logins; §1.3). If a reviewer disagrees, the change belongs in labels + MySanitizers, not in the query.
6. **`params.get` family shape** — matches `params.get(...)` on the *local variable* named `params` in `core/httpd.py`; the grep-verified closure is exactly the 14 labeled rows. In a larger codebase a local named `params` elsewhere in the same file would also match — acceptable here (single file, verified).
7. **`self.data`/`self.rfile`/`self.request` store sites** (:232/:707/:708) are matched as attribute nodes in store position; harmless (they flow only into the already-sourced load sites) and kept because the labels pin those exact lines.
8. **Line pins are snapshot-pinned** — :147 (dispatch), :399 (sink), :1144, the 11 candidate read lines and the 6 decode lines are correct for sha bb4d24b0 (tree == database). If the tree moves, re-verify pins before running.
9. **`urlopen` / `resp.read` candidate family** is location-pinned rather than shape-matched, because `retrieve_content`'s internal reads are the only remote-entry points and an unpinned `.read()` shape would match dozens of trusted file reads.
10. **No compile was executed** (task directive: generate files only). Idiom risk is minimized by reuse from this project's compile-verified extraction queries; `codeql query compile` should be the first step of the run phase.

---

## 6. Modeling principles (consistent with the other project experiments)

1. **Render from reviewed labels only** — formal predicates admit `tp` entries; `candidate` entries go to a diagnostics query; `fp`/`none` entries are documented as rejected, never silently dropped.
2. **Threat model = the remote client (and monitored wire on the sensor side)** — request line/headers/body/params/client address and packet bytes are untrusted; local config (`config.<NAME>`), CLI options, `os.environ` and locally authored files stay on the trusted side (dcnnt-py precedent: local-user/config input is not attacker input).
3. **Signature-level matching with positional precision** — module + callable + argument/parameter index; sibling parameters of the same function are judged individually (`_format` rejected while the 9 handlers are accepted; `struct.unpack` arg 0 constant vs arg 1 data).
4. **Location pinning for the formal sink** when signature matching would admit unreviewed sites; diagnostics keep the unpinned family.
5. **Barriers only with evidence** — with no metacharacter-blocking construct in the snapshot, the barrier predicate resolves to `none()`, never to unconditional taint or blocking.
6. **Summaries are conditional call-shape/location-pinned steps** — no unconditional propagation; internal-wrapper parameters are sources only where Phase 1 reviewed them as boundaries (never auto-promoted); wrapper/diagnostic propagation checks stay out of the formal result (task directive).
7. **Shell-string vs argv-list modeling** — the dangerous argument is arg 0 in both shapes; this snapshot contains only shell=True string commands (8/8), modeled uniformly with the distinction documented.
8. **No execution in this step** — files only; compile and analysis are deferred to the run step.

---

## 7. Files

```
iris/
├── libraries/MySources.qll          # sources, pass-key dispatch (formal/diagnostics)
├── libraries/MySinks.qll            # subprocess arg-0 sinks; formal site location-pinned (httpd.py:399)
├── libraries/MySanitizers.qll       # empty barrier set (none()) — label state
├── libraries/MySummaries.qll        # dispatch / log_event / _process_packet / shared-buffer steps
├── queries/Pass2_CommandInjection.ql           # formal @kind path-problem, severity error
├── diagnostics/Pass2_CommandInjectionDiagnostics.ql  # candidate labels only, severity warning
└── report/query_generation_notes.md # this file
```

No source files, CodeQL database, Phase-1 labels, or extraction artifacts were modified; only the files under `iris/{libraries,queries,diagnostics,report}/` were generated.
