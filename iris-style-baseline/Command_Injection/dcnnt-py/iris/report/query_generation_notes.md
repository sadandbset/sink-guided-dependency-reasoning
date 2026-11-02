# Query Generation Notes — dcnnt-py, Pass 2 (CWE-78), Run r2

**Augur 0.3.0 · Phase 2 Step 4–5** · Run `dcnnt-py-iris-pass2-20261015-r2` · Generated 2026-10-15
**Inputs:** `iris/labels/labels.json` (human-reviewed, 181 entries: 63 tp source / 5 tp sink / 0 tp sanitizer / 12 tp summary / 8+2+1 candidate / 90 fp) and the source tree at `dataset/codeql_databases/dcnnt-py_vuln` (commit 4084ea1, identical to the CodeQL database snapshot — tree, DB and CSV line numbers agree 1:1).
**Outputs:** `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass2_CommandInjection.ql` (formal), plus the supplementary `diagnostics/Pass2_CommandInjectionDiagnostics.ql` (candidate labels only; NOT a formal result).
**Toolchain:** CodeQL CLI 2.25.1, `codeql/python-all` resolved from the local pack cache via `iris/qlpack.yml`. Both queries compile-checked with `codeql query compile` in this step; no database analysis was performed (`codeql database analyze` is deferred to the run step).

**r2 context:** this regeneration closes the r1 omission. In r1 the formal sink set had only 4 tp sites because notifications.py:58 was labeled `candidate` — the r1 labeling session had read a different checkout state of notifications.py (one where every `cmd.format` substitution was wrapped in `shlex.quote`). In the analyzed snapshot (4084ea1) there is no shlex import anywhere in the tree; r2 re-labeling promoted **notifications.py:58 to tp (0.92)** and removed the shlex.quote sanitizer entry. Everything below reflects the r2 label set.

---

## 1. Label ID → CodeQL predicate mapping

All library predicates take `(DataFlow::Node, string passKey)`. Pass-key dispatch (WORKFLOW.md 5.1.5):

| Pass key | Entry classifications admitted | Used by |
| --- | --- | --- |
| `command_injection` | `tp` only | `queries/Pass2_CommandInjection.ql` (formal) |
| `command_injection_diagnostics` | `tp` + `candidate` | `diagnostics/Pass2_CommandInjectionDiagnostics.ql` (NOT formal) |

Rationale: labels.json metadata defines `candidate` as "plausible but unresolved, human review requested". Pending review items must not become formal findings; they are preserved in the diagnostics query so recall is not lost (mirrors the task directive that unverified propagation and internal-wrapper diagnostics belong in diagnostics, not in the formal result set).

### 1.1 MySources::isSource(node, passKey)

| Source family (predicate) | Label IDs (all `source`/tp unless noted) | Matching shape |
| --- | --- | --- |
| raw network reads — `recv` | p2-e-009, p2-e-010, p2-e-060, p2-e-064 | any `<obj>.recv(n)` call result |
| raw network reads — `self.read()` | p2-e-013, p2-e-024, p2-e-094 | `read` attr call with receiver `self` |
| raw network reads — `self.rpc_read()` | p2-e-018, p2-e-025, p2-e-091, p2-e-112 | any `rpc_read` attr call result |
| raw network reads — `decrypt` | p2-e-011, p2-e-053, p2-e-065 | bare `decrypt(...)` call result |
| protocol decode — `json.loads` | p2-e-015, p2-e-050 (p2-e-047 candidate, subsumed, dead site) | API-graph `json.loads` + `json.loads` AST fallback; **`loads` only** — `json.load` of local config is fp (p2-e-043) |
| protocol decode — `RPCRequest.from_dict` | p2-e-014 (p2-e-048 candidate, subsumed, dead site) | `RPCRequest.from_dict(...)` call result |
| protocol decode — `unpack_raw_request` | p2-e-052 | attr call result |
| protocol decode — `b64decode` | p2-e-054 | API-graph + bare-name fallback (`b64encode` is fp, p2-e-055) |
| handler entry params — `process_request` @1 | p2-e-017, p2-e-087, p2-e-105, p2-e-156 | parameter node, `%Plugin` classes |
| handler entry params — `handle_*` @1 | p2-e-080, 084, 085, 098, 102, 110, 116, 122, 124, 129, 142, 143, 146, 148, 154 | parameter node, `handle_%` methods |
| handler entry params — file primitives @1 | p2-e-020 (`_receive_file`), 026 (`receive_file_to_path`), 028 (`receive_file`), 030 (`send_file`) | parameter node |
| handler entry params — `common_upload_handler` @2 | p2-e-134 | parameter node |
| request params reads — subscript | p2-e-023, 086, 138, 147 (+ p2-e-125 bare form) | `request.params['k']` |
| request params reads — `.get/.pop` | p2-e-093, 095, 096, 103, 111, 117, 126, 130, 131, 139, 140, 149, 150, 155 — including **notifications.py:42 (packageIcon), :43 (event), :45 (title)** | `request.params.get/pop('k')` |
| request params reads — UDP dict | p2-e-051 | `request.get/pop('k')` on the decoded datagram dict |
| candidate (diagnostics key only) | p2-e-022 (`_receive_file` @3), p2-e-027 (`receive_file_to_path` @2), p2-e-045 (`dispatch` @1), p2-e-044/049 (`RPCResponse`/`RPCError.from_dict`) | as labeled |

Subsumption note: three candidate sites (p2-e-046/047/048, inside the unused `RPCSerializer.from_bytes`/`RPCDispatcher` in common/jsonrpc.py) are matched by the *confirmed* signature-level families because they use identical call shapes at dead call sites. They cannot produce flow until that ToDo path is wired in (no callers in this version); flagged for transparency.

**r1→r2 source delta:** none — all 63 tp sources are identical to r1 (only notifications sink/sanitizer entries changed). Line references for notifications were corrected to the snapshot (rpc_read :33, read :42, params.get :42/:43/:45).

### 1.2 MySinks::isSink(node, passKey)

| Label ID | Site | Verdict | Formal key |
| --- | --- | --- | --- |
| p2-e-160 | `plugins/file_transfer.py:110` `subprocess.call(command, shell=True)` arg 0 | tp 0.90 | yes |
| **p2-e-164** | **`plugins/notifications.py:58` `subprocess.call(command, shell=True)` arg 0** | **tp 0.92 (r2: promoted from candidate 0.65)** | **yes** |
| p2-e-168 | `plugins/opener.py:34` `subprocess.call(command, shell=True)` arg 0 | tp 0.92 | yes |
| p2-e-172 | `plugins/opener.py:44` `subprocess.call(command, shell=True)` arg 0 | tp 0.92 | yes |
| p2-e-178 | `plugins/sync.py:318` `subprocess.call(command, shell=True)` arg 0 | tp 0.88 | yes |
| p2-e-175 | `plugins/remote_commands.py:48` `subprocess.check_call(cmd, shell=True)` arg 0 | candidate 0.55 | diagnostics only |
| p2-e-181 | `plugins/sync.py:361` `subprocess.call(command, shell=True)` arg 0 | candidate 0.60 | diagnostics only |

Matching shape: command argument = **positional arg 0** of a `subprocess.{call,check_call,check_output,run,Popen}` call, resolved via API graphs (alias-aware) with a `subprocess.<member>` AST fallback. For the formal key the five tp sites are additionally **location-pinned** (file suffix + line, verified against the current source tree at 4084ea1) so the candidate sites cannot leak into formal results.

Shell vs non-shell modeling (task directive): every subprocess site in this repository passes a shell command *string* with `shell=True` (7/7). Arg 0 is the dangerous argument in that shape. For a future non-shell argument-list invocation the dangerous argument is the argv list, also at arg 0; the predicate models arg 0 uniformly and this distinction is recorded in the library header rather than duplicated into two predicates that would be identical here.

### 1.3 MySanitizers::isBarrier(node, passKey)

| Label ID | API | Verdict | Model |
| --- | --- | --- | --- |
| (none) | — | — | **`none()`** — the r2 confirmed sanitizer set is empty |
| p2-e-144 | `SyncPlugin.ensure_file_syncable` (sync.py:328) | candidate 0.55 | **not modeled** — see §4 |

**r1→r2 change:** r1 modeled `shlex.quote(...)` results as a barrier (supplementary label p2-e-182, from that round's detection.json sanitizerObservations). In snapshot 4084ea1 **no `shlex` import exists anywhere in the tree** and no call to any escaping helper occurs on any command-template path, so the r2 label set contains no tp sanitizer. The barrier predicate deliberately resolves to `none()` (WORKFLOW.md 5.2.3: the predicate always exists; with no matching node it is empty, never an unconditional block). The empty barrier is exactly what the code state warrants — there is nothing between the sources and the five sinks that neutralizes metacharacters.

### 1.4 MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, passKey)

| Label IDs | Step | Formal key |
| --- | --- | --- |
| p2-e-081, 099, 128, 141, 152, 153 | `receive_file`/`receive_file_to_path` **arg 0 → call result** (tainted request yields tainted saved path) | yes (both keys) |
| p2-e-158, 162, 166, 170, 177, 180 | `template.format(...)` **substitution argument → formatted string** (positional or keyword; includes notifications.py:56 `cmd.format(uin=..., text=text, ...)` with unescaped values) | yes (both keys) |

Rejected `summary`/`none` labels correctly excluded: the five logging-only `'Execute: ...'.format(command)` calls (p2-e-159, 163, 167, 171, 174) and the seven `internal_exec_wrapper` handler rows (p2-e-157, 161, 165, 169, 173, 176, 179) — the latter would create degenerate source==sink paths on the same request object. Per the task directive, internal wrapper parameters are not automatically sources; any verification of internal-parameter-to-dangerous-call local propagation is the diagnostics query's job, never the formal result.

---

## 2. Source evidence for every effective source/sink

All line numbers verified against the current source tree (`dcnnt-py_vuln` @ 4084ea1 — same state as the database).

**Sources (network boundary, in protocol order):**

- `tcp_server.py:35` `data = self.sock.recv(left)` — outermost raw TCP read; every protocol byte enters here (p2-e-060).
- `tcp_server.py:69` `header = self.recv(60)` — connection header (dst/src UINs, encrypted plugin mark); checks at :73-92 are routing/auth only (p2-e-064).
- `tcp_server.py:85` `plg = decrypt(header[24:], source.key_recv)` — AES-GCM decryption authenticates the paired device, does not restrict plugin payload (p2-e-065; review point 1).
- `plugins/base.py:106/109` `self.handler.recv(4)` / `self.handler.recv(int.from_bytes(size_raw, 'big'))` — size prefix + encrypted body (p2-e-009/010).
- `plugins/base.py:114` `return decrypt(encrypted, key)` (p2-e-011); `base.py:128` `RPCRequest.from_dict(json.loads(request_raw.decode()))` (p2-e-014/015).
- `plugins/base.py:123/148/185/189` `self.read()` / `self.rpc_read()` — plugin message boundary (p2-e-013/018/024/025).
- `server_search.py:17/19/25/38` — UDP JSON datagram `json.loads`, `request.get('pair')`, `unpack_raw_request`, `b64decode` (p2-e-050/051/052/054); `decrypt` at :38 (p2-e-053).
- `notifications.py:33` `self.rpc_read()` (p2-e-091), `:42` `self.read()` / `request.params.get('packageIcon')` (p2-e-094/093), `:43` `request.params.get('event')` (p2-e-095), `:45` `request.params.get('title', 'NULL')` (p2-e-096), `remote_commands.py:59` `rpc_read` (p2-e-112).
- Handler entry parameters — each receives the RPCRequest from `rpc_read → decrypt → json.loads` (labels' standard handler-parameter source per `references/python.md`): e.g. `plugins/base.py:141` `def process_request(self, request: RPCRequest)`, `plugins/opener.py:28/36/46`, `plugins/file_transfer.py:103/112/121/135`, `plugins/sync.py:63/128/276/284/295/320/324/335/343/365/371`, `plugins/remote_commands.py:38`.
- `request.params` reads — 21 confirmed sites, e.g. `base.py:176` `request.params['name']`, `opener.py:38` `request.params.get('link')`, `sync.py:300` `request.params['name']`, `remote_commands.py:40` `request.params.get('index')`, `notifications.py:42/43/45`.

**Sinks (tp):** all five execute a `str.format`-built command string with `shell=True` and an unquoted attacker-controlled substitution:

- `file_transfer.py:105-110` — `path = self.receive_file(request, conf('download_directory'))`; `command = on_download.format(path=path)`; `subprocess.call(command, shell=True)`; `path = os.path.join(download_directory, request.params['name'])` (base.py:176-179).
- **`notifications.py:31-58` (r2 addition)** — `request = self.rpc_read()`; `title = request.params.get('title', 'NULL')` (:45); `text, package = map(request.params.get, ...)` (:44); `command = cmd.format(uin=uin, name=name, icon=icon, text=text, title=title, package=package)` (:56, **no escaping**); `subprocess.call(command, shell=True)` (:58). Default template `notify-send -i '{icon}' '{title}' '{text}'` uses single quotes — a value containing `'` breaks out; `$()`/backticks do not expand inside single quotes, but the `'` breakout (plus template variants) yields direct injection; the `icon` substitution additionally embeds the attacker-controlled package name via the icon filename (:49).
- `opener.py:30-34` — identical shape to file_transfer, default template `xdg-open "{path}"` (double quotes do not stop `"`, `$(`, backticks).
- `opener.py:38-44` — `url = request.params.get('link')` (only `isinstance(url, str)` precedes it) → `format(url=url)` → `subprocess.call(..., shell=True)`.
- `sync.py:314-318` — `res = self.receive_file(request, directory)`; `fn = request.params['name']`; `on_done.format(path=res)` → `subprocess.call(..., shell=True)`.

Shared chain: `request.params` / handler param (source) → `receive_file` arg0→return (summary) → `str.format` (summary) → `subprocess.call` arg 0 (sink). Redundant native propagation also exists: python-all 7.x models `os.path.join` and `.format()` argument taint natively, so the chain holds even without the summaries. For notifications, `title` is a direct family-4 source (:45) that feeds `cmd.format(title=title)` at :56 — a complete source→sink path even without relying on the `map()` bound-method values.

---

## 3. Parameter indices and controllability decisions

Index convention (labels.json metadata + extraction contract): **0-based position in the function definition with `self` counted at 0** — `Parameter.getPosition()` in CodeQL Python returns exactly this, so label `arg_index` maps 1:1 to `getArg(position)` / `pluginHandlerParam(source, position, name)`.

| Function | Index | Label | Controllability judgment |
| --- | --- | --- | --- |
| `process_request` | 1 | p2-e-017/087/105/156 tp | RPCRequest from phone — attacker-controlled `params` |
| `handle_*` (15 methods) | 1 | tp (§1.1) | same |
| `_receive_file` | 1 | p2-e-020 tp | request — attacker data |
| `_receive_file` | 2 | p2-e-021 fp | download directory — `self.conf(...)` local config |
| `_receive_file` | 3 | p2-e-022 candidate | explicit destination path — attacker-derived at sync call sites, config elsewhere → diagnostics |
| `receive_file` / `receive_file_to_path` | 1 / 1 | p2-e-028 / p2-e-026 tp | request |
| `receive_file` | 2 | p2-e-029 fp | config directory |
| `receive_file_to_path` | 2 | p2-e-027 candidate | destination path → diagnostics |
| `send_file` | 1 / 2 / 3 | p2-e-030 tp / p2-e-031, 032 fp | request / server-built index-selected path / numeric size check |
| `common_upload_handler` | 1 / 2 | p2-e-133 fp / p2-e-134 tp | constant `'contacts'`/`'messages'` / request |
| `handle_exec` | 1 | p2-e-110 tp | request; `params.get('index')` (p2-e-111) only *selects* a config command |
| subprocess family | 0 | all sink labels | the command string / argv list |

Sink argument index 0 is uniform across `call`/`check_call`/`run`/`Popen`/`check_output` (no `os.spawn*` sites exist here; the extraction template's index-1 rule for spawn was not needed).

---

## 4. Sanitizer and summary modeling evidence

**Sanitizer set — empty (r2):** `grep` of the snapshot confirms there is no `shlex` import and no `quote`/`escape` call anywhere in `dcnnt/`. r1's barrier (p2-e-182, shlex.quote at notifications.py:57) described a different checkout state and was removed from the labels; `MySanitizers::isBarrier` therefore resolves to `none()` for both pass keys. Modeling a non-existent barrier would be evidence-free and could suppress real paths.

**ensure_file_syncable (p2-e-144, candidate) — intentionally NOT modeled as a barrier**, for three reasons: (1) its semantics are substring containment (`if path in i['path']`, sync.py:331) rather than equality — the labels themselves call it a *partial* sanitizer pending review; (2) a parameter-shaped barrier node cannot block the caller-side flow (the guarded `path` variable continues into `on_merge.format(output=path)` at :359 — flow into a callee parameter is independent of the other uses of the caller variable); (3) asserting an unconfirmed guard as effective could suppress a true positive at sync.py:361. Instead the sync.py:361 path is reachable in the diagnostics query for human review. A faithful model would need a barrier-*guard* (`BarrierGuards`) once the intended semantics are confirmed.

**Summaries (all tp, 0.8–0.85):** `receive_file`/`receive_file_to_path` arg0→return is evidenced by `base.py:176-196` (`name = request.params['name']`, `path = os.path.join(download_directory, name)`, `return path`) and the six call sites (file_transfer.py:105, opener.py:30, sync.py:282/314/358/363). The `format` substitution step is evidenced by the six template sites (file_transfer.py:108, notifications.py:56, opener.py:32/42, sync.py:316/359); it generalizes the shape "any substitution argument → result" (keyword arguments included — every dcnnt site uses keywords), which is safe here because format results only reach sinks on the command-template sites, and label-rejected log-format sites have no downstream sink. Both steps are strictly conditional on call shape — no unconditional taint propagation is created anywhere.

---

## 5. Uncovered APIs, dynamic calls, and known limitations

1. **Dynamic plugin dispatch** — `tcp_server.py:97` `plugin(app, self, source).main()`: the plugin class comes from `app.plugins` (populated from the `PLUGINS` tuple); the constructor target is unresolvable (detection.json uncoveredCases). Mitigated by modeling `Plugin.main`'s inner boundary (`rpc_read`/`read`) and the handler entry parameters as sources, so taint does not depend on resolving this edge.
2. **`map(request.params.get, (...))` / `map(command.get, ...)`** — bound methods passed to `map()` (notifications.py:44, remote_commands.py:30, sync.py:131) are not call sites, so neither the `request.params.get` family nor any other call-shaped predicate matches them. Recall for the affected values (`text`, `package` in notifications; sync dir_list args) rests on object-taint propagation from the `rpc_read`/handler-parameter sources — and on the notifications path the direct `title` source (:45) alone already yields a complete source→sink path to :58, so the formal query does not depend on the map() values.
3. **Unused RPCDispatcher/RPCSerializer path** — `common/jsonrpc.py:123-185` (ToDo). Candidate sources are reachable only under the diagnostics pass key; the three subsumed candidate shapes are noted in §1.1. If this path is wired in later, re-run labeling.
4. **`str.format` on non-template receivers** — the summary family matches any `.format()` call. Log-format call sites match too, but their results flow only into `self.log(...)`, so no spurious sink is reachable. If future code formats attacker data into something other than a command, the step remains taint-correct (value-preserving), not false-positive-generating.
5. **Line numbers are snapshot-pinned** — the formal sink pins (notifications.py:58 etc.) are correct for commit 4084ea1 (tree == database). r1's pins referenced notifications.py:59, which matched a different checkout state; if the tree moves again, re-verify pins before running.
6. **Bare-name fallbacks** (`decrypt`, `b64decode`) match any call with that bare name in the repo. Currently exact (only the intended imports exist); in a larger codebase these would need module-qualification via API graphs only.
7. **No os/exec/popen family** — the repository contains no `os.system`/`os.popen`/`eval`/`exec` sites (verified by extraction sinks.csv: only the 7 subprocess sites), so no predicates were emitted for them; adding them without evidence is forbidden by the modeling rules.
8. **remote_commands.py:48** is expected to produce no flow even in diagnostics: `self.remote_commands.get(index)` does not propagate key taint to the looked-up config value.

---

## 6. Modeling principles (consistent with the other project experiments)

1. **Render from reviewed labels only** — formal predicates admit `tp` entries; `candidate` entries go to a diagnostics query; `fp`/`none` entries are documented as rejected, never silently dropped.
2. **Threat model = the paired phone** — protocol decryption/auth is propagation, not sanitization (review point 1); local config (`self.conf`, `ConfigLoader`, `json.load`) and startup input (`os.environ`, argparse, `sys.argv`) stay on the trusted side; the attacker controls only runtime substitution values.
3. **Signature-level matching with positional precision** — module + callable + argument index; sibling parameters of the same function are judged individually (§3); ambiguous shapes (bare names) get API-graph resolution first, AST fallback second.
4. **Location pinning for formal sinks** when signature matching would admit unreviewed sites; diagnostics keep the unpinned family.
5. **Barriers only with evidence** — a sanitizer is modeled only when a metacharacter-blocking check is confirmed to exist in the analyzed snapshot; with no such check the barrier predicate resolves to `none()`, never to unconditional taint or unconditional blocking. r1→r2 is the worked example: the barrier was removed when the escaping API proved absent.
6. **Summaries are conditional call-shape steps** — no unconditional propagation; wrapper functions are never labeled sinks when their entry parameter is already a source (avoids degenerate source==sink paths); internal-parameter diagnostics stay out of the formal result.
7. **Compile before analysis** (WORKFLOW.md 3.1) — both queries were type-checked against the local `codeql/python-all` with `codeql query compile`; execution (`codeql database analyze`) is deferred to the run step and was not performed here.

---

## 7. Files

```
iris/
├── libraries/MySources.qll          # sources, pass-key dispatch (formal/diagnostics)
├── libraries/MySinks.qll            # subprocess arg-0 sinks, 5 tp sites location-pinned
├── libraries/MySanitizers.qll       # empty barrier set (none()) — r2 label state
├── libraries/MySummaries.qll        # receive_file arg0→return; format arg→result
├── queries/Pass2_CommandInjection.ql          # formal @kind path-problem, severity error
├── diagnostics/Pass2_CommandInjectionDiagnostics.ql  # candidate labels only, severity warning
└── report/query_generation_notes.md # this file
```

No source files, CodeQL database, Phase 1 labels, or extraction artifacts were modified; only the files under `iris/{libraries,queries,diagnostics,report}/` were (re)generated.
