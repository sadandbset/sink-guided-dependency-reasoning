# Phase 1 Checkpoint — Human Review Summary (dcnnt-py, Pass 2 / CWE-78, Run r2)

**Run ID:** `dcnnt-py-iris-pass2-20261015-r2` · 2026-10-15 · model glm-5.3 · 207/207 CSV rows dispositioned · 181 label entries
**Analyzed state:** source tree and CodeQL database both at commit `4084ea1` ("Version 0.9.0") — tree, DB and CSV line numbers agree 1:1.
**Status:** Phase 1 complete. **Do not proceed to Phase 2 (query generation) until this checkpoint is reviewed** (advisory gate per WORKFLOW.md 4.5).

## 1. Label counts by pass and role

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None | Total |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection (CWE-78) | 71 (63 tp / 8 cand.) | 7 (5 tp / 2 cand.) | 1 (cand.) | 12 (tp) | 90 (fp) | 181 |

Pass 1 (path traversal) was not in scope; a zero-entry pass_id=1 stub exists only to satisfy labels_schema.json.

## 2. Top high-risk sink APIs (tp)

1. `plugins/notifications.py:58` — `subprocess.call(command, shell=True)`; `command = cmd.format(uin=uin, name=name, icon=icon, text=text, title=title, package=package)` (`:56`) — **title/text/package come straight from `request.params` and are substituted UNQUOTED**; no shlex/escaping exists anywhere in this snapshot. Confidence 0.92.
2. `plugins/opener.py:44` — `request.params.get('link')` → `default_cmd.format(url=url)` → `subprocess.call(..., shell=True)`; only an `isinstance(url, str)` type check. Confidence 0.92.
3. `plugins/opener.py:34` — `request.params['name']` → saved path → `on_download.format(path=path)` → `subprocess.call(..., shell=True)`. Confidence 0.92.
4. `plugins/file_transfer.py:110` — same shape as opener:34 on the upload path. Confidence 0.90.
5. `plugins/sync.py:318` — `request.params['name']` → `receive_file` → `on_done.format(path=res)` → `subprocess.call(..., shell=True)`. Confidence 0.88.

Shared taint chain confirmed by code review: `rpc_read/params` (source) → `receive_file` arg0→return (summary) → `str.format` substitution (summary) → `subprocess.call` arg0 (sink).

## 3. Top broad source APIs

- `Plugin.rpc_read` / `Plugin.read` (network read boundary — every plugin loop)
- `request.params['…']` / `.get` / `.pop` (JSON-RPC params — 21 sites)
- handler entry parameters `process_request` / `handle_*` / `receive_file*` / `common_upload_handler` (30+ entries)
- `sock.recv` / `handler.recv` / `decrypt` / `json.loads` / `unpack_raw_request` / `b64decode` (protocol stack)

Broad but rejected as trusted: `ConfigLoader` / `json.load` / `self.conf` (local schema-validated config — the command templates themselves), `os.environ`, argparse/`sys.argv` (local single-user CLI).

## 4. Sanitizer list

- `shlex.quote`: **absent from this snapshot** — the r1 supplementary entry (p2-e-182) was removed in r2. Confirmed sanitizer set is EMPTY for pass 2.
- `SyncPlugin.ensure_file_syncable` (sync.py:328): candidate 0.55 — substring containment (`path in i['path']`), not equality; guards the sync.py:361 merge path only. Deliberately NOT modeled as a barrier (needs human review of intended semantics; a wrong barrier could suppress a true positive).

## 5. r1 -> r2 verdict changes (the r1 omission, closed)

| Entry | r1 | r2 | Why |
| --- | --- | --- | --- |
| p2-e-164 `notifications.py:58` sink | candidate 0.65 | **tp 0.92** | r1 judged against a checkout state where every substitution was wrapped in `shlex.quote`; snapshot 4084ea1 has no shlex import — title/text/package (and the package-derived icon path) enter the shell command unquoted. |
| p2-e-182 `shlex.quote` sanitizer | tp 0.88 (supplementary) | **removed** | API does not exist in snapshot 4084ea1. |

Everything else is unchanged from r1 (the two snapshots differ only in `plugins/notifications.py`; all other judgments re-verified in Step 1–2 r2).

## 6. Unresolved / low-confidence items needing human review

1. **notifications.py:58 verdict change (candidate → tp)** — confirm the analyzed checkout (4084ea1, unescaped notification fields) is the intended target state.
2. **remote_commands.py:48** (`check_call(cmd, shell=True)`) — intended predefined-remote-commands feature: config-defined command selected by attacker-controlled index. Selection, not content injection; candidate 0.55. Confirm candidate vs fp for the project's threat model (paired-phone attacker).
3. **sync.py:361** — merge path behind `ensure_file_syncable` substring allow-list and a double-quoted default template. Injection requires metacharacters in a *configured* sync path or a custom template. Candidate 0.60.
4. **sync.py:328 `ensure_file_syncable`** — sanitizer semantics: substring containment vs equality. Candidate 0.55.
5. **common/jsonrpc.py dispatch/serializer sources** — ToDo/unused code path (no live call sites); retained as candidate sources for recall; re-review if wired in a later version.
6. **labels.json pass_id=1 stub** — schema `contains` requires a pass_id=1 element; stub is empty by design.

No entry is below the 0.55 re-ask threshold; 11 candidate entries total (8 sources, 2 sinks, 1 sanitizer) all carry explicit review requests in `labels_raw_pass2.json`.

## 7. Extraction gaps to carry into Phase 2

- `map(request.params.get, ('text', 'package'))` (notifications.py:44) — bound-method form is not a call row; `text`/`package` values rely on the handler-param/`rpc_read` sources plus object-taint propagation, or on the `title` path (notifications.py:45, a direct `.get` source). `title` alone already yields a complete source→sink path to notifications.py:58.
- `plugin(app, self, source).main()` (tcp_server.py:97) — dynamic plugin dispatch unresolvable; covered by the `rpc_read`/handler-param sources instead.
- `func(**request.params)` (jsonrpc.py:130) — unused dispatcher; candidate sources only.

## 8. Constraints honored

- No PyVul ground truth, fix commits, or external advisories were consulted for labeling decisions.
- Project source, CodeQL database, and extraction artifacts (CSV/BQRS) were not modified.
- Diagnostics-vs-formal separation is preserved: only `tp` entries may enter the formal pass-2 query; `candidate` entries go to the diagnostics query (per query_generation policy and the task directive that unverified propagation must not become formal findings).
