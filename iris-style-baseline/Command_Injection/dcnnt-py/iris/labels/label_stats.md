# Label Statistics — dcnnt-py, Pass 2 (CWE-78), Run r2

**Run ID:** `dcnnt-py-iris-pass2-20261015-r2` · Generated 2026-10-15
**Re-labeling of:** `dcnnt-py-iris-pass2-20261015` (r1) — see "r1 -> r2 changes" below.
**Snapshot:** source tree and CodeQL database both at commit `4084ea1` (tree == DB creation sha; every CSV line number matches the current source file, including `plugins/notifications.py`).

## Labeling session

| Item | Value |
| --- | --- |
| Model | glm-5.3 (in-session labeling by the agent's underlying LLM; no external LLM API calls) |
| Batches | 5 (batch-1 protocol/app surface 41 rows · batch-2 plugins/base 34 · batch-3 file_transfer/notifications/opener/remote_commands 49 · batch-4 sync 44 · batch-5 all sinks 39) |
| Candidate rows processed | 207 (sources.csv 168 + sinks.csv 39) — **all rows dispositioned** |
| Rows merged into sibling entries | 26 → 13 entries (12 source-side duplicate rows; 7 subprocess call sites × 2 extra facet rows each = 14 sink-side rows) |
| Supplementary (out-of-CSV) entries | 0 (r1's shlex.quote supplementary entry was removed — API absent in snapshot 4084ea1) |
| Final label entries | 181 |
| Re-ask threshold | 0.55 — entries below threshold: 0 |

## Entries by role × classification

| Role | tp | candidate | fp | total |
| --- | ---: | ---: | ---: | ---: |
| source | 63 | 8 | 0 | 71 |
| sink | 5 | 2 | 0 | 7 |
| sanitizer | 0 | 1 | 0 | 1 |
| summary | 12 | 0 | 0 | 12 |
| none | 0 | 0 | 90 | 90 |
| **total** | **80** | **11** | **90** | **181** |

## Confirmed (tp) sinks — 5 sites

| # | Entry | Site | Confidence |
| --- | --- | --- | --- |
| 1 | p2-e-160 | `plugins/file_transfer.py:110` `subprocess.call(command, shell=True)` | 0.90 |
| 2 | **p2-e-164** | **`plugins/notifications.py:58` `subprocess.call(command, shell=True)`** | **0.92** |
| 3 | p2-e-168 | `plugins/opener.py:34` `subprocess.call(command, shell=True)` | 0.92 |
| 4 | p2-e-172 | `plugins/opener.py:44` `subprocess.call(command, shell=True)` | 0.92 |
| 5 | p2-e-178 | `plugins/sync.py:318` `subprocess.call(command, shell=True)` | 0.88 |

All five execute a `str.format`-built command string with `shell=True` and an unquoted
attacker-controlled substitution value (file name / URL / backup name / notification fields).

Candidate sinks (diagnostics only, not formal): `remote_commands.py:48` (config command
selected by index — intended feature), `sync.py:361` (merge path behind `ensure_file_syncable`
substring allow-list).

## Confirmed (tp) sources — top families (63 entries)

- Raw network reads: `sock.recv`/`handler.recv` (tcp_server.py:35/:69, base.py:106/:109), `decrypt` (tcp_server.py:85, base.py:114, server_search.py:38), `Plugin.read`/`Plugin.rpc_read` (base.py:123/:148/:185/:189, notifications.py:33/:42, remote_commands.py:59)
- Protocol decode: `json.loads` (base.py:128, server_search.py:17), `RPCRequest.from_dict` (base.py:128), `unpack_raw_request` (server_search.py:25), `b64decode` (server_search.py:38)
- Handler entry params: `process_request`/`handle_*`/`receive_file*`/`common_upload_handler` request parameters (30+ entries across the five plugins)
- Request params reads: `request.params['key']` / `.get` / `.pop` (21 entries, including notifications.py:42/:43/:45 — packageIcon/event/title)

Candidate sources (8, diagnostics only): `_receive_file` @3 / `receive_file_to_path` @2 (attacker-derived destination paths at sync call sites), and the five ToDo/unused `RPCDispatcher`/`RPCSerializer` shapes in common/jsonrpc.py.

## Sanitizers

| Entry | API | Verdict |
| --- | --- | --- |
| p2-e-144 | `SyncPlugin.ensure_file_syncable` (sync.py:328) | candidate 0.55 — substring containment guard, semantics need human review |
| ~~p2-e-182~~ | ~~`shlex.quote`~~ | **removed in r2** — API does not exist in snapshot 4084ea1 |

The confirmed (tp) sanitizer set for pass 2 is **empty**: no metacharacter-blocking check
exists anywhere in this snapshot (no shlex import in the tree).

## r1 -> r2 changes (the r1 omission, closed)

| Entry | r1 | r2 | Reason |
| --- | --- | --- | --- |
| p2-e-164 (notifications.py:58 sink) | candidate 0.65 | **tp 0.92** | r1 was judged against a checkout state where `cmd.format` wrapped every substitution in `shlex.quote`; in snapshot 4084ea1 there is no shlex import and title/text/package (plus the package-derived icon path) are substituted unquoted into the shell command. |
| p2-e-182 (shlex.quote sanitizer) | tp 0.88 (supplementary) | **removed** | API absent from snapshot 4084ea1; barrier modeling would block nothing real. |
| 13 notifications entries | stale line refs / quote refs | corrected | CSV lines now match the source tree 1:1; all rationales citing `shlex.quote`/fixed-tree line numbers were rewritten. |

All other 168 entries are unchanged from r1: the r1 and r2 snapshots differ only in
`plugins/notifications.py`, and every non-notifications judgment was re-verified against
the current tree during exploration (Step 1–2 r2).
