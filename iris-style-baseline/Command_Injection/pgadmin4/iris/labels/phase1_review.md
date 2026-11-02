# Phase 1 Checkpoint — Human Review Summary (pgadmin4, Pass 2 / CWE-78)

**Run ID:** `pgadmin4-iris-pass2-20261016` · 2026-10-16 · model glm-5.3 · 2209/2209 CSV rows dispositioned (sources.csv 2149 + sinks.csv 60) · 1705 label entries
**Analyzed state:** source tree and CodeQL database both at sha `61fa8b1` — tree, DB and CSV line numbers agree 1:1 (every line re-checked; evidence strings are verbatim source lines).
**Status:** Phase 1 complete. **Do not proceed to Phase 2 (query generation) until this checkpoint is reviewed** (advisory gate per WORKFLOW.md 4.5).

## 1. Label counts by pass and role

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None | Total |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection (CWE-78) | 1092 (1068 tp / 24 cand.) | 17 (2 tp / 5 cand. / 10 fp) | 0 | 20 (tp) | 576 (fp) | 1705 |

Pass 1 (path traversal) was not in scope; a zero-entry pass_id=1 stub exists only to satisfy labels_schema.json.

## 2. Top high-risk sink APIs (tp)

1. `web/pgadmin/misc/bgprocess/process_executor.py:330` — `Popen(command, stdout=PIPE, stderr=PIPE, **kwargs)` inside `execute()`, with `kwargs['shell'] = True if _IS_WIN else False` (:324). `command = argv[1:]` is the BatchProcess command list `[self.cmd] + self.args` (processes.py:290-291), whose args come from web-request JSON (backup/restore/maintenance/import_export/views/cloud). On Windows this is cmd.exe interpretation of request-derived arguments; only protection is `escape_dquotes_process_arg` (#DQ# markers for already-quoted args, stripped at :414) — double-quote handling, **not** shell quoting. Confidence 0.85.
2. `web/pgadmin/misc/__init__.py:274` — `subprocess.getoutput(r'"{0}" --version'.format(full_path.replace('"', '""')))` inside `validate_binary_path`: `full_path` ← `data['utility_path']` ← `json.loads(request.data)`. getoutput always shells out; mitigated only partially (dquote doubling + `os.path.exists` gate at :268). Confidence 0.75.

Candidate sinks pending human review (5): `passexec.py:36` run(self.cmd, shell=True) — SERVER_MODE-blocked, desktop single-user (0.60); `master_password.py:140` Popen(hook-cmd, shell=True) — admin template with `%u`→username substitution (0.60); `psql/__init__.py:182` Popen(connection_data) — argv-list, no shell (0.60); `psql/__init__.py:237` format-write into cmd.exe (0.65); `utils/__init__.py:375` getoutput probe without dquote escaping — second-order preference path (0.65).

## 3. Top broad source APIs

- Flask request-proxy state (552 entries / 699 rows): `request.data` ×220, `request.form` ×330, `request.args` ×111, plus json/values/files/cookies/headers/environ/get_json, `req` (file_manager alias) and `request_object` (browser delete helpers) — 82 files.
- `json.loads` request-body decode (193 entries): the `json.loads(request.data)` idiom of the tool/browser endpoints.
- `json.loads` request-field decode (59 entries): the `for k, v in request.args/form.items(): json.loads(v)` browser idiom.
- Handler entry params (239 entries): @blueprint.route URL path params + the four @sio.on('/pty') socket payloads (`start_process`/`socket_input`/`resize`/`server_disconnect`).
- `process_executor.py:414` `sys.argv` (1 entry, tp): inter-process BatchProcess command transport — pairs with the :330 sink so the executor-side chain is traceable.
- `import_export_servers/__init__.py:130` / `utils/__init__.py:613` (2 entries, tp): user import-file decodes whose content becomes server registration data incl. `passexec_cmd`.

Broad but rejected as trusted: `config.<NAME>` (423 rows — local settings + PGADMIN_CONFIG_* env of the launching admin), `os.environ` (61 rows), argparse/`sys.argv` of the local CLIs (71 rows — the executor argv row is the deliberate exception).

## 4. Sanitizer list

**Empty for pass 2.** No shlex.quote/pipes.quote/shlex.join exists anywhere in the snapshot; `escape_dquotes_process_arg` is #DQ# marker handling for already-quoted args (stripped in the executor), not shell quoting; the `os.path.exists` gates verify existence, not shell safety; the `PasswordExec.get` SERVER_MODE `NotImplementedError` is a deployment-mode gate, recorded in that sink's rationale rather than modeled as a barrier (a wrong barrier could suppress a true positive).

## 5. Answers to the six mandated review questions

1. **Network data validation before plugins/features?** Cloud provider REST responses (`misc/cloud/*`, `pgacloud/providers/*`) and the upgrade-check URL response are decoded by `json.loads` with no schema validation; they populate UI lists and deployment parameters — no path from this content into a command string exists in this snapshot, so they are retained as `candidate` (0.55), not auto-Source.
2. **Client-supplied notifications/files/config/params reaching system commands?** Yes via three concrete chains: request JSON → BatchProcess args → executor shell (tp sink); `utility_path` request field → getoutput probe (tp sink); socket `/pty` payloads → psql argv / cmd.exe write (candidate sinks). Preferences and import files are second-order paths to the same plumbing (candidate).
3. **subprocess/os call shapes?** All variants coexist: literal `shell=True` (passexec, master_password), dynamic Windows shell toggle (`kwargs['shell']=True if _IS_WIN else False`), argv-list mode (psql Popen, BatchProcess parent, detached re-exec), and fixed constants (yarn bundler, pg_config probes, `PtyProcess.spawn('cmd.exe')`). Fixed-constant and message-format sites are rejected (fp); each exec site carries its mode in the rationale.
4. **Internal functions?** Classified per role: `set_binary_path`/`replace_binary_path`/`get_connection_str` call sites and BatchProcess pipeline wrappers = **summary** (taint steps toward exec); `BatchProcess(id=pid)`/acknowledge = **none** (pid lookup only); `PasswordExec.get`/`get_master_password_from_master_hook`/`execute`/`start` = facets of their sink entries; `validate_binary_path` = wrapper of the tp sink.
5. **Config-fixed commands vs attacker input boundary?** `MASTER_PASSWORD_HOOK` and `DEFAULT_BINARY_PATHS` are admin-authored config (trusted side, fp as sources with tailored rationales); their exec sinks remain labeled (candidate) because the *username substitution* and the *preference override path* respectively are the client-influenced parts. The stored `passexec_cmd` originates from the server-registration API (client-writable in desktop mode) — candidate sink.
6. **Data checks blocking dangerous characters?** Only partial: dquote doubling (misc:275), #DQ# markers (bgprocess:157), `os.path.exists` gates, and int-converted route params (`<int:sid>`). None blocks the general shell metacharacter set; none is modeled as a sanitizer barrier.

## 6. Unresolved / low-confidence items needing human review

29 candidate entries (24 sources + 5 sinks), all with explicit review requests in `labels_raw_pass2.json`:

1. **process_executor.py:330 (tp sink)** — confirm the Windows `shell=True` pipeline is the intended analysis target and whether `escape_dquotes_process_arg` should be treated as a partial barrier (currently not).
2. **misc/__init__.py:274 (tp sink)** — exploitability of the getoutput probe past the `os.path.exists` + dquote-doubling mitigations.
3. **passexec.py:36 / master_password.py:140** — threat-model decision: authenticated desktop-mode user / external-auth username as CWE-78 adversary.
4. **psql:182 / psql:237** — own-session boundary: the socket client can already type arbitrary shell input into the terminal by design.
5. **utils/__init__.py:375 + types.py:83/:198/:229** — the second-order preference→binary-path→getoutput chain (DB round-trip breaks direct taint; decide whether preference-stored values count as attacker data in server mode).
6. **Cloud/upgrade remote response decodes (21 entries)** — compromised-provider/network-position adversary decision.
7. **labels.json pass_id=1 stub** — schema `contains` requires a pass_id=1 element; stub is empty by design.

No entry is below the 0.55 re-ask threshold; minimum confidence used is 0.55.

## 7. Extraction gaps to carry into Phase 2

- `data['db']` / `data['input']` / `data['pwd']` subscripts inside the @sio.on handlers are not individually extracted (detection.json uncoveredCases) — the handler `data` param source plus object-taint propagation must carry them.
- `current_user.username` (the `%u` substitution of the master-password hook) is an ORM attribute read, not extracted — the master_password sink stays candidate partly for this reason.
- `BatchProcess` `self.cmd`/`self.args` re-reads from the ORM (`p.command`/`p.arguments`) are not extracted; the executor-side `sys.argv` source (p2-e-1551) covers the live pipeline instead.
- `escape_dquotes_process_arg` call sites are not extracted as sanitizer rows (deliberate: not a sanitizer).
- `manager.utility(...)` / `get_utility_path` chain from preferences to utility paths crosses ORM/preference reads not captured as rows — covered by the types.py candidate sources and internal_transfer summaries.

## 8. Constraints honored

- No PyVul ground truth (CVE_application_report.md, vulnerability_audit_report.md, cmd_sinks*.csv, 第一审查, pgadmin4-db/cmd_sinks.csv), fix commits, or external advisories were consulted for labeling decisions.
- Project source, CodeQL database, and extraction artifacts (CSV/BQRS) were not modified.
- Diagnostics-vs-formal separation: only `tp` entries may enter the formal pass-2 query; `candidate` entries go to a diagnostics query (unverified propagation must not become formal findings).
- Labeling performed in-session by glm-5.3 (the agent's underlying LLM), 8 batches, 2209 rows; `labels.json` validated against `assets/labels_schema.json` by `labels/scripts/validate_labels.py`.
