# Phase 1 Step 3 — LLM Candidate Labeling Statistics (Pass 1: Path Traversal)

- **Run ID:** `ansible-pathtraversal-pass1-step3-20261021`
- **Date:** 2026-10-21
- **Labeler (LLM):** `glm-5.3` — the model of this session, acting as LLM-as-labeler (no external API calls; every decision was authored from first-hand reading of the `ansible_vuln` source tree, see "Evidence basis" below)
- **Target:** ansible 2.9.6.post0 (lib/ansible), no web framework (detection.json framework scores 0.0; ansible's own plugin architecture plays the framework role)
- **Pass:** 1 — CWE-022 / CWE-023 / CWE-036 / CWE-073 (Path Traversal)
- **Inputs:** `extraction/sources.csv` (1,238 rows), `extraction/sinks.csv` (2,792 rows), `exploration/detection.json`, `augur-0.3.0/WORKFLOW.md` (4.4), `references/python.md`, `references/patterns.md`, `assets/labels_schema.json`; no framework reference loaded (none matched)
- **Outputs:** `labels/labels.json` (schema-validated), `labels/labels_raw_pass1.json` (full audit trail), this file, `phase1_review.md`

## 1. Candidate volume, dedup, and batching

| measure | sources | sinks | total |
| --- | ---: | ---: | ---: |
| CSV candidate rows | 1,238 | 2,792 | 4,030 |
| api/ast double rows dropped (identical file+line+callable+flowKind+argIndex) | 44 | 16 | 60 |
| call sites after dedup | 1,194 | 2,776 | 3,970 |
| unique signatures (→ labels.json entries) | 148 | 291 | **439** |

Dedup policy: (a) exact duplicate rows emitted twice by overlapping family predicates (api + ast match kinds, cf. detection.json `matchKindSemantics`) were collapsed; (b) distinct syntactic shapes of the same boundary (e.g. `context.CLIARGS` attribute read, `CLIARGS[...]` subscript, `CLIARGS.get(...)` call; `os`-qualified vs bare-name `os.remove`) were **kept as separate entries** because Phase 2 `.qll` generation needs distinct node matching per shape; (c) every deduped row maps to exactly one entry — the complete row→entry mapping is in `labels_raw_pass1.json` (`rowAssignments`), and the validator re-checked all 3,970 mappings.

Labeling was performed in **33 signature-family batches** (10 source families `S-*`, 23 sink families `K-*`), each reviewed against the real source code of its sites (representative line text extracted for every entry; full file reads for all controller-side flow-critical files listed in "Evidence basis").

| batch | entries | candidate rows |
| --- | ---: | ---: |
| S-cli_options | 3 | 569 |
| S-env | 4 | 388 |
| S-task_vars | 34 | 67 |
| S-lookup_terms | 62 | 62 |
| S-inventory_addr | 22 | 47 |
| S-task_vars_get | 12 | 21 |
| S-cli | 2 | 21 |
| S-remote_result | 1 | 8 |
| S-cli_args | 7 | 7 |
| S-archive_entry | 1 | 4 |
| K-file_open | 7 | 484 |
| K-path_check | 9 | 313 |
| K-file_delete | 8 | 300 |
| K-path_resolve | 10 | 256 |
| K-path_join | 2 | 228 |
| K-file_create_temp | 6 | 168 |
| K-file_stat | 4 | 158 |
| K-file_read | 6 | 137 |
| K-file_dir_create | 5 | 138 |
| K-action_file_api | 40 | 53 |
| K-file_api_def | 115 | 115 |
| K-loader_file_api | 31 | 39 |
| K-file_copy | 8 | 58 |
| K-file_perms | 6 | 85 |
| K-path_expand | 3 | 67 |
| K-file_move | 4 | 50 |
| K-path_glob | 2 | 50 |
| K-archive_open | 6 | 38 |
| K-lookup_file_api | 7 | 7 |
| K-connection_file_api | 4 | 4 |
| K-file_create | 4 | 24 |
| K-archive_read | 3 | 3 |
| K-archive_extract | 1 | 1 |

Sink call-site scope: 1,766 controller-side rows, 1,010 module-side rows (`lib/ansible/modules/` — modules execute on managed nodes fed by `module.params`, the remote mirror of task args, which was deliberately not extracted as a source family this pass; see §5).

## 2. Label counts by role and classification

### Sources (148 entries)

| role | classification | entries | notes |
| --- | --- | ---: | --- |
| source | tp | 12 | remote_result (json.loads of module stdout, 0.80), archive_entry (galaxy tar member names, 0.85), 10 path-consuming lookup `terms` params (0.65) |
| source | candidate | 22 | host-variable/fact reads (0.55–0.60), fetch dest name components (inventory_hostname 0.70 / remote_addr 0.60), ansible_search_path, passwordstore dir, synchronize/module_common/interpreter_discovery var reads (0.50) |
| none | fp | 114 | see §3 |

### Sinks (291 entries)

| role | classification | entries | notes |
| --- | --- | ---: | --- |
| sink | tp | 62 | open/os.open/io.open/shelve.open, delete/rmtree, makedirs(+makedirs_safe), rename/move, copy family, symlink/link, galaxy extract, DataLoader get_real_file/_get_file_contents/load_from_file, local/chroot connection fetch/put out_path, fetch_file dest call site, wrapper call sites of get_real_file/_get_file_contents |
| sink | candidate | 136 | stat/lstat/getsize, listdir/walk/readlink, chmod/chown/utime, glob, archive_open, generic connection-plugin defs, _transfer_file/_transfer_data/_execute_remote_stat/_remote_checksum, cleanup_tmp_file, find-fetch in_path sides |
| sanitizer | candidate | 7 | basename (0.55), _remote_expand_user ×6 (0.45–0.50, partial `..` guard) |
| summary | tp | 34 | os.path.join, expanduser/expandvars, dirname/splitext/split, unfrackpath, DataLoader path_dwim family, _find_needle, find_file_in_search_path |
| summary | candidate | 15 | realpath/normpath/abspath/relpath, wrapper call sites of path_dwim* |
| none | fp | 37 | see §3 |

### Overall

| role | entries | | classification | entries |
| --- | ---: | --- | --- | ---: |
| sink | 198 | | tp | 108 |
| none | 151 | | candidate | 180 |
| summary | 49 | | fp | 151 |
| source | 34 | | | |
| sanitizer | 7 | | | |

Confidence: sources min 0.50 / mean 0.73 / max 0.85; sinks min 0.40 / mean 0.62 / max 0.90. Per WORKFLOW 4.4.4 the below-0.55 entries (88 sink + 5 source) were re-examined in the consolidation pass of rule authoring; none of them carries `classification: tp` (verified: all tp labels are ≥ 0.65) and each documents its residual doubt in the rationale — they remain `candidate`/`fp` for the human review gate.

## 3. Exclusions (role `none`, 151 entries / 1,404 rows) and why

| reason | entries | rows |
| --- | ---: | ---: |
| non-path lookup terms (network/secret/list lookups: aws_*, k8s, redis, dig, …) | 52 | 52 |
| operator CLI/env trust (context.CLIARGS, sys.argv, CLI `__init__` args, os.environ) | 16 | 985 |
| existence/type checks (os.path.exists/isdir/isfile/islink/isabs, loader path_exists/is_file/is_directory, _remote_file_exists) | 18 | 317 |
| remote_addr non-path uses (connection host assignment, display logging, error strings) | 21 | 46 |
| task_vars write-targets / non-path variable reads (`task_vars['ansible_socket'] = …`, `del task_vars[…]`, role_path, groups) | 21 | 22 |
| abstract connection base defs (ConnectionBase/NetworkConnectionBase put_file/fetch_file raise NotImplementedError) | 8 | 8 |
| tempfile auto-generated names (mkstemp/NamedTemporaryFile/mkdtemp — only dir=/prefix= influenced) | 6 | 168 |
| archive probe / member-content read (is_tarfile, extractfile — TarInfo arg, not a filesystem path) | 5 | 11 |
| variables non-path reads (lookup variables['groups'], variables['role_path'] alias forms) | 2 | 4 |
| other (os.stat-family name-collision rows classified under checks) | 2 | 18 |

The operator-trust decision is the largest single exclusion (16 entries, 985 rows): ansible is a CLI automation engine, not a service — `context.CLIARGS`, `sys.argv`, CLI `args` and `os.environ` are the trusted operator's own inputs (python.md §7.4 over-broad-source guard; the CLI-args source pattern in python.md §3 targets service-mode tools). The genuinely untrusted boundaries kept as sources are: playbook-templated lookup terms (templar variables include remote `ansible_facts`, task_executor.py:694/:758), host-variable/fact reads, `json.loads` of remote module stdout, galaxy tar member names, and fetch-dest name components.

## 4. Highest-coverage entries (rows → entry)

| entry | role | signature | rows |
| --- | --- | --- | ---: |
| p1-snk-001 | sink/tp 0.90 | `open` arg 0 (builtins) | 460 |
| p1-src-003/004 | none/fp | `context.CLIARGS` (operator trust) | 288+253 |
| p1-snk-019 | summary/tp 0.80 | `os.path.join` arg 0 | 223 |
| p1-src-007 | none/fp | `os.environ` (operator trust) | 192 |
| p1-snk-039 | none/fp | `os.path.exists` (check) | 179 |
| p1-snk-010/011 | sink/tp 0.85 | `os.remove` arg 0 (bare + os-qualified forms) | 90+90 |
| p1-snk-036 | sanitizer/candidate 0.55 | `os.path.basename` arg 0 | 70 |
| p1-snk-033/034 | sink/candidate 0.50 | `os.stat` arg 0 (bare + os-qualified) | 69+69 |

## 5. Known gaps carried into review (not fabricatable from the CSVs)

1. **`task_args` boundary missing from sources.csv.** sources.ql families 1–3 (`task_args`/`task_args_get`/`task_args_item` — the primary task-argument boundary of action plugins: fetch.py:51–55, copy.py:412–416, template.py:41–64, include_vars.py:78–100, …) matched **0 rows** because the predicates test `getName() = "task"` while the actual receiver attribute is `_task` (verified by reading sources.ql:184–243; the same file's inventory_addr family correctly uses `"_play_context"` and matched 47 rows). Phase 1 artifacts must not be modified in this step, so no task-argument source entries exist; the affected sink-side flows (fetch dest, copy/template src+dest, include_vars file/dir) are documented as manual-review items in phase1_review.md §6.
2. **`module.params` boundary** (~28k read sites across 3,908 modules) deliberately not extracted (detection.json `uncoveredCases`) — module-side sink sites (1,010 rows) are labelled but no pass-1 controller source reaches them.
3. **`%-format` / string-concat path construction** (fetch.py:132 `"%s/%s/%s"`, :134 `dest.replace("//","/")`) has no extracted family — needs a MySummaries step in Phase 2.
4. **Remote-result dict reads below the json.loads boundary** (fetch.py:100–102 `slurpres.get('source')`, copy.py:355–356 `lnk_source`) — needs result-dict taint steps in Phase 2.

## 6. Validation

- `labels.json` passes a strict offline validation implementing every constraint of `augur-0.3.0/assets/labels_schema.json` (required/forbidden properties, enums, patterns, `arg_index` conditional rule for `flow_kind: argument`, `passes` contains pass_id 1) plus audit checks (439 unique ids; all 3,970 deduped candidate rows map to an entry; labels/raw counts agree). The `jsonschema` package was unavailable in this environment (pip install blocked), so the validator (`labels/work/validate.py`) implements the schema directly; result: **0 errors**.
- Every pass-1 label decision is grounded in source code: `location` + `evidence` (real line text quoted from the tree) on every entry; the full per-row audit trail is `labels_raw_pass1.json`.

## 7. Evidence basis (files read first-hand for labeling)

`plugins/action/fetch.py` (full), `galaxy/role.py` (:100–360), `parsing/dataloader.py` (:130–410), `utils/path.py` (full), `plugins/lookup/{__init__,file,fileglob,first_found,shelvefile}.py`, `plugins/action/{__init__ (415–455, 630–690, 1155–1178), include_vars (70–190), template (95–175), net_get (45–115), copy (330–375)}`, `plugins/connection/{local (125–167), chroot (125–200)}`, `parsing/vault/__init__.py` (:360–435), `executor/task_executor.py` (:570–614, 680–720), `executor/discovery/python_target.py` (full), `config/manager.py` (:290–330), `modules/files/{file,unarchive}.py` (spot checks), plus the extracted source line of every one of the 439 representative candidate sites. Ground-truth artifacts present in the tree (PATH_TRAVERSAL_AUDIT_REPORT.md, CVE_APPLICATION_REPORT.md, CVE申请报告.md, 漏洞审查报告.md, path_traversal_sinks.csv, test/) were not opened.
