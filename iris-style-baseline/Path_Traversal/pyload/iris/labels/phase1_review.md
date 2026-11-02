# Phase 1 Review — pyload, Pass 1 (Path Traversal, CWE-22/23/36/73)

- run_id: `pyload-pass1-20261023`
- target: pyLoad 0.5.0b3 / pyload-ng (`pyload_vuln` source tree; CodeQL DB `pyload-db` nested inside the tree and excluded from all labeling evidence)
- labeling model: glm-5.3, in-session via Claude Code CLI (no external LLM API calls)
- inputs: `extraction/sources.csv` (104 rows) + `extraction/sinks.csv` (663 rows) → **750 unique label entries** after dedup (4 + 7 exact-duplicate rows collapsed; 6 Api definition rows extracted in both CSVs merged into single source entries)
- output: `labels/labels.json` — **validated locally against `iris_tools/augur-0.3.0/assets/labels_schema.json` (jsonschema: PASSED)**; per-row audit trail in `labels/labels_raw_pass1.json`; counts in `labels/label_stats.md`
- process: 7 logical batches (pass1-s1 Flask request families, pass1-s2 route/api boundaries, pass1-s3 archive/CLI families, pass1-k1 direct file-access sinks, pass1-k2 filesystem mutation sinks, pass1-k3 path propagation/validation, pass1-k4 wrapper definitions). Every labeling decision was made after first-hand reading of the cited source lines; evidence ranges are recorded per entry. References loaded: `references/patterns.md`, `references/python.md`, `references/flask.md` (Flask detected at score 1.0 in Step 1).

## Label counts

| role | entries | of which tp | of which candidate |
| --- | --- | --- | --- |
| source | 87 | 85 | 2 |
| sink | 223 | 141 | 82 |
| sanitizer | 15 | 8 | 7 |
| summary | 275 | 187 | — (88 fp) |
| none | 150 | — | — (all fp) |

## Top high-risk sink chains (for the Phase 1 checkpoint review)

1. **`file.save` — `src/pyload/webui/app/blueprints/json_blueprint.py:157`** (P1-K-0550, sink/tp/0.9). `/json/add_package` multipart upload: `file.filename` is used completely unsanitized as `os.path.join(storage_folder, 'tmp_' + file.filename)` (:154-156) and then saved. The `'tmp_'` prefix only defeats a *leading bare* `..` component (`tmp_..`); any filename with intermediate separators (`x/../../evil`) traverses out of the storage folder. Boundary: `flask.request.files['add_file']` / `file.filename` (P1-S-0071/-0072/-0074, 0.95). Auth: `login_required("ADD")`. This is the highest-confidence traversal-write of the pass.
2. **`open(..., 'wb')` — `src/pyload/core/api/__init__.py:535` and `:951`** (P1-K-0297 / P1-K-0299, sink/tp/0.85). `Api.check_online_status_container(container, data)` and `Api.upload_container(filename, data)`: RPC-reachable (`/api/<func>` dispatcher, `literal_eval` args/kwargs) writes with the *same* unsanitized `'tmp_' + name` join shape; ADD permission. Sources: the api_param rows (P1-S-0012, P1-S-0014, P1-S-0015, 0.9).
3. **`os.makedirs` / chunk writes — the `_folder` chain** (P1-K-0398 downloader.py:322, 0.8; P1-K-0530/P1-K-0532 http_chunk.py:183/208; P1-K-0065 ExtractArchive.py:255, 0.8; plus MergeFiles:42, XDCC:985). `/json/edit_package` form field `pack_folder` → `Api.set_package_data` `setattr(p, '_folder', value)` (no write-time sanitization) → `PyPackage.folder = safepath(_folder)` → `safejoin`/`join` into download and extraction destinations. **safepath is only a partial sanitizer** (see below), so `..` *components* survive on posix and the destination escapes `storage_folder`. Source: P1-S-0079 (json_blueprint.py:196, 0.95).
4. **`flask.send_from_directory` — `app_blueprint.py:165`** (P1-K-0341, sink/tp/0.75). `/files/get/<path:path>` with `unquote(path).replace('..','')` at :163. The strip runs after a single unquote (encoded traversal collapses; double-encoding stays a literal name), but the load-bearing containment is **werkzeug `safe_join`, external to the CodeQL DB** — Phase 2 alerts here must be triaged against that external guard. DOWNLOAD permission.
5. **Archive extraction** — UnZip.py:90 (`z.extractall(self.dest, members=namelist-filtered)`; no pyload-side entry check, stdlib `zipfile._extract_member` is the guard — external), UnTar.py:78/23 (behind the `_safe_extractall` CVE-2007-4559 commonprefix guard, P1-K-0192 sanitizer/candidate/0.6), SevenZip.py:261 and UnRar.py:289 (extractor Popen with the Python-supplied dest). All inherit the `_folder` chain via `self.dest`.
6. **Torrent decrypter tmp writes** — AlldebridComTorrent.py:64, RealdebridComTorrent.py:95: `safejoin(tempdir, 'tmp_{package().name}.torrent')` — the package **name** is stored raw (only the *folder* is sanitized in `Api.add_package`), and safepath preserves `..` components, so a crafted package name can escape the tempdir. Partially gated by the `abspath().startswith(tempdir + os.sep)` guards (sanitizer/candidate/0.55).
7. **UpdateManager plugin writes/deletes** — UpdateManager.py:377 (update-server-parsed plugin names, no local sanitization) and :414/:433 (RPC-exposed `remove_plugins(plugin_ids)` → `os.remove(join(basedir, type, name + '.py'))` — traversal delete candidate).

## Top broad sources

- `flask.request.args.items()/form.items()` at api_blueprint.py:53 (P1-S-0030, 0.95) — every query/form key becomes an RPC kwarg (`unquote` + `literal_eval`), the widest entry into all `api_param` receivers via the dynamic `getattr` dispatch.
- All `flask.request.form/args` reads in the cnl/json/app blueprints (49 http_form + 12 http_args rows, tp 0.8-0.95). Non-path uses (login credentials, pagination, captcha results) are kept as sources — they are genuine untrusted boundaries — with the downstream use stated in each rationale.
- `api_param` rows: add_package(name), upload_container(filename), check_online_status_container(container), set_package_data(data incl. `_folder`), set_package_name(name), set_config_value(value, candidate/0.6 — SETTINGS-gated admin-config origin, the admin-config FP heuristic applies at triage).
- `archive_entry` rows: UnZip `namelist()` / UnTar `getnames()` (0.9) — remote archive entry names.
- Discarded as sources: all `sys.argv`/argparse rows (operator trust, none/fp) and `filemanager(path)` at app_blueprint.py:439 (route declares no variable; parameter unused — not externally reachable).

## Sanitizer list

**tp:** `purge.name` (purge.py:41, 0.8 — separator removal at `PyFile._set_name` and content-disposition makes `..` inert), `parse.name` basename (parse.py:45/47, 0.75), HjSplit basename (:57), `http_request` FormFile basename (:252), ZDF basename (:60).
**candidate (partial, verify before use as barriers):** `safepath` (old/__init__.py:36, 0.5) and `safename` (:71, 0.55) — remove in-component separators and drive letters but **preserve `..` as a standalone component on posix**; `safename`-style strips noted on the add_package (:427-438), CNL dlc (:93-94) and TORRENT (:69-73) entries; UnTar `commonprefix` guard (:15, char-prefix boundary weakness, symlink members unchecked); the four `abspath().startswith(tempdir + os.sep)` guards in the torrent decrypters (sep-terminated but symlink-blind).

`os.path.join`, `normpath/realpath/abspath/relpath`, `basename/split/splitext` were **not** treated as sinks or sanitizers by default: join/canon are taint-preserving propagation (summary), and no containment comparison follows the canonicalizations in this codebase.

## Unresolved / manual-review points

- **Dynamic RPC dispatch**: `getattr(api, func)(...)` (api_blueprint.py:72-75) is statically unresolved; the `rpc` func/args route params and the `call_api` api_dispatch row (candidate/0.55) carry the caller side, the `api_param` rows the receiver side. Taint linking needs MySummaries steps in Phase 2.
- **External-library containment not visible to CodeQL**: werkzeug `safe_join` (send_from_directory), jinja2/flask_themes2 template loaders (`/render` route, sink/candidate/0.55), stdlib `zipfile._extract_member`. Alerts on those chains must weigh the external guard at triage.
- **pathchooser/filechooser** (app_blueprint.py:257-308): intentional directory browser fed by `request.args.get('path')`; `listdir`/`stat`/`getmtime`/`getsize` rows are labeled sink/candidate 0.5-0.6 (authorized STATUS-level feature; info-disclosure impact only, no file content read).
- **TOCTOU sequences** recorded as evidence: pathchooser `normpath → isfile/isdir → listdir` and ExtractArchive `exists() → makedirs` (:254-255) / `exists(fname)` → extract (:304).
- **Operator-trust boundaries**: CLI rows (userdir/tempdir/storagedir/pidfile, sys.argv) are labeled none/fp — an internal function parameter or operator CLI value is not automatically a source.
- **Low-confidence entries** (152, conf < 0.55): predominantly stat/oracle probes (path_stat family at 0.45-0.55) where the confidence deliberately encodes the oracle-only semantics; no re-ask pass was run because the rationale is explicit in each row. Full list in `label_stats.md`.
- No pathlib usage, no os.symlink, no request-controlled os.chdir observed in this tree (recorded as not-applicable in detection.json and reflected by the chdir rows being none/fp).

## Dedup / exclusion ledger

- 4 exact-duplicate source rows and 7 exact-duplicate sink rows collapsed (byte-identical CSV rows, e.g. the two `items()` rows at api_blueprint.py:53, duplicated `realpath`/`getsize`/`isdir` rows).
- 6 definition rows extracted by both queries (`set_config_value`, `add_package`, `check_online_status_container`, `set_package_name`, `upload_container`, `set_package_data`) merged into single **source** entries — the parameter is the taint boundary; propagation to the file APIs is carried by the summary entries (joins, wrappers). Recorded per-row in `labels_raw_pass1.json`.
- Excluded from evidence (experiment independence): repo-root `CVE_VULNERABILITY_REPORT.md`, `CVE_Application_Report_Unassigned.md`, `VULNERABILITY_AUDIT_REPORT.md`, `path_traversal_sinks.csv`, the `pyload-db` directory, `tests/`, and any PyVul ground truth, patch diffs or CVE data. `setup.py` rows are in scope but labeled none/fp (build script, not runtime code).
- Nothing in the source tree, the CodeQL database, the Augur installation or the Phase 1 CSVs was modified.

## Checkpoint decision

Automated mode: summary logged above, self-approved for Phase 2 handoff (per WORKFLOW.md 4.5). **No Phase 2 work was started.**
