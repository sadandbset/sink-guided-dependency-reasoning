# Phase 1 Review — Human Review Gate (Advisory) — Pass 1 Path Traversal / ansible

Run `ansible-pathtraversal-pass1-step3-20261021`, labeler model `glm-5.3`, 2026-10-21.
This is the WORKFLOW.md §4.5 checkpoint payload. **Step 3 ends here; Phase 2 is not entered.**

## 1. Label summary

439 entries from 3,970 deduped candidate rows (4,030 raw rows − 60 api/ast doubles); 33 labeling batches; schema-validated against `assets/labels_schema.json` (0 errors). By role: 198 sink, 151 none, 49 summary, 34 source, 7 sanitizer. By classification: 108 tp, 180 candidate, 151 fp. Details and per-batch tables in `label_stats.md`.

## 2. Top high-risk sink chains (all confirmed by direct code reading)

1. **fetch destination write** — `plugins/action/fetch.py`: dest built at :111–134 from task `dest` (expanduser, :111), `flat` basename branch (:118–122) or the non-flat branch `dest = "%s/%s/%s" % (path_dwim(dest), target_name, source_local)` (:132) where `target_name` = `task_vars['inventory_hostname']` (:129) or `remote_addr` (:131) and `source_local` can be the **remote-returned** slurp `source` (:100–102); then `makedirs_safe(os.path.dirname(dest))` (:168) and the write `open(dest,'wb')` (:175) / `self._connection.fetch_file(source, dest)` (:172) whose `out_path` lands on the controller in every connection plugin (paramiko sftp.get, local copyfile, chroot open 'wb+'). Entry p1-snk-268-adjacent (connection_file_api fetch_file arg 1, sink/tp 0.80) + p1-snk-001 (open, 460 sites). The only traversal mitigation in the whole chain is the flat-branch `basename` (:121); the non-flat branch does **not** basename `source_local`.
2. **galaxy role tar extraction** — `galaxy/role.py:330` `role_tar_file.extract(member, self.path)` with the partial name filter at :324–329 (drops `..`/`~`/`$` parts, strips archive parent dir; but `issym()` members carry **unfiltered linknames**, all-dropped parts join to `''`, and only `os.sep` is split). Source family `archive_entry` (untrusted download, :186–203). Entry p1-snk-269, sink/tp 0.85.
3. **DataLoader read channel** — `parsing/dataloader.py:157`/`:355` open after `path_dwim` resolution that has **no base containment** (absolute/`~` passthrough at :181/:222/:283). Fed by lookup terms (file/fileglob/ini/csvfile/shelvefile/template/first_found/password/passwordstore — `find_file_in_search_path` → `path_dwim_relative_stack`) and by action `_find_needle` (copy/template/script/assemble/unarchive/uri/patch/include_vars). Entries: lookup terms 12× source/tp; defs sink/tp 0.70–0.85; call sites sink/tp 0.65–0.80; `shelve.open` sink/tp 0.80 (shelvefile.py:47 chain).
4. **local/chroot connection writes** — `local.py:150` `shutil.copyfile` (via `_ensure_abs`, no containment) and `chroot.py:194` `open(out_path,'wb+')`: controller-side writes of transfer destinations. sink/tp 0.70–0.75.
5. **makedirs_safe** — `utils/path.py:65–90`: self-described "potentially insecure"; realpath guard covers creation only, TOCTOU to the following open remains (fetch.py:168→:175). sink/tp 0.70.

## 3. Top source boundaries (conservative-recall set)

`json.loads` of remote module stdout (remote_result, tp 0.80 — feeds fetch `source` and copy `lnk_source`); galaxy tar member names (archive_entry, tp 0.85); 10 path-consuming lookup `terms` params (tp 0.65); host-variable/fact reads and fetch dest name components (candidate 0.50–0.70).

## 4. Sanitizers (all partial — none accepted as a proven barrier)

- `os.path.basename` (candidate 0.55): neutralizes directory traversal in the filename position (fetch.py:121 flat branch, fileglob.py:60); residuals: `basename('..') == '..'`, non-POSIX separators.
- `ActionBase._remote_expand_user` (×6, candidate 0.45–0.50): rejects `..` in the expanded dirname (action/__init__.py:686–687) — but only for `~`-prefixed paths, only post-expansion.
- Explicitly **not** treated as sanitizers despite their names: `normpath`, `realpath`, `unfrackpath`, `path_dwim*` (canonicalization/resolution without any base-directory containment — labelled summary), `makedirs_safe`'s realpath check (guards creation only), and `os.path.exists`/`isfile`/`isdir`/`isabs` (checks, labelled none).

## 5. Answers to the review checklist

1. **Real untrusted sources?** Yes for lookup terms (playbook-templated with remote facts), host vars/facts, remote module stdout (`json.loads`), galaxy tar member names; no for `context.CLIARGS`/`sys.argv`/CLI `args`/`os.environ` (operator trust — 985 rows excluded) and internal function params generally. No HTTP surface exists (no routes/URL-decoding/multipart — nothing fabricated).
2. **User path → decode/normalize/join → file API traceable?** Yes: the fetch (task dest → expanduser → path_dwim → %-format → makedirs_safe → open/fetch_file) and lookup (terms → find_file_in_search_path → path_dwim_relative_stack → _get_file_contents open) chains were traced line-by-line; no URL decoding exists in the controller tree.
3. **Sinks are real file access?** Yes: open/os.open/io.open/shelve.open reads+writes, delete/rmtree, makedirs, rename/copy, tar extract, connection fetch/put writes. Pure path constructors (`os.path.join`, `Path`-like wrappers) were labelled summary, not sink; checks (`exists`/`isdir`/…) none.
4. **Traversal capability?** Yes where documented: fetch non-flat branch appends the unbasenamed remote path under dest; DataLoader search stack passes absolute/`~` terms through uncontained; galaxy filter leaves issym linknames and `''`-join edge cases; `unfrackpath` even documents `$HOME/../../var/mail` escaping.
5. **Real containment before file access?** None found in the DataLoader/ActionBase chains (no `relative_to`/containment check anywhere); the only genuine guards are the fetch flat-branch basename, the galaxy part filter, and _remote_expand_user's `..` rejection — all labelled candidate sanitizers with their limits.
6. **Does the named function actually block?** Assessed per implementation: basename/`_remote_expand_user` partially (see §4); normpath/realpath/unfrackpath/path_dwim do not (no containment, taint preserved).
7. **Symlinks/timing?** Documented per site: makedirs_safe TOCTOU (realpath→makedirs→open), copy.py `_walk_dirs` follows symlinks per `local_follow`, galaxy issym linkname passthrough, unfrackpath realpath following. No symlink-based root escape beyond these was observed — recorded as not applicable otherwise.
8. **Authorized file service?** Operator-invoked fetch/copy/lookup of chosen files is intended functionality — this is why operator-trust boundaries are excluded and why fetch/copy flows are graded on the *untrusted* components (remote-returned `source`, facts-templated terms) rather than on the operator's own arguments.
9. **Tests/constants/generated code?** The extraction scope (`%/lib/ansible/%`, ansible-db excluded, top-level test/hacking/docs trees out) already excludes tests; remaining noise was labelled fp (checks, abstract defs, write-targets, non-path uses). No candidate was counted as a real flow merely for being in the DB directory.
10. **Full untrusted-source→dangerous-arg flow vs local wrapper fragment?** Distinguished: full flows exist for remote_result/archive_entry→(fetch dest, galaxy extract) and lookup-terms→DataLoader open; wrapper-only fragments (internal `_transfer_file`, generic connection defs) are graded candidate ≤0.60 accordingly.

## 6. Unresolved / manual-review items (blocking for Phase 2 quality)

1. **task_args family missing from sources.csv** (extraction defect: `task` vs `_task` name mismatch in sources.ql families 1–3, 0 rows matched). Without it, task-argument flows into the labelled sinks (fetch/copy/template/include_vars src+dest) are unreachable by the Phase 2 taint query. **Recommendation: fix sources.ql family predicates and re-run extraction before Step 4–5**, or add the boundary in MySources.qll at generation time (fetch.py:51–55, copy.py:412–416, template.py:41–64, include_vars.py:78–100 are the known sites).
2. MySummaries needs: %-format dest construction (fetch.py:132) and `dest.replace("//","/")` (:134); result-dict steps for `slurpres.get('source')` (fetch.py:100–102) and `dest_status_nofollow['lnk_source']` (copy.py:355–356).
3. 88 sink entries below 0.55 confidence (oracle-grade stat/listdir/glob/remote-stat families and generic connection defs) — kept for recall; expect Phase 2 noise from them and filter per WORKFLOW 5.3.2.
4. `makedirs_safe` TOCTOU (CWE-059 timing) is beyond static reach — analyst follow-up.
5. 5 source candidates at 0.50 (synchronize/module_common/interpreter_discovery var reads) — verify whether they can actually reach paths before MySources generation.

## 7. Gate decision

Automated/self-run mode: summary logged above, self-approved for archive; **no Phase 2 execution was started**. The primary actionable outcome of the review is item 6.1 (task_args extraction defect) — it should be resolved before Step 4 (library generation) if task-argument flows are wanted in the taint results.
