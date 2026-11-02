# Augur Phase 1 — Human Review Gate Summary (Pass 1: Path Traversal)

Run ID: `pyramid-pass1-pathtraversal-20261023` · 2026-10-23 · LLM: glm-5.3 (Claude Code CLI)
Scope: pyramid 2.0.1 source under `src/pyramid/` (CodeQL DB `pyramid_vuln/pyramid-db`).
**This run stops after Step 3. No Phase 2 query generation or execution was performed.**

## 1. Label summary (checkpoint payload)

- 307/307 CSV candidates labeled (252 sources, 55 sinks) + 8 analyst-added entries → 315 entries.
- Roles: source 153 · sink 51 · sanitizer 2 · summary 7 · none 102.
- Classifications: tp 208 · fp 106 · candidate 1 · unknown 0.
- Full tables: `label_stats.md`; per-entry rationale/evidence: `labels.json`; per-batch raw output: `labels_raw_pass1.json`.

## 2. The two decisive data flows

### Chain A — HTTP static file serving (guarded; expected FP surface for Phase 2)

`request.path_info` (S037, static.py:133) or `request.subpath` (S045, static.py:131, use_subpath=True)
→ `traversal_path_info` (A003: latin-1→UTF-8 URL-decode + `split_path_info`)
→ **`_secure_path` (A001, sanitizer)**: rejects any element in `{'..', '.', ''}` and any element containing `/` or `os.sep`; `None` → `HTTPNotFound('Out of bounds')` (static.py:136-137)
→ `resource_path = '%s/%s' % (docroot, path)` (package mode, static.py:141) or `normcase(normpath(join(norm_docroot, path)))` (filesystem mode, static.py:152)
→ `resource_isdir`/`isdir` (K051/K052), `resource_exists`/`exists` (K053/K055), `resource_filename` (K054)
→ `FileResponse(filepath, request)` (K050, static.py:112) → `getmtime`/`getsize`/`open(path,'rb')` (K047/K048/K025, response.py:55-57).

Verdict per the review rubric: `Path(...)`/`join()`/string concatenation are not themselves dangerous file access (question 3); the actual accesses are the isdir/exists/filename/open calls, all reached **after** the `_secure_path` guard executes (question 5 — a real, pre-use, restricted-root check). `split_path_info` additionally resolves `..` lexically at ingress (traversal.py:510-523), and URL decoding is canonicalized once at ingress (`decode_path_info`, PEP 3333; `URLDecodeError` on invalid UTF-8) with no re-decode step that could re-introduce `%2e%2e` as a `..` element — and `_secure_path` would reject such an element anyway even if it survived as a literal segment (questions 2, 4, 6). Mixed separators: `_seps = {'/', os.sep}` rejects both on Windows; on POSIX a `\`-bearing element is a single (non-traversal) filename. Absolute paths cannot be injected: no element may contain a separator, so `join()`/`'%s/%s'` always remain under the docroot prefix. **Static file serving is a normal, authorized application function and is defended here** (questions 8, 10): Phase 2 alerts on this chain are expected to be filtered by the A001/A002 barrier.

Residual observations (not traversal): TOCTOU window between `find_resource_path` existence checks, `getsize` ordering (K049, static.py:201) and the later `FileResponse` open, narrowed by the `filemap` cache when `reload=False`; no symlink checks in the static path (existence checks only).

### Chain B — locale-negotiated translation directory (unguarded; primary TP candidate)

`_LOCALE_` from `request.params` (S024/S155), `request.cookies` (S014/S147) or `getattr(request,'_LOCALE_')` (S126, i18n.py:133-138)
→ `request.locale_name` (S026, reified via `negotiate_locale_name`)
→ `request.localizer` (A007) → **`make_localizer(current_locale_name, translation_directories)` (A006)**
→ `ldir = os.path.realpath(os.path.join(tdir, lname))` (i18n.py:192) — **no `..` filtering of the locale name; `os.path.join` discards `tdir` entirely when `lname` is absolute**
→ `os.path.isdir` (K029/K030) → `os.listdir(messages_dir)` (K034) → `os.path.isfile` (K040) → `open(mopath, 'rb')` (K022).

Every step is traceable in the real code (question 2): param/cookie → negotiator → reified property → join → isdir → listdir → isfile → open. No sanitizer exists on this chain (question 5/6): `realpath` (K037–K039, labeled `none`) resolves symlinks but performs no containment; the isdir checks are existence gates, not validation. Consequences an attacker controlling `_LOCALE_` can reach: (a) relative traversal `../../…` out of the configured translation directories; (b) absolute-path override of `tdir` via join semantics; (c) symlink-following is irrelevant since realpath resolves it. Practical impact is bounded: the targeted directory must exist and contain an `LC_MESSAGES/*.mo` structure, and the read `.mo` content is merged into translations (translation-injection / out-of-bounds `.mo` read visible to the attacker themselves) rather than returned as raw file bytes. **Classification: request-derived path reaching file access with no effective containment — the strongest Pass 1 TP candidate; flagged for human confirmation of exploitability/impact assessment.**

### Secondary chains (operator/config boundaries — labeled fp)

- pserve `watch_files` ini setting → `AssetResolver.resolve(file).abspath()` → `PkgResourcesAssetDescriptor`/`FSAssetDescriptor` sinks (K042–K046, K021, K027, K019, K026): operator ini configuration, not per-request input.
- pshell `PYTHONSTARTUP` → `isfile`/`open` (K041/K024): operator environment; the follow-up `exec` is a Pass 4 concern, out of scope here.
- `override_asset` config-time `exists`/`isdir` of `override_with` (K020/K032): executed during configuration, before request handling.
- `matchdict` traverse/subpath sources (S030/S163/S164): feed resource-tree traversal (context lookup via `__getitem__`), not direct file access in this repo — second-order only.
- `Translations.load` (K023, open at i18n.py:272): real public-API file read; grep found no in-repo caller passing request-derived values → `candidate`/0.55, human review point.

## 3. Review-rubric cross-check (10 points)

1. **Source trust boundary**: WSGI `environ` params (S202–S204), `request` entry params, request field/lookup reads confirmed as genuine HTTP boundaries; 98 source rows rejected as CLI/operator/config boundaries (`role=none/fp`) — an internal function parameter alone was never accepted as a source (e.g. `FileResponse.__init__`'s `request` labeled none: only consumed for `wsgi.file_wrapper`).
2. **Traceability**: both chains followed call-by-call in real source (static.py, traversal.py, i18n.py, response.py, request.py); URL decoding (PEP 3333 latin-1→UTF-8 + route-side decoding) documented per step; no speculative edges.
3. **Sink semantics**: only real file read/enumeration/metadata APIs and the file-serving response labeled sink; `join`/`normpath`/string concat/`Path`-style wrappers were never labeled sinks (they appear as summaries A003/A004/A006).
4. **Escape vectors**: `..` (rejected by A001/A002 in Chain A, unfiltered in Chain B), absolute paths (impossible in Chain A — separator-free elements; possible in Chain B via join semantics), separator variants (Chain A rejects `/` and `os.sep` per-platform), repeated/multi decoding (single canonical ingress decode; no double-decode step found).
5. **Real pre-use root checks**: `_secure_path` + `split_path_info` (Chain A: yes, executes before every join/use, including the cached path via `lru_cache` on immutable tuples); Chain B: none — no prefix/containment/whitelist on the locale name.
6. **Named-function skepticism**: `normpath`/`realpath`/`isdir`/`startswith` (DirectoryOverride prefix matching, config-side) were each evaluated against their concrete implementation; `realpath` explicitly labeled non-sanitizer.
7. **Symlinks/TOCTOU**: Chain B uses realpath (resolves links, no containment); Chain A has no symlink check but requires an existing guarded path (TOCTOU window noted, not traversal). Recorded as observations.
8. **Authorization**: static file serving is an intended, guarded application function — not auto-labeled a vulnerability; the *labels* keep sink/tp (real file access) while the vulnerability verdict lives in this review and Phase 2 filtering.
9. **Tests/constants/generated/DB files**: none present in the candidate set (extraction scope guard verified; no `tests/`, `testing.py`, DB-tree, or repo-root rows).
10. **Complete vs local flows**: Chain B is a complete untrusted-source → dangerous-path-argument flow; Chain A is complete but guarded; the asset-descriptor/override sink rows are local internal-wrapper → file-API flows without an untrusted source (documented in their rationale).

## 4. Items for human review before Phase 2

1. **Chain B (`_LOCALE_` → `make_localizer`)**: confirm exploitability thresholds (directory must exist with `LC_MESSAGES/*.mo`) and decide severity; this is the only unguarded request→file path found in `src/pyramid`.
2. **K023** (`Translations.load`, i18n.py:272): no in-repo tainted caller — keep as `candidate` or drop from `MySinks.qll`.
3. Whether the ~14 generic `getattr(request, …)` rows (conf 0.7) should stay in `MySources.qll` for recall or be trimmed to reduce alert volume.
4. TOCTOU observations on the static path (K049/K025) — informational, no label change proposed.
