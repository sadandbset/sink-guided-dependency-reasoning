# Phase 1 Review Gate - Pass 1 (Path Traversal) Labeling Summary

Augur Phase 1 Step 3 complete. This is the advisory human-review checkpoint payload (WORKFLOW.md 4.5). **Phase 2 has NOT been started.**

## Scope

- Target: coderedcms 0.22.2 source tree (`coderedcms_vuln`), Python / Django (Wagtail co-framework).
- Pass 1: CWE-022 / CWE-023 / CWE-036 / CWE-073.
- All 313 raw candidate rows (sources + sinks) processed in 9 LLM batches; 218 unique labeled entries after dedup. Labels: `iris/labels/labels.json` (schema-valid against `assets/labels_schema.json`), raw decisions: `iris/labels/labels_raw_pass1.json`, statistics: `iris/labels/label_stats.md`.

## Label counts by role

| Role | Count |
| --- | --- |
| source | 57 |
| sink | 8 |
| sanitizer | 0 |
| summary | 22 |
| none | 131 |

## Top high-risk sink APIs

1. **`open` - coderedcms/views.py:117 (tp, 0.98)** - `open(fullpath, 'rb')` in `serve_protected_file`: `fullpath = os.path.join(PROTECTED_MEDIA_ROOT, path)` where `path` is the URL-injected route parameter (`re_path(r'^protected/(?P<path>.*)$')`). No containment, no '..' rejection; `isfile` check is existence-only (TOCTOU); `@login_required` gates who, not what. **The confirmed CWE-022 channel.**
2. **`storage.open` - coderedcms/wagtail_flexible_forms/models.py:245 (candidate, 0.75)** - upload write at `session_key_dir + client_filename`; containment depends on Django-external `FileSystemStorage.path()`/safe_join and MultiPartParser filename handling (evidence gap).
3. **`storage.open` - coderedcms/models/page_models.py:1212 (candidate, 0.75)** - same upload shape on the `FileSystemStorage(PROTECTED_MEDIA_ROOT)` wrapper.
4. **`Image.open` / `thumbnail.save` - wff models.py:342/:344 (candidate, 0.70)** - second-order: stored submission paths re-opened/written for thumbnails.
5. **`storage.delete` - wff models.py:379/:488 (candidate, 0.65/0.60)** and **`rmdir` - wff models.py:499 (candidate, 0.55)** - second-order deletion over stored submission paths.

## Top source APIs

- **route_param: `serve_protected_file(request, path)` param 1 (tp, 0.97)** - the entire URL path below `/protected/`, percent-decoded by Django before routing.
- **upload_name: `file.name`/`val.name`/`value.name` (tp, 0.9-0.95, 5 sites)** - client-supplied multipart filenames flowing into `str(Path(directory) / name)` destination construction (absolute name replaces the directory).
- **http: 45 request GET/POST/FILES/META boundary entries (tp, 0.8-0.9)** - genuine untrusted boundaries; most feed ORM/datetime logic only (no path sink downstream), kept for conservative recall.
- **db_json: 6 json.loads sites over stored submission data (candidate, 0.60)** - second-order boundary (stored paths re-used by thumbnail/delete channels).

## Sanitizer list

**None.** No base-directory containment, `..` rejection, normalization-then-containment, basename extraction or `startswith` guard exists anywhere in the project's own code. `os.path.splitext` in `coderedcms/forms.py:66-74` validates upload file *extensions* only and is explicitly recorded as NOT a traversal sanitizer. `MySanitizers.qll` will resolve to `none()` in Phase 2.

## Audit questions (per the labeling contract)

1. **Source trust:** the route parameter (views.py:110) and multipart filenames are the only genuinely untrusted path-bearing inputs; request.GET/POST/FILES/META are true boundaries but only FILES/POST reach file channels; internal function parameters, `session_key` (server-generated random), `cr_settings` config and CLI/operator options are NOT auto-sources - labeled `none`.
2. **Path transformations:** route param -> `os.path.join` (views.py:114) -> `open` (views.py:117), each step verified in the real code; upload filename -> `Path(dir) / name` -> `get_available_name` -> `storage.open`, each step verified (wff :241-247, page :1208-1214).
3. **Sink validity:** only real file read/write/delete APIs are labeled sink (`open`, `storage.open`, `Image.open`, `thumbnail.save`, `storage.delete`, `rmdir`); `Path(...)`, `join()`, `storage.path()`, `get_available_name` are labeled **summary** (propagation), not sink.
4. **Escape potential:** `os.path.join` semantics let an absolute or leading-`..` route path escape PROTECTED_MEDIA_ROOT; pathlib `/` lets an absolute filename replace the session-key directory - both documented per-entry. No percent-decoding issue exists in this code (Django decodes before routing; no unquote calls).
5. **Containment checks:** none exist before any file access (see sanitizer list).
6. **Function-name-only sanitizers:** none assumed; `splitext`, `isfile`, `get_available_name`, `storage.path` are all explicitly NOT treated as sanitizers.
7. **Symlinks/TOCTOU:** no symlink/realpath logic anywhere; TOCTOU window noted between `isfile` (:115) and `open` (:117). Not otherwise applicable.
8. **Authorization:** `@login_required` and wagtail-admin permissions limit the attacker population but do not sanitize paths (django.md section 8) - contextual, not a guard.
9. **Tests/generated code:** migrations/, tests/ and project_template/ were excluded at extraction time; every remaining CSV candidate is labeled (mappings in labels_raw_pass1.json).
10. **Flow completeness:** the protected-media channel is a complete untrusted-source -> dangerous-path-argument flow; the upload and second-order channels are complete flows whose final exploitability depends on Django-external behavior (candidate), not mere local wrapper-to-API fragments.

## Unresolved / low-confidence items (human review points)

1. **Upload write channel (candidate, 0.75):** verify Django 3.0-3.2 `FileSystemStorage.path()`/`safe_join` and MultiPartParser/FileField filename validation behavior externally before judging `storage.open` (:245/:1212) TP/FP.
2. **Second-order db_json channel (candidate, 0.6-0.7):** stored file paths are server-computed by save_files; traversal requires DB-side tampering or a user-text path into a file-field value - decide whether this threat model counts.
3. **session_key directory component:** server-generated random; if a future Django session backend or misconfiguration made it attacker-influenced, the mkdir/storage channels would need re-review.
4. **No sanitizers found:** confirm the empty-sanitizer decision (MySanitizers -> none()) before Phase 2 barrier wiring.

## Decision

Advisory gate: ready for human review. Do not proceed to Phase 2 (library generation, taint queries, report) until the review points above are acknowledged.
