# Augur Phase 1 Step 3 - Pass 1 Labeling Review (flask-cors)

Human-review payload for the CHECKPOINT gate (WORKFLOW.md 4.5). Independent LLM labeling of all 67 candidates from `extraction/sources.csv` (46 rows) and `extraction/sinks.csv` (21 rows) against full source reads of the flask-cors_vuln snapshot (creation sha 5c6e05e, 28 .py files, CodeQL DB `flask-cors-db`). No PyVul ground truth, patch diffs, CVE notices, or post-snapshot analysis artifacts were consulted.

## Verdict summary

| role | count | entries |
| --- | --- | --- |
| source (tp) | 8 | `src-011`, `src-014`, `src-016`, `src-023`, `src-024`, `src-037`, `src-045`, `src-046` |
| sink (fp) | 3 | `sink-011`, `sink-014`, `sink-017` (builtin open, setup.py) |
| summary (candidate) | 4 | `sink-012`, `sink-013`, `sink-015`, `sink-016` (os.path.join/dirname, setup.py) |
| sanitizer | 0 | - (nothing to sanitize; see below) |
| none (fp) | 52 | all config-family source rows (29), internal request-value params (6), wrapper params (2), response-header read (1), examples/docs path helpers and sys.path.insert (14) |

**Headline conclusion**: flask-cors 3.0.8 is a pure CORS response-header filtering Flask extension. Its entire untrusted-input surface is the Flask `request` proxy (Origin / Access-Control-Request-Method / Access-Control-Request-Headers headers, `request.path`, `request.method`), and all of it terminates in regex matching, logging, and response-header writes. The package performs **zero filesystem access** (grep-verified across all 5 modules). The only real file operations in the whole snapshot are three literal-path `open()` reads in the setuptools packaging script plus constant `__file__`-derived path manipulation in examples/docs. **No untrusted-source-to-file-API flow exists; no path traversal vulnerability is reachable in this code.**

## Review against the ten labeling questions

1. **Source from a genuinely untrusted boundary?** Yes for 8 entries, all anchored on the Flask `request` proxy (`from flask import request`, core.py:20 / decorator.py:13 / extension.py:11): `request.path` (extension.py:178, :180 - path-shaped, URL-decoded), `request.headers` (core.py:245), `request.method` (core.py:245, decorator.py:125), and the header reads `request_headers.get('Origin')` (core.py:177), `.get(ACL_REQUEST_METHOD)` (:194), `.get(ACL_REQUEST_HEADERS)` (:203). All other 38 source rows are internal function parameters or operator-trust configuration (developer kwargs, `app.config` CORS_* keys, `DEFAULT_OPTIONS`) - explicitly **not** labeled source; an internal helper parameter is not automatically a source.

2. **User path tracked through decode/normalize/join/object conversion into a file API?** No. The only path-shaped attacker value, `request.path`, flows into `try_match` -> `re.match` (core.py:278/:280) as a regex *subject* and stops there. Every step was traced on real code: extension.py:178 `try_match(request.path, res_regex)` -> core.py:275-285. It is never decoded, joined, normalized, converted, or passed to any file API inside flask_cors.

3. **Sink is an actual file read/write/delete/extract/file-response?** Only `setup.py:15` (`open(join(dirname(__file__), 'flask_cors/version.py'), 'r')`), `setup.py:18` (`requirements.txt`), `setup.py:29` (`open('README.rst')`) - real `builtin open()` calls, labeled `role=sink, classification=fp` (constant paths, packaging-time execution, unreachable from any request). `os.path.join`/`dirname`/`abspath` and `sys.path.insert` are **not** sinks (path construction / import-resolution manipulation), consistent with the rule that `Path(...)`, `join()`, and string concatenation are not themselves dangerous file access.

4. **Can `../`, absolute paths, separator variants, or repeated decoding escape a declared root?** Not applicable: no declared allowed root directory exists anywhere in the codebase (there is no file serving to confine), and no URL decoding is performed inside the library (Werkzeug decodes `request.path` before it is visible; the decoded value is only regex-matched).

5. **Real root-confinement check executed before file access?** Not present and not applicable - no filesystem access exists to guard. (No `startswith` base-dir check, no `relative_to`, no fixed-filename mapping, no whitelist.)

6. **Do normpath/resolve/basename/startswith/blacklist block escape here?** No sanitizer labels emitted. `os.path.abspath` (examples/docs) is canonicalization *without* base-dir containment operating on `__file__` constants - not a proven sanitizer; `os.path.dirname` is component extraction, likewise on constants. Function names alone were not accepted as sanitization evidence.

7. **Symlinks / TOCTOU?** Not applicable - no symlinks are resolved and no check-then-use file sequence exists anywhere in the package (zero FS access). Recorded as not applicable, per policy.

8. **Intentional authorization to access files?** The only file reads (setup.py) are the packaging script reading its own package's version/requirements/README at build time - developer tooling, not user-facing file service. No static-file/download/upload endpoint exists in the snapshot.

9. **Test / constant / unreachable / generated code?** `tests/` (18 files) was excluded at extraction (Step 2 filter), not by labeling. The examples/ and docs/conf.py rows kept in scope are constant-`__file__` import-path hacks in demo/doc code - labeled `none`/fp, not counted as traversal. All `open()` paths are fixed constants. Nothing labeled relies on test or generated code.

10. **Complete untrusted-source-to-dangerous-path flow, or only a local wrapper-to-file-API flow?** Neither exists: the only file-API flows are local constant-path flows inside setup.py (`dirname(__file__) -> join(...) -> open(...)`), modeled with 4 summary steps so that any *future* taint entering that chain would propagate to the `open()` sinks; the 8 untrusted sources have no file API downstream. There is no complete untrusted-source-to-sink flow.

## High-risk sink list (for the checkpoint payload)

- `sink-011` / `sink-014` / `sink-017` - `builtin open()`, arg 0 = path, setup.py:15/:18/:29. Real file-read API (sink role confirmed for query generation), but arguments are literal/`__file__`-derived constants in a packaging script - **instance FP, no exploitation path**. `sink-011`'s read content is additionally `exec`'d at setup.py:16 (recorded as Pass 4 material, out of Pass 1 scope).

## Broadest source APIs (recall tradeoffs)

- `request.path` (extension.py:178/:180) - canonical path-shaped source; would be the primary source for any Flask-app pass query reuse.
- `request.headers` (core.py:245) and the three header reads - attacker-controlled but not path-shaped; kept at 0.65-0.85 for conservative recall. Demoting them to `none` would not change any Phase 2 outcome on this codebase (no sink is reachable regardless).
- `request.method` (core.py:245, decorator.py:125) - weakest (HTTP verb); 0.65.

## Sanitizer list

Empty - see label_stats.md. No path-validation code exists in the codebase; `abspath`/`dirname` on constants are not sanitizers.

## Unresolved / low-confidence items and manual review points

None below the 0.55 re-ask threshold; no `unknown` role assignments. Points a human reviewer may still want to weigh (also recorded in `labels_raw_pass1.json` under `unresolved_or_review`):

1. **Header/method source retention**: `src-011`/`src-014`/`src-016`/`src-023`/`src-024`/`src-037` are real untrusted boundaries but not path-shaped. Reviewer may prefer a tighter Pass 1 source set (source = `request.path` only). No finding-level impact either way.
2. **Summary role for setup.py join/dirname**: `sink-012`/`sink-013`/`sink-015`/`sink-016` model propagation toward the `open()` sinks. Reviewer may prefer `none` given constant arguments; kept as `summary/candidate` for taint-model completeness.
3. **Examples/docs path helpers**: labeled `none`/fp; a reviewer preferring uniform propagation modeling could relabel `dirname`/`abspath` there as summary (no Pass 1 flow exists either way).
4. **Extraction under-coverage carried over** (from detection.json): `serialize_option` subscript reads (core.py:334-336, config-only) and Flask URL-rule variable binding (inside the external flask package) were not extracted; neither is a path traversal flow here.
5. **Phase 2 expectation**: given zero source-to-sink connectivity, `Pass1_PathTraversal.ql` is expected to produce zero alerts on this DB; any alert would be a false positive by construction and should be filtered at Step 6.

## Constraints honored

- Read-only on: the source tree, the CodeQL database, the Augur installation, and the Phase 1 CSVs (the generator script lives in the OS temp dir and only reads the CSVs).
- No PyVul ground truth, patches, or CVE material consulted; no conclusions derived from the post-snapshot analysis artifacts at the source root.
- `labels.json` validated PASS against `assets/labels_schema.json` (pass_id 1, schema field names `version/metadata/passes` with `id/role/classification/confidence/signature/rationale/location/evidence` entries; flow_kind mapped to the schema enum, `argIndex -1` mapped to `arg_index` null).
- Outputs written: `labels/labels.json`, `labels/labels_raw_pass1.json`, `labels/label_stats.md`, `labels/phase1_review.md`. Phase 2 not started.
