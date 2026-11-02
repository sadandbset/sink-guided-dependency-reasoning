# Phase 1 Review — Pass 1 (Path Traversal), pretalx

Human-review-gate payload per Augur WORKFLOW.md §4.5 (advisory checkpoint; this run stops
here and does not enter Phase 2).

- **Run:** `pretalx-pathtraversal-pass1-20261022`, model `glm-5.3`, 2026-10-22
- **Inputs:** 667 candidates (634 sources, 33 sinks) from `extraction/*.csv`, all labeled
- **Artifacts:** `labels/labels.json` (schema-valid, 667 entries), `labels/labels_raw_pass1.json` (12-batch audit trail), `labels/label_stats.md`

## 1. Label counts by role

| role | source rows | sink rows | total |
| --- | ---: | ---: | ---: |
| source | 562 | 0 | 562 |
| sink | 0 | 25 | 25 |
| sanitizer | 0 | 0 | 0 |
| summary | 0 | 0 | 0 |
| none | 72 | 8 | 80 |

By classification: tp 468, fp 182, candidate 17, unknown 0.

## 2. Top high-risk sink APIs (candidate-classified)

1. **`open(path, 'rb')` — `common/views.py:56` (get_static)** with `FileResponse` at `:55` and
   the `path` source parameter at `:48`. Verified complete, unguarded flow:
   `settings.BASE_DIR / 'pretalx/static' / path` → `path.exists()` → `open(path, 'rb')` →
   streamed to the client. No canonicalization, no base-directory containment, no `..`
   rejection; `exists()`-then-`open()` is a plain check-then-use. **Reachability caveat:** the
   only shipped route (`agenda/urls.py:124-131`, `sw.js`) binds the literal
   `'agenda/js/serviceworker.js'`; the view docstring itself says traversal would come from
   "a malicious urlconfig". Attacker control therefore requires a route (e.g. plugin
   urlconfig) that binds a URL variable to this parameter. → human review: is any
   plugin-supplied urlconfig in scope for this deployment?
2. **HTML export command** (`agenda/management/commands/export_schedule_html.py`):
   `open(path, 'wb')` at `:121` (`dump_content`: `Path(destination) / url.lstrip('/')`),
   `open(local_path, 'rb')` at `:134` (`get_mediastatic_content`:
   `STATIC_ROOT/MEDIA_ROOT / url[len(STATIC_URL):]`), `path.parent.mkdir(parents=True)` at
   `:119`. Raw pathlib joins; `lstrip('/')` removes only leading slashes and `..` components
   survive, so a `/static/../../…` URL would escape the export root. The URL set is
   app-generated (`reverse()`, storage URLs); user rich-text content is bleach-cleaned with
   `script`/`img`/`link` not in `ALLOWED_TAGS` (`common/templatetags/rich_text.py:9-45`),
   so the remaining injection vector is organiser-uploaded `custom_css` (CSS `url()`
   matches, `find_urls` at `:53`) or a plugin data exporter. Operator-triggered (CLI or
   `ScheduleExportTriggerView` via celery). → human review: privilege level accepted for
   organiser-supplied CSS.
3. **Django storage save/open/delete with client-derived names** — `cfp/flow.py:260,266`,
   `common/mixins/forms.py:445,450,461`. The call sites perform no own name validation
   (`get_new_filename` at `forms.py:470-479` even embeds the raw uploaded name as a path
   component). Blocking relies entirely on Django-internal validation (multipart filename
   basename, `validate_file_name`, `FileSystemStorage.safe_join`; Django `~=3.2.0` pinned at
   `src/setup.py:101`), which is **outside this CodeQL DB and could not be verified from
   source**. → human review / Phase 2 triage: confirm the installed Django provides these
   protections.

## 3. Top broad source APIs

- `request.GET` reads (144 rows, tp 0.75) — includes `unquote()`-wrapped reads enabling
  double-decoding (`agenda/views/schedule.py:85`, `agenda/views/widget.py:167`,
  `common/views.py:83`, `common/mixins/views.py:155`).
- `form.cleaned_data` (106 rows, tp 0.6, second-order) and `request.FILES` (12 rows, tp 0.8).
- `self.kwargs` route variables (59 rows): int/slug-converter keys labeled fp (payload
  impossible), str-converter keys (`code`, `version`, `name`, `tmpid`, `invitation`) labeled
  tp. `self.kwargs['version']` at `agenda/views/schedule.py:34` is `unquote()`d (second
  decode) but is used only for DB lookups, never a file path.

## 4. Sanitizer list

Empty — by evidence, not by omission: grep-verified (detection.json) that pretalx's own
source contains no `safe_join`/`get_valid_filename`/`basename`/`abspath`/`normpath`/
`realpath`/`relative_to` path guards. `common/utils.py:132 safe_filename()` and
`Storage().get_valid_name()` (`agenda/views/speaker.py:129`) are used only for
Content-Disposition headers, never in front of a file access, so they were not counted as
sanitizers. Framework-internal validation (Django storage) is recorded as evidence caveats
on the affected sink entries.

## 5. Unresolved / low-confidence items

14 entries below 0.55 (all re-checked, unchanged): the 6 `cfp_session.get` reads (0.5), the
export-command mkdir (0.45) and open write/read (0.5), `file_storage.open(tmp_name)` (0.45),
and the 4 storage save/delete rows (0.45–0.5). All carry `human_review` notes in
`labels_raw_pass1.json`.

## 6. Audit answers (task checklist)

1. **Sources from genuinely untrusted boundaries?** Yes for request GET/POST/FILES/headers/
   cookies/body/path and str-converter URL variables. Internal function parameters (`up`,
   `draft`, `steps`, `view`, `obj`, `response`, …), framework metadata (`resolver_match`),
   env/config reads (41 rows) and urlconfig literals are labeled `none`/fp — an internal
   parameter is not automatically a source.
2. **Path from URL-decode/normalization/join to file API traceable?** Traced for three
   chains: get_static (param → raw join → open), export command (URL → raw join →
   open/mkdir), cfp flow (upload name → storage save/open). Every step verified against the
   real source (locations in §2 and in each label's evidence).
3. **Sinks are actual file access?** Yes — every `sink` row is an actual `open()`, storage
   `save/open/delete`, `rmtree`, `rename`, `mkdir`, `make_archive` or file-serving
   `FileResponse` with a real file argument. `Path(...)`, `join()` and string concatenation
   sites were **not** labeled sinks (they are recorded as propagation context in
   detection.json). BytesIO/NamedTemporaryFile call sites are labeled `none` (no filesystem
   access at that site).
4. **Can the path escape the declared root?** For get_static and the export command: yes in
   code (`..` survives both constructions; no containment exists anywhere in pretalx's own
   code). For Django storage chains: expected blocked by framework validation, unverified.
   Slug-derived paths cannot escape (validator `^[a-zA-Z0-9.-]+$`, no separators); residual
   edge: a literal `..` event slug would resolve to the parent of `HTMLEXPORT_ROOT` (e.g.
   `rmtree` of the parent directory) — organiser-privilege only, noted in the sink evidence.
5. **Real root-containment checks before file access?** None in pretalx's own code. The only
   framework-level checks (int/slug URL converters) neutralize traversal for those route
   parameters and are reflected as fp classifications, not sanitizer labels.
6. **Do normpath/resolve/basename/startswith/blacklist block anything here?** No such
   functions exist on any file path in pretalx (grep-verified); the single `.resolve()` use
   is a static locale path (`settings.py:348`). Nothing was accepted as a sanitizer by name.
7. **Symlinks / TOCTOU?** No symlink-specific handling anywhere; `path.exists()` → `open()`
   in get_static is a check-then-use, and `zip_path.exists()` in
   `event/services.py:79` precedes the zip read. Recorded as evidence, no symlink issues
   confirmed.
8. **Intended file-serving functionality?** Yes — schedule zip download, event
   logo/header images, avatars and widget assets are permission-gated, intended file
   serving with storage-assigned or operator-set names → fp, not vulnerabilities.
9. **Tests / fixed constants / unreachable code?** `test_settings.py` (test fixture),
   `makemessages` (dev tooling), literal static reads (`common/tasks.py:54`), env-config
   open, Django-managed upload temp paths — all fp; none counted as traversal.
10. **Complete untrusted-source → dangerous-path flows?** Only get_static is a complete,
    code-verified source→sink flow with no validation; its attacker reachability depends on
    routing. The export chains are complete but their URL inputs are app-generated/organiser
    level. The storage chains are complete but rely on framework validation. Local
    wrapper-to-file-API flows without an untrusted source (e.g. `path_with_hash`) were not
    labeled as sinks — they are propagation helpers.

## 7. Proceeding to Phase 2 (not executed in this run)

Per instructions this run stops after emitting the label artifacts. For Phase 2 the
expected inputs are: 562 source rows (97 unique signature+role tuples → MySources.qll), 25
sink rows (MySinks.qll), an empty-but-declared sanitizer barrier, and 17
candidate-classified entries as the primary triage list. Whether get_static's
urlconfig-gated reachability and the organiser-CSS export vector are accepted as findings
is the main decision for the human reviewer.
