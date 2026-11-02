# Pass 1 Label Statistics (Path Traversal - CWE-022/023/036/073)

- Project: coderedcms 0.22.2 (Wagtail 2.14 / Django 3.x, Python)
- Model: glm-5.3 (LLM labeling over the real source tree, 9 batches)
- Generated: 2026-10-21; run_id: `coderedcms-pass1-labeling-20261021`

## Input coverage

| Input | Rows |
| --- | --- |
| sources.csv raw rows | 206 |
| sinks.csv raw rows | 107 |
| **total raw candidate rows** | **313** |

Dedup key: `(side, file, line, callableName)`. Merged: moduleHint variants, api/ast double rows of the same call site, and Subscript/Attribute shapes of the same site (95 rows merged into existing entries; no row dropped without a mapping - every raw row resolves to an entry in labels_raw_pass1.json).

| Unique sites | Count |
| --- | --- |
| source sites | 143 |
| sink sites | 75 |
| **total labeled entries** | **218** |

## Roles (all entries)

| Role | Sources | Sinks | Total |
| --- | --- | --- | --- |
| source | 57 | 0 | 57 |
| sink | 0 | 8 | 8 |
| sanitizer | 0 | 0 | 0 |
| summary | 0 | 22 | 22 |
| none | 86 | 45 | 131 |

## Classifications

| Classification | Sources | Sinks | Total |
| --- | --- | --- | --- |
| tp | 51 | 9 | 60 |
| fp | 86 | 45 | 131 |
| candidate | 6 | 21 | 27 |
| unknown | 0 | 0 | 0 |

## Confidence distribution

| Bucket | Sources | Sinks |
| --- | --- | --- |
| <0.55 | 0 | 0 |
| 0.55-0.79 | 9 | 33 |
| >=0.8 | 134 | 42 |

## Source families (role=source)

| Family | Entries | Classification |
| --- | --- | --- |
| db_json | 6 | candidate |
| http | 45 | tp |
| route_param | 1 | tp |
| upload_name | 5 | tp |

## Sink families (role=sink)

- `open` (coderedcms/views.py:117) - tp, confidence 0.98, dangerous path arg index 0
- `open` (coderedcms/models/page_models.py:1212) - candidate, confidence 0.75, dangerous path arg index 0
- `open` (coderedcms/wagtail_flexible_forms/models.py:245) - candidate, confidence 0.75, dangerous path arg index 0
- `open` (coderedcms/wagtail_flexible_forms/models.py:342) - candidate, confidence 0.70, dangerous path arg index 0
- `save` (coderedcms/wagtail_flexible_forms/models.py:344) - candidate, confidence 0.70, dangerous path arg index 0
- `delete` (coderedcms/wagtail_flexible_forms/models.py:379) - candidate, confidence 0.65, dangerous path arg index 0
- `delete` (coderedcms/wagtail_flexible_forms/models.py:488) - candidate, confidence 0.60, dangerous path arg index 0
- `rmdir` (coderedcms/wagtail_flexible_forms/models.py:499) - candidate, confidence 0.55, dangerous path arg index n/a (receiver)

## Summary-role entries (taint propagation / wrappers)

22 entries: os.path.join (views.py:114), Path-ctor destinations (wff :244, page :1211), get_available_name, storage.path, with_suffix, parent-walk, splitext (forms.py:68/:73, non-sanitizer) and the 7 internal_file_wrapper/function definition rows.

## Sanitizers

**0 entries.** No containment/normalization guard executes before any file access in the project's own code (no safe_join, no normpath/realpath comparison, no '..' rejection, no basename extraction, no startswith(base) check). The extension whitelist/blacklist in forms.py:60-74 constrains only the filename suffix and is explicitly labeled as NOT a traversal sanitizer.

## Batches

| Batch | Scope | Raw rows | Unique sites |
| --- | --- | --- | --- |
| S1 | source candidates: coderedcms/views.py, urls.py, utils.py, templatetags/coderedcms_tags.py | 28 | 24 |
| S2 | source candidates: forms.py, models/integration_models.py, models/snippet_models.py, models/wagtailsettings_models.py, blocks/base_blocks.py, blocks/layout_blocks.py | 34 | 31 |
| S3 | source candidates: bin/coderedcms.py (CLI family) | 59 | 26 |
| S4 | source candidates: wagtail_flexible_forms/models.py | 42 | 20 |
| S5 | source candidates: models/page_models.py | 36 | 36 |
| S6 | source candidates: wagtail_flexible_forms/wagtail_hooks.py | 7 | 6 |
| K1 | sink candidates: views.py, settings.py, forms.py, bin/coderedcms.py | 32 | 17 |
| K2 | sink candidates: wagtail_flexible_forms/models.py | 62 | 46 |
| K3 | sink candidates: models/page_models.py | 13 | 12 |
