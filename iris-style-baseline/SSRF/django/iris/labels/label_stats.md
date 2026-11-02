# Augur Phase 1 Step 3 — Label Statistics (django, Pass 3: CWE-918 SSRF)

- Run ID: `django-iris-pass3-step3-20261020`
- Generated: 2026-10-20
- Model: glm-5.3 (Z.ai GLM), labeled in-session via Claude Code CLI; 8 batches; temperature unset (harness default); single-pass deterministic labeling with per-module source-context verification (see `labels_raw_pass3.json` model block)
- Schema: validated against `augur-0.3.0/assets/labels_schema.json` (draft 2020-12, `jsonschema.validate` → SCHEMA VALID)

## Coverage

| Input | Rows | Labeled entries |
| --- | --- | --- |
| `extraction/sources.csv` | 235 | 235 (`src-001` … `src-235`, 1:1 row parity) |
| `extraction/sinks.csv` | 3 | 3 (`snk-001` … `snk-003`) |
| **Total** | **238** | **238** |

- Every CSV candidate row is covered; none skipped or merged.
- Exact duplicate CSV rows (identical in every column, kept for row parity with identical labels):
  - sources.csv row 15 = row 14 (`request.POST`, `django/contrib/auth/admin.py:202`)
  - sources.csv row 17 = row 16 (`request.POST`, `django/contrib/auth/admin.py:203`)
  - sources.csv row 181 = row 180 (`request.POST`, `django/contrib/admin/options.py:1717`)
  - sources.csv row 185 = row 184 (`request.POST`, `django/contrib/admin/options.py:1733`)
- No sanitizer candidates existed in the CSVs; no sanitizer entries were invented.

## Role distribution (238 entries)

| Role | Count |
| --- | --- |
| source | 4 |
| sink | 3 |
| sanitizer | 0 |
| summary | 3 |
| none | 228 |

## Classification distribution

| Classification | Count |
| --- | --- |
| tp | 5 |
| candidate | 4 |
| fp | 229 |
| unknown | 0 |

## Confidence distribution

| Confidence | Count | Notes |
| --- | --- | --- |
| 0.55 | 2 | `src-001` ping_google.sitemap_url, `src-002` ping_google.ping_url (candidate) |
| 0.60 | 2 | `src-005` ManagementUtility.__init__.argv, `src-007` execute_from_command_line.argv (candidate) |
| 0.75 | 7 | i18n/auth redirect-response rows, contenttypes shortcut, utils/log REMOTE_ADDR, smtplib.SMTP sink (fp) |
| 0.80 | 59 | boundary params, host/URL-construction reads, redirect-response flows |
| 0.85 | 153 | standard verified request-field reads |
| 0.90 | 15 | operator-environment reads + urlopen/urlretrieve sinks |

Low-confidence (< 0.7, human review required): 4 entries — all `candidate`, listed below.

## Batch summary

| Batch | Description | Candidates | Roles |
| --- | --- | --- | --- |
| B1 | sinks.csv (outbound network call sites) | 3 | sink ×3 |
| B2 | sitemaps ping_google / _get_sitemap_full_url params | 3 | source ×2, summary ×1 |
| B3 | CLI / env / management boundary | 17 | source ×2, summary ×2, none ×13 |
| B4 | WSGI/ASGI request-boundary constructors, core handlers | 12 | none ×12 |
| B5 | middleware request-field reads | 50 | none ×50 |
| B6 | admin cluster (staff-gated views) | 80 | none ×80 |
| B7 | generic class-based views and view decorators | 18 | none ×18 |
| B8 | remaining views and URL-construction utilities | 55 | none ×55 |

## Non-`none` entries (the complete effective label set)

| ID | Role | Cls | Conf | API | Location |
| --- | --- | --- | --- | --- | --- |
| src-001 | source | candidate | 0.55 | `ping_google.sitemap_url` (param 0) | django/contrib/sitemaps/__init__.py:18 |
| src-002 | source | candidate | 0.55 | `ping_google.ping_url` (param 1) | django/contrib/sitemaps/__init__.py:18 |
| src-003 | summary | tp | 0.80 | `_get_sitemap_full_url.sitemap_url` (param 0) | django/contrib/sitemaps/__init__.py:30 |
| src-005 | source | candidate | 0.60 | `ManagementUtility.__init__.argv` (param 1) | django/core/management/__init__.py:175 |
| src-007 | source | candidate | 0.60 | `execute_from_command_line.argv` (param 0) | django/core/management/__init__.py:398 |
| src-209 | summary | tp | 0.75 | `TemplateCommand.handle_template` (param 1) | django/core/management/templates.py:185 |
| src-210 | summary | tp | 0.80 | `TemplateCommand.download` (param 1) | django/core/management/templates.py:244 |
| snk-001 | sink | tp | 0.90 | `urllib.request.urlopen` (argument 0) | django/contrib/sitemaps/__init__.py:27 |
| snk-002 | sink | fp | 0.75 | `smtplib.SMTP` (argument 0) | django/core/mail/backends/smtp.py:62 |
| snk-003 | sink | tp | 0.90 | `urllib.request.urlretrieve` (argument 0) | django/core/management/templates.py:265 |

## Top modules by candidate count

django.contrib.admin.options (58), django.middleware.csrf (18), django.middleware.common (13), django.utils.cache (12), django.contrib.auth.views (10), django.contrib.auth.admin (9), django.views.debug (9), django.views.i18n (7), django.views.generic.base (6), django.contrib.admin.views.main (6), django.contrib.admin.sites (5), django.contrib.sitemaps.__init__ (4).

## Human-review queue (classification = candidate)

1. `src-001` / `src-002` — ping_google params: they compose the outbound urlopen URL, but no in-tree caller supplies attacker data (management command passes only `sitemap_url`; `ping_url` defaults to the fixed PING_URL constant). Library-API surface only.
2. `src-005` / `src-007` — CLI argv boundary: genuine root of both fetch flows (argv → run_from_argv → parse_args → command options → ping_google / handle_template), but management commands are run by the local operator, and the chain crosses argparse machinery.
