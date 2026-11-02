# Phase 1 Review — django / Pass 3 (CWE-918 SSRF), Step 3 LLM Labeling

Checkpoint summary per Augur WORKFLOW.md §4.5 (advisory human review gate). Phase 2 must not start before this review is approved.

## 1. Scope and method

- Target: Django 3.1.12 alpha framework source (CodeQL DB `django_vuln`); framework-only codebase — no application views/settings exist in the database.
- Pass 3 (CWE-918 / 099 / 610, primary CWE-918). Labels assert API roles for this pass only; they are not vulnerability claims.
- 238/238 candidates labeled (235 sources.csv rows + 3 sinks.csv rows), 1:1 row parity, 8 batches, model glm-5.3 in-session (see `labels_raw_pass3.json`).
- Every non-trivial decision was verified against the real source and call context: the two HTTP fetch sites, the SMTP backend, the argv→options dispatch chain, the WSGI/ASGI boundary constructors, and the per-line downstream use of every extracted `request.*` read (admin cluster, middleware, views).
- Ground-truth artifacts in the source root (SSRF audit reports, ssrf_sinks CSV/JSON) were NOT read.

## 2. Label counts by role (pass 3)

source 4 · sink 3 · sanitizer 0 · summary 3 · none 228 (fp 229 / tp 5 / candidate 4 overall).

## 3. Top sink APIs

1. **`urllib.request.urlopen` — django/contrib/sitemaps/__init__.py:27, argument 0 (sink/tp, 0.90)** — `urlopen('%s?%s' % (ping_url, params))` in `ping_google()`. URL at positional arg 0 verified. In-tree reachability: CLI-only (the `ping_google` management command). Host/scheme/path come from `ping_url`, whose in-tree value is the fixed constant `PING_URL` (`https://www.google.com/webmasters/tools/ping`); `sitemap_url` contributes only the urlencode'd query value. No scheme/host validation at the site; default opener follows redirects.
2. **`urllib.request.urlretrieve` — django/core/management/templates.py:265, argument 0 (sink/tp, 0.90)** — `TemplateCommand.download(url)`; `url` traces to the `--template` CLI option of `startproject`/`startapp`. `is_url()` restricts the scheme to http/https/ftp (blocks `file:`/`data:` at this call) but puts no restriction on host/private addresses/redirects.
3. **`smtplib.SMTP` — django/core/mail/backends/smtp.py:62, argument 0 (sink/fp, 0.75)** — real outbound network connection, but non-HTTP and host/port come from `EmailBackend` args or `settings.EMAIL_HOST/EMAIL_PORT`; no web boundary reaches it (request data reaching the mail backend — BrokenLinkEmails, AdminEmailHandler — appears in mail content only). Not a CWE-918 sink in this codebase.

## 4. Source APIs and summaries

- `ping_google.sitemap_url` / `ping_google.ping_url` (source/candidate, 0.55): public library-API params that compose the fetched URL (query value / host-forming prefix respectively). No in-tree attacker-controlled flow (see §6).
- `ManagementUtility.__init__.argv` / `execute_from_command_line.argv` (source/candidate, 0.60): genuine CLI boundary and root of both fetch flows — `execute()` → `fetch_command().run_from_argv(self.argv)` (management/__init__.py:395) → `parser.parse_args(argv[2:])` → `Command.execute(**vars(options))` (base.py:313-330). Operator-local trust boundary; propagation crosses argparse machinery.
- Summaries (taint-transfer steps): `_get_sitemap_full_url` (param → returned URL string, sitemaps/__init__.py:30-51), `TemplateCommand.handle_template` (param → `download()` argument, templates.py:185-209), `TemplateCommand.download` (param 1 → `urlretrieve` argument 0, templates.py:244-265).

## 5. Sanitizer list

None labeled — no sanitizer candidates were extracted, and none were invented. Sanitizer-shaped code reviewed and documented as advisory only:

- `TemplateCommand.is_url()` scheme allowlist http/https/ftp (templates.py:33, 325-330): blocks `file:`/`data:` at the urlretrieve site but does not restrict hosts — not a sufficient SSRF barrier (and `handle_template` strips a `file://` prefix *before* the check, line 194-195, routing it to a local-path branch instead).
- `HttpRequest.get_host()` ALLOWED_HOSTS validation (http/request.py:119-137): validates the Host header for request parsing and response URL construction — it does not validate outbound fetch destinations.
- `url_has_allowed_host_and_scheme` checks (views/i18n.py:37-50, auth/views.py:75-80/143-147): open-redirect (Pass 9) response validation, unrelated to server-side fetches.
- Login/authentication, CSRF checks, staff gating, format validation (e.g. `check_for_language`, `to_field_allowed`, strptime date parsing) were per the rubric NOT treated as SSRF sanitizers.

## 6. Reachability conclusion (per rubric)

**No attacker-controlled SSRF path exists in this framework-only codebase.** Verified per read site across all 235 source candidates:

- Both server-side HTTP fetches are management-CLI-originated, executed by the local operator: `ping_google` (fixed ping host in-tree, CLI `sitemap_url` reaches only the query string) and `startproject/startapp --template` (operator-chosen URL, scheme-restricted).
- No `request.*` field, no WSGI `environ` / ASGI `scope` value, and no environment variable read can influence any outbound request URL. Request-derived values terminate in: ORM queries/writes, form validation, template/JSON response bodies, response headers/cookies, cache keys (md5-digested), logging/signals, local disk serving (staticfiles — Pass 1 territory), and redirect *responses* (Pass 9 territory: set_language and Login/Logout flows are `url_has_allowed_host_and_scheme`-validated; `contrib/contenttypes` shortcut builds an unvalidated absolute redirect URL but from server-derived scheme + Site domain, not from request input).
- The only request-data network egress (BrokenLinkEmailsMiddleware, AdminEmailHandler → SMTP) puts request values in mail content; the connection destination stays settings-controlled.
- `file:`/`data:` handling: `handle_template` strips `file://` to a local path (local-file concern, not CWE-918); `is_url()` excludes both schemes at the urlretrieve call. Recorded separately, not mixed into pass 3.

## 7. Unresolved / low-confidence items (human review required)

| ID | Entry | Question for the reviewer |
| --- | --- | --- |
| src-001 | `ping_google.sitemap_url` (source/candidate, 0.55) | Keep as pass-3 source for out-of-tree callers (query-string position only), or downgrade to none? |
| src-002 | `ping_google.ping_url` (source/candidate, 0.55) | Host-controlling library-API param with no in-tree caller — keep as source for Phase 2 recall? |
| src-005 | `ManagementUtility.__init__.argv` (source/candidate, 0.60) | Is the CLI operator boundary an acceptable source, given management commands are locally executed? |
| src-007 | `execute_from_command_line.argv` (source/candidate, 0.60) | Same question; thin wrapper of src-005. |

## 8. Quality checks performed

- `labels.json` validated against `assets/labels_schema.json` with `jsonschema` (draft 2020-12) → **SCHEMA VALID** (pass-1 placeholder block included per the schema's `contains: pass_id 1` constraint; pass 3 carries all 238 entries).
- Every CSV row covered 1:1; 4 exact duplicate CSV rows kept for parity with identical labels (documented in `labels_raw_pass3.json`).
- Argument indices verified in range and semantically accurate for the 3 sinks (all argument 0 = URL/host position; CSV argIndex −1 normalized to null per schema).
- Pass 3 has ≥ 1 sink (two tp HTTP fetch sinks) — the schema quality bar is met even though zero web-reachable sources exist (documented above).

## 9. Recommendation

Proceed to Phase 2 only after human review of the four `candidate` entries and of the §6 negative conclusion. Expected Phase 2 outcome for pass 3 on this database: the argv→options→ping_google/handle_template→urlopen/urlretrieve flows are the only potential paths, and both depend on operator-supplied CLI input; the smtplib sink (fp) is expected to yield no source-to-sink path.
