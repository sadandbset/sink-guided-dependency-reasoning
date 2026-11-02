# Augur Phase 2 Step 4 — Query Generation Notes (django, Pass 3: CWE-918 SSRF)

- Run: `django-iris-pass3-step3-20261020` (Phase 1 labels, unchanged)
- Generated: 2026-10-20. Files generated only — **no CodeQL analysis has been executed yet** (per instruction), so none of the files below is compile-verified at this point; compile/run is the first action of Step 5.
- Inputs used: `labels/labels.json` (238 pass-3 entries; role source 4 / sink 3 / sanitizer 0 / summary 3 / none 228), `labels/labels_raw_pass3.json`, `labels/phase1_review.md`, and the Phase 1 source verification of the django 3.1.12a tree. Ground-truth artifacts (PyVul truth, fix commits, CVE descriptions, SSRF audit reports/ssrf_sinks files) were NOT read.

## 1. Generated files

| File | Purpose |
| --- | --- |
| `libraries/MySources.qll` | `MySources::isSource(DataFlow::Node, string)` — pass key `"ssrf"` |
| `libraries/MySinks.qll` | `MySinks::isSink(DataFlow::Node, string)` — pass key `"ssrf"` |
| `libraries/MySanitizers.qll` | `MySanitizers::isBarrier(DataFlow::Node, string)` — empty (`none()`), mandatory hook |
| `libraries/MySummaries.qll` | `MySummaries::isAdditionalTaintStep(DataFlow::Node, DataFlow::Node, string)` — pass key `"ssrf"` |
| `queries/Pass3_SSRF.ql` | `@kind path-problem` taint query, id `py/augur/django/pass3-ssrf`, `@problem.severity error`, tags `security` + `external/cwe/cwe-918` (+ cwe-099/610) |
| `diagnostics/Pass3_SSRF_model_bindings.ql` | **Diagnostic only** (kind problem / warning / no CWE tag, id `py/augur/django/pass3-ssrf-diag`): reports the AST bindings of every model predicate. Its output is not a CWE-918 alert and must not be consumed by Step 6. |

Query structure (per WORKFLOW §5.2 and `assets/taint_query.ql.tmpl`, all placeholders substituted): `module Pass3Config implements DataFlow::ConfigSig` delegating to the four libraries with pass key `"ssrf"`; `module Pass3Flow = TaintTracking::Global<Pass3Config>;` `import Pass3Flow::PathGraph;` `from Pass3Flow::PathNode source, Pass3Flow::PathNode sink where Pass3Flow::flowPath(source, sink)`. No `command_injection` strings anywhere; `module` is never used as a variable name; no QL classes are defined (predicates only); no `API::Node`/`DataFlow::Node` mixing (models use the verified AST→Node bridges `DataFlow::parameterNode(Parameter)` and `DataFlow::exprNode(Expr)`, confirmed public in `semmle/python/dataflow/new/internal/DataFlowPublic.qll:336-350` of python-all and used the same way by python-all's own framework models, e.g. `frameworks/Websockets.qll:69`).

## 2. Label ID → QLL predicate mapping

| Label | Role / cls / conf | Signature (labels.json) | QLL realization |
| --- | --- | --- | --- |
| src-001 | source / candidate / 0.55 | `ping_google.sitemap_url`, param, arg_index 0, sitemaps/__init__.py:18 | `MySources` 1st disjunct: `DataFlow::parameterNode(pingGoogleFunction().getArg(0))` |
| src-002 | source / candidate / 0.55 | `ping_google.ping_url`, param, arg_index 1, sitemaps/__init__.py:18 | `MySources` 2nd disjunct: `getArg(1)` |
| src-005 | source / candidate / 0.60 | `ManagementUtility.__init__.argv`, param, arg_index 1, management/__init__.py:175 | `MySources` 3rd disjunct: `getArg(1)` + param-name guard `"argv"` |
| src-007 | source / candidate / 0.60 | `execute_from_command_line.argv`, param, arg_index 0, management/__init__.py:398 | `MySources` 4th disjunct: `getArg(0)` + param-name guard `"argv"` |
| src-003 | summary / tp / 0.80 | `_get_sitemap_full_url.sitemap_url`, param 0, sitemaps/__init__.py:30 | `MySummaries` 1st edge: param → value of any `_get_sitemap_full_url(...)` call |
| src-209 | summary / tp / 0.75 | `TemplateCommand.handle_template`, param 1, templates.py:185 | `MySummaries` 2nd edge: param 1 → arg 0 of `self.download(template)` (templates.py:202) |
| src-210 | summary / tp / 0.80 | `TemplateCommand.download`, param 1, templates.py:244 | `MySummaries` 3rd edge: param 1 → arg 0 of `urlretrieve` (templates.py:265) |
| snk-001 | sink / tp / 0.90 | `urllib.request.urlopen`, argument, arg_index 0, sitemaps/__init__.py:27 | `MySinks` 1st disjunct: `DataFlow::exprNode(urlopenCall().getArg(0))` |
| snk-003 | sink / tp / 0.90 | `urllib.request.urlretrieve`, argument, arg_index 0, templates.py:265 | `MySinks` 2nd disjunct |
| snk-002 | sink / **fp** / 0.75 | `smtplib.SMTP`, argument, arg_index 0, smtp.py:62 | `MySinks` 3rd disjunct (see §4) |
| (all 228 role=none rows) | none / fp | request.* fields, environ/scope, env reads | **Intentionally not modeled** — Phase 1 verified per site that none reaches an outbound request URL |

## 3. Source trust boundaries and propagation basis

- **No web-request sources exist.** All 208 `request.<field>`/`environ`/`scope` candidates were labeled role `none` (fp) in Phase 1 with per-line verification: their values terminate in ORM queries, form validation, template/JSON response bodies, response headers, redirect *responses*, md5 cache keys, logging, or local disk serving. Per the generation constraint ("Source 应对应已审核的不可信 Web 请求/URL 输入边界"), nothing was promoted into `MySources` beyond the four reviewed entries, and no internal wrapper parameter was auto-promoted (`_get_sitemap_full_url`, `handle_template`, `download` are modeled as *summary* steps, exactly as labeled).
- **src-001 `ping_google.sitemap_url` (control scope: query-string value only).** Public sitemaps API parameter; when a caller supplies it, it becomes the `urlencode`d `sitemap` query value of the outbound request to the fixed ping host (sitemaps/__init__.py:25-27). It does not control scheme/host/port.
- **src-002 `ping_google.ping_url` (control scope: full URL host-forming prefix).** The `'%s?%s' % (ping_url, params)` string passed to `urlopen` takes `ping_url` as its prefix, so a caller-supplied value controls scheme/host/port/path. No in-tree caller passes it (default is the fixed `PING_URL` constant, sitemaps/__init__.py:11).
- **src-005/src-007 `argv` (control scope: CLI root boundary, operator-local).** `ManagementUtility.__init__` stores `argv or sys.argv[:]`; it is the root of both fetch flows: `execute()` → `fetch_command().run_from_argv(self.argv)` (management/__init__.py:395) → `parser.parse_args(argv[2:])` → `Command.execute(**vars(options))` (base.py:322-330) → `ping_google(options['sitemap_url'])` / `TemplateCommand.handle_template(options['template'])`. Trust level is deployment-dependent (management commands are run by the local operator); both entries remain classification `candidate`.

Control-scope severity ordering (recorded per the instruction, not merged): full-URL control (src-002) > host-part control (none in-tree) > query/path-only control (src-001) > CLI-operator boundary (src-005/src-007, expected FP-grade in most deployments).

## 4. Sinks: real network APIs, dangerous argument indices, call sites

| Sink | API / call site | Arg index | Notes |
| --- | --- | --- | --- |
| snk-001 | `urllib.request.urlopen('%s?%s' % (ping_url, params))` — django/contrib/sitemaps/__init__.py:27 (inside `ping_google`) | 0 (the requested URL) | Interprocedurally fed by `ping_google`'s params and `_get_sitemap_full_url`'s return. `from urllib.request import urlopen` — the call is matched by callee `Name` id `urlopen` pinned to the reviewed file, which is exact and avoids `Attribute`-style ambiguity. |
| snk-003 | `urlretrieve(url, os.path.join(tempdir, filename))` — django/core/management/templates.py:265 (inside `TemplateCommand.download`) | 0 (the downloaded URL) | Fed by `download(url)` ← `handle_template(options['template'])` (`--template` CLI option). |
| snk-002 | `self.connection_class(self.host, self.port, **connection_params)` — django/core/mail/backends/smtp.py:62 | 0 (SMTP host) | **Reviewed as fp.** The label signature is API-level `smtplib.SMTP` arg 0, but the in-tree construction is the dynamic dispatch through the `connection_class` property (returns `smtplib.SMTP`/`SMTP_SSL`, smtp.py:37-39), so the model pins the concrete reviewed call site (`Attribute` name `connection_class` in smtp.py). Host/port from `EmailBackend` args or `settings.EMAIL_HOST/EMAIL_PORT`. Any alert from this sink is expected to be filtered in Step 6 per the fp classification. |

All sink matching is pinned to the reviewed call-site files; unreviewed same-named calls elsewhere in the database (e.g. under `tests/`) cannot produce alerts.

## 5. URL scheme, fixed targets, redirects, private addresses, sanitizers

- **Scheme handling**: `TemplateCommand.is_url()` restricts the template URL scheme to `http/https/ftp` (templates.py:33, 325-330) — blocks `file:`/`data:` at the `urlretrieve` site (the `file://` prefix is stripped upstream at templates.py:194-195 and routed to a local-path branch — a Pass 1 concern, not modeled here). No scheme restriction exists at the `urlopen` site.
- **Fixed targets**: in-tree, the `urlopen` host is fixed to the `PING_URL` constant; `urlretrieve`'s target is operator-chosen. The SMTP destination is settings-controlled. None of these constitute sanitizers of the *source*; they are reachability facts recorded in the labels and in `phase1_review.md` §6.
- **Redirects**: `urlopen`/`urlretrieve` use the default opener, which follows redirects — no redirect control is implemented anywhere on the two HTTP paths (no custom `HTTPRedirectHandler`, no `allow_redirects` handling).
- **Private addresses / DNS resolution**: no private-IP blocking, post-DNS validation, or host allowlisting exists on any of the three sinks (verified in Phase 1; recorded in labels' sanitizer advisories).
- **Sanitizers modeled: none.** `MySanitizers::isBarrier` is the mandatory empty `none()` hook. The three sanitizer-shaped candidates (`is_url()` scheme allowlist, `ALLOWED_HOSTS` validation in `HttpRequest.get_host()` — which validates the *inbound* Host header, not outbound targets, and `url_has_allowed_host_and_scheme` — Pass 9 open-redirect validation) were reviewed in Phase 1 and deliberately not labeled as sanitizers; none of them blocks the modeled fetch paths, so none is modeled. No evidence-free sanitizer was invented.

## 6. Summary / additional flow steps — source-code basis

Each modeled edge is a concrete, Phase 1-verified transfer (also redundant with native `TaintTracking::Global` interprocedural steps — kept to materialize the reviewed labels and for robustness):

1. **src-003** `_get_sitemap_full_url(sitemap_url)` param 0 → value of any call to it: the function returns `'%s://%s%s' % (scheme, current_site.domain, sitemap_url)` (sitemaps/__init__.py:51), transferring its argument into the URL string that `ping_google` urlencodes into the outbound request (lines 25-26; sole in-tree call at line 25).
2. **src-209** `handle_template(self, template, subdir)` param 1 → arg 0 of `self.download(template)`: templates.py:200-202, after the `is_url()` branch, `template` is passed directly into `download`.
3. **src-210** `download(self, url)` param 1 → arg 0 of `urlretrieve`: templates.py:265 — `url` is passed directly as the URL argument (the local filename is also derived from it, lines 248-260).

No custom edge was created for URL *parsing* (`urlparse`/`urljoin`/`urlsplit`) — per the labels these are not sinks, and no reviewed flow requires them. No unconditional propagation exists anywhere in the model.

## 7. Coverage gaps, dynamic calls, and CodeQL analysis limitations

- **`labels/review_decision.json` is missing.** The Phase 1 checkpoint (advisory) required human review of 4 `candidate` entries; that outcome was never recorded as a file. The four candidate sources were carried into `MySources` **verbatim from the reviewed `labels.json`** (labels were not modified). **Re-review requested:** write `labels/review_decision.json` (approve/adjust the four candidate sources, especially whether the operator-local `argv` boundary and the library-API `ping_url`/`sitemap_url` params should remain formal pass-3 sources) before executing Step 5.
- **argv → command-option propagation is not covered by any model edge** (labeling gap, recorded not patched): the chain `argv → parse_args(argv[2:]) → Namespace → vars() → **cmd_options → handle(**options) → options['sitemap_url'] / options['template']` crosses argparse option-parsing machinery that CodeQL's default taint steps do not track, and no label summarizes it. Consequence: even with the argv sources, the CLI-rooted flows to the sinks will most likely **not** be connected by the formal query. If the reviewer wants that path, a new summary label (argparse `parse_args` return / options-dict value) must be added in Phase 1 — it was not added here because the labels contain no such entry.
- **Expected reachable formal path**: `ping_google.sitemap_url`/`ping_google.ping_url` params → (native call-arg/return steps + src-003 summary) → `urlencode`/`'%s?%s' %` → `urlopen` arg 0. Note the sole in-tree caller passes `sitemap_url` as a *keyword* argument (`ping_google(sitemap_url=...)`, management command), which is irrelevant for the param-node source but relevant if the argv gap above is ever closed. The `smtplib` sink has no reachable source (fp).
- **Dynamic dispatch**: the SMTP construction is `self.connection_class(...)` (property returning the class), so the API-level `smtplib.SMTP` signature cannot be matched directly at the call site; the model pins the concrete `connection_class` call (documented normalization of snk-002, no label change).
- **Name-based call matching**: `urlopen`/`urlretrieve`/`_get_sitemap_full_url` calls are matched by callee `Name` id + reviewed file (the imports are `from urllib.request import ...`, so no module-qualified attribute form exists in this tree). Method calls (`self.download`) are matched by `Attribute` name + file. Matching is pinned to reviewed locations, so tests and any hypothetical future call sites are out of scope by design.
- **Not modeled (out of label scope)**: all `request.*`-shaped web boundaries (labeled `none`), settings/environment reads (operator config), redirect-response URL construction (Pass 9 / CWE-601 flows such as `set_language`, auth views, and the unvalidated `contrib/contenttypes` shortcut redirect), local file reads (`staticfiles` disk serving, `shell` PYTHONSTARTUP — Pass 1 territory), and the `django/test/`+`tests/` trees (excluded from labels in Phase 1).
- **Toolchain note**: `iris/qlpack.yml` pins `codeql/python-all: 7.2.7`, while the local pack cache contains 7.1.1/7.1.2 (the version against which all APIs above were verified). `codeql pack install` during Step 5 must resolve 7.2.7 (download or cache); the APIs used (`DataFlow::ConfigSig`, `TaintTracking::Global`, `PathGraph`, `flowPath`, `DataFlow::parameterNode`/`exprNode`, AST `Call`/`Function`/`Parameter`/`Name`/`Attribute`) are stable across these minor versions, but the first Step 5 action should still be a `codeql query compile` of `queries/Pass3_SSRF.ql` to confirm.
- **Not yet verified by execution**: per instruction, no query was compiled or run in this step. The diagnostics query exists precisely to confirm model bindings (source/sink/summary endpoint nodes) before the formal run.

## 8. Reproducibility and independent-evaluation principles (same as the CWE-78 experiment)

- Every modeled signature is derived deterministically from `labels/labels.json` entries (id, role, classification, signature.callable/arg_index/flow_kind, location) plus Phase 1's recorded source evidence; nothing was added from ground truth, fix commits, or CVE knowledge, and no label was modified (gap: §7 records the two open items instead of patching the model).
- Mapping is auditable end-to-end: label id → QLL disjunct (table in §2); each disjunct cites its reviewed call-site file; the diagnostics query prints the actual bound AST nodes for independent verification.
- Re-generation is deterministic: re-render the four QLLs and the query from the same labels (the only free choices are the two param-name guards and file pinning, both documented above).
- Independent evaluation: run `queries/Pass3_SSRF.ql` (and optionally the diagnostics query) against `django-db` with the recorded toolchain; compare alerts against the Phase 1 conclusion that no attacker-controlled web path exists and that only CLI/library-API flows are conceivable.
- Forbidden inputs were not read: PyVul truth, vulnerability fix commits, CVE descriptions, and the source-root SSRF audit artifacts; the project source, the CodeQL database, and the Phase 1 labels were not modified.

## 9. Next step (not executed here)

Step 5: `codeql pack install` (resolve python-all 7.2.7) → `codeql query compile` the pass query → `codeql database analyze` `django-db` `iris/queries/Pass3_SSRF.ql --format=sarifv2.1.0 --output=iris/results/pass3.sarif`, sequential, single query at a time, logging runtimes to `iris/results/run_log.md`. The diagnostics query may be run first to confirm bindings; its output must not be counted as CWE-918 findings.
