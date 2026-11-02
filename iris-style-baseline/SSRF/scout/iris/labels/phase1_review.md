# Scout — Phase 1 Review (Human Review Gate, Step 3 Checkpoint)

**Run**: `scout-iris-pass3-step3-20261020` · **Pass**: 3 (CWE-918 / 099 / 610, SSRF) · **Date**: 2026-10-20
**Model**: glm-5.3 (Z.ai GLM), in-session via Claude Code CLI · **Candidates labeled**: 73/73 (29 sources + 44 sinks), 4 batches, 0 re-asks
**Artifacts**: `labels/labels.json` (schema-valid), `labels/labels_raw_pass3.json`, `labels/label_stats.md`

This is the advisory checkpoint of Augur Phase 1 (WORKFLOW.md §4.5). Interactive mode: **stop here and wait for explicit human approval before Phase 2.** No Phase 2 work (library/query generation or taint analysis) has been started.

---

## 1. Label counts by pass and role

| pass | entries | source | sink | sanitizer | summary | none |
| --- | --- | --- | --- | --- | --- | --- |
| 3 (SSRF) | 73 | 3 (2 tp, 1 candidate) | 21 (2 tp, 18 candidate, 1 unknown) | 0 | 0 | 49 (fp) |
| 1 (placeholder) | 0 | — | — | — | — | — |

Every enabled pass has at least one sink (pass 3: 21 sink entries). Pass 1 block exists only to satisfy the schema's `contains pass_id: 1` constraint and is empty by design.

## 2. Top high-risk sink APIs (highest expected value for Phase 2)

1. **`requests.request` — `scout/server/blueprints/alignviewers/views.py:42`** (sink/tp, 0.95). The `/remote/cors/<path:remote_url>` CORS proxy: the client-supplied URL is forwarded verbatim as the request target with `allow_redirects=True`; inbound headers (minus Host), body and cookies are forwarded too. Any authenticated user can reach it — no institute/case binding, no role requirement. Pairs with source `src-025` (route param, views.py:34). This is the strongest CWE-918 shape in the project.
2. **`requests.post` — `scout/server/blueprints/cases/controllers.py:94`** (sink/tp, 0.85). `coverage_report_contents` POSTs to `request.url_root + "reports/report"`; `request.url_root` derives from the incoming Host header, so the outbound host is attacker-steerable by an authenticated user with case access when the chanjo integration (`SQLALCHEMY_DATABASE_URI`) is enabled. Pairs with source `src-020` (cases/views.py:225).
3. **`requests.post` — `cases/controllers.py:548` / `:554`** (sink/candidate, 0.60). `mt_coverage_stats` POSTs to `url_for("report.json_chrom_coverage", _external=True)`. With `SERVER_NAME` unset (scout's default config) the external-URL host also derives from the request Host header; setting `SERVER_NAME` pins it. Pairs with source candidate `src-004`.

## 3. Top broad source APIs

- `remote_cors.remote_url` (Flask `<path:remote_url>` route param, alignviewers/views.py:34) — full arbitrary URL, index 0.
- `request.url_root` (flask.request field, cases/views.py:225) — Host-header-derived absolute base URL.
- `flask.url_for` `_external=True` return (cases/controllers.py:544) — Host/SERVER_NAME-derived absolute URL (candidate).

Deliberately **not** treated as sources: all `Beacon.beacon_url` / `MatchMaker.host` / `loqus_settings.get_api_url` admin-config provenance reads (16 rows, none/fp), the `matchmaker_match.target` route variable (constrained to server-listed node ids), `request.form` body-only reads, and the remote_cors header/body/cookie forwarding (impact amplifiers, not destination control).

## 4. Sanitizer list

**Empty.** No scheme allowlist, host whitelist, redirect control, DNS/private-IP check exists on any audited outbound path. `url.startswith("ftp")` in `fetch_resource` is a transport dispatch, not a barrier. Authentication (`before_request check_user`), `institute_and_case` case-ownership checks and the `beacon_submitter` role gate reachability, not the outbound target, so none counts as an SSRF sanitizer. Consequence for Phase 2: `MySanitizers.qll` will resolve to `none()`; queries must keep the mandatory empty `isBarrier` hook.

## 5. Unresolved / low-confidence items (human review requested)

| ids | concern |
| --- | --- |
| snk-007 (`query_phenomizer.query`, controllers.py:837) | Network I/O happens inside the external query-phenomizer package, absent from this CodeQL DB; URL construction/argument positions unverifiable. Kept sink/unknown (0.50). Reviewer should check the installed package's `query()` implementation. |
| src-004 / snk-005 / snk-006 | Host-header vs `SERVER_NAME` derivation of `url_for(_external=True)` depends on deployment config. If production sets `SERVER_NAME`, this flow is pinned and should be dropped to fp. |
| snk-010 / 011 / 013 | MatchMaker host-pinned URLs with server-issued patient/node ids in the path (second-order, no scheme/host/port control). Retained as low-confidence candidates; expected fp at contextual triage. |
| snk-025–032, snk-033 | Final I/O sites of the shared `scout_requests` wrappers and the ftp `urlopen`. All audited callers pass admin-config/constant URLs; kept as recall candidates in case an unmodeled caller exists. |

## 6. Reviewer focus questions (from the task brief)

1. **Untrusted-boundary check**: all three labeled sources sit behind the global login hook (app.py:83–98); `remote_cors` has *no further* authorization (any authenticated user), while `pdf_case_report`/MT-report routes additionally require `institute_and_case` access. No route is reachable unauthenticated unless `LOGIN_DISABLED` is set.
2. **URL influence**: confirmed for `remote_url` (full URL) and `request.url_root`/`url_for(_external=True)` (Host header → outbound host). Form/JSON parameters influence only request bodies on fixed admin-configured hosts (Beacon, Rerunner, MatchMaker).
3. **Wrapper propagation**: all outbound I/O funnels through direct `requests.*`/`urlopen` calls or the `scout_requests` wrappers; wrapper callers were exhaustively audited (beacon, matchmaker, loqus, panel, constant-URL fetchers) — none receives web-derived URLs.
4. **Sink argument positions**: `requests.*` arg 0; `requests.request` url keyword → arg 1; wrapper `url=` keyword → arg 0; `query_phenomizer.query` unresolvable (unknown). `urljoin`/`urlparse` never appear as network sinks (parse/quote-only usage, per detection.json).
5. **Sanitizers**: none exist (see §4).
6. **Fixed vs attacker-steerable destinations**: admin-config hosts (BEACON_URL, MME_URL, LOQUSDB_SETTINGS, RERUNNER_API_ENTRYPOINT, rank-model prefixes) and hard-constant hosts (Ensembl, PanelApp, OMIM, HGNC, ExAC, eutils) are distinguished from attacker-steerable targets throughout the rationales.
7. **file:/data:**: no such outbound fetch exists in scout/; the only cross-protocol fetch is the ftp branch of `fetch_resource` (constant ftp URLs). The `remote_static` local-file endpoint is a path-traversal concern, deliberately kept out of CWE-918 labels.
8. **Internal wrapper formals vs real sources**: the MatchMaker/Beacon/Loqus internal provenance reads and the `matchmaker_match.target` constrained parameter were examined and rejected as formal sources; only genuine request-boundary values were labeled.

## 7. Decision

- [ ] **Approved — proceed to Phase 2** (Step 4 library generation from the 3 source + 21 sink entries)
- [ ] **Changes requested** (specify entries/ids)
- [ ] **Rejected**

Reviewer: ______________________ Date: ____________
