# Phase 1 Review - Pass 3 (SSRF) labels for matrix-sydent

**Status:** Step 3 complete; awaiting human review gate (checkpoint, advisory). Phase 2 not started.

## Scope and method

- Project: matrix-sydent (Matrix Identity Server, vulnerable snapshot). Language: Python; framework: twisted.web (confidence 0.95, detection.json).
- Pass 3 only: CWE-918 (primary), CWE-099, CWE-610. All 139 CSV candidates labeled in 7 batches by glm-5.3 at temperature 0 (see labels/labels_raw_pass3.json for the full per-batch record).
- Every judgment was made by reading the current source under `dataset/codeql_databases/ssrf_dbs/sydent_vuln/sydent/`; no ground truth, CVE text, fix commits, or the pre-existing SSRF reports in the source root were consulted.
- No project source, CodeQL DB, extraction CSV or Augur file was modified; outputs are limited to iris/labels/.

## What is actually attacker-reachable (verified against routes)

The client API (ClientApiHttpServer, default bind `::` port 8090, httpserver.py:134-140) exposes the servlets publicly. Three request fields demonstrably control the host of a server-side request:

1. **`matrix_server_name` on unauthenticated `POST /_matrix/identity/v2/account/register`** (registerservlet.py:42-66). No authV2 call in RegisterServlet. Value is lowercased, passed through `is_valid_hostname` and interpolated into `matrix://%s/...` for `FederationHttpClient.get_json`. The MatrixFederationAgent then routes it: IP-literal/explicit-port short-circuits, `https://%s/.well-known/matrix/server` fetch (RedirectAgent follows 3xx), SRV `_matrix._tcp.<host>`, else host:8448. Attacker chooses host (and may include a port); scheme and path are fixed by the format string.
2. **`mxid` server part on `/3pid/bind`** (threepidbindservlet.py:79 -> bind.py:134-162). The v1 route is mounted by default (`enable_v1_associations` default `'true'`, sydent.py:108) with no authentication and no mxid ownership restriction (the account.userId==mxid check exists only in the authed v2 path); the only gate before `_notify` is a validated email/msisdn session (sid+client_secret), which the same attacker obtains by completing a validation flow. `is_valid_hostname` is again form-only.
3. **X-Matrix `Authorization` header origin on `/3pid/unbind`** (verifier.py:194-211). The header is parsed, origin is hostname-form-checked, and `_getKeysForServer` fetches `matrix://<origin>/_matrix/key/v2/server/` BEFORE the signature is verified - the unauthenticated caller selects the key-fetch target. (Internal-bind variant of chain 2 exists at the same sink but sits behind the internal API's default `::1` bind - labeled candidate.)

## What is NOT attacker-reachable (labeled fp / none)

- **SMTP host** (emailutils.py:96/98/101): `email.smtphost` is operator config; attacker email only becomes the mailTo recipient.
- **OpenMarket SMS URL** (openmarket.py:101): fixed module constant; attacker controls only body/destination.
- **Replication push URL** (peer.py:200, httpsclient.py:70): `replication_url` from `peer.<name>.base_replication_url` config or the operator-managed peers table; no runtime code inserts peers (grep confirms no INSERT INTO peers).
- **Sentry DSN** (sydent.py:210): admin config, keyword argument (CSV argIndex -1 corrected per schema).
- **os.environ reads** (sydent.py:81/84/112/508): deployment configuration; no flow to any request target.
- **`brand`, X-Forwarded-For, bearer access tokens**: genuinely untrusted request data, but they reach template selection / rate limiting / account lookup only - kept as role source with classification fp where they appear in the CSVs.

## Boundary caveats flagged for review

- `AuthenticatedBind/UnbindThreePidServlet` (internal API): default bind `::1` and an explicit out-of-band auth assumption; the mxid chain there is real but reachability depends on operator configuration - labeled candidate, human confirm.
- `ReplicationPushServlet`: mutual-TLS CN matched against the peers table before the body is read; sgAssocs are per-item signature-verified. Labeled candidate.
- `_getKeysForServer.server_name` and `authenticate_request.request` params: internal relay parameters (summary entries) - per the boundary rules they are not standalone vulnerability sources; the true origins are the X-Matrix header read and the unbind handler boundary.

## Sanitizer assessment

No sanitizer labels were emitted. `is_valid_hostname` is the only guard standing between request fields and the matrix:// URL host positions, and it checks hostname syntax and port range only - it accepts `127.0.0.1`, `localhost`, RFC1918 literals and arbitrary ports, so it does not block the SSRF paths above. Authentication controls (authV2, X-Matrix signatures, TLS CN) gate callers, not targets - and in the verifier chain the fetch happens before signature verification. The `file:///` checks on `next_link` are open-redirect guards (Pass 9) and do not apply to any server-side fetch.

## Schema validation

labels.json validates against assets/labels_schema.json (jsonschema 4.26.0) except for the `passes` array's `contains: {pass_id: 1}` keyword, which is a template artifact requiring a Pass 1 block; this run is Pass 3 only by instruction, so that keyword cannot be satisfied (same deviation as the earlier single-pass SSRF runs). All other constraints - required fields, role/classification/flow_kind enums, `argument` implies arg_index >= 0, confidence in [0,1], pass_id range - pass.

## Label summary

See labels/label_stats.md. Headline: 139 entries - source 112, sink 16, summary 2, none 9 (sanitizer 0); classification tp 102, fp 18, candidate 19; 19 entries flagged candidate/unknown for human review.

## Human-review queue

src-8, src-9, src-10, src-11, src-12, src-13, src-14, src-15, src-16, src-17, src-85, src-86, src-87, src-118, src-119, src-120, src-121, src-122, sink-16

## Recommended Phase 2 notes (not executed)

- MySources: get_args/request.content.read/request.args field reads plus the render_POST/render_GET request params of public servlets; MySinks: twisted Agent.request URI (arg 1) sites, HostnameEndpoint host (arg 1), the three matrix:// wrapper call sites; MySanitizers: keep `none()` (no proven sanitizer); MySummaries: verifier relay params (verifier.py:63/:142), plus engine-level edges for `mxid.split(':')[1] -> 'matrix://%s' %` and `'matrix://%s' % server_name` that Phase 2 must model.
- Filtering: expect fp pressure from the internal-bind candidate chain and from SMTP/config sinks; the three tp chains above are the likely true positives.
