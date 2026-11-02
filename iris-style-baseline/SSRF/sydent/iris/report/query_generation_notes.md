# Query Generation Notes - Pass 3 (CWE-918 SSRF), matrix-sydent

Augur Phase 2, Step 4-5 (library + query generation). Generated: 2026-10-20.
Run: `sydent-ssrf-pass3-20261020`; labels: `iris/labels/labels.json` (139 entries, pass_id 3,
pass key `ssrf`); model that produced the labels: glm-5.3.

**Artifacts generated**

| file | content |
| --- | --- |
| `libraries/MySources.qll` | 8 source predicates (93 tp source labels) |
| `libraries/MySinks.qll` | 4 sink predicates (9 tp sink labels) |
| `libraries/MySanitizers.qll` | `isBarrier` = `none()` (0 sanitizer labels) |
| `libraries/MySummaries.qll` | 2 file-scoped, code-backed additional taint steps |
| `queries/Pass3_SSRF.ql` | `TaintTracking::Global` path query, id `py/augur/sydent/pass3-ssrf` |

**Validation performed**: `codeql query compile queries/Pass3_SSRF.ql` against
codeql CLI 2.25.1 + `codeql/python-all` 7.1.2 (the pack pinned by `iris/qlpack.yml`,
name `iris/sydent-cwe918`) - **compiles clean**. No database was touched and **no
taint analysis was executed** (per instruction, Phase 2 execution is deferred).

**Review-gate note**: `labels/review_decision.json` does not exist - the Phase 1
checkpoint was advisory (automated mode) and no approval record was written. The
models below are therefore derived exclusively from `classification = "tp"` entries
of `labels/labels.json` (the reviewed-and-confirmed subset); all `candidate`/`unknown`
entries remain unmodeled pending human review (section 7). No label was modified.

---

## 1. Label ID -> QLL predicate mapping

Selection policy: a label entry is modeled iff `role` matches the library and
`classification = "tp"`. Every other entry is excluded with its reason recorded here
(no label was edited, dropped silently, or re-classified).

### MySources (93 of 122 source rows)

| predicate | label IDs (count) |
| --- | --- |
| `getArgsCallResultSource` | src-6, 19, 24, 27, 34, 37, 43, 49, 53, 58, 64, 67, 76, 79, 82, 89, 103, 106 (18) |
| `requestContentReadSource` | src-2, src-111 (2) |
| `requestArgsAttrSource` | src-3 (1) |
| `requestHeaderSource` | src-5 (1) |
| `xMatrixAuthHeaderSource` | src-123 (1) |
| `requestFieldSubscriptSource` | src-20..22, 25, 28..32, 35, 38..40, 44, 45, 50, 51, 54..56, 59..62, 65, 68..70, 77, 80, 83, 84, 90..93, 104, 107..109, 112..115 (44) |
| `argsGetCallSource` | src-7 (1) |
| `handlerRequestParamSource` | src-4, 18, 23, 26, 33, 36, 42, 46, 47, 48, 52, 57, 63, 66, 74, 75, 78, 81, 88, 101, 102, 105, 110, 116, 117 (25) |

Excluded source rows: **18 candidate** (src-8..17 internal-API servlet boundary,
src-85/86/87 replication-push boundary, src-118..122 verifier internal relays - the
last five are the summary/candidate relay labels, see section 5) and **11 fp**
(src-41 smtphost config, src-71/72/73 peer DB/config, src-94/95/96/100
os.environ, src-97 X-Forwarded-For, src-98/99 brand).

### MySinks (9 of 17 sink rows)

| predicate | label IDs (count) | call sites |
| --- | --- | --- |
| `agentRequestSink` (arg 1) | sink-6, 7, 10, 11 (4) | httpclient.py:52, httpclient.py:91, matrixfederationagent.py:176, matrixfederationagent.py:322 |
| `hostnameEndpointSink` (arg 1) | sink-9, 12 (2) | matrixfederationagent.py:168 (LoggingHostnameEndpoint), :366 (HostnameEndpoint) |
| `federationGetJsonSink` (arg 0) | sink-15, 18 (2) | registerservlet.py:59, verifier.py:80 |
| `bindCallbackPostSink` (arg 0) | sink-2 (1) | bind.py:162 (post_json_get_nothing) |

Excluded sink rows: **7 fp/none** (sink-3/4/5 smtplib hosts from `email.smtphost`
config, sink-8 httpsclient.py:70 replication URL from config/peers table, sink-13
openmarket.py:101 fixed constant `API_BASE_URL`, sink-14 peer.py:200 replication
config/DB target, sink-17 sentry_sdk.init admin DSN) and **1 candidate** (sink-16
srvresolver.py:125 DNS SRV `lookupService` - DNS-only egress, fixed record type,
not an HTTP URL sink; stays in the human-review queue).

### MySanitizers / MySummaries

Zero sanitizer labels -> `isBarrier` resolves to `none()`. Two summary labels
(src-118, src-122): realization in section 5.

---

## 2. Sources: trust boundaries and propagation basis

The client API (`ClientApiHttpServer`, default bind `::` port 8090,
httpserver.py:134-140) exposes every modeled servlet publicly; v2 `authV2` gates
*callers*, not field values (rubric: authentication is not a sanitizer). All
source signatures were verified in source before modeling:

- **get_args() results** (`sydent/http/servlets/__init__.py:41-123`): the function
  materializes `json.loads(request.content.read())` (POST/PUT JSON) or
  `request.args` (v1/GET fallback) and returns the dict consumed by every servlet;
  18 tp call-site labels across the public servlets plus auth.py:45.
- **Field-level subscripts** `args['...']`/`body['...']` (44 labels): modeled
  directly rather than relying only on native container->subscript taint, because
  the upstream `json.loads(...)` call (external builtin) has no native
  arg->result flow - the labels correctly identified the materialized fields as
  the boundary. SSRF-relevant members: `args['matrix_server_name']` (src-83),
  `args['mxid']` (src-108), the unbind `body['...']` fields.
- **`request.content.read()`** (src-2 inside get_args, src-111 in the public
  unbind servlet's direct `json.loads`).
- **`request.args`** attribute read (src-3) - only the get_args copy; the
  sydent.py:374/375 brand reads are fp (local template selection, Pass 1 territory).
- **Bearer `Authorization` header** (src-5, auth.py:39) and
  **`args.get('access_token')`** (src-7, auth.py:46): untrusted but reach account
  lookup only - kept for label fidelity.
- **X-Matrix federation header** (src-123, verifier.py:194): the key source of the
  verifier chain - `authenticate_request` parses the *unauthenticated* header
  (verifier.py:199-203), the origin is only form-checked (is_valid_hostname,
  :208), and the key fetch runs before signature verification (:80 precedes :211).
- **render_GET/render_POST request parameters** (25 labels, position 1): the
  twisted handler boundary. Modeled as uses of the `request` parameter variable -
  best-effort and *not load-bearing* (object-level taint alone does not reach field
  reads; the materialized-read sources above carry all sink connectivity).

Deliberately NOT modeled as sources (per instruction): internal network-wrapper
parameters - `_getKeysForServer.server_name` (verifier.py:63) and
`authenticate_request.request` (verifier.py:142) are internal relay parameters, not
external boundaries; their taint arrives via standard interprocedural flow from
the X-Matrix header source. Likewise `RemotePeer.__init__` server_name/port
(fp-labeled: peers table + config, operator-managed, no runtime INSERT exists).

## 3. Sinks: real network APIs, argument indices, call sites

| sink | API | dangerous position | evidence of network I/O |
| --- | --- | --- | --- |
| twisted `Agent.request` | `self.agent.request(b"GET"/b"POST", uri.encode("utf8"), ...)` | arg index **1** (index 0 = method bytes) | final HTTP egress; httpclient.py:52-55/:91-96 bodies; matrixfederationagent.py:176 (Agent.usingEndpointFactory) / :322 (well-known RedirectAgent) |
| `HostnameEndpoint(reactor, host, port)` + `LoggingHostnameEndpoint` wrapper | arg index **1** (host; port = 2) | concrete TCP dial: matrixfederationagent.py:165-173 endpointForURI -> :366 `HostnameEndpoint(reactor, host, port)` |
| `FederationHttpClient.get_json(uri, ...)` wrapper | arg index **0** (full URL) | wrapper body: `self.agent.request(b"GET", uri.encode("utf8"))` (httpclient.py:52) via MatrixFederationAgent routing |
| `HTTPClient.post_json_get_nothing(uri, post_json, opts)` wrapper | arg index **0** (full URL) | wrapper body: `self.agent.request(b"POST", uri.encode("utf8"), ...)` (httpclient.py:91) |

Arg-index notes: CSV argIndex values for the Agent.request rows were already
correct (1); HostnameEndpoint/LoggingHostnameEndpoint rows use 1 (host position,
verified against the twisted signature); sentry_sdk.init's CSV `-1`/`argument`
mismatch was corrected to `null`/`unknown` during Phase 1 labeling (sink-17 is
excluded anyway). The two wrapper sinks are justified by reading the wrapper
bodies (URL argument -> agent.request), which is the only "URL passed to network
I/O" evidence used - no sink was modeled on pure URL *processing* APIs
(`urljoin`/`urlparse`/`quote`/`URI.fromBytes` are intermediates, never sinks, and
none appear as sinks in the labels).

## 4. Scheme / fixed targets / redirects / private addresses / sanitizers

- **Scheme**: fixed on all modeled chains - `matrix://` (register/bind/verifier
  key fetch, routed by MatrixFederationAgent) and `https://` (the .well-known
  fetch at matrixfederationagent.py:318). The attacker never controls the scheme.
- **Attacker control tier**: **host part** (+ optional explicit port, which
  `is_valid_hostname` accepts, and which `_route_matrix_uri` honors at
  matrixfederationagent.py:212-219; default port 8448). Path and query are fixed
  by the format strings. **No modeled position gives full-URL control.** The only
  query-shaped taint is `args['access_token']` (src-84) URL-encoded into the
  register URL's query string - it is *not* a sink position; an alert requires the
  host operand itself to be tainted, so query-only control does not fire these
  sinks. This tiering is kept explicit in the QLDoc of every sink predicate.
- **Fixed/admin targets** (excluded as fp): OpenMarket `API_BASE_URL` constant,
  SMTP `email.smtphost`, replication `base_replication_url`/peers table, sentry
  DSN. Distinct from attacker-chosen hosts per the labels.
- **Redirects**: the .well-known fetch uses `RedirectAgent`
  (matrixfederationagent.py:105-107), so server-side 3xx following exists on the
  delegated-name resolution path; response-driven target shift (SRV answers,
  .well-known `m.server`, 3xx Location) is **not** modeled as taint (no
  unconditional propagation; would require response-taint modeling absent from
  the labels).
- **Private addresses / DNS**: no private-IP blocking, localhost blocking, or
  post-resolution address validation exists anywhere on the modeled paths;
  `is_valid_hostname` (stringutils.py:39-70) accepts IP literals, `localhost`,
  RFC1918 ranges and explicit ports. `lookupService` (DNS SRV) is candidate and
  excluded (section 1).
- **Sanitizers**: none - `isBarrier` = `none()` (see MySanitizers.qll header for
  the full audit of is_valid_hostname / is_valid_client_secret / authV2 / X-Matrix
  signatures / TLS CN / `file:///` checks and why none is a CWE-918 sanitizer).

## 5. MySummaries: custom propagation edges and their source evidence

Native coverage (verified in the python-all 7.1.2 taint library) means most of the
chains need **no** custom edges: container->subscript reads, `str.split/lower/
encode`, `'...' % x` formatting, for-loop and tuple-unpacking reads, and
interprocedural parameter passing are all default taint steps.

The two summary-labeled entries:

- **src-122** (`authenticate_request.request` param): realized **natively** - the
  request object taints the parameter via standard call-argument flow
  (threepidunbindservlet.py:135). No custom edge added.
- **src-118** (`_getKeysForServer.server_name` param): the direct call
  `verifyServerSignedJson -> _getKeysForServer` (verifier.py:119) is native; two
  container boundaries on the feeding X-Matrix path needed repair, and got
  file-scoped, conditional, code-backed steps in `MySummaries.qll`:

| step | edge | source evidence |
| --- | --- | --- |
| `dictConstructorStep` | tainted arg of `dict(...)` -> dict result | verifier.py:178-179 `param_dict = dict(kv.split(u"=") for kv in params)` - X-Matrix header parameter parsing; the `dict` builtin has no native arg->result flow |
| `dictItemsIterationStep` | receiver of `.items()` -> `.items()` result | verifier.py:114 `for server_name, sigs in signed_json['signatures'].items():` - signature server names (the fetch targets) are dict keys stored from the X-Matrix origin at verifier.py:203; native for-loop/unpacking steps then carry taint to `server_name` |

Both steps are scoped to `sydent/hs_federation/verifier.py` only, fire only when
the `from` node is tainted, and are documented in the QLDoc with file:line
evidence. No other custom edges exist; no edge crosses an external library
boundary.

## 6. Expected connectivity and known under-reporting

Chains the query is expected to connect when run (host-control tier):

1. **register**: `get_args` result / `args['matrix_server_name']` (src-82/83) ->
   `.lower()` -> `"matrix://%s/..." % (matrix_server, quote(access_token))` ->
   `get_json` arg 0 (sink-15) and onward through the wrapper body to
   `agent.request` arg 1 (sink-6) and `agent.request` arg 1 (sink-10). All steps
   native (subscript, string method, Mod formatting, interprocedural).
2. **verifier**: `getRawHeaders('Authorization')` (src-123) -> for-loop read ->
   `parse_auth_header` split chain -> `dictConstructorStep` -> `param_dict
   ["origin"]` -> `strip_quotes` (native return flow) -> setdefault store
   (verifier.py:203) -> `verifyServerSignedJson` param -> subscript ->
   `dictItemsIterationStep` -> `server_name` -> `_getKeysForServer` ->
   `"matrix://%s/..." % server_name` -> `get_json` arg 0 (sink-18) and
   `agent.request` arg 1 (sink-6/10).

Known breaks (documented, deliberately unrepaired):

- **bind chain**: `args['mxid']` (src-108) -> `addBinding` -> `ThreepidAssociation`
  (plain class; native attribute-store) -> `signer.signedThreePidAssociation`
  (dict literal of attribute reads; native) -> **`signedjson.sign.sign_json`**
  (bind path: signer.py:33) - external library with no body in the database and no
  arg->result flow model, so taint stops; `_notify`'s `assoc["mxid"]` and thus
  sink-2 will likely not fire. No unconditional edge was added across this
  external boundary; remedy would be a signedjson flow summary (a modeling
  dependency, i.e. a label/tooling change - not silently patched here).
- **routing sub-chain**: `URI.fromBytes(uri)` (matrixfederationagent.py:141),
  `_RoutingResult` attribute reads and `pick_server_from_list` break taint
  between the request URL and `res.target_host`; sinks sink-9/12
  (HostnameEndpoint) and sink-11 (well-known `agent.request` at :322) are
  reachable only through wrapper-parameter flow, which stops at `URI.fromBytes`.
  These sinks are modeled because the labels marked them tp and the egress is
  real; expected alert volume from them is low/zero - recorded as an analysis
  limitation, not a model gap.
- **`json.loads` boundary**: no native arg->result flow; compensated by modeling
  the materialized dict/field reads as sources (per the labels), see section 2.

## 7. Uncovered APIs, dynamic dispatch, and CodeQL analysis limits

- **Candidate labels unmodeled** (18 source + 1 sink rows, awaiting human review):
  internal-API bind/unbind boundary (src-8..17; default `::1` bind + out-of-band
  auth - the mxid chain there is real but reachability is operator-dependent),
  replication push (src-85/86/87; mutual-TLS CN-matched), verifier second-order
  signature reads (src-119..121), and `lookupService` DNS (sink-16). If review
  promotes them, regenerate the libraries - do not hand-edit.
- **External libraries not in the database**: twisted (Agent, HostnameEndpoint,
  RedirectAgent), signedjson, netaddr, smtplib, sentry_sdk. Sink/source matching
  is therefore AST call-site based (module-qualified file + callee name +
  argument position), not resolved-API based - the same approach as the earlier
  single-pass SSRF runs.
- **Dynamic dispatch / framework indirection**: route registration via
  `putChild` and the twisted reactor are invisible to data flow; irrelevant here
  because sources are expression-level reads inside the handlers.
- **`render_%` handler-parameter sources** are best-effort (uses of the `request`
  parameter variable); if the parameter-defining Name carries no flow node the
  predicate simply never fires - it is supplementary, not load-bearing.
- **render_OPTIONS handlers, v1/v2 version endpoints**: not labeled, not modeled
  (no request content use).
- **Response-driven data** (SRV answers, .well-known `m.server`, redirect
  Location headers, homeserver key responses): not modeled as taint - no labels
  support it and it would be unconditional propagation.
- **`urlopen`-style sinks**: none exist in this codebase (no urllib.request /
  requests / httpx call sites) - per detection.json the twisted Agent sites are
  the only HTTP egress.
- No diagnostics query was needed: wrapper->I/O reachability (get_json /
  post_json_get_nothing bodies) was established by direct source reading, and no
  urlopen-style local reachability question remained open. Should Step 5 execution
  show unexpected zero-alert chains, a `diagnostics/` query may be added then -
  its paths must stay out of the formal CWE-918 alert set.

## 8. Reproducibility and independent evaluation

Same principles as the prior CWE-78 (and single-pass SSRF) experiments:

- **Deterministic generation**: every predicate maps 1:1 to reviewed label IDs
  (section 1 tables); regenerating from the same `labels.json` yields identical
  QLL/query files. The only hand-typed content is QLDoc and the two
  evidence-backed summary steps (section 5).
- **No ground truth consulted**: no PyVul truth data, fix commits, CVE text, or
  the pre-existing SSRF reports in the source root were read during generation;
  all evidence cites the current source tree only.
- **Independent evaluation protocol**: a reviewer can (a) diff the label->predicate
  mapping against labels.json, (b) re-derive each predicate's file/name/arg-index
  constraints from the cited source lines, (c) compile with
  `codeql query compile queries/Pass3_SSRF.ql` (validated: compiles clean, CLI
  2.25.1 / python-all 7.1.2), and (d) when Step 5 is authorized, execute
  sequentially per WORKFLOW.md 5.2.4 and compare alert paths against the three
  chains in section 6.
- **No modification** of project source, the CodeQL database, the extraction
  CSVs, Phase 1 labels, or Augur tool files. Outputs are limited to
  `iris/libraries/`, `iris/queries/`, and this report.
