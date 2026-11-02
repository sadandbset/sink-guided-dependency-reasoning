/**
 * Augur-generated source model for the matrix-sydent CWE-918 (SSRF) pass.
 *
 * Machine-generated in Phase 2 Step 4 from the reviewed labels in
 * iris/labels/labels.json (run sydent-ssrf-pass3-20261020, pass_id 3,
 * pass key "ssrf"). Do not edit by hand; regenerate from the labels.
 *
 * Selection policy: label entries with role "source" AND classification
 * "tp" are modeled (93 of 122 source candidates). Excluded:
 *  - 16 "candidate" rows + 2 "summary" rows (src-8..17 internal-API and
 *    replication-push boundaries, src-85/86/87 replication body fields,
 *    src-118..122 verifier internal relays) - these remain in the Phase 1
 *    human-review queue (labels/phase1_review.md); modeling them requires
 *    a label re-review, not an edit here.
 *  - 11 "fp" rows (config/env/brand/X-Forwarded-For - operator-controlled
 *    or non-network input).
 * Mapping and exclusion rationale: report/query_generation_notes.md.
 *
 * Trust boundaries modeled (verified against sydent source):
 *  - Public twisted.web client API (ClientApiHttpServer, default bind '::'
 *    port 8090, sydent/http/httpserver.py:134-140): the materialized
 *    request data of the /_matrix/identity servlets - get_args() results,
 *    args['...']/body['...'] field reads, request.content.read() bodies,
 *    request.args form data, bearer Authorization header.
 *  - Unauthenticated X-Matrix federation Authorization header consumed by
 *    Verifier.authenticate_request (sydent/hs_federation/verifier.py:194),
 *    which selects the matrix:// key-fetch target.
 *
 * No internal network-wrapper parameter is modeled as a source: the
 * verifier relays (_getKeysForServer.server_name, authenticate_request
 * .request) stay non-sources per the reviewed labels; their taint arrives
 * via standard interprocedural flow from the sources below.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {

  /** Source dispatch. Pass key "ssrf" = pass 3 (CWE-918/099/610). */
  predicate isSource(DataFlow::Node node, string passKey) {
    passKey = "ssrf" and (
      getArgsCallResultSource(node) or
      requestContentReadSource(node) or
      requestArgsAttrSource(node) or
      requestHeaderSource(node) or
      xMatrixAuthHeaderSource(node) or
      requestFieldSubscriptSource(node) or
      argsGetCallSource(node) or
      handlerRequestParamSource(node)
    )
  }

  /**
   * Servlet files whose request boundary is tp-labeled: the public client
   * API servlets. Excludes the internal-API servlets
   * (authenticated_bind/unbind, default bind ::1, out-of-band auth - label
   * rows src-8..17 are candidate) and the peer-authenticated replication
   * push servlet (mutual-TLS CN check - label rows src-85/86/87 are
   * candidate).
   */
  bindingset[path]
  private predicate publicServletFile(string path) {
    path.matches("sydent/http/servlets/%") and
    path != "sydent/http/servlets/authenticated_bind_threepid_servlet.py" and
    path != "sydent/http/servlets/authenticated_unbind_threepid_servlet.py" and
    path != "sydent/http/servlets/replication.py"
  }

  /**
   * get_args(request, ...) call results: the materialized untrusted
   * parameter dict (json.loads(request.content.read()) for POST/PUT JSON,
   * request.args for v1/GET fallback) returned to every public servlet and
   * to sydent/http/auth.py:45 (tokenFromRequest). Downstream field reads
   * are additionally modeled directly by requestFieldSubscriptSource.
   * Labels (18 tp): src-6, src-19, src-24, src-27, src-34, src-37, src-43,
   * src-49, src-53, src-58, src-64, src-67, src-76, src-79, src-82,
   * src-89, src-103, src-106.
   */
  private predicate getArgsCallResultSource(DataFlow::Node node) {
    exists(Call c, Name fn, string path |
      c.getFunc() = fn and
      fn.getId() = "get_args" and
      path = c.getLocation().getFile().getRelativePath() and
      (
        path = "sydent/http/auth.py"
        or
        publicServletFile(path)
      ) and
      node.asExpr() = c
    )
  }

  /**
   * request.content.read() call results: raw public-endpoint request bodies
   * parsed by json.loads (sydent/http/servlets/__init__.py:79 inside
   * get_args; sydent/http/servlets/threepidunbindservlet.py:54 direct
   * json.loads in the public unbind servlet). The replication.py:63 read
   * (src-86) is peer-cert-gated candidate and excluded.
   * Labels (2 tp): src-2, src-111.
   */
  private predicate requestContentReadSource(DataFlow::Node node) {
    exists(Call c, Attribute fn, Attribute content, Name request |
      c.getFunc() = fn and
      fn.getName() = "read" and
      fn.getObject() = content and
      content.getName() = "content" and
      content.getObject() = request and
      request.getId() = "request" and
      c.getLocation().getFile().getRelativePath() =
        ["sydent/http/servlets/__init__.py",
         "sydent/http/servlets/threepidunbindservlet.py"] and
      node.asExpr() = c
    )
  }

  /**
   * request.args attribute reads: twisted form/query parameter dict inside
   * get_args (sydent/http/servlets/__init__.py:87, the v1/GET fallback
   * path). The sydent.py:374/375 brand reads (src-98/99) are fp (local
   * template selection only) and excluded.
   * Labels (1 tp): src-3.
   */
  private predicate requestArgsAttrSource(DataFlow::Node node) {
    exists(Attribute a, Name request |
      a.getName() = "args" and
      a.getObject() = request and
      request.getId() = "request" and
      a.getLocation().getFile().getRelativePath() =
        "sydent/http/servlets/__init__.py" and
      node.asExpr() = a
    )
  }

  /**
   * request.getHeader('Authorization') call result in
   * sydent/http/auth.py:39 (tokenFromRequest): the attacker-supplied bearer
   * token of the public API. Reaches account lookup only, kept for label
   * fidelity and pass coverage.
   * Labels (1 tp): src-5.
   */
  private predicate requestHeaderSource(DataFlow::Node node) {
    exists(Call c, Attribute fn, Name request |
      c.getFunc() = fn and
      fn.getName() = "getHeader" and
      fn.getObject() = request and
      request.getId() = "request" and
      c.getLocation().getFile().getRelativePath() = "sydent/http/auth.py" and
      node.asExpr() = c
    )
  }

  /**
   * request.requestHeaders.getRawHeaders('Authorization') call result in
   * sydent/hs_federation/verifier.py:194 (authenticate_request): the
   * UNAUTHENTICATED X-Matrix federation header. Its origin parameter
   * (verifier.py:187) selects the matrix:// key-fetch target and is
   * fetched BEFORE signature verification (verifier.py:80 precedes :211).
   * The sydent.py:361 X-Forwarded-For read (src-97) is fp and excluded.
   * Labels (1 tp): src-123.
   */
  private predicate xMatrixAuthHeaderSource(DataFlow::Node node) {
    exists(Call c, Attribute fn, Attribute requestHeaders, Name request |
      c.getFunc() = fn and
      fn.getName() = "getRawHeaders" and
      fn.getObject() = requestHeaders and
      requestHeaders.getName() = "requestHeaders" and
      requestHeaders.getObject() = request and
      request.getId() = "request" and
      c.getLocation().getFile().getRelativePath() =
        "sydent/hs_federation/verifier.py" and
      node.asExpr() = c
    )
  }

  /**
   * args['...'] / body['...'] field reads in the public servlets: the
   * request-parameter fields as labeled individually in Phase 1 (including
   * the SSRF-relevant matrix_server_name, mxid, and the unbind body
   * fields). Native container->subscript taint exists, but these are
   * modeled directly to match the field-level labels and to compensate for
   * the json.loads() arg->result boundary (not natively modeled) upstream
   * of the body dicts.
   * Labels (44 tp): src-20..22, src-25, src-28..32, src-35, src-38..40,
   * src-44, src-45, src-50, src-51, src-54..56, src-59..62, src-65,
   * src-68..70, src-77, src-80, src-83, src-84, src-90..93, src-104,
   * src-107..109, src-112..115.
   */
  private predicate requestFieldSubscriptSource(DataFlow::Node node) {
    exists(Subscript s, Name n, string path |
      s.getObject() = n and
      n.getId() = ["args", "body"] and
      path = s.getLocation().getFile().getRelativePath() and
      publicServletFile(path) and
      node.asExpr() = s
    )
  }

  /**
   * args.get('access_token') call result in sydent/http/auth.py:46: the
   * v1 query-parameter access token (request data materialized via
   * get_args, read via dict.get).
   * Labels (1 tp): src-7.
   */
  private predicate argsGetCallSource(DataFlow::Node node) {
    exists(Call c, Attribute fn, Name n |
      c.getFunc() = fn and
      fn.getName() = "get" and
      fn.getObject() = n and
      n.getId() = "args" and
      c.getLocation().getFile().getRelativePath() = "sydent/http/auth.py" and
      node.asExpr() = c
    )
  }

  /**
   * Uses of the `request` parameter (position 1) of render_GET/render_POST
   * methods in the public servlets: the twisted handler boundary itself
   * (the framework hands the untrusted request object to these methods).
   * Best-effort supplementary source - object-level taint alone does not
   * propagate to field reads, so the materialized reads above carry the
   * actual sink connectivity; this predicate keeps the handler-param
   * labels represented. render_OPTIONS handlers are not labeled sources.
   * Labels (25 tp): src-4, src-18, src-23, src-26, src-33, src-36, src-42,
   * src-46, src-47, src-48, src-52, src-57, src-63, src-66, src-74,
   * src-75, src-78, src-81, src-88, src-101, src-102, src-105, src-110,
   * src-116, src-117.
   */
  private predicate handlerRequestParamSource(DataFlow::Node node) {
    exists(Parameter p, Function f, Name use, string path |
      f.getArg(1) = p and
      p.getName() = "request" and
      f.getName().matches("render_%") and
      path = f.getLocation().getFile().getRelativePath() and
      publicServletFile(path) and
      use = p.getVariable().getAnAccess() and
      node.asExpr() = use
    )
  }
}
