/**
 * @name Matrix Sydent source candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate external-input source nodes from the
 *              matrix-sydent (Matrix Identity Server) application source
 *              for subsequent LLM labeling.
 * @id py/augur/sydent/pass3-sources
 *
 * Plain multi-column select query (NO @kind metadata declared) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * The database contains ONLY the sydent application package plus
 * tests/, matrix_is_test/ and setup.py (twisted, signedjson, nacl,
 * sentry_sdk library internals are external dependencies and are not
 * present; only six stubs exist under C_/codeql/...). Source
 * candidates therefore anchor on the application code, grounded in
 * repo evidence only. Sydent is a twisted.web server (no
 * flask/django/fastapi): routing is a Resource/putChild tree in
 * sydent/http/httpserver.py and every servlet implements
 * render_POST / render_GET(self, request).
 *
 *   - get_args(request, ...) calls: the central untrusted-input
 *     boundary (sydent/http/servlets/__init__.py:41-123). It
 *     materializes a dict from json.loads(request.content.read())
 *     (POST/PUT JSON body) or from request.args (query string /
 *     urlencoded form, v1 + GET fallback). 22 call sites across the
 *     servlets plus sydent/http/auth.py:45 (tokenFromRequest).
 *
 *   - json.loads(request.content.read()) direct reads outside
 *     get_args: sydent/http/servlets/threepidunbindservlet.py:54
 *     (unbind body) and sydent/http/servlets/replication.py:63
 *     (peer replication push body, peer-TLS-authenticated). The
 *     inner request.content.read() call nodes are extracted too
 *     (the earliest untrusted bytes in each flow).
 *
 *   - request.args attribute reads: sydent/sydent.py:374-375
 *     (brand_from_request) and sydent/http/servlets/__init__.py:87
 *     (inside get_args).
 *
 *   - Authorization header reads: request.getHeader('Authorization')
 *     (sydent/http/auth.py:41, bearer token) and
 *     request.requestHeaders.getRawHeaders(u"Authorization")
 *     (sydent/hs_federation/verifier.py:194, X-Matrix federation
 *     header whose origin parameter drives the key-fetch URL).
 *     getRawHeaders("X-Forwarded-For") (sydent/sydent.py:361,
 *     spoofable when obey_x_forwarded_for is enabled) is included
 *     for recall.
 *
 *   - Field-level reads on the parsed request dicts:
 *     args['<field>'] / body['<field>'] subscripts and
 *     <dict>.get('<field>') calls, restricted to the field names
 *     actually read by the servlets. URL/host-relevant fields:
 *     matrix_server_name (registerservlet.py:50 -> matrix:// URL at
 *     :59), mxid (threepidbindservlet.py:45 -> MXID server part ->
 *     bind.py:153 matrix:// onbind URL; threepidunbindservlet.py:70),
 *     threepid (unbind), next_link/nextLink (email/msisdn redirect
 *     + email link), signed_json['signatures'] (verifier.py:114,
 *     server names -> key fetch). General request fields: email,
 *     phone_number, country, medium, address, room_id, sender,
 *     token, sid, client_secret, access_token, addresses,
 *     algorithm, pepper, threepids, public_key, private_key,
 *     user_accepts, send_attempt, sgAssocs (replication push).
 *
 *   - Handler boundary functions: the 28 render_POST / render_GET
 *     methods of twisted Resource subclasses under
 *     sydent/http/servlets/ - the request parameter sits at index 1
 *     (index 0 is self).
 *
 *   - Network-target parameters of internal helpers:
 *     Verifier._getKeysForServer(server_name) (verifier.py:63, the
 *     value interpolated into "matrix://%s/_matrix/key/v2/server/"
 *     at :80) and Verifier.authenticate_request(request, content)
 *     (verifier.py:142, the X-Matrix authenticated request object);
 *     RemotePeer.__init__(sydent, server_name, port, ...)
 *     (sydent/replication/peer.py:107, DB-derived replication push
 *     target used at peer.py:133 "https://%s:%i").
 *
 *   - Configuration / environment (operator input, expected FP
 *     material for remote SSRF, kept for labeling recall):
 *     os.environ.get (sydent/sydent.py:81, :84, :112, :508),
 *     sydent.cfg.get('email', 'email.smtphost')
 *     (sydent/util/emailutils.py:88) and
 *     sydent.cfg.get("peer.%s", "base_replication_url")
 *     (sydent/replication/peer.py:127).
 *
 * Verified API usage (codeql/python-all 7.1.2 cached under
 * C:\Users\lzh\.codeql\packages, same surface as the earlier
 * label-studio/django/calibre-web/core/mlflow SSRF runs):
 *   - Subscript.getObject() / Subscript.getIndex() (semmle/python/
 *     Exprs.qll:90-101) for args['field'] reads.
 *   - StringLiteral.getText() (Exprs.qll:551) for the unquoted
 *     index / argument strings; StrConst / Str are deprecated.
 *   - Attribute.getName() / Attribute.getObject(), Name.getId()
 *     for receiver-shape matching; Attribute.getObject() is bound
 *     via equality before any cast comparison.
 *   - Call.getFunc() / Call.getPositionalArg(int) for call shapes.
 *   - Function.getADecorator() returns decorator Expr; not needed
 *     here because twisted handlers are plain render_* methods.
 *   - Parameter names via p.asName().getId(); Parameter positions
 *     via f.getArg(i); class of a method via
 *     f.getScope().(Class) (Class extends Scope, Class.qll:89).
 *   - moduleHint is bound via getScope().getEnclosingModule().
 *     getName(); the variable is named moduleHint because
 *     `module` is a QL keyword.
 *   - Locations use AstNode.getLocation().getFile().
 *     getRelativePath() and getLocation().getStartLine(); there is
 *     no AstNode.getFile() predicate.
 *
 * Scope: path.matches("sydent/%") - this cannot match the nested
 * "sydent-db/" CodeQL database directory (hyphen vs slash at
 * position 7), nor tests/, matrix_is_test/, setup.py, nor the
 * C_/codeql/... extractor stubs.
 *
 * Output columns (same order as the earlier SSRF runs):
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("source_candidate")
 *  3. callable name       (dotted signature hint)
 *  4. flow kind           (param | return | field)
 *  5. receiver hint       (receiver/type hint)
 *  6. module hint         (dotted module path; variable named
 *                          moduleHint, "module" is a QL keyword)
 *  7. argument index      (-1 when not applicable)
 *  8. line
 *  9. file:line
 * 10. expression text
 */

import python

// ------------------------------------------------------------
// 1. Scope and location helpers
// ------------------------------------------------------------

/**
 * Restrict extraction to the sydent application package.
 *
 * The CodeQL database source root is the repository root, so
 * relative paths of application files look like
 * "sydent/http/servlets/emailservlet.py". "sydent/%" cannot match
 * the nested "sydent-db/" database directory ('-' vs '/' at
 * position 7), the top-level tests/ or matrix_is_test/ directories,
 * setup.py, or the C_/codeql/... extractor stubs.
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("sydent/%")
  )
}

/**
 * Restrict a candidate to files under the servlets package (the
 * twisted render_* handler boundary). The path string is bound by
 * matches() on an already-bound variable, so no unbound-variable
 * error can occur.
 */
predicate inServletsModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("sydent/http/servlets/%")
  )
}

/** Dotted module name of a candidate. */
string moduleOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
}

/** Human-readable file and line location. */
string locationOf(AstNode n) {
  result =
    n.getLocation().getFile().getRelativePath() +
    ":" +
    n.getLocation().getStartLine().toString()
}

// ------------------------------------------------------------
// 2. Request-shape signatures (verified against this source)
// ------------------------------------------------------------

/**
 * Names of the local variables that hold the parsed untrusted
 * request dict, as observed in the servlets:
 *   args      - return value of get_args (all servlets)
 *   body      - json.loads(request.content.read()) in
 *               threepidunbindservlet.py:53-54
 *   inJson    - json.loads(request.content.read()) in
 *               replication.py:63 (peer-authenticated)
 *   request_args / request_args_bytes - locals inside
 *               get_args itself (servlets/__init__.py)
 */
predicate isRequestDictName(string name) {
  name in ["args", "body", "inJson", "request_args"]
}

/**
 * Request fields actually read on those dicts in the servlets.
 * matrix_server_name / mxid / threepid / next_link / nextLink /
 * signatures are the URL- and host-bearing fields for Pass 3;
 * the rest are the genuine client-supplied validation fields.
 */
predicate isRequestField(string f) {
  f in [
    "matrix_server_name",
    "access_token",
    "sid",
    "mxid",
    "client_secret",
    "threepid",
    "medium",
    "address",
    "room_id",
    "sender",
    "email",
    "send_attempt",
    "next_link",
    "nextLink",
    "token",
    "phone_number",
    "country",
    "addresses",
    "algorithm",
    "pepper",
    "threepids",
    "public_key",
    "private_key",
    "user_accepts",
    "sgAssocs",
    "signatures"
  ]
}

// ------------------------------------------------------------
// 3. Candidate extraction
// ------------------------------------------------------------

from
  AstNode n,
  string callableName,
  string flowKind,
  string receiverHint,
  string moduleHint,
  int argIndex
where
  inAnalysisScope(n) and
  moduleHint = moduleOf(n) and
  (
    // --------------------------------------------------------
    // (1) get_args(request, ...) call sites - the central
    //     untrusted-input boundary of every servlet. Parses the
    //     JSON request body or the query-string / form args into
    //     a dict (servlets/__init__.py:41-123). 22 sites:
    //     emailservlet.py:48/:95/:145, msisdnservlet.py:53/:119/
    //     :167, threepidbindservlet.py:42, store_invite_servlet.
    //     py:48, registerservlet.py:48 (matrix_server_name +
    //     access_token), lookupservlet.py:51, lookupv2servlet.
    //     py:67, bulklookupservlet.py:47, getvalidated3pidservlet.
    //     py:44, pubkeyservlets.py:46/:62, termsservlet.py:59,
    //     blindlysignstuffservlet.py:46, authenticated_bind/
    //     unbind servlets :34/:35, auth.py:45 (access_token),
    //     threepidunbindservlet via body instead. The returned
    //     dict is where every attacker-controlled value in this
    //     service originates.
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc().(Name) and
      fn.getId() = "get_args" and
      callableName = "sydent.http.servlets.get_args" and
      flowKind = "return" and
      receiverHint = "twisted.web.server.Request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (2) json.loads(request.content.read()) - the raw request
    //     body materialization. Direct sites outside get_args:
    //     threepidunbindservlet.py:54 (unbind body) and
    //     replication.py:63 (replication push, peer TLS
    //     authenticated); servlets/__init__.py:79 is the body
    //     parse inside get_args itself. The outer json.loads
    //     return value is the parsed untrusted dict.
    // --------------------------------------------------------

    exists(Call c, Attribute loads, Name jsonName, Call readCall, Attribute readAttr, Attribute contentAttr, Name requestName |
      n = c and
      loads = c.getFunc().(Attribute) and
      loads.getName() = "loads" and
      jsonName = loads.getObject().(Name) and
      jsonName.getId() = "json" and
      readCall = c.getPositionalArg(0).(Call) and
      readAttr = readCall.getFunc().(Attribute) and
      readAttr.getName() = "read" and
      contentAttr = readAttr.getObject().(Attribute) and
      contentAttr.getName() = "content" and
      requestName = contentAttr.getObject().(Name) and
      requestName.getId() = "request" and
      callableName = "json.loads" and
      flowKind = "return" and
      receiverHint = "json" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (3) request.content.read() inner call nodes of (2) - the
    //     earliest untrusted bytes in each body flow (the node a
    //     taint query can anchor on below json.loads).
    // --------------------------------------------------------

    exists(Call readCall, Attribute readAttr, Attribute contentAttr, Name requestName |
      n = readCall and
      readAttr = readCall.getFunc().(Attribute) and
      readAttr.getName() = "read" and
      contentAttr = readAttr.getObject().(Attribute) and
      contentAttr.getName() = "content" and
      requestName = contentAttr.getObject().(Name) and
      requestName.getId() = "request" and
      callableName = "twisted.web.server.Request.content.read" and
      flowKind = "return" and
      receiverHint = "twisted.web.server.Request.content" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (4) request.args attribute reads - the query-string /
    //     form parameter dict of a twisted request. Observed:
    //     sydent/sydent.py:374-375 (brand_from_request - feeds
    //     the branded template path, not a URL) and
    //     servlets/__init__.py:87 (inside get_args).
    // --------------------------------------------------------

    exists(Attribute a, Name req |
      n = a and
      a.getName() = "args" and
      req = a.getObject().(Name) and
      req.getId() = "request" and
      callableName = "request.args" and
      flowKind = "field" and
      receiverHint = "twisted.web.server.Request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (5) request.getHeader('Authorization') - bearer-token read
    //     of tokenFromRequest (sydent/http/auth.py:39). The token
    //     is client-controlled; it authenticates v2 endpoints and
    //     does not itself drive a URL, kept for labeling recall.
    // --------------------------------------------------------

    exists(Call c, Attribute m, Name req, StringLiteral lit |
      n = c and
      m = c.getFunc().(Attribute) and
      m.getName() = "getHeader" and
      req = m.getObject().(Name) and
      req.getId() = "request" and
      lit = c.getPositionalArg(0).(StringLiteral) and
      lit.getText() = "Authorization" and
      callableName = "twisted.web.server.Request.getHeader" and
      flowKind = "return" and
      receiverHint = "twisted.web.server.Request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (6) request.requestHeaders.getRawHeaders(...) reads of
    //     security-relevant headers: u"Authorization" (the
    //     X-Matrix federation header at verifier.py:194 whose
    //     origin parameter selects the homeserver whose keys are
    //     fetched via "matrix://%s/_matrix/key/v2/server/" at
    //     verifier.py:80) and "X-Forwarded-For" (sydent.py:361,
    //     spoofable when obey_x_forwarded_for is enabled).
    //     Content-Type reads (replication.py:56/:58) are request
    //     metadata and are not extracted.
    // --------------------------------------------------------

    exists(Call c, Attribute m, Attribute rh, Name req, StringLiteral lit |
      n = c and
      m = c.getFunc().(Attribute) and
      m.getName() = "getRawHeaders" and
      rh = m.getObject().(Attribute) and
      rh.getName() = "requestHeaders" and
      req = rh.getObject().(Name) and
      req.getId() = "request" and
      lit = c.getPositionalArg(0).(StringLiteral) and
      (lit.getText() = "Authorization" or lit.getText() = "X-Forwarded-For") and
      callableName = "twisted.web.http_headers.Headers.getRawHeaders" and
      flowKind = "return" and
      receiverHint = "twisted.web.server.Request.requestHeaders" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (7) Field-level reads on the parsed request dicts:
    //     args['<field>'] / body['<field>'] / inJson[...] /
    //     request_args[...] subscripts, e.g.
    //     registerservlet.py:50 args['matrix_server_name'] ->
    //     matrix:// URL at :59; threepidbindservlet.py:45
    //     args['mxid'] -> MXID server part -> bind.py:153
    //     matrix:// onbind URL; threepidunbindservlet.py:69-70
    //     body['threepid'] / body['mxid'];
    //     emailservlet.py:65/:105 args['next_link'] /
    //     args['nextLink']; verifier.py:114
    //     signed_json['signatures'] (attacker-supplied signature
    //     server names -> key fetch).
    // --------------------------------------------------------

    exists(Subscript s, Name obj, StringLiteral lit |
      n = s and
      obj = s.getObject().(Name) and
      (
        isRequestDictName(obj.getId()) and
        callableName = obj.getId() + "['" + lit.getText() + "']"
        or
        obj.getId() = "signed_json" and
        lit.getText() = "signatures" and
        callableName = "signed_json['signatures']"
      ) and
      lit = s.getIndex().(StringLiteral) and
      isRequestField(lit.getText()) and
      flowKind = "field" and
      receiverHint = "sydent.http.servlets.get_args-return" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (8) <request dict>.get('<field>') reads: auth.py:46
    //     args.get('access_token') and replication.py:77
    //     inJson.get('sgAssocs', {}) - the same untrusted dicts
    //     accessed via dict.get instead of a subscript.
    // --------------------------------------------------------

    exists(Call c, Attribute m, Name obj, StringLiteral lit |
      n = c and
      m = c.getFunc().(Attribute) and
      m.getName() = "get" and
      obj = m.getObject().(Name) and
      isRequestDictName(obj.getId()) and
      lit = c.getPositionalArg(0).(StringLiteral) and
      isRequestField(lit.getText()) and
      callableName = obj.getId() + ".get" and
      flowKind = "return" and
      receiverHint = "sydent.http.servlets.get_args-return" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (9) render_POST / render_GET handler methods of twisted
    //     Resource subclasses under sydent/http/servlets/ - the
    //     request handler boundary (28 methods). The untrusted
    //     twisted.web.server.Request object is the parameter at
    //     index 1 (index 0 is self).
    // --------------------------------------------------------

    exists(Function f, Class cls, Parameter p, int i |
      n = f and
      (f.getName() = "render_POST" or f.getName() = "render_GET") and
      cls = f.getScope().(Class) and
      inServletsModule(f) and
      p = f.getArg(i) and
      i = 1 and
      p.asName().getId() = "request" and
      callableName = "sydent.http.servlets." + cls.getName() + "." + f.getName() and
      flowKind = "param" and
      receiverHint = "twisted.web.resource.Resource" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (10) Verifier._getKeysForServer(server_name) parameter at
    //      index 1 (sydent/hs_federation/verifier.py:63) - the
    //      server name interpolated into
    //      "matrix://%s/_matrix/key/v2/server/" at :80. Its
    //      callers feed it from signed_json['signatures'] keys
    //      (request-derived) and from the X-Matrix origin header.
    // --------------------------------------------------------

    exists(Parameter p, Function f, Class cls, int i |
      n = p and
      f.getName() = "_getKeysForServer" and
      cls = f.getScope().(Class) and
      cls.getName() = "Verifier" and
      p = f.getArg(i) and
      i = 1 and
      p.asName().getId() = "server_name" and
      callableName = "sydent.hs_federation.verifier.Verifier._getKeysForServer.server_name" and
      flowKind = "param" and
      receiverHint = "sydent.hs_federation.verifier.Verifier" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (11) Verifier.authenticate_request(request, content)
    //      request parameter at index 1 (verifier.py:142) - the
    //      federation request whose X-Matrix Authorization header
    //      supplies the origin server name (threepidunbindservlet
    //      .py:135 calls it with the unbind request).
    // --------------------------------------------------------

    exists(Parameter p, Function f, Class cls, int i |
      n = p and
      f.getName() = "authenticate_request" and
      cls = f.getScope().(Class) and
      cls.getName() = "Verifier" and
      p = f.getArg(i) and
      i = 1 and
      p.asName().getId() = "request" and
      callableName = "sydent.hs_federation.verifier.Verifier.authenticate_request.request" and
      flowKind = "param" and
      receiverHint = "twisted.web.server.Request" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (12) RemotePeer.__init__(sydent, server_name, port, ...)
    //      server_name at index 2 and port at index 3
    //      (sydent/replication/peer.py:107) - the replication
    //      push target (peers DB table + peer.<name> config)
    //      used at peer.py:133 "https://%s:%i" and pushed to at
    //      peer.py:200. DB/config-derived, operator-controlled:
    //      expected FP material, kept for labeling context.
    // --------------------------------------------------------

    exists(Parameter p, Function f, Class cls, int i |
      n = p and
      f.getName() = "__init__" and
      cls = f.getScope().(Class) and
      cls.getName() = "RemotePeer" and
      p = f.getArg(i) and
      (i = 2 or i = 3) and
      (p.asName().getId() = "server_name" or p.asName().getId() = "port") and
      callableName = "sydent.replication.peer.RemotePeer.__init__." + p.asName().getId() and
      flowKind = "param" and
      receiverHint = "sydent.replication.peer.RemotePeer" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (13) os.environ.get(...) environment reads
    //      (sydent/sydent.py:81 SYDENT_SERVER_NAME, :84
    //      SYDENT_PID_FILE, :112 SYDENT_DB_PATH, :508
    //      SYDENT_CONF). Operator configuration (expected FP
    //      material for remote SSRF); kept for labeling recall.
    // --------------------------------------------------------

    exists(Call c, Attribute method, Attribute environ, Name osName |
      n = c and
      method = c.getFunc().(Attribute) and
      method.getName() = "get" and
      environ = method.getObject().(Attribute) and
      environ.getName() = "environ" and
      osName = environ.getObject().(Name) and
      osName.getId() = "os" and
      callableName = "os.environ.get" and
      flowKind = "return" and
      receiverHint = "os.environ" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (14) Network-target configuration reads:
    //      sydent.cfg.get('email', 'email.smtphost')
    //      (sydent/util/emailutils.py:88 - SMTP egress host) and
    //      sydent.cfg.get("peer.%s", "base_replication_url")
    //      (sydent/replication/peer.py:127 - replication push
    //      base URL override). Only these two option names are
    //      matched so generic cfg.get calls elsewhere (ports,
    //      templates, credentials) do not produce noise.
    // --------------------------------------------------------

    exists(Call c, Attribute m, Attribute cfgAttr, StringLiteral lit |
      n = c and
      m = c.getFunc().(Attribute) and
      m.getName() = "get" and
      cfgAttr = m.getObject().(Attribute) and
      cfgAttr.getName() = "cfg" and
      lit = c.getPositionalArg(1).(StringLiteral) and
      (lit.getText() = "base_replication_url" or lit.getText() = "email.smtphost") and
      callableName = "sydent.config.get." + lit.getText() and
      flowKind = "return" and
      receiverHint = "sydent.config" and
      argIndex = -1
    )
  )

select
  n,
  "source_candidate",
  callableName,
  flowKind,
  receiverHint,
  moduleHint,
  argIndex,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()
