/**
 * @name opendiamond CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   opendiamond CodeQL database (OpenDiamond 10.1.1, snapshot sha
 *   d2f20ffff793f88335f2c0244679d7193295abe2, a CMU distributed multimedia
 *   search platform with three Python web boundaries and one raw-socket RPC
 *   boundary): (1) the Flask dataretriever service (dataretriever/__main__
 *   registers 8 store blueprints) whose '/obj/<path:obj_path>',
 *   '/meta/<path:object_path>', '/id/<path:object_path>',
 *   '/obj/<dataset>/<path:rel_path>' and '/obj/start/.../<path:video>' route
 *   parameters are Flask path-converter segments that accept '/' and flow
 *   into os.path.join(DATAROOT, ...) -> send_file/open (diamond_store.py:131,
 *   test_store.py:290, mixer_store.py:260, yfcc100m_mysql_store.py:126,
 *   video_store.py:84, augment_store.py:159) - plus the default-converter
 *   index/root params ('/<gididx>' diamond_store.py:38,
 *   '/root/<rootdir>...' augment_store.py:57) and the request.args.get
 *   query reads (yfcc100m_simple_store.py:54/:58); (2) the Tornado JSON
 *   Blaster (blaster/handlers.py) whose RequestHandler verb methods receive
 *   URL-regex groups (EvaluateHandler.post(search_key) :347,
 *   ResultHandler.get(search_key, object_key) :405,
 *   AttributeHandler.get(search_key, object_key, attr_name) :431 - the
 *   search/object keys are hex-regex-constrained by blaster/__init__.py:51-58
 *   but attr_name is '(.*)$'), whose self.request.body JSON search specs
 *   (:313/:360/:365) carry the 'blob:<sig>' filter code URIs fetched via
 *   blob_cache[parts.path] at :207, whose self.get_argument('jsonp'/'tint')
 *   reads (:414/:438) are query-string sources, and whose sockjs websocket
 *   event handlers (SearchConnection.start(search_key) :553, dispatched
 *   dynamically via getattr in on_message :505-:520) receive unconstrained
 *   search keys that reach SearchCache.get_search -> open; (3) the Django
 *   scopeserver apps (scopeserver/<app>/views.py) whose request parameters and
 *   request.POST/request.GET form reads feed scope-cookie scopeurl
 *   generation (long-range chain into dataretriever file: URIs); (4) the
 *   raw-socket XDR RPC servers (server/search.py:128-318,
 *   proxy/search.py:137-310) whose @RPCHandlers.handler params arguments are
 *   XDR-decoded client requests carrying 'sha256:<sig>' filter code/blob
 *   URIs and reexecute object ids; plus the ScopeCookie.parse boundary on
 *   request JSON cookie strings (blaster/handlers.py:253), the json.loads
 *   request-body decodes (blaster/handlers.py:360/:507), and the
 *   os.environ.get/os.getenv/os.environ[...] environment reads (deployer
 *   trust level - emitted for the labeling step to judge, not assumed
 *   attacker-controlled; CLI args and DiamondConfig config-file paths are
 *   operator-local and NOT emitted). Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose: the
 *   problem query kind is the wrong shape for candidate tables and no table
 *   kind is assumed to exist.
 * @id iris/opendiamond/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql and to the prior IRIS manual
 * Path_Traversal projects aiohttp/airflow/ansible/coderedcms/copyparty):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - handler/accessor/callable name (e.g. "get_object_src_http",
 *                   "get", "start", "parse", "loads", "body")
 *   4. flow_kind  - "http_route_param" (Flask/Tornado URL-injected handler
 *                   parameter), "http_query" (request.args.get /
 *                   self.get_argument), "http_body" (self.request.body),
 *                   "http_header" (self.request.headers), "socket_message"
 *                   (sockjs event-handler parameter or on_message payload),
 *                   "rpc_param" (XDR-decoded RPC handler argument),
 *                   "json_body" (json.loads of a request/websocket body),
 *                   "http_view_request" (Django view request parameter),
 *                   "http_form" (request.POST/request.GET read),
 *                   "cookie_parse" (ScopeCookie.parse boundary),
 *                   "env" (os.environ/os.getenv boot-time read)
 *   5. receiver   - syntactic receiver hint: the Flask route pattern string
 *                   for route-param rows, the enclosing class name for
 *                   method rows, "request.args"/"self.request"/"self" for
 *                   keyed-read families, "ScopeCookie"/"json" for the parse
 *                   and loads families, "" when none
 *   6. moduleHint - dotted python module path of the candidate's containing
 *                   module (variable intentionally named moduleHint;
 *                   `module` is not a valid QL variable name here), or a
 *                   literal module hint for the parse family
 *                   ("opendiamond.scope") and the env family ("os")
 *   7. arg_index  - 0-based positional argument index of the value/key
 *                   argument for call families (0 for keyed reads and the
 *                   decode/parse argument), the 0-based parameter position
 *                   (including self at 0 for method parameters) for
 *                   parameter rows, -1 for plain attribute reads
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "ast" for every family in this query: all boundaries are
 *                   either first-party handler shapes (decorator/method
 *                   signatures, attribute reads on request objects) or
 *                   aliased stdlib/first-party calls (import simplejson as
 *                   json), so no API-graph resolution is needed; the column
 *                   is kept so the CSV schema stays identical to the prior
 *                   projects of this series
 *
 * Note: this file defines no QL classes (only predicates/functions), keeps
 * every variable bound through a positive body (negation is only applied to
 * already-bound variables such as `not p.isSelf()`), and does not mix
 * API::Node and DataFlow::Node values.
 *
 * Scope (applied to every row): %/opendiamond_vuln/opendiamond/% (the
 * shipped opendiamond package) or the root entry script
 * %/opendiamond_vuln/proxy.py, EXCLUDING the nested %/opendiamond-db/%
 * database directory (also outside the positive scope by construction).
 * tests/, setup.py and the root audit artifacts are outside the positive
 * scope.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Forward-slash-normalized absolute path of the file containing n, so path
 *  matching works with both CodeQL path styles on Windows. */
string normalizedPathOf(AstNode n) {
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
}

/** Dotted module-name hint for the module containing n (opendiamond.x.y);
 *  scripts without a dotted module name (the root proxy.py entry) fall back
 *  to the file base name. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
}

/** True iff the candidate's file path is inside the audited opendiamond
 *  package (or is the root proxy.py entry script), excluding the nested
 *  opendiamond-db CodeQL database directory. bindingset[path] declares that
 *  the caller passes a bound path. */
bindingset[path]
predicate opendiamondSourcePath(string path) {
  (
    path.replaceAll("\\", "/").matches("%/opendiamond_vuln/opendiamond/%")
    or
    path.replaceAll("\\", "/").matches("%/opendiamond_vuln/proxy.py")
  ) and
  not path.replaceAll("\\", "/").matches("%/opendiamond-db/%")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. Every family is grounded in code actually
 *  present in the audited tree (see the file/line anchors in the comments;
 *  line numbers refer to the opendiamond_vuln snapshot). */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: Flask route handler parameters. The route decorator
     (@scope_blueprint.route(...) in the 8 dataretriever store modules,
     @app.route in dataretriever/__main__.py:30) makes Flask inject the URL
     path segments into the handler's positional parameters. The
     path-converter params (<path:obj_path> etc.) accept '/' and reach
     os.path.join(DATAROOT, ...) -> send_file/open; the default-converter
     params ('/<gididx>', '/root/<rootdir>...', '/<dataset>') cannot carry
     '/' but can carry '..' segments. The receiver column carries the route
     pattern expression (toString: a plain literal for most routes, the
     concatenation expression for the multi-part routes of
     augment_store.py:57-:63 and test_store.py:55-:62) so the labeling step
     can see which converter is used. */
  exists(Function f, Parameter p, Call dec, Attribute dfunc |
    dec = f.getADecorator().(Call) and
    dfunc = dec.getFunc().(Attribute) and
    dfunc.getName() = "route" and
    p = f.getAnArg() and
    not p.isSelf() and
    normalizedPathOf(p).matches("%/opendiamond/dataretriever/%") and
    node = p and
    flowKind = "http_route_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = dec.getArg(0).toString() and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  /* family 2: Flask query-string reads: request.args.get(key, ...) -
     argument 0 carries the key whose value is returned. Observed sites:
     yfcc100m_simple_store.py:54 ('slice') and :58 ('distribute') - the
     values drive index slicing, not paths, but the read is a request-data
     boundary row for the labeling step. */
  exists(Call c, Attribute func, Attribute argsattr |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    argsattr = func.getObject().(Attribute) and
    argsattr.getName() = "args" and
    argsattr.getObject().(Name).getId() = "request" and
    normalizedPathOf(c).matches("%/opendiamond/dataretriever/%") and
    node = c and
    flowKind = "http_query" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "request.args" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: Tornado RequestHandler verb methods in blaster/handlers.py -
     the URL-regex groups are injected as positional parameters after self.
     EvaluateHandler.post(search_key) :347, ResultHandler.get(search_key,
     object_key) :405, AttributeHandler.get(search_key, object_key,
     attr_name) :431, SearchHandler/PostBlobHandler/UIHandler (no extra
     params - no rows). search_key/object_key are constrained to
     [0-9a-f]{64} by the route regexes (blaster/__init__.py:51-58);
     attr_name is matched by '(.*)$' and is used as a ZIP member key, not a
     filesystem path. argIndex counts self at 0. */
  exists(Function f, Parameter p |
    f.isMethod() and
    f.getName() in ["get", "post", "put", "delete", "patch", "head", "options"] and
    p = f.getAnArg() and
    not p.isSelf() and
    normalizedPathOf(p).matches("%/opendiamond/blaster/handlers.py") and
    node = p and
    flowKind = "http_route_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = f.getEnclosingScope().(Class).getName() and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  /* family 4: Tornado request-object reads: self.request.body (the JSON
     search spec at :313, the evaluate request at :360, the content-type
     routing via request_content_type at :165 uses headers) - the body
     carries filter blob URIs 'blob:<sig>' and cookie strings.
     self.request.headers['Content-Type'] :165 is the header family. */
  exists(Attribute a, Attribute req |
    req = a.getObject().(Attribute) and
    req.getName() = "request" and
    req.getObject().(Name).getId() = "self" and
    a.getName() in ["body", "headers"] and
    normalizedPathOf(a).matches("%/opendiamond/blaster/handlers.py") and
    node = a and
    (
      (a.getName() = "body" and flowKind = "http_body")
      or
      (a.getName() = "headers" and flowKind = "http_header")
    ) and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "self.request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 5: Tornado query-argument reads: self.get_argument(name, ...)
     - argument 0 carries the argument name whose value is returned.
     Observed sites: handlers.py:414 ('jsonp') and :438 ('tint') - values
     are echoed/tinted, not paths; boundary rows for the labeling step. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get_argument" and
    func.getObject().(Name).getId() = "self" and
    normalizedPathOf(c).matches("%/opendiamond/blaster/handlers.py") and
    node = c and
    flowKind = "http_query" and
    callableName = "get_argument" and
    argIndex = 0 and
    receiver = "self" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6: sockjs websocket message boundary. Event handlers are marked
     with the @_StructuredSocketConnection.event classmethod decorator
     (an Attribute, not a Call) and receive JSON-decoded event data as
     positional parameters: SearchConnection.start(search_key) :553 - the
     search_key flows into SearchCache.get_search(search_key) -> open()
     WITHOUT the hex regex that guards the HTTP routes (dispatch is
     dynamic: getattr(self, event) in on_message :505-:520). The
     on_message(self, data) method itself (:505) receives the raw sockjs
     text frame. argIndex counts self at 0. */
  exists(Function f, Parameter p |
    (
      exists(Attribute dec | dec = f.getADecorator().(Attribute) and dec.getName() = "event")
      or
      f.getName() = "on_message"
    ) and
    p = f.getAnArg() and
    not p.isSelf() and
    normalizedPathOf(p).matches("%/opendiamond/blaster/handlers.py") and
    node = p and
    flowKind = "socket_message" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = f.getEnclosingScope().(Class).getName() and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  /* family 7: raw-socket XDR RPC handler boundary: methods decorated with
     @RPCHandlers.handler(cmd, ...) whose 'params' parameter is the
     XDR-decoded client request. server/search.py: setup :130,
     send_blobs :208, start :217, reexecute_filters :248,
     session_variables_set :301; proxy/search.py: setup :139,
     send_blobs :242, start :281, retrain_filter :310. The setup filter
     configs carry 'sha256:<sig>' code/blob URIs; reexecute carries the
     object id that resolves to file:/sha256: scheme paths. */
  exists(Function f, Parameter p, Call dec, Attribute dfunc |
    dec = f.getADecorator().(Call) and
    dfunc = dec.getFunc().(Attribute) and
    dfunc.getName() = "handler" and
    p = f.getAnArg() and
    p.getName() = "params" and
    (
      normalizedPathOf(p).matches("%/opendiamond/server/search.py")
      or
      normalizedPathOf(p).matches("%/opendiamond/proxy/search.py")
    ) and
    node = p and
    flowKind = "rpc_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = f.getEnclosingScope().(Class).getName() and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  /* family 8: JSON body decode in the blaster: json.loads(...) (simplejson
     imported as json at handlers.py:30) - argument 0 is the JSON text.
     Observed sites: handlers.py:360 (json.loads(self.request.body) - the
     evaluate request object URI) and :507 (json.loads(data) - the sockjs
     message frame). The decoded fields (cookies list, filter blob URIs,
     evaluate object uri) are the actual attacker payloads; the LLM/summary
     step must bridge loads -> dict field reads. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "loads" and
    func.getObject().(Name).getId() in ["json", "simplejson"] and
    normalizedPathOf(c).matches("%/opendiamond/blaster/handlers.py") and
    node = c and
    flowKind = "json_body" and
    callableName = "loads" and
    argIndex = 0 and
    receiver = "json" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 9a: Django view request parameters: the 'request' parameter of
     view functions in scopeserver/<app>/views.py (e.g. gatekeeper manage,
     cocktail index/manage, flickr create, metadata manage, mirage create,
     gigapan generate/browse). Form-cleaned fields flow into
     generate_cookie scopeurls -> dataretriever object src/meta file://
     paths (multi-service chain; labeling judges the boundary trust). */
  exists(Function f, Parameter p |
    p = f.getAnArg() and
    p.getName() = "request" and
    normalizedPathOf(p).matches("%/opendiamond/scopeserver/%/views.py") and
    node = p and
    flowKind = "http_view_request" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  /* family 9b: Django form reads: request.POST / request.GET attribute
     reads in scopeserver/<app>/views.py (request.POST at mirage:27,
     gatekeeper:28/:54, flickr:26, metadata:32/:71, cocktail:32/:84,
     gigapan:75; request.GET at gatekeeper:64, metadata:81, cocktail:94,
     gigapan:85/:117). */
  exists(Attribute a |
    a.getObject().(Name).getId() = "request" and
    a.getName() in ["POST", "GET"] and
    normalizedPathOf(a).matches("%/opendiamond/scopeserver/%/views.py") and
    node = a and
    flowKind = "http_form" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 10: scope-cookie parse boundary: ScopeCookie.parse(c) on cookie
     strings taken from the JSON search spec (blaster/handlers.py:253,
     config['cookies'] split by ScopeCookie.split at :254). Parsed
     scopeurls are signature-verified (semi-trusted) and determine which
     scope lists (and thus file: object URIs) are fetched. Restriction to
     the blaster keeps the CLI caller scope.py:348 out of this family. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "parse" and
    func.getObject().(Name).getId() = "ScopeCookie" and
    normalizedPathOf(c).matches("%/opendiamond/blaster/handlers.py") and
    node = c and
    flowKind = "cookie_parse" and
    callableName = "parse" and
    argIndex = 0 and
    receiver = "ScopeCookie" and
    moduleHint = "opendiamond.scope" and
    matchKind = "ast"
  )
  or
  /* family 11: boot-time environment reads - os.environ.get(name) /
     os.getenv(name) / os.environ[name]. Observed sites:
     blobcache.py:167 (os.environ.get('TMPDIR') - ExecutableBlobCache temp
     dir), server/filter.py:749 (os.getenv('TMPDIR') - docker fifo dir),
     client/util.py:85/:95 (os.environ['HOME'] - local client cookie/
     filter files). Deployer trust level, NOT attacker input - kept for
     the labeling step to judge per the boundary rule. */
  (
    exists(Call c, Attribute func, Attribute env |
      func = c.getFunc().(Attribute) and
      func.getName() = "get" and
      env = func.getObject().(Attribute) and
      env.getName() = "environ" and
      env.getObject().(Name).getId() = "os" and
      normalizedPathOf(c).matches("%/opendiamond/%") and
      node = c and
      flowKind = "env" and
      callableName = "get" and
      argIndex = 0 and
      receiver = "os.environ" and
      moduleHint = "os" and
      matchKind = "ast"
    )
    or
    exists(Call c, Attribute func |
      func = c.getFunc().(Attribute) and
      func.getName() = "getenv" and
      func.getObject().(Name).getId() = "os" and
      normalizedPathOf(c).matches("%/opendiamond/%") and
      node = c and
      flowKind = "env" and
      callableName = "getenv" and
      argIndex = 0 and
      receiver = "os" and
      moduleHint = "os" and
      matchKind = "ast"
    )
    or
    exists(Subscript s, Attribute env |
      env = s.getObject().(Attribute) and
      env.getName() = "environ" and
      env.getObject().(Name).getId() = "os" and
      normalizedPathOf(s).matches("%/opendiamond/%") and
      node = s and
      flowKind = "env" and
      callableName = "environ" and
      argIndex = 0 and
      receiver = "os.environ" and
      moduleHint = "os" and
      matchKind = "ast"
    )
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  opendiamondSourcePath(normalizedPathOf(node))
select
  node,
  "source_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
