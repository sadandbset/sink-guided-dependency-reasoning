/**
 * @name flask-cors CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   Flask-Cors 3.0.8 CodeQL database (snapshot 5c6e05e - the flask_cors
 *   library itself is the audit target): the HTTP request boundary of the
 *   Flask 'request' proxy - request.headers / request.method reads at
 *   flask_cors/core.py:245 (set_cors_headers) and request.method at
 *   flask_cors/decorator.py:125, request.path reads at
 *   flask_cors/extension.py:178/:180 (matched against resource regexes and
 *   logged); the request-header value reads request_headers.get('Origin')
 *   core.py:177, request_headers.get(ACL_REQUEST_METHOD) core.py:194 and
 *   request_headers.get(ACL_REQUEST_HEADERS) core.py:203 (request_headers is
 *   the request Headers object passed in from core.py:245); the response
 *   header read resp.headers.get(ACL_ORIGIN) extension.py:173 (weak secondary
 *   boundary - feeds a boolean skip-check only); the request-value-carrying
 *   parameters of the core helpers (get_cors_origins.request_origin core.py
 *   :113, get_allow_headers.acl_request_headers :161, get_cors_headers
 *   .request_headers/.request_method :176, try_match.request_origin :275 -
 *   receives both the Origin value and request.path from extension.py:178 -
 *   and try_match_any.inst :271); the framework wrapper parameters where
 *   Flask URL rule variables and the view's response object pass through
 *   library code (wrapped_function *args/**kwargs decorator.py:121 and
 *   extension.py:160, cors_after_request.resp extension.py:171,
 *   set_cors_headers.resp core.py:224); and the OPERATOR-TRUST configuration
 *   boundary - the entry parameters cross_origin(*args, **kwargs)
 *   decorator.py:18, CORS.__init__(app, **kwargs) extension.py:126,
 *   CORS.init_app(app, **kwargs) extension.py:131, get_cors_options
 *   (appInstance, *dicts) core.py:288, get_app_kwarg_dict(appInstance)
 *   core.py:303, parse_resources(resources) core.py:66, serialize_options
 *   (opts) core.py:354, make_after_request_function(resources)
 *   extension.py:170 - plus the options/_options/app_config.get(...) field
 *   reads carrying the merged CORS options (core.py, extension.py:138/:158,
 *   decorator.py:116/:125, and the app.config CORS_* reads core.py:311/:313);
 *   operator-trust level, recorded for labeling to classify, NOT
 *   automatically attacker sources. Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not
 *   database analyze). This is a plain multi-column select query on
 *   purpose: @kind problem is the wrong shape for candidate tables and
 *   @kind table is not assumed to exist.
 * @id iris/flask-cors/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (e.g. "get" for the
 *                   request_headers.get / options.get reads, "path"/"headers"/
 *                   "method" for the request attribute reads, "argv"-style
 *                   field names, the function name for parameter rows)
 *   4. flow_kind  - "request_header" (.get reads on the request_headers
 *                   parameter - the Origin / preflight header values),
 *                   "request_attr" (request.path / request.headers /
 *                   request.method reads on the Flask request proxy),
 *                   "response_header" (resp.headers.get(ACL_ORIGIN) - weak
 *                   secondary boundary, boolean skip-check only),
 *                   "request_value_param" (parameters of the core helpers
 *                   carrying request-derived values),
 *                   "wrapper_param" (framework wrapper parameters: the
 *                   wrapped_function *args/**kwargs forwarding Flask URL
 *                   rule variables to the view, and the response-object
 *                   parameters cors_after_request.resp / set_cors_headers
 *                   .resp),
 *                   "config_param" (operator-trust configuration entry
 *                   parameters of the library's public/internal option
 *                   APIs),
 *                   "config_field" (options/_options/app_config .get reads
 *                   carrying merged CORS options - operator-trust)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "request"/"request_headers"/"resp"/
 *                   "options"/"_options"/"app_config" etc., or "" if none;
 *                   enclosing class name for method parameter rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hint "flask" for the request-proxy channel (the
 *                   request name is imported from flask)
 *   7. arg_index  - 0-based positional argument index (index of the key
 *                   argument for keyed reads such as request_headers.get
 *                   (key) and options.get(key); -1 when the tainted value
 *                   is the attribute itself; parameter position in the
 *                   function definition for param rows, including the
 *                   self slot for methods; for the *args/**kwargs wrapper
 *                   parameters the syntactic positions 0/1 are emitted)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no source row is expected to resolve at API level:
 * the request boundary flows through the Flask 'request' proxy (flask and
 * werkzeug are external libraries not part of the database - only the
 * flask-cors tree is), and every value boundary is a .get call on a local
 * parameter/variable name or an attribute read on a local name. All families
 * below are AST-level matches and the match_kind column is kept "ast" for
 * cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (18 unit-test files), and
 * /flask-cors-db/ (the CodeQL database directory sits inside the source
 * tree). setup.py, examples/ and docs/conf.py are kept in scope (build/demo/
 * doc files - no request-derived values are read there; rows, if any, are
 * expected to be labeled none/FP).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  (setup.py, examples/*.py, docs/conf.py) have no dotted module name; their
 *  file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
}

/** Forward-slash-normalized absolute path of the file containing n, so path
 *  matching works with both CodeQL path styles on Windows. */
string normalizedPathOf(AstNode n) {
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
}

/** Base name of the object expression of an attribute access, used as a receiver hint. */
string receiverHint(Attribute a) {
  result = a.getObject().(Name).getId()
  or
  result = a.getObject().(Attribute).getName()
  or
  not a.getObject() instanceof Name and
  not a.getObject() instanceof Attribute and
  result = "<expr>"
}

/** True iff the candidate's file path is one of the excluded trees. Path is
 *  normalized to forward slashes before matching so the query works on both
 *  CodeQL path styles. bindingset[path] declares that the caller passes a
 *  bound path (the path only appears in checked positions such as the
 *  receiver of replaceAll/matches inside this predicate). */
bindingset[path]
predicate excludedPath(string path) {
  path.replaceAll("\\", "/").matches("%/tests/%")
  or
  path.replaceAll("\\", "/").matches("%/flask-cors-db/%")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: request-header value reads: request_headers.get(...) inside
     get_cors_headers (core.py:177 .get('Origin') - THE dominant
     attacker-controlled string; core.py:194 .get(ACL_REQUEST_METHOD, '')
     - the preflight method header; core.py:203 .get(ACL_REQUEST_HEADERS) -
     the preflight requested-headers list). request_headers is the get_cors
     _headers parameter fed from request.headers at core.py:245. Argument 0
     carries the key. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Name).getId() = "request_headers" and
    normalizedPathOf(c).matches("%/flask_cors/core.py") and
    node = c and
    flowKind = "request_header" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "request_headers" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 2: Flask request proxy attribute reads: request.headers and
     request.method (core.py:245 in set_cors_headers - the whole request
     header set and the request method), request.method (decorator.py:125 -
     OPTIONS preflight detection) and request.path (extension.py:178 matched
     against the resource regexes via try_match, :180 passed to LOG.debug).
     request.path is attacker-controlled and path-shaped, but consumed only
     as a regex match subject. The attribute VALUE carries the data, hence
     argIndex -1. */
  exists(Attribute a |
    a.getObject().(Name).getId() = "request" and
    (a.getName() = "path" or a.getName() = "headers" or a.getName() = "method") and
    normalizedPathOf(a).matches("%/flask_cors/%") and
    node = a and
    flowKind = "request_attr" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = "flask" and
    matchKind = "ast"
  )
  or
  /* family 3: response-header read: resp.headers.get(ACL_ORIGIN)
     (extension.py:173 in cors_after_request) - reads a response header
     previously set by the view's own flask-cors decorator; response headers
     can embed request-derived values (a view echoing Origin), so this is a
     weak secondary boundary; the value feeds a boolean skip-check only.
     Argument 0 carries the key. */
  exists(Call c, Attribute func, Attribute hdrs |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    hdrs = func.getObject().(Attribute) and
    hdrs.getName() = "headers" and
    hdrs.getObject().(Name).getId() = "resp" and
    normalizedPathOf(c).matches("%/flask_cors/extension.py") and
    node = c and
    flowKind = "response_header" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "resp" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 4: request-value-carrying parameters of the core helpers:
     get_cors_origins(options, request_origin) core.py:113 (the Origin
     header value), get_allow_headers(options, acl_request_headers)
     core.py:161 (the preflight requested-headers value),
     get_cors_headers(options, request_headers, request_method) core.py:176
     (the request Headers object and the request method),
     try_match(request_origin, maybe_regex) core.py:275 (receives BOTH the
     Origin value from try_match_any core.py:128 AND request.path from
     extension.py:178) and try_match_any(inst, patterns) core.py:271 (inst
     receives the Origin value core.py:128 and each stripped preflight
     header name core.py:167). arg_index is the 0-based position in the
     function definition. */
  exists(Function f, Parameter p |
    (
      (
        f.getName() = "get_cors_origins" and p.getName() = "request_origin"
        or
        f.getName() = "get_allow_headers" and p.getName() = "acl_request_headers"
        or
        f.getName() = "get_cors_headers" and
        (p.getName() = "request_headers" or p.getName() = "request_method")
        or
        f.getName() = "try_match" and p.getName() = "request_origin"
        or
        f.getName() = "try_match_any" and p.getName() = "inst"
      ) and
      normalizedPathOf(f).matches("%/flask_cors/core.py") and
      p = f.getAnArg() and
      node = p and
      flowKind = "request_value_param" and
      callableName = f.getName() and
      argIndex = p.getPosition() and
      matchKind = "ast" and
      moduleHint = moduleHintOf(f) and
      receiver = ""
    )
  )
  or
  /* family 5: framework wrapper parameters: wrapped_function(*args,
     **kwargs) decorator.py:121 (the cross_origin wrapper - Flask URL rule
     variables for the decorated view arrive here and are forwarded to
     f(*args, **kwargs) at decorator.py:128) and extension.py:160 (the
     exception-handler wrapper forwarding to f at extension.py:161) - for
     the star parameters the syntactic positions 0/1 are emitted;
     cors_after_request(resp) extension.py:171 (the after_request callback
     receiving the response object built from the view's output) and
     set_cors_headers(resp, options) core.py:224 (both library entry points
     converge here with the response object). */
  exists(Function f, Parameter p |
    (
      (
        f.getName() = "wrapped_function" and
        (p.getName() = "args" or p.getName() = "kwargs") and
        normalizedPathOf(f).matches("%/flask_cors/decorator.py")
      )
      or
      (
        f.getName() = "wrapped_function" and
        (p.getName() = "args" or p.getName() = "kwargs") and
        normalizedPathOf(f).matches("%/flask_cors/extension.py")
      )
      or
      (
        f.getName() = "cors_after_request" and
        p.getName() = "resp" and
        normalizedPathOf(f).matches("%/flask_cors/extension.py")
      )
      or
      (
        f.getName() = "set_cors_headers" and
        p.getName() = "resp" and
        normalizedPathOf(f).matches("%/flask_cors/core.py")
      )
    ) and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "wrapper_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    (
      f.getEnclosingScope() instanceof Class and
      receiver = f.getEnclosingScope().(Class).getName()
      or
      not f.getEnclosingScope() instanceof Class and
      receiver = ""
    )
  )
  or
  /* family 6: OPERATOR-TRUST configuration entry parameters:
     cross_origin(*args, **kwargs) decorator.py:18 (the decorator's CORS
     options), CORS.__init__(app, **kwargs) extension.py:126 and
     CORS.init_app(app, **kwargs) extension.py:131 (extension options plus
     the app object), get_cors_options(appInstance, *dicts) core.py:288
     (the option-merging hub), get_app_kwarg_dict(appInstance)
     core.py:303 (the app.config reader), and the internal
     config-propagation helpers parse_resources(resources) core.py:66,
     serialize_options(opts) core.py:354 and
     make_after_request_function(resources) extension.py:170. The person
     embedding flask-cors in an app is the same trust domain as the options
     they configure - the labeling step decides whether any of these cross
     a real untrusted boundary. */
  exists(Function f, Parameter p |
    (
      (
        f.getName() = "cross_origin" and
        (p.getName() = "args" or p.getName() = "kwargs") and
        normalizedPathOf(f).matches("%/flask_cors/decorator.py")
      )
      or
      (
        (f.getName() = "__init__" or f.getName() = "init_app") and
        (p.getName() = "app" or p.getName() = "kwargs") and
        normalizedPathOf(f).matches("%/flask_cors/extension.py")
      )
      or
      (
        f.getName() = "get_cors_options" and
        (p.getName() = "appInstance" or p.getName() = "dicts") and
        normalizedPathOf(f).matches("%/flask_cors/core.py")
      )
      or
      (
        f.getName() = "get_app_kwarg_dict" and
        p.getName() = "appInstance" and
        normalizedPathOf(f).matches("%/flask_cors/core.py")
      )
      or
      (
        (f.getName() = "parse_resources" or f.getName() = "serialize_options") and
        (p.getName() = "resources" or p.getName() = "opts") and
        normalizedPathOf(f).matches("%/flask_cors/core.py")
      )
      or
      (
        f.getName() = "make_after_request_function" and
        p.getName() = "resources" and
        normalizedPathOf(f).matches("%/flask_cors/extension.py")
      )
    ) and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "config_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    (
      f.getEnclosingScope() instanceof Class and
      receiver = f.getEnclosingScope().(Class).getName()
      or
      not f.getEnclosingScope() instanceof Class and
      receiver = ""
    )
  )
  or
  /* family 7: config field reads: options.get(...) / _options.get(...) /
     app_config.get(...) inside flask_cors/ - the merged CORS options
     (DEFAULT_OPTIONS + app.config CORS_* keys + decorator/constructor
     kwargs) as consumed by the library: core.py:114/:123/:139/:147/:188/
     :198/:204/:205/:210/:216/:218/:365/:366/:380 (origins, send_wildcard,
     always_send, supports_credentials, methods, max_age, vary_header,
     allow_headers), extension.py:138 (resources) /:158
     (intercept_exceptions), decorator.py:116 (_options 'automatic_options')
     /:125 (options 'automatic_options'), and the app.config CORS_* reads
     app_config.get(k) core.py:311/:313 inside get_app_kwarg_dict's dict
     comprehension. Argument 0 carries the key. Operator-trust level -
     recorded for labeling to classify, not automatically attacker
     sources. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    (
      func.getObject().(Name).getId() = "options"
      or
      func.getObject().(Name).getId() = "_options"
      or
      func.getObject().(Name).getId() = "app_config"
    ) and
    normalizedPathOf(c).matches("%/flask_cors/%") and
    node = c and
    flowKind = "config_field" and
    callableName = "get" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
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
