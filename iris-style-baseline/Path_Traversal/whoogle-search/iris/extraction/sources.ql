/**
 * @name whoogle-search CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   whoogle-search CodeQL database (snapshot 8830615a, whoogle-search 0.8.3,
 *   Flask 2.3.2 web app served by waitress): the flask request-layer reads
 *   on the local name `request` (from flask import request) -
 *   request.args (routes.py:54/:141/:358/:426/:442/:524/:544,
 *   search.py:61), request.form (routes.py:141, search.py:61),
 *   request.data (routes.py:275/:282/:284/:286), request.headers
 *   (routes.py:164/:246, search.py:62), request.url_root
 *   (routes.py:161/:165/:504), request.method (routes.py:141/:423),
 *   request.authorization (routes.py:59) and the self.request.url_root
 *   variant in Search (search.py:129); the .get() boundary calls on those
 *   layers - request.headers.get('User-Agent') (routes.py:164/:246,
 *   search.py:62), request.args.get('tbm') (routes.py:253/:254), THE
 *   request.args.get('name') of the /config route (routes.py:429 PUT
 *   read-side and :447 POST write-side - the value joined under
 *   app.config['CONFIG_PATH'] and opened directly with no '..'/absolute/
 *   containment validation), request.args.get('imgurl'/'url'/'type'/
 *   'location') (routes.py:459/:466/:476/:497); the
 *   request.form.to_dict() boundary (routes.py:437 - POST /config
 *   config_data); the g.request_params alias (assigned
 *   request.args|request.form in before_request routes.py:140-142, read
 *   at :158 and via g.request_params.get('q') at :271, plus the
 *   self.request_params reads and .get('tbm'/'q') calls in Search
 *   search.py:69/:94); the flask session subscripts (session['auth'/
 *   'config'/'uuid'/'key'/'error_message'] at routes.py:55/:68/:149/:151/
 *   :152/:155/:210/:211/:317/:318/:319/:432/:449 - the signed store whose
 *   'config' key is written from request.form in POST /config and reloaded
 *   as Config(**session['config'])); the proxy/Wsgi-environ reads on the
 *   flask Request parameter r in misc.py (r.headers.get(
 *   'X-Forwarded-Proto'/'X-Forwarded-Host') :42/:43, r.environ.get(
 *   'HTTP_X_FORWARDED_FOR') :28, r.environ['REMOTE_ADDR'] :31,
 *   r.full_path :45 - trust depends on ProxyFix); the environment family
 *   (os.getenv / os.environ.get / os.environ[...] - operator/deployment
 *   trust incl. WHOOGLE_TOR_CONF which reaches open(confloc) in
 *   request.py:47-55 - emitted for the labeling step to classify, NOT
 *   automatically treated as attacker sources - incl. the ~38 os.getenv
 *   sites (version.py:4/:5, routes.py:39/:62/:63/:185, misc.py:19/:35,
 *   request.py:47/:190, config.py:42-64, search.py:29, utils/results.py:
 *   34-48 site-alt URL envs (SSRF context), __init__.py:43/:46/:81/:127),
 *   the os.environ.get reads (routes.py:187/:232/:648, request.py:213-217/
 *   :288) and the os.environ[...] writes (routes.py:626-638,
 *   request.py:65/:70)); the argparse CLI boundary
 *   of run_app (parser.parse_args() routes.py:622 plus the args.<field>
 *   reads :624/:629/:630/:637/:640/:641/:642/:646 - operator trust, none
 *   is a file path); the url_decode steps (urlparse.unquote/unquote_plus
 *   at routes.py:285/:348/:383/:410, request.py:163, filter.py:634/:639/
 *   :641/:643 - percent-decode nodes relevant to path semantics; quote/
 *   urlencode are encoding and are NOT emitted); and the request-derived
 *   internal API parameters with true positions (Config.from_params
 *   params config.py:182 - receives g.request_params; Search.__init__
 *   request search.py:58 - receives the flask request; Request.__init__
 *   normal_ua + root_path request.py:188 - receive the User-Agent header
 *   and request.url_root; get_proxy_host_url r misc.py:41; get_client_ip
 *   r misc.py:27; gen_file_hash path + static_file misc.py:10;
 *   gen_bangs_json bangs_file bangs.py:8). NOT present (verified, none
 *   assumed): multipart uploads (request.files never read), URL route
 *   variables (all route strings are static Endpoint enum values), and
 *   archive-entry names (no zipfile/tarfile anywhere). Raw BQRS
 *   extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/whoogle-search/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name ("args"/"form"/"data"/"headers"
 *                   for the request layer reads, "get" for the .get boundary
 *                   calls, "to_dict" for the form boundary, "request_params"
 *                   for the alias reads, "session" for the session subscripts,
 *                   "environ"/"full_path"/"get" for the r-param reads,
 *                   "getenv"/"get"/"environ" for the env family, "parse_args"
 *                   for the CLI boundary plus the argparse field name for
 *                   cli_arg rows, "unquote"/"unquote_plus" for the decode
 *                   steps, the function name for param rows)
 *   4. flow_kind  - "http_args"/"http_form"/"http_data"/"http_headers"/
 *                   "http_cookies"/"http_values"/"http_json"/"http_url"/
 *                   "http_method"/"http_auth" (request layer reads and .get
 *                   calls), "http_params_alias" (g.request_params /
 *                   self.request_params alias reads and .get calls),
 *                   "session" (flask session subscripts), "wsgi_environ"
 *                   (r.environ reads), "env" (os.getenv / os.environ.get /
 *                   os.environ subscripts - operator trust, labeling to
 *                   classify), "cli" (parse_args boundary), "cli_arg"
 *                   (argparse Namespace field reads - operator trust),
 *                   "url_decode" (urlparse.unquote/unquote_plus),
 *                   "param" (request-derived internal API parameters)
 *   5. receiver   - syntactic receiver hint ("request" for layer reads,
 *                   "request.args"/"request.headers" etc. for .get calls,
 *                   "request.form" for the to_dict boundary, "g"/"g.request_params"/
 *                   "self"/"self.request_params" for the alias family,
 *                   "session" for session subscripts, "r"/"r.headers"/
 *                   "r.environ" for the r-param reads, "os"/"os.environ"
 *                   for the env family, "parser"/"args" for the CLI family,
 *                   "urlparse" for the decode family, "" for module-level
 *                   parameter rows, the enclosing class name for method
 *                   parameter rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "flask.request"/"flask.g"/"flask.session" for the
 *                   request/session channels, "os" for the env family,
 *                   "argparse" for the parse boundary, "urllib.parse" for
 *                   the decode family
 *   7. arg_index  - 0-based positional argument index when a call argument
 *                   carries the value (0 = the key position of the request
 *                   .get calls, the env var name position of the env
 *                   family, and the decoded string position of the
 *                   url_decode family; 0 = the dict key position of the
 *                   session and os.environ subscripts); -1 when the value
 *                   is the attribute/return value itself (layer reads,
 *                   to_dict, alias reads, cli_arg reads, parse_args); for
 *                   "param" rows the true parameter position in the
 *                   function definition, including the self slot for
 *                   methods
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
 * a row). In this project NO source row is expected to resolve at API level:
 * flask/werkzeug are external libraries not part of the database (only the
 * whoogle-search tree is), the request layers flow through attribute chains
 * on the unresolved local names `request`/`g`/`session`/`r`/`self`, and the
 * env/CLI/decode families are os/argparse/urllib member calls on unresolved
 * module names. All families below are AST-level matches and the match_kind
 * column is kept "ast" for cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /test/ (unit test tree - the
 * workflow noise rule) and /whoogle-search-db/ (the CodeQL database
 * directory nested inside the source tree; it contains no .py files, the
 * filter is defensive). misc/ is kept in scope (dev scripts; no source rows
 * are expected there - replit.py has no file/request access and
 * update-translations.py reads no env vars). Ground-truth-looking artifacts
 * at the repo root (WHOOSE-* reports, path_traversal_sinks.csv) were never
 * opened (experiment independence).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  have no dotted module name; their file base name is used instead. */
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
  path.replaceAll("\\", "/").matches("%/test/%")
  or
  path.replaceAll("\\", "/").matches("%/whoogle-search-db/%")
}

/** True iff name is one of the flask request data layers read in this
 *  project (args/form/data/headers/method/url_root/authorization are the
 *  ones actually used; the other layer names are kept so any future use
 *  matches). Only literal string comparisons are used in the body. */
private predicate isRequestLayerName(string name) {
  name = "args" or name = "form" or name = "data" or name = "headers" or
  name = "cookies" or name = "values" or name = "json" or
  name = "url" or name = "url_root" or name = "full_path" or name = "path" or
  name = "method" or name = "authorization"
}

/** Maps a flask request layer name to its flow kind. */
private predicate requestLayerFlowKind(string name, string flowKind) {
  (name = "args" and flowKind = "http_args")
  or
  (name = "form" and flowKind = "http_form")
  or
  (name = "data" and flowKind = "http_data")
  or
  (name = "headers" and flowKind = "http_headers")
  or
  (name = "cookies" and flowKind = "http_cookies")
  or
  (name = "values" and flowKind = "http_values")
  or
  (name = "json" and flowKind = "http_json")
  or
  (name = "url" and flowKind = "http_url")
  or
  (name = "url_root" and flowKind = "http_url")
  or
  (name = "full_path" and flowKind = "http_url")
  or
  (name = "path" and flowKind = "http_url")
  or
  (name = "method" and flowKind = "http_method")
  or
  (name = "authorization" and flowKind = "http_auth")
}

/** True iff name is one of the run_app() argparse field names
 *  (operator-trust CLI boundary; none of them is a file path). */
private predicate isCliArgName(string name) {
  name = "port" or name = "host" or name = "unix_socket" or
  name = "debug" or name = "https_only" or name = "userpass" or
  name = "proxyauth" or name = "proxytype" or name = "proxyloc"
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* -------------------------------------------------------------- */
  /* family 1: flask request-layer attribute reads on the local name
     `request` (from flask import request): request.args (routes.py:54
     membership check in auth_required, :141 the before_request method
     branch, :358/:524/:544 'nojs'/'cookies_disabled' membership, :426/:442
     'name' in request.args guards of THE /config chain), request.form
     (:141), request.data (:275/:282/:284/:286 autocomplete), request.
     headers (:164/:246 object of the User-Agent get), request.url_root
     (:161/:165 before_request, :504 window), request.method (:141/:423),
     request.authorization (:59 auth_required), plus the inner layer nodes
     used as call receivers. The attribute itself carries the value
     (arg_index -1). */
  exists(Attribute a, string layerName |
    a.getObject().(Name).getId() = "request" and
    layerName = a.getName() and
    isRequestLayerName(layerName) and
    requestLayerFlowKind(layerName, flowKind) and
    node = a and
    callableName = layerName and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* family 1b: the self.request.<layer> variant inside Search (search.py:129
     self.request.url_root, the object passed to get_proxy_host_url at
     :127-130); the flask request is stored on self in Search.__init__ */
  exists(Attribute a, Attribute req, string layerName |
    req = a.getObject().(Attribute) and
    req.getName() = "request" and
    req.getObject().(Name).getId() = "self" and
    layerName = a.getName() and
    isRequestLayerName(layerName) and
    requestLayerFlowKind(layerName, flowKind) and
    node = a and
    callableName = layerName and
    argIndex = -1 and
    receiver = "self.request" and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 2: .get()/.getlist() boundary calls on the request layers -
     THE request.args.get('name') rows of the /config route (routes.py:429
     PUT read-side, :447 POST write-side - attacker-controlled file-name
     input joined onto CONFIG_PATH), request.args.get('tbm') (:253/:254
     opensearch), request.args.get('imgurl'/'url'/'type'/'location')
     (:459/:466/:476/:497 imgres/element/window), request.headers.get(
     'User-Agent') (:164/:246, search.py:62). Argument 0 carries the key;
     the return value is the tainted value. */
  exists(Call c, Attribute func, Attribute layer, string layerName |
    func = c.getFunc().(Attribute) and
    (func.getName() = "get" or func.getName() = "getlist") and
    layer = func.getObject().(Attribute) and
    layerName = layer.getName() and
    layer.getObject().(Name).getId() = "request" and
    isRequestLayerName(layerName) and
    requestLayerFlowKind(layerName, flowKind) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "request." + layerName and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 3: the request.form.to_dict() boundary at routes.py:437 -
     POST /config config_data, the full form dict stored into session
     ['config'] and partially into the pickle write; the return value
     carries the value (arg_index -1) */
  exists(Call c, Attribute func, Attribute layer |
    func = c.getFunc().(Attribute) and
    func.getName() = "to_dict" and
    layer = func.getObject().(Attribute) and
    layer.getName() = "form" and
    layer.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "http_form" and
    callableName = "to_dict" and
    argIndex = -1 and
    receiver = "request.form" and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 4: the g.request_params alias - assigned request.args or
     request.form per method in before_request (routes.py:140-142) and
     read at :158 (from_params argument) plus the g.request_params.get
     ('q') autocomplete row (:271); also the self.request_params alias in
     Search (search.py:69 'tbm' membership + .get('tbm'), :94 .get('q')).
     These rows mark the request-value propagation channel that Phase 2
     must bridge with summary edges. */
  exists(Attribute a |
    a.getObject().(Name).getId() = "g" and
    a.getName() = "request_params" and
    node = a and
    flowKind = "http_params_alias" and
    callableName = "request_params" and
    argIndex = -1 and
    receiver = "g" and
    moduleHint = "flask.g" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func, Attribute layer |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    layer = func.getObject().(Attribute) and
    layer.getName() = "request_params" and
    layer.getObject().(Name).getId() = "g" and
    node = c and
    flowKind = "http_params_alias" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "g.request_params" and
    moduleHint = "flask.g" and
    matchKind = "ast"
  )
  or
  exists(Attribute a |
    a.getObject().(Name).getId() = "self" and
    a.getName() = "request_params" and
    normalizedPathOf(a).matches("%/app/utils/search.py") and
    node = a and
    flowKind = "http_params_alias" and
    callableName = "request_params" and
    argIndex = -1 and
    receiver = "self" and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func, Attribute layer |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    layer = func.getObject().(Attribute) and
    layer.getName() = "request_params" and
    layer.getObject().(Name).getId() = "self" and
    normalizedPathOf(c).matches("%/app/utils/search.py") and
    node = c and
    flowKind = "http_params_alias" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "self.request_params" and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 5: flask session subscripts - session['auth'] (routes.py:55
     read, :68 write, :152 write), session['uuid']/:key (writes :151/:152),
     session['config'] (:149 write of default_config, :155 the Config(**
     session['config']) reload, :317/:318/:319 the TorError branch,
     :432 the PUT /config fallback, :449 the POST /config write of
     request.form data), session['error_message'] (:210/:211). Signed
     cookie-backed store whose 'config' key is attacker-influenced via
     POST /config - semi-trusted, emitted for the labeling step to
     classify. Index argument 0 carries the dict key. */
  exists(Subscript s |
    s.getObject().(Name).getId() = "session" and
    node = s and
    flowKind = "session" and
    callableName = "session" and
    argIndex = 0 and
    receiver = "session" and
    moduleHint = "flask.session" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 6: proxy/Wsgi-environ reads on the flask Request parameter r
     of misc.py helpers (r.headers.get('X-Forwarded-Proto') :42,
     r.headers.get('X-Forwarded-Host') :43, r.environ.get(
     'HTTP_X_FORWARDED_FOR') :28, r.environ['REMOTE_ADDR'] :31,
     r.full_path :45). Trust depends on ProxyFix (app/__init__.py:26);
     these feed URL construction, not file paths - emitted for
     completeness. Argument 0 carries the key; the attribute itself for
     full_path. */
  exists(Call c, Attribute func, Attribute layer, string layerName |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    layer = func.getObject().(Attribute) and
    layerName = layer.getName() and
    (layerName = "headers" or layerName = "environ") and
    layer.getObject().(Name).getId() = "r" and
    (layerName = "headers" and flowKind = "http_headers"
     or
     layerName = "environ" and flowKind = "wsgi_environ") and
    node = c and
    callableName = "get" and
    argIndex = 0 and
    receiver = "r." + layerName and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  exists(Subscript s, Attribute layer |
    layer = s.getObject().(Attribute) and
    layer.getName() = "environ" and
    layer.getObject().(Name).getId() = "r" and
    node = s and
    flowKind = "wsgi_environ" and
    callableName = "environ" and
    argIndex = 0 and
    receiver = "r.environ" and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  exists(Attribute a |
    a.getObject().(Name).getId() = "r" and
    a.getName() = "full_path" and
    node = a and
    flowKind = "http_url" and
    callableName = "full_path" and
    argIndex = -1 and
    receiver = "r" and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 7: environment reads - os.getenv(...) (version.py:4/:5,
     routes.py:39/:62/:63/:185, misc.py:19/:35, request.py:47/:190,
     config.py:42-64, search.py:29, utils/results.py:34-48 - the site-alt
     URL envs, SSRF context not paths, __init__.py:43/:46/:81/:127) and
     os.environ.get(...) (routes.py:187/:232/:648, request.py:213/:215/
     :216/:217/:288) plus os.environ[...] subscripts (routes.py:626-638
     writes, request.py:65/:70 writes). OPERATOR/deployment trust, NOT
     request trust - notably WHOOGLE_TOR_CONF (request.py:47) whose value
     is os.path.isfile-checked and then opened at request.py:48-55.
     Emitted so the labeling step can classify the trust boundary; the
     workflow's rule is that env values are not automatically attacker
     sources. Argument 0 carries the variable name; subscripts carry it
     at index position 0. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "getenv" and
    func.getObject().(Name).getId() = "os" and
    (normalizedPathOf(c).matches("%/app/%") or
     normalizedPathOf(c).matches("%/misc/%")) and
    node = c and
    flowKind = "env" and
    callableName = "getenv" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func, Attribute envattr |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    envattr = func.getObject().(Attribute) and
    envattr.getName() = "environ" and
    envattr.getObject().(Name).getId() = "os" and
    (normalizedPathOf(c).matches("%/app/%") or
     normalizedPathOf(c).matches("%/misc/%")) and
    node = c and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Subscript s, Attribute envattr |
    envattr = s.getObject().(Attribute) and
    envattr.getName() = "environ" and
    envattr.getObject().(Name).getId() = "os" and
    (normalizedPathOf(s).matches("%/app/%") or
     normalizedPathOf(s).matches("%/misc/%")) and
    node = s and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 8: the argparse CLI boundary of run_app() - the
     parser.parse_args() call (routes.py:622, sys.argv when run as a
     console script) and the args.<field> attribute reads (:624 userpass,
     :629 proxytype/proxyloc, :630 proxyauth, :637 https_only, :640 debug,
     :641/:646 host/port, :642 unix_socket). OPERATOR trust level; none of
     these fields is a file path (they set ports/hosts/flags/env creds) -
     emitted for boundary completeness so labeling can classify them. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "parse_args" and
    func.getObject().(Name).getId() = "parser" and
    normalizedPathOf(c).matches("%/app/routes.py") and
    node = c and
    flowKind = "cli" and
    callableName = "parse_args" and
    argIndex = -1 and
    receiver = "parser" and
    moduleHint = "argparse" and
    matchKind = "ast"
  )
  or
  exists(Attribute a, string argName |
    a.getObject().(Name).getId() = "args" and
    argName = a.getName() and
    isCliArgName(argName) and
    normalizedPathOf(a).matches("%/app/routes.py") and
    node = a and
    flowKind = "cli_arg" and
    callableName = argName and
    argIndex = -1 and
    receiver = "args" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 9: url_decode steps - urlparse.unquote/unquote_plus calls on
     query/URL values (routes.py:285 autocomplete double-decode of
     request.data, :348/:383/:410 display of the query, request.py:163
     gen_query unquoted comparison, filter.py:634/:639/:641/:643 element
     URL/image decodes). urllib.parse is imported as `urlparse`
     (import urllib.parse as urlparse). Percent-decode nodes are recorded
     because a decoded value can change path semantics; quote/quote_plus/
     urlencode are encoding and are NOT emitted. Argument 0 carries the
     decoded string. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "unquote" or func.getName() = "unquote_plus") and
    func.getObject().(Name).getId() = "urlparse" and
    normalizedPathOf(c).matches("%/app/%") and
    node = c and
    flowKind = "url_decode" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "urlparse" and
    moduleHint = "urllib.parse" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 10: request-derived internal API parameters (candidates for
     summary/propagation labeling). Positions include the self slot for
     methods. */

  /* Config.from_params(self, params) - params at position 1: receives
     g.request_params (request.args/request.form) in before_request
     (routes.py:158); filters KEYS via is_safe_key (config.py:200-211) but
     not values. app/models/config.py:182 */
  exists(Function fn, Parameter p |
    fn.getName() = "from_params" and
    fn.getEnclosingScope().(Class).getName() = "Config" and
    normalizedPathOf(fn).matches("%/app/models/config.py") and
    p = fn.getArgByName("params") and
    node = p and
    flowKind = "param" and
    callableName = "from_params" and
    argIndex = p.getPosition() and
    receiver = "Config" and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  /* Search.__init__(self, request, config, session_key, ...) - request at
     position 1: the whole flask request object, whose args/form/headers
     are read at search.py:61-62. app/utils/search.py:58 */
  exists(Function fn, Parameter p |
    fn.getName() = "__init__" and
    fn.getEnclosingScope().(Class).getName() = "Search" and
    normalizedPathOf(fn).matches("%/app/utils/search.py") and
    p = fn.getArgByName("request") and
    node = p and
    flowKind = "param" and
    callableName = "__init__" and
    argIndex = p.getPosition() and
    receiver = "Search" and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  /* Request.__init__(self, normal_ua, root_path, config) - normal_ua at
     position 1 (carries request.headers User-Agent, routes.py:164) and
     root_path at position 2 (carries request.url_root). app/request.py:188 */
  exists(Function fn, Parameter p |
    fn.getName() = "__init__" and
    fn.getEnclosingScope().(Class).getName() = "Request" and
    normalizedPathOf(fn).matches("%/app/request.py") and
    p = fn.getArgByName("normal_ua") and
    node = p and
    flowKind = "param" and
    callableName = "__init__" and
    argIndex = p.getPosition() and
    receiver = "Request" and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  exists(Function fn, Parameter p |
    fn.getName() = "__init__" and
    fn.getEnclosingScope().(Class).getName() = "Request" and
    normalizedPathOf(fn).matches("%/app/request.py") and
    p = fn.getArgByName("root_path") and
    node = p and
    flowKind = "param" and
    callableName = "__init__" and
    argIndex = p.getPosition() and
    receiver = "Request" and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  /* get_proxy_host_url(r, default, root=False) - r at position 0: the
     flask Request whose headers/environ/full_path are read (misc.py:28-45).
     app/utils/misc.py:41 */
  exists(Function fn, Parameter p |
    fn.getName() = "get_proxy_host_url" and
    normalizedPathOf(fn).matches("%/app/utils/misc.py") and
    p = fn.getArgByName("r") and
    node = p and
    flowKind = "param" and
    callableName = "get_proxy_host_url" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  /* get_client_ip(r) - r at position 0: the flask Request whose environ is
     read (misc.py:28-31). app/utils/misc.py:27 */
  exists(Function fn, Parameter p |
    fn.getName() = "get_client_ip" and
    normalizedPathOf(fn).matches("%/app/utils/misc.py") and
    p = fn.getArgByName("r") and
    node = p and
    flowKind = "param" and
    callableName = "get_client_ip" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  /* gen_file_hash(path, static_file) - path at position 0 and static_file
     at position 1: the path-consuming internal helper whose
     open(os.path.join(path, static_file), 'rb') is the cache-busting read
     (misc.py:11, called from __init__.py:156 with listdir results).
     app/utils/misc.py:10 */
  exists(Function fn, Parameter p |
    fn.getName() = "gen_file_hash" and
    normalizedPathOf(fn).matches("%/app/utils/misc.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "param" and
    callableName = "gen_file_hash" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  exists(Function fn, Parameter p |
    fn.getName() = "gen_file_hash" and
    normalizedPathOf(fn).matches("%/app/utils/misc.py") and
    p = fn.getArgByName("static_file") and
    node = p and
    flowKind = "param" and
    callableName = "gen_file_hash" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  /* gen_bangs_json(bangs_file) - bangs_file at position 0: the output
     path of the DDG bangs fetch thread (open(bangs_file, 'w') at
     bangs.py:38; DDG content, not request input - boundary row for
     labeling). app/utils/bangs.py:8 */
  exists(Function fn, Parameter p |
    fn.getName() = "gen_bangs_json" and
    normalizedPathOf(fn).matches("%/app/utils/bangs.py") and
    p = fn.getArgByName("bangs_file") and
    node = p and
    flowKind = "param" and
    callableName = "gen_bangs_json" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(p) and
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
