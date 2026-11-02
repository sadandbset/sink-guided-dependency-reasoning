/**
 * @name aiohttp CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   aiohttp CodeQL database (snapshot 33ccdfb0, aiohttp 4.0.0a2.dev0 - the
 *   aiohttp framework itself is the audit target): aiohttp server request
 *   path state reads (request.path / request.raw_path / request.path_qs /
 *   request.rel_url attribute reads and the request.rel_url.raw_path /
 *   .path / .query / .query_string attribute chains that feed the router,
 *   e.g. web_urldispatcher.py:616 StaticResource.resolve and :997
 *   UrlDispatcher.resolve, web_middlewares.py:86-109
 *   normalize_path_middleware); request header reads
 *   (request.headers.get(...) call sites at web_fileresponse.py:145,
 *   web_app.py:380, web_urldispatcher.py:309/:804, web_protocol.py:682,
 *   web_log.py:128, and request.headers[...] subscripts); the routed path
 *   variable boundary (request.match_info['filename'] subscript read at
 *   web_urldispatcher.py:635 in StaticResource._handle - the single
 *   routed-variable read that feeds the static-file path construction -
 *   plus request.match_info attribute reads); the multipart upload filename
 *   family (field.filename reads at web_request.py:724/:745 in
 *   request.post() FileField construction, multipart.py:552
 *   value.filename, and content_disposition_filename(...) calls at
 *   multipart.py:532/:541, client_reqrep.py:804 - the filename value never
 *   reaches a filesystem path in this tree, the content goes to an
 *   auto-named tempfile.TemporaryFile()); the HTTP wire request-line parse
 *   (http_parser.py:556 line.split(' ', maxsplit=2) in the pure-Python
 *   parser); the percent-decode boundary (_unquote_path(...) calls at
 *   web_urldispatcher.py:625 StaticResource.resolve and :472
 *   DynamicResource._match, defined at :1242-1243 as
 *   URL.build(path=value, encoded=True).path); environment reads
 *   (os.environ.get('NETRC') at helpers.py:197 flowing into Path(netrc_env)
 *   at :200 and the netrc file read at :218, plus AIOHTTP_NO_EXTENSIONS /
 *   PYTHONASYNCIODEBUG / AIOHTTP_NOSENDFILE reads); CLI input
 *   (sys.argv at web.py:599 for the argparse-based `python -m aiohttp.web`
 *   entry whose -U/--path unix-socket argument flows to run_app(path=...),
 *   and tools/check_changes.py:35 Path(argv[0])); the framework-injected
 *   request entry parameters (parameters named `request` of server-side
 *   functions in the web_*.py modules - StaticResource._handle, the
 *   resolve/match overloads, Application._handle, FileResponse.prepare
 *   etc.) and the raw wire data parameters (data/chunk of feed_data at
 *   http_parser.py:286/:648/:785/:935 and data_received at
 *   web_protocol.py:358). Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose: @kind
 *   problem is the wrong shape for candidate tables and @kind table is not
 *   assumed to exist.
 * @id iris/aiohttp/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (e.g. "raw_path", "match_info",
 *                   "filename", "content_disposition_filename", "split",
 *                   "_unquote_path", "get", "argv", the function name for
 *                   parameter rows)
 *   4. flow_kind  - "http_path" (request.path/raw_path/path_qs/rel_url state,
 *                   incl. request.rel_url.<member> chains), "http_request"
 *                   (request.query/query_string/headers/cookies state),
 *                   "http_header" (request.headers.get(...) /
 *                   request.headers[...] keyed reads), "route_var"
 *                   (request.match_info[...] keyed reads and the
 *                   request.match_info read), "multipart_filename"
 *                   (field.filename reads and
 *                   content_disposition_filename(...) results),
 *                   "http_wire" (request-line split in the pure-Python
 *                   parser), "url_decode" (_unquote_path percent-decode),
 *                   "env" (os.environ family), "cli" (sys.argv/argv/args.path),
 *                   "param" (framework-injected request parameters and raw
 *                   wire data parameters)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "request"/"request.headers"/
 *                   "request.match_info"/"os"/"sys"/"line"/"field" etc., or
 *                   "" if none; "<expr>" when the object expression is
 *                   neither Name nor Attribute; enclosing class name for
 *                   parameter rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "os"/"sys"/"aiohttp.multipart" for env/cli/multipart
 *                   families
 *   7. arg_index  - 0-based positional argument index (index of the key
 *                   argument for keyed reads; parameter position in the
 *                   function definition for "param" rows, including the
 *                   self slot for methods), -1 if N/A
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
 * the request objects, match_info mappings, multipart fields, os.environ and
 * sys.argv are framework-injected or interpreter-provided values, not module
 * members, so all families below are AST-level matches and the match_kind
 * column is kept "ast" for cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (integration and unit test
 * trees), /aiohttp-db/ (the CodeQL database directory sits inside the source
 * tree), /docs/, /node_modules/. examples/ and tools/ are kept in scope
 * (bootstrap/dev scripts - rows expected to be labeled none/FP).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  (setup.py, scripts/*.py) have no dotted module name; their file base name
 *  is used instead. */
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
  path.replaceAll("\\", "/").matches("%/aiohttp-db/%")
  or
  path.replaceAll("\\", "/").matches("%/docs/%")
  or
  path.replaceAll("\\", "/").matches("%/node_modules/%")
}

/* ------------------------------------------------------------------ */
/* Shared aiohttp shapes (kept consistent with sinks.ql)                */
/* ------------------------------------------------------------------ */

/** Request state fields that carry the request URL path (reify properties on
 *  BaseRequest, web_request.py:444-467; read sites are the router and the
 *  normalize-path middleware). */
private predicate requestPathField(string field) {
  field = "path"
  or
  field = "raw_path"
  or
  field = "path_qs"
  or
  field = "rel_url"
  or
  field = "url"
}

/** Request state fields carrying other request state (query/headers/cookies;
 *  query and cookies have no package-internal read sites beyond their
 *  definitions - the family is kept as a shape for cross-project recall). */
private predicate requestStateField(string field) {
  field = "query"
  or
  field = "query_string"
  or
  field = "headers"
  or
  field = "cookies"
  or
  field = "match_info"
}

/** Server-side web modules whose `request` parameters are the
 *  framework-injected entry points carrying all HTTP input.
 *  bindingset[path]: the callers pass a bound path (normalizedPathOf of a
 *  bound node); `matches` is a checked position that does not bind its
 *  receiver, so without the annotation the body cannot bind `path`. */
bindingset[path]
private predicate serverRequestModule(string path) {
  path.matches("%/aiohttp/web_urldispatcher.py")
  or
  path.matches("%/aiohttp/web_app.py")
  or
  path.matches("%/aiohttp/web_fileresponse.py")
  or
  path.matches("%/aiohttp/web_middlewares.py")
  or
  path.matches("%/aiohttp/web_protocol.py")
  or
  path.matches("%/aiohttp/web_server.py")
  or
  path.matches("%/aiohttp/web_response.py")
  or
  path.matches("%/aiohttp/web_log.py")
  or
  path.matches("%/aiohttp/web_ws.py")
  or
  path.matches("%/aiohttp/web_exceptions.py")
}

/** Modules where a bare `<obj>.filename` attribute read denotes a multipart
 *  upload filename (BodyPartReader.filename / FileField.filename).
 *  bindingset[path]: same checked-position rationale as
 *  serverRequestModule. */
bindingset[path]
private predicate multipartModule(string path) {
  path.matches("%/aiohttp/web_request.py")
  or
  path.matches("%/aiohttp/multipart.py")
  or
  path.matches("%/aiohttp/payload.py")
  or
  path.matches("%/aiohttp/formdata.py")
  or
  path.matches("%/aiohttp/client_reqrep.py")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: request path state attribute reads: request.path /
     request.raw_path / request.path_qs / request.rel_url / request.url
     (web_middlewares.py:86/:87/:91/:95/:97/:109, the rel_url reads of
     family 2's chains; the properties are defined at web_request.py:444-467;
     request.path/raw_path also appear bare in web_middlewares) */
  exists(Attribute a |
    requestPathField(a.getName()) and
    a.getObject().(Name).getId() = "request" and
    node = a and
    flowKind = "http_path" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 2: request.rel_url.<member> attribute chains - the router reads
     request.rel_url.raw_path at web_urldispatcher.py:616
     (StaticResource.resolve) and :997 (UrlDispatcher.resolve); the raw,
     not-yet-decoded request path used for route matching */
  exists(Attribute a, Attribute base |
    base = a.getObject().(Attribute) and
    base.getName() = "rel_url" and
    base.getObject().(Name).getId() = "request" and
    (
      a.getName() = "raw_path"
      or
      a.getName() = "path"
      or
      a.getName() = "query"
      or
      a.getName() = "query_string"
      or
      a.getName() = "fragment"
    ) and
    node = a and
    (
      (a.getName() = "raw_path" or a.getName() = "path") and
      flowKind = "http_path"
      or
      (a.getName() = "query" or a.getName() = "query_string" or
       a.getName() = "fragment") and
      flowKind = "http_request"
    ) and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "request.rel_url" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 3: other request state attribute reads: request.query /
     request.query_string / request.headers / request.cookies /
     request.match_info (no package-internal read sites beyond definitions
     observed for query/cookies; match_info read sites exist inside
     request.match_info[...] subscripts captured by family 5) */
  exists(Attribute a |
    requestStateField(a.getName()) and
    a.getObject().(Name).getId() = "request" and
    node = a and
    (
      a.getName() = "match_info" and flowKind = "route_var"
      or
      not a.getName() = "match_info" and flowKind = "http_request"
    ) and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 4: request.headers.get(...) call sites (argument 0 carries the
     header key): web_fileresponse.py:145 ACCEPT_ENCODING (toggles the .gz
     sibling lookup only), web_app.py:380 EXPECT, web_urldispatcher.py:309
     EXPECT / :804 HOST, web_protocol.py:682 Accept, web_log.py:128 */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    base = func.getObject().(Attribute) and
    base.getName() = "headers" and
    base.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "http_header" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "request.headers" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 4b: request.headers[...] subscript reads (index carries the key;
     no literal-index sites observed in the package - shape kept for recall) */
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "headers" and
    base.getObject().(Name).getId() = "request" and
    node = s and
    flowKind = "http_header" and
    callableName = "headers" and
    argIndex = 0 and
    receiver = "request.headers" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 5: routed path variable reads: request.match_info[...] subscript
     reads - web_urldispatcher.py:635 request.match_info["filename"] in
     StaticResource._handle is the routed (percent-decoded by
     StaticResource.resolve at :625) filename that feeds Path() at :637 */
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "match_info" and
    base.getObject().(Name).getId() = "request" and
    node = s and
    flowKind = "route_var" and
    callableName = "match_info" and
    argIndex = 0 and
    receiver = "request.match_info" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 6: multipart upload filename attribute reads: <obj>.filename
     where the receiver is a plain local name in the multipart-handling
     modules (web_request.py:724 field.filename / :745 field.filename in
     request.post() FileField construction; multipart.py:552
     value.filename). The filename never reaches a filesystem path in this
     tree (content goes to tempfile.TemporaryFile() at web_request.py:726)
     - emitted for labeling to classify the boundary. */
  exists(Attribute a |
    a.getName() = "filename" and
    a.getObject() instanceof Name and
    multipartModule(normalizedPathOf(a)) and
    node = a and
    flowKind = "multipart_filename" and
    callableName = "filename" and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 7: Content-Disposition filename parsing calls:
     content_disposition_filename(...) (multipart.py:532 name, :541
     filename - BodyPartReader.name/filename properties; client-side
     mirror client_reqrep.py:804); the return value carries the
     attacker-supplied multipart filename */
  exists(Call c |
    c.getFunc().(Name).getId() = "content_disposition_filename" and
    node = c and
    flowKind = "multipart_filename" and
    callableName = "content_disposition_filename" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = "aiohttp.multipart" and
    matchKind = "ast"
  )
  or
  /* family 8: HTTP wire request-line parse in the pure-Python parser:
     line.split(" ", maxsplit=2) at http_parser.py:556 (the C-extension
     parser _http_parser.pyx is not part of the database); the result
     tuple carries method/path/version straight off the socket */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "split" and
    func.getObject().(Name).getId() = "line" and
    normalizedPathOf(c).matches("%/aiohttp/http_parser.py") and
    node = c and
    flowKind = "http_wire" and
    callableName = "split" and
    argIndex = -1 and
    receiver = "line" and
    moduleHint = "aiohttp.http_parser" and
    matchKind = "ast"
  )
  or
  /* family 9: percent-decode boundary: _unquote_path(...) calls
     (web_urldispatcher.py:625 StaticResource.resolve - decodes the raw
     path remainder into the "filename" match variable; :472
     DynamicResource._match - decodes dynamic-route match values; helper
     defined at :1242-1243 as URL.build(path=value, encoded=True).path -
     exactly one decode pass between wire and filename) */
  exists(Call c |
    c.getFunc().(Name).getId() = "_unquote_path" and
    node = c and
    flowKind = "url_decode" and
    callableName = "_unquote_path" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 10: environment reads: os.environ / os.environ[...] /
     os.environ.get(...) (helpers.py:197 NETRC - flows into Path(netrc_env)
     at :200 and the netrc file read at :218; helpers.py:77
     AIOHTTP_NO_EXTENSIONS; helpers.py:80 PYTHONASYNCIODEBUG;
     web_fileresponse.py:38 AIOHTTP_NOSENDFILE - operator/local-process
     trust level, only NETRC is path-relevant) */
  exists(Attribute a |
    a.getName() = "environ" and
    a.getObject().(Name).getId() = "os" and
    node = a and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "environ" and
    base.getObject().(Name).getId() = "os" and
    node = s and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    base = func.getObject().(Attribute) and
    base.getName() = "environ" and
    base.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 11: CLI input: sys.argv attribute reads and sys.argv[...] /
     argv[...] subscripts (web.py:599 main(sys.argv[1:]) - the argparse-based
     `python -m aiohttp.web` entry whose -U/--path unix-socket argument
     flows to run_app(path=...); tools/check_changes.py:35 Path(argv[0])) */
  exists(Attribute a |
    a.getName() = "argv" and
    a.getObject().(Name).getId() = "sys" and
    node = a and
    flowKind = "cli" and
    callableName = "argv" and
    argIndex = -1 and
    receiver = "sys" and
    moduleHint = "sys" and
    matchKind = "ast"
  )
  or
  exists(Subscript s |
    (
      s.getObject().(Attribute).getName() = "argv" and
      s.getObject().(Attribute).getObject().(Name).getId() = "sys"
      or
      s.getObject().(Name).getId() = "argv"
    ) and
    node = s and
    flowKind = "cli" and
    callableName = "argv" and
    argIndex = 0 and
    receiver = "argv" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 12: framework-injected request entry parameters: parameters
     named `request` of server-side functions in the web_*.py modules
     (web_urldispatcher.py:634 StaticResource._handle, :132/:347/:615/:740/
     :846 resolve overloads, :763/:803 match, :303
     _default_expect_handler, :912 SystemRoute._handle, :928 View._iter;
     web_app.py:373 Application._handle; web_fileresponse.py:143
     FileResponse.prepare; web_middlewares/web_protocol/web_log
     request-taking helpers) - these objects carry all HTTP input; self is
     excluded; arg_index is the 0-based position in the function
     definition including the self slot for methods */
  exists(Function f, Parameter p |
    p.getName() = "request" and
    p = f.getAnArg() and
    not p.isSelf() and
    serverRequestModule(normalizedPathOf(f)) and
    node = p and
    flowKind = "param" and
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
  /* family 13: raw wire data parameters: `data`/`chunk` parameters of
     feed_data (http_parser.py:286/:648/:785/:935 - the pure-Python
     incremental parsers) and data_received (web_protocol.py:358 - the
     asyncio protocol callback) - raw bytes off the socket before any
     parsing */
  exists(Function f, Parameter p |
    (
      f.getName() = "feed_data" and
      normalizedPathOf(f).matches("%/aiohttp/http_parser.py")
      or
      f.getName() = "data_received" and
      normalizedPathOf(f).matches("%/aiohttp/web_protocol.py")
    ) and
    p = f.getAnArg() and
    (p.getName() = "data" or p.getName() = "chunk") and
    not p.isSelf() and
    node = p and
    flowKind = "param" and
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
