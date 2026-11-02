/**
 * @name django CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   Django 2.2.26 framework-source CodeQL database (snapshot sha c9f648c):
 *   the URL-resolver-injected view arguments (the `path` parameter of
 *   django.views.static.serve at views/static.py:19 and of
 *   contrib.staticfiles.views.serve at contrib/staticfiles/views.py:15 - both
 *   documented for the (?P<path>.*)$ URLconf pattern; the `packages`/`domain`
 *   kwargs reads of JavaScriptCatalog.get at views/i18n.py:195/:198; the
 *   self.kwargs['template'] subscript of admindocs TemplateDetailView at
 *   contrib/admindocs/views.py:322); the WSGI request-path origin
 *   (get_bytes_from_wsgi(environ, 'PATH_INFO'|'SCRIPT_NAME'|'SCRIPT_URL'|
 *   'REDIRECT_URL'|'QUERY_STRING', ...) in core/handlers/wsgi.py:105/:158/
 *   :186/:189 - PATH_INFO is what WSGIRequest turns into request.path at
 *   wsgi.py:71-:80); every request.<attr> attribute read package-wide (GET,
 *   POST, COOKIES - including the session-key read at contrib/sessions/
 *   middleware.py:19 - META, FILES, headers, body, path, path_info, as
 *   initialized in http/request.py:52-:59); keyed .get() reads on those
 *   request dicts (e.g. views/static.py:45 request.META.get(
 *   'HTTP_IF_MODIFIED_SINCE'), views/i18n.py:34/:43 request.POST.get); the
 *   multipart upload filename boundary (disposition.get('filename') at
 *   http/multipartparser.py:205 plus its RFC2231 unquote() decode at :687,
 *   feeding FileUploadHandler.new_file's `file_name` parameter at
 *   core/files/uploadhandler.py:93 and UploadedFile._set_name's `name`
 *   parameter at core/files/uploadedfile.py:39 - the parser's own
 *   sanitize_file_name docstring says the result is still untrusted); the
 *   cookie-derived session key entering the file session store
 *   (SessionStore.__init__ `session_key` parameter, contrib/sessions/
 *   backends/file.py:20, joined into a filesystem path by _key_to_file at
 *   :55); the CLI boundary of TemplateCommand startproject/startapp (the
 *   `name`/`target` parameters and handle_template's `template` and
 *   download's `url` parameters at core/management/templates.py:59/:180/
 *   :238 - operator/CLI trust level, kept for the labeling step to judge);
 *   and the package-wide os.environ.get environment reads (deployer trust
 *   level - conf/__init__.py:57, core/management/color.py:73,
 *   core/management/utils.py:53/:58, core/management/__init__.py:206/:252/
 *   :253 - also left for labeling to judge). Raw BQRS extraction query: run
 *   with `codeql query run` and decode with `codeql bqrs decode` (not
 *   database analyze). This is a plain multi-column select query on purpose:
 *   @kind problem is the wrong shape for candidate tables and @kind table is
 *   not assumed to exist.
 * @id iris/django/extraction/sources
 * @tags path-traversal
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql and to the prior IRIS manual
 * projects aiohttp/airflow/ansible/coderedcms/copyparty):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field/parameter name (e.g. "serve", "get",
 *                   "get_bytes_from_wsgi", "file_name", "session_key")
 *   4. flow_kind  - "route_param" (URL-resolver-injected view argument),
 *                   "http_path" (WSGI environ path / request.path/path_info),
 *                   "http_query_raw" (WSGI QUERY_STRING), "http_query"
 *                   (request.GET), "http_form" (request.POST), "http_cookie"
 *                   (request.COOKIES), "http_meta" (request.META),
 *                   "http_files" (request.FILES), "http_header"
 *                   (request.headers), "http_body" (request.body),
 *                   "multipart_filename" (upload filename boundary),
 *                   "upload_name" (UploadedFile name setter boundary),
 *                   "session_key" (cookie-derived session store key),
 *                   "cli_param" (CLI positional), "cli_url" (CLI --template
 *                   URL), "env" (os.environ.get read),
 *                   "http_url_decode" (percent-decode call)
 *   5. receiver   - syntactic receiver hint ("request", "self.kwargs",
 *                   "kwargs", "disposition", "self" for method-parameter rows,
 *                   the function name for module-function-parameter rows, ""
 *                   for bare-name calls)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module` is not
 *                   a valid QL variable name here); literal module hints
 *                   "urllib.parse" for the unquote family and "os" for the
 *                   stdlib family
 *   7. arg_index  - 0-based positional index carrying the controlled value:
 *                   the 0-based parameter position (including self) for
 *                   parameter rows, index 0 for keyed reads, index 1 for the
 *                   WSGI environ key position, -1 for plain attribute reads
 *   8. file       - absolute file path, obtained through the Location API
 *                   (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates/functions), does not
 * assign API::Node values to DataFlow::Node variables, keeps every variable
 * bound through a positive body, and keeps resolved-API matching strictly
 * separate from AST syntax matching (the match_kind column records which one
 * produced a row). Only the os.environ.get family resolves at API level here
 * (API::moduleImport("os").getMember("environ").getMember("get").getACall());
 * every other family is a first-party parameter/attribute/subscript/bare-name
 * call, matched at AST level. String literals are matched with the
 * StringLiteral class and its getS() accessor (the shape of the locally
 * installed codeql/python-all 7.1.2; the legacy StrConst/Str spellings and a
 * getValue() accessor are not used).
 *
 * Scope (applied to every row): %/django_vuln/django/% (the shipped django
 * package), EXCLUDING the nested %/django-db/% database directory (also
 * outside the positive scope by construction - 'django-db' does not match
 * %/django/%), %/django/test/% (in-package test tooling) and
 * %/django/contrib/admin/bin/% (manually run asset-build script). Top-level
 * tests/, docs/, extras/ and scripts/ are outside the positive scope.
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

/** True iff the candidate's file path is inside the audited django package
 *  (%/django_vuln/django/% but not the in-package test tooling, not the
 *  admin asset-build script and not the nested %/django-db/% database
 *  directory). bindingset[path] declares that the caller passes a bound path
 *  (the path only appears in checked positions such as the receiver of
 *  replaceAll/matches inside this predicate). */
bindingset[path]
predicate djangoSourcePath(string path) {
  path.replaceAll("\\", "/").matches("%/django_vuln/django/%") and
  not path.replaceAll("\\", "/").matches("%/django-db/%") and
  not path.replaceAll("\\", "/").matches("%/django_vuln/django/test/%") and
  not path.replaceAll("\\", "/").matches("%/django_vuln/django/contrib/admin/bin/%")
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/** Flow kind of a request-object attribute read (request.<name>). */
private string requestAttrFlowKind(string name) {
  result = "http_query" and name = "GET"
  or
  result = "http_form" and name = "POST"
  or
  result = "http_cookie" and name = "COOKIES"
  or
  result = "http_meta" and name = "META"
  or
  result = "http_files" and name = "FILES"
  or
  result = "http_header" and name = "headers"
  or
  result = "http_body" and name = "body"
  or
  result = "http_path" and name in ["path", "path_info"]
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: the route-injected static-file path: the `path` parameter of
     django.views.static.serve (views/static.py:19). The docstring documents
     the URLconf shape url(r'^(?P<path>.*)$', serve, {'document_root': ...})
     - the full request path (after script-name stripping) arrives here and
     is normpath'd + lstrip('/')'d at :35 before safe_join at :36. */
  exists(Function f, Parameter p |
    normalizedPathOf(f).matches("%/django/views/static.py") and
    f.getName() = "serve" and
    p = f.getAnArg() and
    p.getName() = "path" and
    node = p and
    flowKind = "route_param" and
    callableName = "serve" and
    argIndex = p.getPosition() and
    receiver = "serve" and
    moduleHint = "django.views.static" and
    matchKind = "ast"
  )
  or
  /* family 2: the route-injected staticfiles path: the `path` parameter of
     contrib.staticfiles.views.serve (contrib/staticfiles/views.py:15),
     normpath'd + lstrip('/')'d at :32 then resolved through
     finders.find() at :33 before delegation to static.serve at :39. */
  exists(Function f, Parameter p |
    normalizedPathOf(f).matches("%/django/contrib/staticfiles/views.py") and
    f.getName() = "serve" and
    p = f.getAnArg() and
    p.getName() = "path" and
    node = p and
    flowKind = "route_param" and
    callableName = "serve" and
    argIndex = p.getPosition() and
    receiver = "serve" and
    moduleHint = "django.contrib.staticfiles.views" and
    matchKind = "ast"
  )
  or
  /* family 3: the route-injected template name: the self.kwargs['template']
     subscript of admindocs TemplateDetailView.get_context_data
     (contrib/admindocs/views.py:322) - the URL pattern supplies the
     template name that is safe_join'd onto the engine template dirs and
     opened at :332/:334. */
  exists(Subscript s, Attribute kw |
    kw = s.getObject().(Attribute) and
    kw.getName() = "kwargs" and
    kw.getObject().(Name).getId() = "self" and
    normalizedPathOf(s).matches("%/django/contrib/admindocs/views.py") and
    node = s and
    flowKind = "route_param" and
    callableName = "kwargs" and
    argIndex = 0 and
    receiver = "self.kwargs" and
    moduleHint = "django.contrib.admindocs.views" and
    matchKind = "ast"
  )
  or
  /* family 4: the route-injected i18n catalog selectors: kwargs.get(
     'domain', ...) at views/i18n.py:195 and kwargs.get('packages', '') at
     :198 - the plus-sign delimited packages string from the URL controls
     which app locale directories are joined at get_paths (:205-:214). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Name).getId() = "kwargs" and
    normalizedPathOf(c).matches("%/django/views/i18n.py") and
    node = c and
    flowKind = "route_param" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "kwargs" and
    moduleHint = "django.views.i18n" and
    matchKind = "ast"
  )
  or
  /* family 5: the WSGI request-path origin: get_bytes_from_wsgi(environ,
     key, default) calls in core/handlers/wsgi.py. PATH_INFO (get_path_info
     :158 and get_script_name :186 - both feed WSGIRequest.path/path_info at
     :69-:80), SCRIPT_NAME, SCRIPT_URL and REDIRECT_URL carry the request
     URL; QUERY_STRING (:105) carries the raw query string. The key literal
     sits at argument 1. */
  exists(Call c, StringLiteral key |
    c.getFunc().(Name).getId() = "get_bytes_from_wsgi" and
    normalizedPathOf(c).matches("%/django/core/handlers/wsgi.py") and
    key = c.getArg(1).(StringLiteral) and
    key.getS() in ["PATH_INFO", "SCRIPT_NAME", "SCRIPT_URL", "REDIRECT_URL", "QUERY_STRING"] and
    node = c and
    callableName = "get_bytes_from_wsgi" and
    argIndex = 1 and
    receiver = "" and
    moduleHint = "django.core.handlers.wsgi" and
    matchKind = "ast" and
    (
      key.getS() = "QUERY_STRING" and flowKind = "http_query_raw"
      or
      key.getS() != "QUERY_STRING" and flowKind = "http_path"
    )
  )
  or
  /* family 6: request-object attribute reads package-wide: every
     request.<attr> read where <attr> is one of the HttpRequest data
     containers (initialized at http/request.py:52-:59; headers is the
     cached_property at :70-:72 over META). Includes the session-key
     container read at contrib/sessions/middleware.py:19 (request.COOKIES)
     and the raw body stream reads via request.body (:278). */
  exists(Attribute a |
    a.getName() in ["GET", "POST", "COOKIES", "META", "FILES", "headers", "body", "path", "path_info"] and
    a.getObject().(Name).getId() = "request" and
    requestAttrFlowKind(a.getName()) = flowKind and
    node = a and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 7: keyed reads on the request dicts: request.<dict>.get(key) -
     argument 0 names the key whose value is returned. Sites include
     views/static.py:45 (request.META.get('HTTP_IF_MODIFIED_SINCE')),
     views/i18n.py:34/:43 (request.POST.get('next'/'language')),
     contrib/sessions/middleware.py:19 (request.COOKIES.get(
     SESSION_COOKIE_NAME) - THE session-key source). */
  exists(Call c, Attribute func, Attribute reqattr |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    reqattr = func.getObject().(Attribute) and
    reqattr.getObject().(Name).getId() = "request" and
    requestAttrFlowKind(reqattr.getName()) = flowKind and
    node = c and
    callableName = "get" and
    argIndex = 0 and
    receiver = "request." + reqattr.getName() and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 8: the multipart upload filename boundary:
     disposition.get('filename') at http/multipartparser.py:205 - the
     client-supplied Content-Disposition filename parameter, BEFORE
     sanitize_file_name (html.unescape + basename rsplit at :296-:315, whose
     own docstring states the result must still be treated as untrusted
     user input). Argument 0 is the parameter name 'filename'. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Name).getId() = "disposition" and
    normalizedPathOf(c).matches("%/django/http/multipartparser.py") and
    node = c and
    flowKind = "multipart_filename" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "disposition" and
    moduleHint = "django.http.multipartparser" and
    matchKind = "ast"
  )
  or
  /* family 9: the RFC2231 percent-decode boundary: unquote(...) calls in
     http/multipartparser.py:687 (filename*=UTF-8''... values inside
     parse_header) and views/i18n.py:38 (the HTTP_REFERER 'next' value).
     Argument 0 is the percent-encoded attacker value. */
  exists(Call c |
    c.getFunc().(Name).getId() = "unquote" and
    (
      normalizedPathOf(c).matches("%/django/http/multipartparser.py")
      or
      normalizedPathOf(c).matches("%/django/views/i18n.py")
    ) and
    node = c and
    flowKind = "http_url_decode" and
    callableName = "unquote" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "urllib.parse" and
    matchKind = "ast"
  )
  or
  /* family 10: the upload handler filename boundary: the `file_name`
     parameter of FileUploadHandler.new_file (core/files/uploadhandler.py:93)
     - the sanitized-but-untrusted multipart filename handed to every
     registered upload handler (TemporaryFileUploadHandler builds
     TemporaryUploadedFile from it at :140). 0-based position including
     self: self=0, field_name=1, file_name=2. */
  exists(Function f, Parameter p |
    normalizedPathOf(f).matches("%/django/core/files/uploadhandler.py") and
    f.getName() = "new_file" and
    p = f.getAnArg() and
    p.getName() = "file_name" and
    node = p and
    flowKind = "multipart_filename" and
    callableName = "new_file" and
    argIndex = p.getPosition() and
    receiver = "self" and
    moduleHint = "django.core.files.uploadhandler" and
    matchKind = "ast"
  )
  or
  /* family 11: the uploaded-file name boundary: the `name` parameter of
     UploadedFile._set_name (core/files/uploadedfile.py:39) - every
     UploadedFile.name assignment passes through this setter (basename +
     255-char truncation + validate_file_name at :43-:51); the stored name
     later reaches the storage layer through FileField/FieldFile. 0-based
     position including self. */
  exists(Function f, Parameter p |
    normalizedPathOf(f).matches("%/django/core/files/uploadedfile.py") and
    f.getName() = "_set_name" and
    p = f.getAnArg() and
    p.getName() = "name" and
    node = p and
    flowKind = "upload_name" and
    callableName = "_set_name" and
    argIndex = p.getPosition() and
    receiver = "self" and
    moduleHint = "django.core.files.uploadedfile" and
    matchKind = "ast"
  )
  or
  /* family 12: the cookie-derived session key: the `session_key` parameter
     of the file session store's SessionStore.__init__
     (contrib/sessions/backends/file.py:20). SessionMiddleware constructs it
     from request.COOKIES.get(SESSION_COOKIE_NAME) at
     contrib/sessions/middleware.py:19-:20; the key is joined into a
     filesystem path by _key_to_file at :55 (guarded by the VALID_KEY_CHARS
     subset check at :51). 0-based position including self. */
  exists(Function f, Parameter p |
    normalizedPathOf(f).matches("%/django/contrib/sessions/backends/file.py") and
    f.getName() = "__init__" and
    p = f.getAnArg() and
    p.getName() = "session_key" and
    node = p and
    flowKind = "session_key" and
    callableName = "__init__" and
    argIndex = p.getPosition() and
    receiver = "self" and
    moduleHint = "django.contrib.sessions.backends.file" and
    matchKind = "ast"
  )
  or
  /* family 13: the CLI boundary of startproject/startapp: the `name` and
     `target` parameters of TemplateCommand.handle
     (core/management/templates.py:59 - name is joined onto os.getcwd() at
     :68 and target is abspath'ed/expanduser'd at :76), the `template`
     parameter of handle_template (:180 - the --template value: local path,
     file:// path or URL) and the `url` parameter of download (:238).
     Operator/CLI trust level - kept for the labeling step to judge. 0-based
     positions including self. */
  exists(Function f, Parameter p |
    normalizedPathOf(f).matches("%/django/core/management/templates.py") and
    f.getName() in ["handle", "handle_template", "download"] and
    p = f.getAnArg() and
    p.getName() in ["name", "target", "template", "url"] and
    node = p and
    (
      p.getName() = "url" and flowKind = "cli_url"
      or
      p.getName() != "url" and flowKind = "cli_param"
    ) and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = "self" and
    moduleHint = "django.core.management.templates" and
    matchKind = "ast"
  )
  or
  /* family 14a: environment reads, resolved via API graphs: os.environ.get(
  ...) package-wide. Deployer trust level, NOT attacker input - kept for
     the labeling step to judge per the boundary rule. Sites in scope:
     conf/__init__.py:57 (DJANGO_SETTINGS_MODULE), core/management/
     color.py:73 (DJANGO_COLORS), compilemessages.py:62, core/management/
     utils.py:53/:58 (PATH/PATHEXT), core/management/__init__.py:206/:252/
     :253. Argument 0 is the variable name. */
  exists(API::CallNode cn |
    cn = API::moduleImport("os").getMember("environ").getMember("get").getACall() and
    node = astCallOf(cn) and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "api"
  )
  or
  /* family 14b: syntax-level fallback of the same os.environ.get family
     (qualified os.environ.get(...) calls; all uses in this codebase are
     qualified). */
  exists(Call c, Attribute func, Attribute env |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    env = func.getObject().(Attribute) and
    env.getName() = "environ" and
    env.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  djangoSourcePath(normalizedPathOf(node))
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
