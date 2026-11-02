
/**
 * @name Django source candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate external-input source nodes from the
 *              Django 3.1.12 framework source for subsequent LLM labeling.
 * @id py/augur/django/pass3-sources
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * This database contains ONLY the Django framework source (the django/
 * package plus framework tests and root dev tooling). There is no user
 * application code, so source candidates anchor on the framework's own
 * request boundaries (WSGI environ / ASGI scope), request-field reads
 * inside framework views/middleware, host-header-derived URL
 * construction, the two CLI URL inputs that reach the framework's
 * urlopen/urlretrieve fetch sites, and environment reads.
 *
 * Verified API usage (codeql/python-all 7.1.2):
 *   - Parameter is a Name-or-Tuple AST node; parameter names are read
 *     via p.asName().getId().
 *   - Parameter positions include `self` as index 0 for methods
 *     (WSGIRequest.__init__(self, environ) -> environ at index 1).
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("source_candidate")
 *  3. callable name       (dotted signature hint)
 *  4. flow kind           (param | return | field)
 *  5. receiver hint       (receiver/type hint)
 *  6. module hint         (dotted module path; variable named moduleHint,
 *                          "module" is a QL keyword and must not be used)
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
 * Restrict extraction to the Django framework package.
 *
 * The CodeQL database source root is the repository root, so relative
 * paths of framework files look like "django/http/request.py".
 * "django/%" cannot match the nested "django-db/" database directory
 * (position 6 is '-' vs '/'), and tests are additionally excluded
 * (django/test/ tree, tests/ tree, and any module named tests.py
 * at any depth).
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("django/%") and
    not path.matches("django/test/%") and
    not path.matches("tests/%") and
    not path.matches("%/tests.py")
  )
}

/**
 * Restrict a candidate to one framework module. The path string is
 * bound by equality before any comparison, so no unbound-variable
 * error can occur.
 */
predicate inModule(AstNode n, string relPath) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path = relPath
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
// 2. Django request-shape signatures (verified against this source)
// ------------------------------------------------------------

/**
 * HttpRequest fields whose contents originate from the HTTP client
 * (query string, form body, cookies, headers, request line, scheme
 * via the server/proxy). Framework-internal fields (resolver_match,
 * user, session, content_type, ...) are intentionally excluded and
 * documented in detection.json.
 */
predicate isClientRequestField(string name) {
  name in [
    "GET",
    "POST",
    "COOKIES",
    "META",
    "FILES",
    "body",
    "headers",
    "path",
    "path_info",
    "method",
    "scheme"
  ]
}

/**
 * HttpRequest methods whose return values are URLs or URL components
 * built from the client-supplied Host header (see
 * django/http/request.py:100-117 _get_raw_host, :185-194 get_raw_uri,
 * :196-231 build_absolute_uri, :233-234 _current_scheme_host).
 */
predicate isRequestUrlConstructor(string name) {
  name in [
    "get_host",
    "build_absolute_uri",
    "get_raw_uri"
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
    // (1) WSGI boundary: WSGIRequest.__init__(self, environ)
    //     django/core/handlers/wsgi.py:65 - environ carries the
    //     query string, all HTTP headers, and the body stream;
    //     earliest untrusted boundary for every WSGI request.
    //     Parameter positions include self at index 0.
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "__init__" and
      p.asName().getId() = "environ" and
      inModule(f, "django/core/handlers/wsgi.py") and
      callableName = "WSGIRequest.__init__" and
      flowKind = "param" and
      receiverHint = "django.core.handlers.wsgi.WSGIRequest" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (2) WSGI boundary: WSGIHandler.__call__(self, environ,
    //     start_response) - django/core/handlers/wsgi.py:129
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "__call__" and
      p.asName().getId() = "environ" and
      inModule(f, "django/core/handlers/wsgi.py") and
      callableName = "WSGIHandler.__call__" and
      flowKind = "param" and
      receiverHint = "django.core.handlers.wsgi.WSGIHandler" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (3) ASGI boundary: ASGIRequest.__init__(self, scope,
    //     body_file) - django/core/handlers/asgi.py:31 - scope
    //     carries method, path, query_string, headers, client.
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "__init__" and
      p.asName().getId() = "scope" and
      inModule(f, "django/core/handlers/asgi.py") and
      callableName = "ASGIRequest.__init__" and
      flowKind = "param" and
      receiverHint = "django.core.handlers.asgi.ASGIRequest" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (4) ASGI boundary: ASGIRequest.__init__(self, scope,
    //     body_file) - body_file is the spooled request body.
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "__init__" and
      p.asName().getId() = "body_file" and
      inModule(f, "django/core/handlers/asgi.py") and
      callableName = "ASGIRequest.__init__" and
      flowKind = "param" and
      receiverHint = "django.core.handlers.asgi.ASGIRequest" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (5) ASGI boundary: ASGIHandler.__call__(self, scope,
    //     receive, send) - django/core/handlers/asgi.py:136
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "__call__" and
      p.asName().getId() = "scope" and
      inModule(f, "django/core/handlers/asgi.py") and
      callableName = "ASGIHandler.__call__" and
      flowKind = "param" and
      receiverHint = "django.core.handlers.asgi.ASGIHandler" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (6) request.<field> reads on a `request` name
    //     e.g. django/views/i18n.py:34 request.POST.get('next'),
    //          django/middleware/common.py:125
    //          request.META.get('HTTP_REFERER'),
    //          django/contrib/admin/views/autocomplete.py:26
    //          request.GET.get('term', '')
    //     The Attribute node itself is the materialization of the
    //     client-controlled value, whether it is read directly,
    //     chained (.get(...)), or subscripted (request.META[...]).
    // --------------------------------------------------------

    exists(Attribute a, Name req |
      n = a and
      isClientRequestField(a.getName()) and
      req = a.getObject() and
      req.getId() = "request" and
      callableName = "request." + a.getName() and
      flowKind = "field" and
      receiverHint = "django.http.HttpRequest" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (7) self.request.<field> reads (class-based views)
    //     e.g. django/views/generic/edit.py:44 self.request.POST,
    //          django/contrib/auth/views.py:71
    //          self.request.POST.get(...)
    // --------------------------------------------------------

    exists(Attribute a, Attribute reqAttr, Name selfName |
      n = a and
      isClientRequestField(a.getName()) and
      reqAttr = a.getObject() and
      reqAttr.getName() = "request" and
      selfName = reqAttr.getObject() and
      selfName.getId() = "self" and
      callableName = "request." + a.getName() and
      flowKind = "field" and
      receiverHint = "django.http.HttpRequest" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (8) request.get_host() / request.build_absolute_uri() /
    //     request.get_raw_uri() calls - URLs built from the
    //     client-supplied Host header.
    //     e.g. django/middleware/security.py:28,
    //          django/middleware/common.py:48,94,123,
    //          django/utils/cache.py:331,339,
    //          django/contrib/sites/requests.py:10,
    //          django/contrib/auth/decorators.py:22
    // --------------------------------------------------------

    exists(Call c, Attribute method, Name req |
      n = c and
      method = c.getFunc() and
      isRequestUrlConstructor(method.getName()) and
      req = method.getObject() and
      req.getId() = "request" and
      callableName = "request." + method.getName() and
      flowKind = "return" and
      receiverHint = "django.http.HttpRequest" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (9) self.request.get_host() / self.request.build_absolute_uri()
    //     calls - e.g. django/contrib/auth/views.py:37
    // --------------------------------------------------------

    exists(Call c, Attribute method, Attribute reqAttr, Name selfName |
      n = c and
      method = c.getFunc() and
      isRequestUrlConstructor(method.getName()) and
      reqAttr = method.getObject() and
      reqAttr.getName() = "request" and
      selfName = reqAttr.getObject() and
      selfName.getId() = "self" and
      callableName = "request." + method.getName() and
      flowKind = "return" and
      receiverHint = "django.http.HttpRequest" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (10) ping_google(sitemap_url, ping_url, ...) and
    //      _get_sitemap_full_url(sitemap_url, ...) parameters in
    //      django/contrib/sitemaps/__init__.py - caller-controlled
    //      URL inputs that reach urlopen()
    //      (ping_url defaults to the hardcoded PING_URL constant;
    //       the in-tree caller is the `ping_google` management
    //       command, i.e. a CLI boundary)
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      (f.getName() = "ping_google" or f.getName() = "_get_sitemap_full_url") and
      (p.asName().getId() = "sitemap_url" or p.asName().getId() = "ping_url") and
      inModule(f, "django/contrib/sitemaps/__init__.py") and
      callableName = f.getName() + "." + p.asName().getId() and
      flowKind = "param" and
      receiverHint = "django.contrib.sitemaps" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (11) TemplateCommand URL parameters:
    //      handle_template(self, template, subdir) (line 185) and
    //      download(self, url) (line 244) in
    //      django/core/management/templates.py - the CLI
    //      `--template` option value that reaches urlretrieve()
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      inModule(f, "django/core/management/templates.py") and
      (
        (f.getName() = "handle_template" and p.asName().getId() = "template")
        or
        (f.getName() = "download" and p.asName().getId() = "url")
      ) and
      callableName = "TemplateCommand." + f.getName() and
      flowKind = "param" and
      receiverHint = "django.core.management.templates.TemplateCommand" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (12) Management CLI boundary: argv parameters of command-line
    //      entry points in django/core/management/__init__.py
    //      (ManagementUtility.__init__ line 175,
    //       execute_from_command_line line 398)
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      p.asName().getId() = "argv" and
      inModule(f, "django/core/management/__init__.py") and
      callableName = f.getName() + ".argv" and
      flowKind = "param" and
      receiverHint = "django.core.management" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (13) os.environ.get(...) environment reads
    //     e.g. django/conf/__init__.py:60 (DJANGO_SETTINGS_MODULE),
    //          django/utils/autoreload.py:404,615,
    //          django/core/management/color.py:72
    // --------------------------------------------------------

    exists(Call call, Attribute method, Attribute environ, Name osName |
      n = call and
      method = call.getFunc() and
      method.getName() = "get" and
      environ = method.getObject() and
      environ.getName() = "environ" and
      osName = environ.getObject() and
      osName.getId() = "os" and
      callableName = "os.environ.get" and
      flowKind = "return" and
      receiverHint = "os.environ" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (14) os.getenv(...) environment reads
    // --------------------------------------------------------

    exists(Call call, Attribute method, Name osName |
      n = call and
      method = call.getFunc() and
      method.getName() = "getenv" and
      osName = method.getObject() and
      osName.getId() = "os" and
      callableName = "os.getenv" and
      flowKind = "return" and
      receiverHint = "os" and
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
