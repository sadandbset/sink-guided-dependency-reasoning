/**
 * Augur Pass 1 (Path Traversal, CWE-22/23/36/73) - source model for the
 * Django 2.2.26 (django_vuln) CodeQL database.
 *
 * Rendered deterministically from the reviewed Phase 1 labels
 * (iris/labels/labels.json, run django-pathtraversal-pass1-step3-20261022).
 * Only entries with role=source AND classification=tp are modeled
 * (194 label rows -> the 7 rule families below). Candidate-classified
 * source rows (views/i18n.py kwargs.get('domain'/'packages'), src-0092/
 * src-0093) are deliberately NOT modeled: they were left for human review
 * in labels/phase1_review.md and no approval is on record.
 *
 * Every rule is AST-shape based (same idioms as the Step 2 extraction
 * queries, which compiled against the locally installed
 * codeql/python-all 7.1.2): `module` is never used as a variable name,
 * API::Node and DataFlow::Node are never mixed, and no AST accessor that
 * does not exist in the installed pack is called (AstNode.getLocation().
 * getFile().getAbsolutePath(), Attribute.getName()/getObject(), Subscript.
 * getObject(), Call.getFunc()/getArg(), Function.getAnArg(), Parameter.
 * getName()/getPosition(), StringLiteral.getS(), DataFlow::parameterNode).
 *
 * Label-rule mapping and per-site source evidence:
 *   isStaticServePathParameter   src-0180, src-0206 (route_param/param)
 *   isAdmindocsKwargsSubscript   src-0197..src-0200 (route_param/field)
 *   isRequestAttribute           140 rows: http_path 35, http_meta 32,
 *                                 http_form 45, http_query 20, http_files 3,
 *                                 http_cookie 5 (attribute reads)
 *   isRequestDictGetCall         39 rows: http_meta 19, http_form 9,
 *                                 http_query 9, http_cookie 2 (keyed .get())
 *   isWsgiEnvironExtraction      src-0207..src-0211 (get_bytes_from_wsgi)
 *   isMultipartFilename          src-0116 (disposition.get('filename'))
 *   isSessionKeyParameter        src-0077 (SessionStore.__init__ param 1)
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {


  /** Forward-slash-normalized absolute path of the file containing n. */
  private string normalizedPathOf(AstNode n) {
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
  }

  /** True iff n is inside the audited django package scope (the same scope
   *  predicate the Step 2 extraction queries applied to every row). */
  private predicate inAuditedDjangoTree(AstNode n) {
    normalizedPathOf(n).matches("%/django_vuln/django/%") and
    not normalizedPathOf(n).matches("%/django-db/%") and
    not normalizedPathOf(n).matches("%/django_vuln/django/test/%") and
    not normalizedPathOf(n).matches("%/django_vuln/django/contrib/admin/bin/%")
  }

  /**
   * Holds if `n` is the `path` parameter of one of the two static-serving
   * views. Labels src-0180 / src-0206.
   *
   * Evidence: django/views/static.py:19 `def serve(request, path, document_root
   * =None, ...)` with the docstring route `url(r'^(?P<path>.*)$', serve,
   * {'document_root': ...})` - the URL resolver injects the full request path
   * into `path`; django/contrib/staticfiles/views.py:15 `def serve(request,
   * path, insecure=False, **kwargs)` with the same documented route. Both are
   * remote, unauthenticated input boundaries (DEBUG-only static serving).
   */
  private predicate isStaticServePathParameter(DataFlow::Node n) {
    exists(Function f, Parameter p |
      f.getName() = "serve" and
      p = f.getAnArg() and
      p.getName() = "path" and
      (
        normalizedPathOf(f).matches("%/django/views/static.py")
        or
        normalizedPathOf(f).matches("%/django/contrib/staticfiles/views.py")
      ) and
      n = DataFlow::parameterNode(p)
    )
  }

  /**
   * Holds if `n` is a `self.kwargs[...]` subscript in the admin-docs views.
   * Labels src-0197 (view), src-0198 (model_name), src-0199 (app_label),
   * src-0200 (template).
   *
   * Evidence: django/contrib/admindocs/views.py:322 `template =
   * self.kwargs['template']` in TemplateDetailView.get_context_data - URL-
   * captured template name flowing to Path(safe_join(directory, template))
   * at :332 and template_file.open() at :334; :157/:187/:190 are the same
   * resolver-injected kwargs shape (view/model_name/app_label) used for
   * module/model lookup. All four are unauthenticated-route inputs on
   * admin-docs pages (staff-only pages behind admin auth, still remote).
   */
  private predicate isAdmindocsKwargsSubscript(DataFlow::Node n) {
    exists(Subscript s, Attribute kw |
      kw = s.getObject().(Attribute) and
      kw.getName() = "kwargs" and
      kw.getObject().(Name).getId() = "self" and
      normalizedPathOf(s).matches("%/django/contrib/admindocs/views.py") and
      n.asExpr() = s
    )
  }

  /**
   * Holds if `n` is a `request.<attr>` attribute read. 140 label rows.
   *
   * Evidence: the HttpRequest containers are initialized from the WSGI
   * environ in django/http/request.py:52-:59 (GET/POST/COOKIES/META/FILES)
   * and request.path/path_info come from PATH_INFO (core/handlers/wsgi.py
   * :69-:80). Every matched site is request-processing code (middleware,
   * admin/auth views, handlers, debug/i18n views) where the value is fully
   * client-controlled (URL path, query string, form body, headers, cookies,
   * multipart). Access conditions: these reads are reachable from any HTTP
   * client; authentication (admin views) or DEBUG flags gate some sites but
   * never sanitize the path content.
   */
  private predicate isRequestAttribute(DataFlow::Node n) {
    exists(Attribute a |
      a.getName() in ["GET", "POST", "COOKIES", "META", "FILES", "path", "path_info"] and
      a.getObject().(Name).getId() = "request" and
      inAuditedDjangoTree(a) and
      n.asExpr() = a
    )
  }

  /**
   * Holds if `n` is the result of a keyed read `request.<dict>.get(key)`.
   * 39 label rows.
   *
   * Evidence: same request containers as isRequestAttribute; the keyed value
   * returned by .get() is the client-controlled entry, e.g. contrib/sessions/
   * middleware.py:19 `request.COOKIES.get(settings.SESSION_COOKIE_NAME)` (the
   * session-key source feeding the file session backend) and
   * views/static.py:45 `request.META.get('HTTP_IF_MODIFIED_SINCE')`. The
   * source node is the call result, so no receiver-to-result modeling of
   * MultiValueDict.get is required.
   */
  private predicate isRequestDictGetCall(DataFlow::Node n) {
    exists(Call c, Attribute func, Attribute reqattr |
      func = c.getFunc().(Attribute) and
      func.getName() = "get" and
      reqattr = func.getObject().(Attribute) and
      reqattr.getName() in ["GET", "POST", "COOKIES", "META", "FILES"] and
      reqattr.getObject().(Name).getId() = "request" and
      inAuditedDjangoTree(c) and
      n.asExpr() = c
    )
  }

  /**
   * Holds if `n` is a get_bytes_from_wsgi(environ, '<key>', ...) call result.
   * Labels src-0207..src-0211.
   *
   * Evidence: django/core/handlers/wsgi.py - the extraction keys are
   * PATH_INFO (:158 via get_path_info), SCRIPT_NAME (:186/:189),
   * SCRIPT_URL/REDIRECT_URL (:179) and QUERY_STRING (:105). These are the
   * lowest-level WSGI environ extractions that become request.path/path_info
   * and request.GET; the values are raw remote input bytes from the HTTP
   * request line and headers as passed by the front server.
   */
  private predicate isWsgiEnvironExtraction(DataFlow::Node n) {
    exists(Call c, StringLiteral key |
      c.getFunc().(Name).getId() = "get_bytes_from_wsgi" and
      normalizedPathOf(c).matches("%/django/core/handlers/wsgi.py") and
      key = c.getArg(1).(StringLiteral) and
      key.getS() in ["PATH_INFO", "SCRIPT_NAME", "SCRIPT_URL", "REDIRECT_URL", "QUERY_STRING"] and
      n.asExpr() = c
    )
  }

  /**
   * Holds if `n` is the multipart upload-filename boundary read
   * `disposition.get('filename')`. Label src-0116.
   *
   * Evidence: django/http/multipartparser.py:205 `file_name =
   * disposition.get('filename')` inside MultiPartParser.parse() - the
   * Content-Disposition filename parameter is fully client-controlled
   * (RFC2231 filename* values are percent-decoded by unquote() at :687 in
   * parse_header). The value then flows through force_text (:207) and
   * sanitize_file_name (:208, a labeled barrier) before reaching the upload
   * handler chain.
   */
  private predicate isMultipartFilename(DataFlow::Node n) {
    exists(Call c, Attribute func, StringLiteral key |
      func = c.getFunc().(Attribute) and
      func.getName() = "get" and
      func.getObject().(Name).getId() = "disposition" and
      normalizedPathOf(c).matches("%/django/http/multipartparser.py") and
      key = c.getArg(0).(StringLiteral) and
      key.getS() = "filename" and
      n.asExpr() = c
    )
  }

  /**
   * Holds if `n` is the `session_key` parameter of the file session store
   * constructor. Label src-0077.
   *
   * Evidence: django/contrib/sessions/backends/file.py:20
   * `def __init__(self, session_key=None)` - the parameter is not a plain
   * internal function argument: contrib/sessions/middleware.py:19-:20
   * instantiates `self.SessionStore(session_key)` with
   * `request.COOKIES.get(settings.SESSION_COOKIE_NAME)`, so the cookie value
   * (fully client-controlled) is injected here automatically. Inside the file
   * backend it reaches _key_to_file's os.path.join at :55 (guarded by the
   * inline VALID_KEY_CHARS subset check at :51 - a control-flow guard, see
   * report/query_generation_notes.md).
   */
  private predicate isSessionKeyParameter(DataFlow::Node n) {
    exists(Function f, Parameter p |
      f.getName() = "__init__" and
      p = f.getAnArg() and
      p.getName() = "session_key" and
      normalizedPathOf(f).matches("%/django/contrib/sessions/backends/file.py") and
      n = DataFlow::parameterNode(p)
    )
  }

  /**
   * Pass-1 source dispatch. The pass key is checked so the same library shape
   * can serve later passes; only "path_traversal" is enabled in this run.
   */
  predicate isSource(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      isStaticServePathParameter(n)
      or
      isAdmindocsKwargsSubscript(n)
      or
      isRequestAttribute(n)
      or
      isRequestDictGetCall(n)
      or
      isWsgiEnvironExtraction(n)
      or
      isMultipartFilename(n)
      or
      isSessionKeyParameter(n)
    )
  }

}
