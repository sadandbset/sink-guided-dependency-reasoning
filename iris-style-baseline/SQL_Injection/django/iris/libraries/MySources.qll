/**
 * Augur Phase 2 - Pass 5 (CWE-89 SQL Injection) source library.
 *
 * Project : django (CodeQL DB snapshot django-db, Django 4.2.0-alpha0, sha eb3699ea -
 *           file/line references below use snapshot numbering, NOT the 2.2.4 working tree)
 * Labels  : iris/labels/labels.json, pass 5 (approved at the Phase 1 review gate;
 *           see iris/labels/phase1_review.md)
 *
 * Label id -> modeling:
 *   p5-src-037  request.GET     field read  -> HttpRequestFieldRead
 *   p5-src-038  request.POST    field read  -> HttpRequestFieldRead
 *   p5-src-039  request.META    field read  -> HttpRequestFieldRead
 *   p5-src-040  request.COOKIES field read  -> HttpRequestFieldRead
 *   p5-src-041  request.FILES   field read  -> HttpRequestFieldRead
 *   p5-src-042  WSGI `environ` attribute reads (non-`os` receiver) -> WsgiEnvironRead
 *   p5-src-043  get_bytes_from_wsgi(...) call result -> GetBytesFromWsgiCall
 *   p5-src-044  request.<map>.get()/getlist() call result -> QueryDictAccessorCall
 *   p5-src-045  request.<map>.items()/copy()/urlencode() call result -> WholeMappingCall
 *   p5-src-046  `request` parameter of HTTP handler functions/methods -> HandlerRequestParam
 *   p5-src-047  self.kwargs (URL route parameters) -> UrlKwargsRead
 *
 * Deliberately NOT modeled (labels/phase1_review.md section 7, unmodified labels):
 *   p5-src-048 / p5-src-050 (management-CLI `options` / `sys.argv`, classification
 *   'candidate'): operator-level input; manage.py runs with database credentials and is
 *   not an attacker-reachable boundary in the audited threat model.
 *   p5-none-049..055 (parser.add_argument, open, read, os.environ, settings.<ATTR>,
 *   non-SQL internal wrappers): labeled fp for pass 5.
 *
 * Only the HTTP/WSGI request boundary (the audited attacker-controlled surface) is a
 * source; no function parameter of a cursor.execute-containing wrapper is treated as a
 * source by itself.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /** Holds if `n` is a source for the pass identified by `passKey`. */
  predicate isSource(DataFlow::Node n, string passKey) {
    passKey = "sql_injection" and
    (
      n instanceof HttpRequestFieldRead
      or n instanceof WsgiEnvironRead
      or n instanceof GetBytesFromWsgiCall
      or n instanceof QueryDictAccessorCall
      or n instanceof WholeMappingCall
      or n instanceof HandlerRequestParam
      or n instanceof UrlKwargsRead
    )
  }

  /** Holds if `e` refers to a request object (`request` or `self.request`). */
  private predicate requestish(Expr e) {
    e.toString().regexpMatch("(^|\\.)request$")
  }

  /**
   * Holds if `n` is inside the audited candidate scope: the Phase 1 extraction
   * filtered /tests/, /django-db/, /docs/, /js_tests/, /node_modules/ and /fixtures/
   * paths, so the query restricts itself to the same universe. Paths inside this
   * CodeQL database use forward slashes (verified against extraction CSVs).
   */
  private predicate inScope(AstNode n) {
    not excludedPath(n.getLocation().getFile().getAbsolutePath())
  }

bindingset[p]
  private predicate excludedPath(string p) {
    p.matches("%/tests/%")
    or p.matches("%/django-db/%")
    or p.matches("%/docs/%")
    or p.matches("%/js_tests/%")
    or p.matches("%/node_modules/%")
    or p.matches("%/fixtures/%")
  }

  /**
   * request.GET / request.POST / request.META / request.COOKIES / request.FILES
   * attribute reads (labels p5-src-037..041).
   * Evidence: django/contrib/admin/views/main.py:95-112 (ChangeList), :101
   * `request.GET.get(PAGE_VAR, 1)`; django/middleware/csrf.py:261-262
   * `request.META["CSRF_COOKIE"]`.
   */
  private class HttpRequestFieldRead extends DataFlow::Node {
    HttpRequestFieldRead() {
      exists(Attribute a |
        a.getName() in ["GET", "POST", "META", "COOKIES", "FILES"] and
        requestish(a.getObject()) and
        inScope(a) and
        this.asExpr() = a
      )
    }
  }

  /**
   * WSGI environ attribute reads with a non-`os` receiver (label p5-src-042);
   * `os.environ` reads were labeled fp (p5-none-053) and are excluded by the
   * receiver guard.
   * Evidence: django/core/handlers/wsgi.py WSGIRequest (`self.environ`), :144
   * `environ.get("wsgi.file_wrapper")` context.
   */
  private class WsgiEnvironRead extends DataFlow::Node {
    WsgiEnvironRead() {
      exists(Attribute a |
        a.getName() = "environ" and
        not a.getObject().toString() = "os" and
        inScope(a) and
        this.asExpr() = a
      )
    }
  }

  /**
   * Result of get_bytes_from_wsgi(environ, ...) - raw WSGI environ bytes such as
   * QUERY_STRING at the request parse boundary (label p5-src-043).
   * Evidence: django/core/handlers/wsgi.py:159/:180 call sites.
   */
  private class GetBytesFromWsgiCall extends DataFlow::Node {
    GetBytesFromWsgiCall() {
      exists(Call c |
        c.getFunc() instanceof Name and
        c.getFunc().(Name).getId() = "get_bytes_from_wsgi" and
        inScope(c) and
        this.asExpr() = c
      )
    }
  }

  /**
   * request.<GET|POST|META|COOKIES>.get(key) / .getlist(key) call results
   * (label p5-src-044; highest-signal source shape of the extraction).
   * Evidence: django/contrib/admin/views/main.py:106
   * `request.GET.get(TO_FIELD_VAR)`; django/middleware/common.py:41
   * `request.META.get(...)`.
   */
  private class QueryDictAccessorCall extends DataFlow::Node {
    QueryDictAccessorCall() {
      exists(Call c, Attribute fn, Attribute base |
        c.getFunc() = fn and
        fn.getName() in ["get", "getlist"] and
        fn.getObject() = base and
        base.getName() in ["GET", "POST", "META", "COOKIES"] and
        requestish(base.getObject()) and
        inScope(c) and
        this.asExpr() = c
      )
    }
  }

  /**
   * Whole-mapping reads of request input: request.<map>.items()/copy()/urlencode()
   * call results (label p5-src-045).
   * Evidence: django/contrib/admin/views/main.py:112
   * `self.params = dict(request.GET.items())`.
   */
  private class WholeMappingCall extends DataFlow::Node {
    WholeMappingCall() {
      exists(Call c, Attribute fn, Attribute base |
        c.getFunc() = fn and
        fn.getName() in ["items", "copy", "urlencode"] and
        fn.getObject() = base and
        base.getName() in ["GET", "POST", "COOKIES", "META"] and
        requestish(base.getObject()) and
        inScope(c) and
        this.asExpr() = c
      )
    }
  }

  /**
   * The `request` parameter of framework HTTP handler functions/methods
   * (label p5-src-046; 631 candidate rows over 323 handlers: admin ModelAdmin
   * views, middleware __call__/process_request/process_view, CBV verbs, auth
   * views, staticfiles serve, admindocs, GIS sitemaps). The parameter position
   * varies (0 for plain functions, 1 after `self` for methods), so the match is
   * by parameter name; a parameter named `request` that is itself `self` is
   * excluded.
   * Taint on the request object propagates through attribute reads
   * (request.GET[...], request.META[...]) by standard local flow.
   */
  private class HandlerRequestParam extends DataFlow::Node {
    HandlerRequestParam() {
      exists(Parameter p |
        p.getName() = "request" and
        not p.isSelf() and
        inScope(p) and
        this = DataFlow::parameterNode(p)
      )
    }
  }

  /**
   * self.kwargs attribute reads in class-based generic views - URL route
   * parameters (label p5-src-047).
   * Evidence: django/views/generic/detail.py:34-35
   * `pk = self.kwargs.get(self.pk_url_kwarg)`; dates.py:39+ `self.kwargs['year']`.
   */
  private class UrlKwargsRead extends DataFlow::Node {
    UrlKwargsRead() {
      exists(Attribute a |
        a.getName() = "kwargs" and
        a.getObject().toString() = "self" and
        inScope(a) and
        this.asExpr() = a
      )
    }
  }
}
