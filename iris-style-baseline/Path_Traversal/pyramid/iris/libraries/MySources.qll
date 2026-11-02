/**
 * Augur Phase 2 Step 4 — Pass 1 (Path Traversal) source model for pyramid.
 *
 * Machine-generated from iris/labels/labels.json (run
 * pyramid-pass1-pathtraversal-20261023, pass_id 1). Every rule renders exactly
 * the label entries with role=source (all 153 are classification=tp; the 98
 * role=none rows — CLI argv/argparse, ini settings, os.environ, config-time
 * asset specs, environ write targets, server WSGI keys, pviews/prequest CLI
 * requests — are excluded by the reviewed labeling decisions, see
 * iris/labels/phase1_review.md and iris/labels/label_stats.md).
 *
 * Rule groups and their label IDs:
 *  requestFieldRead      49 entries  S003-S026, S028-S034, S036-S053
 *                        (attribute reads of request.<field>: path_info,
 *                        subpath, path, url, path_url, query_string,
 *                        accept_encoding, environ, cookies, headers, POST,
 *                        params, GET, matchdict, locale_name)
 *  requestFieldSubscript 4 entries  S109 (traversal.py:631 environ[VH_ROOT]),
 *                        S114/S118 (authentication.py:1058/1146
 *                        environ['REMOTE_ADDR']), S119 (csrf.py:139
 *                        request.cookies[...])
 *  requestFieldLookup   15 entries  S144-S158 (request.<field>.get(...) calls)
 *  localDictGet          6 entries  S159-S164 (environ.get / matchdict.get on
 *                        locals bound from request.environ / request.matchdict)
 *  getattrRequestRead   17 entries  S121-S137 (getattr(request, ...) calls)
 *  entryParamSource     62 entries  S176-S239 (WSGI environ parameters and
 *                        request-object parameters of request-entry methods,
 *                        framework view wrappers, predicates and events)
 *
 * The attribute/lookup/getattr rules are the generalization of the audited
 * label sites (same node shapes as the validated extraction query
 * iris/extraction/sources.ql): they match by field name and receiver shape
 * ("request" / "self.request" / "self" for the locale_name reified property)
 * within the extraction scope (src/pyramid minus scripts/, testing.py,
 * config/testing.py, interfaces.py). No rendered source row lies under
 * scripts/ (verified against labels.json), so scripts are excluded to keep
 * the pviews/prequest CLI-simulated requests (labels role=none) out.
 *
 * Per the review rubric, an internal function parameter is NOT automatically
 * a source: the 62 parameter sources are restricted to the exact audited
 * (function, parameter-position, parameter-name, file, parameter-line) tuples
 * from the labels; nothing else is promoted.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  // --------------------------------------------------------------------------
  // Shared helpers (same shapes as the validated extraction query
  // iris/extraction/sources.ql, so the library matches exactly the node
  // universe the candidates were extracted from).
  // --------------------------------------------------------------------------

  /**
   * Gets the repository-relative path of the file containing this node, e.g.
   * "src/pyramid/static.py". On this Windows-created database
   * getRelativePath() may yield backslash forms or no result, so fall back to
   * capturing the "src/pyramid/..." suffix from the absolute path.
   */
  private string relPath(AstNode n) {
    exists(string p |
      p = n.getLocation().getFile().getRelativePath() and
      result = p.replaceAll("\\", "/")
    )
    or
    not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/").regexpCapture(".*/(src/pyramid/.+)$", 1)
  }

  /**
   * Restricts nodes to the extraction scope of iris/extraction/sources.ql:
   * src/pyramid minus the framework's own testing helper modules and the
   * zope.interface declaration stubs. scripts/ is additionally excluded for
   * the name-based rules (no rendered source label lives there; the
   * pviews/prequest CLI-simulated request rows are role=none).
   */
  private predicate inSourceScope(AstNode n) {
    relPath(n).matches("src/pyramid/%") and
    not relPath(n).matches("src/pyramid/scripts/%") and
    not relPath(n).matches("src/pyramid/testing.py") and
    not relPath(n).matches("src/pyramid/config/testing.py") and
    not relPath(n).matches("src/pyramid/interfaces.py")
  }

  /** Gets the dotted name of a simple name/attribute chain, e.g. "os.path". */
  private string dottedName(Expr e) {
    result = e.(Name).getId()
    or
    result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
  }

  /**
   * Request object fields whose reads are untrusted HTTP input (webob/pyramid
   * Request, PATH_INFO/WSGI-derived). "localizer" is deliberately NOT here:
   * its label (S027) is role=summary, handled in MySummaries documentation.
   */
  private predicate isRequestField(string fieldName) {
    fieldName in ["path_info", "subpath", "path", "url", "path_url",
      "query_string", "accept_encoding", "environ", "cookies", "headers",
      "POST", "params", "GET", "matchdict", "locale_name"]
  }

  /**
   * Holds for attribute reads of a request field, matching "request.<field>",
   * "self.request.<field>", and — for locale_name only — "self.locale_name":
   * pyramid.request.Request (request.py:144-149) mixes in
   * LocalizerRequestMixin, whose reified locale_name property
   * (i18n.py:377-380) is the same request attribute; the self form is read at
   * i18n.py:363 inside the localizer property that feeds make_localizer.
   */
  private predicate requestFieldAttr(Attribute a, string fieldName) {
    isRequestField(fieldName) and
    a.getName() = fieldName and
    (
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() = "request"
      or
      a.getObject() instanceof Attribute and
      a.getObject().(Attribute).getName() = "request" and
      a.getObject().(Attribute).getObject() instanceof Name and
      a.getObject().(Attribute).getObject().(Name).getId() = "self"
      or
      fieldName = "locale_name" and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() = "self"
    )
  }

  // --------------------------------------------------------------------------
  // requestFieldRead — labels S003-S026, S028-S034, S036-S053 (49 entries,
  // tp, conf 0.7-0.98).
  //
  // Attribute reads of HTTP-controlled request fields. Key path-relevant
  // sites (Phase 1 review, iris/labels/phase1_review.md section 2):
  //   S037 static.py:133    request.path_info -> traversal_path_info ->
  //                         _secure_path -> docroot join -> FileResponse (the
  //                         guarded static-file chain, Chain A)
  //   S045 static.py:131    request.subpath -> _secure_path (use_subpath)
  //   S024/S026 i18n.py:135/166  request.params / request.locale_name ->
  //                         make_localizer os.path.join(tdir, locale) with no
  //                         '..' filtering (the unguarded locale chain,
  //                         Chain B)
  //   S030/S036/S038        matchdict / path_info feeding traversal & routing
  //   S003-S013             request.environ (raw WSGI environ incl. HTTP_*)
  // --------------------------------------------------------------------------
  private predicate requestFieldRead(DataFlow::Node n) {
    exists(Attribute a |
      n.asExpr() = a and
      inSourceScope(a) and
      requestFieldAttr(a, a.getName())
    )
  }

  // --------------------------------------------------------------------------
  // requestFieldSubscript — labels S109, S114, S118, S119 (4 entries, tp).
  //
  // S109 traversal.py:631      environ[self.VH_ROOT_KEY] — the X-Vhm-Root
  //                            request header (line-restricted read site).
  // S114 authentication.py:1058, S118 authentication.py:1146
  //                            environ['REMOTE_ADDR'] client address reads
  //                            (line-restricted; the environ[...] assignments
  //                            at authentication.py:1105-1107 are write
  //                            targets and role=none, not matched).
  // S119 csrf.py:139           request.cookies[...] — attacker cookie value.
  // --------------------------------------------------------------------------
  private predicate requestFieldSubscript(DataFlow::Node n) {
    // request.cookies[...] (and any other request.<field>[...] read)
    exists(Subscript s, Attribute a |
      n.asExpr() = s and
      inSourceScope(s) and
      s.getValue() = a and
      requestFieldAttr(a, a.getName())
    )
    or
    // local environ[...] reads, line-restricted to the audited read sites
    exists(Subscript s |
      n.asExpr() = s and
      s.getValue() instanceof Name and
      s.getValue().(Name).getId() = "environ" and
      relPath(s) = "src/pyramid/traversal.py" and
      s.getLocation().getStartLine() = 631
    )
    or
    exists(Subscript s |
      n.asExpr() = s and
      s.getValue() instanceof Name and
      s.getValue().(Name).getId() = "environ" and
      relPath(s) = "src/pyramid/authentication.py" and
      s.getLocation().getStartLine() in [1058, 1146]
    )
  }

  // --------------------------------------------------------------------------
  // requestFieldLookup — labels S144-S158 (15 entries, tp, conf 0.7-0.95).
  //
  // request.<field>.get(...) value lookups. Key path-relevant sites:
  //   S147 i18n.py:137        request.cookies.get('_LOCALE_') (Chain B)
  //   S155 i18n.py:135        request.params.get('_LOCALE_')  (Chain B)
  //   S145/S146 authentication.py:211/214, S150-S153
  //                          request.environ.get(...) / request.headers.get /
  //                          request.cookies.get / request.POST.get — auth
  //                          and CSRF data (not path-relevant, kept as
  //                          boundary sources)
  // --------------------------------------------------------------------------
  private predicate requestFieldLookup(DataFlow::Node n) {
    exists(Call c, Attribute obj |
      n.asExpr() = c and
      inSourceScope(c) and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject() = obj and
      requestFieldAttr(obj, obj.getName())
    )
  }

  // --------------------------------------------------------------------------
  // localDictGet — labels S159-S164 (6 entries, tp, conf 0.75-0.9).
  //
  // .get() lookups on locals named environ / matchdict, line-restricted to
  // the audited sites (the local-name convention was verified by hand during
  // extraction, see detection.json family request_field_lookup):
  //   S159 traversal.py:729   environ.get(VH_ROOT_KEY) in ResourceURL
  //   S160/S161 request.py:274/275  environ.get('SCRIPT_NAME'/'PATH_INFO') —
  //                          raw WSGI boundary values (PATH_INFO = URL path)
  //   S162 httpexceptions.py:257    environ.get('HTTP_ACCEPT')
  //   S163/S164 traversal.py:601/608 matchdict.get('traverse'/'subpath') —
  //                          *traverse/*subpath star-args, URL-decoded route
  //                          values that become traversal path / request.subpath
  // --------------------------------------------------------------------------
  private predicate localDictGet(DataFlow::Node n) {
    exists(Call c |
      n.asExpr() = c and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject() instanceof Name and
      c.getFunc().(Attribute).getObject().(Name).getId() = "environ" and
      (
        relPath(c) = "src/pyramid/traversal.py" and
        c.getLocation().getStartLine() = 729
        or
        relPath(c) = "src/pyramid/request.py" and
        c.getLocation().getStartLine() in [274, 275]
        or
        relPath(c) = "src/pyramid/httpexceptions.py" and
        c.getLocation().getStartLine() = 257
      )
    )
    or
    exists(Call c |
      n.asExpr() = c and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject() instanceof Name and
      c.getFunc().(Attribute).getObject().(Name).getId() = "matchdict" and
      relPath(c) = "src/pyramid/traversal.py" and
      c.getLocation().getStartLine() in [601, 608]
    )
  }

  // --------------------------------------------------------------------------
  // getattrRequestRead — labels S121-S137 (17 entries, tp, conf 0.7-0.95).
  //
  // Dynamic getattr on the request object. Key path-relevant sites:
  //   S126 i18n.py:133        getattr(request, '_LOCALE_', None) — first
  //                          input of the locale negotiation chain (Chain B)
  //   S133 request.py:276     getattr(request, 'subpath', ()) — subpath tuple
  //                          rebuilt as PATH_INFO for subrequests
  //   remaining 15 rows      framework attribute plumbing (authenticated_userid,
  //                          exc_info, matchdict, ...) — conservative
  //                          secondary boundary sources per the labels
  // --------------------------------------------------------------------------
  private predicate getattrRequestRead(DataFlow::Node n) {
    exists(Call c |
      n.asExpr() = c and
      inSourceScope(c) and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "getattr" and
      c.getArg(0) instanceof Name and
      c.getArg(0).(Name).getId() = "request"
    )
  }

  // --------------------------------------------------------------------------
  // entryParamSource — labels S176-S239 minus S224/S225 (62 entries, tp,
  // conf 0.75-0.98).
  //
  // The exact audited (function name, parameter name, parameter position,
  // file, parameter line) tuples from the labels. Three groups:
  //   WSGI environ parameters (outermost untrusted boundary, PEP 3333):
  //     S204 Router.__call__            router.py:262    arg 1 'environ'
  //     S203 Router.request_context     router.py:193    arg 1 'environ'
  //     S202 HTTPException.__call__     httpexceptions.py:336  arg 1 'environ'
  //   Request-entry methods (carry path_info/subpath/matchdict/params/...):
  //     S230 static_view.__call__       static.py:104    arg 2 'request'
  //     S234 ResourceTreeTraverser.__call__  traversal.py:595  arg 1
  //     S237 RoutesMapper.__call__      urldispatch.py:72  arg 1
  //     S226-S228 Router.handle_request / invoke_request / invoke_subrequest
  //     S229 CookieSession.__init__, S231/S232 cache busters, S233
  //     RequestContext.__init__, S235 ResourceURL.__init__, S236
  //     DefaultRootFactory.__init__, S238 AppendSlashNotFoundViewFactory,
  //     S239 MultiView.__call__
  //   Framework view wrappers / predicates / events (secondary boundaries
  //   carrying the same request object; field-level reads are the precise
  //   sources, these are kept for conservative recall per the labels):
  //     S176-S201 view wrappers, S205-S208 events, S209-S223 predicates
  //
  // Matching is by parameter NAME + POSITION + parameter location line + file
  // and the enclosing function's name, so unlabeled lookalikes (e.g. the
  // unlabeled `wrapper` at config/views.py:508, the pviews RoutesMultiView at
  // pviews.py:107 and FileResponse.__init__'s request at response.py:43,
  // which are role=none) are not promoted to sources.
  // --------------------------------------------------------------------------
  private predicate entryParam(string fName, string pName, int position, string file, int line) {
    // WSGI environ parameters
    fName = "__call__" and pName = "environ" and position = 1 and
      file = "src/pyramid/router.py" and line = 262
    or
    fName = "request_context" and pName = "environ" and position = 1 and
      file = "src/pyramid/router.py" and line = 193
    or
    fName = "__call__" and pName = "environ" and position = 1 and
      file = "src/pyramid/httpexceptions.py" and line = 336
    or
    // request-entry methods
    fName = "__call__" and pName = "request" and position = 2 and
      file = "src/pyramid/static.py" and line = 104
    or
    fName = "__call__" and pName = "request" and position = 1 and
      file = "src/pyramid/static.py" and line in [305, 421]
    or
    fName = "__call__" and pName = "request" and position = 1 and
      file = "src/pyramid/traversal.py" and line = 595
    or
    fName = "__init__" and pName = "request" and position = 2 and
      file = "src/pyramid/traversal.py" and line = 717
    or
    fName = "__init__" and pName = "request" and position = 1 and
      file = "src/pyramid/traversal.py" and line = 758
    or
    fName = "__call__" and pName = "request" and position = 1 and
      file = "src/pyramid/urldispatch.py" and line = 72
    or
    fName = "handle_request" and pName = "request" and position = 1 and
      file = "src/pyramid/router.py" and line = 56
    or
    fName = "invoke_request" and pName = "request" and position = 1 and
      file = "src/pyramid/router.py" and line = 229
    or
    fName = "invoke_subrequest" and pName = "request" and position = 1 and
      file = "src/pyramid/router.py" and line = 173
    or
    fName = "__init__" and pName = "request" and position = 1 and
      file = "src/pyramid/session.py" and line = 211
    or
    fName = "__init__" and pName = "request" and position = 1 and
      file = "src/pyramid/threadlocal.py" and line = 75
    or
    fName = "__call__" and pName = "request" and position = 2 and
      file = "src/pyramid/view.py" and line = 324
    or
    fName = "__call__" and pName = "request" and position = 2 and
      file = "src/pyramid/config/views.py" and line = 148
    or
    // view / rendering helpers (view.py, security.py, wsgi.py,
    // httpexceptions.py)
    fName = "render_view_to_response" and pName = "request" and position = 1 and
      file = "src/pyramid/view.py" and line = 28
    or
    fName = "render_view_to_iterable" and pName = "request" and position = 1 and
      file = "src/pyramid/view.py" and line = 79
    or
    fName = "render_view" and pName = "request" and position = 1 and
      file = "src/pyramid/view.py" and line = 110
    or
    fName = "view_execution_permitted" and pName = "request" and position = 1 and
      file = "src/pyramid/security.py" and line = 124
    or
    fName = "decorator" and pName = "request" and position = 1 and
      file = "src/pyramid/wsgi.py" and line in [38, 82]
    or
    fName = "default_exceptionresponse_view" and pName = "request" and position = 1 and
      file = "src/pyramid/httpexceptions.py" and line = 1333
    or
    // view derivers (viewderivers.py)
    (
      fName in ["mapped_view", "_class_requestonly_view", "_class_view",
                "_requestonly_view", "_attr_view", "_owrapped_view",
                "permitted", "secured_view", "authdebug_view",
                "viewresult_to_response", "rendered_view", "csrf_view",
                "wrapper"] and
      pName = "request" and position = 1 and
      file = "src/pyramid/viewderivers.py" and
      line in [91, 107, 123, 139, 151, 230, 271, 313, 316, 351, 391, 426, 503]
    )
    or
    // config/views.py view wrappers
    (
      fName in ["attr_view", "predicate_wrapper", "checker", "view",
                "wrapper_view", "wrapper"] and
      pName = "request" and position = 1 and
      file = "src/pyramid/config/views.py" and
      line in [169, 188, 198, 826, 2103, 2122]
    )
    or
    // request lifecycle events (events.py)
    fName = "__init__" and pName = "request" and position = 1 and
      file = "src/pyramid/events.py" and line in [121, 158, 180, 206]
    or
    // route/view predicates (predicates.py) — request is argument 2 after
    // (self, context)
    fName = "__call__" and pName = "request" and position = 2 and
      file = "src/pyramid/predicates.py" and
      line in [24, 41, 59, 89, 125, 151, 164, 178, 196, 226, 248, 273, 288, 304, 331]
  }

  private predicate entryParamSource(DataFlow::Node n) {
    exists(Function f, Parameter p |
      n = DataFlow::parameterNode(p) and
      f.getArg(_) = p and
      entryParam(f.getName(), p.getName(), p.getPosition(), relPath(p), p.getLocation().getStartLine())
    )
  }

  /** Holds if `n` is a pass 1 source node. `passKey` must be "path_traversal". */
  predicate isSource(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      requestFieldRead(n)
      or requestFieldSubscript(n)
      or requestFieldLookup(n)
      or localDictGet(n)
      or getattrRequestRead(n)
      or entryParamSource(n)
    )
  }
}
