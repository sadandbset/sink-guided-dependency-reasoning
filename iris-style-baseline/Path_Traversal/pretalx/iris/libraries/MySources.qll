/**
 * Augur Phase 2 Step 4 — Pass 1 (Path Traversal) source model for pretalx.
 *
 * Machine-generated from iris/labels/labels.json (run
 * pretalx-pathtraversal-pass1-20261022, pass_id 1). Every rule renders exactly the
 * label entries whose role=source AND whose classification is tp or candidate
 * (475 of the 562 role=source rows). The source-code evidence for each entry was
 * verified during Phase 1 Step 3 labeling against the pretalx_vuln source tree
 * (see iris/labels/phase1_review.md sections 3 and 6, and the per-row evidence
 * in iris/labels/labels_raw_pass1.json).
 *
 * Excluded from the source model (reviewed decisions, not omissions):
 *  - 87 role=source rows with classification=fp: route parameters bound through
 *    <int:...> converters (25) and <slug:...> converters (46+16) — the converter
 *    regexes admit no path separators, so a traversal payload cannot reach the
 *    handler (labels P1-S-0001..P1-S-0076 minus the five kept below, plus the
 *    fp-classified route_kwarg rows). Re-including them would only add noise.
 *  - 41 env_config rows (os.environ/os.getenv): operator/deployment boundary,
 *    not attacker-controlled (role=none, classification=fp).
 *  - 8 resolver_match whole-object reads (role=none): framework routing metadata.
 *  - 23 internal handler parameters (up/draft/steps/response/view/obj/...)
 *    (role=none): passed by framework callers or internal call sites with
 *    constants — an internal function parameter is not automatically a source.
 *
 * Only request-object field reads, form-validated value re-entry points, URL
 * route variables and the cfp wizard session reads are taint origins; path
 * propagation between them and the sinks is handled by the default data flow /
 * python-all stdlib models plus the two evidence-based steps in MySummaries.qll.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  // --------------------------------------------------------------------------
  // Shared helpers (same shapes as the validated extraction query
  // iris/extraction/sources.ql, so the library matches exactly the nodes that
  // were extracted and labeled).
  // --------------------------------------------------------------------------

  /**
   * Gets the repository-relative path of the file containing this node, e.g.
   * "src/pretalx/common/views.py". On this Windows-created database
   * getRelativePath() may yield backslash forms or no result, so fall back to
   * capturing the "src/pretalx/..." suffix from the absolute path.
   */
  private string relPath(AstNode n) {
    exists(string p |
      p = n.getLocation().getFile().getRelativePath() and
      result = p.replaceAll("\\", "/")
    )
    or
    not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/").regexpCapture(".*/(src/pretalx/.+)$", 1)
  }

  /** Restricts nodes to the pretalx package (excludes tests/migrations/db). */
  private predicate inPretalxPackage(AstNode n) {
    relPath(n).matches("src/pretalx/%") and
    not relPath(n).matches("%/migrations/%")
  }

  /** Gets the dotted name of a simple name/attribute chain, e.g. "os.path". */
  private string dottedName(Expr e) {
    result = e.(Name).getId()
    or
    result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
  }

  /**
   * Request object fields whose reads are untrusted HTTP input.
   * "resolver_match" is deliberately NOT a source field: its whole-object reads
   * are role=none labels; its URL-derived kwargs members are covered by the
   * routeKwargRead rule below.
   */
  private predicate isRequestField(string fieldName) {
    fieldName in ["GET", "POST", "FILES", "headers", "COOKIES", "META", "body",
      "path", "path_info", "session"]
  }

  /**
   * Holds for attribute reads of a request field, matching both "request.<field>"
   * and "self.request.<field>" chains. Only these chains are accepted, so local
   * variables that merely happen to be named "request" cannot match.
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
    )
  }

  /**
   * Holds for route-kwarg mapping attributes: "self.kwargs" (class-based view URL
   * variables), "url.kwargs" (resolver match kwargs) and
   * "request.resolver_match.kwargs".
   */
  private predicate kwargsAttr(Attribute a) {
    a.getName() = "kwargs" and
    (
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() in ["self", "url"]
      or
      a.getObject() instanceof Attribute and
      a.getObject().(Attribute).getName() = "resolver_match"
    )
  }

  /**
   * Holds for form value container attributes: "self.cleaned_data",
   * "form.cleaned_data", "self.files", "form.files" — the boundary where request
   * data re-enters code after Django form validation.
   */
  private predicate formValueAttr(Attribute a, string containerName) {
    a.getName() = containerName and
    containerName in ["cleaned_data", "files"] and
    a.getObject() instanceof Name
  }

  // --------------------------------------------------------------------------
  // requestFieldRead — labels P1-S-0077..P1-S-0097, P1-S-0100..P1-S-0269,
  // P1-S-0276..P1-S-0332, P1-S-0404..P1-S-0411, P1-S-0472..P1-S-0480,
  // P1-S-0514..P1-S-0553, P1-S-0557..P1-S-0587 (336 entries, tp, conf 0.55-0.8).
  //
  // Django HttpRequest fields read directly on the request object:
  //   GET (144)   query parameters (incl. unquote()-wrapped reads at
  //               agenda/views/schedule.py:85, agenda/views/widget.py:167,
  //               common/views.py:83, common/mixins/views.py:155)
  //   POST (66)   form body fields
  //   FILES (12)  multipart uploads — client-supplied filenames reach Django
  //               form/FileField handling and the storage save sinks
  //   headers/META/COOKIES (35)  request metadata
  //   body (3), path/path_info (29)  raw body and URL path
  //   session (47) server-side session (second-order: user-entered values)
  // All three node shapes extracted in Phase 1 are matched: plain attribute
  // reads, subscripts of a request field, and .get()/.getlist() lookups.
  // --------------------------------------------------------------------------
  private predicate requestFieldRead(DataFlow::Node n) {
    exists(Attribute a |
      n.asExpr() = a and
      inPretalxPackage(a) and
      isRequestField(a.getName()) and
      requestFieldAttr(a, a.getName())
    )
    or
    exists(Subscript s, Attribute a |
      n.asExpr() = s and
      inPretalxPackage(s) and
      s.getValue() = a and
      requestFieldAttr(a, a.getName())
    )
    or
    exists(Call c, Attribute obj |
      n.asExpr() = c and
      inPretalxPackage(c) and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() in ["get", "getlist"] and
      c.getFunc().(Attribute).getObject() = obj and
      requestFieldAttr(obj, obj.getName())
    )
  }

  // --------------------------------------------------------------------------
  // formValueRead — labels P1-S-0099, P1-S-0335..P1-S-0381, P1-S-0412..P1-S-0471
  // (108 entries, tp, conf 0.6-0.7).
  //
  // Second-order re-entry of request POST/FILES values after Django form
  // validation, which constrains types/lengths but not path semantics:
  //   - cleaned_data subscripts and .get() reads (106), e.g.
  //     common/mixins/forms.py:439 `value = self.cleaned_data[name]` (the
  //     HierarkeyMixin save chain feeding default_storage.save),
  //     orga/forms/review.py:370 `uploaded_file = self.cleaned_data["import_file"]`
  //   - files subscripts/.get() (2): orga/forms/event.py:193-194
  //     self.files.get("custom_css") / self.files["custom_css"]
  // --------------------------------------------------------------------------
  private predicate formValueRead(DataFlow::Node n) {
    exists(Subscript s, Attribute a |
      n.asExpr() = s and
      inPretalxPackage(s) and
      s.getValue() = a and
      formValueAttr(a, a.getName())
    )
    or
    exists(Call c, Attribute a |
      n.asExpr() = c and
      inPretalxPackage(c) and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject() = a and
      formValueAttr(a, a.getName())
    )
  }

  // --------------------------------------------------------------------------
  // cfpSessionGetRead — labels P1-S-0629..P1-S-0634 (6 entries, candidate,
  // conf 0.5).
  //
  // cfp_session.get(...) in the CfP wizard (src/pretalx/cfp/flow.py:191, 192,
  // 411, 436, 519, 534): reads previously stored wizard data. The stored
  // "files" dict carries upload tmp_names that are opened directly via
  // FileSystemStorage.open(tmp_name) at flow.py:258-262 (sink K0016). Kept as
  // candidate-classified sources per the review: the session is server-managed
  // and tmp_name values are storage-generated, so direct path control is
  // unlikely; alerts on this rule belong to the human-review bucket.
  // --------------------------------------------------------------------------
  private predicate cfpSessionGetRead(DataFlow::Node n) {
    exists(Call c, Attribute a |
      n.asExpr() = c and
      relPath(c) = "src/pretalx/cfp/flow.py" and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject() = a and
      a.getName() = "cfp_session" and
      a.getObject() instanceof Name
    )
  }

  // --------------------------------------------------------------------------
  // routedHandlerParam — labels P1-S-0056, P1-S-0064, P1-S-0066, P1-S-0068,
  // P1-S-0070 (5 entries).
  //
  // P1-S-0056 (candidate, conf 0.6): the 'path' parameter of get_static
  // (src/pretalx/common/views.py:48) — urlconfig-injected value joined raw as
  // settings.BASE_DIR / "pretalx/static" / path and opened at :56 with no
  // containment (sink K0010); currently bound to the literal
  // "agenda/js/serviceworker.js" via agenda/urls.py:124-131, so attacker control
  // requires a route that binds a URL variable (malicious/plugin urlconfig).
  //
  // P1-S-0064/0066/0068/0070 (tp, conf 0.65): the 'version' parameter (arg
  // index 2) of the versioned schedule/widget handlers in
  // src/pretalx/agenda/views/widget.py (cache_control :126, cache_version :140,
  // version_prefix :152, widget_data_v2 :162). Bound from the plain
  // str-converter route "schedule/v/<version>" (agenda/urls.py:65,
  // get_schedule_urls) — a single attacker-controlled URL segment.
  //
  // All other http_route_param labels are excluded: int-converter (pk/user_pk/
  // talkid/roomid), slug-converter (event), widget int-route version/locale,
  // and internal parameters (labels classification=fp / role=none).
  // --------------------------------------------------------------------------
  private predicate routedHandlerParam(DataFlow::Node n) {
    exists(Function f, Parameter p |
      n = DataFlow::parameterNode(p) and
      f.getArg(_) = p and
      (
        (
          f.getName() = "get_static" and
          p.getName() = "path" and
          p.getPosition() = 1 and
          relPath(f) = "src/pretalx/common/views.py"
        )
        or
        (
          f.getName() in ["cache_control", "cache_version", "version_prefix", "widget_data_v2"] and
          p.getName() = "version" and
          p.getPosition() = 2 and
          relPath(f) = "src/pretalx/agenda/views/widget.py"
        )
      )
    )
  }

  // --------------------------------------------------------------------------
  // routeKwargRead — labels P1-S-0098, P1-S-0382..P1-S-0383,
  // P1-S-0397..P1-S-0401, P1-S-0488..P1-S-0490, P1-S-0494..P1-S-0496,
  // P1-S-0500, P1-S-0502, P1-S-0511..P1-S-0513, P1-S-0554 (20 entries, tp,
  // conf 0.6-0.75).
  //
  // URL route variables read through the kwargs mapping, restricted to the
  // keys the review classified tp (plain str-converter segments):
  //   version     agenda/views/schedule.py:34  ("schedule/v/<version>", passed
  //               through unquote() — a second URL decode)
  //   tmpid       cfp/flow.py:64               ("submit/<tmpid>/<step>/")
  //   code        review.py:372, user.py:459/131/210, speaker.py:66/78/111,
  //               submission.py:123/351/616, event.py:486, schedule.py:429,
  //               cfp.py:607/640/671
  //   invitation  user.py:460                   ("invitation/<code>/<invitation>")
  //   name        schedule.py:85                ("schedule/export/<name>")
  //   <dynamic>   api/views/submission.py:93   (self.kwargs.get(self.lookup_field),
  //               DRF lookup value)
  // kwargs reads with int-converter keys (pk/user_pk) and slug-converter keys
  // (event/organiser/slug) are excluded (labels classification=fp).
  // --------------------------------------------------------------------------
  private predicate routeKwargKey(string key) {
    key in ["version", "tmpid", "code", "invitation", "name"]
  }

  private predicate routeKwargRead(DataFlow::Node n) {
    exists(Subscript s, Attribute a, StringLiteral lit |
      n.asExpr() = s and
      inPretalxPackage(s) and
      s.getValue() = a and
      kwargsAttr(a) and
      s.getIndex() = lit and
      routeKwargKey(lit.getS())
    )
    or
    exists(Call c, Attribute a, StringLiteral lit |
      n.asExpr() = c and
      inPretalxPackage(c) and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() in ["get", "getlist"] and
      c.getFunc().(Attribute).getObject() = a and
      kwargsAttr(a) and
      c.getArg(0) = lit and
      routeKwargKey(lit.getS())
    )
    or
    // DRF dynamic lookup: self.kwargs.get(self.lookup_field)
    // (src/pretalx/api/views/submission.py:93)
    exists(Call c, Attribute a |
      n.asExpr() = c and
      relPath(c) = "src/pretalx/api/views/submission.py" and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject() = a and
      kwargsAttr(a) and
      c.getArg(0) instanceof Name
    )
  }

  /** Holds if `n` is a pass 1 source node. `passKey` must be "path_traversal". */
  predicate isSource(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      requestFieldRead(n)
      or formValueRead(n)
      or cfpSessionGetRead(n)
      or routedHandlerParam(n)
      or routeKwargRead(n)
    )
  }
}
