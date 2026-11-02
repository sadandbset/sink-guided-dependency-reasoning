/**
 * @name Scout source candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate external-input source nodes from the
 *              Clinical-Genomics scout Flask application for subsequent
 *              LLM labeling.
 * @id py/augur/scout/pass3-sources
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * This database contains ONLY the scout application package
 * (Flask itself and the requests/urllib libraries are external
 * dependencies and are not present). Source candidates therefore
 * anchor on what this source proves:
 *   - the remote_cors route handler `remote_url` parameter (Flask
 *     <path:remote_url> converter) - the arbitrary client-supplied
 *     URL passed straight to requests.request(url=remote_url);
 *   - Host-header-derived URLs: request.url_root (pdf_case_report ->
 *     coverage_report_contents -> requests.post) and
 *     url_for(..., _external=True) (mt_coverage_stats ->
 *     requests.post), detected via the `_external` keyword;
 *   - request.headers / request.cookies / request.get_data() inside
 *     remote_cors - client data forwarded verbatim into the outgoing
 *     proxied request;
 *   - request form payloads that reach outbound POST bodies
 *     (beacon_add_variants, reanalysis sample_metadata);
 *   - case/DB content reused into URL construction (rank model
 *     version) and the MatchMaker external node `target` route
 *     variable;
 *   - admin-config URL provenance reads (MME_URL host, BEACON_URL,
 *     Rerunner entrypoint, rank model link prefix, LoqusDB api_url)
 *     kept for labeling recall - expected FP under the SSRF
 *     admin-configured-URL heuristic.
 *
 * Verified API usage (same AST surface as the earlier
 * django/calibre-web/core/label-studio/fides SSRF runs,
 * codeql CLI 2.25.x + codeql/python-all):
 *   - AstNode.getLocation().getFile().getRelativePath() and
 *     Location.getStartLine() for locations (no AstNode.getFile()).
 *   - Parameter names via p.asName().getId(); positions via
 *     f.getArg(i) (self counts as index 0 for methods).
 *   - Attribute.getObject() returns the object expression; it is
 *     bound to Name via equality before getId() comparisons.
 *   - Keyword.getArg() returns the keyword name string,
 *     Keyword.getValue() the value expression.
 *   - StringLiteral.getText() returns the literal source text WITH
 *     quotes, so dictionary-key style arguments are matched against
 *     both "\"name\"" and "'name'" forms.
 *   - The module column variable is named moduleHint ("module" is a
 *     QL keyword and must not be used as a variable name).
 *
 * Scope: relative paths under scout/ only. "scout/%" cannot match the
 * nested scout-db/ database directory ('-' vs '/' after "scout").
 * Repo-root tests/, scripts/, docs/ and containers/ are outside the
 * package and excluded by construction. CLI download commands have
 * no untrusted web input; scout/commands is covered by the generic
 * scope only through the families below (which cite server-side
 * evidence).
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("source_candidate")
 *  3. callable name       (dotted signature hint)
 *  4. flow kind           (param | return | field)
 *  5. receiver hint       (receiver/type hint)
 *  6. module hint         (dotted module path)
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
 * Restrict extraction to the scout application package.
 *
 * The CodeQL database source root is the repository root, so relative
 * paths of application files look like
 * "scout/server/blueprints/alignviewers/views.py".
 * "scout/%" cannot match the nested "scout-db/" database directory
 * ('-' at position 6 instead of '/'). Tests and scripts live at the
 * repository root and are excluded by construction.
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("scout/%")
  )
}

/**
 * Restrict a candidate to one application module. The path string is
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
// 2. Candidate extraction
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
    // (1) remote_cors(remote_url) route handler parameter
    //     scout/server/blueprints/alignviewers/views.py:33-34
    //       @alignviewers_bp.route("/remote/cors/<path:remote_url>",
    //                               methods=["OPTIONS", "GET"])
    //       def remote_cors(remote_url):
    //     The Flask <path:...> converter captures an arbitrary
    //     client-supplied URL (path, host and scheme included) and
    //     forwards it unchanged to requests.request(url=remote_url)
    //     at line 42. The global before_request login hook
    //     (scout/server/app.py:82-97) requires an authenticated
    //     session; no institute/case or role check exists on this
    //     endpoint. Module-level function, self not counted ->
    //     index 0.
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "remote_cors" and
      p.asName().getId() = "remote_url" and
      inModule(f, "scout/server/blueprints/alignviewers/views.py") and
      callableName = "remote_cors.remote_url" and
      flowKind = "param" and
      receiverHint = "flask.route_handler.path_variable" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (2) request.url_root attribute read
    //     scout/server/blueprints/cases/views.py:225 (inside
    //     pdf_case_report, route GET /<institute_id>/<case_name>/
    //     pdf_report):
    //       controllers.coverage_report_contents(
    //           request.url_root, institute_obj, case_obj)
    //     Flask derives url_root from the request Host header; the
    //     value is concatenated with "reports/report" and POSTed by
    //     coverage_report_contents (cases/controllers.py:94).
    //     Host-header-controlled outbound URL.
    // --------------------------------------------------------

    exists(Attribute a, Name req |
      n = a and
      a.getName() = "url_root" and
      req = a.getObject() and
      req.getId() = "request" and
      inModule(a, "scout/server/blueprints/cases/views.py") and
      callableName = "request.url_root" and
      flowKind = "field" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (3) url_for("report.json_chrom_coverage", _external=True)
    //     scout/server/blueprints/cases/controllers.py:544 (inside
    //     mt_coverage_stats):
    //       cov_calc_url = url_for("report.json_chrom_coverage",
    //                              _external=True)
    //     _external=True makes Flask build an absolute URL from the
    //     request Host/SERVER_NAME; the result is POSTed at
    //     controllers.py:548/:554. Detected via the _external
    //     keyword (no string-literal parsing of the endpoint name).
    // --------------------------------------------------------

    exists(Call c, Name fn, Keyword k |
      n = c and
      fn = c.getFunc() and
      fn.getId() = "url_for" and
      k = c.getAKeyword() and
      k.getArg() = "_external" and
      inModule(c, "scout/server/blueprints/cases/controllers.py") and
      callableName = "flask.url_for_external" and
      flowKind = "return" and
      receiverHint = "flask" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (4a) request.headers / request.cookies attribute reads in the
    //      alignviewers views module - client-controlled data that
    //      remote_cors forwards verbatim into the outgoing proxied
    //      request (views.py:45 headers dict comprehension minus
    //      Host, :47 cookies). Also matches the request.headers read
    //      at :77 inside remote_static (Range header; local-file
    //      flow) - kept for labeling, expected none for CWE-918.
    // --------------------------------------------------------

    exists(Attribute a, Name req |
      n = a and
      a.getName() in ["headers", "cookies"] and
      req = a.getObject() and
      req.getId() = "request" and
      inModule(a, "scout/server/blueprints/alignviewers/views.py") and
      callableName = "request." + a.getName() and
      flowKind = "field" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (4b) request.get_data() call in remote_cors
    //      (views.py:46, data=request.get_data()) - the raw client
    //      request body forwarded into the proxied request body.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name req |
      n = c and
      fn = c.getFunc() and
      fn.getName() = "get_data" and
      req = fn.getObject() and
      req.getId() = "request" and
      inModule(c, "scout/server/blueprints/alignviewers/views.py") and
      callableName = "request.get_data" and
      flowKind = "return" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (5a) request.form.get("sample_metadata")
    //      scout/server/blueprints/cases/views.py:839 (reanalysis,
    //      POST /<institute_id>/<case_name>/reanalysis):
    //        edited_metadata = json.loads(
    //            request.form.get("sample_metadata"))
    //        controllers.call_rerunner(store, institute_id,
    //            case_name, edited_metadata)
    //      The form payload becomes the json= body of the Rerunner
    //      requests.post (cases/controllers.py:894). URL itself is
    //      admin config; the taint lands in the request body.
    // --------------------------------------------------------

    exists(Call c, Attribute getAttr, Attribute formAttr, Name req, StringLiteral lit |
      n = c and
      getAttr = c.getFunc() and
      getAttr.getName() = "get" and
      formAttr = getAttr.getObject() and
      formAttr.getName() = "form" and
      req = formAttr.getObject() and
      req.getId() = "request" and
      lit = c.getArg(0) and
      lit.getText() in ["\"sample_metadata\"", "'sample_metadata'"] and
      inModule(c, "scout/server/blueprints/cases/views.py") and
      callableName = "request.form.get" and
      flowKind = "return" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (5b) plain request.form pass-through
    //      scout/server/blueprints/cases/views.py:93 (inside
    //      beacon_add_variants, POST
    //      /beacon_add_variants/<institute_id>/<case_name>):
    //        beacon.add_variants(store, case_obj, request.form)
    //      The form (vcf_files selection, dataset ids, user data)
    //      is merged into the POST body sent to the Beacon server
    //      (beacon_extension.py add_variants -> post_request_json).
    //      Only the plain pass-through read is matched; form reads
    //      consumed as the base of .get()/[...] are covered by (5a)
    //      or are subscripts (not matched).
    // --------------------------------------------------------

    exists(Attribute a, Name req |
      n = a and
      a.getName() = "form" and
      req = a.getObject() and
      req.getId() = "request" and
      inModule(a, "scout/server/blueprints/cases/views.py") and
      not exists(Attribute outer | outer.getObject() = a) and
      not exists(Call c | c.getFunc() = a) and
      not exists(Subscript s | s.getObject() = a) and
      callableName = "request.form" and
      flowKind = "field" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (6) case_obj.get("sv_rank_model_version") /
    //     case_obj.get("rank_model_version")
    //     scout/server/blueprints/variant/controllers.py:401/:405
    //     (rank_score_results): the case-DB rank model version is
    //     concatenated into the rank model URL
    //     (RankModelHandler.rank_model_from_url ->
    //     requests.get at scout/adapter/mongo/rank_model.py:23).
    //     Case content reused into a URL.
    // --------------------------------------------------------

    exists(Call c, Attribute getAttr, Name caseObj, StringLiteral lit |
      n = c and
      getAttr = c.getFunc() and
      getAttr.getName() = "get" and
      caseObj = getAttr.getObject() and
      caseObj.getId() = "case_obj" and
      lit = c.getArg(0) and
      lit.getText() in [
        "\"sv_rank_model_version\"",
        "'sv_rank_model_version'",
        "\"rank_model_version\"",
        "'rank_model_version'"
      ] and
      inModule(c, "scout/server/blueprints/variant/controllers.py") and
      callableName = "case_obj.get_rank_model_version" and
      flowKind = "return" and
      receiverHint = "scout.models.case.Case" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (7) matchmaker_match(request, target, institute_id, case_name)
    //     `target` parameter at index 1
    //     scout/server/blueprints/cases/controllers.py:1223, route
    //     POST/GET /<institute_id>/<case_name>/mme_match/<target>
    //     (cases/views.py:116). The route path variable is used as
    //     an external MME node id: match_external(patient_id, node)
    //     -> "".join([self.host, "/match/external/", patient_id,
    //     "?node=", node_id]) (matchmaker_extension.py:150).
    //     Constrained: the controller loops over connected node ids
    //     and only proceeds when node == target, so arbitrary URL
    //     injection is not proven - flagged for labeling.
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "matchmaker_match" and
      p.asName().getId() = "target" and
      inModule(f, "scout/server/blueprints/cases/controllers.py") and
      callableName = "matchmaker_match.target" and
      flowKind = "param" and
      receiverHint = "flask.route_handler.path_variable" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (8a) self.host reads in the MatchMaker extension
    //      scout/server/extensions/matchmaker_extension.py - MME
    //      server host read from app config MME_URL (init_app:26)
    //      and used to build every outbound MME URL (:76/:90/:103/
    //      :122/:133/:150). Admin-configured URL provenance;
    //      expected FP under the SSRF admin-config heuristic, kept
    //      for labeling recall. Assignment targets are excluded.
    // --------------------------------------------------------

    exists(Attribute a, Name selfName |
      n = a and
      a.getName() = "host" and
      selfName = a.getObject() and
      selfName.getId() = "self" and
      inModule(a, "scout/server/extensions/matchmaker_extension.py") and
      not exists(Assign asg | asg.getATarget() = a) and
      callableName = "MatchMaker.host" and
      flowKind = "field" and
      receiverHint = "scout.server.extensions.MatchMaker" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (8b) self.beacon_url reads in the Beacon extension
    //      scout/server/extensions/beacon_extension.py - BEACON_URL
    //      from app config (init_app:28), read at :30/:31 (add/
    //      delete variants URL construction) and :39 (datasets GET).
    //      Admin-configured; expected FP, kept for labeling recall.
    // --------------------------------------------------------

    exists(Attribute a, Name selfName |
      n = a and
      a.getName() = "beacon_url" and
      selfName = a.getObject() and
      selfName.getId() = "self" and
      inModule(a, "scout/server/extensions/beacon_extension.py") and
      not exists(Assign asg | asg.getATarget() = a) and
      callableName = "Beacon.beacon_url" and
      flowKind = "field" and
      receiverHint = "scout.server.extensions.Beacon" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (8c) cnf.get("entrypoint") in call_rerunner
    //      scout/server/blueprints/cases/controllers.py:889 -
    //      Rerunner API entrypoint from app config
    //      RERUNNER_API_ENTRYPOINT (rerunner_extension.py:20),
    //      POSTed to at controllers.py:894. Admin-configured;
    //      expected FP, kept for labeling recall.
    // --------------------------------------------------------

    exists(Call c, Attribute getAttr, Name cnf, StringLiteral lit |
      n = c and
      getAttr = c.getFunc() and
      getAttr.getName() = "get" and
      cnf = getAttr.getObject() and
      cnf.getId() = "cnf" and
      lit = c.getArg(0) and
      lit.getText() in ["\"entrypoint\"", "'entrypoint'"] and
      inModule(c, "scout/server/blueprints/cases/controllers.py") and
      callableName = "rerunner.connection_settings.get_entrypoint" and
      flowKind = "return" and
      receiverHint = "flask.app.config" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (8d) current_app.config.get("RANK_MODEL_LINK_PREFIX" /
    //      "SV_RANK_MODEL_LINK_PREFIX") reads
    //      scout/server/blueprints/variant/controllers.py:402/:406 -
    //      the URL prefix concatenated with the case rank model
    //      version (see family (6)). Admin-configured; expected FP,
    //      kept for labeling recall.
    // --------------------------------------------------------

    exists(Call c, Attribute getAttr, Attribute configAttr, Name app, StringLiteral lit |
      n = c and
      getAttr = c.getFunc() and
      getAttr.getName() = "get" and
      configAttr = getAttr.getObject() and
      configAttr.getName() = "config" and
      app = configAttr.getObject() and
      app.getId() = "current_app" and
      lit = c.getArg(0) and
      lit.getText() in [
        "\"RANK_MODEL_LINK_PREFIX\"",
        "'RANK_MODEL_LINK_PREFIX'",
        "\"SV_RANK_MODEL_LINK_PREFIX\"",
        "'SV_RANK_MODEL_LINK_PREFIX'"
      ] and
      inModule(c, "scout/server/blueprints/variant/controllers.py") and
      callableName = "flask_config.get_rank_model_link" and
      flowKind = "return" and
      receiverHint = "flask.current_app.config" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (8e) loqus_instance.get(API_URL) / instance_settings.get(
    //      API_URL) reads
    //      scout/server/extensions/loqus_extension.py:122/:182/:212
    //      - LoqusDB REST API base URL from the LOQUSDB_SETTINGS
    //      config, consumed by api_get(...) GET requests (:133/
    //      :183/:242). API_URL is a module constant Name, not a
    //      literal; the object names + module restriction isolate
    //      the URL reads. Admin-configured; expected FP, kept for
    //      labeling recall.
    // --------------------------------------------------------

    exists(Call c, Attribute getAttr, Name obj |
      n = c and
      getAttr = c.getFunc() and
      getAttr.getName() = "get" and
      obj = getAttr.getObject() and
      obj.getId() in ["loqus_instance", "instance_settings"] and
      inModule(c, "scout/server/extensions/loqus_extension.py") and
      callableName = "loqus_settings.get_api_url" and
      flowKind = "return" and
      receiverHint = "scout.server.extensions.LoqusDB" and
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
