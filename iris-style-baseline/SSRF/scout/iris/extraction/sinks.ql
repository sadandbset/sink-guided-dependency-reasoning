/**
 * @name Scout sink candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate outbound-network request nodes from
 *              the Clinical-Genomics scout Flask application for
 *              subsequent LLM labeling.
 * @id py/augur/scout/pass3-sinks
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * Only network-I/O call sites that exist in this source tree are
 * extracted. requests is imported module-style (`import requests`)
 * in every file below, so the calls resolve as
 * Attribute(<verb>) on Name "requests". httpx, aiohttp and
 * http.client are not used anywhere in this project and are absent.
 * urllib usage outside scout_requests.fetch_resource is parse-only
 * (urllib.parse quote/unquote/urlencode) and is not a sink.
 *
 * Sink families (all anchored on call sites verified in this repo):
 *  (1) requests.get/post/delete/request(...) - final HTTP I/O of
 *      python-requests; URL at positional argument 0, or at the
 *      url= keyword (argIndex -1, node = the call).
 *  (2) urllib.request.urlopen(url) - ftp:// resource fetch in
 *      scout_requests.fetch_resource (only urlopen in the repo).
 *  (3) scout.utils.scout_requests wrapper invocations
 *      (get_request_json / post_request_json / delete_request_json /
 *      get_request / fetch_resource / api_get alias) - the shared
 *      HTTP layer all integrations go through.
 *  (4) MatchMaker / Beacon extension wrapper invocations from web
 *      handlers - URL built inside the wrapper from admin config,
 *      request-derived data lands in the body / URL path parts.
 *  (5) query_phenomizer.query(username, password, *hpo_ids) -
 *      network I/O inside the external query-phenomizer package
 *      (not in this DB); recorded at the wrapper call site.
 *
 * Verified API usage (same AST surface as the earlier
 * django/calibre-web/core/label-studio/fides SSRF runs,
 * codeql CLI 2.25.x + codeql/python-all):
 *   - AstNode.getLocation().getFile().getRelativePath() and
 *     Location.getStartLine() for locations (no AstNode.getFile()).
 *   - Attribute.getObject() returns the object expression; it is
 *     bound to Name via equality before getId() comparisons.
 *   - Keyword.getArg() returns the keyword name string,
 *     Keyword.getValue() the value expression.
 *   - The module column variable is named moduleHint ("module" is a
 *     QL keyword and must not be used as a variable name).
 *
 * Scope: relative paths under scout/ only. "scout/%" cannot match
 * the nested scout-db/ database directory ('-' vs '/' after
 * "scout"). Repo-root tests/, scripts/, docs/ and containers/ are
 * outside the package and excluded by construction.
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("sink_candidate")
 *  3. callable name       (dotted signature hint)
 *  4. flow kind           (argument)
 *  5. receiver hint       (receiver/type hint)
 *  6. module hint         (dotted module path)
 *  7. argument index      (-1 when not applicable)
 *  8. line
 *  9. file:line
 * 10. expression text
 *
 * flow kind vocabulary:
 *   argument - the tainted URL position is an argument of the
 *              network call (positional index recorded, or -1 when
 *              the URL is passed via the url= keyword; the node is
 *              then the whole call expression)
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
 * Restrict a candidate to the server integration layer
 * (extensions + web blueprints).
 */
predicate inServerModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("scout/server/%")
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
// 2. Wrapper name helpers (verified against this source)
// ------------------------------------------------------------

/**
 * scout.utils.scout_requests wrapper functions whose bodies perform
 * the actual requests.* network I/O. `api_get` is the import alias
 * used by scout/server/extensions/loqus_extension.py:13
 * (`from scout.utils.scout_requests import get_request_json as
 *  api_get`). Only these names appear as calls in non-test code.
 */
predicate isScoutRequestWrapper(string name) {
  name in [
    "get_request_json",
    "post_request_json",
    "delete_request_json",
    "get_request",
    "fetch_resource",
    "api_get"
  ]
}

/**
 * MatchMaker / Beacon extension methods invoked from web handlers.
 * All of them end in a scout_requests wrapper call (URL assembled
 * from admin config; request-derived data in the body / URL path).
 */
predicate isExtensionNetworkMethod(string name) {
  name in [
    "patient_submit",
    "patient_delete",
    "patient_matches",
    "match_internal",
    "match_external",
    "add_variants",
    "delete_variants"
  ]
}

/** Receiver hint for the extension object name. */
string extensionReceiver(string objId) {
  objId = "matchmaker" and result = "scout.server.extensions.MatchMaker"
  or
  objId = "beacon" and result = "scout.server.extensions.Beacon"
}

/**
 * Argument position of interest for extension wrapper calls:
 * beacon.add_variants(store, case_obj, form) carries the request
 * form at index 2; the MatchMaker methods carry patient/node data at
 * index 0.
 */
int extensionArgIndex(string method) {
  method = "add_variants" and result = 2
  or
  method in [
    "patient_submit",
    "patient_delete",
    "patient_matches",
    "match_internal",
    "match_external",
    "delete_variants"
  ] and result = 0
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
    // (1) requests.get/post/delete/request(...) module-level calls
    //     URL at positional argument 0, or at the url= keyword
    //     (argIndex -1).
    //     Verified sites (complete inventory of requests.* calls
    //     in scout/, import requests everywhere):
    //       alignviewers/views.py:42 requests.request(
    //         method=request.method, url=remote_url, headers=...,
    //         data=..., cookies=..., allow_redirects=True)
    //         - the remote CORS proxy; URL is the <path:remote_url>
    //           route variable (url= keyword form)
    //       cases/controllers.py:94 requests.post(
    //         base_url + "reports/report", ...) - base_url is
    //         request.url_root (Host-header-derived)
    //       cases/controllers.py:548/:554 requests.post(
    //         cov_calc_url, json=data) - url_for _external=True
    //       cases/controllers.py:894 requests.post(url, params=...,
    //         json=metadata, auth=HTTPBasicAuth(...)) - Rerunner
    //         entrypoint from admin config
    //       adapter/mongo/rank_model.py:23 requests.get(
    //         rank_model_url) - config prefix + case version
    //       utils/ensembl_rest_clients.py:81 requests.get(url,
    //         headers=HEADERS) and :188 requests.get(url,
    //         stream=True) - fixed Ensembl hosts
    //       utils/scout_requests.py:34/:36 requests.post,
    //         :59/:61/:110 requests.get, :85/:87/:89
    //         requests.delete - the shared HTTP layer
    //     get/post/delete/request are the only request verbs used.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name reqModule, string verb |
      n = c and
      fn = c.getFunc() and
      fn.getName() = verb and
      verb in ["get", "post", "delete", "request"] and
      reqModule = fn.getObject() and
      reqModule.getId() = "requests" and
      (
        (
          exists(Expr a0 | a0 = c.getArg(0)) and
          not exists(Keyword k |
            k = c.getAKeyword() and
            k.getArg() = "url"
          ) and
          argIndex = 0
        )
        or
        (
          exists(Keyword k |
            k = c.getAKeyword() and
            k.getArg() = "url"
          ) and
          argIndex = -1
        )
      ) and
      callableName = "requests." + verb and
      flowKind = "argument" and
      receiverHint = "requests"
    )

    or

    // --------------------------------------------------------
    // (2) urllib.request.urlopen(url, timeout=...)
    //     scout/utils/scout_requests.py:141 (fetch_resource):
    //       response = urllib.request.urlopen(url, timeout=TIMEOUT)
    //     reached for every fetch_resource("ftp...") resource
    //     (fetch_hgnc, fetch_exac_constraint, OMIM downloads via
    //     CLI). URL at positional argument 0. Imported as
    //     `import urllib.request` (scout_requests.py:4), so the
    //     call is Attribute 'urlopen' on Attribute 'request' on
    //     Name 'urllib'.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Attribute reqAttr, Name urllibName |
      n = c and
      fn = c.getFunc() and
      fn.getName() = "urlopen" and
      reqAttr = fn.getObject() and
      reqAttr.getName() = "request" and
      urllibName = reqAttr.getObject() and
      urllibName.getId() = "urllib" and
      exists(Expr a0 | a0 = c.getArg(0)) and
      callableName = "urllib.request.urlopen" and
      flowKind = "argument" and
      receiverHint = "urllib.request" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (3a) bare-name scout_requests wrapper invocations
    //      (imported directly into the calling module):
    //        beacon_extension.py:39  get_request_json(url=f"{self.beacon_url}/")
    //        beacon_extension.py:131 post_request_json(url=..., headers=..., data=...)
    //        beacon_extension.py:180 delete_request_json(url=..., headers=..., data=...)
    //        loqus_extension.py:133/:183/:242 api_get(...) - positional URL
    //        load/panel.py:126/:131 fetch_resource(...) - positional URL
    //        scout_requests.py:147 get_request(url) inside fetch_resource
    //      URL at positional argument 0 or at the url= keyword
    //      (argIndex -1). The network I/O (requests.*) happens
    //      inside the wrapper in scout/utils/scout_requests.py.
    // --------------------------------------------------------

    exists(Call c, Name fn, string wrapperName |
      n = c and
      fn = c.getFunc() and
      fn.getId() = wrapperName and
      isScoutRequestWrapper(wrapperName) and
      (
        (
          exists(Expr a0 | a0 = c.getArg(0)) and
          not exists(Keyword k |
            k = c.getAKeyword() and
            k.getArg() = "url"
          ) and
          argIndex = 0
        )
        or
        (
          exists(Keyword k |
            k = c.getAKeyword() and
            k.getArg() = "url"
          ) and
          argIndex = -1
        )
      ) and
      callableName = "scout_requests." + wrapperName and
      flowKind = "argument" and
      receiverHint = "scout.utils.scout_requests"
    )

    or

    // --------------------------------------------------------
    // (3b) module-qualified scout_requests wrapper invocations:
    //      matchmaker_extension.py imports `from scout.utils import
    //      scout_requests` and calls
    //        :59 scout_requests.get_request_json(url=url, headers=headers)
    //        :61 scout_requests.delete_request_json(url=url, headers=headers)
    //        :63 scout_requests.post_request_json(url=url, headers=headers, data=...)
    //      (MatchMaker.request dispatch for every MME endpoint).
    //      URL at the url= keyword (argIndex -1) or positional 0.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name srq, string wrapperName |
      n = c and
      fn = c.getFunc() and
      fn.getName() = wrapperName and
      isScoutRequestWrapper(wrapperName) and
      srq = fn.getObject() and
      srq.getId() = "scout_requests" and
      (
        (
          exists(Expr a0 | a0 = c.getArg(0)) and
          not exists(Keyword k |
            k = c.getAKeyword() and
            k.getArg() = "url"
          ) and
          argIndex = 0
        )
        or
        (
          exists(Keyword k |
            k = c.getAKeyword() and
            k.getArg() = "url"
          ) and
          argIndex = -1
        )
      ) and
      callableName = "scout_requests." + wrapperName and
      flowKind = "argument" and
      receiverHint = "scout.utils.scout_requests"
    )

    or

    // --------------------------------------------------------
    // (4) MatchMaker / Beacon extension wrapper invocations from
    //     the web layer (URL assembled inside the wrapper from
    //     admin config, request-derived data in body / path):
    //       cases/controllers.py:1124 matchmaker.patient_submit(patient)
    //         (matchmaker_add, POST mme_add, form-derived patient)
    //       cases/controllers.py:1163 matchmaker.patient_delete(patient_id)
    //       cases/controllers.py:1206 matchmaker.patient_matches(patient_id)
    //       cases/controllers.py:1241 matchmaker.match_internal(patient)
    //       cases/controllers.py:1257 matchmaker.match_external(patient_id, node)
    //         (node from the <target> route variable)
    //       cases/views.py:93 beacon.add_variants(store, case_obj, request.form)
    //         (POST /beacon_add_variants/...; form at index 2)
    //     Restricted to the scout/server module tree so that
    //     same-named methods on unrelated objects elsewhere cannot
    //     match.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name extObj, string method |
      n = c and
      fn = c.getFunc() and
      fn.getName() = method and
      isExtensionNetworkMethod(method) and
      extObj = fn.getObject() and
      extObj.getId() in ["matchmaker", "beacon"] and
      inServerModule(n) and
      callableName = extensionReceiver(extObj.getId()) + "." + method and
      flowKind = "argument" and
      receiverHint = extensionReceiver(extObj.getId()) and
      argIndex = extensionArgIndex(method)
    )

    or

    // --------------------------------------------------------
    // (5) query_phenomizer.query(username, password, *hpo_ids)
    //     scout/server/blueprints/cases/controllers.py:837
    //     (hpo_diseases): the external query-phenomizer package
    //     performs the HTTP POST to the phenomizer server inside
    //     the library (endpoint not visible in this database).
    //     username/password come from app config; hpo_ids derive
    //     from case phenotype terms. Recorded at the wrapper call
    //     site with argIndex -1 (the interesting data is in the
    //     star-args). Coverage gap: final I/O is outside this DB.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name qp |
      n = c and
      fn = c.getFunc() and
      fn.getName() = "query" and
      qp = fn.getObject() and
      qp.getId() = "query_phenomizer" and
      inModule(c, "scout/server/blueprints/cases/controllers.py") and
      callableName = "query_phenomizer.query" and
      flowKind = "argument" and
      receiverHint = "query_phenomizer (external library)" and
      argIndex = -1
    )
  )

select
  n,
  "sink_candidate",
  callableName,
  flowKind,
  receiverHint,
  moduleHint,
  argIndex,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()
