
/**
 * @name mindsdb sink candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate outbound-network request APIs from the
 *              mindsdb application (Flask/REST + SQL-wire + integration
 *              handlers) for subsequent LLM labeling.
 * @id py/augur/mindsdb/pass3-sinks
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * Scope: relative paths under mindsdb/ only, excluding per-handler
 * tests/ directories. This excludes the nested mindsdb-db CodeQL
 * database directory (its files would be mindsdb-db/..., which does
 * not match "mindsdb/%") and the repo-root tests/ tree by
 * construction.
 *
 * Only network-I/O call sites that exist in this source tree are
 * extracted. urllib.request.urlopen / urlretrieve, httpx, aiohttp,
 * http.client and pycurl are not used anywhere in this project
 * (urllib usage is parse-only: urlparse/urlencode/quote_plus), and
 * are therefore absent. `import requests` is never aliased and no
 * bare `from requests import get/post` style is used, so matching
 * the object Name 'requests' covers the complete module-level call
 * surface.
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("sink_candidate")
 *  3. callable            (dotted signature hint)
 *  4. flow kind           (argument)
 *  5. receiver            (receiver/type hint)
 *  6. module hint         (dotted module path; variable named moduleHint,
 *                          "module" is a QL keyword and must not be used)
 *  7. argument index      (-1 when not applicable)
 *  8. line
 *  9. file:line
 * 10. expression text
 *
 * flow kind vocabulary:
 *   argument - the tainted URL position is an argument of the call
 *              (positional index given, or the url=/uri= keyword
 *               value node is extracted with arg index -1)
 */

import python

// ------------------------------------------------------------
// 1. Scope and location helpers
// ------------------------------------------------------------

/**
 * Restrict extraction to the mindsdb application package, excluding
 * per-handler tests directories. The path string is bound by equality
 * before matches(), so no unbound-variable error can occur.
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("mindsdb/%") and
    not path.matches("mindsdb/%/tests/%")
  )
}

/** Restrict a candidate to the web crawl helper module. */
predicate inWebCrawlModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path = "mindsdb/integrations/handlers/web_handler/urlcrawl_helpers.py"
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
  string callable,
  string flow_kind,
  string receiver,
  string moduleHint,
  int arg_index
where
  inAnalysisScope(n) and
  moduleHint = moduleOf(n) and
  (
    // --------------------------------------------------------
    // (1) requests.get/post/put/delete/patch/head module-level
    //     calls; URL at positional argument 0, or at the url=
    //     keyword (node = keyword value, arg index -1).
    //     Representative call sites:
    //     - api/http/namespaces/file.py:116
    //         requests.get(url, stream=True)
    //         (url = data["source"] from PUT /api/files body when
    //          source_type == "url"; also requests.head(url) :99)
    //     - api/mysql/mysql_proxy/utilities/functions.py:33
    //         requests.get(url) in download_file(url)
    //         (called from executor_commands.py:1057 with the
    //          {'url': ...} PATH-type connection arg from SQL)
    //     - integrations/handlers/file_handler/file_handler.py:386
    //         requests.get(url, stream=True) in _fetch_url(url)
    //     - api/http/namespaces/auth.py:44/78/109 (cloud OAuth),
    //       session_controller.py:121 (executor service),
    //       handler_helpers.py:48 (registry),
    //       utilities/auth.py:19/45, utilities/functions.py:86,
    //       gui.py:24, initialize.py:71 (fixed/config hosts)
    //     - ~45 integration handler API clients (fixed provider
    //       hosts or url/host from connection args, e.g.
    //       confluence_handler.py:57 url=self.connection_data.get('url'))
    // --------------------------------------------------------

    exists(Call c, Attribute attr, Name lib, string verb |
      attr = c.getFunc() and
      attr.getName() = verb and
      verb in ["get", "post", "put", "delete", "patch", "head"] and
      lib = attr.getObject() and
      lib.getId() = "requests" and
      (
        (
          n = c and
          arg_index = 0 and
          not exists(Keyword k |
            k = c.getAKeyword() and
            k.getArg() = "url"
          )
        )
        or
        (
          exists(Keyword k |
            k = c.getAKeyword() and
            k.getArg() = "url" and
            n = k.getValue()
          ) and
          arg_index = -1
        )
      ) and
      callable = "requests." + verb and
      flow_kind = "argument" and
      receiver = "requests"
    )

    or

    // --------------------------------------------------------
    // (2) requests.request(...) module-level calls.
    //     With positional arguments the URL is at index 1
    //     (method first):
    //       e.g. dremio_handler.py:138/143/146
    //            requests.request("GET", self.base_url + ...)
    //            instatus_handler.py:105, intercom_handler.py:97,
    //            strapi_handler.py:96, sharepoint utils.py:153
    //     The **kwargs wrapper form has no extractable URL
    //     position (URL travels inside the kwargs dict):
    //       lightdash_handler/api.py:21
    //         return requests.request(**kwargs)
    //       sap_erp_handler/api.py:55
    //         return requests.request(**kwargs)
    //     extracted with node = call and arg index -1.
    // --------------------------------------------------------

    exists(Call c, Attribute attr, Name lib |
      attr = c.getFunc() and
      attr.getName() = "request" and
      lib = attr.getObject() and
      lib.getId() = "requests" and
      (
        (
          n = c and
          exists(c.getArg(1)) and
          arg_index = 1
        )
        or
        (
          n = c and
          not exists(c.getArg(1)) and
          arg_index = -1
        )
      ) and
      callable = "requests.request" and
      flow_kind = "argument" and
      receiver = "requests"
    )

    or

    // --------------------------------------------------------
    // (3) session.get(url, headers) transport call of the web
    //     crawl handler. 'session' is assigned from
    //     requests.Session() at urlcrawl_helpers.py:94 inside
    //     get_all_website_links(url); the URL originates from the
    //     web handler SQL surface (SELECT ... FROM crawl WHERE
    //     url = ... / native query) and is crawled recursively.
    //     URL at positional argument 0.
    // --------------------------------------------------------

    exists(Call c, Attribute method, Name sessionVar |
      c = n and
      method = c.getFunc() and
      method.getName() = "get" and
      sessionVar = method.getObject() and
      sessionVar.getId() = "session" and
      inWebCrawlModule(n) and
      exists(c.getArg(0)) and
      callable = "requests.Session.get" and
      flow_kind = "argument" and
      receiver = "requests.Session" and
      arg_index = 0
    )
  )

select
  n,
  "sink_candidate",
  callable,
  flow_kind,
  receiver,
  moduleHint,
  arg_index,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()
