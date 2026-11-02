/**
 * @name dtale CWE-918 sink candidate extraction
 * @description Extract network-request sink candidates from the D-Tale
 *   CodeQL database (snapshot 063423aa) for Pass 3 / CWE-918 (SSRF).
 *   Sink families derived from real source inspection (line evidence
 *   verified against the checked-out snapshot):
 *     1. resolved requests.get calls (API graphs, alias-aware): the
 *        ONLY HTTP-client API used in this tree. All 5 call sites:
 *          - dtale/cli/clickutils.py:244 `resp = requests.get(path,
 *            **req_kwargs)` inside handle_path - the shared remote-fetch
 *            funnel; `path` is the URL and `req_kwargs` carries the
 *            caller-supplied `proxy` as requests proxies
 *            (dict(http=proxy, https=proxy), clickutils.py:241-243).
 *            Reachable from the UNAUTHENTICATED /web-upload route
 *            (views.py:3921: `url = get_str_arg(request, "url")` :3930
 *            -> load_csv/load_json/load_excel(path=url, proxy=proxy)
 *            :3933/:3945/:3951 -> loader handle_path) and from the CLI
 *            --csv-path/--csv-proxy style options.
 *          - dtale/datasets.py:40 `response = requests.get(url)` inside
 *            load_zip (demo dataset fetcher; url parameter forwarded
 *            from hardcoded GitHub literals, also reachable via
 *            /datasets -> getattr(datasets, dataset)())
 *          - dtale/views.py:196 kill() `requests.get(build_shutdown_url
 *            (base))` and :210 is_up() `requests.get("{}/health".
 *            format(base), verify=False, timeout=10)` (DtaleData
 *            internal instance URLs)
 *          - dtale/app.py:272 reaper closure `requests.get(self.
 *            shutdown_url)` (internal shutdown URL)
 *     2. syntax-level shapes of the same API (`requests.get(...)`)
 *     3. the internal remote-fetch funnel call sites: handle_path(...)
 *        (csv_loader.py:29, excel_loader.py:31, json_loader.py:38) -
 *        summary/label candidates; the loaders hand the caller's path/
 *        proxy to the funnel
 *     4. internal loader wrappers: functions whose body calls
 *        handle_path (csv_loader.loader_func, excel_loader.load_file,
 *        json_loader.loader_func)
 *     5. internal fetch wrappers: functions whose body directly issues
 *        a requests.get fetch (handle_path, load_zip, kill, is_up, the
 *        app reaper closure _func)
 *     6. URL parse/encode construction: urllib.parse.parse_qsl /
 *        urlencode (charts.py:91/:94/:199) and urllib quote/unquote
 *        (utils.py:49/:56, PY2/PY3 shims) - URL handling but NOT final
 *        network I/O; emitted only as summary-labeling candidates
 *   requests.post/put/head/delete/patch/request/Session, httpx,
 *   aiohttp, urllib.request.urlopen and urllib.request.urlretrieve have
 *   ZERO call sites in this tree and are not emitted (operator rule:
 *   only APIs proven present; see detection.json uncoveredCases).
 *   pandas IO calls (pd.read_csv/read_json/read_excel/read_parquet)
 *   fetch URLs library-internally and are not provable from this source
 *   tree - listed as a coverage gap, not emitted. is_url()
 *   (clickutils.py:234-235) is the http(s)-prefix gate that routes
 *   handle_path into requests.get, not a sanitizer or sink.
 *   Rows under tests/, dtale-db/ and the pre-existing root-level
 *   ssrf_analyzer.py / ssrf_precise_analyzer.py artifacts are excluded
 *   by path.
 *   Raw BQRS extraction query: run with `codeql query run` and decode
 *   with `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/dtale-cwe918/extraction/sinks
 * @tags ssrf
 */

import python
import semmle.python.ApiGraphs

/* ------------------------------------------------------------------ */
/* Column contract (identical order to sources.ql):                    */
/* ------------------------------------------------------------------ */

/*
 *   1. node       - candidate AST node (location-backed, decodes as
 *                   file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - API member name, funnel/wrapper function name, or
 *                   the parse-function attribute name
 *   4. flow_kind  - "arg"                    (external HTTP API verb
 *                                             call, URL at arg_index)
 *                   "internal_path_funnel"   (handle_path call site)
 *                   "internal_loader_wrapper"(function that hands its
 *                                             path/proxy to the funnel)
 *                   "internal_fetch_wrapper" (function that directly
 *                                             issues a network request)
 *                   "url_parse"              (urllib parse/encode
 *                                             reference; not final I/O)
 *   5. receiver   - syntactic receiver hint (module prefix "requests"/
 *                   "urllib"/"urllib.parse" for external ast rows,
 *                   enclosing class name for wrapper rows, "" if none)
 *   6. moduleHint - external module name ("requests", "urllib.parse")
 *                   for API rows or the dotted python module path of
 *                   the candidate (variable intentionally named
 *                   moduleHint; `module` is not a valid QL variable
 *                   name here)
 *   7. arg_index  - 0-based positional argument index carrying the URL
 *                   (0 for requests.get and handle_path), -1 when not
 *                   applicable (wrapper function rows, url_parse rows)
 *   8. file       - absolute file path, obtained through the Location
 *                   API (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or
 *                   "ast" (syntax-level match)
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Path filter (Augur candidate strategy: exclude tests/fixtures, the
 *  nested CodeQL database directory and the pre-existing root-level
 *  SSRF analysis artifacts, which are not D-Tale source). Both
 *  forward-slash and backslash separators are covered; only called
 *  with paths obtained from CodeQL File locations (input binding set
 *  declared explicitly). */
bindingset[p]
predicate isExcludedPath(string p) {
  p.matches("%/tests/%")
  or
  p.matches("%\\tests\\%")
  or
  p.matches("%/test_%.py")
  or
  p.matches("%\\test_%.py")
  or
  p.matches("%/conftest.py")
  or
  p.matches("%\\conftest.py")
  or
  p.matches("%dtale-db%")
  or
  p.matches("%ssrf_analyzer.py")
  or
  p.matches("%ssrf_precise_analyzer.py")
}

/** Dotted path of the python module containing n (used as moduleHint
 *  for internal candidates). Files that are not on an import path have
 *  no dotted module name; their file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getBaseName()
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Sink families 1+2: external HTTP-client API (API graphs + AST)      */
/* ------------------------------------------------------------------ */

/**
 * External HTTP-client API table with the 0-based positional argument
 * index that carries the URL. Only APIs proven present in this tree:
 * requests.get (URL at arg 0) - the single HTTP verb used anywhere in
 * D-Tale. requests.post/put/..., requests.Session, httpx, aiohttp,
 * urllib.request.urlopen/urlretrieve do not occur in the tree and are
 * deliberately absent (operator rule).
 */
predicate httpApiShape(string moduleHint, string member, string flowKind, int argIndex) {
  moduleHint = "requests" and
  member = "get" and
  flowKind = "arg" and
  argIndex = 0
}

/** Holds if cn is a call node genuinely resolved to the external
 *  requests.get API (alias-aware, covers `import requests` +
 *  `requests.get(...)` and `from requests import get` + `get(...)`
 *  idioms). */
private predicate resolvedHttpApiCall(API::CallNode cn, string moduleHint,
                                      string member, string flowKind, int argIndex) {
  httpApiShape(moduleHint, member, flowKind, argIndex) and
  cn = API::moduleImport(moduleHint).getMember(member).getACall()
}

/** AST-only matches: syntactic `requests.get(...)` shapes. Intentionally
 *  redundant with the api family (covers shapes API graphs miss). */
private predicate syntacticHttpApiCall(Call c, string moduleHint, string member,
                                       string flowKind, int argIndex) {
  httpApiShape(moduleHint, member, flowKind, argIndex) and
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = member and
  c.getFunc().(Attribute).getObject() instanceof Name and
  c.getFunc().(Attribute).getObject().(Name).getId() = moduleHint
}

/* ------------------------------------------------------------------ */
/* Sink family 3: the internal remote-fetch funnel call sites          */
/* ------------------------------------------------------------------ */

/**
 * handle_path(path, kwargs) call sites: the shared remote-fetch funnel
 * in dtale.cli.clickutils (is_url(path) -> requests.get(path,
 * proxies=proxy)). In-tree callers (all three pass the caller's
 * path/proxy through):
 *   - dtale/cli/loaders/csv_loader.py:29   `path = handle_path(kwargs.pop("path"), kwargs)`
 *   - dtale/cli/loaders/excel_loader.py:31 `path = handle_path(path, kwargs)`
 *   - dtale/cli/loaders/json_loader.py:38  `path = handle_path(kwargs.pop("path"), kwargs, resp_handler=resp_handler)`
 * The URL is positional argument 0. The funnel definition itself is
 * emitted by the internal_fetch_wrapper family.
 */
private predicate pathFunnelCall(Call c) {
  c.getFunc() instanceof Name and
  c.getFunc().(Name).getId() = "handle_path"
}

/* ------------------------------------------------------------------ */
/* Sink families 4+5: internal loader and fetch wrappers               */
/* ------------------------------------------------------------------ */

/** Functions in this codebase whose body calls handle_path: the
 *  csv/json/excel loader_func wrappers that sit between the /web-upload
 *  route (or CLI options) and the fetch funnel. */
private predicate internalLoaderWrapper(Function f) {
  exists(Call c |
    pathFunnelCall(c) and
    c.getScope().(Function) = f
  )
}

/** Holds if c is any call site (resolved or syntactic shape) that
 *  issues a network request: an external requests.get verb call.
 *  handle_path funnel calls and URL parsing are not fetch sites by
 *  themselves (they are emitted as their own families). */
private predicate fetchCallSite(Call c) {
  syntacticHttpApiCall(c, _, _, "arg", _)
  or
  exists(API::CallNode cn, string moduleHint, string member, int argIndex |
    resolvedHttpApiCall(cn, moduleHint, member, "arg", argIndex) and
    c = astCallOf(cn)
  )
}

/** Functions in this codebase whose body directly issues a network
 *  request (clickutils.py handle_path, datasets.py load_zip,
 *  views.py kill and is_up, and the reaper closure _func in
 *  app.py build_reaper). */
private predicate internalFetchWrapper(Function f) {
  exists(Call c |
    fetchCallSite(c) and
    c.getScope().(Function) = f
  )
}

/* ------------------------------------------------------------------ */
/* Sink family 6: URL parse/encode construction (AST)                  */
/* ------------------------------------------------------------------ */

/**
 * References to urllib URL parse/encode helpers - the PY2/PY3 shims of
 * dtale (returned by getter functions, then invoked by chart URL
 * building and data-id quoting):
 *   - dtale/dash_application/charts.py:91/:94 `urllib.parse.parse_qsl`
 *     / `urllib.parse_qsl` (get_url_parser)
 *   - dtale/dash_application/charts.py:199 `urllib.parse.urlencode` /
 *     `urllib.urlencode` (url_encode_func, chart querystrings)
 *   - dtale/utils.py:49 `urllib.parse.unquote` / `urllib.unquote`
 *     (get_url_unquote, data_id decoding in app.py url_value_preprocessor)
 *   - dtale/utils.py:56 `urllib.parse.quote` / `urllib.quote`
 *     (get_url_quote, data_id encoding)
 * These are NOT final network I/O; they are emitted so the labeling
 * pass can decide summary/none roles. Only the syntactic shapes
 * `urllib.parse.<name>` and `urllib.<name>` are matched.
 */
private predicate urlParseReference(AstNode n, string callableName,
                                    string receiver, string moduleHint) {
  exists(Attribute a |
    a.getName() = callableName and
    callableName in ["parse_qsl", "urlencode", "quote", "unquote"] and
    (
      /* urllib.parse.<name> */
      a.getObject() instanceof Attribute and
      a.getObject().(Attribute).getName() = "parse" and
      a.getObject().(Attribute).getObject() instanceof Name and
      a.getObject().(Attribute).getObject().(Name).getId() = "urllib" and
      receiver = "urllib.parse" and
      moduleHint = "urllib.parse"
      or
      /* urllib.<name> (PY2 fallback shims) */
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() = "urllib" and
      receiver = "urllib" and
      moduleHint = "urllib"
    ) and
    n = a
  )
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: resolved external HTTP-client API calls (API graphs) */
  exists(API::CallNode cn, string member |
    resolvedHttpApiCall(cn, moduleHint, member, flowKind, argIndex) and
    node = astCallOf(cn) and
    callableName = member and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 2: syntax-level external HTTP-client API shapes */
  exists(Call c |
    syntacticHttpApiCall(c, moduleHint, callableName, flowKind, argIndex) and
    node = c and
    receiver = "requests" and
    matchKind = "ast"
  )
  or
  /* family 3: handle_path funnel call sites */
  exists(Call c |
    pathFunnelCall(c) and
    node = c and
    callableName = "handle_path" and
    flowKind = "internal_path_funnel" and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c) and
    receiver = ""
  )
  or
  /* family 4: internal loader wrappers (functions calling handle_path) */
  exists(Function f |
    internalLoaderWrapper(f) and
    node = f and
    callableName = f.getName() and
    flowKind = "internal_loader_wrapper" and
    argIndex = -1 and
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
  /* family 5: internal functions that directly issue network requests */
  exists(Function f |
    internalFetchWrapper(f) and
    node = f and
    callableName = f.getName() and
    flowKind = "internal_fetch_wrapper" and
    argIndex = -1 and
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
  /* family 6: URL parse/encode references (not final network I/O) */
  exists(AstNode n |
    urlParseReference(n, callableName, receiver, moduleHint) and
    node = n and
    flowKind = "url_parse" and
    argIndex = -1 and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  not isExcludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "sink_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
