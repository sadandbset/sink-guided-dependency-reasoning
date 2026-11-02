/**
 * @name CairoSVG CWE-918 sink candidate extraction
 * @description Extract sink candidate AST nodes (network resource fetch)
 *   from the CairoSVG CodeQL database (snapshot 58be378) for Pass 3 /
 *   CWE-918 (SSRF). Sink families derived from real source inspection:
 *     1. resolved urllib.request API calls (urlopen, Request; urlretrieve is
 *        kept as the standard CWE-918 baseline but does not occur in this
 *        source and is expected to yield zero rows) - the only real network
 *        I/O in the codebase is cairosvg/url.py:84
 *        urlopen(Request(url, headers=HTTP_HEADERS)).read() inside fetch()
 *     2. syntax-level bare-name calls of urlopen/Request (from-import
 *        aliases bound at url.py:10, same single call site)
 *     3. Node.fetch_url(url, resource_type) wrapper call sites
 *        (parser.py:386 external SVG, css.py:39 CSS @import,
 *        image.py:28 image element)
 *     4. read_url(url, url_fetcher, resource_type) wrapper call
 *        (parser.py:243)
 *     5. the url_fetcher(url, resource_type) dynamic dispatch
 *        (url.py:143) whose default target is fetch -> urlopen
 *     6. wrapper definitions whose url parameter reaches the network:
 *        fetch (url.py:77, param 0), read_url (url.py:132, param 0),
 *        Node.fetch_url (parser.py:242, param 1)
 *     7. Tree(...) constructions receiving url= keyword arguments
 *        (external SVG references from surface.py/parser.py/defs.py/
 *        bounding_box.py/image.py; Tree.__init__ fetches when no
 *        bytestring is given)
 *     8. the 'file://{}'.format(...) scheme rewrite in read_url
 *        (url.py:140), recorded separately as a non-HTTP scheme behavior
 *        (local file loading, not CWE-918 network SSRF by itself)
 *   URL parsing/joining (parse_url, urljoin, urlparse, urlunparse) is NOT
 *   recorded as a sink: those calls only build strings/objects and are
 *   covered as source-side url_derived candidates in sources.ql.
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong shape
 *   for candidate tables and @kind table is not assumed to exist.
 * @id iris/cairosvg-cwe918/extraction/sinks
 * @tags ssrf
 */

import python
import semmle.python.ApiGraphs

/* ------------------------------------------------------------------ */
/* Column contract (identical order to sources.ql):                    */
/* ------------------------------------------------------------------ */

/*
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or
 *                   attribute name; "Tree" for keyword-argument rows)
 *   4. flow_kind  - "arg"              (call site whose positional argument 0
 *                                       carries the fetched URL)
 *                   "kwarg"            (Tree(...) receiving url=... keyword)
 *                   "wrapper_param"    (definition whose url parameter reaches
 *                                       the network fetcher chain)
 *                   "fetcher_dispatch" (dynamic url_fetcher(url, ...) call)
 *                   "file_scheme"      (file:// URL construction)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression, "" if none; class name for method
 *                   definitions)
 *   6. moduleHint - module hint: "urllib.request" for resolved external API
 *                   calls, otherwise the dotted python module path of the
 *                   containing module (variable intentionally named
 *                   moduleHint; `module` is not a valid QL variable name)
 *   7. arg_index  - 0-based positional argument index that carries the URL,
 *                   parameter position for wrapper_param rows, -1 otherwise
 *   8. file       - absolute file path, obtained through the Location API
 *                   (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note on urlopen/Request argument positions: at the single real call site
 * (url.py:84) urlopen receives the Request object at index 0 and Request
 * receives the URL string at index 0; both rows use arg_index 0 so that
 * labeling and query generation can attach to whichever node carries the
 * tainted URL.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/**
 * Test-path filter (Augur candidate strategy: exclude tests and fixtures).
 *
 * `string` is an infinite-domain QL type. This predicate is intended to be
 * called only with a path that has already been obtained from a CodeQL File
 * location, so explicitly declare p as an input binding set.
 */
bindingset[p]
predicate isTestPath(string p) {
  p.matches("%test%")
}

/** Dotted path of the python module containing n (used as moduleHint).
 *  Top-level scripts that are not on an import path have no dotted module
 *  name; their file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getBaseName()
}

/** Base name of the object expression of an attribute access, used as a
 *  receiver hint. */
string receiverHint(Attribute a) {
  result = a.getObject().(Name).getId()
  or
  result = a.getObject().(Attribute).getName()
  or
  not a.getObject() instanceof Name and
  not a.getObject() instanceof Attribute and
  result = "<expr>"
}

/** Receiver hint for the callee expression of a call ("" when there is no
 *  attribute receiver). */
string receiverHintOfCall(Call c) {
  exists(Attribute a |
    a = c.getFunc() and
    result = receiverHint(a)
  )
  or
  not c.getFunc() instanceof Attribute and result = ""
}

/* ------------------------------------------------------------------ */
/* Sink family 1: resolved urllib.request API calls (API graphs)       */
/* ------------------------------------------------------------------ */

/**
 * Network request APIs of urllib.request with the 0-based positional
 * argument index that carries the target URL (urlopen's first argument is
 * the URL or the Request object wrapping it; Request's and urlretrieve's
 * first argument is the URL).
 *
 * url.py:10 binds both names through
 * `from urllib.request import Request, urlopen`, so the API graph resolves
 * them. urlretrieve does not occur in this source; it is kept because it is
 * the standard CWE-918 baseline set member and the extraction is meant to
 * be exhaustive (expected zero rows, same policy as previous projects).
 */
predicate resolvedNetCall(Call c, string member, int argIndex) {
  argIndex = 0 and
  (
    member = "urlopen" and
    c = API::moduleImport("urllib.request").getMember("urlopen").getACall().asExpr()
    or
    member = "Request" and
    c = API::moduleImport("urllib.request").getMember("Request").getACall().asExpr()
    or
    member = "urlretrieve" and
    c = API::moduleImport("urllib.request").getMember("urlretrieve").getACall().asExpr()
  )
}

/* ------------------------------------------------------------------ */
/* Sink family 2: syntax-level bare-name network call shapes           */
/* ------------------------------------------------------------------ */

/**
 * AST-only matches: bare-name calls of urlopen/Request/urlretrieve. In this
 * repository those names are bound only by the from-import at url.py:10,
 * so the moduleHint "urllib.request" is justified by source evidence even
 * though the match itself is syntactic; this family is the fallback for
 * shapes the API graph may miss.
 */
predicate bareNetCall(Call c, string member, int argIndex) {
  argIndex = 0 and
  c.getFunc() instanceof Name and
  c.getFunc().(Name).getId() = member and
  member in ["urlopen", "Request", "urlretrieve"]
}

/* ------------------------------------------------------------------ */
/* Sink families 3-5: internal fetcher wrapper call sites              */
/* ------------------------------------------------------------------ */

/**
 * Node.fetch_url(url, resource_type) call sites: the resource-loading
 * wrapper that every consumer of an input-derived reference goes through.
 * The url argument is a parsed URL object (parse_url result), position 0.
 */
predicate fetchUrlCall(Call c) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = "fetch_url"
}

/** read_url(url, url_fetcher, resource_type) bare-name call, position 0. */
predicate readUrlCall(Call c) {
  c.getFunc() instanceof Name and
  c.getFunc().(Name).getId() = "read_url"
}

/**
 * url_fetcher(url, resource_type) dynamic dispatch at url.py:143: the
 * callee is the pluggable fetcher callable (default fetch, which calls
 * urlopen). The dispatch target is not statically resolvable; the call
 * shape itself is the sink candidate.
 */
predicate fetcherDispatchCall(Call c) {
  c.getFunc() instanceof Name and
  c.getFunc().(Name).getId() = "url_fetcher"
}

/* ------------------------------------------------------------------ */
/* Sink family 6: wrapper definitions whose url parameter fetches      */
/* ------------------------------------------------------------------ */

/**
 * Internal wrappers on the path from a resource URL to the network:
 *   - fetch (url.py:77): default fetcher, directly calls urlopen; url at
 *     parameter position 0
 *   - read_url (url.py:132): rewrites schemeless URLs and dispatches to
 *     url_fetcher; url at parameter position 0
 *   - Node.fetch_url (parser.py:242): method wrapper, self at 0, url at
 *     parameter position 1
 * Identified by function name plus containing-file base name (plus the
 * enclosing class for the method), because bare names like fetch are too
 * collision-prone to match on name alone.
 */
predicate wrapperDefinition(Function f, string callableName, int argIndex) {
  f.getName() = "fetch" and
  f.getEnclosingModule().getFile().getBaseName() = "url.py" and
  callableName = "fetch" and
  argIndex = 0
  or
  f.getName() = "read_url" and
  f.getEnclosingModule().getFile().getBaseName() = "url.py" and
  callableName = "read_url" and
  argIndex = 0
  or
  f.getName() = "fetch_url" and
  f.getEnclosingModule().getFile().getBaseName() = "parser.py" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "Node" and
  callableName = "fetch_url" and
  argIndex = 1
}

/* ------------------------------------------------------------------ */
/* Sink family 7: Tree(...) url= keyword argument sites                */
/* ------------------------------------------------------------------ */

/**
 * Tree(...) constructions receiving a url= keyword argument. Tree.__init__
 * (parser.py:343) fetches the referenced document through
 * self.fetch_url(parse_url(self.url), 'image/svg+xml') whenever no
 * bytestring is supplied, so these keyword sites hand an input-derived
 * resource URL to the fetch chain. The keyword node is the row anchor.
 */
predicate treeUrlKeyword(Call c, Keyword k) {
  c.getFunc() instanceof Name and
  c.getFunc().(Name).getId() = "Tree" and
  k = c.getANamedArg().(Keyword) and
  k.getArg() = "url"
}

/* ------------------------------------------------------------------ */
/* Sink family 8: file:// scheme construction                          */
/* ------------------------------------------------------------------ */

/**
 * 'file://{}'.format(...) at url.py:140: read_url rewrites schemeless URLs
 * into local file:// URLs before dispatching to the fetcher. Recorded as a
 * separate non-HTTP-scheme row: local file loading is not CWE-918 network
 * SSRF by itself, but it is the scheme behavior to review when judging
 * fetcher reachability.
 */
predicate fileSchemeFormatCall(Call c) {
  exists(StringLiteral lit |
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "format" and
    c.getFunc().(Attribute).getObject() = lit and
    lit.getText().matches("file://%")
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
  /* family 1: resolved urllib.request API calls */
  exists(Call c |
    resolvedNetCall(c, callableName, argIndex) and
    node = c and
    flowKind = "arg" and
    receiver = "" and
    moduleHint = "urllib.request" and
    matchKind = "api"
  )
  or
  /* family 2: syntax-level bare-name network call shapes */
  exists(Call c |
    bareNetCall(c, callableName, argIndex) and
    node = c and
    flowKind = "arg" and
    receiver = "" and
    moduleHint = "urllib.request" and
    matchKind = "ast"
  )
  or
  /* family 3: Node.fetch_url wrapper call sites */
  exists(Call c |
    fetchUrlCall(c) and
    node = c and
    callableName = "fetch_url" and
    flowKind = "arg" and
    receiver = receiverHintOfCall(c) and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 4: read_url wrapper call site */
  exists(Call c |
    readUrlCall(c) and
    node = c and
    callableName = "read_url" and
    flowKind = "arg" and
    receiver = "" and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 5: url_fetcher dynamic dispatch call site */
  exists(Call c |
    fetcherDispatchCall(c) and
    node = c and
    callableName = "url_fetcher" and
    flowKind = "fetcher_dispatch" and
    receiver = "" and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 6: wrapper definitions whose url parameter reaches the network */
  exists(Function f |
    wrapperDefinition(f, callableName, argIndex) and
    node = f and
    flowKind = "wrapper_param" and
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
  /* family 7: Tree(...) url= keyword argument sites */
  exists(Call c, Keyword k |
    treeUrlKeyword(c, k) and
    node = k and
    callableName = "Tree" and
    flowKind = "kwarg" and
    receiver = "" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(k)
  )
  or
  /* family 8: file:// scheme construction in read_url */
  exists(Call c |
    fileSchemeFormatCall(c) and
    node = c and
    callableName = "format" and
    flowKind = "file_scheme" and
    receiver = "" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint,
    argIndex, matchKind) and
  not isTestPath(node.getLocation().getFile().getAbsolutePath())
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
