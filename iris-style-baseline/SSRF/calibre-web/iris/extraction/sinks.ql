
/**
 * @name Calibre-Web sink candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate outbound-network request APIs from the
 *              Calibre-Web Flask application for subsequent LLM labeling.
 * @id py/augur/calibre-web/pass3-sinks
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * Only network-I/O call sites that exist in this source tree are
 * extracted. urllib.request.urlopen / urlretrieve / httpx are not
 * used anywhere in this project and are therefore absent.
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("sink_candidate")
 *  3. callable            (dotted signature hint)
 *  4. flow kind           (argument | return | call)
 *  5. receiver            (receiver/type hint)
 *  6. module hint         (dotted module path; variable named moduleHint,
 *                          "module" is a QL keyword and must not be used)
 *  7. argument index      (-1 when not applicable)
 *  8. line
 *  9. file:line
 * 10. expression text
 *
 * flow kind vocabulary:
 *   argument - the tainted URL/payload position is an argument of the call
 *   call     - wrapper invocation whose URL is constructed inside the
 *              wrapper (internal function issues the network request)
 */

import python

// ------------------------------------------------------------
// 1. Scope and location helpers
// ------------------------------------------------------------

/**
 * Restrict extraction to Calibre-Web production code.
 *
 * The nested calibre-web-db CodeQL database directory and the test/
 * harness tree are outside the cps/ package and are therefore
 * excluded by this path filter.
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    (
      path.matches("cps/%")
      or
      path = "cps.py"
    )
  )
}

/**
 * Restrict a candidate to the metadata provider package.
 * The path string is bound by equality before matches(), so no
 * unbound-variable error can occur (an inPath(n, pattern) predicate
 * would leave "pattern" unbound inside matches()).
 */
predicate inMetadataProvider(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("cps/metadata_provider/%")
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
    // (1) requests.get(url, ...) - URL at positional argument 0
    //     cps/helper.py:740, cps/metadata_provider/google.py:48,
    //     comicvine.py:49, lubimyczytac.py:115/203, cps/updater.py:76/352/378/613
    // --------------------------------------------------------

    exists(Call c, Attribute attr, Name lib |
      c = n and
      attr = c.getFunc() and
      attr.getName() = "get" and
      lib = attr.getObject() and
      lib.getId() = "requests" and
      callable = "requests.get" and
      flow_kind = "argument" and
      receiver = "requests" and
      arg_index = 0
    )

    or

    // --------------------------------------------------------
    // (2) requests.request(..., url=..., ...) - URL at the url= keyword
    //     cps/kobo.py:94 make_request_to_kobo_store
    //     (node is the keyword value expression; arg_index -1)
    // --------------------------------------------------------

    exists(Call c, Attribute attr, Name lib, Keyword k |
      attr = c.getFunc() and
      attr.getName() = "request" and
      lib = attr.getObject() and
      lib.getId() = "requests" and
      k = c.getAKeyword() and
      k.getArg() = "url" and
      n = k.getValue() and
      callable = "requests.request" and
      flow_kind = "argument" and
      receiver = "requests" and
      arg_index = -1
    )

    or

    // --------------------------------------------------------
    // (3) session.get(url, ...) on a requests.Session object,
    //     restricted to the metadata provider package
    //     cps/metadata_provider/amazon.py:53 (session) and :110 (self.session)
    //     Import resolution must be confirmed during labeling.
    // --------------------------------------------------------

    exists(Call c, Attribute attr |
      c = n and
      attr = c.getFunc() and
      attr.getName() = "get" and
      inMetadataProvider(n) and
      (
        (
          attr.getObject() instanceof Name and
          attr.getObject().(Name).getId() = "session"
        )
        or
        (
          attr.getObject() instanceof Attribute and
          attr.getObject().(Attribute).getName() = "session"
        )
      ) and
      callable = "requests.Session.get" and
      flow_kind = "argument" and
      receiver = "requests.Session" and
      arg_index = 0
    )

    or

    // --------------------------------------------------------
    // (4) pydrive httplib2 transport:
    //     Get_Http_Object().request(url, ...) - URL at argument 0
    //     cps/gdriveutils.py:626 do_gdrive_download
    // --------------------------------------------------------

    exists(Call c, Attribute attr, Call inner, Attribute innerFunc |
      c = n and
      attr = c.getFunc() and
      attr.getName() = "request" and
      inner = attr.getObject() and
      innerFunc = inner.getFunc() and
      innerFunc.getName() = "Get_Http_Object" and
      callable = "Get_Http_Object.request" and
      flow_kind = "argument" and
      receiver = "httplib2.Http" and
      arg_index = 0
    )

    or

    // --------------------------------------------------------
    // (5) scholarly.search_pubs(query) - library issues HTTP fetches
    //     with the query; query at positional argument 0
    //     cps/metadata_provider/scholar.py:47
    // --------------------------------------------------------

    exists(Call c, Attribute attr, Name lib |
      c = n and
      attr = c.getFunc() and
      attr.getName() = "search_pubs" and
      lib = attr.getObject() and
      lib.getId() = "scholarly" and
      callable = "scholarly.search_pubs" and
      flow_kind = "argument" and
      receiver = "scholarly" and
      arg_index = 0
    )

    or

    // --------------------------------------------------------
    // (6) Internal wrapper: helper.save_cover_from_url(url, book_path)
    //     forwards its first argument to requests.get
    //     cps/editbooks.py:808 (URL at positional argument 0)
    // --------------------------------------------------------

    exists(Call c, Attribute attr |
      c = n and
      attr = c.getFunc() and
      attr.getName() = "save_cover_from_url" and
      callable = "helper.save_cover_from_url" and
      flow_kind = "argument" and
      receiver = "cps.helper" and
      arg_index = 0
    )

    or

    // --------------------------------------------------------
    // (7) Internal wrapper invocation: make_request_to_kobo_store()
    //     issues requests.request internally with a URL built from
    //     request.full_path; call sites cps/kobo.py:114, 330, 1059.
    //     No argument of the call carries the URL, hence flow kind
    //     "call" and arg_index -1.
    // --------------------------------------------------------

    exists(Call c, Name fn |
      c = n and
      fn = c.getFunc() and
      fn.getId() = "make_request_to_kobo_store" and
      callable = "make_request_to_kobo_store" and
      flow_kind = "call" and
      receiver = "cps.kobo" and
      arg_index = -1
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
