/**
 * @name CairoSVG CWE-918 source candidate extraction
 * @description Extract source candidates from the CairoSVG CodeQL database
 *   (snapshot 58be378): input boundaries of an SVG conversion library for
 *   Pass 3 / CWE-918 (SSRF). Source families derived from real source
 *   inspection:
 *     1. public conversion entry parameters (svg2png/svg2pdf/svg2svg/svg2ps/
 *        svg2eps, Surface.convert: bytestring / url / file_obj) and CLI entry
 *        parameters (__main__.main: argv / stdin)
 *     2. CLI input reads (argparse options.input, parser.parse_args,
 *        sys.stdin, stdin.buffer)
 *     3. href/xlink:href/xml:base/style attribute reads out of the parsed
 *        SVG node dict (.get(...) with a resource-relevant string literal)
 *     4. Node.get_href() calls (the generic href reader)
 *     5. parse_url(...) call sites (relative-URL/base-URL composition of
 *        input-derived references; candidates for summary labeling rather
 *        than the earliest boundary)
 *     6. CSS parsing boundaries (tinycss2.parse_* and css.parse_declarations)
 *     7. the CSS @import URL token read (url_token.value)
 *     8. the defusedxml ElementTree.fromstring document parse
 *     9. file_obj.read() at the file-object entry
 *   CairoSVG is a library, not a web service: untrusted input is the SVG
 *   document content supplied by a host application (or CLI) and the
 *   external-resource references it embeds. Internal helper url parameters
 *   that merely forward already-derived URLs are NOT listed as sources here
 *   (they are covered on the sink side as wrapper candidates).
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong shape
 *   for candidate tables and @kind table is not assumed to exist.
 * @id iris/cairosvg-cwe918/extraction/sources
 * @tags ssrf
 */

import python

/* ------------------------------------------------------------------ */
/* Column contract (identical order to sinks.ql):                      */
/* ------------------------------------------------------------------ */

/*
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (function name, attribute name, or parameter name)
 *   4. flow_kind  - "param"          (entry function parameter)
 *                   "cli"            (CLI input read)
 *                   "svg_attribute"  (dict.get of an input XML attribute)
 *                   "svg_href"       (Node.get_href() return value)
 *                   "url_derived"    (parse_url return value: composed resource URL)
 *                   "css_parse"      (CSS text parsing boundary, input text at arg 0)
 *                   "css_import_url" (CSS @import URL token read)
 *                   "xml_parse"      (defusedxml document parse, content at arg 0)
 *                   "file"           (file_obj.read() return value)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression, "" if none)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module` is
 *                   not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index that carries the
 *                   input (for param rows: the parameter position), -1 when
 *                   the candidate is a return value / attribute read
 *   8. file       - absolute file path, obtained through the Location API
 *                   (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "ast" (syntax-level match; every external input boundary
 *                   in this library is internal code, and defusedxml/tinycss2
 *                   are not part of the database, so no API-graph rows exist)
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
/* Source family 1: public conversion entry parameters                 */
/* ------------------------------------------------------------------ */

/**
 * Externally callable entry functions of the library:
 *   - the five svg2* API functions in cairosvg/__init__.py
 *   - Surface.convert (classmethod) in cairosvg/surface.py, the single
 *     dispatch target of all svg2* entries
 *   - __main__.main, the CLI entry point in cairosvg/__main__.py
 * Identified by function name plus containing-file base name plus (for
 * convert) the enclosing class, because bare names like convert/main are
 * too collision-prone to match on name alone.
 */
predicate entryFunction(Function f) {
  f.getName() in ["svg2svg", "svg2png", "svg2pdf", "svg2ps", "svg2eps"] and
  f.getEnclosingModule().getFile().getBaseName() = "__init__.py"
  or
  f.getName() = "convert" and
  f.getEnclosingModule().getFile().getBaseName() = "surface.py" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "Surface"
  or
  f.getName() = "main" and
  f.getEnclosingModule().getFile().getBaseName() = "__main__.py"
}

/**
 * The resource-location / document-content parameters of the entry
 * functions: bytestring (SVG content), url (input filename or URL),
 * file_obj (file-like input), argv and stdin (CLI).
 * getArgByName covers both positional and keyword-only parameters.
 * Keyword-only parameters carry no positional index and use -1.
 */
predicate entryParam(Function f, Parameter p, string name, int argIndex) {
  entryFunction(f) and
  name in ["bytestring", "url", "file_obj", "argv", "stdin"] and
  p = f.getArgByName(name) and
  (
    argIndex = p.getPosition()
    or
    not exists(p.getPosition()) and argIndex = -1
  )
}

/* ------------------------------------------------------------------ */
/* Source families 2-9: input reads and parse boundaries               */
/* ------------------------------------------------------------------ */

/**
 * CLI input reads in cairosvg/__main__.py:
 *   - the argparse Namespace attribute options.input ("input filename or
 *     URL", forwarded as kwargs['url'] at __main__.py:72)
 *   - parser.parse_args(argv) (returns the options Namespace)
 *   - sys.stdin / stdin.buffer (piped SVG content, forwarded as
 *     kwargs['file_obj'] at __main__.py:70)
 */
predicate cliInputNode(AstNode n, string callableName, string flowKind,
                       string receiver) {
  exists(Attribute a |
    a.getName() = "input" and
    a.getObject() instanceof Name and
    a.getObject().(Name).getId() = "options" and
    n = a and
    callableName = "input" and
    flowKind = "cli" and
    receiver = "options"
  )
  or
  exists(Attribute a |
    a.getName() = "stdin" and
    a.getObject() instanceof Name and
    a.getObject().(Name).getId() = "sys" and
    n = a and
    callableName = "stdin" and
    flowKind = "cli" and
    receiver = "sys"
  )
  or
  exists(Attribute a |
    a.getName() = "buffer" and
    a.getObject() instanceof Name and
    a.getObject().(Name).getId() = "stdin" and
    n = a and
    callableName = "buffer" and
    flowKind = "cli" and
    receiver = "stdin"
  )
  or
  exists(Call c |
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "parse_args" and
    c.getFunc().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Name).getId() = "parser" and
    n = c and
    callableName = "parse_args" and
    flowKind = "cli" and
    receiver = "parser"
  )
}

/**
 * dict.get(...) reads of input-document attributes that identify external
 * resources: href, xlink:href, xml:base and the inline style attribute.
 * The Node dict is populated from XML attributes at parser.py:190
 * (self.update(self.xml_tree.attrib)); these read sites are where
 * input-derived reference strings surface in later consumers.
 */
predicate svgAttributeRead(Call c, string literalKey) {
  exists(StringLiteral lit |
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    lit = c.getPositionalArg(0) and
    lit.getText() in [
      "href",
      "{http://www.w3.org/1999/xlink}href",
      "{http://www.w3.org/XML/1998/namespace}base",
      "style"
    ] and
    literalKey = lit.getText()
  )
}

/**
 * Content/parse boundary call shapes:
 *   - .get_href()      : the generic href reader (parser.py:312)
 *   - parse_url(...)   : URL composition of input-derived references
 *   - file_obj.read()  : entry file-object content read (parser.py:359)
 *   - ElementTree.fromstring(...) : defusedxml document parse
 *     (parser.py:390); bytestring at positional argument 0
 */
predicate contentBoundaryNode(AstNode n, string callableName, string flowKind,
                              string receiver, int argIndex) {
  exists(Call c |
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get_href" and
    n = c and
    callableName = "get_href" and
    flowKind = "svg_href" and
    receiver = receiverHintOfCall(c) and
    argIndex = -1
  )
  or
  exists(Call c |
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = "parse_url" and
    n = c and
    callableName = "parse_url" and
    flowKind = "url_derived" and
    receiver = "" and
    argIndex = -1
  )
  or
  exists(Call c |
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "read" and
    c.getFunc().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Name).getId() = "file_obj" and
    n = c and
    callableName = "read" and
    flowKind = "file" and
    receiver = "file_obj" and
    argIndex = -1
  )
  or
  exists(Call c |
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "fromstring" and
    c.getFunc().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Name).getId() = "ElementTree" and
    n = c and
    callableName = "fromstring" and
    flowKind = "xml_parse" and
    receiver = "ElementTree" and
    argIndex = 0
  )
}

/**
 * CSS parsing boundaries: tinycss2.parse_stylesheet / parse_one_component_value /
 * parse_declaration_list (css.py:24/34/54/96, input text at argument 0) and
 * the internal css.parse_declarations of inline style attributes
 * (parser.py:195, style attribute content at argument 0).
 */
predicate cssParseNode(Call c, string callableName, string receiver,
                       int argIndex) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() in [
    "parse_stylesheet",
    "parse_one_component_value",
    "parse_declaration_list"
  ] and
  c.getFunc().(Attribute).getObject() instanceof Name and
  c.getFunc().(Attribute).getObject().(Name).getId() = "tinycss2" and
  callableName = c.getFunc().(Attribute).getName() and
  receiver = "tinycss2" and
  argIndex = 0
  or
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = "parse_declarations" and
  c.getFunc().(Attribute).getObject() instanceof Name and
  c.getFunc().(Attribute).getObject().(Name).getId() = "css" and
  callableName = "parse_declarations" and
  receiver = "css" and
  argIndex = 0
}

/** The CSS @import URL token read at css.py:37 (url_token.value). */
predicate cssImportUrlRead(Attribute a) {
  a.getName() = "value" and
  a.getObject() instanceof Name and
  a.getObject().(Name).getId() = "url_token"
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: public entry function parameters.
   * The callable column carries "<functionName>.<parameterName>" so that
   * labeling can attach to the exact entry parameter. */
  exists(Parameter p, string paramName, Function f |
    entryParam(f, p, paramName, argIndex) and
    node = p and
    callableName = f.getName() + "." + paramName and
    flowKind = "param" and
    receiver = "" and
    matchKind = "ast" and
    moduleHint = moduleHintOf(p)
  )
  or
  /* family 2: CLI input reads */
  exists(AstNode n |
    cliInputNode(n, callableName, flowKind, receiver) and
    node = n and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(n)
  )
  or
  /* family 3: href/xlink:href/xml:base/style attribute reads */
  exists(Call c |
    svgAttributeRead(c, callableName) and
    node = c and
    flowKind = "svg_attribute" and
    receiver = receiverHintOfCall(c) and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* families 4-7 and 9: get_href / parse_url / read / fromstring shapes */
  exists(AstNode n |
    contentBoundaryNode(n, callableName, flowKind, receiver, argIndex) and
    node = n and
    matchKind = "ast" and
    moduleHint = moduleHintOf(n)
  )
  or
  /* family 6: CSS parse boundaries */
  exists(Call c |
    cssParseNode(c, callableName, receiver, argIndex) and
    node = c and
    flowKind = "css_parse" and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 7: CSS @import URL token read */
  exists(Attribute a |
    cssImportUrlRead(a) and
    node = a and
    callableName = "value" and
    flowKind = "css_import_url" and
    receiver = "url_token" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(a)
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint,
    argIndex, matchKind) and
  not isTestPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "source_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
