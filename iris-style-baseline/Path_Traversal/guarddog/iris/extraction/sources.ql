/*
 * GuardDog (vulnerable snapshot) - Pass 1 (CWE-22 / CWE-23 / CWE-36 / CWE-73) source
 * candidate extraction.
 *
 * Run with:
 *   codeql query run extraction/sources.ql --database <DB> --output extraction/sources.bqrs
 *   codeql bqrs decode extraction/sources.bqrs --format=csv --output=extraction/sources.csv
 *
 * Plain multi-column select query for candidate extraction. It deliberately carries no
 * @kind problem annotation (multi-column extraction must not be declared as a problem
 * query) and assumes no @kind table support.
 *
 * Column contract (shared with sinks.ql):
 *   node, role, callableName, flowKind, receiver, moduleHint, argIndex, location, context
 *
 * Evidence-driven source families (all observed in the shipped guarddog package;
 * tests/ and scripts/evaluator/ are excluded, guarddog-db is not part of the source set):
 *   1. Parameters of click CLI handler functions (guarddog/cli.py: verify, scan)
 *   2. Parameters of internal scanner wrappers carrying path/name/url values
 *      (package_scanner.py, project_scanner.py, analyzer.py, package_info.py)
 *   3. os.getenv(...) environment reads (recorded with trust-boundary caveat)
 *   4. requests.get(...) remote HTTP responses (PyPI / GitHub raw)
 *   5. .json() / .read() / .readlines() content reads and deserialization
 *
 * Note: argIndex for parameter rows is the declared positional index; for methods this
 * includes 'self' at index 0. -1 is used for return-value candidates.
 */

import python

/* ---------------- shared helpers ---------------- */

/*
 * Dotted syntactic path of an expression, e.g. "os.path.join", "requests.get",
 * "tarsafe.open". Textual resolution only: it does not track alias imports.
 */
string dottedPath(Expr e) {
  e instanceof Name and result = e.(Name).getId()
  or
  e instanceof Attribute and e.(Attribute).getObject() instanceof Name and
    result = e.(Attribute).getObject().(Name).getId() + "." + e.(Attribute).getName()
  or
  e instanceof Attribute and e.(Attribute).getObject() instanceof Attribute and
    result = dottedPath(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
}

/* "file:line" location string. AstNode.getFile() does not exist; use the Location API. */
string locationStr(AstNode n) {
  result = n.getLocation().getFile().getAbsolutePath() + ":" +
    n.getLocation().getStartLine().toString()
}

/* Exclude tests/ and the offline evaluation harness from candidate extraction. */
predicate inAnalysisScope(AstNode n) {
  exists(File f | f = n.getLocation().getFile() |
    not f.getAbsolutePath().matches("%/tests/%") and
    not f.getAbsolutePath().matches("%\\tests\\%") and
    not f.getAbsolutePath().matches("%/scripts/evaluator/%") and
    not f.getAbsolutePath().matches("%\\scripts\\evaluator\\%")
  )
}

/* Receiver column for function-level candidates: enclosing class for methods, '' otherwise. */
string receiverOfFunction(Function f) {
  result = "" and not f.isMethod()
  or
  result = f.getEnclosingScope().(Class).getName() and f.isMethod()
}

/*
 * Click CLI handler detection via decorator expressions.
 * There is no Decorator AST type in Python CodeQL; Function.getADecorator() returns Expr.
 */
predicate isCliHandler(Function f) {
  exists(Expr d |
    d = f.getADecorator() and
    (
      dottedPath(d) = "cli.command" or
      dottedPath(d) = "click.command" or
      dottedPath(d) = "click.group" or
      dottedPath(d) = "click.argument" or
      dottedPath(d) = "click.option"
    )
  )
}

/* Internal scanner wrappers observed in the repo (parameters may carry paths/names). */
predicate isScannerWrapper(Function f) {
  f.getName() = "scan_local" or
  f.getName() = "scan_remote" or
  f.getName() = "_scan_remote" or
  f.getName() = "download_package" or
  f.getName() = "download_compressed" or
  f.getName() = "analyze" or
  f.getName() = "analyze_sourcecode" or
  f.getName() = "scan_requirements" or
  f.getName() = "get_package_info"
}

/* Parameter names observed to carry path/name/url values in the scanner wrappers. */
predicate isPathishParam(Parameter p) {
  p.getName() = "path" or
  p.getName() = "identifier" or
  p.getName() = "name" or
  p.getName() = "package_name" or
  p.getName() = "version" or
  p.getName() = "base_dir" or
  p.getName() = "directory" or
  p.getName() = "url" or
  p.getName() = "zippath" or
  p.getName() = "unzippedpath" or
  p.getName() = "requirements"
}

/* Context text for os.getenv rows; includes the literal variable name when available. */
string envVarContext(Call c) {
  exists(StringLiteral s | s = c.getArg(0) |
    result = "environment variable read: " + s.getText() +
      " (local operator credential/config; judge trust boundary before treating as source)"
  )
  or
  not exists(StringLiteral s | s = c.getArg(0)) and
    result = "environment variable read (name not a string literal)"
}

/* Context text for open-mode style literal argument 1, reused by content-read families. */
string contentReadContext(Attribute attr) {
  attr.getName() = "json" and
    result = "JSON deserialization of '" + attr.getObject().toString() +
      "' (remote PyPI/GitHub response or file content feeding path/name construction)"
  or
  attr.getName() = "read" and
    result = "content read from '" + attr.getObject().toString() +
      "' (downloaded archive bytes or file content)"
  or
  attr.getName() = "readlines" and
    result = "line-wise read from '" + attr.getObject().toString() +
      "' (requirements.txt content feeding dependency names)"
}

/* ---------------- source candidate rows ---------------- */

predicate sourceCandidate(
  string node, string callableName, string flowKind, string receiver, string moduleHint,
  int argIndex, string loc, string context
) {
  /* Family 1: click CLI handler parameters (guarddog/cli.py) */
  exists(Function f, Parameter p |
    isCliHandler(f) and
    exists(int i | f.getArg(i) = p) and
    inAnalysisScope(p) and
    node = "Parameter:" + p.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOfFunction(f) and
    moduleHint = f.getEnclosingModule().getName() and
    argIndex = p.getPosition() and
    loc = locationStr(p) and
    context = "click CLI handler '" + f.getName() + "' parameter '" + p.getName() +
      "' (command-line input; 'path'/'identifier'/'version' carry package paths, names and versions)"
  )

  or

  /* Family 2: internal scanner wrapper parameters (taint summary candidates) */
  exists(Function f, Parameter p |
    isScannerWrapper(f) and
    exists(int i | f.getArg(i) = p) and
    isPathishParam(p) and
    inAnalysisScope(p) and
    node = "Parameter:" + p.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOfFunction(f) and
    moduleHint = f.getEnclosingModule().getName() and
    argIndex = p.getPosition() and
    loc = locationStr(p) and
    context = "internal wrapper '" + f.getName() + "' parameter '" + p.getName() +
      "' (propagates caller-controlled path/name/url values; taint summary candidate)"
  )

  or

  /* Family 3: os.getenv environment reads */
  exists(Call c |
    inAnalysisScope(c) and
    dottedPath(c.getFunc()) = "os.getenv" and
    node = "Call:os.getenv" and
    callableName = "getenv" and
    flowKind = "return" and
    receiver = "os" and
    moduleHint = "os.getenv" and
    argIndex = -1 and
    loc = locationStr(c) and
    context = envVarContext(c)
  )

  or

  /* Family 4: requests.get/post/request remote HTTP responses */
  exists(Call c, Attribute attr |
    inAnalysisScope(c) and
    attr = c.getFunc() and
    (
      dottedPath(attr) = "requests.get" or
      dottedPath(attr) = "requests.post" or
      dottedPath(attr) = "requests.request"
    ) and
    node = "Call:" + dottedPath(attr) and
    callableName = attr.getName() and
    flowKind = "return" and
    receiver = "requests" and
    moduleHint = dottedPath(attr) and
    argIndex = -1 and
    loc = locationStr(c) and
    context = "remote HTTP response from '" + dottedPath(attr) +
      "' (PyPI JSON API / GitHub raw; metadata and archive bytes are attacker-influenced when scanning untrusted packages)"
  )

  or

  /* Family 5: .json() / .read() / .readlines() content reads */
  exists(Call c, Attribute attr |
    inAnalysisScope(c) and
    attr = c.getFunc() and
    (
      attr.getName() = "json" or
      attr.getName() = "read" or
      attr.getName() = "readlines"
    ) and
    node = "Call:." + attr.getName() and
    callableName = attr.getName() and
    flowKind = "return" and
    receiver = attr.getObject().toString() and
    moduleHint = "<dynamic>." + attr.getName() and
    argIndex = -1 and
    loc = locationStr(c) and
    context = contentReadContext(attr)
  )
}

from string candNode, string candCallable, string candFlowKind, string candReceiver,
  string candModuleHint, int candArgIndex, string candLocation, string candContext
where
  sourceCandidate(candNode, candCallable, candFlowKind, candReceiver, candModuleHint,
    candArgIndex, candLocation, candContext)
select
  candNode as node,
  "source_candidate" as role,
  candCallable as callableName,
  candFlowKind as flowKind,
  candReceiver as receiver,
  candModuleHint as moduleHint,
  candArgIndex as argIndex,
  candLocation as location,
  candContext as context
