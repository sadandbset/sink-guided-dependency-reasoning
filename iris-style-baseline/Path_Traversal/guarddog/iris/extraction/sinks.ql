/*
 * GuardDog (vulnerable snapshot) - Pass 1 (CWE-22 / CWE-23 / CWE-36 / CWE-73) sink
 * candidate extraction.
 *
 * Run with:
 *   codeql query run extraction/sinks.ql --database <DB> --output extraction/sinks.bqrs
 *   codeql bqrs decode extraction/sinks.bqrs --format=csv --output=extraction/sinks.csv
 *
 * Plain multi-column select query for candidate extraction. It deliberately carries no
 * @kind problem annotation (multi-column extraction must not be declared as a problem
 * query) and assumes no @kind table support.
 *
 * Column contract (shared with sources.ql):
 *   node, role, callableName, flowKind, receiver, moduleHint, argIndex, location, context
 *
 * Sink definition: real filesystem operations (or extraction into the filesystem) whose
 * path argument may be attacker-controlled. Path-string construction nodes
 * (os.path.join / abspath / relpath, pathlib.Path(...)) are intentionally NOT emitted
 * here; they are recorded as propagation evidence in exploration/detection.json.
 *
 * Families (all observed in the shipped guarddog package; tests/ and
 * scripts/evaluator/ are excluded, guarddog-db is not part of the source set):
 *   1. built-in open()            - arg 0 (mode captured from literal arg 1)
 *   2. shutil.unpack_archive      - args 0 and 1 (archive path / destination)
 *   3. .extractall (any receiver) - arg 0 (destination; tarsafe receiver noted)
 *   4. os.remove / os.unlink / os.rmdir / shutil.rmtree - arg 0 (deletion)
 *   5. os.listdir                 - arg 0 (directory enumeration)
 *   6. os.path.exists / isdir / isfile / getmtime - arg 0 (TOCTOU-relevant checks)
 *   7. invoke_semgrep             - arg 1 (target path list of the external scanner)
 */

import python

/* ---------------- shared helpers ---------------- */

/* Dotted syntactic path of an expression, e.g. "shutil.unpack_archive", "os.path.join". */
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

/* Mode text for open() rows, taken from a literal argument 1 when present. */
string openModeContext(Call c) {
  exists(StringLiteral m | m = c.getArg(1) |
    result = "; mode: " + m.getText()
  )
  or
  not exists(StringLiteral m | m = c.getArg(1)) and
    result = ""
}

/* ---------------- sink candidate rows ---------------- */

predicate sinkCandidate(
  string node, string callableName, string flowKind, string receiver, string moduleHint,
  int argIndex, string loc, string context
) {
  /* Family 1: built-in open() - path is argument 0 */
  exists(Call c |
    inAnalysisScope(c) and
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = "open" and
    exists(Expr a | a = c.getArg(0)) and
    node = "Call:open" and
    callableName = "open" and
    flowKind = "arg" and
    receiver = "" and
    moduleHint = "open" and
    argIndex = 0 and
    loc = locationStr(c) and
    context = "built-in file open; argument 0 is the file path" + openModeContext(c)
  )

  or

  /* Family 2: shutil.unpack_archive - archive path (arg 0) and destination (arg 1) */
  exists(Call c, int ai |
    inAnalysisScope(c) and
    dottedPath(c.getFunc()) = "shutil.unpack_archive" and
    (ai = 0 or ai = 1) and
    exists(Expr a | a = c.getArg(ai)) and
    node = "Call:shutil.unpack_archive" and
    callableName = "unpack_archive" and
    flowKind = "arg" and
    receiver = "shutil" and
    moduleHint = "shutil.unpack_archive" and
    argIndex = ai and
    loc = locationStr(c) and
    context = "generic archive extraction; entry names inside the archive control extracted " +
      "paths (path traversal / zip-slip); argument " + ai.toString() +
      " is the archive path or the extraction destination"
  )

  or

  /* Family 3: .extractall method call - destination is argument 0 */
  exists(Call c, Attribute attr |
    inAnalysisScope(c) and
    attr = c.getFunc() and
    attr.getName() = "extractall" and
    exists(Expr a | a = c.getArg(0)) and
    node = "Call:.extractall" and
    callableName = "extractall" and
    flowKind = "arg" and
    receiver = attr.getObject().toString() and
    moduleHint = "<dynamic>.extractall" and
    argIndex = 0 and
    loc = locationStr(c) and
    context = "archive extraction; argument 0 is the destination directory; receiver '" +
      attr.getObject().toString() + "' is a dynamic/wrapper call (e.g. tarsafe.open, a " +
      "path-sanitizing extraction wrapper - sanitizer candidate)"
  )

  or

  /* Family 4: file/directory deletion - path is argument 0 */
  exists(Call c |
    inAnalysisScope(c) and
    (
      dottedPath(c.getFunc()) = "os.remove" or
      dottedPath(c.getFunc()) = "os.unlink" or
      dottedPath(c.getFunc()) = "os.rmdir" or
      dottedPath(c.getFunc()) = "shutil.rmtree"
    ) and
    exists(Expr a | a = c.getArg(0)) and
    node = "Call:" + dottedPath(c.getFunc()) and
    callableName = c.getFunc().(Attribute).getName() and
    flowKind = "arg" and
    receiver = c.getFunc().(Attribute).getObject().toString() and
    moduleHint = dottedPath(c.getFunc()) and
    argIndex = 0 and
    loc = locationStr(c) and
    context = "file/directory deletion; argument 0 is the target path"
  )

  or

  /* Family 5: os.listdir - directory enumeration, argument 0 */
  exists(Call c |
    inAnalysisScope(c) and
    dottedPath(c.getFunc()) = "os.listdir" and
    exists(Expr a | a = c.getArg(0)) and
    node = "Call:os.listdir" and
    callableName = "listdir" and
    flowKind = "arg" and
    receiver = "os" and
    moduleHint = "os.listdir" and
    argIndex = 0 and
    loc = locationStr(c) and
    context = "directory enumeration (read access); argument 0 is the directory path"
  )

  or

  /* Family 6: filesystem existence/metadata checks - TOCTOU-relevant validation nodes */
  exists(Call c |
    inAnalysisScope(c) and
    (
      dottedPath(c.getFunc()) = "os.path.exists" or
      dottedPath(c.getFunc()) = "os.path.isdir" or
      dottedPath(c.getFunc()) = "os.path.isfile" or
      dottedPath(c.getFunc()) = "os.path.getmtime"
    ) and
    exists(Expr a | a = c.getArg(0)) and
    node = "Call:" + dottedPath(c.getFunc()) and
    callableName = c.getFunc().(Attribute).getName() and
    flowKind = "arg" and
    receiver = "os.path" and
    moduleHint = dottedPath(c.getFunc()) and
    argIndex = 0 and
    loc = locationStr(c) and
    context = "filesystem existence/metadata check on argument 0 (TOCTOU-relevant " +
      "check-then-use validation node; candidate sanitizer/check evidence)"
  )

  or

  /* Family 7: invoke_semgrep - external scanner target path list is argument 1 */
  exists(Call c |
    inAnalysisScope(c) and
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = "invoke_semgrep" and
    exists(Expr a | a = c.getArg(1)) and
    node = "Call:invoke_semgrep" and
    callableName = "invoke_semgrep" and
    flowKind = "arg" and
    receiver = "" and
    moduleHint = "invoke_semgrep" and
    argIndex = 1 and
    loc = locationStr(c) and
    context = "external resource loader (semgrep); argument 1 is the list of target paths " +
      "scanned, derived from the analyzed package path"
  )
}

from string candNode, string candCallable, string candFlowKind, string candReceiver,
  string candModuleHint, int candArgIndex, string candLocation, string candContext
where
  sinkCandidate(candNode, candCallable, candFlowKind, candReceiver, candModuleHint,
    candArgIndex, candLocation, candContext)
select
  candNode as node,
  "sink_candidate" as role,
  candCallable as callableName,
  candFlowKind as flowKind,
  candReceiver as receiver,
  candModuleHint as moduleHint,
  candArgIndex as argIndex,
  candLocation as location,
  candContext as context
