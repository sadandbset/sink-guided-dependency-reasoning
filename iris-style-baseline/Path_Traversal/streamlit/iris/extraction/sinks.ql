/**
 * @name streamlit Pass 1 sink candidates (Path Traversal)
 * @description Extracts filesystem-operation sink candidates for CWE-22/23/36/73
 *   from the streamlit 1.11.0 codebase: real file read/write/create/delete APIs
 *   (open, tokenize.open, os.remove, os.makedirs, os.stat, shutil.rmtree,
 *   tempfile.mkdtemp, tornado.netutil.bind_unix_socket) plus two
 *   dynamically-dispatched operations (tornado RequestHandler.render template
 *   load, pathlib Path.glob directory enumeration). Only calls that perform
 *   actual filesystem access are extracted; path-construction and validation
 *   nodes (os.path.join/abspath/basename/exists/isdir, pathlib.Path()) are
 *   treated as propagation/validation, not sinks, and in-memory media serving
 *   (MediaFileHandler) is excluded because it never touches disk.
 *   Evidence-derived from lib/streamlit/components/v1/components.py,
 *   lib/streamlit/server/routes.py, lib/streamlit/cli.py,
 *   lib/streamlit/elements/image.py, lib/streamlit/elements/media.py,
 *   lib/streamlit/file_util.py, lib/streamlit/source_util.py,
 *   lib/streamlit/credentials.py, lib/streamlit/config.py,
 *   lib/streamlit/secrets.py, lib/streamlit/metrics_util.py,
 *   lib/streamlit/watcher/util.py, lib/streamlit/caching/memo_decorator.py,
 *   lib/streamlit/legacy_caching/caching.py,
 *   lib/streamlit/temporary_directory.py and lib/streamlit/util.py.
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/streamlit-cwe22/extract-sinks
 */

import python

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Gets the dotted name of a simple name/attribute chain,
 * e.g. "os.path.join" or "shutil.rmtree".
 */
private string dottedName(Expr e) {
  result = e.(Name).getId()
  or
  result = dottedName(e.(Attribute).getValue()) + "." + e.(Attribute).getName()
}

/**
 * Gets the repository-relative path of the file containing this node,
 * e.g. "lib/streamlit/server/routes.py". The primary source is
 * File.getRelativePath() (backslash-normalized); on this Windows-created
 * database the stored source location prefix uses backslashes while file
 * paths are forward-slash normalized, so getRelativePath() may have no
 * result - in that case fall back to capturing the "lib/streamlit/..."
 * suffix from the absolute path (verified forward-slash format in the
 * database string pool and src.zip).
 */
private string relPath(AstNode n) {
  result = n.getLocation().getFile().getRelativePath().replaceAll("\\\\", "/")
  or
  not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
  result = n.getLocation().getFile().getAbsolutePath().regexpCapture(".*/(lib/streamlit/.+)$", 1)
}

/**
 * Restricts candidates to the lib/streamlit package itself. This structurally
 * excludes the nested streamlit-db CodeQL database directory, lib/tests/,
 * e2e/, scripts/ and the generated proto package, which are noise or out of
 * scope per the Augur policy.
 */
private predicate inStreamlitPackage(AstNode n) {
  relPath(n).matches("lib/streamlit/%") and
  not relPath(n).matches("lib/streamlit/proto/%")
}

/**
 * Gets a receiver hint for a call: the dotted object expression for
 * attribute calls (e.g. "os" for os.remove, or the variable name for
 * dynamically dispatched calls such as pages_dir.glob), "" for
 * plain-name calls.
 */
private string callReceiver(Call c) {
  c.getFunc() instanceof Name and result = ""
  or
  c.getFunc() instanceof Attribute and
  (
    exists(string obj | obj = dottedName(c.getFunc().(Attribute).getValue()) and result = obj)
    or
    not exists(string obj | obj = dottedName(c.getFunc().(Attribute).getValue())) and
      result = c.getFunc().(Attribute).getValue().toString()
  )
}

/**
 * Describes the syntactic shape of a path argument, so that labelers can see
 * whether the sink is fed by a join, a variable, a literal or a subscript.
 */
private string argNote(Expr arg) {
  if arg instanceof Call and exists(string d | d = dottedName(arg.(Call).getFunc()))
  then result = "call to " + dottedName(arg.(Call).getFunc())
  else if arg instanceof Name then result = "variable '" + arg.(Name).getId() + "'"
  else if arg instanceof Attribute and exists(string d | d = dottedName(arg))
  then result = "attribute '" + dottedName(arg) + "'"
  else if arg instanceof StringLiteral then result = "string literal"
  else if arg instanceof Subscript then result = "subscript expression"
  else result = "other expression"
}

/* ------------------------------------------------------------------ */
/* Sink families                                                       */
/* ------------------------------------------------------------------ */

/**
 * Filesystem calls whose callee resolves to a known dotted name.
 * `argIndex` selects the path-carrying positional argument (-1 when the
 * path is controlled through keyword arguments instead).
 */
private predicate resolvedFileIoCall(
  Call c, string dotted, string moduleHint, string receiver,
  int argIndex, string accessType
) {
  dotted = dottedName(c.getFunc()) and
  (
    (
      dotted = "open" and moduleHint = "builtins" and receiver = "" and argIndex = 0 and
      accessType = "file open (read or write per mode argument)"
    )
    or
    (
      dotted = "tokenize.open" and moduleHint = "tokenize" and receiver = "tokenize" and
      argIndex = 0 and
      accessType = "python source file open, PEP263-encoding-aware read (source_util.open_python_file wrapper)"
    )
    or
    (
      dotted = "os.remove" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "file delete"
    )
    or
    (
      dotted = "os.makedirs" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "directory create"
    )
    or
    (
      dotted = "os.stat" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "file stat (metadata read)"
    )
    or
    (
      dotted = "shutil.rmtree" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 0 and
      accessType = "directory tree delete"
    )
    or
    (
      dotted = "tempfile.mkdtemp" and moduleHint = "tempfile" and receiver = "tempfile" and
      argIndex = -1 and
      accessType = "temp directory creation; prefix/suffix/dir keyword arguments influence the created path"
    )
    or
    (
      dotted = "tornado.netutil.bind_unix_socket" and moduleHint = "tornado.netutil" and
      receiver = "tornado.netutil" and argIndex = 0 and
      accessType = "unix socket file creation at a config-derived path (server.address)"
    )
  )
}

/**
 * Dynamically dispatched filesystem operations on receivers whose module
 * cannot be resolved syntactically (tornado RequestHandler.render template
 * loads; pathlib Path.glob directory enumeration). The module hint is
 * inferred and the context records that caveat. Path.glob rows carry the
 * enumerated directory on the receiver, so their flow kind is 'receiver'
 * with argIndex -1.
 */
private predicate dynamicFileIoCall(
  Call c, string name, string moduleHint, string flowKind, int argIndex,
  string accessType
) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = name and
  (
    (
      name = "render" and moduleHint = "tornado.web.RequestHandler (inferred)" and
      flowKind = "arg" and argIndex = 0 and
      accessType = "template file load: tornado RequestHandler.render loads and renders a template file from disk; the only observed call site (routes.py:90) uses a fixed index.html path joined to the static dir"
    )
    or
    (
      name = "glob" and moduleHint = "pathlib.Path (inferred)" and
      flowKind = "receiver" and argIndex = -1 and
      accessType = "directory enumeration: pathlib Path.glob lists files under the receiver directory; the path is carried by the receiver, not an argument"
    )
  )
}

/**
 * Holds for each filesystem sink candidate. `argIndex` is the 0-based
 * positional argument index carrying the file path, or -1 when the path is
 * controlled through keyword arguments (tempfile.mkdtemp) or the receiver
 * (Path.glob).
 */
private predicate sinkCandidate(
  string nodeRepr, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string context, AstNode node
) {
  exists(Call c, string accessType |
    node = c and
    inStreamlitPackage(c) and
    (
      resolvedFileIoCall(c, callableName, moduleHint, receiver, argIndex, accessType) and
      flowKind = "arg"
      or
      dynamicFileIoCall(c, callableName, moduleHint, flowKind, argIndex, accessType) and
      receiver = callReceiver(c)
    )
    and
    (
      argIndex >= 0 and
      exists(c.getPositionalArg(argIndex)) and
      nodeRepr = "call '" + callableName + "' argument " + argIndex and
      context = accessType + "; path argument is a " + argNote(c.getPositionalArg(argIndex))
      or
      argIndex = -1 and
      flowKind = "arg" and
      nodeRepr = "call '" + callableName + "' (keyword-controlled)" and
      context = accessType
      or
      argIndex = -1 and
      flowKind = "receiver" and
      nodeRepr = "call '" + callableName + "' (receiver-controlled directory)" and
      context = accessType + "; receiver is '" + callReceiver(c) + "'"
    )
  )
}

/* ------------------------------------------------------------------ */
/* Select                                                              */
/* ------------------------------------------------------------------ */

from AstNode node, string nodeRepr, string role, string callableName,
     string flowKind, string receiver, string moduleHint, int argIndex,
     string filePath, int line, string context
where
  role = "sink_candidate" and
  sinkCandidate(nodeRepr, callableName, flowKind, receiver, moduleHint, argIndex, context, node) and
  inStreamlitPackage(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
