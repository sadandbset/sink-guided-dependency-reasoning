/**
 * @name mlflow Pass 1 sink candidates (Path Traversal)
 * @description Extracts filesystem-operation sink candidates for CWE-22/23/36/73
 *   from the mlflow 2.0.0.dev0 codebase: real file read/write/create/delete/move
 *   APIs (open, codecs.open, send_file, send_from_directory, shutil.copyfile/
 *   copy/copytree/move/rmtree, os.remove/rmdir/makedirs/mkdir/listdir/walk/
 *   scandir, os.path.getsize, distutils dir_util.copy_tree, zipfile.ZipFile,
 *   tarfile.open, dynamic .extractall/.mkdir/.read_text/.write_text calls).
 *   Only calls that perform actual filesystem access are extracted;
 *   path-construction nodes (os.path.join, os.path.normpath, os.path.abspath,
 *   posixpath.join, pathlib Path()) are treated as propagation/validation,
 *   not sinks. Evidence-derived from mlflow/server/handlers.py,
 *   mlflow/server/__init__.py, mlflow/store/artifact/local_artifact_repo.py,
 *   mlflow/store/artifact/artifact_repo.py, mlflow/store/tracking/file_store.py,
 *   mlflow/utils/file_utils.py, mlflow/projects/utils.py and
 *   mlflow/utils/_spark_utils.py.
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/mlflow-cwe22/extract-sinks
 */

import python

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Gets the dotted name of a simple name/attribute chain,
 * e.g. "os.path.getsize" or "shutil.copyfile".
 */
private string dottedName(Expr e) {
  result = e.(Name).getId()
  or
  result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
}

/**
 * Gets the repository-relative path of the file containing this node,
 * e.g. "mlflow/server/handlers.py". The primary source is File.getRelativePath();
 * on this Windows-created database the stored source location prefix uses
 * backslashes while file paths are forward-slash normalized, so
 * getRelativePath() may have no result - in that case fall back to capturing
 * the "mlflow/..." suffix from the absolute path (verified forward-slash
 * format in the database string pool).
 */
private string relPath(AstNode n) {
  result = n.getLocation().getFile().getRelativePath()
  or
  not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
  result = n.getLocation().getFile().getAbsolutePath().regexpCapture(".*/(mlflow/.+)$", 1)
}

/**
 * Restricts candidates to the mlflow Python package itself. This structurally
 * excludes the nested mlflow-db CodeQL database directory (mlflow-db/...), the
 * mlflow_vuln ground-truth directory, tests/ and examples/ files, and the
 * generated mlflow/protos/ code, which are noise per the Augur policy.
 */
private predicate inMlflowPackage(AstNode n) {
  relPath(n).matches("mlflow/%") and
  not relPath(n).matches("mlflow/protos/%")
}

/**
 * Gets a receiver hint for a call: the dotted object expression for
 * attribute calls (e.g. "os.path" for os.path.getsize, or the variable
 * name for dynamically dispatched calls such as zip_ref.extractall), "" for
 * plain-name calls.
 */
private string callReceiver(Call c) {
  c.getFunc() instanceof Name and result = ""
  or
  c.getFunc() instanceof Attribute and
  (
    exists(string obj | obj = dottedName(c.getFunc().(Attribute).getObject()) and result = obj)
    or
    not exists(string obj | obj = dottedName(c.getFunc().(Attribute).getObject())) and
      result = c.getFunc().(Attribute).getObject().toString()
  )
}

/**
 * Describes the syntactic shape of a path argument, so that labelers can see
 * whether the sink is fed by a join, a variable or a literal.
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

/**
 * Gets the mode argument of an open() / codecs.open() call when it is a string
 * literal, so that labelers can distinguish read from write access. Defaults
 * to "read" when no literal mode argument is present. The gating on the
 * callable name is done at the call site (via an existentially quantified
 * modeNote variable) because a string concatenation operand in QL must be a
 * term, not an if-then-else expression, and `in [...]` tests do not bind
 * function parameters inside a function body.
 */
private string openModeNote(Call c) {
  exists(StringLiteral lit |
    lit = c.getPositionalArg(1) and
    result = "; mode '" + lit.getText() + "'"
  )
  or
  not exists(StringLiteral lit | lit = c.getPositionalArg(1)) and
  result = "; mode default ('r', read)"
}

/* ------------------------------------------------------------------ */
/* Sink families                                                       */
/* ------------------------------------------------------------------ */

/**
 * Filesystem calls whose callee resolves to a known dotted name.
 * `argIndex` selects the path-carrying positional argument.
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
      dotted = "codecs.open" and moduleHint = "codecs" and receiver = "codecs" and
      argIndex = 0 and
      accessType = "file open via codecs (read or write per mode argument)"
    )
    or
    (
      dotted = "send_file" and moduleHint = "flask" and receiver = "" and argIndex = 0 and
      accessType = "file read served as HTTP file response (Flask send_file)"
    )
    or
    (
      dotted = "send_from_directory" and moduleHint = "flask" and receiver = "" and
      argIndex = 1 and
      accessType = "file read served as HTTP file response (Flask send_from_directory; argument 0 is the base directory, Flask safe_join containment applies)"
    )
    or
    (
      dotted = "shutil.copyfile" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 0 and
      accessType = "copy source path (read)"
    )
    or
    (
      dotted = "shutil.copyfile" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 1 and
      accessType = "copy destination path (write)"
    )
    or
    (
      dotted = "shutil.copy" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 0 and
      accessType = "copy source path (read)"
    )
    or
    (
      dotted = "shutil.copy" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 1 and
      accessType = "copy destination path (write)"
    )
    or
    (
      dotted = "shutil.copytree" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 0 and
      accessType = "recursive copy source directory (read)"
    )
    or
    (
      dotted = "shutil.copytree" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 1 and
      accessType = "recursive copy destination directory (write)"
    )
    or
    (
      dotted = "shutil.move" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 0 and
      accessType = "move source path (read then unlink)"
    )
    or
    (
      dotted = "shutil.move" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 1 and
      accessType = "move destination path (write)"
    )
    or
    (
      dotted = "shutil.rmtree" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 0 and
      accessType = "recursive directory delete"
    )
    or
    (
      dotted = "os.remove" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "file delete"
    )
    or
    (
      dotted = "os.rmdir" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "directory delete"
    )
    or
    (
      dotted = "os.makedirs" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "directory create (recursive)"
    )
    or
    (
      dotted = "os.mkdir" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "directory create"
    )
    or
    (
      dotted = "os.listdir" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "directory listing read"
    )
    or
    (
      dotted = "os.walk" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "recursive directory walk (listing read)"
    )
    or
    (
      dotted = "os.scandir" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "directory iteration read"
    )
    or
    (
      dotted = "os.path.getsize" and moduleHint = "os.path" and receiver = "os.path" and
      argIndex = 0 and
      accessType = "file stat read"
    )
    or
    (
      dotted = "dir_util.copy_tree" and moduleHint = "distutils.dir_util" and
      receiver = "dir_util" and argIndex = 0 and
      accessType = "recursive directory copy source (read)"
    )
    or
    (
      dotted = "dir_util.copy_tree" and moduleHint = "distutils.dir_util" and
      receiver = "dir_util" and argIndex = 1 and
      accessType = "recursive directory copy destination (write)"
    )
    or
    (
      dotted = "zipfile.ZipFile" and moduleHint = "zipfile" and receiver = "zipfile" and
      argIndex = 0 and
      accessType = "archive file open (zip read; later .extractall writes entry-controlled targets)"
    )
    or
    (
      dotted = "tarfile.open" and moduleHint = "tarfile" and receiver = "tarfile" and
      argIndex = 0 and
      accessType = "archive file open (tar read or write per mode argument)"
    )
  )
}

/**
 * Dynamically dispatched filesystem calls on locally-typed receivers
 * (zipfile extractall, pathlib-style mkdir/read_text/write_text). The
 * receiver module cannot always be resolved syntactically, so the module
 * hint is inferred and the context records that caveat.
 */
private predicate dynamicFileIoCall(
  Call c, string name, string moduleHint, int argIndex, string accessType
) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = name and
  argIndex = 0 and
  (
    (
      name = "extractall" and moduleHint = "zipfile (inferred from receiver)" and
      accessType = "archive extraction write (zipfile extractall); archive entry names control the written paths (zip-slip), destination is argument 0"
    )
    or
    (
      name = "mkdir" and moduleHint = "pathlib/hdfs/sftp (inferred from receiver)" and
      not dottedName(c.getFunc()).matches("os.%") and
      accessType = "directory create (receiver module inferred; some receivers are remote filesystem clients, not local paths)"
    )
    or
    (
      name = "read_text" and moduleHint = "pathlib (inferred from receiver)" and
      accessType = "file read (pathlib read_text); receiver module inferred"
    )
    or
    (
      name = "write_text" and moduleHint = "pathlib (inferred from receiver)" and
      accessType = "file write (pathlib write_text); receiver module inferred"
    )
  )
}

/**
 * Holds for each filesystem sink candidate. `argIndex` is the 0-based
 * positional argument index carrying the file path.
 */
private predicate sinkCandidate(
  string nodeRepr, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string context, AstNode node
) {
  exists(Call c, string accessType, string modeNote |
    node = c and
    inMlflowPackage(c) and
    (
      resolvedFileIoCall(c, callableName, moduleHint, receiver, argIndex, accessType)
      or
      dynamicFileIoCall(c, callableName, moduleHint, argIndex, accessType) and
      receiver = callReceiver(c)
    ) and
    flowKind = "arg" and
    argIndex >= 0 and
    exists(c.getPositionalArg(argIndex)) and
    nodeRepr = "call '" + callableName + "' argument " + argIndex and
    (
      (
        callableName in ["open", "codecs.open"] and
        modeNote = openModeNote(c)
      )
      or
      (
        not callableName in ["open", "codecs.open"] and
        modeNote = ""
      )
    ) and
    context = accessType + "; path argument is a " + argNote(c.getPositionalArg(argIndex)) + modeNote
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
  inMlflowPackage(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
