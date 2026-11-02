/**
 * @name mindsdb Pass 1 sink candidates (Path Traversal)
 * @description Extracts filesystem-operation sink candidates for CWE-22/23/36/73
 *   from the mindsdb 23.2.2.1 codebase: real file read/write/create/delete/move
 *   APIs (open, zipfile.ZipFile, tarfile.open, sqlite3.connect, send_file,
 *   send_from_directory, os.remove/unlink/rmdir/makedirs/listdir,
 *   shutil.move/copy/copy2/copytree/rmtree/unpack_archive/make_archive) and
 *   dynamically dispatched filesystem calls (extractall, FileStorage.save,
 *   predictor.save, DataFrame.to_pickle, pathlib write_text/mkdir/touch/
 *   unlink/rmdir on receiver paths). Only calls that perform actual filesystem
 *   access are extracted; path-construction nodes (os.path.join,
 *   Path.joinpath) and existence checks (os.path.exists, Path.is_file) are
 *   treated as propagation/validation, not sinks. Evidence-derived from
 *   mindsdb/api/http/namespaces/{file,handlers,config,start}.py,
 *   mindsdb/api/http/initialize.py, mindsdb/interfaces/file/file_controller.py,
 *   mindsdb/interfaces/storage/fs.py,
 *   mindsdb/interfaces/database/integrations.py,
 *   mindsdb/integrations/handlers/{file_handler,sqlite_handler,bigquery_handler}
 *   and mindsdb/utilities/{cache,telemetry,wizards,fs}.py.
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/mindsdb-cwe22/extract-sinks
 */

import python

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Gets the dotted name of a simple name/attribute chain,
 * e.g. "os.path.getsize" or "shutil.copy2".
 */
private string dottedName(Expr e) {
  result = e.(Name).getId()
  or
  result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
}

/** Gets the repository-relative path of the file containing this node. */
private string relPath(AstNode n) {
  result = n.getLocation().getFile().getRelativePath()
}

/**
 * Restricts candidates to the mindsdb package itself. This structurally
 * excludes the nested mindsdb-db CodeQL database directory (mindsdb-db/...),
 * the top-level tests/ directory, and handler-level tests/ and setup.py
 * files, which are noise per the Augur policy.
 */
private predicate inMindsdbPackage(AstNode n) {
  relPath(n).matches("mindsdb/%") and
  not relPath(n).matches("%/tests/%") and
  not relPath(n).matches("%setup.py")
}

/**
 * Gets a receiver hint for a call: the dotted object expression for
 * attribute calls (e.g. "os.path" for os.path.join, or the variable
 * name for dynamically dispatched calls such as f.extractall), "" for
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
 * `argIndex` selects the path-carrying positional argument (0-based);
 * -1 is not used here because every resolved family has a positional
 * path argument. `open` calls with an integer file descriptor
 * (byom proc_wrapper.py, ml_handler_proc.py) are excluded.
 */
private predicate resolvedFileIoCall(
  Call c, string dotted, string moduleHint, string receiver,
  int argIndex, string accessType
) {
  dotted = dottedName(c.getFunc()) and
  (
    (
      dotted = "open" and moduleHint = "builtins" and receiver = "" and argIndex = 0 and
      not c.getPositionalArg(0) instanceof IntegerLiteral and
      accessType = "file open (read or write per mode argument)"
    )
    or
    (
      dotted = "zipfile.ZipFile" and moduleHint = "zipfile" and receiver = "zipfile" and
      argIndex = 0 and
      accessType = "archive file open/read (zipfile.ZipFile)"
    )
    or
    (
      dotted = "tarfile.open" and moduleHint = "tarfile" and receiver = "tarfile" and
      argIndex = 0 and
      accessType = "archive file open/read (tarfile.open)"
    )
    or
    (
      dotted = "os.remove" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "file delete"
    )
    or
    (
      dotted = "os.unlink" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
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
      accessType = "directory create"
    )
    or
    (
      dotted = "os.listdir" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "directory listing read"
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
      dotted = "shutil.copy" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 0 and
      accessType = "copy source path (read); observed copying raw request-supplied ARG_TYPE.PATH connection args"
    )
    or
    (
      dotted = "shutil.copy" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 1 and
      accessType = "copy destination path (write)"
    )
    or
    (
      dotted = "shutil.copy2" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 0 and
      accessType = "copy source path (read)"
    )
    or
    (
      dotted = "shutil.copy2" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 1 and
      accessType = "copy destination path (write)"
    )
    or
    (
      dotted = "shutil.copytree" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 0 and
      accessType = "recursive copy source path (read)"
    )
    or
    (
      dotted = "shutil.copytree" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 1 and
      accessType = "recursive copy destination path (write)"
    )
    or
    (
      dotted = "shutil.rmtree" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 0 and
      accessType = "recursive directory delete"
    )
    or
    (
      dotted = "shutil.unpack_archive" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 0 and
      accessType = "archive extraction (archive member files written under the destination)"
    )
    or
    (
      dotted = "shutil.make_archive" and moduleHint = "shutil" and receiver = "shutil" and
      argIndex = 0 and
      accessType = "archive creation (reads the base directory tree)"
    )
    or
    (
      dotted = "sqlite3.connect" and moduleHint = "sqlite3" and receiver = "sqlite3" and
      argIndex = 0 and
      accessType = "sqlite database file open (read/write/create); observed with request-influenced connection_data['db_file']"
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
      accessType = "static file read served as HTTP file response (Flask send_from_directory; arg 0 is the base directory, arg 1 is the requested relative path; werkzeug safe_join applies inside the framework)"
    )
  )
}

/**
 * Dynamically dispatched filesystem calls on locally-typed receivers
 * (zipfile/tarfile extractall, werkzeug FileStorage.save, lightwood
 * predictor.save, pandas DataFrame.to_pickle, pathlib methods whose
 * receiver is the path). The receiver module cannot be resolved
 * syntactically, so the module hint is inferred and the context records
 * that caveat. For pathlib families the path IS the receiver, so
 * argIndex is -1 and flow kind is "receiver".
 */
private predicate dynamicFileIoCall(
  Call c, string name, string moduleHint, int argIndex, string accessType
) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = name and
  (
    (
      name = "extractall" and argIndex = 0 and
      moduleHint = "zipfile/tarfile (inferred from receiver)" and
      accessType = "archive extraction into destination directory; archive entry names are resolved inside the stdlib library with no in-repo member validation (zip-slip style risk); observed on client-uploaded .zip/.tar.gz at the /api/files/<name> route"
    )
    or
    (
      name = "save" and argIndex = 0 and
      moduleHint = "werkzeug FileStorage / lightwood predictor (inferred from receiver)" and
      accessType = "file write: werkzeug FileStorage.save writes an uploaded file to the destination path (after a resolve+parents containment check at its call site); lightwood predictor.save writes model files"
    )
    or
    (
      name = "to_pickle" and argIndex = 0 and
      moduleHint = "pandas (inferred from receiver)" and
      accessType = "DataFrame pickle file write (cache path derived from a checksum name)"
    )
    or
    (
      name = "write_text" and argIndex = -1 and
      moduleHint = "pathlib (receiver is the path)" and
      accessType = "pathlib text file write; the path is the receiver object"
    )
    or
    (
      name = "mkdir" and argIndex = -1 and
      moduleHint = "pathlib (receiver is the path)" and
      accessType = "pathlib directory create; the path is the receiver object"
    )
    or
    (
      name = "touch" and argIndex = -1 and
      moduleHint = "pathlib (receiver is the path)" and
      accessType = "pathlib empty file create; the path is the receiver object"
    )
    or
    (
      name = "unlink" and argIndex = -1 and
      moduleHint = "pathlib (receiver is the path)" and
      accessType = "pathlib file delete; the path is the receiver object"
    )
    or
    (
      name = "rmdir" and argIndex = -1 and
      moduleHint = "pathlib (receiver is the path)" and
      accessType = "pathlib directory delete; the path is the receiver object"
    )
  )
}

/**
 * Holds for each filesystem sink candidate. `argIndex` is the 0-based
 * positional argument index carrying the file path (flow kind "arg"), or
 * -1 when the path is the call receiver itself (flow kind "receiver").
 */
private predicate sinkCandidate(
  string nodeRepr, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string context, AstNode node
) {
  exists(Call c, string accessType |
    node = c and
    inMindsdbPackage(c) and
    (
      resolvedFileIoCall(c, callableName, moduleHint, receiver, argIndex, accessType)
      or
      dynamicFileIoCall(c, callableName, moduleHint, argIndex, accessType) and
      receiver = callReceiver(c)
    ) and
    (
      (
        argIndex >= 0 and
        flowKind = "arg" and
        exists(c.getPositionalArg(argIndex)) and
        nodeRepr = "call '" + callableName + "' argument " + argIndex and
        context = accessType + "; path argument is a " + argNote(c.getPositionalArg(argIndex))
      )
      or
      (
        argIndex = -1 and
        flowKind = "receiver" and
        nodeRepr = "call '" + callableName + "' (receiver-controlled path)" and
        context = accessType
      )
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
  inMindsdbPackage(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
