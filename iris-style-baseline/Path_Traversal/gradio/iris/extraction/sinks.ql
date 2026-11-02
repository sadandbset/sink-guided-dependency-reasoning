/**
 * @name gradio Pass 1 sink candidates (Path Traversal)
 * @description Extracts filesystem-operation sink candidates for CWE-22/23/36/73
 *   from the gradio 2.5.0 codebase: real file read/write/create/delete/move APIs
 *   (open, send_file, shutil.move/copy2, os.remove/makedirs/listdir,
 *   os.path.getsize, tempfile.NamedTemporaryFile, ffmpy.FFmpeg, pydub
 *   from_file/export, PIL/matplotlib save). Only calls that perform actual
 *   filesystem access are extracted; path-construction nodes (os.path.join,
 *   os.path.basename) are treated as propagation/validation, not sinks.
 *   Evidence-derived from gradio/networking.py, gradio/component.py,
 *   gradio/interface.py, gradio/inputs.py, gradio/outputs.py,
 *   gradio/processing_utils.py and gradio/queue.py.
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/gradio-cwe22/extract-sinks
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

/**
 * Gets the repository-relative path of the file containing this node,
 * e.g. "gradio/networking.py". The primary source is File.getRelativePath();
 * on this Windows-created database the stored source location prefix uses
 * backslashes while file paths are forward-slash normalized, so
 * getRelativePath() may have no result - in that case fall back to capturing
 * the "gradio/..." suffix from the absolute path (verified forward-slash
 * format in the database string pool).
 */
private string relPath(AstNode n) {
  result = n.getLocation().getFile().getRelativePath()
  or
  not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
  result = n.getLocation().getFile().getAbsolutePath().regexpCapture(".*/(gradio/.+)$", 1)
}

/**
 * Restricts candidates to the gradio package itself. This structurally
 * excludes the nested gradio-db CodeQL database directory (gradio-db/...)
 * as well as test/ and demo/ files, which are noise per the Augur policy.
 */
private predicate inGradioPackage(AstNode n) {
  relPath(n).matches("gradio/%")
}

/**
 * Gets a receiver hint for a call: the dotted object expression for
 * attribute calls (e.g. "os.path" for os.path.getsize, or the variable
 * name for dynamically dispatched calls such as audio.export), "" for
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
 * whether the sink is fed by a join, a basename, a variable or a literal.
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
      dotted = "send_file" and moduleHint = "flask" and receiver = "" and argIndex = 0 and
      accessType = "file read served as HTTP file response (Flask send_file)"
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
      dotted = "os.listdir" and moduleHint = "os" and receiver = "os" and argIndex = 0 and
      accessType = "directory listing read"
    )
    or
    (
      dotted = "os.path.getsize" and moduleHint = "os.path" and receiver = "os.path" and argIndex = 0 and
      accessType = "file stat read"
    )
    or
    (
      dotted = "shutil.move" and moduleHint = "shutil" and receiver = "shutil" and argIndex = 0 and
      accessType = "move source path (read then unlink)"
    )
    or
    (
      dotted = "shutil.move" and moduleHint = "shutil" and receiver = "shutil" and argIndex = 1 and
      accessType = "move destination path (write)"
    )
    or
    (
      dotted = "shutil.copy2" and moduleHint = "shutil" and receiver = "shutil" and argIndex = 0 and
      accessType = "copy source path (read)"
    )
    or
    (
      dotted = "shutil.copy2" and moduleHint = "shutil" and receiver = "shutil" and argIndex = 1 and
      accessType = "copy destination path (write)"
    )
    or
    (
      dotted = "tempfile.NamedTemporaryFile" and moduleHint = "tempfile" and receiver = "tempfile" and
      argIndex = -1 and
      accessType = "temp file creation; prefix/suffix keyword arguments control the generated filename"
    )
    or
    (
      dotted = "FFmpeg" and moduleHint = "ffmpy" and receiver = "" and argIndex = -1 and
      accessType = "ffmpeg subprocess file read/write; inputs/outputs keyword dicts map input and output file paths"
    )
    or
    (
      dotted = "AudioSegment.from_file" and moduleHint = "pydub" and receiver = "AudioSegment" and
      argIndex = 0 and
      accessType = "audio file read (pydub AudioSegment.from_file)"
    )
  )
}

/**
 * Dynamically dispatched write calls on locally-typed receivers
 * (pydub export, PIL Image.save, matplotlib savefig). The receiver module
 * cannot be resolved syntactically, so the module hint is inferred and the
 * context records that caveat. Some .save/.savefig call sites in this
 * codebase target BytesIO objects rather than filesystem paths; those rows
 * are still extracted (broad-first) and the context flags this.
 */
private predicate dynamicFileWriteCall(
  Call c, string name, string moduleHint, int argIndex, string accessType
) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = name and
  argIndex = 0 and
  (
    (
      name = "export" and moduleHint = "pydub (inferred from receiver)" and
      accessType = "audio file write (pydub AudioSegment.export); receiver module inferred"
    )
    or
    (
      name = "save" and moduleHint = "PIL.Image (inferred from receiver)" and
      accessType = "image file write (PIL Image.save); receiver module inferred; BytesIO call sites are not filesystem access"
    )
    or
    (
      name = "savefig" and moduleHint = "matplotlib (inferred from receiver)" and
      accessType = "plot image write (matplotlib savefig); receiver module inferred; BytesIO call sites are not filesystem access"
    )
  )
}

/**
 * Holds for each filesystem sink candidate. `argIndex` is the 0-based
 * positional argument index carrying the file path, or -1 when the path is
 * controlled through keyword arguments (tempfile prefix/suffix, ffmpeg
 * inputs/outputs dicts).
 */
private predicate sinkCandidate(
  string nodeRepr, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string context, AstNode node
) {
  exists(Call c, string accessType |
    node = c and
    inGradioPackage(c) and
    (
      resolvedFileIoCall(c, callableName, moduleHint, receiver, argIndex, accessType)
      or
      dynamicFileWriteCall(c, callableName, moduleHint, argIndex, accessType) and
      receiver = callReceiver(c)
    ) and
    flowKind = "arg" and
    (
      argIndex >= 0 and
      exists(c.getPositionalArg(argIndex)) and
      nodeRepr = "call '" + callableName + "' argument " + argIndex and
      context = accessType + "; path argument is a " + argNote(c.getPositionalArg(argIndex))
      or
      argIndex = -1 and
      nodeRepr = "call '" + callableName + "' (keyword-controlled)" and
      context = accessType
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
  inGradioPackage(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
