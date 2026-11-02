/**
 * @name pretalx Pass 1 sink candidates (Path Traversal)
 * @description Extracts filesystem-operation sink candidates for CWE-22/23/36/73
 *   from the pretalx 2.3.1post0 codebase: real file read/write/create/delete/move
 *   APIs only - builtins open, django.http FileResponse (HTTP file serving,
 *   including FieldFile arguments read through Django storage), Django storage
 *   save/open/delete wrappers (FileSystemStorage/default_storage), PIL
 *   Image.open, shutil.rmtree, shutil.make_archive (keyword-controlled), pathlib
 *   Path.rename/Path.mkdir and tempfile.NamedTemporaryFile. Path-construction
 *   nodes (pathlib `/` joins,
 *   path_with_hash's os.path.split/os.path.join, upload_to callables,
 *   get_new_filename, url.lstrip('/')) are deliberately NOT extracted as sinks;
 *   they are propagation/validation nodes recorded in
 *   exploration/detection.json. Evidence-derived from pretalx/common/views.py,
 *   pretalx/common/mixins/views.py, pretalx/common/mixins/forms.py,
 *   pretalx/common/tasks.py, pretalx/common/forms/fields.py,
 *   pretalx/cfp/flow.py, pretalx/orga/views/schedule.py,
 *   pretalx/orga/views/cards.py, pretalx/agenda/views/speaker.py,
 *   pretalx/agenda/management/commands/export_schedule_html.py and
 *   pretalx/common/settings/config.py. No zipfile/tarfile/extractall APIs
 *   exist in this codebase (grep-verified).
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/pretalx-cwe22/extract-sinks
 */

import python

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Gets the dotted name of a simple name/attribute chain,
 * e.g. "os.path.getsize" or "shutil.rmtree".
 */
private string dottedName(Expr e) {
  result = e.(Name).getId()
  or
  result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
}

/**
 * Gets the repository-relative path of the file containing this node,
 * e.g. "src/pretalx/common/views.py". The primary source is
 * File.getRelativePath(); on this Windows-created database the stored source
 * location prefix uses backslashes while file paths are forward-slash
 * normalized, so getRelativePath() may yield backslash forms or no result -
 * in that case fall back to capturing the "src/pretalx/..." suffix from the
 * absolute path (verified forward-slash format in the database string pool).
 */
private string relPath(AstNode n) {
  exists(string p |
    p = n.getLocation().getFile().getRelativePath() and
    result = p.replaceAll("\\", "/")
  )
  or
  not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/").regexpCapture(".*/(src/pretalx/.+)$", 1)
}

/**
 * Restricts candidates to the pretalx package itself. This structurally
 * excludes the nested pretalx-db CodeQL database directory, the src/tests
 * tree and repository-root scripts, and per the Augur noise policy it also
 * excludes generated migration files.
 */
private predicate inPretalxPackage(AstNode n) {
  relPath(n).matches("src/pretalx/%") and
  not relPath(n).matches("%/migrations/%")
}

/**
 * Gets a receiver hint for a call: the dotted object expression for
 * attribute calls (e.g. "os.path" for os.path.getsize, "self.file_storage"
 * for self.file_storage.save), "" for plain-name calls. Falls back to the
 * object's source text when it is not a simple name/attribute chain.
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

/* ------------------------------------------------------------------ */
/* Sink families                                                       */
/* ------------------------------------------------------------------ */

/**
 * Filesystem calls whose callee resolves to a known dotted or plain name.
 * `argIndex` selects the path-carrying positional argument.
 * Django framework sources are not part of the database, so framework APIs
 * are matched by their call-site names with a module hint.
 */
private predicate resolvedFileIoCall(
  Call c, string dotted, string moduleHint, string receiver,
  int argIndex, string accessType
) {
  (
    c.getFunc() instanceof Name and
    dotted = c.getFunc().(Name).getId()
    or
    c.getFunc() instanceof Attribute and
    dotted = dottedName(c.getFunc())
  ) and
  (
    (
      dotted = "open" and moduleHint = "builtins" and receiver = "" and argIndex = 0 and
      accessType = "file open (read or write per mode argument); observed sites: get_static route-injected static path, schedule export zip, staticfiles widget file, upload temp file, HTML export write/read, env-config file"
    )
    or
    (
      dotted = "FileResponse" and moduleHint = "django.http" and receiver = "" and argIndex = 0 and
      accessType = "Django FileResponse serving a file as HTTP response; argument may be an already-opened file, a FieldFile (actual read happens in Django storage), or a BytesIO (no filesystem access at this call site)"
    )
    or
    (
      dotted = "Image.open" and moduleHint = "PIL.Image" and receiver = "Image" and argIndex = 0 and
      accessType = "image file read via PIL; the observed call site passes a BytesIO (in-memory upload validation), not a filesystem path"
    )
    or
    (
      dotted = "shutil.rmtree" and moduleHint = "shutil" and receiver = "shutil" and argIndex = 0 and
      accessType = "recursive directory delete (schedule HTML export dirs, makemessages locale dirs)"
    )
    or
    (
      dotted in ["make_archive", "shutil.make_archive"] and moduleHint = "shutil" and argIndex = -1 and
      (
        dotted = "shutil.make_archive" and receiver = "shutil"
        or
        dotted = "make_archive" and receiver = ""
      ) and
      accessType = "zip archive creation; the observed call site passes all path arguments as keywords (base_name destination, root_dir=HTMLEXPORT_ROOT, base_dir=event.slug)"
    )
    or
    (
      dotted = "tempfile.NamedTemporaryFile" and moduleHint = "tempfile" and receiver = "tempfile" and
      argIndex = -1 and
      accessType = "temp file creation; prefix/suffix keyword arguments control the generated filename (observed site uses literal suffix '.pdf')"
    )
  )
}

/**
 * Dynamically dispatched Django storage calls: .save(name, content) /
 * .open(name) / .delete(name) on receivers matching a storage name
 * (self.file_storage / default_storage). The storage name argument (arg 0)
 * is storage-relative, so it is the traversal-relevant parameter; Django's
 * FileSystemStorage applies internal name validation and safe_join before
 * the actual access, which is a labeling/Phase 2 concern, not an extraction
 * filter.
 */
private predicate storageMethodCall(
  Call c, string name, string moduleHint, int argIndex, string accessType
) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = name and
  name in ["save", "open", "delete"] and
  argIndex = 0 and
  moduleHint = "django.core.files.storage" and
  (
    (
      name = "save" and
      accessType = "Django Storage.save: writes uploaded content under the given storage-relative name (FileSystemStorage rooted at MEDIA_ROOT); observed sites store client-supplied upload filenames (cfp flow) and get_new_filename(value.name) paths"
    )
    or
    (
      name = "open" and
      accessType = "Django Storage.open: opens a stored file by storage-relative name; observed site opens a cfp session 'tmp_name' under MEDIA_ROOT/cfp_uploads"
    )
    or
    (
      name = "delete" and
      accessType = "Django Storage.delete: deletes a stored file by storage-relative name (previously stored settings File)"
    )
  ) and
  (
    callReceiver(c).matches("%file_storage")
    or
    callReceiver(c).matches("%default_storage")
  )
}

/**
 * Dynamically dispatched pathlib method calls with real filesystem effects:
 * Path.rename (destination in arg 0) and Path.mkdir (the receiver itself is
 * the created directory, so no positional path argument applies).
 */
private predicate pathlibMethodCall(
  Call c, string name, string moduleHint, int argIndex, string accessType
) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = name and
  moduleHint = "pathlib (inferred from receiver)" and
  (
    (
      name = "rename" and argIndex = 0 and
      accessType = "pathlib Path.rename: moves the receiver path to the destination given in arg 0 (schedule HTML export tmp_dir -> export_dir)"
    )
    or
    (
      name = "mkdir" and argIndex = -1 and
      accessType = "pathlib Path.mkdir: creates the directory named by the receiver path (export dirs, settings data dirs)"
    )
  )
}

/* ------------------------------------------------------------------ */
/* Sink candidate relation                                             */
/* ------------------------------------------------------------------ */

/**
 * Holds for each filesystem sink candidate. `argIndex` is the 0-based
 * positional argument index carrying the file path, or -1 when the path is
 * the call receiver (Path.mkdir) or controlled through keyword arguments
 * (tempfile prefix/suffix, make_archive root_dir/base_dir).
 */
private predicate sinkCandidate(
  string nodeRepr, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string context, AstNode node
) {
  exists(Call c, string accessType |
    node = c and
    inPretalxPackage(c) and
    (
      resolvedFileIoCall(c, callableName, moduleHint, receiver, argIndex, accessType)
      or
      storageMethodCall(c, callableName, moduleHint, argIndex, accessType) and
      receiver = callReceiver(c)
      or
      pathlibMethodCall(c, callableName, moduleHint, argIndex, accessType) and
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
      nodeRepr = "call '" + callableName + "' (receiver/keyword-controlled)" and
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
  inPretalxPackage(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
