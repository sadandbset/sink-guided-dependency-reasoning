/**
 * @name Zope Pass 1 sink candidates (Path Traversal)
 * @description Extracts filesystem-operation sink candidates for CWE-22/23/36/73
 *   from the Zope 5.2.dev0 framework source (src/): real file access only -
 *   builtins open (ObjectManager zexp export write, App.Extensions external
 *   method source, App.ImageFile content sniff, PageTemplateFile/ZopePageTemplate
 *   template reads, zconsole/copyzopeskel/mkwsgiinstance/serve CLI files,
 *   custom_zodb.py startup read), filestream_iterator (App.ImageFile HTTP
 *   file serving, plus the super().__init__(name, mode) io.FileIO open inside
 *   ZPublisher/Iterators.py), os.listdir and os.walk, os.path.exists/isdir/
 *   isfile/getmtime and os.stat existence/metadata checks (including the
 *   request-derived ++resource++ filename checks in Products/Five/browser/
 *   resource.py:156-157), os.remove, os.makedirs, shutil.copyfile/copymode,
 *   ZODB Connection.importFile (ObjectManager.py:679, external API that
 *   opens the imported file), and the DirectoryResource factory(name,
 *   filename) dynamic call handing the request-derived joined path to the
 *   external zope.browserresource File resource (resource.py:170).
 *   Path-construction and validation nodes (os.path.join at ObjectManager
 *   :621/:644, Extensions :46/:50/:103/:137, resource.py:155, ImageFile:57,
 *   special_dtml:69, PageTemplateFile:95/:97, cookId basename extraction,
 *   HTTPRequest.physicalPathFromURL, BaseRequest.traverse segment loop) are
 *   deliberately NOT extracted as sinks; they are propagation/validation
 *   nodes recorded in exploration/detection.json. No zipfile/tarfile/
 *   extractall, pathlib, io.open, tempfile or shutil.rmtree usage exists in
 *   non-test src code (grep-verified). Multi-column candidate table intended
 *   for `codeql query run` followed by `codeql bqrs decode --format=csv`.
 *   This query deliberately has NO @kind annotation: a @kind problem select
 *   shape cannot carry the multi-column extraction contract, and no @kind
 *   table is assumed.
 * @id iris/zope-cwe22/extract-sinks
 */

import python

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Gets the dotted name of a simple name/attribute chain,
 * e.g. "os.path.getmtime" or "connection.importFile".
 */
private string dottedName(Expr e) {
  result = e.(Name).getId()
  or
  result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
}

/**
 * Gets the repository-relative path of the file containing this node,
 * e.g. "src/OFS/ObjectManager.py". The primary source is
 * File.getRelativePath(); on this Windows-created database the stored source
 * location prefix uses backslashes while file paths are forward-slash
 * normalized, so getRelativePath() may yield backslash forms or no result -
 * in that case fall back to capturing the "src/..." suffix from the absolute
 * path (verified forward-slash format in the database string pool).
 */
private string relPath(AstNode n) {
  exists(string p |
    p = n.getLocation().getFile().getRelativePath() and
    result = p.replaceAll("\\", "/")
  )
  or
  not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/").regexpCapture(".*/(src/.+)$", 1)
}

/**
 * Restricts candidates to the Zope src/ tree. This structurally excludes the
 * nested Zope-db CodeQL database directory (repo root), repo-root files
 * (setup.py, util.py, reports, CSVs) and the src/Testing/ test-scaffolding
 * package; per the Augur noise policy all tests/ directories, test_*.py
 * files and interfaces.py declaration stubs are excluded as well.
 */
private predicate inZopeSrc(AstNode n) {
  relPath(n).matches("src/%") and
  not relPath(n).matches("%/tests/%") and
  not relPath(n).matches("src/Testing/%") and
  not relPath(n).matches("%/test_%.py") and
  not relPath(n).matches("%/interfaces.py") and
  not relPath(n).matches("%/testing.py")
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
  else if arg instanceof BinaryExpr then result = "concatenation/interpolation expression"
  else result = "other expression"
}

/* ------------------------------------------------------------------ */
/* Sink families                                                       */
/* ------------------------------------------------------------------ */

/**
 * Resolved filesystem calls. `callableName` is the plain callee name for
 * builtin calls (open, filestream_iterator, factory), a dotted callee name
 * for module-qualified calls (os.listdir, os.path.*, shutil.*), or an
 * attribute callee name constrained to its file (importFile in
 * ObjectManager.py). `argIndex` selects the path-carrying positional
 * argument; shutil.copyfile/copymode carry paths in both arguments and are
 * emitted as two rows (argIndex 0 and 1).
 */
private predicate resolvedFileIoCall(
  Call c, string callableName, string moduleHint, string receiver,
  int argIndex, string flowKind, string accessType
) {
  (
    /* builtins open - real file read/write. */
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = "open" and
    callableName = "open" and
    moduleHint = "builtins" and
    receiver = "" and
    argIndex = 0 and
    flowKind = "fs_open" and
    accessType = "builtins open: file read/write/create; observed sites: ObjectManager.manage_exportObject zexp export write (ObjectManager.py:622, path = os.path.join(CONFIG.clienthome, '{id}.zexp') with the request-derived id at :621, after _getOb(id) resolution at :604), App.Extensions external-method module source read (Extensions.py:178, exec'd at :184), App.ImageFile content-type sniff read (ImageFile.py:72), PageTemplateFile template read (PageTemplateFile.py:194, on _cook_check at request time in debug mode), ZopePageTemplate default content read (ZopePageTemplate.py:115), zconsole script read + exec (zconsole.py:20), copyzopeskel skeleton copy read/write (copyzopeskel.py:221/:226), serve pid-file write (serve.py:236), mkwsgiinstance inituser write (mkwsgiinstance.py:191), startup custom_zodb.py read (Zope2/App/startup.py:52)"
  )
  or
  (
    /* filestream_iterator: an io.FileIO subclass - constructing it opens the
       file; the HTTP file-serving read path of App.ImageFile.index_html. */
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = "filestream_iterator" and
    callableName = "filestream_iterator" and
    moduleHint = "ZPublisher.Iterators" and
    receiver = "" and
    argIndex = 0 and
    flowKind = "fs_open_fileio" and
    accessType = "filestream_iterator(name, mode='rb'): ZPublisher.Iterators.filestream_iterator subclasses io.FileIO, so construction opens the file and iteration streams it as the HTTP response body; observed site: App.ImageFile.index_html (ImageFile.py:121) serving the ZCML-registered image path (self.path fixed at registration, request-time read)"
  )
  or
  (
    /* The io.FileIO open inside filestream_iterator.__init__ itself. */
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "__init__" and
    c.getFunc().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Name).getId() = "super" and
    relPath(c).matches("src/ZPublisher/Iterators.py") and
    callableName = "super().__init__" and
    moduleHint = "io.FileIO" and
    receiver = "super" and
    argIndex = 0 and
    flowKind = "fs_open_fileio" and
    accessType = "io.FileIO constructor call inside filestream_iterator.__init__ (Iterators.py:49, super().__init__(name, mode)): the actual filesystem open performed for every filestream_iterator construction"
  )
  or
  (
    c.getFunc() instanceof Attribute and
    callableName = "os.listdir" and
    dottedName(c.getFunc()) = "os.listdir" and
    moduleHint = "os" and
    receiver = "os" and
    argIndex = 0 and
    flowKind = "fs_listdir" and
    accessType = "os.listdir: directory enumeration; observed sites: ObjectManager.list_imports (ObjectManager.py:709, fixed instance import directories filtered to .zexp/.xml), OFS.Application.get_products product discovery (Application.py:370, Products.__path__ at startup)"
  )
  or
  (
    c.getFunc() instanceof Attribute and
    callableName = "os.walk" and
    dottedName(c.getFunc()) = "os.walk" and
    moduleHint = "os" and
    receiver = "os" and
    argIndex = 0 and
    flowKind = "fs_listdir" and
    accessType = "os.walk: recursive directory enumeration; observed site: copyzopeskel.py:181 (CLI skeleton copy over os.curdir, operator boundary)"
  )
  or
  (
    c.getFunc() instanceof Attribute and
    dottedName(c.getFunc()) in ["os.path.exists", "os.path.isdir", "os.path.isfile", "os.path.getmtime"] and
    callableName = dottedName(c.getFunc()) and
    moduleHint = "os.path" and
    receiver = "os.path" and
    argIndex = 0 and
    flowKind = "fs_metadata" and
    accessType = "os.path filesystem existence/metadata check; observed sites: ObjectManager.manage_importObject (ObjectManager.py:645 os.path.exists(filepath) of the request-derived import path immediately before connection.importFile - TOCTOU window), Products/Five/browser/resource.py:156/:157 os.path.isfile/os.path.isdir(filename) where filename = os.path.join(path, name) with the URL-derived ++resource++ segment, ObjectManager.py:707 import-dir isdir, App/Extensions.py:61/:144 external-method path resolution, OFS/Application.py:352/:356-358 product package checks, PageTemplateFile.py:160 template getmtime (request-time in debug mode)"
  )
  or
  (
    c.getFunc() instanceof Attribute and
    callableName = "os.stat" and
    dottedName(c.getFunc()) = "os.stat" and
    moduleHint = "os" and
    receiver = "os" and
    argIndex = 0 and
    flowKind = "fs_metadata" and
    accessType = "os.stat: file metadata read; observed sites: App/special_dtml.py:78 os.stat(self.raw) - DTML file mtime check in debug-mode _cook_check (per-request read of the registered .dtml path), App/ImageFile.py:84 os.stat(path) of the registered image file"
  )
  or
  (
    c.getFunc() instanceof Attribute and
    callableName = "os.remove" and
    dottedName(c.getFunc()) = "os.remove" and
    moduleHint = "os" and
    receiver = "os" and
    argIndex = 0 and
    flowKind = "fs_delete" and
    accessType = "os.remove: file deletion; observed site: OFS/userfolder.py:309 os.remove(os.path.join(cfg.instancehome, 'inituser')) - fixed instancehome path, removed after user creation"
  )
  or
  (
    c.getFunc() instanceof Attribute and
    callableName = "os.makedirs" and
    dottedName(c.getFunc()) = "os.makedirs" and
    moduleHint = "os" and
    receiver = "os" and
    argIndex = 0 and
    flowKind = "fs_create_dir" and
    accessType = "os.makedirs: directory creation; observed site: copyzopeskel.py:172 (CLI skeleton target directory, operator boundary)"
  )
  or
  (
    c.getFunc() instanceof Attribute and
    dottedName(c.getFunc()) in ["shutil.copyfile", "shutil.copymode"] and
    callableName = dottedName(c.getFunc()) and
    moduleHint = "shutil" and
    receiver = "shutil" and
    argIndex in [0, 1] and
    flowKind = "fs_copy" and
    accessType = "shutil file copy/mode-copy: both the source and destination arguments are filesystem paths, so each call is emitted as two rows (argIndex 0 and 1); observed sites: copyzopeskel.py:214/:215/:229 (CLI skeleton copy, operator boundary)"
  )
  or
  (
    /* ZODB Connection.importFile - external API that opens the imported
       zexp/xml file; the receiver is a local 'connection' variable. */
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "importFile" and
    relPath(c).matches("src/OFS/ObjectManager.py") and
    callableName = "connection.importFile" and
    moduleHint = "ZODB.Connection (external)" and
    receiver = "connection" and
    argIndex = 0 and
    flowKind = "external_import_file" and
    accessType = "ZODB Connection.importFile(filepath): imports an object export; the ZODB connection performs the actual file open of the zexp/xml file (external dependency, not in the DB); observed site: ObjectManager._importObjectFromFile (ObjectManager.py:679) with filepath = os.path.join(impath, 'import', file) where 'file' is the request parameter guarded by the os.path.split dirname rejection at :639-641"
  )
  or
  (
    /* DirectoryResource's dynamic factory call handing the request-derived
       joined path to the external zope.browserresource File resource. */
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = "factory" and
    relPath(c).matches("src/Products/Five/browser/resource.py") and
    callableName = "factory" and
    moduleHint = "zope.browserresource (external)" and
    receiver = "" and
    argIndex = 1 and
    flowKind = "external_resource_factory" and
    accessType = "resource factory construction (resource.py:170 factory(name, filename)): the factory comes from the resource_factories dict (external zope.browserresource File/Image or in-repo _PageTemplate); filename is the os.path.join(path, name) result with the URL-derived ++resource++ traversal segment (resource.py:155); the external File/FileResource object performs the actual file read when the resource is served - traced only syntactically since zope.browserresource is not in the DB"
  )
}

/* ------------------------------------------------------------------ */
/* Sink candidate relation                                             */
/* ------------------------------------------------------------------ */

/**
 * Holds for each filesystem sink candidate. `argIndex` is the 0-based
 * positional argument index carrying the file path/resource name.
 */
private predicate sinkCandidate(
  string nodeRepr, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string context, AstNode node
) {
  exists(Call c, string accessType |
    node = c and
    inZopeSrc(c) and
    resolvedFileIoCall(c, callableName, moduleHint, receiver, argIndex, flowKind, accessType) and
    argIndex >= 0 and
    exists(c.getPositionalArg(argIndex)) and
    nodeRepr = "call '" + callableName + "' argument " + argIndex and
    context = accessType + "; path argument is a " + argNote(c.getPositionalArg(argIndex))
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
  inZopeSrc(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
