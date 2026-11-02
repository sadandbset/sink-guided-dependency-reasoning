/**
 * @name pyramid Pass 1 sink candidates (Path Traversal)
 * @description Extracts filesystem-operation sink candidates for CWE-22/23/36/73
 *   from the Pyramid 2.0.1 framework source (src/pyramid): real file access
 *   only - builtins open (FileResponse file serving, manifest load,
 *   FSAssetDescriptor.stream, FSAssetSource.get_stream, i18n .mo loads,
 *   pshell PYTHONSTARTUP), os.listdir, os.path.* metadata checks
 *   (isdir/isfile/exists/realpath/getsize/getmtime) plus their from-import
 *   bare aliases in static.py and response.py, the FileResponse HTTP file
 *   serving wrapper (actual open/getmtime/getsize inside FileResponse.__init__
 *   in pyramid/response.py:55-57), and pkg_resources resource access
 *   (resource_stream/resource_filename/resource_exists/resource_isdir/
 *   resource_listdir in dotted, self.pkg_resources and static.py bare-alias
 *   forms, plus OverrideProvider delegations to
 *   pkg_resources.DefaultProvider.*). Path-construction and validation nodes
 *   (traversal_path_info/split_path_info/decode_path_info,
 *   _secure_path, os.path.join/normpath/normcase/abspath/isabs,
 *   asset spec resolution, descriptor wrapper methods) are deliberately NOT
 *   extracted as sinks; they are propagation/validation nodes recorded in
 *   exploration/detection.json. No zipfile/tarfile/extractall, pathlib,
 *   shutil or tempfile APIs exist in this codebase (grep-verified).
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/pyramid-cwe22/extract-sinks
 */

import python

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Gets the dotted name of a simple name/attribute chain,
 * e.g. "os.path.getsize" or "self.pkg_resources.resource_stream".
 */
private string dottedName(Expr e) {
  result = e.(Name).getId()
  or
  result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
}

/**
 * Gets the repository-relative path of the file containing this node,
 * e.g. "src/pyramid/static.py". The primary source is
 * File.getRelativePath(); on this Windows-created database the stored source
 * location prefix uses backslashes while file paths are forward-slash
 * normalized, so getRelativePath() may yield backslash forms or no result -
 * in that case fall back to capturing the "src/pyramid/..." suffix from the
 * absolute path (verified forward-slash format in the database string pool).
 */
private string relPath(AstNode n) {
  exists(string p |
    p = n.getLocation().getFile().getRelativePath() and
    result = p.replaceAll("\\", "/")
  )
  or
  not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/").regexpCapture(".*/(src/pyramid/.+)$", 1)
}

/**
 * Restricts candidates to the pyramid package itself. This structurally
 * excludes the nested pyramid-db CodeQL database directory (repo root), the
 * tests/ tree, setup.py and repository-root scripts; per the Augur noise
 * policy the framework's own testing helper modules are excluded, and
 * interfaces.py (zope.interface declaration stubs with no executable logic)
 * is excluded to keep interface method declarations out of the candidate set.
 */
private predicate inPyramidPackage(AstNode n) {
  relPath(n).matches("src/pyramid/%") and
  not relPath(n).matches("src/pyramid/testing.py") and
  not relPath(n).matches("src/pyramid/config/testing.py") and
  not relPath(n).matches("src/pyramid/interfaces.py")
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
 * Resolved filesystem calls. `callableName` is the plain callee name for
 * builtin calls (open, FileResponse), a dotted callee name for module-qualified
 * calls (os.listdir, os.path.*, pkg_resources.*), or a bare from-import alias
 * name (exists/isdir/getsize in static.py, getmtime/getsize in response.py,
 * resource_exists/resource_filename/resource_isdir in static.py). Bare
 * aliases are constrained to their files because from-import alias
 * resolution is not modeled. `argIndex` selects the path-carrying positional
 * argument.
 */
private predicate resolvedFileIoCall(
  Call c, string callableName, string moduleHint, string receiver,
  int argIndex, string flowKind, string accessType
) {
  (
    c.getFunc() instanceof Name and
    callableName = c.getFunc().(Name).getId()
    or
    c.getFunc() instanceof Attribute and
    callableName = dottedName(c.getFunc())
  )
  and
  (
    (
      /* builtins open - real file read/write. */
      callableName = "open" and
      moduleHint = "builtins" and
      receiver = "" and
      argIndex = 0 and
      flowKind = "fs_open" and
      accessType = "builtins open: file read/write/create; observed sites: FileResponse HTTP file serving (response.py:57, mode 'rb'), ManifestCacheBuster manifest load (static.py:394), FSAssetDescriptor.stream (path.py:436), FSAssetSource.get_stream (config/assets.py:281), i18n translation .mo load (i18n.py:203, locale-name-derived path), Translations.load (i18n.py:272), pshell PYTHONSTARTUP startup file (scripts/pshell.py:211)"
    )
    or
    (
      callableName = "os.listdir" and
      moduleHint = "os" and
      receiver = "os" and
      argIndex = 0 and
      flowKind = "fs_listdir" and
      accessType = "os.listdir: directory enumeration; observed sites: i18n.py:201 (locale .mo candidates under the locale-derived messages_dir), path.py:442 (FSAssetDescriptor.listdir), config/assets.py:302 (FSAssetSource.listdir)"
    )
    or
    (
      callableName in ["os.path.isdir", "os.path.isfile", "os.path.exists", "os.path.realpath", "os.path.getsize", "os.path.getmtime"] and
      moduleHint = "os.path" and
      receiver = "os.path" and
      argIndex = 0 and
      flowKind = "fs_metadata" and
      accessType = "os.path filesystem existence/metadata check; observed sites: i18n.py:192/193/198/202 (realpath/isdir/isfile around the locale-name join - symlink resolution and .mo validation), path.py:439/445 (FSAssetDescriptor isdir/exists), config/assets.py:275/297/347/352 (FSAssetSource exists/isdir, override_asset exists/isdir of override_with)"
    )
    or
    (
      /* Bare os.path aliases in static.py via 'from os.path import exists,
         getmtime, getsize, isdir, join, normcase, normpath' (static.py:5). */
      callableName in ["exists", "isdir", "getsize"] and
      relPath(c).matches("src/pyramid/static.py") and
      moduleHint = "os.path (from-import alias)" and
      receiver = "" and
      argIndex = 0 and
      flowKind = "fs_metadata" and
      accessType = "os.path exists/isdir/getsize via from-import alias in static.py: find_resource_path existence check (static.py:170), isdir of the joined resource_path (static.py:153), getsize for candidate ordering (static.py:201 - TOCTOU window between the existence check, getsize and the later FileResponse open)"
    )
    or
    (
      /* Bare os.path aliases in response.py via 'from os.path import
         getmtime, getsize' (response.py:2). */
      callableName in ["getmtime", "getsize"] and
      relPath(c).matches("src/pyramid/response.py") and
      moduleHint = "os.path (from-import alias)" and
      receiver = "" and
      argIndex = 0 and
      flowKind = "fs_metadata" and
      accessType = "os.path getmtime/getsize via from-import alias in response.py: FileResponse last_modified/content_length metadata read before open (response.py:55-56); part of the HTTP file-serving sink together with the open at :57"
    )
    or
    (
      /* pyramid FileResponse: the HTTP file-serving wrapper; the real
         filesystem access happens inside FileResponse.__init__ in this
         same repo (open + getmtime + getsize, response.py:55-57). */
      callableName = "FileResponse" and
      moduleHint = "pyramid.response" and
      receiver = "" and
      argIndex = 0 and
      flowKind = "http_file_response" and
      accessType = "pyramid FileResponse: serves a file as an HTTP response; the real filesystem access (open + getmtime + getsize) happens inside FileResponse.__init__ in this same repo (response.py:55-57); observed site static.py:112 passes the filepath derived from request path_info/subpath via _secure_path + normcase(normpath(join(norm_docroot, path))) or pkg_resources resource_filename"
    )
    or
    (
      /* pkg_resources resource_stream (dotted and self.pkg_resources forms). */
      (
        callableName = "pkg_resources.resource_stream" and receiver = "pkg_resources"
        or
        callableName = "self.pkg_resources.resource_stream" and receiver = "self.pkg_resources"
      ) and
      moduleHint = "pkg_resources" and
      argIndex = 1 and
      flowKind = "fs_resource_stream" and
      accessType = "pkg_resources resource_stream: opens a package-relative resource for reading (the external setuptools provider performs the actual filesystem open); observed sites: path.py:411-412 (PkgResourcesAssetDescriptor.stream, self.path is the asset spec path), config/assets.py:233-234 (PackageAssetSource.get_stream)"
    )
    or
    (
      /* pkg_resources resource_filename (dotted, self.pkg_resources and
         static.py bare-alias forms). */
      (
        (
          callableName = "pkg_resources.resource_filename" and receiver = "pkg_resources"
          or
          callableName = "self.pkg_resources.resource_filename" and receiver = "self.pkg_resources"
        ) and
        moduleHint = "pkg_resources"
        or
        callableName = "resource_filename" and
        relPath(c).matches("src/pyramid/static.py") and
        receiver = "" and
        moduleHint = "pkg_resources (from-import alias)"
      ) and
      argIndex = 1 and
      flowKind = "fs_resource_filename" and
      accessType = "pkg_resources resource_filename: resolves a package-relative resource name to an absolute filesystem filename (external API; filesystem access and possible archive extraction inside setuptools); observed sites: static.py:168 (bare alias, result flows into find_best_match -> FileResponse), asset.py:43 (abspath_from_asset_spec), path.py:407-408 (PkgResourcesAssetDescriptor.abspath) and :71 (package_path), config/assets.py:229 (PackageAssetSource.get_filename)"
    )
    or
    (
      /* pkg_resources existence checks (dotted, self.pkg_resources and
         static.py bare-alias forms). */
      (
        (
          callableName in ["pkg_resources.resource_exists", "pkg_resources.resource_isdir", "pkg_resources.resource_listdir"] and receiver = "pkg_resources"
          or
          callableName in ["self.pkg_resources.resource_exists", "self.pkg_resources.resource_isdir", "self.pkg_resources.resource_listdir"] and receiver = "self.pkg_resources"
        ) and
        moduleHint = "pkg_resources"
        or
        callableName in ["resource_exists", "resource_isdir"] and
        relPath(c).matches("src/pyramid/static.py") and
        receiver = "" and
        moduleHint = "pkg_resources (from-import alias)"
      ) and
      argIndex = 1 and
      flowKind = "fs_resource_metadata" and
      accessType = "pkg_resources resource_exists/resource_isdir/resource_listdir: package resource existence and directory checks (external API performing filesystem access); observed sites: static.py:142 (resource_isdir of the request-derived resource_path) and :167 (resource_exists), path.py:414-421 (PkgResourcesAssetDescriptor isdir/exists/listdir via self.pkg_resources), config/assets.py:241-254 (PackageAssetSource)"
    )
    or
    (
      /* OverrideProvider delegations to the parent DefaultProvider in
         config/assets.py; resource_name carries the resource path. */
      (
        callableName = "pkg_resources.DefaultProvider.get_resource_filename" and
        argIndex = 2 and
        flowKind = "fs_resource_filename"
        or
        callableName in ["pkg_resources.DefaultProvider.get_resource_stream", "pkg_resources.DefaultProvider.get_resource_string"] and
        argIndex = 2 and
        flowKind = "fs_resource_stream"
      ) and
      moduleHint = "pkg_resources" and
      receiver = "pkg_resources.DefaultProvider" and
      accessType = "OverrideProvider delegation to pkg_resources.DefaultProvider (config/assets.py:32-82); the resource_name argument (arg 2, after self/manager) carries the resource path into the setuptools provider's real filesystem access"
    )
    or
    (
      callableName in [
        "pkg_resources.DefaultProvider.has_resource",
        "pkg_resources.DefaultProvider.resource_isdir",
        "pkg_resources.DefaultProvider.resource_listdir"
      ] and
      moduleHint = "pkg_resources" and
      receiver = "pkg_resources.DefaultProvider" and
      argIndex = 1 and
      flowKind = "fs_resource_metadata" and
      accessType = "OverrideProvider delegation to pkg_resources.DefaultProvider (config/assets.py:64-84); the resource_name argument (arg 1, after self) carries the resource path into the provider's existence/isdir/listdir check"
    )
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
    inPyramidPackage(c) and
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
  inPyramidPackage(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
