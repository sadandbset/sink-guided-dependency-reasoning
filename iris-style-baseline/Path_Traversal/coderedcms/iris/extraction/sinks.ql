/**
 * @name coderedcms CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the coderedcms
 *   CodeQL database (coderedcms 0.22.2, snapshot sha acc37d2c, a Wagtail 2.14 /
 *   Django 3.x CMS): the builtin open() call of the protected-media view
 *   (views.py:117, fed by os.path.join(PROTECTED_MEDIA_ROOT, path) with the
 *   URL-injected path at :114 - the primary file-serving site); the
 *   os.path propagation/validation pipeline (join/isfile/isdir/splitext/
 *   basename/dirname/abspath, emitted both as API-graph-resolved and as
 *   module-qualified syntax rows); pathlib Path(...) constructor calls and
 *   receiver-path methods (.mkdir/.rmdir/.with_suffix) plus pathlib path
 *   attribute propagation (.name/.parent/.root/.suffix); the Django
 *   FileSystemStorage API surface that actually touches the filesystem in
 *   the form-upload pipeline (storage.open(path,'wb+') upload writes,
 *   storage.path(...), storage.get_available_name(...), storage.delete(...),
 *   storage.listdir(...), storage.url(...), the get_storage() wrapper calls
 *   and the FileSystemStorage(location=PROTECTED_MEDIA_ROOT) constructors);
 *   PIL image file access (Image.open(storage.path(path)) at wff:342,
 *   thumbnail.save(...) at :344); file-handle writes (destination.write(chunk)
 *   inside the storage.open context managers); and internal wrapper
 *   functions whose body directly performs a filesystem operation
 *   (serve_protected_file, Steps.save_files, CoderedFormMixin.process_data,
 *   SessionFormSubmission.get_thumbnail_path/delete_file, the delete_files
 *   signal receiver, CreateProject.handle). flow_kind marks each row as a
 *   real file operation (file_open, storage_open, storage_delete,
 *   storage_listdir, file_dir_create, file_dir_delete, image_open,
 *   image_save, file_obj_write), an external-API path resolution step
 *   (storage_path, storage_name), a path propagation/validation node
 *   (path_join, path_check, path_resolve, path_ctor, path_propagate,
 *   storage_url) or an internal wrapper definition (internal_file_wrapper);
 *   only the rows that actually access the filesystem with a controlled
 *   path argument are expected to label as sinks - the propagation rows
 *   are candidates for summary/sanitizer labels. Raw BQRS extraction query:
 *   run with `codeql query run` and decode with `codeql bqrs decode` (not
 *   database analyze). This is a plain multi-column select query on
 *   purpose: @kind problem is the wrong shape for candidate tables and
 *   @kind table is not assumed to exist.
 * @id iris/coderedcms/extraction/sinks
 * @tags path-traversal
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql and to the prior IRIS manual
 * projects aiohttp/airflow/ansible):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or attribute name)
 *   4. flow_kind  - see the @description: real fs operations (file_open,
 *                   storage_open, storage_delete, storage_listdir,
 *                   file_dir_create, file_dir_delete, image_open,
 *                   image_save, file_obj_write), external-API path
 *                   resolution (storage_path, storage_name), propagation/
 *                   validation nodes (path_join, path_check, path_resolve,
 *                   path_ctor, path_propagate, storage_url), storage
 *                   acquisition/creation (storage_get, storage_ctor) and
 *                   internal wrapper definitions (internal_file_wrapper)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "os.path", "storage", "get_storage()",
 *                   "Image", "thumbnail", "destination", or "" when none;
 *                   enclosing class name for wrapper definition rows)
 *   6. moduleHint - module hint: external module name (os.path, pathlib,
 *                   PIL, django.core.files.storage, builtin), or dotted
 *                   python module path for internal candidates (variable
 *                   intentionally named moduleHint; `module` is not a valid
 *                   QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (-1 when the path is the receiver or for wrapper rows)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Scope: real filesystem operations (open/create/read/write/remove/directory
 * ops, file-serving) plus the path propagation/validation nodes and storage
 * wrapper surface that carry the controlled path values toward them. Every
 * row points at a call/attribute actually present in the code - the
 * propagation families exist so the labeling step can mark summary steps and
 * sanitizers, not to inflate sink counts. The os.path members resolve both
 * via API graphs (alias-aware, API::moduleImport("os").getMember("path")
 * .getMember(member).getACall()) and via the qualified os.path.<member>
 * syntax shape (all uses in this codebase are qualified; `from os import
 * path` does not occur); the same call site can legitimately yield one api
 * and one ast row (identical to the airflow project of this series).
 *
 * Note: this file defines no QL classes (only predicates/functions), does not
 * assign API::Node values to DataFlow::Node variables, and keeps resolved-API
 * matching strictly separate from AST syntax matching (the match_kind column
 * records which one produced a row).
 *
 * Scope (applied to every row): %/coderedcms/% (the shipped coderedcms
 * package), EXCLUDING %/coderedcms/migrations/% (generated migrations),
 * %/coderedcms/tests/% (incl. blocks/tests and models/tests),
 * %/coderedcms/project_template/% (CLI project scaffolding) and the nested
 * %/coderedcms-db/% database directory. Root setup.py, docs/, ci/ and
 * tutorial/ are outside the positive scope (setup.py's README open() is
 * build tooling, not request-reachable).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  have no dotted module name; their file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
}

/** Forward-slash-normalized absolute path of the file containing n, so path
 *  matching works with both CodeQL path styles on Windows. */
string normalizedPathOf(AstNode n) {
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
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

/** True iff the candidate's file path is inside the audited coderedcms
 *  package (%/coderedcms/% but not the generated/scaffold/test subtrees and
 *  not the nested %/coderedcms-db/% database directory). bindingset[path]
 *  declares that the caller passes a bound path (the path only appears in
 *  checked positions such as the receiver of replaceAll/matches inside this
 *  predicate). */
bindingset[path]
predicate coderedSourcePath(string path) {
  path.replaceAll("\\", "/").matches("%/coderedcms/%") and
  not path.replaceAll("\\", "/").matches("%/coderedcms-db/%") and
  not path.replaceAll("\\", "/").matches("%/coderedcms/migrations/%") and
  not path.replaceAll("\\", "/").matches("%/coderedcms/tests/%") and
  not path.replaceAll("\\", "/").matches("%/coderedcms/project_template/%")
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Sink family tables                                                  */
/* ------------------------------------------------------------------ */

/**
 * os.path members observed in this codebase, classified as propagation
 * (join), validation/check (isfile/isdir/splitext/basename) or resolution
 * (dirname/abspath) nodes. None of them is a file access by itself; they
 * carry and transform the controlled path values (views.py:114 joins the
 * URL-injected path onto PROTECTED_MEDIA_ROOT right before the open at
 * :117; forms.py:68/:73 validate only the upload filename extension).
 */
private predicate osPathMemberKind(string member, string flowKind) {
  member = "join" and flowKind = "path_join"
  or
  member in ["isfile", "isdir", "splitext", "basename"] and flowKind = "path_check"
  or
  member in ["dirname", "abspath"] and flowKind = "path_resolve"
}

/**
 * Django FileSystemStorage / default_storage members called in this codebase:
 * open/delete/listdir perform real filesystem operations on the storage
 * root; path/get_available_name resolve or deduplicate the name inside the
 * storage (external Django behavior); url builds the protected-media URL
 * (the bridge value consumed by serve_protected_file, not a file access).
 * The path/name argument sits at index 0 for every member.
 */
private predicate storageMemberKind(string member, string flowKind) {
  member = "open" and flowKind = "storage_open"
  or
  member = "path" and flowKind = "storage_path"
  or
  member = "get_available_name" and flowKind = "storage_name"
  or
  member = "delete" and flowKind = "storage_delete"
  or
  member = "listdir" and flowKind = "storage_listdir"
  or
  member = "url" and flowKind = "storage_url"
}

/** Holds if func is the callee attribute of a call whose receiver is the
 *  local storage variable (`storage.<member>(...)` - the dominant shape) or
 *  the value of a get_storage() call (`self.get_storage().<member>(...)` at
 *  wff models.py:379/:402). */
private predicate storageCallFunc(Attribute func) {
  func.getObject().(Name).getId() = "storage"
  or
  func.getObject().(Call).getFunc().(Attribute).getName() = "get_storage"
}

/** Receiver hint for a storage member call. */
private string storageReceiverHint(Attribute func) {
  func.getObject().(Name).getId() = "storage" and result = "storage"
  or
  func.getObject().(Call).getFunc().(Attribute).getName() = "get_storage" and
  result = "get_storage()"
}

/**
 * Holds if c is a call site that directly performs a filesystem operation
 * (used for the internal_file_wrapper family): builtin open, the storage
 * open/delete/listdir members (both receiver shapes), the pathlib mkdir/
 * rmdir receiver-path methods, PIL Image.open, thumbnail.save, the
 * destination.write file-handle write, and the os.path isfile/isdir
 * stat checks (syntactic os.path form; views.py:115, bin/coderedcms.py:67).
 * Pure string operations (join/splitext/dirname/abspath/basename,
 * get_available_name, url, with_suffix) deliberately do NOT count.
 */
private predicate fileOpCallSite(Call c) {
  c.getFunc().(Name).getId() = "open"
  or
  exists(Attribute func |
    func = c.getFunc().(Attribute) and
    (
      func.getName() in ["mkdir", "rmdir"]
      or
      func.getName() in ["open", "delete", "listdir"] and
      storageCallFunc(func)
      or
      func.getName() = "open" and
      func.getObject().(Name).getId() = "Image"
      or
      func.getName() = "save" and
      func.getObject().(Name).getId() = "thumbnail"
      or
      func.getName() = "write" and
      func.getObject().(Name).getId() = "destination"
    )
  )
  or
  exists(Attribute func, Attribute pathmod |
    func = c.getFunc().(Attribute) and
    func.getName() in ["isfile", "isdir"] and
    pathmod = func.getObject().(Attribute) and
    pathmod.getName() = "path" and
    pathmod.getObject().(Name).getId() = "os"
  )
}

/**
 * Functions in this codebase whose body directly performs a filesystem
 * operation: serve_protected_file (views.py:110, open at :117),
 * Steps.save_files (wff models.py:226, mkdir/storage.open/write at
 * :241-:247), CoderedFormMixin.process_data (page_models.py:1194,
 :1208-:1214), SessionFormSubmission.get_thumbnail_path (wff:323,
 * Image.open/thumbnail.save at :342/:344), SessionFormSubmission.delete_file
 * (wff:376, self.get_storage().delete at :379), the delete_files signal
 * receiver (wff:483, delete/listdir/rmdir at :488/:495/:499) and
 * CreateProject.handle (bin/coderedcms.py:37, os.path.isdir at :67).
 */
private predicate internalFileWrapper(Function f) {
  exists(Call c |
    fileOpCallSite(c) and
    c.getScope().(Function) = f
  )
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 0: builtin open() - the single file-serving read of the
     package: views.py:117 open(fullpath, 'rb') inside
     serve_protected_file, fullpath = os.path.join(PROTECTED_MEDIA_ROOT,
     path) with the URL-injected path at :114 (no containment guard between
     join and open); the path is argument 0. */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtin" and
    matchKind = "ast"
  )
  or
  /* family 1a: os.path member calls resolved via API graphs (alias-aware):
     API::moduleImport("os").getMember("path").getMember(member).getACall().
     Sites: join at views.py:114, settings.py:13, bin/coderedcms.py:60/:61;
     isfile at views.py:115; splitext at forms.py:68/:73,
     page_models.py:1491, wff models.py:769/:814; dirname at
     settings.py:6/:7/:9, bin/coderedcms.py:57; abspath at settings.py:7;
     isdir at bin/coderedcms.py:67; basename at bin/coderedcms.py:128. */
  exists(API::CallNode cn, string member |
    osPathMemberKind(member, flowKind) and
    cn = API::moduleImport("os").getMember("path").getMember(member).getACall() and
    node = astCallOf(cn) and
    callableName = member and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os.path" and
    matchKind = "api"
  )
  or
  /* family 1b: os.path member calls, qualified syntax shape
     (os.path.<member>(...) - the only form used in this codebase; the
     receiver column carries the module prefix). Same sites as family 1a. */
  exists(Call c, Attribute func, Attribute pathmod |
    func = c.getFunc().(Attribute) and
    osPathMemberKind(func.getName(), flowKind) and
    pathmod = func.getObject().(Attribute) and
    pathmod.getName() = "path" and
    pathmod.getObject().(Name).getId() = "os" and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 2a: pathlib.Path(...) constructor calls (bare from-imported
     name in page_models.py and wff models.py): the destination
     construction str(Path(directory) / val.name) at page_models.py:1211 /
     wff models.py:244, the mkdir base Path(storage.path(directory)) at
     page_models.py:1208 / wff models.py:241, the thumbnail path re-wrap
     Path(path) at wff models.py:336, Path(value) at :403, the directory
     walk Path(path)/Path(directory.root) at :491/:492. The path is
     argument 0. */
  exists(Call c |
    c.getFunc().(Name).getId() = "Path" and
    node = c and
    flowKind = "path_ctor" and
    callableName = "Path" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 2b: receiver-path method calls: .mkdir (directory creation of
     the upload storage, page_models.py:1208 / wff models.py:241),
     .rmdir (empty-directory removal, wff models.py:499) and .with_suffix
     (thumbnail path derivation, wff models.py:337) - the receiver object
     is the path; arg_index is -1 by convention. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (
      func.getName() = "mkdir" and flowKind = "file_dir_create"
      or
      func.getName() = "rmdir" and flowKind = "file_dir_delete"
      or
      func.getName() = "with_suffix" and flowKind = "path_propagate"
    ) and
    node = c and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 2c: pathlib path attribute propagation: .name / .parent /
     .root / .suffix reads on path-bearing locals (path, directory) or on
     Path(...) call results, restricted to wagtail_flexible_forms/models.py
     where they all occur (:338 path.suffix, :403 Path(value).name,
     :492/:493 directory.parent, :492 directory.root). */
  exists(Attribute a |
    a.getName() in ["name", "parent", "root", "suffix"] and
    (
      a.getObject().(Name).getId() in ["path", "directory"]
      or
      a.getObject() instanceof Call
    ) and
    normalizedPathOf(a).matches("%/coderedcms/wagtail_flexible_forms/models.py") and
    node = a and
    flowKind = "path_propagate" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 3a/3b: Django storage member calls: storage.open(path, 'wb+')
     (upload writes, page_models.py:1212 / wff models.py:245),
     storage.get_available_name(...) (page:1210, wff:243/:340),
     storage.path(...) (page:1208, wff:241/:342/:344/:499),
     storage.delete(path) (wff:488), storage.listdir(directory) (wff:495),
     storage.url(value) (wff:397/:398), and the self.get_storage()
     receiver forms (delete at wff:379, url at wff:402). The path/name
     argument sits at index 0 for every member. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    storageMemberKind(func.getName(), flowKind) and
    storageCallFunc(func) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = storageReceiverHint(func) and
    moduleHint = "django.core.files.storage" and
    matchKind = "ast"
  )
  or
  /* family 3c: get_storage() wrapper calls - the internal accessor that
     returns the FileSystemStorage/default_storage object (page:1207, wff:
     :240/:339/:379/:402/:486). The storage root/base_url are bound inside
     get_storage, not by arguments; arg_index -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get_storage" and
    node = c and
    flowKind = "storage_get" and
    callableName = "get_storage" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3d: FileSystemStorage(location=cr_settings['PROTECTED_MEDIA_
     * ROOT'], base_url=...) constructors binding the protected-media root
     (page_models.py:1223 and :1714; wff models.py:669 returns
     default_storage instead). The location argument sits at index 0. */
  exists(Call c |
    c.getFunc().(Name).getId() = "FileSystemStorage" and
    node = c and
    flowKind = "storage_ctor" and
    callableName = "FileSystemStorage" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "django.core.files.storage" and
    matchKind = "ast"
  )
  or
  /* family 4: PIL image file access: Image.open(storage.path(path)) at
     wff models.py:342 - reads the stored submission path for thumbnailing;
     the path is argument 0 (the storage.path call itself is a separate
     family 3 row). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "Image" and
    node = c and
    flowKind = "image_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "Image" and
    moduleHint = "PIL" and
    matchKind = "ast"
  )
  or
  /* family 5: PIL image write: thumbnail.save(storage.path(thumbnail_path))
     at wff models.py:344 - writes the thumbnail next to the stored path;
     the destination is argument 0. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "save" and
    func.getObject().(Name).getId() = "thumbnail" and
    node = c and
    flowKind = "image_save" and
    callableName = "save" and
    argIndex = 0 and
    receiver = "thumbnail" and
    moduleHint = "PIL" and
    matchKind = "ast"
  )
  or
  /* family 6: file-handle writes: destination.write(chunk) inside the
     `with storage.open(path, 'wb+') as destination:` context managers
     (wff models.py:245-:247, page_models.py:1212-:1214). The path was
     bound at the storage.open call; the receiver is the opened handle, so
     arg_index is -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "write" and
    func.getObject().(Name).getId() = "destination" and
    node = c and
    flowKind = "file_obj_write" and
    callableName = "write" and
    argIndex = -1 and
    receiver = "destination" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 7: internal functions that directly perform a filesystem
     * operation: serve_protected_file, Steps.save_files,
     * CoderedFormMixin.process_data,
     * SessionFormSubmission.get_thumbnail_path/delete_file, the
     * delete_files signal receiver and CreateProject.handle. */
  exists(Function f |
    internalFileWrapper(f) and
    node = f and
    flowKind = "internal_file_wrapper" and
    callableName = f.getName() and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    (
      f.getEnclosingScope() instanceof Class and
      receiver = f.getEnclosingScope().(Class).getName()
      or
      not f.getEnclosingScope() instanceof Class and
      receiver = ""
    )
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  coderedSourcePath(normalizedPathOf(node))
select
  node,
  "sink_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
