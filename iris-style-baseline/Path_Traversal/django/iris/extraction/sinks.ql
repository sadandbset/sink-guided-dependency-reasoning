/**
 * @name django CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the Django
 *   2.2.26 framework-source CodeQL database (snapshot sha c9f648c): the real
 *   file operations - builtin open() (~40 sites: contrib/sessions/backends/
 *   file.py:78 the cookie-keyed session file read, core/cache/backends/
 *   filebased.py:34/:53/:63/:93 the cache file read/write, core/files/
 *   storage.py:231 FileSystemStorage._open, core/files/base.py:112 File.open
 *   reopen-by-name, core/files/move.py:56, core/mail/backends/filebased.py:61,
 *   template/loaders/filesystem.py:23 the template source read,
 *   utils/archive.py:183/:221 the archive member extraction writes, the
 *   management commands and core/management/templates.py:151/:155); the
 *   os-level syscalls (os.open storage.py:273 the O_EXCL upload write and
 *   sessions file.py:126, os.remove, os.unlink, os.rename, os.rmdir,
 *   os.makedirs, os.mkdir, os.chmod, os.utime, os.stat, os.scandir
 *   storage.py:322, os.listdir, os.walk, os.symlink, os.access, os.fdopen);
 *   shutil.move/rmtree/copyfile/copy/copymode plus the bare-name copystat of
 *   core/files/move.py (from shutil import copystat); the pathlib family
 *   (the Path(safe_join(document_root, path)) constructor + fullpath.open(
 *   'rb') of the dev static server at views/static.py:36/:50 - THE file
 *   download sink - with its is_dir/exists/stat probes at :37/:41/:44 and
 *   iterdir at :95; admindocs template_file.open() at contrib/admindocs/
 *   views.py:334; attach_file's Path(path).open('rb') at core/mail/message.
 *   py:351-:352; the qualified pathlib.PurePath/PurePosixPath constructions);
 *   the archive extraction chain (archive.extract(filename, tempdir) at
 *   core/management/templates.py:313, Archive/tarfile.open/zipfile.ZipFile at
 *   utils/archive.py:50/:155/:197, extractfile at :173, target_filename
 *   prefix check at :138-:143); the file-serving wrappers (FileResponse at
 *   views/static.py:50, the static.serve delegation at contrib/staticfiles/
 *   views.py:39, finders.find at :33); the first-party storage API consumed
 *   by FieldFile and the staticfiles finders (self.storage.open/save/delete/
 *   path/exists at db/models/fields/files.py:44/:75/:88/:58 and
 *   contrib/staticfiles/finders.py:223/:229/:230); file_move_safe (the
 *   atomic move wrapper, storage.py:268 and cache filebased.py:55); the
 *   os.path/posixpath propagation and validation pipeline (join - api+ast
 *   rows, abspath/realpath/normpath/normcase/dirname/split/expanduser/
 *   samefile, exists/isfile/isdir/getsize/splitext/basename, and the
 *   normpath the request path passes through before serve) plus the
 *   alias-import forms (from os.path import ... in utils/_os.py, from os
 *   import path in core/management/templates.py); the sanitizer family as
 *   candidate rows for labeling (safe_join, validate_file_name,
 *   get_valid_filename, sanitize_file_name); and internal functions whose
 *   body directly performs a filesystem operation (FileSystemStorage
 *   _open/_save/delete/exists/listdir/size/get_*_time, SessionStore
 *   load/save/exists/delete/_last_modification, FileBasedCache get/set/
 *   touch/has_key/_delete/_cull/_createdir, EmailBackend.open,
 *   FileSystemLoader.get_contents, File.open, file_move_safe, the archive
 *   extract family, TemplateCommand handle/download/extract/
 *   make_writeable, serve itself, and the management commands). flow_kind
 *   marks each row as a real file operation (file_open, file_read,
 *   file_write, fs_open, fs_unlink, fs_rename, fs_mkdir, fs_perm, fs_stat,
 *   fs_link, fs_listdir, fs_copy, archive_extract, archive_open,
 *   archive_read), a file serving/validation wrapper (file_serve,
 *   fs_storage_wrapper, fs_move_wrapper, path_check), a path
 *   construction/propagation node (path_construct, path_join,
 *   path_resolve) or a sanitizer (path_sanitize); only the rows that
 *   actually access the filesystem with a controlled path argument are
 *   expected to label as sinks - the propagation rows are candidates for
 *   summary/sanitizer labels. Raw BQRS extraction query: run with `codeql
 *   query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose:
 *   @kind problem is the wrong shape for candidate tables and @kind table
 *   is not assumed to exist.
 * @id iris/django/extraction/sinks
 * @tags path-traversal
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql and to the prior IRIS manual
 * projects aiohttp/airflow/ansible/coderedcms/copyparty):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or
 *                   parameter/method name)
 *   4. flow_kind  - see the @description: real fs operations (file_open,
 *                   file_read, file_write, fs_open, fs_unlink, fs_rename,
 *                   fs_mkdir, fs_perm, fs_stat, fs_link, fs_listdir,
 *                   fs_copy, archive_extract, archive_open, archive_read),
 *                   file serving / storage wrappers (file_serve,
 *                   fs_storage_wrapper, fs_move_wrapper), path construction
 *                   and propagation nodes (path_construct, path_join,
 *                   path_resolve), validation nodes (path_check) and the
 *                   sanitizer family (path_sanitize)
 *   5. receiver   - syntactic receiver hint ("os", "os.path", "posixpath",
 *                   "pathlib", "pathlib.Path" (static type hint: for the
 *                   Path-method family the path is the RECEIVER, not an
 *                   argument), "zipfile", "tarfile", "self", "self.storage",
 *                   "self._archive", "finders", "static", "" when none; the
 *                   enclosing function name for wrapper rows)
 *   6. moduleHint - module hint: external module name (os, os.path, shutil,
 *                   posixpath, pathlib, tarfile, zipfile, builtin), the
 *                   first-party module providing the wrapper ("django.utils.
 *                   _os" for safe_join, "django.core.files.move" for
 *                   file_move_safe, "django.core.files.utils" for
 *                   validate_file_name, "django.utils.text" for
 *                   get_valid_filename, "django.http.multipartparser" for
 *                   sanitize_file_name, "django.views.static" for the serve
 *                   delegation, "django.contrib.staticfiles.finders" for
 *                   finders.find, "django.http" for FileResponse), or the
 *                   dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module` is
 *                   not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (1 for the rename/move/link destination and for the
 *                   archive extract destination; -1 when the path is the
 *                   receiver or for wrapper rows)
 *   8. file       - absolute file path, obtained through the Location API
 *                   (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Scope: real filesystem operations (open/create/read/write/remove/rename/
 * directory ops, file-serving, archive extraction) plus the os.path/posixpath
 * propagation and validation nodes that carry the controlled path values
 * toward them. Every row points at a call/attribute/function actually
 * present in the code - the propagation families exist so the labeling step
 * can mark summary steps and sanitizers, not to inflate sink counts. The
 * os.path.join family resolves both via API graphs (alias-aware, API::
 * moduleImport("os").getMember("path").getMember("join").getACall()) and via
 * the qualified os.path.join syntax shape; the same call site can
 * legitimately yield one api and one ast row (identical to the airflow/
 * coderedcms/copyparty projects of this series). The Path-method family
 * (attribute-name matching for .open/.read_text/.read_bytes/.write_text/
 * .write_bytes/.iterdir) cannot constrain the receiver to a pathlib Path at
 * AST level, so non-Path .open receivers (self.storage.open, self.file.open)
 * also match and are additionally covered by the dedicated storage-wrapper
 * family - the same call node can therefore yield two rows with different
 * flow_kind (same duplicate policy as above). FileResponse itself only
 * streams an already-open file object (filelike.read) and stats its name
 * (http/response.py:390-:427); its file_serve rows mark the serving
 * boundary, the actual open happens at the .open call feeding it.
 *
 * Note: this file defines no QL classes (only predicates/functions), does not
 * assign API::Node values to DataFlow::Node variables, and keeps resolved-API
 * matching strictly separate from AST syntax matching (the match_kind column
 * records which one produced a row).
 *
 * Scope (applied to every row): %/django_vuln/django/% (the shipped django
 * package), EXCLUDING the nested %/django-db/% database directory (also
 * outside the positive scope by construction), %/django/test/% (in-package
 * test tooling) and %/django/contrib/admin/bin/% (manually run asset-build
 * script). Top-level tests/, docs/, extras/ and scripts/ are outside the
 * positive scope.
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

/** True iff the candidate's file path is inside the audited django package
 *  (%/django_vuln/django/% but not the in-package test tooling, not the
 *  admin asset-build script and not the nested %/django-db/% database
 *  directory). bindingset[path] declares that the caller passes a bound path
 *  (the path only appears in checked positions such as the receiver of
 *  replaceAll/matches inside this predicate). */
bindingset[path]
predicate djangoSourcePath(string path) {
  path.replaceAll("\\", "/").matches("%/django_vuln/django/%") and
  not path.replaceAll("\\", "/").matches("%/django-db/%") and
  not path.replaceAll("\\", "/").matches("%/django_vuln/django/test/%") and
  not path.replaceAll("\\", "/").matches("%/django_vuln/django/contrib/admin/bin/%")
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Sink family tables                                                  */
/* ------------------------------------------------------------------ */

/**
 * os module members observed in this codebase, classified by filesystem
 * operation and the argument index carrying the path (rename: dst at 1,
 * src at 0; symlink: link path at 1).
 */
private predicate osMemberKind(string member, string flowKind, int argIndex) {
  member in ["open", "fdopen"] and flowKind = "fs_open" and argIndex = 0
  or
  member in ["remove", "unlink", "rmdir"] and flowKind = "fs_unlink" and argIndex = 0
  or
  member = "rename" and flowKind = "fs_rename" and argIndex = 1
  or
  member in ["mkdir", "makedirs"] and flowKind = "fs_mkdir" and argIndex = 0
  or
  member in ["chmod", "utime"] and flowKind = "fs_perm" and argIndex = 0
  or
  member in ["stat", "listdir", "scandir", "walk", "access"] and flowKind = "fs_stat" and argIndex = 0
  or
  member = "symlink" and flowKind = "fs_link" and argIndex = 1
}

/**
 * shutil members observed in this codebase, classified by filesystem
 * operation and the argument index carrying the path (move: dst at 1;
 * rmtree: 0; copy* family: dst at 1).
 */
private predicate shutilMemberKind(string member, string flowKind, int argIndex) {
  member = "move" and flowKind = "fs_rename" and argIndex = 1
  or
  member = "rmtree" and flowKind = "fs_unlink" and argIndex = 0
  or
  member in ["copyfile", "copy", "copymode"] and flowKind = "fs_copy" and argIndex = 1
}

/**
 * os.path members observed in this codebase, classified as propagation
 * (join), validation/check or resolution nodes. None of them is a file
 * access by itself; they carry and transform the controlled path values
 * (sessions _key_to_file join, cache _key_to_file join, storage
 * generate_filename join, the normpath the request path passes through
 * before serve). Argument 0.
 */
private predicate osPathMemberKind(string member, string flowKind) {
  member = "join" and flowKind = "path_join"
  or
  member in ["abspath", "realpath", "dirname", "split", "normpath", "normcase", "expanduser", "samefile"] and
  flowKind = "path_resolve"
  or
  member in ["isfile", "isdir", "exists", "lexists", "getsize", "getmtime", "getatime", "getctime", "splitext", "basename", "isabs", "islink"] and
  flowKind = "path_check"
}

/**
 * posixpath members observed in this codebase (views/static.py:35 and
 * contrib/staticfiles/views.py:32 norm the request path before serve;
 * core/management/templates.py:296 splitext). Same classification; argument 0.
 */
private predicate posixpathMemberKind(string member, string flowKind) {
  member = "join" and flowKind = "path_join"
  or
  member = "normpath" and flowKind = "path_resolve"
  or
  member = "splitext" and flowKind = "path_check"
}

/**
 * Holds if func is the callee attribute of a call whose receiver is the
 * os.path module prefix (os.path.<member>(...)) - the qualified syntax
 * shape used everywhere in this codebase.
 */
private predicate osPathCallFunc(Attribute func, Attribute pathmod) {
  pathmod = func.getObject().(Attribute) and
  pathmod.getName() = "path" and
  pathmod.getObject().(Name).getId() = "os"
}

/**
 * Holds if func is the callee attribute of a call whose receiver is the
 * `path` name imported via `from os import path` in
 * core/management/templates.py (path.join/expanduser/normpath/isdir/exists/
 * abspath/isfile - the alias-import form of the os.path family).
 */
private predicate osPathAliasCallFunc(Attribute func, Name base) {
  base = func.getObject().(Name) and
  base.getId() = "path"
}

/**
 * pathlib method names that access the filesystem with the path object as
 * the receiver, classified by access type.
 */
private predicate pathMethodKind(string member, string flowKind) {
  member = "open" and flowKind = "file_open"
  or
  member in ["read_text", "read_bytes"] and flowKind = "file_read"
  or
  member in ["write_text", "write_bytes"] and flowKind = "file_write"
  or
  member = "iterdir" and flowKind = "fs_listdir"
}

/**
 * Holds if c is a call site that directly performs a filesystem operation
 * (used for the internal_file_wrapper family): builtin open, the os fs-op
 * members, the shutil members, the os.path existence checks, pathlib-style
 * .open()/.iterdir() attribute calls, zipfile.ZipFile/tarfile.open (via the
 * .open row), the archive extract family, file_move_safe and the Archive
 * wrapper. Pure string operations (os.path join/splitext/dirname/abspath/
 * basename, posixpath, djoin-style helpers, safe_join, validate_file_name)
 * and the permission-only checks deliberately do NOT count - a wrapper row
 * requires a file access in the body.
 */
private predicate fileOpCallSite(Call c) {
  c.getFunc().(Name).getId() = "open"
  or
  c.getFunc().(Name).getId() = "file_move_safe"
  or
  c.getFunc().(Name).getId() = "Archive"
  or
  c.getFunc().(Name).getId() = "copystat" and
  normalizedPathOf(c).matches("%/django/core/files/move.py")
  or
  exists(Attribute func, string kind, int ai |
    func = c.getFunc().(Attribute) and
    osMemberKind(func.getName(), kind, ai) and
    func.getObject().(Name).getId() = "os"
  )
  or
  exists(Attribute func, string kind, int ai |
    func = c.getFunc().(Attribute) and
    shutilMemberKind(func.getName(), kind, ai) and
    func.getObject().(Name).getId() = "shutil"
  )
  or
  exists(Attribute func, Attribute pathmod |
    func = c.getFunc().(Attribute) and
    func.getName() in ["isfile", "isdir", "exists", "lexists"] and
    osPathCallFunc(func, pathmod)
  )
  or
  exists(Attribute func, string kind |
    func = c.getFunc().(Attribute) and
    pathMethodKind(func.getName(), kind)
  )
  or
  exists(Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "ZipFile" and
    func.getObject().(Name).getId() = "zipfile"
  )
  or
  exists(Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["extract", "extractfile"] and
    (
      func.getObject().(Name).getId() = "archive"
      or
      func.getObject().(Attribute).getName() = "_archive"
    )
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
  /* family 0: builtin open() - bare-name calls across the package. Key
     sites: contrib/sessions/backends/file.py:78 (session file read, the
     cookie-derived _key_to_file path), core/cache/backends/filebased.py:34/
     :53/:63/:93 (cache file read/write on the md5'd cache key),
     core/files/storage.py:231 (FileSystemStorage._open - opens
     self.path(name), the safe_join of MEDIA_ROOT and the stored name),
     core/files/base.py:112 (File.open - reopens by self.name, the stored
     upload/field name), core/files/move.py:56, core/mail/backends/
     filebased.py:61, template/loaders/filesystem.py:23 (template source
     read, safe_join-fed), utils/archive.py:183/:221 (archive member
     extraction writes), views/debug.py:358, core/management/templates.py:
     :151/:155, the makemessages/makemigrations/compilemessages/dumpdata/
     squashmigrations/shell commands. The path is argument 0. */
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
  /* family 1: the os-level fs syscalls: os.<member>(...). Key sites:
     os.open (core/files/storage.py:273 the O_CREAT|O_EXCL upload write;
     contrib/sessions/backends/file.py:126 the session placeholder),
     os.remove/os.unlink (storage.py:310 delete, sessions file.py:181,
     cache filebased.py:59/:85, collectstatic.py:239/:319), os.rename
     (sessions file.py:137/:161, move.py:34/:48/:51 - dst at 1), os.rmdir
     (storage.py:308), os.makedirs/os.mkdir (storage.py:241-:252, cache
     filebased.py:117/:121, archive.py:170/:182/:215/:219, sessions
     mkstemp dir, collectstatic, makemessages), os.chmod (storage.py:297,
     archive.py:110, templates.py:334), os.stat (sessions file.py:61),
     os.scandir (storage.py:322 listdir, forms/fields.py:1109
     FilePathField), os.listdir (sessions file.py:193), os.walk
     (templates.py:117, forms/fields.py:1094, compilemessages,
     makemessages), os.symlink (collectstatic.py:320 - link path at 1),
     os.access (move.py:45, templates.py:331), os.fdopen (storage.py:280,
     core/files/temp.py:40). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getObject().(Name).getId() = "os" and
    osMemberKind(func.getName(), flowKind, argIndex) and
    node = c and
    callableName = func.getName() and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 2a: the shutil fs operations: shutil.<member>(...). Sites:
     shutil.move (contrib/sessions/backends/file.py:164 the atomic session
     rename; core/management/templates.py:286 the downloaded template move
     - dst at 1), shutil.rmtree (templates.py:178), shutil.copyfile
     (templates.py:158), shutil.copy (sqlite creation.py:76),
     shutil.copymode (templates.py:163). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getObject().(Name).getId() = "shutil" and
    shutilMemberKind(func.getName(), flowKind, argIndex) and
    node = c and
    callableName = func.getName() and
    receiver = "shutil" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  /* family 2b: the alias-import form of the shutil family: bare-name
     copystat(...) in core/files/move.py (from shutil import copystat at
     move.py:10; called at :71 - dst at 1). */
  exists(Call c |
    c.getFunc().(Name).getId() = "copystat" and
    normalizedPathOf(c).matches("%/django/core/files/move.py") and
    node = c and
    flowKind = "fs_copy" and
    callableName = "copystat" and
    argIndex = 1 and
    receiver = "" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  /* family 3a: os.path.join resolved via API graphs (alias-aware).
     Sites: contrib/sessions/backends/file.py:55 (the session-key join),
     core/cache/backends/filebased.py:134 (the cache-key join),
     core/files/storage.py:82/:96/:108 (upload name joins),
     db/models/fields/files.py path plumbing, core/management/templates.py
     (aliased path.join at :68/:122/:135/:259/:285 - covered by family 5),
     the ~250 qualified join sites. Argument 0 carries the base; the
     controlled component may sit at any index - labeling must treat join
     as taint-preserving for ALL arguments. */
  exists(API::CallNode cn |
    cn = API::moduleImport("os").getMember("path").getMember("join").getACall() and
    node = astCallOf(cn) and
    flowKind = "path_join" and
    callableName = "join" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "api"
  )
  or
  /* family 3b: os.path member calls, qualified syntax shape
     (os.path.<member>(...)). join rows share the api rows' sites; the
     check members (exists/isfile/isdir/...) are the TOCTOU-relevant stat
     probes (views/static.py fullpath.stat before open is pathlib-side;
     sessions exists at file.py:173, storage exists at :317, move.py
     _samefile samefile probe at :20-:26); the resolve members
     (abspath/realpath/normpath/...) include the request-path
     normalization pipeline. */
  exists(Call c, Attribute func, Attribute pathmod |
    func = c.getFunc().(Attribute) and
    osPathMemberKind(func.getName(), flowKind) and
    osPathCallFunc(func, pathmod) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 4: the posixpath family: posixpath.<member>(...) - the
     request-path normalizer of the static servers
     (posixpath.normpath(path).lstrip('/') at views/static.py:35 and
     contrib/staticfiles/views.py:32) and templates.py:296 splitext. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getObject().(Name).getId() = "posixpath" and
    posixpathMemberKind(func.getName(), flowKind) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "posixpath" and
    moduleHint = "posixpath" and
    matchKind = "ast"
  )
  or
  /* family 5: the alias-import form of the os.path family in
     core/management/templates.py: `from os import path` at :9, used as
     path.join/expanduser/normpath/isdir/exists/abspath/isfile. The path
     prefix is the Name `path`, not the os.path attribute chain. Sites:
     :68 (top_dir join onto cwd + the CLI `name`), :76 (abspath of the CLI
     target), :123/:142 (exists), :135 (join with CLI-derived name), :175
     (isfile), :191-:193 (expanduser/normpath/isdir of the --template
     value), :199 (abspath), :259/:285 (tempdir joins). */
  exists(Call c, Attribute func, Name base |
    func = c.getFunc().(Attribute) and
    osPathAliasCallFunc(func, base) and
    osPathMemberKind(func.getName(), flowKind) and
    normalizedPathOf(c).matches("%/django/core/management/templates.py") and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 6: the alias-import form of the os.path family in
     utils/_os.py: `from os.path import abspath, dirname, join, normcase,
     sep` at :3, used as bare names inside safe_join (:32-:33) and the
     containment check (:41-:43). */
  exists(Call c |
    c.getFunc().(Name).getId() in ["join", "abspath", "normcase", "dirname"] and
    normalizedPathOf(c).matches("%/django/utils/_os.py") and
    node = c and
    (
      c.getFunc().(Name).getId() = "join" and flowKind = "path_join"
      or
      c.getFunc().(Name).getId() != "join" and flowKind = "path_resolve"
    ) and
    callableName = c.getFunc().(Name).getId() and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 7: the pathlib constructors, qualified form
     (pathlib.<member>(...)): pathlib.PurePath(dir_name) at core/files/
     storage.py:71 and :106 (the '..' parts traversal check on the upload
     dirname), pathlib.PurePosixPath(name) at core/files/utils.py:16.
     Pure constructors - no fs access, recorded as path construction
     nodes. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getObject().(Name).getId() = "pathlib" and
    func.getName() in ["Path", "PurePath", "PurePosixPath"] and
    node = c and
    flowKind = "path_construct" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "pathlib" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 8: the pathlib Path constructor, bare-name form: Path(...)
     calls. Key sites: views/static.py:36 (Path(safe_join(document_root,
     path)) - the dev static server's request-path resolution),
     contrib/admindocs/views.py:332 (Path(safe_join(directory, template))),
     core/mail/message.py:351 (attach_file's Path(path)), plus the
     config-path uses in utils/autoreload.py, views/debug.py,
     core/files/storage.py-adjacent modules, template/utils.py,
     core/validators.py, db/utils.py, forms/renderers.py, conf/__init__.py,
     contrib/auth/password_validation.py, contrib/gis/geoip2/base.py. */
  exists(Call c |
    c.getFunc().(Name).getId() = "Path" and
    node = c and
    flowKind = "path_construct" and
    callableName = "Path" and
    argIndex = 0 and
    receiver = "Path" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 9: the pathlib method family: <path>.<member>(...) attribute
     calls where the PATH IS THE RECEIVER (argIndex -1). Key sites:
     views/static.py:50 fullpath.open('rb') - THE static file download
     open, fed by Path(safe_join(document_root, path)); views/static.py:95
     fullpath.iterdir() (directory index); contrib/admindocs/views.py:334
     template_file.open(); core/mail/message.py:352 path.open('rb');
     core/files/base.py and db/models/fields/files.py self.file.open(...)
     (the File reopen path); the storage-wrapper overlaps (self.storage.
     open) also match here and yield a second row via family 13. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    pathMethodKind(func.getName(), flowKind) and
    node = c and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = "pathlib.Path" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 10: the pathlib existence/stat probes on the request-path-driven
     Path objects, restricted to the two request-path sites (a package-wide
     attribute-name match would collide with QuerySet.exists() etc.):
     views/static.py:37 fullpath.is_dir(), :41 fullpath.exists(), :44
     fullpath.stat() (the TOCTOU-shaped stat-probe-then-open of serve),
     contrib/admindocs/views.py:333 template_file.exists(). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["is_dir", "is_file", "exists", "stat"] and
    (
      normalizedPathOf(c).matches("%/django/views/static.py")
      or
      normalizedPathOf(c).matches("%/django/contrib/admindocs/views.py")
    ) and
    node = c and
    flowKind = "path_check" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = "pathlib.Path" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 11: the base-directory containment sanitizer: safe_join(base,
     *paths) bare-name calls (utils/_os.py:24-:47: abspath(join(base,
     *paths)) + normcase prefix containment raising SuspiciousFileOperation).
     Sites: views/static.py:36 (static serve), core/files/storage.py:330
     (FileSystemStorage.path), template/loaders/filesystem.py:36,
     template/backends/base.py:77, contrib/staticfiles/finders.py:121,
     contrib/admindocs/views.py:332. Argument 1 is the joined path
     component (argument 0 is the base directory). */
  exists(Call c |
    c.getFunc().(Name).getId() = "safe_join" and
    node = c and
    flowKind = "path_sanitize" and
    callableName = "safe_join" and
    argIndex = 1 and
    receiver = "" and
    moduleHint = "django.utils._os" and
    matchKind = "ast"
  )
  or
  /* family 12a: the CLI archive extraction entry: archive.extract(
     filename, tempdir) at core/management/templates.py:313 (Attribute
     extract on the module alias `from django.utils import archive`) - the
     --template tar/zip is unpacked into a temp dir; the member-name
     containment is checked inside by target_filename. Argument 1 is the
     destination. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "extract" and
    func.getObject().(Name).getId() = "archive" and
    normalizedPathOf(c).matches("%/django/core/management/templates.py") and
    node = c and
    flowKind = "archive_extract" and
    callableName = "extract" and
    argIndex = 1 and
    receiver = "archive" and
    moduleHint = "django.utils.archive" and
    matchKind = "ast"
  )
  or
  /* family 12b: the module-level archive helper: archive.extract(to_path)
     at utils/archive.py:51 (Attribute extract on the LOCAL variable
     `archive` shadowing the module name - bound by the
     Archive(path) context manager). Argument 0 is the destination. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "extract" and
    func.getObject().(Name).getId() = "archive" and
    normalizedPathOf(c).matches("%/django/utils/archive.py") and
    node = c and
    flowKind = "archive_extract" and
    callableName = "extract" and
    argIndex = 0 and
    receiver = "archive" and
    moduleHint = "django.utils.archive" and
    matchKind = "ast"
  )
  or
  /* family 12c: the Archive.extract method: self._archive.extract(to_path)
     at utils/archive.py:89 - the per-format extraction entry (Tar/Zip).
     Argument 0 is the destination. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "extract" and
    func.getObject().(Attribute).getName() = "_archive" and
    normalizedPathOf(c).matches("%/django/utils/archive.py") and
    node = c and
    flowKind = "archive_extract" and
    callableName = "extract" and
    argIndex = 0 and
    receiver = "self._archive" and
    moduleHint = "django.utils.archive" and
    matchKind = "ast"
  )
  or
  /* family 12d: the Archive wrapper: Archive(path) bare-name calls at
     utils/archive.py:50 - dispatches to TarArchive(tarfile.open) or
     ZipArchive(zipfile.ZipFile). Argument 0 is the archive path. */
  exists(Call c |
    c.getFunc().(Name).getId() = "Archive" and
    normalizedPathOf(c).matches("%/django/utils/archive.py") and
    node = c and
    flowKind = "archive_open" and
    callableName = "Archive" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "django.utils.archive" and
    matchKind = "ast"
  )
  or
  /* family 12e: the zip reader: zipfile.ZipFile(file) at utils/archive.py:
     197 (also core/management/commands/loaddata.py:339/:347 for fixture
     zips). Argument 0 is the archive path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "ZipFile" and
    func.getObject().(Name).getId() = "zipfile" and
    node = c and
    flowKind = "fs_open" and
    callableName = "ZipFile" and
    argIndex = 0 and
    receiver = "zipfile" and
    moduleHint = "zipfile" and
    matchKind = "ast"
  )
  or
  /* family 12f: the archive member reader: self._archive.extractfile(
     member) at utils/archive.py:173 - reads the tar member stream.
     Argument 0 is the member. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "extractfile" and
    func.getObject().(Attribute).getName() = "_archive" and
    normalizedPathOf(c).matches("%/django/utils/archive.py") and
    node = c and
    flowKind = "archive_read" and
    callableName = "extractfile" and
    argIndex = 0 and
    receiver = "self._archive" and
    moduleHint = "django.utils.archive" and
    matchKind = "ast"
  )
  or
  /* family 12g: the archive member containment check:
     self.target_filename(to_path, name) at utils/archive.py:167/:212 -
     abspath(join(to_path, name)) must startswith abspath(to_path), else
     SuspiciousOperation (utils/archive.py:138-:143). Argument 1 is the
     archive member name. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "target_filename" and
    normalizedPathOf(c).matches("%/django/utils/archive.py") and
    node = c and
    flowKind = "path_check" and
    callableName = "target_filename" and
    argIndex = 1 and
    receiver = "self" and
    moduleHint = "django.utils.archive" and
    matchKind = "ast"
  )
  or
  /* family 13a: the HTTP file-serving boundary: FileResponse(...) calls -
     views/static.py:50 FileResponse(fullpath.open('rb'), ...) streams the
     opened file (FileResponse itself reads via filelike.read and stats
     filelike.name, http/response.py:390-:427). Argument 0 is the opened
     file object. */
  exists(Call c |
    c.getFunc().(Name).getId() = "FileResponse" and
    node = c and
    flowKind = "file_serve" and
    callableName = "FileResponse" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "django.http" and
    matchKind = "ast"
  )
  or
  /* family 13b: the staticfiles serve delegation: static.serve(request,
     path, document_root=...) at contrib/staticfiles/views.py:39 (Attribute
     serve on the module alias `from django.views import static`) - the
     request path (already normpath'd and finders.find-resolved) is re-fed
     into the dev static server. Argument 1 is the path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "serve" and
    func.getObject().(Name).getId() = "static" and
    normalizedPathOf(c).matches("%/django/contrib/staticfiles/views.py") and
    node = c and
    flowKind = "file_serve" and
    callableName = "serve" and
    argIndex = 1 and
    receiver = "static" and
    moduleHint = "django.views.static" and
    matchKind = "ast"
  )
  or
  /* family 13c: the staticfiles resolution: finders.find(normalized_path)
     (Attribute find on the module alias `from django.contrib.staticfiles
     import finders`) - resolves the request path through the storages
     (safe_join inside FileSystemStorage.path / finders.find_location).
     Sites: contrib/staticfiles/views.py:33, collectstatic.py. Argument 0
     is the request path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "find" and
    func.getObject().(Name).getId() = "finders" and
    node = c and
    flowKind = "path_check" and
    callableName = "find" and
    argIndex = 0 and
    receiver = "finders" and
    moduleHint = "django.contrib.staticfiles.finders" and
    matchKind = "ast"
  )
  or
  /* family 14: the first-party storage API consumed with a controlled name:
     self.storage.<member>(name, ...) attribute calls for the name-carrying
     members (open, save, delete, exists, path, listdir, size). Sites:
     db/models/fields/files.py:44 (self.storage.open(self.name, 'rb') -
     the FieldFile read), :58 (self.storage.path(self.name)), :75
     (self.storage.open(self.name, mode)), :88 (self.storage.save(name,
     content...) - the upload commit whose name came through
     generate_filename), :106 (self.storage.delete(self.name));
     contrib/staticfiles/finders.py:223/:229/:230 (self.storage.path('')/
     exists(path)/path(path) - the request-path-driven staticfiles
     resolution). Argument 0 is the storage-relative name. */
  exists(Call c, Attribute func, Attribute stor |
    func = c.getFunc().(Attribute) and
    func.getName() in ["open", "save", "delete", "exists", "path", "listdir", "size"] and
    stor = func.getObject().(Attribute) and
    stor.getName() = "storage" and
    stor.getObject().(Name).getId() = "self" and
    node = c and
    flowKind = "fs_storage_wrapper" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "self.storage" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 15: the atomic move wrapper: file_move_safe(old_file_name,
     new_file_name, ...) bare-name calls (core/files/move.py:30-:81:
     os.rename with open+os.open fallback, allow_overwrite-controlled
     O_EXCL). Sites: core/files/storage.py:268 (the upload save move onto
     full_path), core/cache/backends/filebased.py:55 (the cache file move).
     Argument 1 is the destination. */
  exists(Call c |
    c.getFunc().(Name).getId() = "file_move_safe" and
    node = c and
    flowKind = "fs_move_wrapper" and
    callableName = "file_move_safe" and
    argIndex = 1 and
    receiver = "" and
    moduleHint = "django.core.files.move" and
    matchKind = "ast"
  )
  or
  /* family 16a: the upload filename sanitizer: self.sanitize_file_name(
     file_name) at http/multipartparser.py:208 (Attribute call on self) -
     html.unescape + basename rsplit on '/' and '\\'; the result is still
     documented as untrusted. Argument 0 is the raw filename. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "sanitize_file_name" and
    func.getObject().(Name).getId() = "self" and
    normalizedPathOf(c).matches("%/django/http/multipartparser.py") and
    node = c and
    flowKind = "path_sanitize" and
    callableName = "sanitize_file_name" and
    argIndex = 0 and
    receiver = "self" and
    moduleHint = "django.http.multipartparser" and
    matchKind = "ast"
  )
  or
  /* family 16b: the filename validators, bare-name calls:
     validate_file_name(name, allow_relative_path) (core/files/utils.py:
     7-:24 - rejects '', '.', '..' and path elements; sites
     core/files/storage.py:73, core/files/uploadedfile.py:51,
     db/models/fields/files.py:308) and get_valid_filename(name)
     (django.utils.text, site core/files/storage.py:63). Argument 0 is the
     name being validated. */
  exists(Call c |
    c.getFunc().(Name).getId() in ["validate_file_name", "get_valid_filename"] and
    node = c and
    flowKind = "path_sanitize" and
    callableName = c.getFunc().(Name).getId() and
    argIndex = 0 and
    receiver = "" and
    (
      c.getFunc().(Name).getId() = "validate_file_name" and
      moduleHint = "django.core.files.utils"
      or
      c.getFunc().(Name).getId() = "get_valid_filename" and
      moduleHint = "django.utils.text"
    ) and
    matchKind = "ast"
  )
  or
  /* family 17: internal functions that directly perform a filesystem
     operation (or reach one through a first-party wrapper call such as
     .open()/file_move_safe/archive.extract): expected members include
     django.views.static.serve (:19 - the full serve pipeline ending in
     fullpath.open('rb')), FileSystemStorage _open/_save/delete/exists/
     listdir/size/get_accessed_time/get_created_time/get_modified_time,
     Storage.save/get_available_name (os.path.exists probe at :80),
     SessionStore load/save/exists/delete/_last_modification, FileBasedCache
     get/set/touch/delete/has_key/_delete/_cull/_createdir, EmailBackend.
     open, FileSystemLoader.get_contents, File.open (core/files/base.py),
     TemporaryUploadedFile.__init__/close, file_move_safe, the archive
     family (utils/archive.py extract/Archive.__init__/TarArchive.extract/
     ZipArchive.extract/_copy_permissions), views/static.py
     directory_index (fullpath.iterdir() at :95 is a path-method family
     call site), TemplateCommand handle/download/extract/make_writeable/
     handle_template, the makemessages/compilemessages/loaddata/
     squashmigrations commands, collectstatic helpers, sqlite creation
     helpers. NOT included by design: pure string/validation helpers whose
     body only calls os.path.join/safe_join/validate_file_name (for
     example Storage.get_available_name's self.exists(name) call is an
     unbound first-party wrapper call, not a direct fs operation).
     Module-level code has no enclosing Function and yields no row. */
  exists(Function f |
    exists(Call c |
      fileOpCallSite(c) and
      c.getScope().(Function) = f
    ) and
    node = f and
    flowKind = "internal_file_wrapper" and
    callableName = f.getName() and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    receiver = f.getName()
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  djangoSourcePath(normalizedPathOf(node))
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
