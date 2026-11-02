/**
 * @name pyload CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the pyload
 *   CodeQL database (snapshot 14a9f11, pyLoad 0.5.0b3 / pyload-ng): builtin
 *   open(...) (the RPC container writes core/api/__init__.py:535-540
 *   "tmp_"+container and :951-956 "tmp_"+filename - the second join
 *   component is UNSANITIZED; the log read :346; the CNL dlc write
 *   cnl_blueprint.py:97 with separators stripped; the download chunk
 *   writes core/network/http/http_chunk.py:183/:208 and chunk-merge reads
 *   http_download.py:90/:96; the password file read/create
 *   plugins/addons/ExtractArchive.py:585/:591/:609; the container/captcha/
 *   torrent/ccf writes plugins/base/container.py:69, captcha.py:86,
 *   plugins/containers/{TORRENT,CCF,DLC,RSDF,TXT}.py; the plugin-update
 *   write UpdateManager.py:377; config/account/db/log/plugin-manager
 *   reads+writes under core/); io.open in core/utils/fs.py:158/:167/:200/
 *   :206/:207/:230; the file-response channel flask.send_from_directory
 *   (directory, path) webui/app/blueprints/app_blueprint.py:165 - argument
 *   1 is the /files/get/<path:path> route variable after unquote(path)
 *   .replace('..','') :163, base directory = configured storage_folder;
 *   the multipart upload write file.save(file_path) json_blueprint.py:157
 *   on join(storage_folder, "tmp_" + file.filename) :154-156; the template
 *   render channel (render_template(filename) app_blueprint.py:36 and
 *   flask_themes2.render_theme_template helpers.py:86); archive extraction
 *   (z.extractall(self.dest, members=z.namelist()-filtered) UnZip.py:90 -
 *   NO pyload-side entry-name check; tar.extractall UnTar.py:23 and
 *   _safe_extractall(t, self.dest) UnTar.py:78 behind the CVE-2007-4559
 *   commonprefix guard UnTar.py:11-21; the 7z/UnRAR extractor subprocess
 *   Popen SevenZip.py:261 / UnRar.py:289 writing at the Python-supplied
 *   dest); directory creation (os.makedirs argument 0 - the package-
 *   folder-derived destination plugins/base/downloader.py:322 and
 *   extraction destination plugins/addons/ExtractArchive.py:255); the
 *   deletion/move/copy/chmod families (os.remove, os.rmdir,
 *   send2trash.send2trash, shutil.rmtree/move/copy-family; os.chmod; the
 *   BasePlugin.remove/self.remove and self.set_permissions wrappers);
 *   the os.path.* propagation/validation family (join, normpath, realpath,
 *   abspath, relpath, dirname, basename, split, splitext, splitdrive,
 *   commonprefix - the UnTar containment guard -, isdir/isfile/isabs/
 *   exists/getmtime/getsize); os.stat/statvfs/access, os.listdir, os.walk,
 *   os.chdir; the fs.free_space/fs.remove wrapper calls; and definition
 *   rows for pyload's own path-taking APIs (BasePlugin.remove/
 *   set_permissions/upload, BaseExtractor.__init__ out, Api.add_package/
 *   upload_container/check_online_status_container/set_package_data/
 *   set_package_name/set_config_value, FileManager.add_package folder,
 *   Core.__init__ userdir/tempdir/storagedir, the fs.* wrappers, the
 *   plugins/helpers.py exists/compute_checksum/copy_tree/move_tree, and
 *   the path propagation/sanitization wrappers safejoin/safepath/
 *   safename/purge.name/fs.fullpath) with the true path parameter
 *   positions. Raw BQRS extraction query: run with `codeql query run` and
 *   decode with `codeql bqrs decode` (not database analyze). This is a
 *   plain multi-column select query on purpose: @kind problem is the
 *   wrong shape for candidate tables and @kind table is not assumed to
 *   exist.
 * @id iris/pyload/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member/field name ("open" / "send_from_
 *                   directory" / "save" / "render_template" /
 *                   "render_theme_template" / "extractall" /
 *                   "_safe_extractall" / "Popen" / "makedirs" / "remove" /
 *                   "rmdir" / "send2trash" / "rmtree" / "move" / "rename" /
 *                   "copy"/"copy2"/"copyfile"/"copytree" / "chmod" /
 *                   "chdir" / "stat"/"statvfs"/"access" / "listdir" /
 *                   "walk" / the os.path member name / "free_space" /
 *                   "set_permissions" / the function name for file_api_def
 *                   and path_api_def definition rows)
 *   4. flow_kind  - "file_open" (builtin open, argument 0; read/append/
 *                   write mode noted in the site context above),
 *                   "io_open" (io.open in fs.py, argument 0),
 *                   "file_response" (flask.send_from_directory, argument
 *                   1 = the request-controlled relative path),
 *                   "file_save" (werkzeug FileStorage.save, argument 0 =
 *                   the upload destination), "template_render"
 *                   (render_template argument 0 / render_theme_template
 *                   argument 1 - template file lookup), "archive_extract"
 *                   (zipfile/tarfile extractall argument 0; the UnTar
 *                   wrapper _safe_extractall argument 1), "process_file_
 *                   write" (extractor subprocess.Popen argument 0 = the
 *                   command list carrying the archive path and the
 *                   extraction destination), "dir_create" (os.makedirs/
 *                   os.mkdir, argument 0), "file_delete" (os.remove /
 *                   send2trash / self.remove / fs.remove, argument 0),
 *                   "dir_delete" (os.rmdir / shutil.rmtree, argument 0),
 *                   "file_move" (shutil.move / os.rename, argument 0 =
 *                   source), "file_copy" (shutil.copy/copy2/copyfile/
 *                   copytree, argument 0 = source), "file_chmod"
 *                   (os.chmod / self.set_permissions, argument 0),
 *                   "chdir" (os.chdir, argument 0 - CWD scoping),
 *                   "path_stat" (os.stat/statvfs/access and the os.path
 *                   guard reads isdir/isfile/isabs/exists/getmtime/
 *                   getsize, plus fs.free_space, argument 0), "dir_list"
 *                   (os.listdir, argument 0), "dir_walk" (os.walk,
 *                   argument 0), "path_join" (os.path.join, argument 0),
 *                   "path_canon" (os.path.normpath/realpath/abspath,
 *                   argument 0 - normalization, NOT containment here),
 *                   "path_rel" (os.path.relpath, argument 0), "path_part"
 *                   (os.path.dirname/basename/split/splitext/splitdrive,
 *                   argument 0), "path_containment_check" (os.path.
 *                   commonprefix, argument 0 - the UnTar CVE-2007-4559
 *                   guard shape), "file_api_def" (definition row of a
 *                   pyload-internal path-taking API, carrying the path
 *                   parameter position), "path_api_def" (definition row
 *                   of an internal path propagation/sanitization wrapper:
 *                   safejoin/safepath/safename/purge.name/fs.fullpath)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "flask"/"file"/"flask_themes2"/"os"/
 *                   "shutil"/"send2trash"/"subprocess"/"io"/"fs"/"self"/
 *                   "z"/"t" etc., or "" if none; enclosing class name for
 *                   definition rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "builtins"/"io"/"flask"/"werkzeug.datastructures"
 *                   /"flask_themes2"/"zipfile"/"tarfile"/"subprocess"/"os"
 *                   /"os.path"/"shutil"/"send2trash" for the stdlib/
 *                   external channels
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for open/io.open/remove/rmdir/mkdir-
 *                   family/chmod/chdir/stat-family/listdir/walk/join/
 *                   realpath-family/dirname-family/relative-family/
 *                   extractall/save/copy-family; argument 0 = source for
 *                   rmtree/move/rename; argument 1 for send_from_
 *                   directory (the relative path; argument 0 is the base
 *                   directory) and render_theme_template (the template
 *                   name) and the UnTar wrapper _safe_extractall (the
 *                   destination; argument 0 is the tar object); the
 *                   parameter position for file_api_def/path_api_def rows
 *                   including the self/cls slot; -1 for safejoin
 *                   (variadic *args))
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): the sink core is the FILE
 * PATH PARAMETER of actual filesystem operations (open, the werkzeug/flask
 * file-serving calls, extractall, makedirs, the deletion/move/copy/chmod
 * families, the extractor subprocess destinations) plus the os.path
 * pipeline nodes that directly determine the accessed path (join/normpath/
 * realpath/relpath/dirname-family and the isdir/isfile-family guard reads
 * including commonprefix) - NOT every path string construction node:
 * string concatenation and f-string path building (e.g. the "tmp_" +
 * filename expressions feeding os.path.join, f"{filename}.chunk{i}"
 * http_chunk.py:95, "tmp_{}.dlc".format(pyfile.name) CCF.py:52,
 * "tmp_{}.torrent".format(pack_name) TORRENT.py:71-73) are indistinguishable
 * from ordinary string building at AST level and are anchored by their
 * consuming sink rows instead (documented in detection.json uncoveredCases).
 * The non-extractor subprocess calls (ExternalScripts, AntiVirus,
 * AntiStandby, plugins/helpers check_prog/renice) are Pass 2 material and
 * are NOT emitted as path sinks; only the 7z/UnRAR extractor Popen calls
 * (whose processes write the extracted tree at the Python-supplied dest)
 * are emitted as process_file_write.
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project NO sink row is expected to resolve at API level:
 * all channels are either builtin/stdlib module members matched on the
 * syntactic qualifier (os/shutil/os.path/io/subprocess/zipfile/tarfile -
 * the stdlib is not part of the database), external-library members on the
 * unresolved names flask/file/flask_themes2/send2trash, instance members on
 * local variables (z/t extractall, self.remove/self.set_permissions, fs.*),
 * or calls of pyload-internal/local names (render_template,
 * _safe_extractall). The match_kind column is kept "ast" for all families
 * for cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (unit test tree) and
 * /pyload-db/ (the CodeQL database directory nested inside the source
 * tree). setup.py at the repo root is kept in scope (build script - rows,
 * if any, expected to be labeled none/FP). Ground-truth-looking artifacts
 * at the repo root were never opened (experiment independence).
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

/** Base name of the object expression of an attribute access, used as a receiver hint. */
string receiverHint(Attribute a) {
  result = a.getObject().(Name).getId()
  or
  result = a.getObject().(Attribute).getName()
  or
  not a.getObject() instanceof Name and
  not a.getObject() instanceof Attribute and
  result = "<expr>"
}

/** True iff the candidate's file path is one of the excluded trees. Path is
 *  normalized to forward slashes before matching so the query works on both
 *  CodeQL path styles. bindingset[path] declares that the caller passes a
 *  bound path (the path only appears in checked positions such as the
 *  receiver of replaceAll/matches inside this predicate). */
bindingset[path]
predicate excludedPath(string path) {
  path.replaceAll("\\", "/").matches("%/tests/%")
  or
  path.replaceAll("\\", "/").matches("%/pyload-db/%")
}

/* ------------------------------------------------------------------ */
/* Shared pyload shapes (kept consistent with sources.ql)               */
/* ------------------------------------------------------------------ */

/** os.path.<member> members performing path propagation/validation/guard
 *  reads, mapped to their flow kind. The equality body binds both
 *  parameters (same no-annotation style as the proven mapping predicates
 *  in the earlier Path_Traversal projects: call sites pass the member
 *  name via func.getName() and leave the flow kind to be bound here). */
private predicate osPathFlowKind(string member, string kind) {
  (member = "join" and kind = "path_join")
  or
  (member = "normpath" and kind = "path_canon")
  or
  (member = "realpath" and kind = "path_canon")
  or
  (member = "abspath" and kind = "path_canon")
  or
  (member = "relpath" and kind = "path_rel")
  or
  (member = "dirname" and kind = "path_part")
  or
  (member = "basename" and kind = "path_part")
  or
  (member = "split" and kind = "path_part")
  or
  (member = "splitext" and kind = "path_part")
  or
  (member = "splitdrive" and kind = "path_part")
  or
  (member = "commonprefix" and kind = "path_containment_check")
  or
  (member = "isdir" and kind = "path_stat")
  or
  (member = "isfile" and kind = "path_stat")
  or
  (member = "isabs" and kind = "path_stat")
  or
  (member = "exists" and kind = "path_stat")
  or
  (member = "getmtime" and kind = "path_stat")
  or
  (member = "getsize" and kind = "path_stat")
}

/** os.<member> members (module-level attribute of the name `os`), mapped to
 *  their flow kind. Same equality-body binding as osPathFlowKind. */
private predicate osModuleFlowKind(string member, string kind) {
  (member = "makedirs" and kind = "dir_create")
  or
  (member = "mkdir" and kind = "dir_create")
  or
  (member = "remove" and kind = "file_delete")
  or
  (member = "rmdir" and kind = "dir_delete")
  or
  (member = "rename" and kind = "file_move")
  or
  (member = "chmod" and kind = "file_chmod")
  or
  (member = "chdir" and kind = "chdir")
  or
  (member = "stat" and kind = "path_stat")
  or
  (member = "statvfs" and kind = "path_stat")
  or
  (member = "access" and kind = "path_stat")
  or
  (member = "listdir" and kind = "dir_list")
  or
  (member = "walk" and kind = "dir_walk")
}

/** shutil.<member> members, mapped to their flow kind. Same equality-body
 *  binding as osPathFlowKind. */
private predicate shutilFlowKind(string member, string kind) {
  (member = "rmtree" and kind = "dir_delete")
  or
  (member = "move" and kind = "file_move")
  or
  (member = "copy" and kind = "file_copy")
  or
  (member = "copy2" and kind = "file_copy")
  or
  (member = "copyfile" and kind = "file_copy")
  or
  (member = "copytree" and kind = "file_copy")
}

/** The pyload-internal path-taking API definitions with their path
 *  parameter (function, parameter) - definition rows for the file_api_def
 *  family. Parameter positions (0-based, including the self/cls slot) are
 *  documented per shape in the row-assembly family. */
private predicate fileApiDefShape(Function f, Parameter p) {
  /* BasePlugin.remove(path, try_trash=True) - plugins/base/plugin.py:112
     (self 0, path 1) - the deletion wrapper called as self.remove(...) at
     downloader.py:263/:323/:338/:394/:495 and container.py:51, delegating
     to fs.remove -> send2trash/shutil.rmtree/os.remove */
  f.getName() = "remove" and
  normalizedPathOf(f).matches("%/plugins/base/plugin.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* BasePlugin.set_permissions(path) - plugins/base/plugin.py:126 (self 0,
     path 1) - the chmod wrapper applied to dl_dirname/dl_filename/extracted
     files */
  f.getName() = "set_permissions" and
  normalizedPathOf(f).matches("%/plugins/base/plugin.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* BasePlugin.upload(path, url, ...) - plugins/base/plugin.py:263 (self 0,
     path 1) - open(os.fsencode(path), 'rb') :297 reads the local file to
     upload */
  f.getName() = "upload" and
  normalizedPathOf(f).matches("%/plugins/base/plugin.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* BaseExtractor.__init__(pyfile, filename, out, fullpath, overwrite,
     excludefiles, priority, keepbroken) - plugins/base/extractor.py:119
     (self 0, pyfile 1, filename 2, out 3) - `out` is THE extraction
     destination (self.dest) that UnZip/UnTar/SevenZip/UnRar/HjSplit
     extract into; the archive source path is `filename` (also a path
     param, both are emitted) */
  f.getName() = "__init__" and
  normalizedPathOf(f).matches("%/plugins/base/extractor.py") and
  (p.getName() = "filename" or p.getName() = "out") and
  p = f.getAnArg()
  or
  /* Api.add_package(name, links, dest) - core/api/__init__.py:418 (self 0,
     name 1) - the package name whose sanitized form becomes the download
     folder (FileManager.add_package folder, PyPackage._folder) */
  f.getName() = "add_package" and
  normalizedPathOf(f).matches("%/core/api/__init__.py") and
  p.getName() = "name" and
  p = f.getAnArg()
  or
  /* Api.upload_container(filename, data) - core/api/__init__.py:944 (self
     0, filename 1) - open(join(storage_folder, 'tmp_' + filename), 'wb') */
  f.getName() = "upload_container" and
  normalizedPathOf(f).matches("%/core/api/__init__.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* Api.check_online_status_container(urls, container, data) -
     core/api/__init__.py:526 (self 0, container 2) -
     open(join(storage_folder, 'tmp_' + container), 'wb') */
  f.getName() = "check_online_status_container" and
  normalizedPathOf(f).matches("%/core/api/__init__.py") and
  p.getName() = "container" and
  p = f.getAnArg()
  or
  /* Api.set_package_data(package_id, data) - core/api/__init__.py:985
     (self 0, data 2) - the dict setattr'd onto the package (incl. the
     '_folder' key written by json edit_package) */
  f.getName() = "set_package_data" and
  normalizedPathOf(f).matches("%/core/api/__init__.py") and
  p.getName() = "data" and
  p = f.getAnArg()
  or
  /* Api.set_package_name(package_id, name) - core/api/__init__.py:902
     (self 0, name 2) - package rename feeding the folder derivation */
  f.getName() = "set_package_name" and
  normalizedPathOf(f).matches("%/core/api/__init__.py") and
  p.getName() = "name" and
  p = f.getAnArg()
  or
  /* Api.set_config_value(category, option, value, section) -
     core/api/__init__.py:174 (self 0, value 3) - config values incl.
     storage_folder / ExtractArchive destination+passwordfile */
  f.getName() = "set_config_value" and
  normalizedPathOf(f).matches("%/core/api/__init__.py") and
  p.getName() = "value" and
  p = f.getAnArg()
  or
  /* FileManager.add_package(name, folder, queue) -
     core/managers/file_manager.py:144 (self 0, name 1, folder 2) - the
     folder persisted to the db and re-exposed as PyPackage.folder */
  f.getName() = "add_package" and
  normalizedPathOf(f).matches("%/core/managers/file_manager.py") and
  p.getName() = "folder" and
  p = f.getAnArg()
  or
  /* pyload.core.utils.fs free-space/stat wrappers - fs.py:30
     free_space(path) (position 0) - os.statvfs/GetDiskFreeSpaceExW */
  f.getName() = "free_space" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* fs.exists(path, strict) - fs.py:92 (position 0) - case-sensitive
     os.path.exists + os.listdir listing check */
  f.getName() = "exists" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* fs.filesize(filename) - fs.py:102 (position 0) - os.stat */
  f.getName() = "filesize" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* fs.copy(src, dst, ...) - fs.py:86 (src 0, dst 1) -
     _shdo(shutil.copytree/copy) */
  f.getName() = "copy" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  (p.getName() = "src" or p.getName() = "dst") and
  p = f.getAnArg()
  or
  /* fs.move(src, dst, ...) - fs.py:271 (src 0, dst 1) -
     _shdo(shutil.move) + _moverc walk */
  f.getName() = "move" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  (p.getName() = "src" or p.getName() = "dst") and
  p = f.getAnArg()
  or
  /* fs.remove(path, try_trash) - fs.py:329 (position 0) - the deletion
     pipeline: exists -> send2trash / shutil.rmtree / os.remove */
  f.getName() = "remove" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* fs.empty(path, ...) - fs.py:348 (position 0) - truncate: io.open(path,
     'wb'), os.rename backup, os.listdir children removal */
  f.getName() = "empty" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* fs.merge(dst_file, src_file) - fs.py:205 (dst 0, src 1) - io.open
     append/read chunk merge */
  f.getName() = "merge" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  (p.getName() = "dst_file" or p.getName() = "src_file") and
  p = f.getAnArg()
  or
  /* fs.mkfile(filename, size) - fs.py:227 (position 0) - io.open(filename,
     'wb') creation */
  f.getName() = "mkfile" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* fs.makedirs(dirname, ...) - fs.py:235 (position 0) - os.makedirs */
  f.getName() = "makedirs" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "dirname" and
  p = f.getAnArg()
  or
  /* fs.makefile(filepath, ...) - fs.py:244 (position 0) - makedirs +
     mkfile composition */
  f.getName() = "makefile" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "filepath" and
  p = f.getAnArg()
  or
  /* fs.checksum(filename, chkname, ...) - fs.py:173 (position 0) -
     io.open(filename, 'rb') hash read */
  f.getName() = "checksum" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* fs.mtime(path) - fs.py:281 (position 0) - os.path.getmtime over walk */
  f.getName() = "mtime" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* fs.cleanpy(dirname, ...) - fs.py:320 (position 0) - os.walk +
     os.remove of .pyc/.pyo/__pycache__ */
  f.getName() = "cleanpy" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "dirname" and
  p = f.getAnArg()
  or
  /* fs.which(filename) - fs.py:369 (position 0) - os.path/is_exec over
     PATH entries */
  f.getName() = "which" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* plugins/helpers.py module wrappers (imported as `from ..helpers
     import exists` by the extractors/container base): exists(path)
     :245 (position 0 - case-insensitive os.path.exists + os.listdir on
     NT) and compute_checksum(filename, hashtype) :559 (position 0 -
     open(file, 'rb') hash read) and copy_tree(src, dst) :590 /
     move_tree(src, dst) :623 (src 0, dst 1 - os.walk/makedirs/copy/
     move/remove trees) */
  (
    (f.getName() = "exists" and p.getName() = "path")
    or
    (f.getName() = "compute_checksum" and p.getName() = "filename")
    or
    ((f.getName() = "copy_tree" or f.getName() = "move_tree") and
     (p.getName() = "src" or p.getName() = "dst"))
  ) and
  normalizedPathOf(f).matches("%/plugins/helpers.py") and
  p = f.getAnArg()
  or
  /* render_template(template, **context) - webui/app/helpers.py:84
     (position 0) - the /render route's template name reaching
     flask_themes2.render_theme_template -> the jinja loader */
  f.getName() = "render_template" and
  normalizedPathOf(f).matches("%/webui/app/helpers.py") and
  p.getName() = "template" and
  p = f.getAnArg()
  or
  /* Core.__init__(userdir, tempdir, storagedir, ...) -
     src/pyload/core/__init__.py:80 (self 0, userdir 1, tempdir 2,
     storagedir 3) - the directory anchors: makedirs core/__init__.py:96/
     :119/:120/:141, chdir datadir :97; fed from the CLI --userdir/
     --tempdir/--storagedir flags (operator-trust) */
  f.getName() = "__init__" and
  normalizedPathOf(f).matches("%/core/__init__.py") and
  (p.getName() = "userdir" or p.getName() = "tempdir" or p.getName() = "storagedir") and
  p = f.getAnArg()
}

/** The pyload-internal path propagation/sanitization wrapper definitions
 *  (definition rows for the path_api_def family) - these are the nodes the
 *  labeling step will mark as sanitizer or taint-step. */
private predicate pathApiDefShape(Function f, Parameter p) {
  /* safepath(value) - core/utils/old/__init__.py:40 (position 0):
     splitdrive + per-component safename (separators REMOVED, '..'
     components survive the split/join on posix) - the PyPackage.folder
     property normalization datatypes/pypackage.py:26-28 */
  f.getName() = "safepath" and
  normalizedPathOf(f).matches("%/core/utils/old/__init__.py") and
  p.getName() = "value" and
  p = f.getAnArg()
  or
  /* safejoin(*args) - core/utils/old/__init__.py:59 (variadic - argIndex
     -1): safepath(os.path.join(*args)) - used for dl_dirname/
     dl_filename in plugins/base/downloader.py:319-320/:336 */
  f.getName() = "safejoin" and
  normalizedPathOf(f).matches("%/core/utils/old/__init__.py") and
  p.getName() = "args" and
  p = f.getAnArg()
  or
  /* safename(value) - core/utils/old/__init__.py:66 (position 0):
     purge.chars(value, '<>:"/\\|?*\\0') - separator strip (used by
     ExtractArchive subfolder fallback and the TORRENT pack name) */
  f.getName() = "safename" and
  normalizedPathOf(f).matches("%/core/utils/old/__init__.py") and
  p.getName() = "value" and
  p = f.getAnArg()
  or
  /* purge.name(text, sep, allow_whitespaces) - core/utils/purge.py:41
     (position 0): removes path separators and platform-bad chars - the
     PyFile.name setter pyfile.py:29-34 and the content-disposition
     sanitization http_chunk.py:349 */
  f.getName() = "name" and
  normalizedPathOf(f).matches("%/core/utils/purge.py") and
  p.getName() = "text" and
  p = f.getAnArg()
  or
  /* fs.fullpath(path) - core/utils/fs.py:124 (position 0):
     os.path.realpath(os.path.expanduser(path)) - canonicalization */
  f.getName() = "fullpath" and
  normalizedPathOf(f).matches("%/core/utils/fs.py") and
  p.getName() = "path" and
  p = f.getAnArg()
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: builtin open(...) - argument 0 carries the path. Key sites:
     the RPC container writes core/api/__init__.py:535-540 (check_online_
     status_container: open(join(storage_folder, 'tmp_' + container),
     'wb') - RPC-CONTROLLED second join component) and :951-956
     (upload_container: same shape with filename); the log read :346; the
     CNL dlc write cnl_blueprint.py:97 (package separators stripped at
     :93-94); the scan_download read plugins/base/downloader.py:358; the
     download chunk writes core/network/http/http_chunk.py:183 ('ab'
     resume) /:208 ('wb' new file) - THE real download write - and the
     chunk-info/merge reads :58/:69 and http_download.py:90/:96; the
     password-file read/create/write ExtractArchive.py:585/:591/:609; the
     container/captcha/torrent/ccf writes plugins/base/container.py:69
     (remote container 'tmp_' write), captcha.py:86, plugins/containers/
     CCF.py:62, TORRENT.py:51/:74, DLC.py:118, RSDF.py:58, TXT.py:44/:72;
     the plugin-update write UpdateManager.py:377; HotFolder.py:63/:68/
     :75; MergeFiles.py:42/:51; plugin.py:297 (upload read)/:406 (html
     dump); and the config/account/db/log/plugin-manager reads+writes
     under core/ (operator/config-level paths). */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* family 2: io.open(...) - argument 0 carries the path. Sites are the
     core/utils/fs.py wrapper internals: _crcsum :158 and _hashsum :167
     (hash reads, 'rb'), flush :200, merge :206 ('ab' dst) /:207 ('rb'
     src), mkfile :230 ('wb' creation). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "io" and
    node = c and
    flowKind = "io_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "io" and
    moduleHint = "io" and
    matchKind = "ast"
  )
  or
  /* family 3: the file-download response - flask.send_from_directory(
     directory, path, as_attachment=True) app_blueprint.py:165: argument
     0 is the configured storage_folder base, argument 1 is the
     /files/get/<path:path> route value after unquote(path).replace('..',
     '') at :163 (partial traversal strip; werkzeug's safe_join - external
     to this database - is the actual containment). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "send_from_directory" and
    func.getObject().(Name).getId() = "flask" and
    node = c and
    flowKind = "file_response" and
    callableName = "send_from_directory" and
    argIndex = 1 and
    receiver = "flask" and
    moduleHint = "flask" and
    matchKind = "ast"
  )
  or
  /* family 4: the multipart upload write - file.save(file_path)
     json_blueprint.py:157 with file_path = os.path.join(storage_folder,
     'tmp_' + file.filename) at :154-156 (filename from the uploaded
     FileStorage); argument 0 carries the destination path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "save" and
    func.getObject().(Name).getId() = "file" and
    normalizedPathOf(c).matches("%/webui/app/blueprints/json_blueprint.py") and
    node = c and
    flowKind = "file_save" and
    callableName = "save" and
    argIndex = 0 and
    receiver = "file" and
    moduleHint = "werkzeug.datastructures" and
    matchKind = "ast"
  )
  or
  /* family 5: the template render channel - (a) the local helper call
     render_template(filename) app_blueprint.py:36 (argument 0 is the
     /render/<path:filename> route variable; other call sites pass
     literal template names, rows expected to be labeled none) resolved
     to webui/app/helpers.py:84 -> flask_themes2.render_theme_template;
     (b) flask_themes2.render_theme_template(themeid, template, ...)
     helpers.py:86 itself (argument 1 carries the template name into the
     jinja theme loaders - external to this database). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "render_theme_template" and
    func.getObject().(Name).getId() = "flask_themes2" and
    node = c and
    flowKind = "template_render" and
    callableName = "render_theme_template" and
    argIndex = 1 and
    receiver = "flask_themes2" and
    moduleHint = "flask_themes2" and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "render_template" and
    node = c and
    flowKind = "template_render" and
    callableName = "render_template" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6: archive extraction - (a) z.extractall(self.dest, members)
     UnZip.py:90: argument 0 is the destination directory, the members
     list is z.namelist() filtered by excludefiles ONLY (:87-89 - NO
     pyload-side '..' check; stdlib zipfile sanitization is the only
     guard); tar.extractall(path) UnTar.py:23 inside _safe_extractall
     (behind the commonprefix CVE-2007-4559 guard :11-21); (b) the UnTar
     wrapper call _safe_extractall(t, self.dest) UnTar.py:78 (argument 1
     carries the destination; argument 0 is the tar object). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "extractall" and
    node = c and
    flowKind = "archive_extract" and
    callableName = "extractall" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    matchKind = "ast" and
    (
      (normalizedPathOf(c).matches("%/plugins/extractors/UnZip.py") and
       moduleHint = "zipfile")
      or
      (normalizedPathOf(c).matches("%/plugins/extractors/UnTar.py") and
       moduleHint = "tarfile")
    )
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "_safe_extractall" and
    normalizedPathOf(c).matches("%/plugins/extractors/UnTar.py") and
    node = c and
    flowKind = "archive_extract" and
    callableName = "_safe_extractall" and
    argIndex = 1 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 7: the extractor subprocess file writes - subprocess.Popen(
     call) plugins/extractors/SevenZip.py:261 and UnRar.py:289: the 7z/
     UnRAR binaries write the extracted tree at the Python-supplied
     destination carried inside the command list (argument 0); the HjSplit
     open(join(self.dest, name), 'wb') :88 channel is covered by family 1.
     Non-extractor subprocess uses are Pass 2 material, not emitted. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "Popen" and
    func.getObject().(Name).getId() = "subprocess" and
    normalizedPathOf(c).matches("%/plugins/extractors/%") and
    node = c and
    flowKind = "process_file_write" and
    callableName = "Popen" and
    argIndex = 0 and
    receiver = "subprocess" and
    moduleHint = "subprocess" and
    matchKind = "ast"
  )
  or
  /* family 8: os.<member>(...) module-level operations - makedirs/mkdir
     (dir_create; incl. downloader.py:322 on the package-folder-derived
     dl_dirname and ExtractArchive.py:255 on the extraction folder),
     remove (file_delete), rmdir (dir_delete), rename (file_move), chmod
     (file_chmod), chdir (core/__init__.py:97/:446 bootstrap-level),
     stat/statvfs/access (path_stat), listdir (dir_list), walk
     (dir_walk); argument 0 carries the path (source for rename). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getObject().(Name).getId() = "os" and
    osModuleFlowKind(func.getName(), flowKind) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 9: os.path.<member>(...) propagation/validation/guard reads -
     join (the dominant path builder: app_blueprint.py:141-146/:297/:300/
     :306/:308 for the files/pathchooser listing, core/api/__init__.py:
     536-537/:952-953 for the 'tmp_' container writes, cnl_blueprint.py:
     93 for the dlc write, json_blueprint.py:154 for the upload,
     downloader.py:262/:489/:515, ExtractArchive.py:239-252/:266, the
     core dir builders and the fs.py internals; argument 0 is the FIRST
     path component - later positional arguments also carry components),
     normpath (app_blueprint.py:257 - applied to the REQUEST path,
     propagation NOT containment), realpath/abspath (pathchooser :269/
     :276/:279/:285, api get_userdir/get_cachedir :1262-1266),
     relpath (pathchooser :272/:280/:282-283 - display form),
     dirname/basename/split/splitext/splitdrive (component extraction:
     extractor archivetype, downloader :262/:489, TORRENT/CCF containers,
     pathchooser :261/:277), commonprefix (UnTar.py:15 - THE
     CVE-2007-4559 containment guard), isdir/isfile/isabs/exists/
     getmtime/getsize (pathchooser :259-308 guard reads, fs/exists
     wrappers); argument 0 carries the path (the list for commonprefix). */
  exists(Call c, Attribute func, Attribute mid |
    func = c.getFunc().(Attribute) and
    mid = func.getObject().(Attribute) and
    mid.getName() = "path" and
    mid.getObject().(Name).getId() = "os" and
    osPathFlowKind(func.getName(), flowKind) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 10: shutil.<member>(...) operations - rmtree (dir_delete;
     fs.remove internals), move (file_move; HotFolder.py:105,
     AntiVirus.py:118/:127/:134 quarantine, database_thread.py:144,
     fs.py:257/:273 - argument 0 = source), copy/copy2/copyfile/copytree
     (file_copy; account_manager.py:87 backup, config/parser.py:68/:85
     default-config copy, fs.py:75-88); argument 0 = source path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getObject().(Name).getId() = "shutil" and
    shutilFlowKind(func.getName(), flowKind) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "shutil" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  /* family 11: send2trash.send2trash(path) - the trash deletion used by
     ExtractArchive.py:525 (archive chunks after extraction),
     AntiVirus.py:109 (infected downloads) and fs.remove :~288;
     argument 0 carries the path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "send2trash" and
    func.getObject().(Name).getId() = "send2trash" and
    node = c and
    flowKind = "file_delete" and
    callableName = "send2trash" and
    argIndex = 0 and
    receiver = "send2trash" and
    moduleHint = "send2trash" and
    matchKind = "ast"
  )
  or
  /* family 12: the fs.* wrapper calls (from pyload.core.utils import fs):
     fs.free_space(storage_folder) api/__init__.py:309,
     thread_manager.py:329, core/__init__.py:386 (path_stat) and
     fs.remove(path, try_trash=...) plugins/base/plugin.py:114 (the
     BasePlugin.remove delegation - file_delete); argument 0 carries the
     path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getObject().(Name).getId() = "fs" and
    (
      (func.getName() = "free_space" and flowKind = "path_stat")
      or
      (func.getName() = "remove" and flowKind = "file_delete")
    ) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "fs" and
    moduleHint = "pyload.core.utils.fs" and
    matchKind = "ast"
  )
  or
  /* family 13: the BasePlugin instance wrappers called as self.<member>
     (...) throughout the plugin tree - self.remove(path) (file_delete;
     downloader.py:263 bad_file/:323/:338 dl paths/:394/:495 last_
     download, container.py:51 the tmp_ container url) and
     self.set_permissions(path) (file_chmod; downloader.py:323/:338,
     ExtractArchive.py:258/:360/:363); argument 0 carries the path.
     Restricted to the plugin tree where the BasePlugin receiver is
     declared. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getObject().(Name).getId() = "self" and
    (
      (func.getName() = "remove" and flowKind = "file_delete")
      or
      (func.getName() = "set_permissions" and flowKind = "file_chmod")
    ) and
    normalizedPathOf(c).matches("%/src/pyload/plugins/%") and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "self" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 14: file_api_def definition rows - the pyload-internal
     path-taking API definitions with the true path parameter positions
     (0-based, including the self/cls slot): BasePlugin.remove(path)
     plugin.py:112 pos 1, BasePlugin.set_permissions(path) :126 pos 1,
     BasePlugin.upload(path) :263 pos 1, BaseExtractor.__init__
     filename/out extractor.py:119 pos 2/3, Api.add_package(name)
     core/api/__init__.py:418 pos 1, Api.upload_container(filename)
     :944 pos 1, Api.check_online_status_container(container) :526 pos
     2, Api.set_package_data(data) :985 pos 2, Api.set_package_name(name)
     :902 pos 2, Api.set_config_value(value) :174 pos 3,
     FileManager.add_package(folder) file_manager.py:144 pos 2, fs
     wrappers (free_space/exists/filesize/copy/move/remove/empty/merge/
     mkfile/makedirs/makefile/checksum/mtime/cleanpy/which - fs.py:30/
     :92/:102/:86/:271/:329/:348/:205/:227/:235/:244/:173/:281/:320/:369),
     plugins/helpers.py exists(:245)/compute_checksum(:559)/copy_tree
     (:590)/move_tree(:623), render_template(template)
     webui/app/helpers.py:84 pos 0, Core.__init__ userdir/tempdir/
     storagedir core/__init__.py:80 pos 1/2/3; these rows give the
     labeling step the summary/propagation backbone between the webui/RPC
     source fields and the concrete file operations. */
  exists(Function f, Parameter p |
    fileApiDefShape(f, p) and
    not p.isSelf() and
    node = p and
    flowKind = "file_api_def" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
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
  or
  /* family 15: path_api_def definition rows - the internal path
     propagation/sanitization wrapper definitions (0-based positions
     including the self slot): safepath(value) core/utils/old/__init__
     .py:40 pos 0 (the PyPackage.folder normalization - separators
     removed, '..' components survive the split/join on posix),
     safejoin(*args) :59 variadic (argIndex -1 - os.path.join +
     safepath, used for dl_dirname/dl_filename downloader.py:319-320/
     :336), safename(value) :66 pos 0 (separator strip - ExtractArchive
     subfolder fallback, TORRENT pack name), purge.name(text)
     core/utils/purge.py:41 pos 0 (the PyFile.name setter and the
     content-disposition sanitization), fs.fullpath(path)
     core/utils/fs.py:124 pos 0 (realpath+expanduser); these rows let
     the labeling step mark sanitizers / taint steps precisely. */
  exists(Function f, Parameter p |
    pathApiDefShape(f, p) and
    node = p and
    flowKind = "path_api_def" and
    callableName = f.getName() and
    (
      p.getName() = "args" and argIndex = -1
      or
      not p.getName() = "args" and argIndex = p.getPosition()
    ) and
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
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
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
