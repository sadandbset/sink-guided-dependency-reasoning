/**
 * @name ganga CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the ganga
 *   CodeQL database (Ganga 8.4.2, CERN workload management framework - the
 *   ganga/ package tree is the audit target): the GUI file-serve channel
 *   (send_file(abs_path) at GangaGUI/gui/routes.py:671 inside job_browse -
 *   abs_path = os.path.join(job_base_dir, path) :659 with the raw request
 *   path from the /job/<int:job_id>/browse/<path:path> route, NO
 *   containment guard - and :975 inside storage_page -
 *   abs_path = os.path.join(storage_folder, path) :934 from the
 *   /storage/<path:path> route; :578 the fixed UPLOAD_FOLDER/export.txt
 *   serve); the werkzeug upload write channel (storagefile.save(save_path)
 *   gui/routes.py:955 with save_path = os.path.join(abs_path,
 *   secure_filename(filename)) :954 - the DIRECTORY component carries the
 *   unsanitized route path; loadfile.save :302 / runfile.save :328 write
 *   fixed server paths); the GangaGUI os.path propagation and guard reads
 *   of the two browser flows (join :659/:934/:682/:986, dirname
 *   :651/:662/:966, exists :665/:969, isfile :670/:974, isdir :949);
 *   builtin open() (~430 sites; the HTTP-reachable ones:
 *   GangaCore/GPIDev/Persistency/__init__.py:85 open(filepath, mode) in
 *   stripped_export - the internal-API export WRITE target, filepath =
 *   fullpath(filename) = abspath(expandvars(expanduser(...))) :149 - and
 *   :190 in load - the internal-API load READ; gui/routes.py:375/:606/:273
 *   fixed-path content writes, :270/:275/:612/:905/:908/:911 fixed-path
 *   reads; GangaCore/Runtime/bootstrap.py:345 config read, :1097 CLI
 *   script read+exec); os.open (repository session locks,
 *   SessionLock.py:53/:430/:544/:577/:778/:811); directory
 *   creation/removal/rename/move/copy (os.makedirs/os.mkdir ~93,
 *   os.remove/unlink/rmdir ~64, os.rename 20, shutil.move 10,
 *   shutil.copy/copy2/copyfile/copytree 56, shutil.rmtree 34 - incl. the
 *   bare-name from-import forms in GangaLHCb GaudiExec.py and
 *   GangaRepositoryXML.py:968 copyfile); directory listings and walks
 *   (os.listdir ~75 incl. the two browser flows :676/:980, os.walk 6);
 *   globbing (glob.glob 28); symlink and permission changes (os.symlink 9,
 *   os.chmod 11); tarfile archive handling (tarfile.open /
 *   tarfile.TarFile.open 18 - job sandbox creation and unpacking; the
 *   .extractall destinations at GangaCore/Core/Sandbox/Sandbox.py:154 -
 *   output sandbox unpacked at job completion - WNSandbox.py:71 - input
 *   sandbox unpack at runtime - GangaLHCb GaudiExecMerger.py:226,
 *   GangaSAGA SAGAWrapperScript.py:87 bare extractall() to CWD,
 *   GangaSNOplus job_tools.py:310/:322; NO filter= argument at any site);
 *   the path-sanitization material (secure_filename
 *   gui/routes.py:953 - partial sanitizer of the uploaded FILENAME only);
 *   and definition rows for the tool's own path-taking APIs (export,
 *   stripped_export, fullpath, load, runfile, getScriptPath,
 *   expandfilename, fullpath, getPackedOutputSandbox,
 *   createPackedOutputSandbox, getPackedInputSandbox, createOutputSandbox,
 *   recursive_copy, FileWorkspace.getPath, allowed_file) with the true path
 *   parameter positions. Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not
 *   database analyze). This is a plain multi-column select query on
 *   purpose: @kind problem is the wrong shape for candidate tables and
 *   @kind table is not assumed to exist.
 * @id iris/ganga/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member/field name ("open" / "send_file" /
 *                   "save" / "makedirs" / "mkdir" / "remove" / "unlink" /
 *                   "rmdir" / "rename" / "move" / "copy" / "copy2" /
 *                   "copyfile" / "copytree" / "rmtree" / "listdir" /
 *                   "walk" / "symlink" / "chmod" / "glob" / "join" /
 *                   "exists" / "isfile" / "isdir" / "dirname" /
 *                   "basename" / "extractall" / "secure_filename" /
 *                   "TarFile" / the function name for file_api_def rows)
 *   4. flow_kind  - "file_open" (builtin open(...) - argument 0 carries
 *                   the path),
 *                   "file_open_lowlevel" (os.open(...) - argument 0),
 *                   "file_response" (send_file(argument 0) - the GUI file
 *                   serve; the actual open happens inside
 *                   flask/werkzeug, external to this database),
 *                   "file_save_member" (werkzeug FileStorage
 *                   .save(argument 0) - the upload write destination),
 *                   "dir_create" (os.makedirs/os.mkdir - argument 0),
 *                   "file_remove" (os.remove/os.unlink/os.rmdir -
 *                   argument 0),
 *                   "file_rename" (os.rename - argument 0; argument 1 is
 *                   the destination),
 *                   "file_move" (shutil.move - argument 0; argument 1 is
 *                   the destination),
 *                   "file_copy" (shutil.copy/copy2/copyfile/copytree -
 *                   argument 0; argument 1 is the destination),
 *                   "dir_remove" (shutil.rmtree - argument 0),
 *                   "dir_list" (os.listdir - argument 0),
 *                   "dir_walk" (os.walk - argument 0),
 *                   "symlink_create" (os.symlink - argument 0; argument 1
 *                   is the link path),
 *                   "file_perm" (os.chmod - argument 0),
 *                   "archive_open" (tarfile.open / tarfile.TarFile.open -
 *                   argument 0 carries the tarball path),
 *                   "archive_extract" (.extractall(argument 0) - the
 *                   extraction destination; arg_index -1 for the bare
 *                   extractall() that extracts to the CWD),
 *                   "path_glob" (glob.glob(argument 0) - directory
 *                   pattern discovery),
 *                   "path_join" (os.path.join(argument 0) - the
 *                   propagation join of the two browser flows, scoped to
 *                   GangaGUI),
 *                   "path_stat" (os.path.exists/isfile/isdir(argument 0)
 *                   - guard reads, scoped to GangaGUI),
 *                   "path_part" (os.path.dirname/basename(argument 0) -
 *                   component extraction, scoped to GangaGUI),
 *                   "path_sanitize" (secure_filename(argument 0) - guard
 *                   material: sanitizes the uploaded FILENAME only, never
 *                   the directory component),
 *                   "file_api_def" (definition row of a tool-internal
 *                   path-taking API, carrying the path parameter position)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "os"/"os.path"/"shutil"/"tarfile"/"glob"
 *                   etc., or "" if none; the local FileStorage name
 *                   (storagefile/loadfile/runfile) or the tar handle name
 *                   for member calls; "" for file_api_def rows of
 *                   module-level functions, the class name for methods)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "builtins"/"os"/"os.path"/"shutil"/"tarfile"/
 *                   "glob"/"werkzeug" for the stdlib/external channels
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for every positional family here; the
 *                   parameter position for file_api_def rows), -1 for the
 *                   bare extractall() (destination is the CWD)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): the sink core is the FILE
 * PATH PARAMETER of actual filesystem operations (open, os.open,
 * send_file, FileStorage.save, makedirs/mkdir, remove/unlink/rmdir,
 * rename/move/copy, listdir/walk/glob, symlink/chmod, tarfile
 * open/extractall) - NOT every path string construction node. The
 * os.path join/stat/part families are therefore scoped to GangaGUI, the
 * only module where they sit inside the untrusted request flows (the two
 * browser routes and their upload branch); across the rest of the tree
 * os.path.join (~800 sites) / dirname (~150) / basename (~250) /
 * exists (~80) are ubiquitous operator-level job-workspace plumbing,
 * anchored by their consuming open/copy/remove rows and by the file_api_def
 * rows (expandfilename, fullpath, getScriptPath, FileWorkspace.getPath) -
 * a MySummaries taint step must be added in Phase 2 if a core-tree
 * os.path.join flow needs tracing. The GangaGUI content-write sites
 * (gui/routes.py:375/:606/:273) write attacker-controlled request bodies
 * into FIXED server paths - recorded as adjacent content channels in
 * detection.json, anchored here by their open() rows.
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching out entirely
 * (all channels are builtin/stdlib module members matched on the syntactic
 * qualifier - the stdlib and flask/werkzeug are not part of this database -
 * or instance member calls on local names; the match_kind column is kept
 * "ast" for cross-project contract consistency with the prior projects of
 * this series). The builtin open() family matches only the Name form
 * (c.getFunc() is a Name "open"), so os.open, tarfile.open and any
 * X.open(...) member calls are never double-counted; the member-call
 * families (save/extractall) cannot collide with the qualified forms.
 * Bare-name os members (from os import listdir/rename/makedirs/unlink/
 * chmod, from shutil import copyfile, from glob import glob) are matched
 * through the per-module import allowlists below, mirroring the actual
 * import statements of those files.
 *
 * Excluded paths (applied to every row, in addition to the positive scope):
 * GangaTest/ (test-runner plugin package), /test/, /old_test/, /testlib/
 * (test fixtures/harnesses of every package), and the two stray test
 * modules GangaCore/Utility/Config/tests.py and
 * GangaCore/Utility/logging/test.py. The CodeQL database ganga-db sits in
 * the source ROOT as a sibling of the ganga/ package, so the positive
 * scope %/ganga/% excludes it by construction; a defensive filter is kept
 * in excludedPath anyway. Repo-root build/test tooling (setup.py,
 * conftest.py, postBuild, bin/) and doc/ are never candidates.
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
  path.replaceAll("\\", "/").matches("%/ganga-db/%")
  or
  path.replaceAll("\\", "/").matches("%/GangaTest/%")
  or
  path.replaceAll("\\", "/").matches("%/test/%")
  or
  path.replaceAll("\\", "/").matches("%/old_test/%")
  or
  path.replaceAll("\\", "/").matches("%/testlib/%")
  or
  path.replaceAll("\\", "/").matches("%/GangaCore/Utility/Config/tests.py")
  or
  path.replaceAll("\\", "/").matches("%/GangaCore/Utility/logging/test.py")
}

/** True iff the candidate is inside the audited ganga package tree (positive
 *  scope; the shipped python packages GangaCore/GangaGUI/GangaService plus
 *  the experiment plugins). Same bindingset rationale as excludedPath. */
bindingset[path]
predicate inScope(string path) {
  path.replaceAll("\\", "/").matches("%/ganga/%")
}

/** Modules that call os members through from-imported BARE names (verified
 *  against the actual import statements of each file):
 *  GangaLHCb/Lib/Applications/GaudiExec.py:1 `from os import rename, path,
 *  makedirs, chdir, unlink, listdir, chmod`;
 *  GangaLHCb/Lib/Applications/GaudiExecUtils.py:5
 *  `from os import makedirs, path`;
 *  GangaCore/Core/GangaRepository/SubJobJsonList.py:7 and
 *  SubJobXMLList.py:12 `from os import listdir, path, stat`;
 *  GangaDirac/Lib/RTHandlers/ExeDiracRTHandler.py:164 and
 *  GangaLHCb/Lib/RTHandlers/ExeDiracRTHandler.py:170
 *  `from os import system, environ, pathsep, getcwd, listdir, path`;
 *  GangaLHCb/Lib/RTHandlers/GaudiExecRTHandlers.py:696
 *  `from os import listdir, environ, pathsep, getcwd, system`;
 *  GangaLHCb/__init__.py:7 `from os import pathsep, listdir, environ,
 *  fdopen`;
 *  GangaLSST/Lib/Im3ShapeApp/Im3ShapeRTHandler.py:127 `from os import
 *  system, environ, pathsep, getcwd, listdir, path, chdir`. Same
 *  bindingset rationale as excludedPath. */
bindingset[path]
private predicate bareOsImportModule(string path) {
  path.matches("%/ganga/GangaLHCb/Lib/Applications/GaudiExec.py")
  or
  path.matches("%/ganga/GangaLHCb/Lib/Applications/GaudiExecUtils.py")
  or
  path.matches("%/ganga/GangaCore/Core/GangaRepository/SubJobJsonList.py")
  or
  path.matches("%/ganga/GangaCore/Core/GangaRepository/SubJobXMLList.py")
  or
  path.matches("%/ganga/GangaDirac/Lib/RTHandlers/ExeDiracRTHandler.py")
  or
  path.matches("%/ganga/GangaLHCb/Lib/RTHandlers/ExeDiracRTHandler.py")
  or
  path.matches("%/ganga/GangaLHCb/Lib/RTHandlers/GaudiExecRTHandlers.py")
  or
  path.matches("%/ganga/GangaLHCb/__init__.py")
  or
  path.matches("%/ganga/GangaLSST/Lib/Im3ShapeApp/Im3ShapeRTHandler.py")
}

/** os members invoked through the from-imported bare names of the modules
 *  above, mapped to their flow kind. */
private predicate bareOsFlowKind(string member, string kind) {
  (member = "listdir" and kind = "dir_list")
  or
  (member = "makedirs" and kind = "dir_create")
  or
  (member = "rename" and kind = "file_rename")
  or
  (member = "unlink" and kind = "file_remove")
  or
  (member = "chmod" and kind = "file_perm")
}

/** os.path members of the GangaGUI propagation/guard families, mapped to
 *  their flow kind (GangaGUI imports only `import os`, so every os.path
 *  member there is the qualified os.path.<member>(...) form). */
private predicate guiPathFlowKind(string member, string kind) {
  (member = "join" and kind = "path_join")
  or
  (member = "exists" and kind = "path_stat")
  or
  (member = "isfile" and kind = "path_stat")
  or
  (member = "isdir" and kind = "path_stat")
  or
  (member = "dirname" and kind = "path_part")
  or
  (member = "basename" and kind = "path_part")
}

/** The tool's internal path-taking API definitions with their path
 *  parameter (function, parameter, file) - definition rows for the
 *  file_api_def family. Parameter positions (0-based; for the one method,
 *  FileWorkspace.getPath, self occupies position 0). */
private predicate fileApiDefShape(Function f, Parameter p) {
  /* GangaCore.GPIDev.Persistency.export(item, filename, mode) -
     Persistency/__init__.py:35 (module function, filename at position 1) -
     the GPI export function called by the internal-API route
     /internal/jobs/<job_id>/export (api/routes.py:227) with
     save_path = request.args.get("path"); delegates to stripped_export */
  f.getName() = "export" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* GangaCore.GPIDev.Persistency.stripped_export(item, filename, mode) -
     Persistency/__init__.py:41 (position 1) - the write itself:
     filepath = fullpath(filename) (:83) then open(filepath, mode) (:85) */
  f.getName() = "stripped_export" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* GangaCore.GPIDev.Persistency.fullpath(filename) -
     Persistency/__init__.py:140 (position 0) - the export/load path
     expander: os.path.abspath(os.path.expandvars(os.path.expanduser(
     filename))) (:149-:150) - NORMALIZATION WITHOUT containment (abspath
     resolves '..' but confines to nothing) */
  f.getName() = "fullpath" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* GangaCore.GPIDev.Persistency.load(filename, returnList) -
     Persistency/__init__.py:154 (position 0) - the GPI load function
     called by the internal-API route /internal/load (api/routes.py:984)
     with path = request.args.get("path"); resolves via getScriptPath
     (:188) then open(filepath) (:190) */
  f.getName() = "load" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* GangaCore.Runtime.GPIFunctions.runfile(path_to_file) -
     GPIFunctions.py:101 (position 0) - the GPI runfile function called by
     the internal-API route /internal/runfile (api/routes.py:1005) with
     path = request.args.get("path"); runpy.run_path(path_to_file)
     (:115) - Pass 4 execution, recorded as pass-1-adjacent file consumer */
  f.getName() = "runfile" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/Runtime/GPIFunctions.py") and
  p.getName() = "path_to_file" and
  p = f.getAnArg()
  or
  /* GangaCore.Utility.Runtime.getScriptPath(name, searchPath) -
     Runtime.py:28 (position 0) - the search-path script resolver used by
     load (:188) and by the CLI script argument (bootstrap.py:1080):
     expanduser/expandvars, exists check, basename + listdir + join over
     the search path */
  f.getName() = "getScriptPath" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/Utility/Runtime.py") and
  p.getName() = "name" and
  p = f.getAnArg()
  or
  /* GangaCore.Utility.files.expandfilename(filename, force) - files.py:19
     (position 0) - THE 107-site path expansion wrapper
     (expandvars/expanduser, NO normalization, NO containment) used by the
     CLI config file (bootstrap.py:341) and all plugin path expansion */
  f.getName() = "expandfilename" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/Utility/files.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* GangaCore.Utility.files.fullpath(path, force) - files.py:32
     (position 0) - expandfilename plus os.path.realpath (:38) - the
     canonicalizing variant (not used by the GUI flows) */
  f.getName() = "fullpath" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/Utility/files.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* GangaCore.Core.Sandbox.getPackedOutputSandbox(src_dir, dest_dir) -
     Sandbox.py:133 (dest_dir at position 1) - the job-output sandbox
     unpack at job completion: tarfile.open(tgzfile) (:149) then
     tf.extractall(dest_dir, [tarinfo]) (:154); src_dir (position 0)
     carries the downloaded tarball location - recorded in this comment,
     only the destination is emitted as the traversal-relevant parameter */
  f.getName() = "getPackedOutputSandbox" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/Core/Sandbox/Sandbox.py") and
  p.getName() = "dest_dir" and
  p = f.getAnArg()
  or
  /* GangaCore.Core.Sandbox.createPackedOutputSandbox(output_patterns,
     _filter, dest_dir) - Sandbox.py:95 (dest_dir at position 2) - packs
     job output files into a tarball written under dest_dir */
  f.getName() = "createPackedOutputSandbox" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/Core/Sandbox/Sandbox.py") and
  p.getName() = "dest_dir" and
  p = f.getAnArg()
  or
  /* GangaCore.Core.Sandbox.getPackedInputSandbox(tarpath, dest_dir) -
     WNSandbox.py:61 (dest_dir at position 1) - the input sandbox unpack
     at wrapper runtime: tarfile.open(tarpath) (:70) then
     tf.extractall(dest_dir) (:71); tarpath (position 0) carries the
     tarball path - recorded in this comment */
  f.getName() = "getPackedInputSandbox" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/Core/Sandbox/WNSandbox.py") and
  p.getName() = "dest_dir" and
  p = f.getAnArg()
  or
  /* GangaCore.Core.Sandbox.createOutputSandbox(output_patterns, filter,
     dest_dir) - WNSandbox.py:76 (dest_dir at position 2) - writes the
     files matching the output patterns into dest_dir */
  f.getName() = "createOutputSandbox" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/Core/Sandbox/WNSandbox.py") and
  p.getName() = "dest_dir" and
  p = f.getAnArg()
  or
  /* GangaCore.Core.Sandbox.recursive_copy(src, dest) - WNSandbox.py:33
     (dest at position 1) - shutil.copytree/copy/makedirs destination;
     src (position 0) carries the source path - recorded in this
     comment */
  f.getName() = "recursive_copy" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/Core/Sandbox/WNSandbox.py") and
  p.getName() = "dest" and
  p = f.getAnArg()
  or
  /* GangaCore.Core.FileWorkspace.getPath(self, filename) -
     FileWorkspace.py:77 (filename at position 1, self at position 0) -
     the job-workspace path constructor (joins the workspace base with
     filename); method of class FileWorkspace */
  f.getName() = "getPath" and
  normalizedPathOf(f).matches("%/ganga/GangaCore/Core/FileWorkspace.py") and
  p.getName() = "filename" and
  p = f.getAnArg()
  or
  /* GangaGUI.gui.routes.allowed_file(filename) - gui/routes.py:1799
     (position 0) - the upload extension allowlist
     ("." in filename and rsplit extension in ALLOWED_EXTENSIONS,
     :1800) - SANITIZER candidate: validates the filename extension only,
     never the directory component */
  f.getName() = "allowed_file" and
  normalizedPathOf(f).matches("%/ganga/GangaGUI/gui/routes.py") and
  p.getName() = "filename" and
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
  /* family 1: builtin open(...) - ~430 sites in scope. The
     HTTP-reachable ones: Persistency/__init__.py:85
     open(filepath, mode) inside stripped_export (the internal-API export
     WRITE target; filepath = fullpath(filename) = abspath/expandvars/
     expanduser - normalization WITHOUT containment) and :190
     open(filepath) inside load (the internal-API load READ); the GUI
     fixed-path writes: gui/routes.py:375 (runfile content),
     :606 (edited-job-info), :273 (gangarc rewrite); GUI fixed-path
     reads: :270/:275 (gangarc), :612 (export.txt), :905/:908/:911
     (logs); bootstrap.py:345 (CLI/env config read) and :1097
     open(script).read() + exec (CLI script argument). The rest are
     job-workspace/config/credential reads and writes of the
     operator-level machinery. Only the Name form matches, so os.open,
     tarfile.open and member .open(...) calls are never counted here. */
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
  /* family 2: os.open(...) low-level opens -
     GangaCore/Core/GangaRepository/SessionLock.py:53/:430/:544/:577/:778/:811
     (O_EXCL|O_CREAT repository lock-file creation; paths derived from
     gangadir + job ids). Argument 0 carries the path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_open_lowlevel" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 3: send_file(path) - THE GUI file serves: gui/routes.py:671
     send_file(abs_path) inside job_browse (abs_path =
     os.path.join(job_base_dir, path) :659 with the raw
     /job/<id>/browse/<path:path> request path, exists :665 / isfile :670
     guards, NO containment check - TOCTOU shape), :975 send_file(abs_path)
     inside storage_page (abs_path = os.path.join(storage_folder, path)
     :934 from /storage/<path:path>, same unchecked shape) and :578
     send_file(export_path, as_attachment=True, ...) (the fixed
     UPLOAD_FOLDER/export.txt; its PRODUCER - the internal-API export
     handler - takes the request path). The actual file open happens
     inside flask/werkzeug (external to this database). */
  exists(Call c |
    c.getFunc().(Name).getId() = "send_file" and
    node = c and
    flowKind = "file_response" and
    callableName = "send_file" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "flask" and
    matchKind = "ast"
  )
  or
  /* family 4: werkzeug FileStorage .save(path) - the GUI upload writes,
     scoped to GangaGUI (the only FileStorage users): gui/routes.py:955
     storagefile.save(save_path) with save_path =
     os.path.join(abs_path, secure_filename(filename)) :954 - the
     DIRECTORY component abs_path carries the unsanitized
     /storage/<path:path> route path (traversal-relevant write);
     :302 loadfile.save and :328 runfile.save write the FIXED
     UPLOAD_FOLDER paths. Argument 0 carries the destination path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "save" and
    normalizedPathOf(c).matches("%/ganga/GangaGUI/%") and
    node = c and
    flowKind = "file_save_member" and
    callableName = "save" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "werkzeug" and
    matchKind = "ast"
  )
  or
  /* family 5: directory creation - os.makedirs/os.mkdir (argument 0):
     ~93 sites, e.g. GangaGUI/gui/config.py:11/:17 (module-init creation
     of gangadir/gui/{upload,logs,storage} - operator-config gangadir),
     bootstrap.py:1179 (IPYTHONDIR), FileWorkspace create, plugin
     scripts; plus the bare-name makedirs of GaudiExec.py /
     GaudiExecUtils.py (from os import makedirs). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "makedirs" or func.getName() = "mkdir") and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "dir_create" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Call c, string member |
    c.getFunc().(Name).getId() = member and
    member = "makedirs" and
    bareOsImportModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "dir_create" and
    callableName = member and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 6: file removal - os.remove/os.unlink/os.rmdir (argument 0):
     ~64 sites (job output cleanup, repository scratch files); plus the
     bare-name unlink of GaudiExec.py (from os import unlink). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "remove" or func.getName() = "unlink" or func.getName() = "rmdir") and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_remove" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Call c, string member |
    c.getFunc().(Name).getId() = member and
    member = "unlink" and
    bareOsImportModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "file_remove" and
    callableName = member and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 7: file rename - os.rename (argument 0; argument 1 is the
     destination): 20 sites (repository atomic writes, plugin staging);
     plus the bare-name rename of GaudiExec.py (from os import rename). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "rename" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_rename" and
    callableName = "rename" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Call c, string member |
    c.getFunc().(Name).getId() = member and
    member = "rename" and
    bareOsImportModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "file_rename" and
    callableName = member and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 8: file move - shutil.move (argument 0; argument 1 is the
     destination): 10 sites (job staging moves, e.g.
     GangaAtlas/Lib/Tasks/AtlasTransform.py:389
     shutil.move(old_path, new_path)). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "move" and
    func.getObject().(Name).getId() = "shutil" and
    node = c and
    flowKind = "file_move" and
    callableName = "move" and
    argIndex = 0 and
    receiver = "shutil" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  /* family 9: file copy - shutil.copy/copy2/copyfile/copytree (argument
     0; argument 1 is the destination): 56 sites (sandbox staging
     WNSandbox.py:49/:54/:59, File.py:119/:241/:249, LocalFile.py:238/:264,
     container_controllers.py:420, IPrepareApp.py:97 ...); plus the
     bare-name copyfile of GangaRepositoryXML.py:968
     (`from shutil import copyfile` at :968 - the repository import
     backup write). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "copy" or func.getName() = "copy2"
     or func.getName() = "copyfile" or func.getName() = "copytree") and
    func.getObject().(Name).getId() = "shutil" and
    node = c and
    flowKind = "file_copy" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "shutil" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "copyfile" and
    normalizedPathOf(c).matches("%/ganga/GangaCore/Core/GangaRepository/GangaRepositoryXML.py") and
    node = c and
    flowKind = "file_copy" and
    callableName = "copyfile" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  /* family 10: directory removal - shutil.rmtree (argument 0): 34 sites
     (job workspace teardown FileWorkspace.py:159/:165, sandbox cleanup
     IBackend.py:273, File.py:344, PrepRegistry.py:391/:458/:473,
     Condor.py:171 ...). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "rmtree" and
    func.getObject().(Name).getId() = "shutil" and
    node = c and
    flowKind = "dir_remove" and
    callableName = "rmtree" and
    argIndex = 0 and
    receiver = "shutil" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  /* family 11: directory listing - os.listdir (argument 0): ~75 sites,
     incl. the two request-path-derived browser reads
     gui/routes.py:676 (job_browse) and :980 (storage_page) - THE
     traversal-relevant listing channels; plus the bare-name listdir of
     SubJobJsonList.py/SubJobXMLList.py/ExeDiracRTHandler.py (Dirac and
     LHCb)/GaudiExec.py/GaudiExecRTHandlers.py/GangaLHCb/__init__.py/
     Im3ShapeRTHandler.py. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "listdir" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "dir_list" and
    callableName = "listdir" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Call c, string member |
    c.getFunc().(Name).getId() = member and
    member = "listdir" and
    bareOsImportModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "dir_list" and
    callableName = member and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 12: directory walk - os.walk (argument 0): 6 sites
     (StandardJobConfig.py:95 sandbox assembly, Athena.py:175 and other
     plugin walks). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "walk" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "dir_walk" and
    callableName = "walk" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 13: symlink creation - os.symlink (argument 0 is the target;
     argument 1 the link path): 9 sites, e.g.
     GangaCore/GPIDev/Lib/File/LocalFile.py:281 os.symlink(f,
     os.path.basename(f)) (output symlink with basename only) and legacy
     Atlas run scripts. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "symlink" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "symlink_create" and
    callableName = "symlink" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 14: permission change - os.chmod (argument 0): 11 sites
     (GoogleFile.py:132 cred_path, AtlasLCGRequirements.py:147, Condor
     wrapper chmod strings ...); plus the bare-name chmod of
     GaudiExec.py (from os import chmod). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "chmod" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_perm" and
    callableName = "chmod" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Call c, string member |
    c.getFunc().(Name).getId() = member and
    member = "chmod" and
    bareOsImportModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "file_perm" and
    callableName = member and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 15: tarball open - tarfile.open(...) (argument 0 carries the
     tarball path): archive CREATION Sandbox.py:68
     tarfile.open(tgzfile, "w:%s") and WNSandbox.py:116 (job sandbox
     packing), feedback_report.py:622 tarfile.TarFile.open(resultArchive,
     "w:gz"), Remote.py:704/:716 (inputdir sandboxes); archive READING
     Sandbox.py:149 tarfile.open(tgzfile, "r:*") and WNSandbox.py:70
     tarfile.open(tarpath, "r:*") (the unpack sides of family 16). Both
     the tarfile.open and the tarfile.TarFile.open shapes match. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "tarfile" and
    node = c and
    flowKind = "archive_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "tarfile" and
    moduleHint = "tarfile" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func, Attribute tf |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    tf = func.getObject().(Attribute) and
    tf.getName() = "TarFile" and
    tf.getObject().(Name).getId() = "tarfile" and
    node = c and
    flowKind = "archive_open" and
    callableName = "TarFile" and
    argIndex = 0 and
    receiver = "tarfile.TarFile" and
    moduleHint = "tarfile" and
    matchKind = "ast"
  )
  or
  /* family 16: archive extraction - .extractall(destination) (argument 0
     carries the extraction destination; -1 for the bare extractall()
     that extracts to the CWD): GangaCore/Core/Sandbox/Sandbox.py:154
     tf.extractall(dest_dir, [tarinfo]) - the job OUTPUT sandbox unpacked
     at job completion (tarball downloaded from the backend; entry names
     are backend-controlled, no filter= argument), WNSandbox.py:71
     tf.extractall(dest_dir) - the input sandbox unpack at wrapper
     runtime, GangaLHCb/Lib/Mergers/GaudiExecMerger.py:226
     tar.extractall(tmp_dir), GangaSAGA/Lib/SAGA/SAGAWrapperScript.py:87
     tar.extractall() (bare - CWD destination, hence argIndex -1) and
     GangaSNOplus/Lib/Applications/job_tools.py:310/:322
     tarred_file.extractall(target_path/temp_dir). NO zipfile-based
     extraction exists anywhere in the tree. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "extractall" and
    (argIndex = 0 and exists(c.getArg(0))
     or argIndex = -1 and not exists(c.getArg(0))) and
    node = c and
    flowKind = "archive_extract" and
    callableName = "extractall" and
    receiver = receiverHint(func) and
    moduleHint = "tarfile" and
    matchKind = "ast"
  )
  or
  /* family 17: globbing - glob.glob(pattern) (argument 0): 28 sites
     (GangaRepositoryImmutableTransient.py:44 repository scans,
     IChecker.py:85, IMerger.py:139, IGangaFile.py:232,
     LocalFile.py:122/:146/:237 outputdir pattern discovery, ...); plus
     the bare-name glob of AfsToken.py (`from glob import glob` at :9). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "glob" and
    func.getObject().(Name).getId() = "glob" and
    node = c and
    flowKind = "path_glob" and
    callableName = "glob" and
    argIndex = 0 and
    receiver = "glob" and
    moduleHint = "glob" and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "glob" and
    normalizedPathOf(c).matches("%/ganga/GangaCore/GPIDev/Credentials/AfsToken.py") and
    node = c and
    flowKind = "path_glob" and
    callableName = "glob" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "glob" and
    matchKind = "ast"
  )
  or
  /* family 18: the GangaGUI os.path propagation/guard family (qualified
     os.path.<member>(...) only - GangaGUI imports `import os`), scoped
     to GangaGUI where the members sit inside the untrusted request
     flows: join - gui/routes.py:659 os.path.join(job_base_dir, path)
     THE unchecked join of the browse route, :934
     os.path.join(storage_folder, path) THE unchecked join of the
     storage route, :682/:986 os.path.join(abs_path, file) listing
     checks, :301/:327/:370/:570/:597/:598 fixed UPLOAD_FOLDER joins;
     dirname - :651 the job base derivation from repository content,
     :662/:966 back-path derivation; exists - :665/:969, isfile -
     :670/:974, isdir - :949 (guard reads; separate syscalls from the
     send_file open - TOCTOU shape). Argument 0 carries the path (first
     component for join). */
  exists(Call c, Attribute func, Attribute mid |
    func = c.getFunc().(Attribute) and
    mid = func.getObject().(Attribute) and
    mid.getName() = "path" and
    mid.getObject().(Name).getId() = "os" and
    guiPathFlowKind(func.getName(), flowKind) and
    normalizedPathOf(c).matches("%/ganga/GangaGUI/%") and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 19: the upload filename sanitizer -
     secure_filename(storagefile.filename) at gui/routes.py:953 (from
     werkzeug.utils import secure_filename at :15): neutralizes traversal
     in the uploaded FILENAME only - the save destination DIRECTORY
     (abs_path from the route path, family 18 join :954) is NOT covered.
     Guard material emitted for the labeling step; argument 0 carries the
     sanitized name. */
  exists(Call c |
    c.getFunc().(Name).getId() = "secure_filename" and
    node = c and
    flowKind = "path_sanitize" and
    callableName = "secure_filename" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "werkzeug" and
    matchKind = "ast"
  )
  or
  /* family 20: file_api_def definition rows - the tool's internal
     path-taking API definitions with the true path parameter positions
     (0-based; self occupies position 0 for the one method):
     export(filename) Persistency/__init__.py:35 pos 1,
     stripped_export(filename) :41 pos 1 - the internal-API export write
     chain -, fullpath(filename) :140 pos 0 - abspath/expandvars/
     expanduser, normalization WITHOUT containment -, load(filename)
     :154 pos 0 - the internal-API load read chain -, runfile
     (path_to_file) GPIFunctions.py:101 pos 0 - runpy execution,
     getScriptPath(name) Utility/Runtime.py:28 pos 0 - the search-path
     script resolver used by load and the CLI script argument,
     expandfilename(filename) Utility/files.py:19 pos 0 - THE 107-site
     expansion wrapper (no normalization, no containment), fullpath(path)
     Utility/files.py:32 pos 0 - the realpath variant,
     getPackedOutputSandbox(dest_dir) Sandbox.py:133 pos 1 - output
     sandbox extractall destination -, createPackedOutputSandbox
     (dest_dir) Sandbox.py:95 pos 2, getPackedInputSandbox(dest_dir)
     WNSandbox.py:61 pos 1 - input sandbox extractall destination -,
     createOutputSandbox(dest_dir) WNSandbox.py:76 pos 2,
     recursive_copy(dest) WNSandbox.py:33 pos 1, FileWorkspace.getPath
     (filename) FileWorkspace.py:77 pos 1 (method of FileWorkspace,
     self at 0) - the job-workspace path constructor -, allowed_file
     (filename) gui/routes.py:1799 pos 0 - the upload extension
     allowlist (sanitizer candidate); these rows give the labeling step
     the summary/propagation backbone between the source boundaries and
     the concrete file operations */
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
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  inScope(node.getLocation().getFile().getAbsolutePath()) and
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
