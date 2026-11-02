/**
 * @name dfetch CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the dfetch
 *   CodeQL database (snapshot 81020d5, dfetch 0.5.1 - the dfetch CLI tool
 *   itself is the audit target): builtin open(...) (manifest read
 *   dfetch/manifest/manifest.py:158, manifest write :230, metadata read
 *   dfetch/project/metadata.py:70, metadata write :165 whose path =
 *   realpath(join(destination, ".dfetch_data.yaml")) is
 *   MANIFEST-DST-CONTROLLED, the .git/info/sparse-checkout append at
 *   dfetch/vcs/git.py:149-154 whose CONTENT is the manifest "src", the
 *   patch write commands/diff.py:171 with patch_name =
 *   f"{project.name}.patch" - MANIFEST-NAME-CONTROLLED - and the hash read
 *   util/util.py:107 under the walked destination); pathlib directory
 *   creation (pathlib.Path(self.local_path).mkdir(parents=True,
 *   exist_ok=True) project/git.py:70 - creates the manifest dst anywhere it
 *   points - and pathlib.Path(os.path.dirname(self.local_path)).mkdir(...)
 *   project/svn.py:196); deletion (os.remove util/util.py:33 via
 *   safe_rm(self.local_path) vcs.py:105 and project/svn.py:206 of
 *   non-matching files under the destination, shutil.rmtree util.py:39 via
 *   safe_rmtree of local_path vcs.py:105, join(local_path, ".git")
 *   project/git.py:80 and PurePath(src).parts[0] vcs/git.py:170); moves and
 *   copies (shutil.move vcs/git.py:169 of the manifest-"src" subtree into
 *   the CWD, freeze.py:103 literal backup move, shutil.copyfile
 *   commands/init.py:38); os.chdir (util.py:52/:54 via in_directory - the
 *   CWD scoping every relative path in the fetch pipeline resolves
 *   against); the os.path propagation/validation family (join, realpath,
 *   dirname, basename, relpath, isdir/isfile/exists/access - incl. the
 *   metadata path construction metadata.py:129/:132-133 and the walk-result
 *   joins util.py:25/:83/:95); pathlib construction (pathlib.Path
 *   manifest.py:244/:274, project/git.py:70, project/svn.py:196, and
 *   PurePath(src) vcs/git.py:170) with the .relative_to containment-check
 *   shape (manifest.py:274) and the .parts[0] subscript (vcs/git.py:170);
 *   the patch_ng channel (fromfile(self.__project.patch) vcs.py:134 reads
 *   the manifest-designated patch file, patch_set.apply(0,
 *   root=self.local_path, fuzz=True) vcs.py:138 writes the patch target
 *   files under the destination - the archive-like extraction channel);
 *   the svn export subprocess file write (run_on_cmdline(logger,
 *   ["svn","export","--force"] + rev.split(" ") + [url, dst]) project/svn.py
 *   :243-246 - the svn process writes the exported tree at the
 *   Python-supplied manifest dst; the git-side checkout writes are anchored
 *   by the chdir channel instead); external-library file IO
 *   (outputter.output_to_file(outfile, ...) reporting/sbom_reporter.py:106
 *   with the CLI --outfile, infer_license.api.guess_file(license_file)
 *   commands/report.py:90 reading files globbed from the destination CWD);
 *   directory walks and listings feeding deletion and hashing (os.walk
 *   util.py:22/:83/:92, os.listdir project/svn.py:207 and vcs/git.py:168,
 *   glob.glob report.py:88); the permission change (os.chmod util.py:14 in
 *   the rmtree onerror callback); and definition rows for the tool's own
 *   path-taking APIs (safe_rm/safe_rmtree/in_directory/find_file/
 *   find_non_matching_files/hash_directory/hash_file, Manifest.from_file/
 *   dump, Metadata.from_file, GitLocalRepo.__init__/checkout_version,
 *   SvnRepo._export, _dump_patch) with the true path parameter positions.
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong shape
 *   for candidate tables and @kind table is not assumed to exist.
 * @id iris/dfetch/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member/field name ("open" / "mkdir" / "remove" /
 *                   "rmtree" / "move" / "copyfile" / "chmod" / "chdir" /
 *                   "join" / "realpath" / "dirname" / "basename" / "relpath"
 *                   / "isdir"/"isfile"/"exists"/"access" / "Path" /
 *                   "PurePath" / "relative_to" / "parts" / "fromfile" /
 *                   "apply" / "run_on_cmdline" / "output_to_file" /
 *                   "guess_file" / "glob" / "listdir" / "walk" / the
 *                   function name for file_api_def definition rows)
 *   4. flow_kind  - "file_open" (builtin open(...) - argument 0 carries the
 *                   path; modes "r"/"rb" read, "w+"/"w" write, "a" append
 *                   noted via the site context in the description),
 *                   "dir_create" (.mkdir(parents=True, exist_ok=True) - the
 *                   path is the RECEIVER, a pathlib.Path construction),
 *                   "file_delete" (os.remove(argument 0)),
 *                   "dir_delete" (shutil.rmtree(argument 0)),
 *                   "file_move" (shutil.move(argument 0 = source)),
 *                   "file_copy" (shutil.copyfile(argument 0 = source)),
 *                   "file_chmod" (os.chmod(argument 0)),
 *                   "chdir" (os.chdir(argument 0) - CWD scoping),
 *                   "path_join" (os.path.join - propagation; argument 0 is
 *                   the first path component, later positional arguments
 *                   also carry components), "path_canon" (os.path.realpath -
 *                   normalization, NOT a containment guard here),
 *                   "path_part" (os.path.dirname / os.path.basename and the
 *                   PurePath(...).parts[0] subscript - component extraction,
 *                   propagation nodes), "path_rel" (os.path.relpath -
 *                   display-only), "path_stat" (os.path.isdir/isfile/
 *                   exists/access - guard reads), "path_ctor"
 *                   (pathlib.Path/PurePath construction - argument 0
 *                   carries the path), "path_containment_check"
 *                   (.relative_to(argument 0) - containment-check-shaped,
 *                   used at manifest.py:274 for a log prefix only),
 *                   "patch_read" (patch_ng.fromfile(argument 0) - reads the
 *                   manifest-designated patch file), "patch_apply"
 *                   (patch_set.apply(0, root=..., fuzz=True) - writes the
 *                   patch target files under the destination root; the root
 *                   is the KEYWORD argument `root`, hence arg_index -1),
 *                   "process_file_write" (the "svn export --force <url>
 *                   <dst>" run_on_cmdline call - the svn process writes at
 *                   the Python-supplied dst, the LAST element of the
 *                   concatenated command list whose length varies with the
 *                   revision argument, hence arg_index -1),
 *                   "file_write_ext" (cyclonedx outputter.output_to_file
 *                   (argument 0) - CLI --outfile), "file_read_ext"
 *                   (infer_license.api.guess_file(argument 0) - license
 *                   files globbed from the destination CWD), "dir_list"
 *                   (os.listdir / glob.glob(argument 0)), "dir_walk"
 *                   (os.walk(argument 0)), "file_api_def" (definition row of
 *                   a tool-internal path-taking API, carrying the path
 *                   parameter position)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "os"/"shutil"/"pathlib"/"patch_set"/
 *                   "outputter" etc., or "" if none; "<expr>" when the
 *                   object expression is neither Name nor Attribute - e.g.
 *                   the pathlib.Path(...) constructions receiving .mkdir;
 *                   enclosing class name for file_api_def rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "builtins"/"os"/"os.path"/"shutil"/"pathlib"/
 *                   "patch_ng"/"glob"/"infer_license.api"/"cyclonedx.output"
 *                   for the stdlib/external channels
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for open/remove/chmod/chdir/join/realpath/
 *                   dirname/basename/relpath/stat-family/Path/copyfile/
 *                   output_to_file/guess_file/glob/listdir/walk; argument 0
 *                   = source for rmtree/move; the parameter position for
 *                   file_api_def rows including the self/cls slot), -1 for
 *                   mkdir (path is the receiver), relative_to is argument 0,
 *                   parts is the subscript index 0, apply and the svn
 *                   export (keyword root / dynamic list position)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): the sink core is the FILE
 * PATH PARAMETER of actual filesystem operations (open/mkdir/remove/rmtree/
 * move/copyfile/chmod/chdir, the svn-export destination, the patch_ng apply
 * root, the external-library write/read) plus the os.path/pathlib pipeline
 * nodes that directly determine the accessed path (join/realpath/dirname/
 * basename/relpath/ctor/parts and the isdir/isfile/exists guard reads) -
 * NOT every path string construction node: string concatenation and
 * f-string path building (vcs/git.py:169 "src + \"/\" + file_to_copy",
 * vcs/git.py:270 "toplevel + \"/.gitmodules\"", diff.py:166
 * f"{project.name}.patch") are indistinguishable from ordinary string
 * building at AST level and are anchored by their consuming sink rows
 * instead (documented in detection.json uncoveredCases). The git-side
 * subprocess writes (git init/fetch/reset inside in_directory(local_path))
 * are anchored by the chdir channel; their command strings are Pass 2
 * material. The subprocess run_on_cmdline call is emitted ONLY for the svn
 * export shape (list-concatenation command carrying an explicit destination
 * path element).
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no sink row is expected to resolve at API level:
 * all channels are either builtin/stdlib module members matched on the
 * syntactic qualifier (os/shutil/os.path/pathlib/glob - the stdlib is not
 * part of the database), instance members on local variables
 * (patch_set.apply, outputter.output_to_file, the pathlib.Path(...)
 * constructions receiving .mkdir) or calls of dfetch-internal/local names
 * (run_on_cmdline, fromfile). The match_kind column is kept "ast" for all
 * families for cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/, /features/ (behave-BDD
 * step files), /dfetch-db/ (the CodeQL database directory nested inside the
 * source tree), /doc/, /node_modules/ (defensive). setup.py and
 * create_venv.py at the repo root are kept in scope (build/dev scripts with
 * literal paths - rows, if any, expected to be labeled none/FP).
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
  path.replaceAll("\\", "/").matches("%/features/%")
  or
  path.replaceAll("\\", "/").matches("%/dfetch-db/%")
  or
  path.replaceAll("\\", "/").matches("%/doc/%")
  or
  path.replaceAll("\\", "/").matches("%/node_modules/%")
}

/* ------------------------------------------------------------------ */
/* Shared dfetch shapes (kept consistent with sources.ql)               */
/* ------------------------------------------------------------------ */

/** os.path.<member> members performing path propagation/validation/guard
 *  reads, mapped to their flow kind. */
private predicate osPathFlowKind(string member, string kind) {
  (member = "join" and kind = "path_join")
  or
  (member = "realpath" and kind = "path_canon")
  or
  (member = "dirname" and kind = "path_part")
  or
  (member = "basename" and kind = "path_part")
  or
  (member = "relpath" and kind = "path_rel")
  or
  (member = "isdir" and kind = "path_stat")
  or
  (member = "isfile" and kind = "path_stat")
  or
  (member = "exists" and kind = "path_stat")
  or
  (member = "access" and kind = "path_stat")
}

/** The tool's internal path-taking API definitions with their path
 *  parameter (function, parameter name, file) - definition rows for the
 *  file_api_def family. Parameter positions (0-based, including the
 *  self/cls slot) are documented per shape in the row-assembly family. */
private predicate fileApiDefShape(Function f, Parameter p) {
  /* dfetch.util.util.safe_rm(path) - util.py:28 (module function, path at
     position 0) - called as safe_rm(self.local_path) from VCS.update
     (vcs.py:105) with the manifest dst */
  f.getName() = "safe_rm" and
  normalizedPathOf(f).matches("%/dfetch/util/util.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* dfetch.util.util.safe_rmtree(path) - util.py:36 (position 0) - used for
     local_path (vcs.py:105), join(local_path, ".git") (project/git.py:80)
     and PurePath(src).parts[0] (vcs/git.py:170) */
  f.getName() = "safe_rmtree" and
  normalizedPathOf(f).matches("%/dfetch/util/util.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* dfetch.util.util.in_directory(path) - util.py:47 (position 0) - the
     os.chdir CWD-scoping context manager used for the manifest dir, the
     project destination and the src handling */
  f.getName() = "in_directory" and
  normalizedPathOf(f).matches("%/dfetch/util/util.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* dfetch.util.util.find_file(name, path=".") - util.py:80 (path at
     position 1) - the os.walk-based manifest discovery root */
  f.getName() = "find_file" and
  normalizedPathOf(f).matches("%/dfetch/util/util.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* dfetch.util.util.find_non_matching_files(directory, pattern) -
     util.py:20 (position 0) - yields files under the fetched destination
     for os.remove (svn.py:206) */
  f.getName() = "find_non_matching_files" and
  normalizedPathOf(f).matches("%/dfetch/util/util.py") and
  p.getName() = "directory" and
  p = f.getAnArg()
  or
  /* dfetch.util.util.hash_directory(path, skiplist) - util.py:87 (position
     0) - os.walk + open + read over the destination */
  f.getName() = "hash_directory" and
  normalizedPathOf(f).matches("%/dfetch/util/util.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* dfetch.util.util.hash_file(file_path, digest) - util.py:104 (position
     0) - open(file_path, "rb") read under the walked destination */
  f.getName() = "hash_file" and
  normalizedPathOf(f).matches("%/dfetch/util/util.py") and
  p.getName() = "file_path" and
  p = f.getAnArg()
  or
  /* dfetch.manifest.manifest.Manifest.from_file(path) - manifest.py:145
     (staticmethod, path at position 0) - open(path, "r") + yaml.safe_load */
  f.getName() = "from_file" and
  normalizedPathOf(f).matches("%/dfetch/manifest/manifest.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* dfetch.manifest.manifest.Manifest.dump(path) - manifest.py:228 (self
     at 0, path at position 1) - open(path, "w+") manifest write */
  f.getName() = "dump" and
  normalizedPathOf(f).matches("%/dfetch/manifest/manifest.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* dfetch.project.metadata.Metadata.from_file(path) - metadata.py:68
     (classmethod, cls at 0, path at position 1) - open(path, "r") +
     yaml.safe_load of the fetched project's .dfetch_data.yaml */
  f.getName() = "from_file" and
  normalizedPathOf(f).matches("%/dfetch/project/metadata.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* dfetch.vcs.git.GitLocalRepo.__init__(path=".") - vcs/git.py:114 (self
     at 0, path at position 1) - the local repo root all git operations
     chdir into (constructed with self.local_path, the manifest dst) */
  f.getName() = "__init__" and
  normalizedPathOf(f).matches("%/dfetch/vcs/git.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* dfetch.vcs.git.GitLocalRepo.checkout_version(remote, version, src,
     must_keeps) - vcs/git.py:127 (self at 0, src at position 3) - the
     manifest "src" driving the sparse-checkout write, os.listdir,
     shutil.move and safe_rmtree(PurePath(src).parts[0]) */
  f.getName() = "checkout_version" and
  normalizedPathOf(f).matches("%/dfetch/vcs/git.py") and
  p.getName() = "src" and
  p = f.getAnArg()
  or
  /* dfetch.project.svn.SvnRepo._export(url, rev="", dst=".") - svn.py:242
     (staticmethod, dst at position 2) - "svn export --force <url> <dst>"
     with the manifest dst */
  f.getName() = "_export" and
  normalizedPathOf(f).matches("%/dfetch/project/svn.py") and
  p.getName() = "dst" and
  p = f.getAnArg()
  or
  /* dfetch.commands.diff._dump_patch(path, revs, project, patch_name,
     patch) - diff.py:160 (patch_name at position 3) - open(patch_name,
     "w") with patch_name = f"{project.name}.patch" */
  f.getName() = "_dump_patch" and
  normalizedPathOf(f).matches("%/dfetch/commands/diff.py") and
  p.getName() = "patch_name" and
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
  /* family 1: builtin open(...) - manifest read manifest.py:158
     open(path, "r") (path from the os.walk-based find_manifest), manifest
     write manifest.py:230 open(path, "w+") (Manifest.dump), metadata read
     metadata.py:70 open(path, "r"), metadata write metadata.py:165
     open(self.path, "w+") - self.path = realpath(join(destination,
     ".dfetch_data.yaml")) is MANIFEST-DST-CONTROLLED -, the sparse-checkout
     append vcs/git.py:149-154 open(".git/info/sparse-checkout", "a") -
     literal relative path, but the written CONTENT is the manifest "src" -
     the patch write diff.py:171 open(patch_name, "w") with the
     manifest-name-controlled patch_name, and the hash read util.py:107
     open(file_path, "rb") under the walked destination; argument 0
     carries the path */
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
  /* family 2: pathlib .mkdir(parents=True, exist_ok=True) - project/git.py:70
     pathlib.Path(self.local_path).mkdir(...) creates the manifest dst
     (including any missing parents, ANYWHERE the dst points) and
     project/svn.py:196 pathlib.Path(os.path.dirname(self.local_path))
     .mkdir(...) creates the dst's parent chain; the path is the RECEIVER
     (a pathlib.Path construction - the receiverHint yields "<expr>" for
     such call-object receivers; the construction sites are captured by the
     path_ctor rows), hence argIndex -1 */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "mkdir" and
    node = c and
    flowKind = "dir_create" and
    callableName = "mkdir" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 3: os.remove(path) - util.py:33 inside safe_rm (called as
     safe_rm(self.local_path) from VCS.update vcs.py:105 - the manifest
     dst) and project/svn.py:206 (every file under the fetched destination
     that does not match the manifest "src" pattern); argument 0 carries
     the path */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "remove" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_delete" and
    callableName = "remove" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 4: os.chmod(path, stat.S_IWUSR) - util.py:14 inside
     _remove_readonly, the shutil.rmtree onerror callback re-permissioning
     the path being deleted (path supplied by rmtree from the deleted
     tree); argument 0 carries the path */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "chmod" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_chmod" and
    callableName = "chmod" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 5: shutil.rmtree(path, onerror=...) - util.py:39 inside
     safe_rmtree, used for local_path (vcs.py:105 - the manifest dst),
     os.path.join(local_path, ".git") (project/git.py:80) and
     PurePath(src).parts[0] (vcs/git.py:170 - the FIRST COMPONENT of the
     manifest "src", recursively deleted); argument 0 carries the path */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "rmtree" and
    func.getObject().(Name).getId() = "shutil" and
    node = c and
    flowKind = "dir_delete" and
    callableName = "rmtree" and
    argIndex = 0 and
    receiver = "shutil" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  /* family 6: shutil.move(src, dst) - vcs/git.py:169
     shutil.move(src + "/" + file_to_copy, ".") moves each entry of the
     manifest-"src" subtree into the CWD (which in_directory set to the
     dst) and freeze.py:103 shutil.move(DEFAULT_MANIFEST_NAME,
     DEFAULT_MANIFEST_NAME + ".backup") (literal paths); argument 0
     carries the SOURCE path */
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
  /* family 7: shutil.copyfile(src, dst) - commands/init.py:38
     shutil.copyfile(template_path, DEFAULT_MANIFEST_NAME) - the packaged
     template.yaml to the literal manifest name; argument 0 carries the
     source path */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "copyfile" and
    func.getObject().(Name).getId() = "shutil" and
    node = c and
    flowKind = "file_copy" and
    callableName = "copyfile" and
    argIndex = 0 and
    receiver = "shutil" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  /* family 8: os.chdir(path) - util.py:52 os.chdir(path) / :54
     os.chdir(pwd) inside in_directory: every relative path in the fetch
     pipeline resolves against the CWD this sets (manifest directory
     update.py:70/check.py:63/freeze.py:76/diff.py:106/report.py:67;
     project.destination update.py:76/check.py:69 - fetched-project
     child-manifest discovery; local_path/src in the GitLocalRepo and
     SvnRepo methods); a dst that is absolute or contains ".." escapes
     this scoping entirely; argument 0 carries the path */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "chdir" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "chdir" and
    callableName = "chdir" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 9: os.path.<member>(...) propagation/validation/guard reads -
     join (util.py:25/:83/:95 walk-result joins, metadata.py:129/:133
     destination+metadata-filename joins, project/git.py:80
     local_path+".git", project/svn.py:70 externals import join,
     vcs/git.py:237 getcwd()+sm_path; argument 0 is the FIRST path
     component - later positional arguments also carry components),
     realpath (manifest.py:247/:270 manifest path normalization - NOT a
     containment guard, metadata.py:129/:132, commands/import_.py:195
     toplevel comparison), dirname (util.py:51, commands/update.py:70,
     check.py:63, freeze.py:76, report.py:67, diff.py:131/:169,
     metadata.py:133, project/svn.py:196/:219, manifest.py:274,
     commands/common.py:37), basename (metadata.py:131 - the sibling
     metadata filename, a partial basename guard shape), relpath
     (commands/common.py:36, commands/validate.py:35 - display-only),
     isdir/isfile/exists/access (guard reads: util.py:13/:30/:50/:106,
     update.py:75, check.py:69, diff.py:127, init.py:33, report.py:81,
     vcs.py:103/:117/:232/:244, metadata.py:128, project/svn.py:218/:283,
     vcs/git.py:161/:252/:285); argument 0 carries the path */
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
  /* family 10: pathlib.Path(...) / pathlib.PurePath(...) constructor calls
     - manifest.py:244 pathlib.Path(paths[0]).as_posix() (warning
     display), manifest.py:274 pathlib.Path(path).relative_to(...)
     (child-manifest log prefix), project/git.py:70
     pathlib.Path(self.local_path).mkdir(...) (THE dst directory
     creation), project/svn.py:196
     pathlib.Path(os.path.dirname(self.local_path)).mkdir(...) and
     vcs/git.py:170 PurePath(src) (first-component extraction feeding
     safe_rmtree); both the Attribute form (import pathlib - the only form
     used in this tree) and the bare Name form (from pathlib import
     Path - kept for cross-project recall) are matched; argument 0
     carries the path */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "Path" or func.getName() = "PurePath") and
    func.getObject().(Name).getId() = "pathlib" and
    node = c and
    flowKind = "path_ctor" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "pathlib" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  exists(Call c |
    (c.getFunc().(Name).getId() = "Path" or
     c.getFunc().(Name).getId() = "PurePath") and
    node = c and
    flowKind = "path_ctor" and
    callableName = c.getFunc().(Name).getId() and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 11: .relative_to(...) base-containment shape - manifest.py:274
     pathlib.Path(path).relative_to(os.path.dirname(os.getcwd())).as_posix()
     (prefix_runtime_exceptions prefix for child-manifest validation) -
     containment-check-shaped but used for a log/error prefix, NOT as a
     destination guard (raises ValueError when a walked child manifest is
     not below the CWD); argument 0 carries the base */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "relative_to" and
    node = c and
    flowKind = "path_containment_check" and
    callableName = "relative_to" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 12: PurePath(...).parts[0] subscript - vcs/git.py:170
     safe_rmtree(PurePath(src).parts[0]) - the first-component extraction
     of the manifest "src" that then feeds safe_rmtree (a traversal
     AMPLIFIER, not a guard); index argument 0 carries the component
     index */
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "parts" and
    node = s and
    flowKind = "path_part" and
    callableName = "parts" and
    argIndex = 0 and
    receiver = receiverHint(base) and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 13: patch_ng.fromfile(self.__project.patch) - vcs.py:134
     (imported via `from patch_ng import fromfile`): reads and parses the
     manifest-designated patch file; argument 0 carries the path */
  exists(Call c |
    c.getFunc().(Name).getId() = "fromfile" and
    normalizedPathOf(c).matches("%/dfetch/project/vcs.py") and
    node = c and
    flowKind = "patch_read" and
    callableName = "fromfile" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "patch_ng" and
    matchKind = "ast"
  )
  or
  /* family 14: patch_set.apply(0, root=self.local_path, fuzz=True) -
     vcs.py:138: applies the parsed patch writing its target files under
     the destination root (root = self.local_path = the manifest dst; the
     patch-internal target paths are parsed inside patch_ng, not part of
     this database - the archive-like extraction channel); the root is
     the KEYWORD argument `root`, hence argIndex -1 */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "apply" and
    normalizedPathOf(c).matches("%/dfetch/project/vcs.py") and
    node = c and
    flowKind = "patch_apply" and
    callableName = "apply" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "patch_ng" and
    matchKind = "ast"
  )
  or
  /* family 15: the svn export subprocess file write - project/svn.py:243-246
     run_on_cmdline(logger, ["svn", "export", "--force"] + rev.split(" ") +
     [url, dst]) inside SvnRepo._export: the svn process writes the
     exported tree at the Python-supplied dst = self.local_path (the
     manifest dst; called from _fetch_impl svn.py:202 and for license
     files svn.py:221). Identified as the ONLY run_on_cmdline call in
     project/svn.py whose command argument (positional argument 1) is a
     list-concatenation BinaryExpr; the dst is the LAST element of the
     concatenated list whose length varies with the revision argument,
     hence argIndex -1. The git-side subprocess writes are anchored by the
     chdir channel (family 8) instead. */
  exists(Call c, BinaryExpr b |
    c.getFunc().(Name).getId() = "run_on_cmdline" and
    b = c.getPositionalArg(1).(BinaryExpr) and
    normalizedPathOf(c).matches("%/dfetch/project/svn.py") and
    node = c and
    flowKind = "process_file_write" and
    callableName = "run_on_cmdline" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 16: cyclonedx report write - reporting/sbom_reporter.py:106
     outputter.output_to_file(outfile, allow_overwrite=True): the SBOM
     report is written at the CLI --outfile path (commands/report.py:75
     dump_to_file(args.outfile)); argument 0 carries the path */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "output_to_file" and
    node = c and
    flowKind = "file_write_ext" and
    callableName = "output_to_file" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "cyclonedx.output" and
    matchKind = "ast"
  )
  or
  /* family 17: license file read - commands/report.py:90
     infer_license.api.guess_file(license_file): reads license files found
     by glob.glob("*") (report.py:88) in the CWD that in_directory set to
     project.destination (report.py:85 - the manifest dst); argument 0
     carries the path */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "guess_file" and
    node = c and
    flowKind = "file_read_ext" and
    callableName = "guess_file" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "infer_license.api" and
    matchKind = "ast"
  )
  or
  /* family 18: glob.glob("*") - commands/report.py:88: destination-CWD
     listing feeding the license file reads; argument 0 carries the
     pattern */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "glob" and
    func.getObject().(Name).getId() = "glob" and
    node = c and
    flowKind = "dir_list" and
    callableName = "glob" and
    argIndex = 0 and
    receiver = "glob" and
    moduleHint = "glob" and
    matchKind = "ast"
  )
  or
  /* family 19: os.listdir(path) - project/svn.py:207
     os.listdir(self.local_path) (emptiness check after pattern
     deletion) and vcs/git.py:168 os.listdir(src) (the manifest-"src"
     subtree listing whose entries feed shutil.move at :169); argument 0
     carries the path */
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
  /* family 20: os.walk(path) - util.py:22
     find_non_matching_files(directory, pattern) (yields files under the
     fetched destination for os.remove at project/svn.py:206), util.py:83
     find_file (the os.walk-based manifest discovery) and util.py:92
     hash_directory (yields files under the destination for open+read);
     argument 0 carries the path */
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
  /* family 21: file_api_def definition rows - the tool's internal
     path-taking API definitions with the true path parameter positions
     (0-based, including the self/cls slot): safe_rm(path) util.py:28 pos
     0, safe_rmtree(path) util.py:36 pos 0, in_directory(path) util.py:47
     pos 0, find_file(name, path) util.py:80 pos 1,
     find_non_matching_files(directory, pattern) util.py:20 pos 0,
     hash_directory(path, skiplist) util.py:87 pos 0, hash_file(file_path,
     digest) util.py:104 pos 0, Manifest.from_file(path) manifest.py:145
     pos 0 (staticmethod), Manifest.dump(path) manifest.py:228 pos 1,
     Metadata.from_file(path) metadata.py:68 pos 1 (classmethod),
     GitLocalRepo.__init__(path) vcs/git.py:114 pos 1,
     GitLocalRepo.checkout_version(src) vcs/git.py:127 pos 3,
     SvnRepo._export(dst) project/svn.py:242 pos 2 (staticmethod),
     _dump_patch(patch_name) commands/diff.py:160 pos 3; these rows give
     the labeling step the summary/propagation backbone between the
     manifest source fields and the concrete file operations */
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
