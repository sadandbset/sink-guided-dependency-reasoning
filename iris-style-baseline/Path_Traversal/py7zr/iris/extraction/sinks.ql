/**
 * @name py7zr CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the
 *   py7zr CodeQL database (snapshot 04e3af5a, py7zr ~0.20.0+ unreleased -
 *   the py7zr archive library itself is the audit target): pathlib path
 *   construction (pathlib.Path(...) / pathlib.WindowsPath(...) constructor
 *   calls incl. the archive-entry-driven pathlib.Path(
 *   remove_relative_path_marker(outname)) at py7zr.py:580, the base join
 *   path.joinpath(...) at :582 and pathlib.Path(os.getcwd()).joinpath(...)
 *   at :577, the caller output dir pathlib.Path(path) at :542, the
 *   long-path pathlib.WindowsPath("\\\\?" + str(outfilename)) at :597, the
 *   link-target pathlib.Path(omfp.read().decode("utf-8")) at :1343, the
 *   write-side pathlib.Path(arcname) at :830/:912, pathlib.Path(path)/
 *   Path(file) at :1015/:1026 (writeall/write str->Path), Path(linkname)
 *   at :1427, helpers.py:299 Path(res) and win32compat.py:198
 *   WindowsPath(rpath) (readlink results), and the CLI
 *   pathlib.Path(...) constructions at cli.py:203/:399/:415/:426/:440/:447);
 *   the base-containment validation nodes (.relative_to(...) at
 *   py7zr.py:577 against os.getcwd() and :584 outfilename.relative_to(path)
 *   - both raise Bad7zFile on failure); the custom path wrapper
 *   (remove_relative_path_marker(...) at py7zr.py:577/:580/:582 - strips
 *   ONLY a leading "./", does not reject ".." or absolute paths; plus the
 *   os.path.join/basename/splitext/relpath/dirname pure path ops at
 *   py7zr.py:513/:730/:1432 and the entry-name .replace("\\", "/")
 *   normalization at archiveinfo.py:757); real file content and metadata
 *   access (builtin open(...) at py7zr.py:344/:346/:348/:350 archive open,
 *   :1155/:1158 is_7zfile, :1239 Worker parallel re-open, :1288
 *   extract_single str fp, cli.py:301 run_test, utils/bench_result.py:50;
 *   .open(...) member calls at py7zr.py:358/:360/:362/:364 archive open,
 *   :1349 fileish.open(mode="wb") THE archive-content write sink, :1359
 *   empty-file open, :1460 f.origin.open(mode="rb"); .mkdir(...) at :545
 *   caller output dir, :625 archive-entry directories, :1328
 *   fileish.parent.mkdir; .unlink() at :1336/:1346 and .touch() at :1357;
 *   fileish.symlink_to(sym_target) at :1347 and
 *   _winapi.CreateJunction(str(fileish), dst) at :1338 - link creation
 *   whose path AND target are archive-controlled; os.utime at :659 and
 *   .chmod at :663/:668 with archive-supplied times/modes; the stat family
 *   (.stat/.lstat/.exists/.is_dir/.is_file/.is_symlink/.samefile,
 *   os.stat at py7zr.py:936 + cli.py:286, os.path.islink/exists at
 *   helpers.py:270/:302, GetFileAttributesW at win32compat.py:94,
 *   CreateFileW at win32compat.py:139); the listing/link-target read
 *   family (os.listdir at py7zr.py:729, the readlink calls at
 *   helpers.py:290/:292/:294/:304 and py7zr.py:1422); and definition rows
 *   for the library's own path-consuming internal APIs
 *   (SevenZipFile._make_file_info target, SevenZipFile._writeall path,
 *   Worker.extract fp, Worker.extract_single fp, Worker.register_filelike
 *   fileish, Worker._find_link_target target, remove_relative_path_marker
 *   path, helpers.readlink path, win32compat.readlink path,
 *   win32compat.is_reparse_point path) with the true parameter positions.
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong shape
 *   for candidate tables and @kind table is not assumed to exist.
 * @id iris/py7zr/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member name ("Path" / "WindowsPath" for
 *                   construction rows, "joinpath" / "relative_to" for
 *                   pipeline rows, "remove_relative_path_marker" /
 *                   "join" / "basename" / "splitext" / "relpath" /
 *                   "dirname" / "replace" for wrapper rows, "open" /
 *                   "CreateFileW" / "CreateJunction" / "mkdir" / "unlink" /
 *                   "touch" / "symlink_to" / "stat" / "lstat" / "exists" /
 *                   "is_dir" / "is_file" / "is_symlink" / "samefile" /
 *                   "utime" / "chmod" / "listdir" / "readlink" /
 *                   "GetFileAttributesW" for access rows, the function
 *                   name for file_api_def definition rows)
 *   4. flow_kind  - "path_ctor" (pathlib.Path()/WindowsPath()
 *                   construction), "path_join" (.joinpath(argument 0)
 *                   base join), "path_containment_check" (.relative_to
 *                   (argument 0) base-containment validation),
 *                   "path_wrapper" (remove_relative_path_marker /
 *                   os.path pure ops / entry-name separator rewrite),
 *                   "file_open" (open(...)/.open(...)/CreateFileW - the
 *                   path argument or receiver), "file_junction"
 *                   (_winapi.CreateJunction(argument 0 = link path;
 *                   argument 1 carries the archive-controlled target)),
 *                   "file_mkdir" (.mkdir - receiver is the path),
 *                   "file_unlink" (.unlink), "file_touch" (.touch),
 *                   "file_symlink" (.symlink_to(argument 0 = link target,
 *                   receiver = link path)), "file_stat" (.stat/.lstat/
 *                   .exists/.is_dir/.is_file/.is_symlink/.samefile,
 *                   os.stat, os.path.islink/exists, GetFileAttributesW),
 *                   "file_read" (os.listdir and the readlink family),
 *                   "file_utime" (os.utime(argument 0)),
 *                   "file_chmod" (.chmod - receiver is the path),
 *                   "file_api_def" (definition row of a path-consuming
 *                   internal API, carrying the path parameter position)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "path"/"outfilename"/"fileish"/
 *                   "fileish.parent"/"target_dir"/"target"/"f.origin"/
 *                   "self.fp"/"pathlib"/"os"/"_winapi" etc., or "" if
 *                   none; "<expr>" when the object expression is neither
 *                   Name nor Attribute; enclosing class name for
 *                   file_api_def rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "pathlib"/"os"/"os.path"/"builtins"/"_winapi"/
 *                   "py7zr.helpers" for the stdlib/wrapper channels
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for Path/open/joinpath/relative_to/
 *                   remove_relative_path_marker/os.* rows; argument 0 for
 *                   CreateJunction with the archive-controlled dst at
 *                   argument 1 documented in the family comment; -1 when
 *                   the receiver carries the path (.open/.mkdir/.unlink/
 *                   .touch/.chmod/stat-family rows); the parameter
 *                   position for file_api_def rows, including the self
 *                   slot)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): the sink core is the
 * FILE PATH PARAMETER of actual filesystem operations and the
 * path-pipeline nodes that directly determine the accessed file - the
 * pathlib channels (.open/.mkdir/.unlink/.touch/.symlink_to/.chmod/stat
 * family and the Path construction/join/containment pipeline feeding
 * them), the os.* channels (open/os.stat/os.utime/os.listdir/
 * os.readlink), the win32 channels (_winapi.CreateJunction,
 * CreateFileW, GetFileAttributesW), and the remove_relative_path_marker
 * wrapper - NOT every path string construction node (.as_posix(),
 * str(...), is_absolute() and drive.startswith() are pure and are
 * documented in detection.json uncoveredCases instead).
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no sink row is expected to resolve at API level:
 * all file access flows through pathlib instance members on local variables
 * (file/outfilename/fileish/path/target/src/f.origin) and os/_winapi module
 * attribute calls whose receivers cannot be bound to stdlib members by API
 * graphs (pathlib/os/_winapi are not part of the database - only the py7zr
 * tree is). Member-name matching is receiver-name-agnostic on purpose;
 * receiver hints are emitted for the labeling step, and name-collision noise
 * (a .stat()/.open() on a non-path object) is left to labeling - the
 * MemIO/NullIO duck-typed IO stubs in helpers.py:307-383 define
 * .open/.mkdir/.parent but contain no call sites, so they produce no rows.
 *
 * Excluded paths (applied to every row): /tests/, /py7zr-db/ (the CodeQL
 * database directory nested inside the source tree), /docs/. utils/ is
 * kept in scope (one literal-ish open() row in utils/bench_result.py:50
 * expected to be labeled none/FP).
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
  path.replaceAll("\\", "/").matches("%/py7zr-db/%")
  or
  path.replaceAll("\\", "/").matches("%/docs/%")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* -------------------------------------------------------------- */
  /* family 1: path_ctor - pathlib.Path(...) and pathlib.WindowsPath
     (...) constructor calls (all call sites use the `import pathlib`
     module-qualified form; no `from pathlib import Path` aliasing is
     observed in the package). Key sites: py7zr.py:542
     pathlib.Path(path) (str->Path of the caller output dir), :577
     pathlib.Path(os.getcwd()) (cwd base for the path=None branch), :580
     pathlib.Path(remove_relative_path_marker(outname)) (THE
     archive-entry-name construction for the path=None branch), :597
     pathlib.WindowsPath("\\\\?" + str(outfilename)) (Windows long-path
     prefixing of the joined archive-entry path), :830/:912
     pathlib.Path(arcname) (write-side archive-internal names), :1015
     Path(path) (writeall str->Path), :1026 Path(file) (write str->Path),
     :1343 pathlib.Path(omfp.read().decode("utf-8")) (the
     archive-controlled symlink target), :1427 Path(linkname)
     (write-side link target normalization); helpers.py:299 Path(res)
     (readlink result); win32compat.py:198 WindowsPath(rpath) (win32
     readlink result); cli.py:203 Path(target.parent, target.stem)
     (multivolume target; BOTH positional args carry path components -
     row reports arg 0), :399/:440 Path(sztarget) (CLI archive target),
     :415/:426/:447 Path(path) (CLI source names) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "Path" or func.getName() = "WindowsPath") and
    func.getObject().(Name).getId() = "pathlib" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "path_ctor" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "pathlib" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 2: path_join - .joinpath(argument 0) base joins:
     py7zr.py:582 path.joinpath(remove_relative_path_marker(outname)) -
     THE archive entry name joined onto the caller output dir, followed
     by the relative_to(path) containment check of family 3;
     py7zr.py:577 Path(os.getcwd()).joinpath(...) - the path=None branch
     equivalent; py7zr.py:731 path.joinpath(nm) - write-side directory
     walk join */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "joinpath" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "path_join" and
    callableName = "joinpath" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 3: path_containment_check - .relative_to(argument 0) base
     containment validation: py7zr.py:577
     Path(os.getcwd()).joinpath(...).relative_to(os.getcwd()) and :584
     outfilename.relative_to(path); a ValueError from these checks is
     converted to Bad7zFile (py7zr.py:578-579/:583-586) - the primary
     CWE-22 guard, applied AFTER joinpath on a name whose ".." segments
     survive remove_relative_path_marker */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "relative_to" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "path_containment_check" and
    callableName = "relative_to" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 4a: path_wrapper - remove_relative_path_marker(...) calls at
     py7zr.py:577/:580/:582; the helper (helpers.py:424-433) strips ONLY a
     leading "./" (RELATIVE_PATH_MARKER) and neither rejects ".." nor
     absolute paths - emitted as the custom path wrapper for the labeling
     step to judge as sanitizer-or-not */
  exists(Call c |
    c.getFunc().(Name).getId() = "remove_relative_path_marker" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "remove_relative_path_marker" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "py7zr.helpers" and
    matchKind = "ast"
  )
  or
  /* family 4b: path_wrapper - os.path pure path operations:
     py7zr.py:513 os.path.splitext(os.path.basename(basefilename))
     (basename extraction over the archive file's own name - fallback
     entry-name generation), :730 os.path.join(arcname, nm) (write-side
     archive-name join), :1432 os.path.relpath(linkname,
     os.path.dirname(targetname)) (write-side link target
     normalization) */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    base = func.getObject().(Attribute) and
    base.getName() = "path" and
    base.getObject().(Name).getId() = "os" and
    (func.getName() = "join" or func.getName() = "basename" or
     func.getName() = "splitext" or func.getName() = "relpath" or
     func.getName() = "dirname") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 4c: path_wrapper - the entry-name separator rewrite at
     archiveinfo.py:757: read_utf16(buffer).replace("\\", "/") - the
     attacker-controlled name gets Windows separators rewritten to posix
     separators at the decode boundary (mixed-separator evidence; this
     rewrites traversal-relevant semantics before the path pipeline;
     the path is the receiver, the arguments are literals) */
  exists(Call c, Attribute func, Call inner |
    func = c.getFunc().(Attribute) and
    func.getName() = "replace" and
    inner = func.getObject().(Call) and
    inner.getFunc().(Name).getId() = "read_utf16" and
    normalizedPathOf(c).matches("%/py7zr/archiveinfo.py") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "replace" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5a: file_open - builtin open(...) calls: py7zr.py:344/:346/
     :348/:350 (SevenZipFile.__init__ str-form archive open with the
     `file` parameter at argument 0), :1155 (is_7zfile str form), :1239
     (Worker.extract parallel branch re-open of the archive by
     getattr(fp, "name") filename), :1288 (Worker.extract_single opens a
     str fp argument), cli.py:301 (run_test opens args.arcfile),
     utils/bench_result.py:50 (dev script, argparse-provided results
     file - expected none/FP) */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    (normalizedPathOf(c).matches("%/py7zr/%") or normalizedPathOf(c).matches("%/utils/%")) and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* family 5b: file_open - pathlib .open(...) member calls (the receiver
     is the path): py7zr.py:358/:360/:362/:364 (SevenZipFile.__init__
     pathlib.Path-form archive open, mode rb/w+b/x+b/r+b), :1158
     (is_7zfile Path form, mode rb), :1349 fileish.open(mode="wb") - THE
     archive-content write sink, the path being the joined
     archive-entry path registered by register_filelike, :1359
     fileish.open() (empty-file branch), :1460 f.origin.open(mode="rb")
     (write-side source file read) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 5c: file_open - CreateFileW(target, ...) at
     win32compat.py:139 inside win32compat.readlink: opens a reparse
     point handle with FILE_FLAG_OPEN_REPARSE_POINT |
     FILE_FLAG_BACKUP_SEMANTICS; argument 0 is the path (a local name
     bound from the ctypes kernel32 WinDLL at win32compat.py:16) */
  exists(Call c |
    c.getFunc().(Name).getId() = "CreateFileW" and
    normalizedPathOf(c).matches("%/py7zr/win32compat.py") and
    node = c and
    flowKind = "file_open" and
    callableName = "CreateFileW" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6: file_junction - _winapi.CreateJunction(str(fileish), dst)
     at py7zr.py:1338: argument 0 is the archive-entry-controlled link
     path, argument 1 (dst) is the archive-controlled junction target
     decoded from the decompressed payload at :1333; the row reports
     argument 0 (the mapping of argument 1 is left to labeling) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "CreateJunction" and
    func.getObject().(Name).getId() = "_winapi" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "file_junction" and
    callableName = "CreateJunction" and
    argIndex = 0 and
    receiver = "_winapi" and
    moduleHint = "_winapi" and
    matchKind = "ast"
  )
  or
  /* family 7: file_mkdir - .mkdir(...) member calls (receiver is the
     path): py7zr.py:545 path.mkdir(parents=True) (caller output dir
     creation, EEXIST-tolerated), :625 target_dir.mkdir(parents=True)
     (archive-entry directory names), :1328
     fileish.parent.mkdir(parents=True, exist_ok=True) (archive-entry
     parent directories of extracted files; the MemIO/NullIO stub
     .mkdir definitions in helpers.py contain no calls) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "mkdir" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "file_mkdir" and
    callableName = "mkdir" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 8: file_unlink - .unlink() at py7zr.py:1336/:1346: deletion of
     a pre-existing file at the archive-entry-controlled link path
     before junction/symlink creation (exists() check at :1335/:1345 -
     TOCTOU window evidence) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "unlink" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "file_unlink" and
    callableName = "unlink" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 9: file_touch - fileish.touch() at py7zr.py:1357: creation of
     an empty file at the archive-entry-controlled path (emptystream
     entries) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "touch" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "file_touch" and
    callableName = "touch" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 10: file_symlink - fileish.symlink_to(sym_target) at
     py7zr.py:1347: receiver is the archive-entry-controlled link path,
     argument 0 is the archive-controlled link target decoded at :1343 -
     both sides attacker-controlled (CWE-23/36-style arbitrary link
     creation) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "symlink_to" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "file_symlink" and
    callableName = "symlink_to" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 11a: file_stat - pathlib metadata member calls (receiver is
     the path): py7zr.py:544/:549 path.exists()/.is_dir() (output dir
     check, EEXIST branch), :611 outfilename.exists(), :627/:629
     target_dir.is_dir()/:630 target_dir.is_file(), :668
     outfilename.stat() (readonly fallback), :722/:724/:726/:727
     path.is_symlink()/.is_file()/.is_dir()/samefile(".") (write-side
     walk), :834/:835/:837/:850/:853/:865/:866/:868/:883/:888/:894/:895/
     :898 target.lstat()/.is_symlink()/.stat()/.is_dir()/.is_file()
     (write-side _make_file_info, all platform branches), :932
     self.fp.stat() (MultiVolume archive stat), :1016/:1018
     path.exists()/.is_dir()/.is_file() (writeall validation - two calls
     on :1018), :1335/:1345 fileish.exists() (link pre-creation
     checks); cli.py:400/:441 target.exists(), :416/:427/:448
     src.is_dir() */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "stat" or func.getName() = "lstat" or
     func.getName() = "exists" or func.getName() = "is_dir" or
     func.getName() = "is_file" or func.getName() = "is_symlink" or
     func.getName() = "samefile") and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "file_stat" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 11b: file_stat - os.stat(...) at py7zr.py:936
     (ArchiveInfo construction over the archive file name) and
     cli.py:286 os.stat(archive.filename) (run_test listing) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "stat" and
    func.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "file_stat" and
    callableName = "stat" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 11c: file_stat - os.path.islink(...)/os.path.exists(...) at
     helpers.py:270/:302 (cross-platform islink/readlink support on the
     write-side link resolution path) */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    base = func.getObject().(Attribute) and
    base.getName() = "path" and
    base.getObject().(Name).getId() = "os" and
    (func.getName() = "islink" or func.getName() = "exists") and
    node = c and
    flowKind = "file_stat" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 11d: file_stat - GetFileAttributesW(str(path)) at
     win32compat.py:94 inside is_reparse_point: win32 attribute query
     with the path at argument 0 (local name bound from the kernel32
     WinDLL at win32compat.py:17) */
  exists(Call c |
    c.getFunc().(Name).getId() = "GetFileAttributesW" and
    normalizedPathOf(c).matches("%/py7zr/win32compat.py") and
    node = c and
    flowKind = "file_stat" and
    callableName = "GetFileAttributesW" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 12a: file_read - os.listdir(str(path)) at py7zr.py:729
     (write-side directory walk feeding _writeall recursion) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "listdir" and
    func.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "file_read" and
    callableName = "listdir" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 12b: file_read - the readlink family: helpers.py:292/:294
     os.readlink(path, dir_fd=...) (argument 0 is the path) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "readlink" and
    func.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "file_read" and
    callableName = "readlink" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 12c: file_read - helpers.py:304
     py7zr.win32compat.readlink(path) (module-qualified call; argument 0
     is the path) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "readlink" and
    func.getObject() instanceof Attribute and
    normalizedPathOf(c).matches("%/py7zr/helpers.py") and
    node = c and
    flowKind = "file_read" and
    callableName = "readlink" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 12d: file_read - helpers.py:290 path.readlink() (the path is
     the receiver, no positional arguments) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "readlink" and
    func.getObject().(Name).getId() = "path" and
    normalizedPathOf(c).matches("%/py7zr/helpers.py") and
    node = c and
    flowKind = "file_read" and
    callableName = "readlink" and
    argIndex = -1 and
    receiver = "path" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 12e: file_read - readlink(targetname) at py7zr.py:1422 (bare
     name imported from py7zr.helpers; argument 0 is the path, inside
     Worker._find_link_target write-side link resolution) */
  exists(Call c |
    c.getFunc().(Name).getId() = "readlink" and
    normalizedPathOf(c).matches("%/py7zr/py7zr.py") and
    node = c and
    flowKind = "file_read" and
    callableName = "readlink" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "py7zr.helpers" and
    matchKind = "ast"
  )
  or
  /* family 13: file_utime - os.utime(str(outfilename),
     times=(lastmodified, lastmodified)) at py7zr.py:659: the path at
     argument 0 is the joined archive-entry path; the timestamps come
     from the archive-supplied lastwritetime property */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "utime" and
    func.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "file_utime" and
    callableName = "utime" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 14: file_chmod - outfilename.chmod(...) at py7zr.py:663
     (archive-supplied posix_mode) and :668 (readonly mask over
     outfilename.stat()); the receiver is the joined archive-entry
     path */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "chmod" and
    normalizedPathOf(c).matches("%/py7zr/%") and
    node = c and
    flowKind = "file_chmod" and
    callableName = "chmod" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 15: file_api_def - definition rows of the library's own
     path-consuming internal APIs (candidates for summary/propagation
     labeling). Positions include the self slot for methods. */

  /* SevenZipFile._make_file_info(self, target, arcname, dereference) -
     target at position 1: the write-side source path whose
     lstat()/stat()/is_dir()/is_file() calls build the entry metadata
     (py7zr.py:826-906) */
  exists(Function fn, Parameter p |
    fn.getName() = "_make_file_info" and
    fn.getEnclosingScope().(Class).getName() = "SevenZipFile" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    p = fn.getArgByName("target") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "_make_file_info" and
    argIndex = p.getPosition() and
    receiver = "SevenZipFile" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* SevenZipFile._writeall(self, path, arcname) - path at position 1:
     the write-side directory walk (samefile/is_file/is_dir/listdir/
     joinpath at py7zr.py:720-740) */
  exists(Function fn, Parameter p |
    fn.getName() = "_writeall" and
    fn.getEnclosingScope().(Class).getName() = "SevenZipFile" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "_writeall" and
    argIndex = p.getPosition() and
    receiver = "SevenZipFile" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Worker.extract(self, fp, parallel, ...) - fp at position 1: the
     archive file pointer or str filename re-opened by open(filename,
     "rb") at py7zr.py:1239 / open(fp, "rb") at :1288 */
  exists(Function fn, Parameter p |
    fn.getName() = "extract" and
    fn.getEnclosingScope().(Class).getName() = "Worker" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    p = fn.getArgByName("fp") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "extract" and
    argIndex = p.getPosition() and
    receiver = "Worker" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Worker.extract_single(self, fp, files, ...) - fp at position 1: the
     str-form archive path opened by open(fp, "rb") at py7zr.py:1288 */
  exists(Function fn, Parameter p |
    fn.getName() = "extract_single" and
    fn.getEnclosingScope().(Class).getName() = "Worker" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    p = fn.getArgByName("fp") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "extract_single" and
    argIndex = p.getPosition() and
    receiver = "Worker" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Worker.register_filelike(self, id, fileish) - fileish at position 2:
     the joined archive-entry pathlib.Path (or MemIO) stored into
     target_filepath and later opened/mkdir'd/unlinked/touched by
     Worker._extract_single (py7zr.py:1298-1365) */
  exists(Function fn, Parameter p |
    fn.getName() = "register_filelike" and
    fn.getEnclosingScope().(Class).getName() = "Worker" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    p = fn.getArgByName("fileish") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "register_filelike" and
    argIndex = p.getPosition() and
    receiver = "Worker" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Worker._find_link_target(self, target) - target at position 1: the
     write-side link source path read by readlink(targetname) at
     py7zr.py:1422 */
  exists(Function fn, Parameter p |
    fn.getName() = "_find_link_target" and
    fn.getEnclosingScope().(Class).getName() = "Worker" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    p = fn.getArgByName("target") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "_find_link_target" and
    argIndex = p.getPosition() and
    receiver = "Worker" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* remove_relative_path_marker(path) - helpers.py:424, path at
     position 0: the './'-stripping wrapper applied to archive entry
     names at py7zr.py:577/:580/:582 (family 4a call rows) */
  exists(Function fn, Parameter p |
    fn.getName() = "remove_relative_path_marker" and
    normalizedPathOf(fn).matches("%/py7zr/helpers.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "remove_relative_path_marker" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* readlink(path, *, dir_fd) - helpers.py:280, path at position 0: the
     cross-platform os.readlink/Path.readlink/win32compat.readlink
     dispatcher (families 12b-12d call rows) */
  exists(Function fn, Parameter p |
    fn.getName() = "readlink" and
    normalizedPathOf(fn).matches("%/py7zr/helpers.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "readlink" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* readlink(path) - win32compat.py:96 (module-level inside the
     `if sys.platform == "win32":` block), path at position 0: opens the
     reparse point via CreateFileW (family 5c) and returns the decoded
     link target */
  exists(Function fn, Parameter p |
    fn.getName() = "readlink" and
    normalizedPathOf(fn).matches("%/py7zr/win32compat.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "readlink" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* is_reparse_point(path) - win32compat.py:91, path at position 0:
     queries GetFileAttributesW (family 11d) for the reparse-point
     attribute */
  exists(Function fn, Parameter p |
    fn.getName() = "is_reparse_point" and
    normalizedPathOf(fn).matches("%/py7zr/win32compat.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "is_reparse_point" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
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
