/**
 * @name py7zr CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   py7zr CodeQL database (snapshot 04e3af5a, py7zr ~0.20.0+ unreleased -
 *   the py7zr archive library itself is the audit target; there is no web
 *   surface, the untrusted boundary is the ARCHIVE CONTENT plus the
 *   argparse CLI): the 7z header entry-name decode family
 *   (read_utf16(buffer) whose return value is the raw attacker-supplied
 *   UTF-16LE entry name, and the f["filename"] dict store at
 *   archiveinfo.py:757 inside FilesInfo._read_name that also rewrites
 *   backslashes to forward slashes via .replace("\\", "/")); the
 *   entry-name property reads (f.filename / x.filename attribute reads at
 *   py7zr.py:560/:561/:565/:598 in SevenZipFile._extract - the duplicate
 *   check, the outname assignment and the targets filter that feed
 *   remove_relative_path_marker + path.joinpath path construction - plus
 *   :959 list(), :926 getnames lambda, :1316/:1353/:1362/:1375 in
 *   Worker._extract_single/_check, and cli.py:274 run_list output); the
 *   archive link-target content family (ofp.read() at py7zr.py:1333 whose
 *   decoded value becomes the _winapi.CreateJunction dst, and omfp.read()
 *   at :1343 whose decoded value becomes the fileish.symlink_to target -
 *   both read straight out of the decompressed archive payload); the CLI
 *   boundary (args.arcfile / args.odir / args.filenames attribute reads in
 *   cli.py run_list/run_test/run_extract/run_create/run_append, and the
 *   self.parser.parse_args(arg) boundary call at cli.py:96 whose Namespace
 *   return carries sys.argv when Cli.run() is invoked without arguments);
 *   and the library/CLI API parameter boundary (SevenZipFile.__init__ file,
 *   SevenZipFile._extract path/targets, extractall path, extract
 *   path/targets, read targets, writeall path, write file, is_7zfile file,
 *   unpack_7zarchive archive/path - the shutil.register_unpack_format hook
 *   where a caller-supplied archive+path pair is unpacked, pack_7zarchive
 *   base_name/base_dir, Cli.run arg) with true parameter positions.
 *   Operator-configured inputs that are NOT attacker-controlled (the
 *   archive file's own name self.filename and its basename fallback at
 *   py7zr.py:504-516, archive_info.filename, getpass passwords, the
 *   GITHUB_TOKEN env read in utils) are NOT emitted - documented in
 *   detection.json instead. Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose: @kind
 *   problem is the wrong shape for candidate tables and @kind table is not
 *   assumed to exist.
 * @id iris/py7zr/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (e.g. "read_utf16",
 *                   "filename", "read", "arcfile", "parse_args", or the
 *                   function name for parameter rows)
 *   4. flow_kind  - "archive_entry_name" (raw 7z header entry-name decode,
 *                   dict store, and ArchiveFile.filename property reads),
 *                   "archive_link_target" (decompressed junction/symlink
 *                   target content reads), "cli" (argparse Namespace field
 *                   reads and the parse_args boundary),
 *                   "param" (library/CLI API boundary parameters)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "f"/"x"/"ofp"/"omfp"/"args" etc., ""
 *                   when none, "self.parser" for the parse boundary row,
 *                   enclosing class name for parameter rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index when a call argument
 *                   carries the value (0 = the dict key position of the
 *                   f["filename"] store row); -1 when the receiver
 *                   attribute or the return value carries it; for "param"
 *                   rows the true parameter position in the function
 *                   definition, including the self slot for methods
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no source row is expected to resolve at API level:
 * the entry names, link targets, argparse fields and boundary parameters are
 * archive-derived or caller-injected values, not module members, so all
 * families below are AST-level matches and the match_kind column is kept
 * "ast" for cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (integration and unit test
 * trees), /py7zr-db/ (the CodeQL database directory sits inside the source
 * tree), /docs/. utils/ is kept in scope (benchmark/dev scripts; no source
 * rows are expected there - the GITHUB_TOKEN env read in
 * utils/github_comment_bench.py is a token, not a path, and is not matched).
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

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: raw entry-name decode origin - read_utf16(buffer) at
     archiveinfo.py:757 in FilesInfo._read_name; the return value is the
     attacker-supplied UTF-16LE entry name straight out of the 7z header
     bytes (the call is unique to this file/line; names are then stored via
     the dict-store row of family 2) */
  exists(Call c |
    c.getFunc().(Name).getId() = "read_utf16" and
    normalizedPathOf(c).matches("%/py7zr/archiveinfo.py") and
    node = c and
    flowKind = "archive_entry_name" and
    callableName = "read_utf16" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 2: entry-name dict store - f["filename"] = <decoded name> at
     archiveinfo.py:757; the Subscript assignment target is where the
     attacker-controlled name enters the file_info dicts that become
     ArchiveFile objects (read by SevenZipFile._extract through the
     f.filename property of family 3) */
  exists(AssignStmt a, Subscript s |
    s = a.getATarget() and
    s.getObject().(Name).getId() = "f" and
    s.getIndex().(StringLiteral).getText() = "filename" and
    normalizedPathOf(s).matches("%/py7zr/archiveinfo.py") and
    node = s and
    flowKind = "archive_entry_name" and
    callableName = "filename" and
    argIndex = 0 and
    receiver = "f" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 3: entry-name property reads - f.filename / x.filename
     attribute reads carrying archive entry names:
     py7zr.py:560 (duplicate-name check), :561 (outname = f.filename - THE
     value that flows into remove_relative_path_marker and
     path.joinpath), :565 (duplicate suffix construction), :598 (targets
     filter), :959 (list()), :1316/:1353/:1362/:1375 (worker progress and
     CrcError reporting), :926 (getnames lambda x.filename);
     cli.py:274 (run_list table output). The ArchiveFile.filename property
     itself is defined at py7zr.py:111-113. */
  exists(Attribute a |
    a.getName() = "filename" and
    (a.getObject().(Name).getId() = "f" or a.getObject().(Name).getId() = "x") and
    (normalizedPathOf(a).matches("%/py7zr/py7zr.py") or normalizedPathOf(a).matches("%/py7zr/cli.py")) and
    node = a and
    flowKind = "archive_entry_name" and
    callableName = "filename" and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 4: archive link-target content reads - ofp.read() at
     py7zr.py:1333 (junction branch: the decoded value becomes the dst of
     _winapi.CreateJunction(str(fileish), dst) at :1338) and omfp.read()
     at :1343 (symlink branch: the decoded value becomes sym_target of
     fileish.symlink_to(sym_target) at :1347); both streams are
     decompressed archive payload, so the link target is fully
     attacker-controlled (both where the link is created and what it
     points at) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "read" and
    (func.getObject().(Name).getId() = "ofp" or func.getObject().(Name).getId() = "omfp") and
    normalizedPathOf(c).matches("%/py7zr/py7zr.py") and
    node = c and
    flowKind = "archive_link_target" and
    callableName = "read" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5: CLI argument reads - args.arcfile (pathlib.Path-typed 7z
     archive path: cli.py:200 run_list, :297 run_test, :322 run_extract,
     :390 run_create, :434 run_append), args.odir (extraction output
     directory passed as a.extractall(path=args.odir) at cli.py:356),
     args.filenames (create/append source paths: cli.py:391/:435).
     Non-path fields (version/verbose/password/volume) are not matched. */
  exists(Attribute a |
    a.getObject().(Name).getId() = "args" and
    (a.getName() = "arcfile" or a.getName() = "odir" or a.getName() = "filenames") and
    normalizedPathOf(a).matches("%/py7zr/cli.py") and
    node = a and
    flowKind = "cli" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "args" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 6: the argparse parse boundary - self.parser.parse_args(arg) at
     cli.py:96 in Cli.run; when run() is invoked without arguments
     (py7zr/__main__.main -> cli.Cli().run()) arg is None and parse_args
     reads sys.argv; the returned Namespace carries all CLI input */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    func.getName() = "parse_args" and
    base = func.getObject().(Attribute) and
    base.getName() = "parser" and
    base.getObject().(Name).getId() = "self" and
    normalizedPathOf(c).matches("%/py7zr/cli.py") and
    node = c and
    flowKind = "cli" and
    callableName = "parse_args" and
    argIndex = -1 and
    receiver = "self.parser" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 7: library/CLI API boundary parameters (caller-provided values
     that may carry untrusted input when applications embed py7zr; the CLI
     handlers pass argparse values through these parameters). Positions
     include the self slot for methods. */

  /* SevenZipFile.__init__(self, file, mode, ...) - file at position 1;
     the str form is opened by open(file, ...) at py7zr.py:344-350, the
     pathlib.Path form by file.open(...) at :358-364 */
  exists(Function fn, Parameter p |
    fn.getName() = "__init__" and
    fn.getEnclosingScope().(Class).getName() = "SevenZipFile" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    p = fn.getArgByName("file") and
    node = p and
    flowKind = "param" and
    callableName = "__init__" and
    argIndex = p.getPosition() and
    receiver = "SevenZipFile" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* SevenZipFile._extract(self, path, targets, ...) - the internal
     extraction entry used by extractall/extract/read/readall;
     path (position 1) is the output base directory (mkdir at :545,
     joinpath base at :582, containment base at :584), targets
     (position 2) is the entry-name filter list */
  exists(Function fn, Parameter p |
    fn.getName() = "_extract" and
    fn.getEnclosingScope().(Class).getName() = "SevenZipFile" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    (p = fn.getArgByName("path") or p = fn.getArgByName("targets")) and
    node = p and
    flowKind = "param" and
    callableName = "_extract" and
    argIndex = p.getPosition() and
    receiver = "SevenZipFile" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* SevenZipFile.extractall(self, path, ...) - path at position 1 */
  exists(Function fn, Parameter p |
    fn.getName() = "extractall" and
    fn.getEnclosingScope().(Class).getName() = "SevenZipFile" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "param" and
    callableName = "extractall" and
    argIndex = p.getPosition() and
    receiver = "SevenZipFile" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* SevenZipFile.extract(self, path, targets) - positions 1 and 2 */
  exists(Function fn, Parameter p |
    fn.getName() = "extract" and
    fn.getEnclosingScope().(Class).getName() = "SevenZipFile" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    (p = fn.getArgByName("path") or p = fn.getArgByName("targets")) and
    node = p and
    flowKind = "param" and
    callableName = "extract" and
    argIndex = p.getPosition() and
    receiver = "SevenZipFile" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* SevenZipFile.read(self, targets) - targets at position 1 */
  exists(Function fn, Parameter p |
    fn.getName() = "read" and
    fn.getEnclosingScope().(Class).getName() = "SevenZipFile" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    p = fn.getArgByName("targets") and
    node = p and
    flowKind = "param" and
    callableName = "read" and
    argIndex = p.getPosition() and
    receiver = "SevenZipFile" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* SevenZipFile.writeall(self, path, arcname) - path at position 1 (the
     source tree to archive; arcname is archive-internal, not emitted) */
  exists(Function fn, Parameter p |
    fn.getName() = "writeall" and
    fn.getEnclosingScope().(Class).getName() = "SevenZipFile" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "param" and
    callableName = "writeall" and
    argIndex = p.getPosition() and
    receiver = "SevenZipFile" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* SevenZipFile.write(self, file, arcname) - file at position 1 (the
     source file to archive; Worker.write opens f.origin at py7zr.py:1460) */
  exists(Function fn, Parameter p |
    fn.getName() = "write" and
    fn.getEnclosingScope().(Class).getName() = "SevenZipFile" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    p = fn.getArgByName("file") and
    node = p and
    flowKind = "param" and
    callableName = "write" and
    argIndex = p.getPosition() and
    receiver = "SevenZipFile" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* is_7zfile(file) - module-level function, file at position 0; opened by
     open(file, "rb") at py7zr.py:1155 / file.open(mode="rb") at :1158 */
  exists(Function fn, Parameter p |
    fn.getName() = "is_7zfile" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    p = fn.getArgByName("file") and
    node = p and
    flowKind = "param" and
    callableName = "is_7zfile" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* unpack_7zarchive(archive, path, extra) - module-level function at
     py7zr.py:1167 registered with shutil.register_unpack_format();
     archive (position 0) is opened by SevenZipFile(archive) and path
     (position 1) becomes the extractall output base - a service-style
     entry where a caller-supplied archive+path pair meets archive content */
  exists(Function fn, Parameter p |
    fn.getName() = "unpack_7zarchive" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    (p = fn.getArgByName("archive") or p = fn.getArgByName("path")) and
    node = p and
    flowKind = "param" and
    callableName = "unpack_7zarchive" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* pack_7zarchive(base_name, base_dir, ...) - module-level function at
     py7zr.py:1176 registered with shutil.register_archive_format();
     base_name (position 0) becomes the "{}.7z" archive target name and
     base_dir (position 1) is the source tree written into it */
  exists(Function fn, Parameter p |
    fn.getName() = "pack_7zarchive" and
    normalizedPathOf(fn).matches("%/py7zr/py7zr.py") and
    (p = fn.getArgByName("base_name") or p = fn.getArgByName("base_dir")) and
    node = p and
    flowKind = "param" and
    callableName = "pack_7zarchive" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Cli.run(self, arg) - arg at position 1; None means parse_args falls
     back to sys.argv (py7zr/__main__.main -> cli.Cli().run()) */
  exists(Function fn, Parameter p |
    fn.getName() = "run" and
    fn.getEnclosingScope().(Class).getName() = "Cli" and
    normalizedPathOf(fn).matches("%/py7zr/cli.py") and
    p = fn.getArgByName("arg") and
    node = p and
    flowKind = "param" and
    callableName = "run" and
    argIndex = p.getPosition() and
    receiver = "Cli" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "source_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
