/**
 * @name aiohttp CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the
 *   aiohttp CodeQL database (snapshot 33ccdfb0, aiohttp 4.0.0a2.dev0 - the
 *   aiohttp framework itself is the audit target): pathlib path
 *   construction (Path(...) / pathlib.Path(...) constructor calls incl. the
 *   attacker-controlled Path(rel_url) at web_urldispatcher.py:637
 *   StaticResource._handle and the FileResponse ctor pathlib.Path(path) at
 *   web_fileresponse.py:54, the env-controlled Path(netrc_env) at
 *   helpers.py:200, the operator-config Path(directory) at
 *   web_urldispatcher.py:534, the basename-extraction Path(name) at
 *   helpers.py:360, and the literal __file__-relative constructions in
 *   helpers/examples/tools; .with_name(...) at web_fileresponse.py:134);
 *   the StaticResource path pipeline nodes (.joinpath(...) argument 0 at
 *   web_urldispatcher.py:577/:643 - attacker/caller-controlled filename
 *   joined onto the base directory; .resolve() canonicalization at
 *   :537/:577/:643; .relative_to(...) base-containment checks at
 *   :579/:645/:678/:686; the filename.anchor absolute-path guard read at
 *   :638; os.path.expanduser at :536); real file metadata and content
 *   access (.stat() / .is_file() / .is_dir() / .is_file() at
 *   web_fileresponse.py:136/:141, web_urldispatcher.py:538/:584/:657/:667,
 *   helpers.py:224; .open(...) calls at web_urldispatcher.py:587,
 *   cookiejar.py:107 WRITE / :112 READ, plus bare filepath.open / fobj.read
 *   method references submitted to loop.run_in_executor at
 *   web_fileresponse.py:288/:68/:74 and payload.py:300/:303/:348/:356
 *   (client upload payloads reading pre-opened file objects); builtin
 *   open(...) at
 *   examples/web_ws.py:21, tools/gen.py:170/:173,
 *   tools/bench-asyncio-write.py:131; .read() / .iterdir() content and
 *   directory-listing reads at web_urldispatcher.py:588/:683 and
 *   payload.py:279); the file-serving wrappers (FileResponse(filepath, ...)
 *   construction at web_urldispatcher.py:668 whose prepare() performs the
 *   stat/open/sendfile above; loop.sendfile(transport, fobj, ...) at
 *   web_fileresponse.py:93 with the file object at argument 1); file
 *   creation channels (tempfile.TemporaryFile() at web_request.py:726 -
 *   auto-named, content-only; loop.create_unix_server(server, path, ...)
 *   at web_runner.py:158 with the operator-configured socket path at
 *   argument 1); the netrc file read (netrc.netrc(str(netrc_path)) at
 *   helpers.py:218 with the path at argument 0); and definition rows for
 *   the library's own path-taking APIs (FileResponse.__init__ path,
 *   StaticResource.__init__ directory, UrlDispatcher.add_static path,
 *   CookieJar.save/load file_path, UnixSite.__init__ path) with the true
 *   parameter positions. Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose: @kind
 *   problem is the wrong shape for candidate tables and @kind table is
 *   assumed not to exist.
 * @id iris/aiohttp/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member name ("Path" / "with_name" for
 *                   construction rows, "joinpath" / "resolve" /
 *                   "relative_to" / "anchor" / "expanduser" for pipeline
 *                   rows, "open" / "stat" / "read" / "iterdir" /
 *                   "sendfile" / "TemporaryFile" / "create_unix_server" /
 *                   "netrc" for access rows, "FileResponse" for the
 *                   file-serving wrapper, the function name for
 *                   file_api_def definition rows)
 *   4. flow_kind  - "path_ctor" (Path()/pathlib.Path()/Path.home()/
 *                   .with_name() construction - the controlled value is the
 *                   constructed path), "path_join" (.joinpath(argument 0)
 *                   base join), "path_resolve" (.resolve() canonicalization
 *                   - propagation/validation node), "path_containment_check"
 *                   (.relative_to(argument 0) base-containment validation),
 *                   "path_guard" (filename.anchor absolute-path guard
 *                   read), "path_expand" (os.path.expanduser(argument 0)),
 *                   "file_open" (.open(...)/open(...) call - argument 0
 *                   carries the path; mode 'rb' read / 'wb' write noted via
 *                   receiver/moduleHint context), "file_open_ref" (bare
 *                   .open/.read/.seek method reference submitted to an
 *                   executor), "file_stat" (.stat()/.is_file()/.is_dir()/
 *                   .is_file()), "file_read" (.read()/.iterdir()/
 *                   netrc.netrc(argument 0) content and listing reads),
 *                   "file_response" (FileResponse(argument 0) - file access
 *                   follows from construction), "file_send"
 *                   (loop.sendfile(argument 1) - file object),
 *                   "file_create" (loop.create_unix_server(argument 1)),
 *                   "file_create_temp" (tempfile.TemporaryFile() - name NOT
 *                   attacker-controlled), "file_api_def" (definition row of
 *                   a library path-taking API, carrying the path parameter
 *                   position)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "filepath"/"self._directory"/"gzip_path"/
 *                   "file_path"/"loop"/"tempfile"/"netrc" etc., or "" if
 *                   none; "<expr>" when the object expression is neither
 *                   Name nor Attribute; enclosing class name for
 *                   file_api_def rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "pathlib"/"os.path"/"builtins"/"netrc" for the
 *                   stdlib-channel families
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for Path/open/joinpath/relative_to/
 *                   expanduser/FileResponse/netrc rows; argument 1 for
 *                   sendfile/create_unix_server rows; the parameter
 *                   position for file_api_def rows, including the self
 *                   slot), -1 for stat/resolve/guard/read/ref rows
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
 * pathlib channels (.open/.stat/.iterdir and the Path construction/join/
 * resolve/containment pipeline feeding them), the FileResponse wrapper
 * whose prepare() performs stat+open+sendfile, the netrc read, the
 * sendfile/create_unix_server file-object arguments - NOT every path
 * string construction node (yarl URL building, mimetypes.guess_type, and
 * plain string formatting are not emitted; the pathlib `/` operator
 * cannot be distinguished from numeric division syntactically and is
 * documented in detection.json uncoveredCases instead).
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no sink row is expected to resolve at API level:
 * all file access flows through pathlib instance members on local variables
 * (filepath / self._path / self._directory / file_path / netrc_path) whose
 * receiver types cannot be bound to the stdlib pathlib module by API graphs
 * (pathlib is not part of the database). Member-name matching is
 * receiver-name-agnostic on purpose; receiver hints are emitted for the
 * labeling step, and name-collision noise (a .resolve()/.read() on a
 * non-path/non-file object) is left to labeling.
 *
 * Excluded paths (applied to every row): /tests/, /aiohttp-db/ (the CodeQL
 * database directory nested inside the source tree), /docs/, /node_modules/.
 * examples/ and tools/ are kept in scope (literal-path rows expected to be
 * labeled none/FP).
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
  path.replaceAll("\\", "/").matches("%/aiohttp-db/%")
  or
  path.replaceAll("\\", "/").matches("%/docs/%")
  or
  path.replaceAll("\\", "/").matches("%/node_modules/%")
}

/* ------------------------------------------------------------------ */
/* Shared aiohttp shapes (kept consistent with sources.ql)              */
/* ------------------------------------------------------------------ */

/** pathlib stat-family members performing real file metadata access
 *  (os.stat under the hood). */
private predicate pathStatMember(string member) {
  member = "stat"
  or
  member = "is_file"
  or
  member = "is_dir"
  or
  member = "exists"
}

/** Bare method-reference names that, when submitted to an executor,
 *  perform real file operations (web_fileresponse.py:66 fobj.seek /
 *  :68/:74 fobj.read / :288 filepath.open). */
private predicate fileMethodRefName(string name) {
  name = "open"
  or
  name = "read"
  or
  name = "seek"
}

/** The library's own path-taking API definitions with their path parameter
 *  (class, function, parameter name, file) - definition rows for the
 *  file_api_def family. */
private predicate fileApiDefShape(Function f, Parameter p) {
  /* FileResponse.__init__(self, path: PathLike, ...) - web_fileresponse.py:44 */
  f.getName() = "__init__" and
  f.getEnclosingScope().(Class).getName() = "FileResponse" and
  normalizedPathOf(f).matches("%/aiohttp/web_fileresponse.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* StaticResource.__init__(self, prefix, directory: PathLike, ...) -
     web_urldispatcher.py:520 (operator-configured base directory) */
  f.getName() = "__init__" and
  f.getEnclosingScope().(Class).getName() = "StaticResource" and
  normalizedPathOf(f).matches("%/aiohttp/web_urldispatcher.py") and
  p.getName() = "directory" and
  p = f.getAnArg()
  or
  /* UrlDispatcher.add_static(self, prefix, path: PathLike, ...) -
     web_urldispatcher.py:1135 (the app-facing static mount entry) */
  f.getName() = "add_static" and
  f.getEnclosingScope().(Class).getName() = "UrlDispatcher" and
  normalizedPathOf(f).matches("%/aiohttp/web_urldispatcher.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* CookieJar.save(self, file_path: PathLike) / CookieJar.load(...) -
     cookiejar.py:105/:110 (operator-configured persistence paths) */
  (f.getName() = "save" or f.getName() = "load") and
  f.getEnclosingScope().(Class).getName() = "CookieJar" and
  normalizedPathOf(f).matches("%/aiohttp/cookiejar.py") and
  p.getName() = "file_path" and
  p = f.getAnArg()
  or
  /* UnixSite.__init__(self, runner, path: PathLike, ...) -
     web_runner.py:131 (operator-configured unix socket path) */
  f.getName() = "__init__" and
  f.getEnclosingScope().(Class).getName() = "UnixSite" and
  normalizedPathOf(f).matches("%/aiohttp/web_runner.py") and
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
  /* family 1: pathlib.Path(...) constructor calls - both the
     `from pathlib import Path` Name form (web_urldispatcher.py:534
     Path(directory) operator-config, :637 Path(rel_url) ATTACKER-CONTROLLED
     static-file filename, helpers.py:200 Path(netrc_env) env-controlled,
     :360 Path(name) basename extraction, tools/cleanup_changes.py:28,
     tools/check_changes.py Path(argv[0])) and the `import pathlib`
     Attribute form (web_fileresponse.py:54 pathlib.Path(path) FileResponse
     ctor - receives the checked filepath at web_urldispatcher.py:668;
     cookiejar.py:106/:112 operator-config; examples/fake_server.py:55,
     examples/static_files.py:7); argument 0 carries the path */
  exists(Call c |
    (
      c.getFunc().(Name).getId() = "Path"
      or
      c.getFunc().(Attribute).getName() = "Path" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "pathlib"
    ) and
    node = c and
    flowKind = "path_ctor" and
    callableName = "Path" and
    argIndex = 0 and
    receiver = receiverHintOfPathCtor(c) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 1b: Path.home() class construction (helpers.py:203 - the netrc
     default directory; no argument). helpers.py imports Path via
     `from pathlib import Path`, so the qualifier is the bare Name `Path`;
     the `pathlib.Path.home` Attribute form is matched too for
     robustness. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "home" and
    (
      func.getObject().(Name).getId() = "Path"
      or
      func.getObject().(Attribute).getName() = "Path" and
      func.getObject().(Attribute).getObject().(Name).getId() = "pathlib"
    ) and
    node = c and
    flowKind = "path_ctor" and
    callableName = "home" and
    argIndex = -1 and
    receiver = "Path" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 2: .with_name(...) sibling-path construction
     (web_fileresponse.py:134 gzip_path = filepath.with_name(filepath.name +
     ".gz") - the compressed sibling lookup path; argument 0 carries the
     appended name) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "with_name" and
    node = c and
    flowKind = "path_ctor" and
    callableName = "with_name" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: .joinpath(...) base-directory joins - web_urldispatcher.py:643
     filepath = self._directory.joinpath(filename).resolve()
     (StaticResource._handle: argument 0 is the attacker-controlled
     filename Path) and :577 (url_for: caller-supplied filename);
     argument 0 carries the joined relative path */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "joinpath" and
    node = c and
    flowKind = "path_join" and
    callableName = "joinpath" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 4: .resolve() canonicalization - web_urldispatcher.py:537
     (StaticResource ctor), :577 and :643 (the pipeline:
     joinpath(filename).resolve()); receiver-agnostic member match, the
     canonicalized path is the propagation/validation result */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "resolve" and
    node = c and
    flowKind = "path_resolve" and
    callableName = "resolve" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5: .relative_to(...) base-containment validation -
     web_urldispatcher.py:645 (the StaticResource._handle guard),
     web_urldispatcher.py:579 (url_for guard), :678/:686 (listing code);
     argument 0 carries the allowed base directory */
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
  /* family 6: filename.anchor absolute-path guard read -
     web_urldispatcher.py:638 `if filename.anchor: raise HTTPForbidden()`
     - the ONLY absolute-path defense in the static-file pipeline (empty
     for pure-relative ../ traversal strings) */
  exists(Attribute a |
    a.getName() = "anchor" and
    node = a and
    flowKind = "path_guard" and
    callableName = "anchor" and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 7: os.path.expanduser(...) - web_urldispatcher.py:536
     (StaticResource ctor: expands ~-prefixed operator directories);
     argument 0 carries the path */
  exists(Call c, Attribute func, Attribute mid |
    func = c.getFunc().(Attribute) and
    func.getName() = "expanduser" and
    mid = func.getObject().(Attribute) and
    mid.getName() = "path" and
    mid.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "path_expand" and
    callableName = "expanduser" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 8: .open(...) member calls - web_urldispatcher.py:587
     filepath.open("rb") (url_for hash read), cookiejar.py:107
     file_path.open(mode="wb") (cookie persistence WRITE) and :112
     file_path.open(mode="rb") (pickle load read), tools/gen.py:170/:173
     (folder / literal).open("w"); argument 0 carries the path (mode is
     passed positionally at :587 and as keyword mode= at cookiejar) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 9: builtin open(...) Name calls - examples/web_ws.py:21
     open(WS_FILE, "rb"), tools/bench-asyncio-write.py:131
     open("bench.md", "w"); argument 0 carries the path */
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
  /* family 10: bare file-method references (NOT the func of a call)
     submitted to loop.run_in_executor - web_fileresponse.py:288
     filepath.open (opened "rb" for serving), :66 fobj.seek, :68/:74
     fobj.read (chunked sendfile fallback), payload.py:300/:303/:348/:356
     self._value.read (client upload payload reading a pre-opened file
     object). Restricted to the file-content modules so socket-stream
     self-references (streams.py:624 self.read) do not produce noise; the
     method executes against the file object, argument none */
  exists(Attribute a |
    fileMethodRefName(a.getName()) and
    not exists(Call c | a = c.getFunc()) and
    (
      normalizedPathOf(a).matches("%/aiohttp/web_fileresponse.py")
      or
      normalizedPathOf(a).matches("%/aiohttp/payload.py")
      or
      normalizedPathOf(a).matches("%/aiohttp/web_urldispatcher.py")
      or
      normalizedPathOf(a).matches("%/aiohttp/cookiejar.py")
      or
      normalizedPathOf(a).matches("%/aiohttp/helpers.py")
    ) and
    node = a and
    flowKind = "file_open_ref" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 11: pathlib stat family - .stat()/.is_file()/.is_dir()/
     .exists() calls: web_fileresponse.py:136 gzip_path.stat(), :141
     filepath.stat() (FileResponse.prepare, executed in a thread),
     web_urldispatcher.py:538 directory.is_dir(), :584/:667
     filepath.is_file(), :657 filepath.is_dir(), helpers.py:224
     netrc_path.is_file(); receiver-agnostic member match */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    pathStatMember(func.getName()) and
    node = c and
    flowKind = "file_stat" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 12: content/listing reads - .read() calls in the
     file-content modules (web_urldispatcher.py:588 f.read() after
     filepath.open("rb"); payload.py:279 value.read() - client upload
     payload reading a pre-opened file object) and .iterdir() directory
     listing (web_urldispatcher.py:683 filepath.iterdir() in
     _directory_as_html show_index listing) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "read" and
    (
      normalizedPathOf(c).matches("%/aiohttp/web_urldispatcher.py")
      or
      normalizedPathOf(c).matches("%/aiohttp/payload.py")
    ) and
    node = c and
    flowKind = "file_read" and
    callableName = "read" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "iterdir" and
    node = c and
    flowKind = "file_read" and
    callableName = "iterdir" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 13: FileResponse(...) construction - web_urldispatcher.py:668
     FileResponse(filepath, chunk_size=...): the containment-checked
     filepath at argument 0; FileResponse.prepare() performs the
     stat/open/sendfile access (family 11/10/14 rows) */
  exists(Call c |
    c.getFunc().(Name).getId() = "FileResponse" and
    node = c and
    flowKind = "file_response" and
    callableName = "FileResponse" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 14: loop.sendfile(transport, fobj, offset, count) -
     web_fileresponse.py:93: file content transmission from the
     already-open file object at argument 1 */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "sendfile" and
    node = c and
    flowKind = "file_send" and
    callableName = "sendfile" and
    argIndex = 1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 15: tempfile.TemporaryFile() - web_request.py:726 in
     request.post(): the multipart upload content sink; the name is
     auto-generated (NOT attacker-controlled) - emitted so labeling can
     classify the upload-content channel as name-safe */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "TemporaryFile" and
    func.getObject().(Name).getId() = "tempfile" and
    node = c and
    flowKind = "file_create_temp" and
    callableName = "TemporaryFile" and
    argIndex = -1 and
    receiver = "tempfile" and
    moduleHint = "tempfile" and
    matchKind = "ast"
  )
  or
  /* family 16: loop.create_unix_server(server, self._path, ...) -
     web_runner.py:158: unix socket file creation with the
     operator-configured path at argument 1 */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "create_unix_server" and
    node = c and
    flowKind = "file_create" and
    callableName = "create_unix_server" and
    argIndex = 1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 17: netrc.netrc(str(netrc_path)) - helpers.py:218: the netrc
     parser reads the file designated by the NETRC env var (or the home
     default) at argument 0 */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "netrc" and
    func.getObject().(Name).getId() = "netrc" and
    node = c and
    flowKind = "file_read" and
    callableName = "netrc" and
    argIndex = 0 and
    receiver = "netrc" and
    moduleHint = "netrc" and
    matchKind = "ast"
  )
  or
  /* family 18: file_api_def definition rows - the library's own
     path-taking API definitions with the true path parameter position:
     FileResponse.__init__(path) web_fileresponse.py:46,
     StaticResource.__init__(directory) web_urldispatcher.py:523,
     UrlDispatcher.add_static(path) web_urldispatcher.py:1138,
     CookieJar.save(file_path) / CookieJar.load(file_path)
     cookiejar.py:105/:110, UnixSite.__init__(path) web_runner.py:134;
     arg_index is the 0-based parameter position including the self slot */
  exists(Function f, Parameter p |
    fileApiDefShape(f, p) and
    not p.isSelf() and
    node = p and
    flowKind = "file_api_def" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = f.getEnclosingScope().(Class).getName() and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
}

/** Receiver hint for a Path constructor call (the syntactic qualifier of
 *  `Path` / `pathlib.Path`: "" for the bare Name form, "pathlib" for the
 *  Attribute form). */
string receiverHintOfPathCtor(Call c) {
  c.getFunc() instanceof Name and result = ""
  or
  exists(Attribute a |
    a = c.getFunc().(Attribute) and
    a.getName() = "Path" and
    result = receiverHint(a)
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
