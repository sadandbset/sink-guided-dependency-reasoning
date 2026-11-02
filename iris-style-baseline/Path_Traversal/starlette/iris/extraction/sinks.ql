/**
 * @name starlette CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the
 *   starlette CodeQL database (snapshot 24c1fac6, starlette 0.26.1 - the
 *   starlette ASGI framework itself is the audit target): the StaticFiles
 *   path pipeline (os.path.join at staticfiles.py:111 - argument 0 is the
 *   starred split of the ATTACKER-controlled scope["path"] - :136
 *   (argument 0 = the get_path output), :166 in lookup_path (argument 1
 *   = the attacker path joined onto the base directory), :83
 *   (operator-config package statics dir); os.path.normpath at :111 -
 *   the '..'/'.'-collapsing node acting on the scope path - and :82;
 *   os.path.abspath at :168 (the follow_symlink=True branch with NO
 *   containment check) and os.path.realpath at :170/:171 (the
 *   follow_symlink=False branch); the os.path.commonprefix([full_path,
 *   directory]) base-containment check at :172); real file metadata and
 *   content access (os.stat(full_path) at staticfiles.py:177;
 *   anyio.to_thread.run_sync(os.stat, self.path/self.directory) at
 *   staticfiles.py:209 and responses.py:335 - argument 1 carries the
 *   path; os.path.isdir/isfile at staticfiles.py:56/:85 and config.py:62;
 *   anyio.open_file(self.path, mode="rb") at responses.py:353 - THE
 *   actual serving open, path at argument 0 - and the file.read(
 *   chunk_size) chunked transmission at :356; builtin open(file_name)
 *   at config.py:121); the lookup_path offload wrapper
 *   (anyio.to_thread.run_sync(self.lookup_path, path) at
 *   staticfiles.py:121/:137/:150 - argument 1 carries the path, the
 *   method performs join/realpath/commonprefix/os.stat); the
 *   file-serving wrappers (FileResponse(full_path, ...) construction at
 *   staticfiles.py:154/:192 - argument 0 - whose __call__ performs the
 *   re-stat and anyio.open_file above; jinja2.FileSystemLoader(directory)
 *   and env.get_template(name) at templating.py:85/:94/:112 - the
 *   template-loading channel, operator/application input); the multipart
 *   upload storage (SpooledTemporaryFile at formparsers.py:207 -
 *   auto-named, NOT attacker-controlled; part.file.write(data)/seek(0)
 *   at :263/:266; UploadFile self.file.write/read/seek/close direct
 *   calls and run_in_threadpool(self.file.write/read/seek/close, ...)
 *   executor submissions at datastructures.py:465-484); os.fspath(url) at
 *   responses.py:35; and definition rows for the library's own
 *   path-taking APIs (FileResponse.__init__ path, StaticFiles.__init__
 *   directory, StaticFiles.get_response path, StaticFiles.lookup_path
 *   path, StaticFiles.file_response full_path,
 *   Jinja2Templates.__init__ directory, Jinja2Templates.get_template
 *   name, Jinja2Templates.TemplateResponse name, Config.__init__
 *   env_file, Config._read_file file_name, UploadFile.__init__
 *   filename) with the true parameter positions. Raw BQRS extraction
 *   query: run with `codeql query run` and decode with `codeql bqrs
 *   decode` (not database analyze). This is a plain multi-column select
 *   query on purpose: @kind problem is the wrong shape for candidate
 *   tables and @kind table is not assumed to exist.
 * @id iris/starlette/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member name ("join" / "normpath" / "abspath"
 *                   / "realpath" / "commonprefix" / "stat" / "isdir" /
 *                   "isfile" / "run_sync" / "open_file" / "open" /
 *                   "read" / "FileResponse" / "FileSystemLoader" /
 *                   "get_template" / "SpooledTemporaryFile" / "write" /
 *                   "seek" / "close" / "fspath" / "run_in_threadpool",
 *                   the function name for file_api_def definition rows)
 *   4. flow_kind  - "path_join" (os.path.join - argument carrying the
 *                   attacker-influenced path per site), "path_normalize"
 *                   (os.path.normpath - the '..'-collapsing
 *                   propagation/validation node), "path_resolve"
 *                   (os.path.abspath / os.path.realpath
 *                   canonicalization), "path_containment_check"
 *                   (os.path.commonprefix base-containment validation),
 *                   "path_ctor" (os.fspath path conversion),
 *                   "file_open" (anyio.open_file / builtin open -
 *                   argument 0 carries the path), "file_stat"
 *                   (os.stat / os.path.isdir / os.path.isfile /
 *                   run_sync(os.stat, ...) - metadata access),
 *                   "file_lookup" (run_sync(self.lookup_path, ...) - the
 *                   wrapper performing join/realpath/containment/stat),
 *                   "file_read" (file.read / get_template - content and
 *                   template loads), "file_write" (part.file.write /
 *                   self.file.write upload-content writes),
 *                   "file_close" (self.file.close), "file_response"
 *                   (FileResponse(argument 0) - file access follows from
 *                   construction), "file_loader" (jinja2
 *                   FileSystemLoader(argument 0)), "file_create_temp"
 *                   (SpooledTemporaryFile() - name NOT
 *                   attacker-controlled), "file_api_def" (definition row
 *                   of a library path-taking API, carrying the path
 *                   parameter position)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "os.path" / "anyio" /
 *                   "anyio.to_thread" / "self" / "part.file" /
 *                   "self.file" / "file" / "jinja2" / "self.env" /
 *                   "self" etc., or "" if none; enclosing class name for
 *                   file_api_def rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "os.path" / "os" / "anyio" / "anyio.to_thread"
 *                   / "jinja2" / "tempfile" / "starlette.concurrency"
 *                   for the stdlib/external-channel families
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for join-in-get_path/get_response/
 *                   normpath/abspath/realpath/commonprefix/fspath/stat/
 *                   isdir/isfile/open_file/open/FileResponse/
 *                   FileSystemLoader/get_template; argument 1 for the
 *                   run_sync rows - the slot after the function object;
 *                   argument 1 for join-in-lookup_path where the
 *                   attacker path is joined onto the base directory; the
 *                   parameter position for file_api_def rows, including
 *                   the self slot; -1 for SpooledTemporaryFile and the
 *                   method-reference-style rows where the file object is
 *                   the receiver rather than an argument)
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
 * os.path join/normpath/realpath/commonprefix pipeline feeding
 * os.stat/anyio.open_file in the StaticFiles serving path, the
 * FileResponse wrapper whose __call__ performs the re-stat and
 * anyio.open_file, the lookup_path run_sync offload, the jinja2
 * template-loading wrappers, the config env-file open and the multipart
 * upload storage channels - NOT every path string construction node
 * (URL f-string building in datastructures.py:44-56, mimetypes.guess_type
 * at responses.py:36/:303 and string formatting are not emitted; the
 * requests.py cookie parsing and scope dict writes are not sinks).
 *
 * Note: this file defines no QL classes (only predicates and functions),
 * does not assign API::Node values to DataFlow::Node variables, keeps
 * every variable bound through a positive body, and keeps resolved-API
 * matching strictly separate from AST syntax matching (the match_kind
 * column records which one produced a row). In this project no sink row
 * is expected to resolve at API level: the os.path/anyio/jinja2 members
 * are matched by their syntactic module-qualified Attribute chains
 * (os / anyio / jinja2 are external modules not part of the database),
 * and the instance-member channels (file.read / part.file.write /
 * self.file.write) flow through local variables whose receiver types
 * cannot be bound by API graphs. The match_kind column is kept "ast"
 * for cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (the test tree covered
 * by the database snapshot) and /starlette-db/ (the CodeQL database
 * directory nested inside the source tree). No other tree carries
 * candidate rows (the database snapshot covers only starlette/ and
 * tests/).
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
  path.replaceAll("\\", "/").matches("%/starlette-db/%")
}

/* ------------------------------------------------------------------ */
/* Shared starlette shapes (kept consistent with sources.ql)            */
/* ------------------------------------------------------------------ */

/** True iff the func expression of a call is the member `member` reached
 *  through `os.path` (os.path.join / os.path.normpath / os.path.abspath /
 *  os.path.realpath / os.path.commonprefix / os.path.isdir /
 *  os.path.isfile / os.path.fspath). */
private predicate osPathFunc(Expr func, string member) {
  func.(Attribute).getName() = member and
  func.(Attribute).getObject().(Attribute).getName() = "path" and
  func.(Attribute).getObject().(Attribute).getObject().(Name).getId() = "os"
}

/** True iff the func expression of a call is `anyio.to_thread.run_sync`. */
private predicate anyioRunSyncFunc(Expr func) {
  func.(Attribute).getName() = "run_sync" and
  func.(Attribute).getObject().(Attribute).getName() = "to_thread" and
  func.(Attribute).getObject().(Attribute).getObject().(Name).getId() = "anyio"
}

/** Instance-member file-operation names on the upload storage channels
 *  (write/read/seek/close on self.file in datastructures.py and
 *  part.file in formparsers.py). */
private predicate uploadFileMember(string member) {
  member = "write"
  or
  member = "read"
  or
  member = "seek"
  or
  member = "close"
}

/** The library's own path-taking API definitions with their path parameter
 *  (class, function, parameter name, file) - definition rows for the
 *  file_api_def family. */
private predicate fileApiDefShape(Function f, Parameter p) {
  /* FileResponse.__init__(self, path: Union[str, os.PathLike[str]], ...) -
     responses.py:286 (the serving path; __call__ stats and opens it) */
  f.getName() = "__init__" and
  f.getEnclosingScope().(Class).getName() = "FileResponse" and
  normalizedPathOf(f).matches("%/starlette/responses.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* StaticFiles.__init__(self, *, directory: PathLike = None, ...) -
     staticfiles.py:39 (the operator-configured base directory) */
  f.getName() = "__init__" and
  f.getEnclosingScope().(Class).getName() = "StaticFiles" and
  normalizedPathOf(f).matches("%/starlette/staticfiles.py") and
  p.getName() = "directory" and
  p = f.getAnArg()
  or
  /* StaticFiles.get_response(self, path: str, scope: Scope) -
     staticfiles.py:113 (receives the get_path output built from
     scope["path"]) */
  f.getName() = "get_response" and
  f.getEnclosingScope().(Class).getName() = "StaticFiles" and
  normalizedPathOf(f).matches("%/starlette/staticfiles.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* StaticFiles.lookup_path(self, path: str) - staticfiles.py:162 (the
     join/realpath/containment/stat worker receiving the request path) */
  f.getName() = "lookup_path" and
  f.getEnclosingScope().(Class).getName() = "StaticFiles" and
  normalizedPathOf(f).matches("%/starlette/staticfiles.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* StaticFiles.file_response(self, full_path: PathLike, ...) -
     staticfiles.py:182 (the looked-up path passed to FileResponse) */
  f.getName() = "file_response" and
  f.getEnclosingScope().(Class).getName() = "StaticFiles" and
  normalizedPathOf(f).matches("%/starlette/staticfiles.py") and
  p.getName() = "full_path" and
  p = f.getAnArg()
  or
  /* Jinja2Templates.__init__(self, directory: Union[str, PathLike], ...) -
     templating.py:65 (the operator-configured template root handed to
     jinja2.FileSystemLoader) */
  f.getName() = "__init__" and
  f.getEnclosingScope().(Class).getName() = "Jinja2Templates" and
  normalizedPathOf(f).matches("%/starlette/templating.py") and
  p.getName() = "directory" and
  p = f.getAnArg()
  or
  /* Jinja2Templates.get_template(self, name: str) - templating.py:93
     (the template name handed to env.get_template) */
  f.getName() = "get_template" and
  f.getEnclosingScope().(Class).getName() = "Jinja2Templates" and
  normalizedPathOf(f).matches("%/starlette/templating.py") and
  p.getName() = "name" and
  p = f.getAnArg()
  or
  /* Jinja2Templates.TemplateResponse(self, name: str, context: dict, ...) -
     templating.py:96 (the app-facing template name entry) */
  f.getName() = "TemplateResponse" and
  f.getEnclosingScope().(Class).getName() = "Jinja2Templates" and
  normalizedPathOf(f).matches("%/starlette/templating.py") and
  p.getName() = "name" and
  p = f.getAnArg()
  or
  /* Config.__init__(self, env_file: Union[str, Path] = None, ...) -
     config.py:53 (the operator-configured env file path) */
  f.getName() = "__init__" and
  f.getEnclosingScope().(Class).getName() = "Config" and
  normalizedPathOf(f).matches("%/starlette/config.py") and
  p.getName() = "env_file" and
  p = f.getAnArg()
  or
  /* Config._read_file(self, file_name: Union[str, Path]) - config.py:119
     (opens the env file at config.py:121) */
  f.getName() = "_read_file" and
  f.getEnclosingScope().(Class).getName() = "Config" and
  normalizedPathOf(f).matches("%/starlette/config.py") and
  p.getName() = "file_name" and
  p = f.getAnArg()
  or
  /* UploadFile.__init__(self, file: BinaryIO, *, size=None, filename:
     Optional[str] = None, ...) - datastructures.py:437 (the wrapper
     storing the attacker-controlled multipart filename - position 3
     including the self slot; the filename never reaches a filesystem
     path inside this tree) */
  f.getName() = "__init__" and
  f.getEnclosingScope().(Class).getName() = "UploadFile" and
  normalizedPathOf(f).matches("%/starlette/datastructures.py") and
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
  /* family 1: os.path.join(...) base-directory joins - per-site argument
     index resolved through the enclosing function:
     staticfiles.py:111 in get_path: os.path.join(*scope["path"].split("/"))
     - argument 0 is the starred split of the ATTACKER-controlled scope
     path; :136 in get_response: os.path.join(path, "index.html") -
     argument 0 is the get_path output (attacker-influenced);
     :166 in lookup_path: os.path.join(directory, path) - argument 1 is
     the attacker path joined onto the base directory;
     :83 in get_directories: os.path.join(spec.origin, "..",
     statics_dir) - argument 0 (operator-config package statics dir) */
  exists(Call c |
    osPathFunc(c.getFunc(), "join") and
    normalizedPathOf(c).matches("%/starlette/staticfiles.py") and
    node = c and
    flowKind = "path_join" and
    callableName = "join" and
    (
      c.getScope().(Function).getName() = "get_path" and argIndex = 0
      or
      c.getScope().(Function).getName() = "get_response" and argIndex = 0
      or
      c.getScope().(Function).getName() = "lookup_path" and argIndex = 1
      or
      c.getScope().(Function).getName() = "get_directories" and argIndex = 0
    ) and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 2: os.path.normpath(...) - staticfiles.py:111 in get_path
     (os.path.normpath(os.path.join(*scope["path"].split("/"))) - the
     '..'/'.'-collapsing node acting on the attacker path BEFORE the
     base-directory join; sanitizer-shaped: pure-relative traversal
     strings are neutralized here, Windows separator interplay is a
     labeling concern) and :82 in get_directories (operator config);
     argument 0 carries the path */
  exists(Call c |
    osPathFunc(c.getFunc(), "normpath") and
    node = c and
    flowKind = "path_normalize" and
    callableName = "normpath" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 3: os.path.abspath / os.path.realpath canonicalization -
     staticfiles.py:168 os.path.abspath(joined_path) (the
     follow_symlink=True branch - NO containment check on that branch)
     and :170 os.path.realpath(joined_path) / :171 realpath(directory)
     (the follow_symlink=False branch feeding the commonprefix check);
     argument 0 carries the path */
  exists(Call c |
    (
      osPathFunc(c.getFunc(), "abspath")
      or
      osPathFunc(c.getFunc(), "realpath")
    ) and
    node = c and
    flowKind = "path_resolve" and
    callableName = c.getFunc().(Attribute).getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 4: os.path.commonprefix([full_path, directory]) -
     staticfiles.py:172: the base-directory containment guard (skips the
     directory when the canonicalized full path does not share the
     prefix); a pure string-prefix comparison, not path-component aware,
     and only applied on the follow_symlink=False branch; argument 0
     carries the path list */
  exists(Call c |
    osPathFunc(c.getFunc(), "commonprefix") and
    node = c and
    flowKind = "path_containment_check" and
    callableName = "commonprefix" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 5: os.stat(...) direct calls - staticfiles.py:177
     os.stat(full_path) in lookup_path (the stat after the containment
     check - the file-existence probe); argument 0 carries the path */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "stat" and
    c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_stat" and
    callableName = "stat" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 6: os.path.isdir(...) / os.path.isfile(...) metadata checks -
     staticfiles.py:56 (StaticFiles ctor directory check), :85
     (package statics dir check), config.py:62 (env file check);
     argument 0 carries the path */
  exists(Call c |
    (
      osPathFunc(c.getFunc(), "isdir")
      or
      osPathFunc(c.getFunc(), "isfile")
    ) and
    node = c and
    flowKind = "file_stat" and
    callableName = c.getFunc().(Attribute).getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 7: anyio.to_thread.run_sync(os.stat, path) - staticfiles.py:209
     (check_config: os.stat(self.directory)) and responses.py:335
     (FileResponse.__call__: os.stat(self.path) - the re-stat before
     serving); the path is argument 1 (the slot after the function
     object) */
  exists(Call c |
    anyioRunSyncFunc(c.getFunc()) and
    c.getPositionalArg(0).(Attribute).getName() = "stat" and
    c.getPositionalArg(0).(Attribute).getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_stat" and
    callableName = "run_sync" and
    argIndex = 1 and
    receiver = "anyio.to_thread" and
    moduleHint = "anyio.to_thread" and
    matchKind = "ast"
  )
  or
  /* family 8: anyio.to_thread.run_sync(self.lookup_path, path) -
     staticfiles.py:121 (get_response: the request path), :137 (the
     index.html path), :150 (the literal "404.html"): the threadpool
     offload of the join/realpath/containment/stat worker; the path is
     argument 1 */
  exists(Call c |
    anyioRunSyncFunc(c.getFunc()) and
    c.getPositionalArg(0).(Attribute).getName() = "lookup_path" and
    c.getPositionalArg(0).(Attribute).getObject().(Name).getId() = "self" and
    node = c and
    flowKind = "file_lookup" and
    callableName = "run_sync" and
    argIndex = 1 and
    receiver = "anyio.to_thread" and
    moduleHint = "anyio.to_thread" and
    matchKind = "ast"
  )
  or
  /* family 9: anyio.open_file(self.path, mode="rb") - responses.py:353 in
     FileResponse.__call__: THE actual file open for HTTP serving; the
     path is argument 0 */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "open_file" and
    c.getFunc().(Attribute).getObject().(Name).getId() = "anyio" and
    node = c and
    flowKind = "file_open" and
    callableName = "open_file" and
    argIndex = 0 and
    receiver = "anyio" and
    moduleHint = "anyio" and
    matchKind = "ast"
  )
  or
  /* family 10: builtin open(...) Name calls - config.py:121
     open(file_name) in Config._read_file: the env-file read with the
     operator-configured path at argument 0 */
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
  /* family 11: file.read(chunk_size) - responses.py:356 on the file
     opened by anyio.open_file at :353: the chunked body transmission;
     argument 0 carries the chunk size (the file object is the
     receiver) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "read" and
    func.getObject().(Name).getId() = "file" and
    normalizedPathOf(c).matches("%/starlette/responses.py") and
    node = c and
    flowKind = "file_read" and
    callableName = "read" and
    argIndex = 0 and
    receiver = "file" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 12: FileResponse(...) construction - staticfiles.py:192
     (StaticFiles.file_response: the containment-checked full_path) and
     :154 (html-mode 404.html): argument 0 is the served path;
     FileResponse.__call__ performs the re-stat (responses.py:335) and
     anyio.open_file (:353) */
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
  /* family 13: jinja2.FileSystemLoader(directory) - templating.py:85 in
     Jinja2Templates._create_env: the template root (operator-config)
     at argument 0; the actual template file loads happen inside jinja2
     (not part of the database) */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "FileSystemLoader" and
    c.getFunc().(Attribute).getObject().(Name).getId() = "jinja2" and
    node = c and
    flowKind = "file_loader" and
    callableName = "FileSystemLoader" and
    argIndex = 0 and
    receiver = "jinja2" and
    moduleHint = "jinja2" and
    matchKind = "ast"
  )
  or
  /* family 14: get_template(...) calls - templating.py:94
     self.env.get_template(name) and :112 self.get_template(name): the
     template NAME at argument 0 (application-supplied string, not
     request input in this tree - emitted so labeling can classify the
     trust level); the underlying file load happens inside jinja2 */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get_template" and
    node = c and
    flowKind = "file_loader" and
    callableName = "get_template" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 15: SpooledTemporaryFile(max_size=...) - formparsers.py:207 in
     MultiPartParser.on_headers_finished: the multipart upload content
     sink; the name is auto-generated (NOT attacker-controlled) -
     emitted so labeling can classify the upload-content channel as
     name-safe (the attacker filename goes to UploadFile(filename=...),
     see sources.ql family 15) */
  exists(Call c |
    c.getFunc().(Name).getId() = "SpooledTemporaryFile" and
    node = c and
    flowKind = "file_create_temp" and
    callableName = "SpooledTemporaryFile" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = "tempfile" and
    matchKind = "ast"
  )
  or
  /* family 16: part.file.write(data) / part.file.seek(0) -
     formparsers.py:263/:266 in MultiPartParser.parse: the upload
     content written into (and rewound in) the spooled temporary file;
     the file object is the receiver, argument 0 carries the data */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    uploadFileMember(func.getName()) and
    func.getObject().(Attribute).getName() = "file" and
    func.getObject().(Attribute).getObject().(Name).getId() = "part" and
    normalizedPathOf(c).matches("%/starlette/formparsers.py") and
    node = c and
    (
      func.getName() = "write" and flowKind = "file_write"
      or
      not func.getName() = "write" and flowKind = "file_read"
    ) and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "part.file" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 17: self.file.write/read/seek/close direct calls -
     datastructures.py:465 (self.file.write(data)), :471
     (self.file.read(size)), :476 (self.file.seek(offset)), :482
     (self.file.close()) in UploadFile: the in-memory branch of the
     upload storage channel (auto-named spooled file); the file object
     is the receiver, argument 0 carries the data where applicable */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    uploadFileMember(func.getName()) and
    func.getObject().(Attribute).getName() = "file" and
    func.getObject().(Attribute).getObject().(Name).getId() = "self" and
    normalizedPathOf(c).matches("%/starlette/datastructures.py") and
    node = c and
    (
      func.getName() = "write" and flowKind = "file_write"
      or
      func.getName() = "read" and flowKind = "file_read"
      or
      func.getName() = "seek" and flowKind = "file_read"
      or
      func.getName() = "close" and flowKind = "file_close"
    ) and
    callableName = func.getName() and
    (
      func.getName() = "close" and argIndex = -1
      or
      not func.getName() = "close" and argIndex = 0
    ) and
    receiver = "self.file" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 18: run_in_threadpool(self.file.write/read/seek/close, ...) -
     datastructures.py:467/:472/:478/:484 in UploadFile: the threadpool
     branch of the upload storage channel (the bare method reference is
     argument 0, the data argument 1 where applicable) */
  exists(Call c, Attribute fileOp |
    c.getFunc().(Name).getId() = "run_in_threadpool" and
    fileOp = c.getPositionalArg(0).(Attribute) and
    uploadFileMember(fileOp.getName()) and
    fileOp.getObject().(Attribute).getName() = "file" and
    fileOp.getObject().(Attribute).getObject().(Name).getId() = "self" and
    normalizedPathOf(c).matches("%/starlette/datastructures.py") and
    node = c and
    (
      fileOp.getName() = "write" and flowKind = "file_write"
      or
      fileOp.getName() = "read" and flowKind = "file_read"
      or
      fileOp.getName() = "seek" and flowKind = "file_read"
      or
      fileOp.getName() = "close" and flowKind = "file_close"
    ) and
    callableName = "run_in_threadpool" and
    (
      fileOp.getName() = "close" and argIndex = -1
      or
      not fileOp.getName() = "close" and argIndex = 1
    ) and
    receiver = receiverHint(fileOp.getObject().(Attribute)) and
    moduleHint = "starlette.concurrency" and
    matchKind = "ast"
  )
  or
  /* family 19: os.fspath(url) - responses.py:35 in the mimetypes
     compatibility wrapper (converts a PathLike to str for
     guess_type on <py3.8): a path-conversion node, argument 0 carries
     the path */
  exists(Call c |
    osPathFunc(c.getFunc(), "fspath") and
    node = c and
    flowKind = "path_ctor" and
    callableName = "fspath" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 20: file_api_def definition rows - the library's own
     path-taking API definitions with the true path parameter position:
     FileResponse.__init__(path) responses.py:288, StaticFiles.__init__(directory)
     staticfiles.py:42, StaticFiles.get_response(path) staticfiles.py:113,
     StaticFiles.lookup_path(path) staticfiles.py:163,
     StaticFiles.file_response(full_path) staticfiles.py:184,
     Jinja2Templates.__init__(directory) templating.py:67,
     Jinja2Templates.get_template(name) templating.py:93,
     Jinja2Templates.TemplateResponse(name) templating.py:98,
     Config.__init__(env_file) config.py:55, Config._read_file(file_name)
     config.py:119, UploadFile.__init__(filename) datastructures.py:442;
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
