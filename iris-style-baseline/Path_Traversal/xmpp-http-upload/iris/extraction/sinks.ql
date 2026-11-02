/**
 * @name xmpp-http-upload CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the
 *   xmpp-http-upload CodeQL database (version 0.3.0, creation sha
 *   f0fc7443c06a0e8aecb5696fc2bd513a2cc8b611 - a Flask-based HTTP file
 *   upload/download service; the entire server is the single module
 *   xhu.py, plus setup.py packaging and config.example.py). Sink core
 *   per the task contract: the FILE PATH PARAMETER / RECEIVER of actual
 *   filesystem operations and the path-pipeline nodes that directly
 *   determine the accessed file. Families: the pathlib true-division
 *   join `root / path` (Div BinaryExpr at xhu.py:43 inside
 *   sanitized_join - left operand the DATA_ROOT base, right operand
 *   the attacker path, arg_index 1 = right operand; the single Div
 *   occurrence of the module); the .absolute() member call at :43 (the
 *   make-absolute node of the guard chain - no resolve()/realpath
 *   exists anywhere in the code); pathlib.Path(...) constructions at
 *   :50/:51 (the '<base>.data'/'<base>.meta' suffix joins onto the
 *   sanitized path) and :66/:109/:194/:219 (the DATA_ROOT base
 *   conversion); the custom sanitized_join(path, root) validation-
 *   wrapper call sites at :64 (get_info) and :107 (put_file), argument
 *   0 = the attacker path; pathlib member file accesses
 *   (.open("r") :57 read, .open("xb") :76 exclusive create of the
 *   uploaded data file, .open("x") :144 exclusive create of the
 *   metadata file, .unlink() :80 rollback delete,
 *   .parent.mkdir(parents=True, exist_ok=True, mode=0o770) :137
 *   intermediate directory creation from URL path components,
 *   .stat() :197 HEAD probe); the flask.send_file(str(data_file))
 *   file-response sink at :228 (argument 0 - the framework
 *   file-read-into-HTTP-response call of the GET route; the wrapping
 *   flask.make_response call is a response wrapper, NOT a file access,
 *   and is not emitted); definition rows of the path-consuming
 *   internal APIs (sanitized_join path/root :42, get_paths base_path
 *   :49, load_metadata metadata_file :56, get_info path/root :61,
 *   write_file at :75) with the true parameter positions; and the
 *   setup.py packaging rows (builtin open(os.path.join(here,
 *   "README.rst")) :10, os.path.join :10, os.path.abspath :8,
 *   os.path.dirname :8 - literal packaging paths, expected FP).
 *   Content I/O on already-open handles (stream_file src.read/
 *   dest.write :94/:97, json.load :58, json.dump :145), str()
 *   coercions, the startswith prefix guard (:44) and response header
 *   writes are NOT emitted - recorded in detection.json instead. Raw
 *   BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to
 *   exist.
 * @id iris/xmpp-http-upload/extraction/sinks
 * @tags path-traversal
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql and to the prior IRIS
 * manual projects):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member name ("/" for the pathlib
 *                   true-division join, "Path" for construction rows,
 *                   "absolute"/"sanitized_join"/"join"/"abspath"/
 *                   "dirname" for wrapper rows, "open"/"send_file"/
 *                   "mkdir"/"unlink"/"stat" for access rows, the
 *                   function name for file_api_def definition rows)
 *   4. flow_kind  - "path_join" (the `root / path` Div BinaryExpr),
 *                   "path_ctor" (pathlib.Path(...) construction),
 *                   "path_wrapper" (sanitized_join wrapper calls, the
 *                   .absolute() normalization node, os.path pure ops),
 *                   "file_open" (open(...)/.open(...) - the path
 *                   argument or receiver), "file_serve"
 *                   (flask.send_file - the framework file-response
 *                   call), "file_mkdir" (.mkdir - receiver is the
 *                   path), "file_unlink" (.unlink), "file_stat"
 *                   (.stat), "file_api_def" (definition row of a
 *                   path-consuming internal API, carrying the path
 *                   parameter position)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "root"/"metadata_file"/"at"/"parent"/
 *                   "data_file"/"pathlib"/"flask"/"os.path" etc., "" if
 *                   none; "<expr>" when the object expression is
 *                   neither Name nor Attribute; "" for module-level
 *                   file_api_def rows)
 *   6. moduleHint - literal module hints "pathlib"/"flask"/"builtins"/
 *                   "os.path" for the library channels, otherwise the
 *                   dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the
 *                   path (argument 0 for Path/send_file/
 *                   sanitized_join/os.* rows; 1 for the path_join Div
 *                   row, where operand index 0 is the left/base
 *                   operand and operand index 1 the right operand
 *                   carrying the attacker path); -1 when the receiver
 *                   carries the path (.open/.mkdir/.unlink/.stat/
 *                   .absolute rows); the true parameter position for
 *                   file_api_def rows
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (call additionally resolved through API graphs
 *                   via the real `import flask` xhu.py:31 /
 *                   `import pathlib` xhu.py:28 / `import os.path`
 *                   setup.py:2) or "ast" (syntax-level match only)
 *
 * Sink modeling decision (per the task contract): the sink core is the
 * FILE PATH PARAMETER / RECEIVER of actual filesystem operations and
 * the path-pipeline nodes that directly determine the accessed file -
 * NOT every path string construction node. Pure operations are not
 * emitted and are documented in detection.json instead: str()
 * coercions (:50/:51/:229), the '<base> + ".data"/".meta"'
 * concatenations (:50/:51), the startswith prefix guard (:44),
 * hmac/hashlib/fnmatch/int calls, json.load/json.dump (file-object
 * I/O), stream_file read/write on open handles (:94/:97 - the path
 * decision point is the preceding .open()), and the flask.
 * make_response wrapper around send_file (:228 outer call - a
 * response-object constructor, not a file access).
 *
 * Note: this file defines no QL classes (only predicates), does not
 * assign API::Node values to DataFlow::Node variables (API graph nodes
 * only appear inside exists() bodies feeding astCallOf), keeps every
 * variable bound through a positive body, and keeps resolved-API
 * matching strictly separate from AST syntax matching: every row is
 * GENERATED by its AST shape (guaranteeing candidate presence), and the
 * match_kind column records whether the API graph additionally
 * resolves the call. Member-name matching (.open/.mkdir/.unlink/
 * .stat/.absolute) is receiver-name-agnostic on purpose: receiver
 * identity cannot be proven syntactically, so receiver hints
 * (metadata_file/at/dest_path.parent/data_file) are emitted for the
 * labeling step; in this codebase every matched member call is a
 * pathlib instance call (verified against the full 236-line module -
 * no name collisions exist).
 *
 * Excluded paths (applied to every row): /xmpp-http-upload-db/ (the
 * CodeQL database directory nested inside the source tree) and /.git/
 * (not part of the database; filtered for safety). No /tests/ tree
 * exists in this project.
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

/** Base name of an arbitrary expression, used as a receiver/operand hint
 *  (same shape as receiverHint, generalized for binary operands). */
string exprNameHint(Expr e) {
  result = e.(Name).getId()
  or
  result = e.(Attribute).getName()
  or
  not e instanceof Name and
  not e instanceof Attribute and
  result = "<expr>"
}

/** True iff the candidate's file path is one of the excluded trees. Path is
 *  normalized to forward slashes before matching so the query works on both
 *  CodeQL path styles. bindingset[path] declares that the caller passes a
 *  bound path (the path only appears in checked positions such as the
 *  receiver of replaceAll/matches inside this predicate). */
bindingset[path]
predicate excludedPath(string path) {
  path.replaceAll("\\", "/").matches("%/xmpp-http-upload-db/%")
  or
  path.replaceAll("\\", "/").matches("%/.git/%")
}

/** The syntactic Call node behind an API graph call node (same proven
 *  helper shape as the airflow project of this series). */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/** Holds if c is a call that the API graph resolves through the real
 *  import statements of the database: flask.send_file (import flask,
 *  xhu.py:31), pathlib.Path (import pathlib, xhu.py:28) and the
 *  os.path members used by setup.py (import os.path, setup.py:2). */
private predicate apiResolvedSinkCall(Call c) {
  exists(API::CallNode cn |
    (
      cn = API::moduleImport("flask").getMember("send_file").getACall()
      or
      cn = API::moduleImport("pathlib").getMember("Path").getACall()
      or
      cn = API::moduleImport("os").getMember("path").getMember("join").getACall()
      or
      cn = API::moduleImport("os").getMember("path").getMember("abspath").getACall()
      or
      cn = API::moduleImport("os").getMember("path").getMember("dirname").getACall()
    ) and
    c = astCallOf(cn)
  )
}

/** Binds matchKind according to whether the API graph resolves c. */
private predicate matchKindOf(Call c, string matchKind) {
  (apiResolvedSinkCall(c) and matchKind = "api")
  or
  (not apiResolvedSinkCall(c) and matchKind = "ast")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: path_join - the pathlib true-division join
     `result = (root / path).absolute()` at xhu.py:43 inside
     sanitized_join: THE node where the attacker-controlled route path
     is concatenated onto the DATA_ROOT base. Syntactically a Div
     BinaryExpr (pathlib.Path.__truediv__); it is the single Div
     occurrence of the module. Operand index 0 = left operand (the
     `root` base - emitted as the receiver hint), operand index 1 =
     right operand (the attacker `path` - emitted as arg_index).
     FloorDiv is not matched; numeric divisions elsewhere would be
     name-collision rows (none exist here). */
  exists(BinaryExpr b |
    b.getOp() instanceof Div and
    normalizedPathOf(b).matches("%/xhu.py") and
    node = b and
    flowKind = "path_join" and
    callableName = "/" and
    argIndex = 1 and
    receiver = exprNameHint(b.getLeft()) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 2: path_ctor - pathlib.Path(...) constructor calls
     (module-qualified form; no `from pathlib import Path` aliasing is
     observed). Key sites: xhu.py:50 pathlib.Path(str(base_path) +
     ".data") and :51 pathlib.Path(str(base_path) + ".meta") - the
     '<base>.data'/'<base>.meta' companions of the sanitized path that
     feed .open/.stat; :66/:109/:194/:219
     pathlib.Path(app.config["DATA_ROOT"]) - the operator-configured
     containment base (not a source, but the base operand of every
     join). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "Path" and
    func.getObject().(Name).getId() = "pathlib" and
    normalizedPathOf(c).matches("%/xhu.py") and
    node = c and
    flowKind = "path_ctor" and
    callableName = "Path" and
    argIndex = 0 and
    receiver = "pathlib" and
    moduleHint = "pathlib" and
    matchKindOf(c, matchKind)
  )
  or
  /* family 3: path_wrapper (custom validation wrapper call sites) -
     sanitized_join(path, root) at xhu.py:64-67 (inside get_info,
     called by head_file :192 and get_file :217) and :107-110 (inside
     put_file). Argument 0 carries the attacker-controlled route path;
     argument 1 is the DATA_ROOT base. The wrapper body performs the
     join (family 1) and the startswith prefix guard (recorded as guard
     evidence in detection.json, not a row). */
  exists(Call c |
    c.getFunc().(Name).getId() = "sanitized_join" and
    normalizedPathOf(c).matches("%/xhu.py") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "sanitized_join" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 4: path_wrapper (normalization node) - the .absolute()
     member call at xhu.py:43: `(root / path).absolute()` - pathlib
     make-absolute WITHOUT normalization and WITHOUT symlink
     resolution (no resolve()/realpath() exists anywhere in the
     codebase); the receiver is the joined path, hence arg_index -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "absolute" and
    normalizedPathOf(c).matches("%/xhu.py") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "absolute" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 5: path_wrapper (os.path pure ops in the packaging script) -
     setup.py:10 os.path.join(here, "README.rst") (argument 0), :8
     os.path.abspath(...) and :8 os.path.dirname(__file__) - literal
     packaging paths, expected FP rows, kept for auditability. */
  exists(Call c, Attribute func, Attribute pathAttr |
    func = c.getFunc().(Attribute) and
    (func.getName() = "join" or func.getName() = "abspath" or func.getName() = "dirname") and
    pathAttr = func.getObject().(Attribute) and
    pathAttr.getName() = "path" and
    pathAttr.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/setup.py") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKindOf(c, matchKind)
  )
  or
  /* family 6: file_open (pathlib .open member calls) - the actual file
     accesses of the service. xhu.py:57 metadata_file.open("r") (the
     metadata read inside load_metadata), :76 at.open("xb") (EXCLUSIVE
     CREATE of the uploaded data file inside write_file), :144
     metadata_file.open("x") (exclusive create of the metadata JSON).
     The receiver carries the path, hence arg_index -1; the mode string
     is documented per site. No other .open call exists in the module. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    normalizedPathOf(c).matches("%/xhu.py") and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 7: file_open (builtin open in the packaging script) -
     setup.py:10 open(os.path.join(here, "README.rst"),
     encoding="utf-8"), argument 0 - literal packaging path, expected
     FP row. io.open does not occur in this codebase. */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    normalizedPathOf(c).matches("%/setup.py") and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* family 8: file_serve - flask.send_file(str(data_file)) at
     xhu.py:228 in get_file, argument 0: the framework
     file-read-into-HTTP-response call for the GET route (the real file
     access; the flask/werkzeug internals are outside the database).
     The wrapping flask.make_response(...) is a response-object
     constructor, not a file access, and is NOT emitted; the str()
     coercion of data_file is pure and is not emitted. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "send_file" and
    func.getObject().(Name).getId() = "flask" and
    normalizedPathOf(c).matches("%/xhu.py") and
    node = c and
    flowKind = "file_serve" and
    callableName = "send_file" and
    argIndex = 0 and
    receiver = "flask" and
    moduleHint = "flask" and
    matchKindOf(c, matchKind)
  )
  or
  /* family 9: file_mkdir -
     dest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o770)
     at xhu.py:137 in put_file: creates every intermediate directory of
     the uploaded path under DATA_ROOT (the receiver
     dest_path.parent carries the path, hence arg_index -1; parents
     tolerance and the 0o770 mode are documented in detection.json). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "mkdir" and
    normalizedPathOf(c).matches("%/xhu.py") and
    node = c and
    flowKind = "file_mkdir" and
    callableName = "mkdir" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 10: file_unlink - at.unlink() at xhu.py:80 inside the
     write_file error path: the rollback deletion of a partially
     written data file (receiver `at` carries the path). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "unlink" and
    normalizedPathOf(c).matches("%/xhu.py") and
    node = c and
    flowKind = "file_unlink" and
    callableName = "unlink" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 11: file_stat - data_file.stat() at xhu.py:197 in
     head_file: the HEAD-route metadata probe whose st_size becomes the
     response Content-Length (receiver `data_file` carries the path). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "stat" and
    normalizedPathOf(c).matches("%/xhu.py") and
    node = c and
    flowKind = "file_stat" and
    callableName = "stat" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 12: file_api_def - definition rows of the path-consuming
     internal APIs, carrying the true parameter positions (0-based,
     module-level functions so no self slot). These rows feed the
     labeling step as summary/boundary signatures. */

  /* sanitized_join(path: str, root: pathlib.Path) - xhu.py:42 - the
     custom validation wrapper: path (position 0) is the
     attacker-controlled route path, root (position 1) the DATA_ROOT
     base; the body performs the Div join (family 1) and the
     startswith guard */
  exists(Function fn, Parameter p |
    fn.getName() = "sanitized_join" and
    normalizedPathOf(fn).matches("%/xhu.py") and
    (p = fn.getArgByName("path") or p = fn.getArgByName("root")) and
    node = p and
    flowKind = "file_api_def" and
    callableName = "sanitized_join" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* get_paths(base_path: pathlib.Path) - xhu.py:49 - base_path
     (position 0) is the sanitized destination path; the body builds
     the '<base>.data'/'<base>.meta' companions (path_ctor family 2) */
  exists(Function fn, Parameter p |
    fn.getName() = "get_paths" and
    normalizedPathOf(fn).matches("%/xhu.py") and
    p = fn.getArgByName("base_path") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "get_paths" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* load_metadata(metadata_file) - xhu.py:56 - metadata_file
     (position 0) is opened read-only by the body (.open("r"),
     file_open family 6) */
  exists(Function fn, Parameter p |
    fn.getName() = "load_metadata" and
    normalizedPathOf(fn).matches("%/xhu.py") and
    p = fn.getArgByName("metadata_file") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "load_metadata" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* get_info(path: str, root: pathlib.Path) - xhu.py:61 - the
     read-side pipeline entry called by head_file (:192) and get_file
     (:217): path (position 0) is the attacker-controlled route path,
     root (position 1) the DATA_ROOT base; the body calls
     sanitized_join (family 3) and load_metadata */
  exists(Function fn, Parameter p |
    fn.getName() = "get_info" and
    normalizedPathOf(fn).matches("%/xhu.py") and
    (p = fn.getArgByName("path") or p = fn.getArgByName("root")) and
    node = p and
    flowKind = "file_api_def" and
    callableName = "get_info" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* write_file(at: pathlib.Path) - xhu.py:75 - the @contextlib.
     contextmanager wrapper whose body performs at.open("xb")
     (exclusive create, file_open family 6) and the at.unlink()
     rollback (file_unlink family 10); at (position 0) is the data
     file path derived from the sanitized join. stream_file(src, dest,
     nbytes) is NOT emitted: src/dest are already-open file objects
     (the path decision point is the preceding .open()). */
  exists(Function fn, Parameter p |
    fn.getName() = "write_file" and
    normalizedPathOf(fn).matches("%/xhu.py") and
    p = fn.getArgByName("at") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "write_file" and
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
