/**
 * @name airflow CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the airflow CodeQL
 *   database (Apache Airflow 2.7.0.dev0, snapshot sha 2811ba7): builtin open() calls
 *   (112 non-test sites; io.open does not occur in this snapshot), pathlib
 *   constructor Path(...) and receiver-path methods (.open/.read_text/.read_bytes/
 *   .write_text/.write_bytes/.mkdir/.touch/.unlink/.glob/.chmod/.rename/.replace),
 *   os and shutil path-taking operations (os.walk/os.remove/os.makedirs/os.symlink/
 *   os.listdir/os.unlink/os.open/os.rename..., shutil.rmtree/copy/copyfile/copytree/
 *   move - path at argument 0, destination at argument 1 where applicable),
 *   zipfile.ZipFile / tarfile.open constructors and flask send_file /
 *   send_from_directory (filename at argument 1 for send_from_directory, the
 *   serve-logs /log/<path:filename> endpoint being the primary file-serving site),
 *   importlib.machinery.SourceFileLoader (file path at argument 1, DAG/plugin file
 *   execution), and internal wrapper functions whose body performs a real filesystem
 *   operation (open_maybe_zipped, FileTaskHandler._read/_read_from_local/_init_file,
 *   TaskLogReader.read_log_chunks/read_log_stream, DagCode._get_code_from_file,
 *   DagBag.process_file, serve_logs_view, CLI import/export handlers, ...).
 *   flow_kind: "arg" = path-carrying positional argument at arg_index, "method" =
 *   receiver-path method call (the receiver object is the path), "internal_file_
 *   wrapper" = function that directly performs a filesystem operation.
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain multi-column select query
 *   on purpose: @kind problem is the wrong shape for candidate tables and @kind table is
 *   not assumed to exist.
 * @id iris/airflow/extraction/sinks
 * @tags path-traversal
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql and to the prior IRIS manual projects):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or attribute name)
 *   4. flow_kind  - "arg" (path argument of a filesystem API call at arg_index),
 *                   "method" (method call whose receiver object is the path),
 *                   "internal_file_wrapper" (function that directly performs a
 *                   filesystem operation)
 *   5. receiver   - syntactic receiver hint (base name of the object expression, "" if none)
 *   6. moduleHint - module hint: external module name, or dotted python module path for
 *                   internal candidates (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the path (-1 when the
 *                   path is the receiver or for wrapper rows); for copy/copytree/move
 *                   the destination sits at index 1 (noted per family)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath(); AstNode.getFile()
 *                    does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast" (syntax-level match)
 *
 * Scope: only operations that actually touch the filesystem (open/create/read/write/
 * remove/move/directory ops and file-serving). Path-string construction and validation
 * nodes (os.path.join/abspath/realpath, Path.resolve/relative_to, zipfile.is_zipfile)
 * are deliberately NOT extracted as sinks; they are recorded as propagation/sanitizer
 * notes in iris/exploration/detection.json.
 *
 * Note: this file defines no QL classes (only predicates/functions), avoids assigning
 * API::Node values to DataFlow::Node variables, and keeps resolved-API matching strictly
 * separate from AST syntax matching (the match_kind column records which one produced a row).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for internal candidates). */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
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

/** Holds if n sits inside a test file: any path under a tests/ directory or conftest.py. */
predicate isTestLocation(AstNode n) {
  n.getLocation().getFile().getAbsolutePath().matches("%/tests/%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\tests\\%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%/conftest.py")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\conftest.py")
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Sink family 1: filesystem API table (API graphs + syntax shapes)    */
/* ------------------------------------------------------------------ */

/**
 * External filesystem APIs with the 0-based positional argument index that carries
 * the path. flask send_from_directory takes the (trusted) base directory at index 0
 * and the controlled filename at index 1. For shutil copy/copytree/move the source
 * path is at index 0 and the destination at index 1 (the destination is a traversal
 * target as well; only index 0 is emitted per row and the copy is noted here).
 * io.open and os.path.* members are not listed: io.open does not occur in this
 * snapshot, and os.path.* are validation/propagation nodes, not file access.
 */
private predicate fsApiArgIndex(string moduleHint, string member, int argIndex) {
  moduleHint = "os" and
  member in ["remove", "unlink", "rmdir", "removedirs", "makedirs", "mkdir", "walk",
             "listdir", "scandir", "symlink", "link", "readlink", "stat", "lstat",
             "chmod", "rename", "replace", "open"] and
  argIndex = 0
  or
  moduleHint = "shutil" and
  member in ["rmtree", "copy", "copy2", "copyfile", "copytree", "move"] and
  argIndex = 0
  or
  moduleHint = "zipfile" and
  member = "ZipFile" and
  argIndex = 0
  or
  moduleHint = "tarfile" and
  member = "open" and
  argIndex = 0
  or
  moduleHint = "flask" and
  member = "send_file" and
  argIndex = 0
  or
  moduleHint = "flask" and
  member = "send_from_directory" and
  argIndex = 1
}

/** Holds if cn is a call node genuinely resolved to a filesystem API (alias-aware). */
private predicate resolvedFsCall(API::CallNode cn, string moduleHint, string member, int argIndex) {
  fsApiArgIndex(moduleHint, member, argIndex) and
  cn = API::moduleImport(moduleHint).getMember(member).getACall()
}

/**
 * AST-only matches: syntactic `<module>.<member>(...)` shapes with a known
 * filesystem-API member (os.walk, os.remove, shutil.rmtree, zipfile.ZipFile,
 * tarfile.open; os members take the path at index 0, os.open at index 0), plus the
 * from-imported flask names actually used in this snapshot
 * (send_from_directory: airflow/www/views.py:55, airflow/utils/serve_logs.py:27;
 * send_file does not occur but is kept in the shape table). Bare os/shutil member
 * names are too collision-prone and do not occur as from-imports.
 */
private predicate syntacticFsCall(Call c, string moduleHint, string member, int argIndex) {
  fsApiArgIndex(moduleHint, member, argIndex) and
  c.getFunc().(Attribute).getName() = member and
  c.getFunc().(Attribute).getObject().(Name).getId() = moduleHint
  or
  moduleHint = "flask" and
  member in ["send_file", "send_from_directory"] and
  argIndex = fsFlaskArgIndex(member) and
  c.getFunc().(Name).getId() = member
}

/** Filename argument index of the flask file-serving APIs (see fsApiArgIndex). */
private int fsFlaskArgIndex(string member) {
  member = "send_file" and result = 0
  or
  member = "send_from_directory" and result = 1
}

/* ------------------------------------------------------------------ */
/* Sink family 2: importlib.machinery.SourceFileLoader (AST shape)     */
/* ------------------------------------------------------------------ */

/**
 * `importlib.machinery.SourceFileLoader(mod_name, filepath)` - loads (and via a
 * subsequent .exec_module() executes) a python file; the file path sits at
 * argument index 1. Real sites: airflow/models/dagbag.py:341 (DAG zip/file loading),
 * airflow/plugins_manager.py:254 (plugin loading).
 */
private predicate sourceFileLoaderCall(Call c) {
  c.getFunc().(Attribute).getName() = "SourceFileLoader" and
  c.getFunc().(Attribute).getObject().(Attribute).getName() = "machinery" and
  c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "importlib"
}

/* ------------------------------------------------------------------ */
/* Sink family 3: pathlib constructor and receiver-path methods        */
/* ------------------------------------------------------------------ */

/**
 * `Path(...)` constructor calls: bare `Path` (from pathlib import Path, 26 files)
 * and qualified `pathlib.Path` (airflow/configuration.py). The path is argument 0.
 */
private predicate pathConstructorCall(Call c) {
  c.getFunc().(Name).getId() = "Path"
  or
  c.getFunc().(Attribute).getName() = "Path" and
  c.getFunc().(Attribute).getObject().(Name).getId() = "pathlib"
}

/**
 * Method calls whose receiver object is the path: pathlib read/write/mkdir/glob
 * methods plus generic `.open` (covers pathlib.Path.open, zipfile.ZipFile.open
 * member reads as in airflow/utils/file.py:192/:360 and resource-file opens in
 * airflow/providers_manager.py:137/:148). The receiver column carries the object
 * name; arg_index is -1 because the path is the receiver.
 */
private predicate filePathMethod(string name, string moduleHint) {
  name in ["read_text", "read_bytes", "write_text", "write_bytes", "mkdir", "touch",
           "unlink", "glob", "chmod", "rename", "replace"] and
  moduleHint = "pathlib"
  or
  name = "open" and
  moduleHint = "pathlib|zipfile"
}

/* ------------------------------------------------------------------ */
/* Sink family 4: internal file wrappers                               */
/* ------------------------------------------------------------------ */

/** Holds if c is any call site (resolved, syntactic, pathlib or loader) into a filesystem operation. */
private predicate fileOpCallSite(Call c) {
  exists(API::CallNode cn |
    resolvedFsCall(cn, _, _, _) and
    c = astCallOf(cn)
  )
  or
  syntacticFsCall(c, _, _, _)
  or
  sourceFileLoaderCall(c)
  or
  pathConstructorCall(c)
  or
  exists(Attribute func |
    func = c.getFunc().(Attribute) and
    filePathMethod(func.getName(), _)
  )
  or
  /* builtin open() - the dominant file API of this codebase (112 non-test sites) */
  c.getFunc().(Name).getId() = "open"
}

/**
 * Functions in this codebase whose body directly performs a filesystem operation:
 * open_maybe_zipped (airflow/utils/file.py:183), FileTaskHandler._read /
 * _read_from_local / _init_file / _prepare_log_folder, TaskLogReader.read_log_chunks /
 * read_log_stream, DagCode._get_code_from_file, DagBag.process_file /
 * _load_modules_from_file / _load_modules_from_zip, serve_logs_view,
 * find_path_from_directory / find_dag_file_paths / might_contain_dag_via_default_heuristic,
 * CLI import/export handlers (variable/pool/user/role/task/kubernetes commands) and the
 * many provider-local file helpers.
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
  /* family 0: builtin open() calls - the dominant file API of this codebase
     (112 non-test sites; io.open does not occur in this snapshot); the path
     is argument 0 */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    node = c and
    flowKind = "arg" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtin" and
    matchKind = "ast"
  )
  or
  /* family 1a: resolved filesystem API calls (API graphs, alias-aware) */
  exists(API::CallNode cn |
    resolvedFsCall(cn, moduleHint, callableName, argIndex) and
    node = astCallOf(cn) and
    flowKind = "arg" and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 1b: syntax-level filesystem API call shapes, module-qualified form
     (os.walk, os.remove, shutil.rmtree, zipfile.ZipFile, tarfile.open, ...);
     the receiver column carries the module prefix */
  exists(Call c |
    syntacticFsCall(c, moduleHint, callableName, argIndex) and
    moduleHint != "flask" and
    node = c and
    flowKind = "arg" and
    receiver = moduleHint and
    matchKind = "ast"
  )
  or
  /* family 1c: flask file-serving calls (send_from_directory / send_file), matched
     both as from-imported bare names (the form actually used: airflow/www/views.py:55,
     airflow/utils/serve_logs.py:27) and as a qualified flask.<member> shape;
     send_from_directory carries the controlled filename at argument index 1 */
  exists(Call c |
    syntacticFsCall(c, "flask", callableName, argIndex) and
    node = c and
    flowKind = "arg" and
    receiver = "" and
    moduleHint = "flask" and
    matchKind = "ast"
  )
  or
  /* family 2: importlib.machinery.SourceFileLoader(mod_name, filepath) - file
     execution by path, argument index 1 */
  exists(Call c |
    sourceFileLoaderCall(c) and
    node = c and
    flowKind = "arg" and
    callableName = "SourceFileLoader" and
    argIndex = 1 and
    receiver = "machinery" and
    moduleHint = "importlib.machinery" and
    matchKind = "ast"
  )
  or
  /* family 3a: pathlib.Path(...) constructor (path at argument 0) */
  exists(Call c |
    pathConstructorCall(c) and
    node = c and
    flowKind = "arg" and
    callableName = "Path" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 3b: receiver-path method calls (.read_text/.read_bytes/.write_text/
     .write_bytes/.open/.mkdir/.touch/.unlink/.glob/.chmod/... - the receiver
     object is the path; arg_index is -1 by convention) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    filePathMethod(func.getName(), moduleHint) and
    node = c and
    flowKind = "method" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    matchKind = "ast"
  )
  or
  /* family 4: internal functions that directly perform a filesystem operation */
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
  not isTestLocation(node)
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
