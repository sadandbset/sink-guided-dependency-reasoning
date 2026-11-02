/**
 * @name ansible CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the
 *   ansible CodeQL database (snapshot cef62967, ansible 2.9.6.post0 - the
 *   ansible code base under lib/ansible is the audit target): builtin
 *   open(...) calls (argument 0 carries the path; e.g.
 *   plugins/action/fetch.py:175 open(to_bytes(dest), 'wb') - the fetch
 *   destination whose construction consumed task src/dest, the
 *   inventory_hostname and the remote-returned slurp source path;
 *   plugins/action/template.py:112/:172, plugins/action/__init__.py:1144
 *   diff source read, galaxy/__init__.py:39, galaxy/role.py:112/:132/:155,
 *   config/manager.py:304/:320, parsing/vault/__init__.py:423, and the
 *   356 module-side open sites); os/shutil/io/tarfile/zipfile/glob/shelve
 *   filesystem APIs (both API-graph-resolved and module-qualified syntax
 *   forms - os.remove/unlink/rmdir/makedirs/mkdir/rename/replace/symlink/
 *   link/stat/lstat/listdir/scandir/readlink/walk/chmod/chown/utime/open,
 *   shutil.rmtree/copy/copy2/copyfile/copytree/move, io.open, tarfile.open/
 *   is_tarfile, zipfile.ZipFile, glob.glob, shelve.open - e.g. copy.py
 *   _walk_dirs os.walk/os.path.realpath/os.readlink/os.stat cluster,
 *   galaxy/role.py:271 tarfile.open(tmp_file) + :330
 *   role_tar_file.extract(member, self.path), lookup/shelvefile.py:47
 *   shelve.open, fetch.py:168 makedirs_safe); archive member extraction
 *   (.extract(member, path) with the destination at argument 1,
 *   .extractall(path) at argument 0, .extractfile at argument 0 - the
 *   galaxy role install pipeline and the unarchive/archive module
 *   family); tempfile creation channels (tempfile.mkstemp/mkdtemp/
 *   NamedTemporaryFile - the destination is the `dir` keyword, name
 *   auto-generated: copy.py:388, assemble.py:43, action/__init__.py:438,
 *   galaxy/role.py:193); the ansible path wrappers (makedirs_safe,
 *   unfrackpath from ansible.utils.path - fetch.py:168, utils/path.py:65
 *   realpath+normpath pipeline); the os.path propagation/validation family
 *   (os.path.join/abspath/normpath/realpath/relpath/basename/dirname/
 *   splitext/split/expanduser/expandvars/isfile/isdir/exists/isabs/islink/
 *   samefile/getsize and the `from os import path` name form - e.g.
 *   fetch.py:111-:132 dest construction: expanduser/isdir/basename/join/
 *   path_dwim, copy.py:114/:119/:125, galaxy/role.py:324/:329, and the
 *   include_vars path.* cluster); the DataLoader file channel
 *   (self._loader.get_real_file / _get_file_contents / path_dwim /
 *   path_dwim_relative / path_dwim_relative_stack / find_vars_files /
 *   load_from_file / path_exists / is_file / is_directory /
 *   list_directory call sites - the vault-aware controller file access
 *   wrapper whose open() sites sit in parsing/dataloader.py:157/:355);
 *   the ActionBase file channel (self._transfer_file(local_path,
 *   remote_path) at action/__init__.py:415/:434, self._transfer_data,
 *   self._find_needle at :1167, self._remote_expand_user at :637,
 *   self._execute_remote_stat at :569, self._remote_checksum at :608 -
 *   e.g. fetch.py:125, copy.py:300/:464, template.py:95, script.py:86,
 *   assemble.py:111); the connection file channel (self._connection.
 *   put_file / fetch_file call sites and the put_file/fetch_file(in_path,
 *   out_path) definitions of the 20+ connection plugins - local.py copies
 *   into the local filesystem, chroot/docker/kubectl into their roots);
 *   the lookup file channel (self.find_file_in_search_path(myvars,
 *   subdir, needle) - lookup/__init__.py:108/:120, file.py:68,
 *   fileglob.py:61, first_found.py:168); and definition rows for the
 *   library's own path-taking APIs (DataLoader methods, ActionBase
 *   methods, LookupBase.find_file_in_search_path, ansible.utils.path
 *   unfrackpath/makedirs_safe/cleanup_tmp_file, FileVaultSecret /
 *   ScriptVaultSecret._read_file, connection put_file/fetch_file) with
 *   the true path parameter positions. Raw BQRS extraction query: run
 *   with `codeql query run` and decode with `codeql bqrs decode` (not
 *   database analyze). This is a plain multi-column select query on
 *   purpose: @kind problem is the wrong shape for candidate tables and
 *   @kind table is not assumed to exist.
 * @id iris/ansible/extraction/sinks
 * @tags path-traversal
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql and to the prior IRIS
 * manual projects aiohttp/airflow):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member name ("open" / "extract" / "makedirs"
 *                   for direct calls, "joinpath-less" os.path member names,
 *                   "path_dwim_relative" / "_transfer_file" /
 *                   "find_file_in_search_path" for wrapper calls, the
 *                   function name for file_api_def definition rows)
 *   4. flow_kind  - "file_open" (open/io.open/os.open/shelve.open), "file_
 *                   delete" (os.remove/unlink/rmdir/removedirs,
 *                   shutil.rmtree), "file_dir_create" (os.makedirs/mkdir,
 *                   makedirs_safe), "file_create" (os.symlink/link - the
 *                   created path is argument 1), "file_move" (os.rename/
 *                   replace, shutil.move), "file_copy" (shutil.copy/copy2/
 *                   copyfile/copytree), "file_stat" (os.stat/lstat),
 *                   "file_read" (os.listdir/scandir/readlink/walk),
 *                   "file_perms" (os.chmod/chown/utime), "archive_open"
 *                   (tarfile.open/is_tarfile, zipfile.ZipFile),
 *                   "archive_extract" (.extract(arg 1)/.extractall(arg 0)),
 *                   "archive_read" (.extractfile), "path_glob" (glob.glob),
 *                   "file_create_temp" (tempfile.mkstemp/mkdtemp/
 *                   NamedTemporaryFile - destination is the dir= keyword,
 *                   name auto-generated), "path_join" (os.path.join),
 *                   "path_resolve" (abspath/normpath/realpath/relpath/
 *                   basename/dirname/splitext/split, unfrackpath),
 *                   "path_expand" (expanduser/expandvars), "path_check"
 *                   (isfile/isdir/exists/isabs/islink/samefile/getsize),
 *                   "loader_file_api" (self._loader.<file method>),
 *                   "action_file_api" (self.<ActionBase file method>),
 *                   "connection_file_api" (self._connection.put_file/
 *                   fetch_file), "lookup_file_api"
 *                   (self.find_file_in_search_path), "file_api_def"
 *                   (definition row of a path-taking API, carrying the
 *                   path parameter position)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "os"/"os.path"/"shutil"/"tarfile"/"os"/
 *                   "self._loader"/"self"/"self._connection" etc., or ""
 *                   if none; enclosing class name for file_api_def rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "builtins"/"os"/"os.path"/"io"/"shutil"/
 *                   "tarfile"/"zipfile"/"glob"/"shelve"/"tempfile"/
 *                   "ansible.utils.path" for the stdlib/wrapper channels
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for open/join/stat/copy channels; argument
 *                   1 for os.symlink/os.link (the created link) and
 *                   .extract (the destination); argument 2 for
 *                   path_dwim_relative(_stack) (source) and argument 1
 *                   for _find_needle (needle) and find_vars_files (name);
 *                   -1 for tempfile channels (dir= keyword) and
 *                   receiver-path calls; the 0-based parameter position
 *                   including the self slot for file_api_def rows)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): the sink core is the
 * FILE PATH PARAMETER of actual filesystem operations plus the
 * propagation/validation nodes that directly determine the accessed file -
 * the open()/os/shutil/tarfile/zipfile channels, the archive extraction
 * pipeline, the ansible-internal wrappers that provably reach an open()
 * (DataLoader._get_file_contents at parsing/dataloader.py:157 and
 * get_real_file at :355; ActionBase._transfer_file -> connection.put_file;
 * unfrackpath -> realpath/normpath), and the os.path family as
 * propagation/validation nodes - NOT every path string construction node
 * (plain string formatting like fetch.py:132 dest = "%s/%s/%s" % (...) is
 * not emitted; the %-formatting operator cannot be told apart from other
 * modulo uses without receiver types and is documented in
 * detection.json uncoveredCases).
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables (the api family only chains
 * API::CallNode.getNode().getNode().(Call) - the pattern proven on this
 * same CLI + pack family by the airflow project of this series), keeps
 * every variable bound through a positive body, and keeps resolved-API
 * matching strictly separate from AST syntax matching (the match_kind
 * column records which one produced a row; the same call site can appear
 * twice - once as "api" and once as "ast" - exactly like the airflow
 * project). os.fdopen is deliberately NOT a sink family: its argument 0 is
 * a file descriptor from tempfile.mkstemp (copy.py:389, assemble.py:44,
 * action/__init__.py:442, dataloader.py:326), never a path.
 *
 * Scope (applied to every row): %/lib/ansible/% including
 * %/lib/ansible/modules/% for the direct filesystem-operation families
 * (modules execute on the managed nodes and their open/os/shutil sites
 * are real sinks fed by task arguments at runtime), EXCLUDING
 * %/ansible-db/% (the CodeQL database directory sits inside the source
 * tree). The os.path propagation family and all wrapper/definition
 * families are restricted to the controller tree (lib/ansible minus
 * modules) because the captured source boundaries are controller-side;
 * module-side propagation rows would be source-free noise. The top-level
 * test/, hacking/, examples/, docs/, contrib/ trees are outside the
 * positive scope; bin/ansible* wrappers contain no filesystem operations.
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

/** True iff the candidate's file path is inside the shipped ansible
 *  package (modules included). bindingset[path]: the caller passes a
 *  bound path; matches only appears in checked positions. */
bindingset[path]
predicate packageSinkPath(string path) {
  path.replaceAll("\\", "/").matches("%/lib/ansible/%") and
  not path.replaceAll("\\", "/").matches("%/ansible-db/%")
}

/** True iff the candidate's file path is inside the controller tree
 *  (%/lib/ansible/% but not %/lib/ansible/modules/% and not %/ansible-db/%). */
bindingset[path]
private predicate controllerSinkPath(string path) {
  path.replaceAll("\\", "/").matches("%/lib/ansible/%") and
  not path.replaceAll("\\", "/").matches("%/lib/ansible/modules/%") and
  not path.replaceAll("\\", "/").matches("%/ansible-db/%")
}

/** The syntactic Call node behind an API graph call node
 *  (API::CallNode -> ControlFlowNode -> AstNode -> Call). */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Filesystem API tables                                               */
/* ------------------------------------------------------------------ */

/**
 * External filesystem APIs with the 0-based positional argument index that
 * carries the path. Secondary path arguments are documented here rather
 * than emitted as extra rows: os.rename/replace carry the destination at
 * argument 1, shutil.copy/copy2/copyfile/copytree/move carry the
 * destination at argument 1; the source at argument 0 is the row emitted
 * (both endpoints are recorded in the flow_kind name). os.symlink and
 * os.link carry the created path at argument 1 (target at 0) so argument 1
 * is emitted. tempfile.mkstemp/mkdtemp/NamedTemporaryFile receive their
 * destination directory through the `dir` keyword (copy.py:388
 * tempfile.mkstemp(dir=C.DEFAULT_LOCAL_TMP), action/__init__.py:438) - no
 * positional path argument exists, hence -1.
 */
private predicate fsMemberTable(string moduleHint, string member, int argIndex, string flowKind) {
  moduleHint = "os" and
  member in ["remove", "unlink", "rmdir", "removedirs"] and
  argIndex = 0 and flowKind = "file_delete"
  or
  moduleHint = "os" and
  member in ["makedirs", "mkdir"] and
  argIndex = 0 and flowKind = "file_dir_create"
  or
  moduleHint = "os" and
  member in ["rename", "replace"] and
  argIndex = 0 and flowKind = "file_move"
  or
  moduleHint = "os" and
  member in ["symlink", "link"] and
  argIndex = 1 and flowKind = "file_create"
  or
  moduleHint = "os" and
  member in ["stat", "lstat"] and
  argIndex = 0 and flowKind = "file_stat"
  or
  moduleHint = "os" and
  member in ["listdir", "scandir", "readlink", "walk"] and
  argIndex = 0 and flowKind = "file_read"
  or
  moduleHint = "os" and
  member in ["chmod", "chown", "utime"] and
  argIndex = 0 and flowKind = "file_perms"
  or
  moduleHint = "os" and
  member = "open" and
  argIndex = 0 and flowKind = "file_open"
  or
  moduleHint = "io" and
  member = "open" and
  argIndex = 0 and flowKind = "file_open"
  or
  moduleHint = "shutil" and
  member = "rmtree" and
  argIndex = 0 and flowKind = "file_delete"
  or
  moduleHint = "shutil" and
  member in ["copy", "copy2", "copyfile", "copytree"] and
  argIndex = 0 and flowKind = "file_copy"
  or
  moduleHint = "shutil" and
  member = "move" and
  argIndex = 0 and flowKind = "file_move"
  or
  moduleHint = "tarfile" and
  member in ["open", "is_tarfile"] and
  argIndex = 0 and flowKind = "archive_open"
  or
  moduleHint = "zipfile" and
  member = "ZipFile" and
  argIndex = 0 and flowKind = "archive_open"
  or
  moduleHint = "glob" and
  member = "glob" and
  argIndex = 0 and flowKind = "path_glob"
  or
  moduleHint = "shelve" and
  member = "open" and
  argIndex = 0 and flowKind = "file_open"
  or
  moduleHint = "tempfile" and
  member in ["mkstemp", "mkdtemp", "NamedTemporaryFile"] and
  argIndex = -1 and flowKind = "file_create_temp"
}

/** Holds if cn is a call node genuinely resolved to a filesystem API
 *  (alias-aware through API graphs). */
private predicate resolvedFsCall(API::CallNode cn, string moduleHint, string member, int argIndex, string flowKind) {
  fsMemberTable(moduleHint, member, argIndex, flowKind) and
  cn = API::moduleImport(moduleHint).getMember(member).getACall()
}

/** os.path members with the 0-based positional argument index carrying the
 *  path, grouped by their role in the path pipeline (propagation /
 *  canonicalization / expansion / validation). These are NOT final file
 *  access sinks; they are extracted as the propagation/validation nodes
 *  the pass-1 taint config needs between the task-arg sources and the
 *  open()/os.* sinks (fetch.py:111-:132, copy.py:114-:125/:481/:494,
 *   galaxy/role.py:324-:329, dataloader.py:181-:314). */
private predicate osPathMemberTable(string member, int argIndex, string flowKind) {
  member = "join" and argIndex = 0 and flowKind = "path_join"
  or
  member in ["abspath", "normpath", "realpath", "relpath", "basename", "dirname", "splitext", "split"] and
  argIndex = 0 and flowKind = "path_resolve"
  or
  member in ["expanduser", "expandvars"] and
  argIndex = 0 and flowKind = "path_expand"
  or
  member in ["isfile", "isdir", "exists", "isabs", "islink", "samefile", "getsize"] and
  argIndex = 0 and flowKind = "path_check"
}

/** DataLoader file API members with the 0-based positional argument index
 *  that carries the path/file name (dataloader.py:100-:134 path_exists/
 *  is_file/is_directory/list_directory, :134 _get_file_contents,
 *  :173 path_dwim, :209 path_dwim_relative(path, dirname, source - the
 *  source is argument 2), :264 path_dwim_relative_stack (argument 2),
 *  :337 get_real_file, :74 load_from_file, :394 find_vars_files(path,
 *  name - the name is argument 1), :377 cleanup_tmp_file). */
private predicate loaderApiTable(string member, int argIndex) {
  member in ["get_real_file", "_get_file_contents", "path_dwim", "load_from_file",
             "path_exists", "is_file", "is_directory", "list_directory",
             "cleanup_tmp_file"] and
  argIndex = 0
  or
  member in ["path_dwim_relative", "path_dwim_relative_stack"] and
  argIndex = 2
  or
  member = "find_vars_files" and
  argIndex = 1
}

/** ActionBase file API members with the 0-based positional argument index
 *  that carries the path (action/__init__.py:415 _transfer_file(local_path,
 *  remote_path) - both arguments are paths, both rows are emitted; :433
 *  _transfer_data(remote_path, data); :1167 _find_needle(dirname, needle) -
 *  the needle is argument 1; :637 _remote_expand_user(path, ...); :569
 *  _execute_remote_stat(path, ...); :608 _remote_checksum(path, ...);
 *  :148 _remote_file_exists(path)). */
private predicate actionApiTable(string member, int argIndex) {
  member = "_transfer_file" and (argIndex = 0 or argIndex = 1)
  or
  member = "_transfer_data" and argIndex = 0
  or
  member = "_find_needle" and argIndex = 1
  or
  member in ["_remote_expand_user", "_execute_remote_stat", "_remote_checksum",
             "_remote_file_exists"] and
  argIndex = 0
}

/** LookupBase file API members with the path argument index
 *  (lookup/__init__.py:108 find_file_in_search_path(myvars, subdir,
 *  needle) - the needle is argument 2). */
private predicate lookupApiTable(string member, int argIndex) {
  member = "find_file_in_search_path" and argIndex = 2
}

/** The library's own path-taking API definitions with their path parameter
 *  (function, parameter name, file) - definition rows for the file_api_def
 *  family. Parameters are matched by name so the true path position comes
 *  from Parameter.getPosition(). */
private predicate fileApiDefShape(Function f, Parameter p) {
  /* DataLoader (parsing/dataloader.py) - the vault-aware controller file
     access wrapper; _get_file_contents performs the open() at :157 and
     get_real_file at :355 */
  f.getEnclosingScope().(Class).getName() = "DataLoader" and
  normalizedPathOf(f).matches("%/lib/ansible/parsing/dataloader.py") and
  (
    f.getName() = "_get_file_contents" and p.getName() = "file_name"
    or
    f.getName() = "get_real_file" and p.getName() = "file_path"
    or
    f.getName() = "path_dwim" and p.getName() = "given"
    or
    (f.getName() = "path_dwim_relative" or f.getName() = "path_dwim_relative_stack") and
    p.getName() = "source"
    or
    f.getName() = "find_vars_files" and p.getName() = "name"
    or
    f.getName() = "load_from_file" and p.getName() = "file_name"
    or
    (f.getName() = "path_exists" or f.getName() = "is_file" or
     f.getName() = "is_directory" or f.getName() = "list_directory") and
    p.getName() = "path"
    or
    f.getName() = "cleanup_tmp_file" and p.getName() = "file_path"
  )
  or
  /* ActionBase (plugins/action/__init__.py) - the file transfer/stat
     wrappers used by every action plugin */
  f.getEnclosingScope().(Class).getName() = "ActionBase" and
  normalizedPathOf(f).matches("%/lib/ansible/plugins/action/__init__.py") and
  (
    f.getName() = "_transfer_file" and (p.getName() = "local_path" or p.getName() = "remote_path")
    or
    f.getName() = "_transfer_data" and p.getName() = "remote_path"
    or
    f.getName() = "_find_needle" and p.getName() = "needle"
    or
    (f.getName() = "_remote_expand_user" or f.getName() = "_execute_remote_stat" or
     f.getName() = "_remote_checksum" or f.getName() = "_remote_file_exists") and
    p.getName() = "path"
    or
    f.getName() = "_get_diff_data" and p.getName() = "source"
  )
  or
  /* LookupBase (plugins/lookup/__init__.py) - the search-path resolver of
     the file lookups */
  f.getEnclosingScope().(Class).getName() = "LookupBase" and
  normalizedPathOf(f).matches("%/lib/ansible/plugins/lookup/__init__.py") and
  f.getName() = "find_file_in_search_path" and
  p.getName() = "needle"
  or
  /* module-level wrappers in ansible.utils.path (utils/path.py) -
     unfrackpath canonicalizes via expanduser/expandvars/realpath/normpath
     (:31-:62), makedirs_safe creates directories after a realpath-based
     race check (:65-:87) */
  not f.getEnclosingScope() instanceof Class and
  normalizedPathOf(f).matches("%/lib/ansible/utils/path.py") and
  (
    (f.getName() = "unfrackpath" or f.getName() = "makedirs_safe" or
     f.getName() = "cleanup_tmp_file") and
    p.getName() = "path"
  )
  or
  /* vault secret file readers (parsing/vault/__init__.py) -
     FileVaultSecret._read_file (:415, open(filename, 'rb') at :423) and
     ScriptVaultSecret._read_file (:445); get_file_vault_secret (:373)
     realpaths+expandusers the CLI-supplied filename first */
  f.getEnclosingScope() instanceof Class and
  normalizedPathOf(f).matches("%/lib/ansible/parsing/vault/__init__.py") and
  f.getName() = "_read_file" and
  p.getName() = "filename"
  or
  /* connection transport file APIs (plugins/connection/*.py) -
     put_file(in_path, out_path) / fetch_file(in_path, out_path) of the
     20+ connection plugins (local.py:138/:156 - shutil on the local
     filesystem, chroot.py, docker.py, kubectl.py, paramiko_ssh.py sftp,
     winrm.py); both parameters are path positions and both rows are
     emitted per function */
  f.getEnclosingScope() instanceof Class and
  normalizedPathOf(f).matches("%/lib/ansible/plugins/connection/%") and
  (f.getName() = "put_file" or f.getName() = "fetch_file") and
  (p.getName() = "in_path" or p.getName() = "out_path")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 0: builtin open(...) Name calls - the dominant file API of this
     codebase (304 controller sites + 356 module-side sites; io.open occurs
     once at executor/discovery/python_target.py:19 and is covered by
     family 1); the path is argument 0. Representative controller sites:
     fetch.py:175 open(to_bytes(dest), 'wb') - the fetch destination;
     template.py:112/:172; action/__init__.py:1144; galaxy/role.py:112/:132/
     :155; config/manager.py:304/:320; parsing/vault/__init__.py:423;
     parsing/dataloader.py:157/:355. */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    packageSinkPath(normalizedPathOf(c)) and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* family 1a: resolved filesystem API calls (API graphs, alias-aware) -
     os/shutil/io/tarfile/zipfile/glob/shelve/tempfile members per
     fsMemberTable */
  exists(API::CallNode cn, string m, string member, int idx, string kind |
    resolvedFsCall(cn, m, member, idx, kind) and
    packageSinkPath(astCallOf(cn).getLocation().getFile().getAbsolutePath()) and
    node = astCallOf(cn) and
    flowKind = kind and
    callableName = member and
    argIndex = idx and
    receiver = "" and
    moduleHint = m and
    matchKind = "api"
  )
  or
  /* family 1b: syntax-level module-qualified filesystem API calls
     (`os.walk(...)`, `shutil.rmtree(...)`, `tarfile.open(...)`, ...) per
     fsMemberTable; the receiver column carries the module prefix */
  exists(Call c, Attribute func |
    fsMemberTable(moduleHint, callableName, argIndex, flowKind) and
    func = c.getFunc().(Attribute) and
    func.getName() = callableName and
    func.getObject().(Name).getId() = moduleHint and
    packageSinkPath(normalizedPathOf(c)) and
    node = c and
    matchKind = "ast" and
    receiver = moduleHint
  )
  or
  /* family 2: archive member extraction - .extract(member, path) with the
     destination directory at argument 1 (galaxy/role.py:330
     role_tar_file.extract(member, self.path) - the role install pipeline
     that already stripped '..' at :324-:329; the unarchive module family),
     .extractall(path) with the destination at argument 0, and
     .extractfile(member) reads at argument 0; receiver-agnostic member
     match, labeling filters non-archive receivers */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "extract" and
    packageSinkPath(normalizedPathOf(c)) and
    node = c and
    flowKind = "archive_extract" and
    callableName = "extract" and
    argIndex = 1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "extractall" and
    packageSinkPath(normalizedPathOf(c)) and
    node = c and
    flowKind = "archive_extract" and
    callableName = "extractall" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "extractfile" and
    packageSinkPath(normalizedPathOf(c)) and
    node = c and
    flowKind = "archive_read" and
    callableName = "extractfile" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: ansible path wrappers - makedirs_safe(path) (fetch.py:168,
     creating the fetch dest parent directories) and unfrackpath(path)
     (the canonicalization wrapper used by config/manager.py:164
     resolve_path and the inventory/cli layers); argument 0 carries the
     path */
  exists(Call c |
    (c.getFunc().(Name).getId() = "makedirs_safe" or
     c.getFunc().(Name).getId() = "unfrackpath") and
    packageSinkPath(normalizedPathOf(c)) and
    node = c and
    (
      c.getFunc().(Name).getId() = "makedirs_safe" and
      flowKind = "file_dir_create"
      or
      c.getFunc().(Name).getId() = "unfrackpath" and
      flowKind = "path_resolve"
    ) and
    callableName = c.getFunc().(Name).getId() and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "ansible.utils.path" and
    matchKind = "ast"
  )
  or
  /* family 4: os.path propagation/validation nodes (controller tree only):
     os.path.<member>(...) and the `from os import path` name form
     path.<member>(...) in the files that actually use it
     (plugins/action/include_vars.py:103/:106/:149/:151/:155/:207,
     module_utils/infinibox.py, module_utils/pure.py), plus the
     `from os import walk` name form in include_vars.py:173
     sorted_walk = list(walk(self.source_dir)). Representative sites:
     fetch.py:111 expanduser, :113 isdir, :121 basename, :122/:132 join;
     copy.py:114/:119/:125/:481/:494; galaxy/role.py:324/:329;
     dataloader.py:181-:314. */
  exists(Call c, Attribute func, Attribute mid |
    osPathMemberTable(callableName, argIndex, flowKind) and
    func = c.getFunc().(Attribute) and
    func.getName() = callableName and
    mid = func.getObject().(Attribute) and
    mid.getName() = "path" and
    mid.getObject().(Name).getId() = "os" and
    controllerSinkPath(normalizedPathOf(c)) and
    node = c and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    osPathMemberTable(callableName, argIndex, flowKind) and
    func = c.getFunc().(Attribute) and
    func.getName() = callableName and
    func.getObject().(Name).getId() = "path" and
    (
      normalizedPathOf(c).matches("%/lib/ansible/plugins/action/include_vars.py")
      or
      normalizedPathOf(c).matches("%/lib/ansible/module_utils/infinibox.py")
      or
      normalizedPathOf(c).matches("%/lib/ansible/module_utils/pure.py")
    ) and
    controllerSinkPath(normalizedPathOf(c)) and
    node = c and
    receiver = "path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "walk" and
    normalizedPathOf(c).matches("%/lib/ansible/plugins/action/include_vars.py") and
    controllerSinkPath(normalizedPathOf(c)) and
    node = c and
    flowKind = "file_read" and
    callableName = "walk" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 5: DataLoader file channel - self._loader.<member>(...) call
     sites per loaderApiTable (file.py:72 _get_file_contents,
     filetree.py:183 path_dwim_relative, fetch.py:125 path_dwim,
     copy.py:240/:464 get_real_file + :306 cleanup_tmp_file,
     template.py:105 get_real_file, net_get.py:106 path_dwim_relative,
     script.py:86 get_real_file, include_vars.py:124 find_needle via
     family 6). The wrapper reaches open() at parsing/dataloader.py:157
     (after vault decryption) / :355. */
  exists(Call c, Attribute func, Attribute loader |
    loaderApiTable(callableName, argIndex) and
    func = c.getFunc().(Attribute) and
    func.getName() = callableName and
    loader = func.getObject().(Attribute) and
    loader.getName() = "_loader" and
    loader.getObject().(Name).getId() = "self" and
    packageSinkPath(normalizedPathOf(c)) and
    node = c and
    flowKind = "loader_file_api" and
    receiver = "self._loader" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6: ActionBase file channel - self.<member>(...) call sites per
     actionApiTable (action/__init__.py:434 _transfer_file inside
     _transfer_data; fetch.py:125 path_dwim/:172 _connection.fetch_file,
     copy.py:300/:464, template.py:95, script.py:86, assemble.py:111/:146,
     net_put.py). _transfer_file delegates to
     self._connection.put_file(local_path, remote_path) at :434. */
  exists(Call c, Attribute func |
    actionApiTable(callableName, argIndex) and
    func = c.getFunc().(Attribute) and
    func.getName() = callableName and
    func.getObject().(Name).getId() = "self" and
    packageSinkPath(normalizedPathOf(c)) and
    node = c and
    flowKind = "action_file_api" and
    receiver = "self" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 7: connection file channel - self._connection.put_file(local,
     remote) / self._connection.fetch_file(remote, local) call sites
     (action/__init__.py:434 inside _transfer_file; fetch.py:172
     self._connection.fetch_file(source, dest) - the remote->controller
     file pull whose dest is the controller-side fetch destination);
     argument 1 is the destination in both cases, argument 0 the source */
  exists(Call c, Attribute func, Attribute conn |
    (callableName = "put_file" or callableName = "fetch_file") and
    (argIndex = 0 or argIndex = 1) and
    func = c.getFunc().(Attribute) and
    func.getName() = callableName and
    conn = func.getObject().(Attribute) and
    conn.getName() = "_connection" and
    conn.getObject().(Name).getId() = "self" and
    packageSinkPath(normalizedPathOf(c)) and
    node = c and
    flowKind = "connection_file_api" and
    receiver = "self._connection" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 8: LookupBase file channel -
     self.find_file_in_search_path(variables, subdir, needle) call sites
     (lookup/file.py:68, fileglob.py:61, first_found.py:168); argument 2
     is the searched file name; the wrapper reaches DataLoader
     path_dwim_relative_stack (dataloader.py:264) */
  exists(Call c, Attribute func |
    lookupApiTable(callableName, argIndex) and
    func = c.getFunc().(Attribute) and
    func.getName() = callableName and
    func.getObject().(Name).getId() = "self" and
    packageSinkPath(normalizedPathOf(c)) and
    node = c and
    flowKind = "lookup_file_api" and
    receiver = "self" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 9: file_api_def definition rows - the library's own
     path-taking API definitions with the true path parameter position:
     DataLoader methods (parsing/dataloader.py), ActionBase methods
     (plugins/action/__init__.py), LookupBase.find_file_in_search_path
     (plugins/lookup/__init__.py), ansible.utils.path
     unfrackpath/makedirs_safe/cleanup_tmp_file (utils/path.py),
     FileVaultSecret/ScriptVaultSecret._read_file
     (parsing/vault/__init__.py) and every connection plugin's
     put_file/fetch_file(in_path, out_path) (plugins/connection/*.py);
     arg_index is the 0-based parameter position including the self slot */
  exists(Function f, Parameter p |
    fileApiDefShape(f, p) and
    p = f.getAnArg() and
    not p.isSelf() and
    packageSinkPath(normalizedPathOf(f)) and
    node = p and
    flowKind = "file_api_def" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    (
      f.getEnclosingScope() instanceof Class and
      receiver = f.getEnclosingScope().(Class).getName()
      or
      not f.getEnclosingScope() instanceof Class and
      receiver = ""
    ) and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind)
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
