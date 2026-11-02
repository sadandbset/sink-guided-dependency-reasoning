/**
 * @name thefuck CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the
 *   thefuck CodeQL database (thefuck 3.30, creation sha 6da0bc55): the
 *   file open family (os.open(output, os.O_CREAT | os.O_TRUNC |
 *   os.O_RDWR) entrypoints/shell_logger.py:74 - THE create/truncate sink
 *   whose argument 0 is the CLI -l/--shell-logger value; os.open(
 *   os.environ['THEFUCK_OUTPUT_LOG'], os.O_RDONLY) read_log.py:93;
 *   io.open(history_file_name, 'r') shells/generic.py:60 - the HISTFILE
 *   env read; builtin open() calls shells/fish.py:124 (history append),
 *   ssh_known_hosts.py:33/:36 (read then rewrite of the known_hosts file
 *   whose path is regex-extracted from the failed command's output),
 *   utils.py:15 (os.devnull literal - expected FP); shelve.open(
 *   cache_path) utils.py:217/:222 - the XDG_CACHE_HOME-derived shelve
 *   backing file; pathlib .open member calls conf.py:39 settings_path.
 *   open(mode='w') - settings.py created inside the env-controlled user
 *   dir, not_configured.py:42/:62 tracker open write/read and :78/:85
 *   shell-config open read/append); the file remove family (os.remove(
 *   file) dirty_untar.py:45 and dirty_unzip.py:49 - argument 0 is the
 *   UNVALIDATED archive entry name, '..' segments escape the CWD; and
 *   os.remove(cache_path) utils.py:221); the file mkdir family (
 *   rules_dir.mkdir(parents=True) conf.py:64 inside the XDG user dir and
 *   os.makedirs(cache_dir) utils.py:233 - the XDG_CACHE_HOME dir); the
 *   archive open family (tarfile.TarFile(...) dirty_untar.py:42 and
 *   zipfile.ZipFile(...) dirty_unzip.py:9/:46 - argument 0 is the archive
 *   path taken from the failed command's argv); the file stat family
 *   (os.path.isfile/isdir/exists/getsize/getmtime/access incl. the
 *   command.output-derived checks fix_file.py:52, the script_parts checks
 *   cat_dir.py:9, chmod_x.py:8/:10, has_exists_script.py:7,
 *   grep_arguments_order.py:7, ln_s_order.py:8, prove_recursively.py:13,
 *   the HISTFILE isfile at shells/generic.py:59 and fish.py:123, the
 *   THEFUCK_OUTPUT_LOG getsize at read_log.py:65, the cache getmtime at
 *   utils.py:242, the socket-path exists at output_readers/
 *   shell_logger.py:26, the brew tap isdir/listdir at
 *   brew_unknown_command.py:36 and the XDG is_dir checks at conf.py:51/
 *   :63; pathlib .exists/.is_dir/.is_file member calls incl. git_add.
 *   py:13 Path(pathspec).exists() over the output-regex pathspec and
 *   path_from_history.py:50 Path(path).expanduser().exists()); the
 *   listing family (os.listdir brew_install.py:15, brew_unknown_command.
 *   py:17/:38/:49, cd_correction.py:16; .iterdir utils.py:127,
 *   workon_doesnt_exists.py:12); the pathlib pipeline (Path(...)
 *   constructors conf.py:47/:48, corrector.py:29/:31/:34, not_configured.
 *   py:31/:77/:84, utils.py:214/:255, shells/generic.py:154,
 *   git_add.py:13, path_from_history.py:50, scm_correction.py:18,
 *   workon_doesnt_exists.py:8; .joinpath conf.py:37/:62/:70,
 *   corrector.py:29/:31/:35, not_configured.py:31, utils.py:214;
 *   os.path.join bash.py:46/:77/:78, zsh.py:51, utils.py:66,
 *   cd_correction.py:16/:58; the expanduser/absolute/split wrapper
 *   family); the code-load family (imp.load_source at conf.py:69 - the
 *   settings.py module inside the XDG user dir, argument 1 - and
 *   types.py:144 - rule modules, argument 1); the socket connect family
 *   (client.connect(_get_socket_path()) output_readers/shell_logger.py:31
 *   - argument 0 is the SHELL_LOGGER_SOCKET env path); and definition
 *   rows for the package's own path-consuming internal APIs (Rule.
 *   from_path path, get_loaded_rules rules_paths, shell_logger output,
 *   Settings.init args, Cache._get_mtime path, _tar_file cmd, _zip_file
 *   command, _get_actual_file parts, _get_destination script_parts,
 *   _get_directory_names_only path, _get_brew_commands brew_path_prefix,
 *   path_from_history _get_destination command, _search output) with the
 *   true parameter positions. NO base-directory containment, '..'
 *   rejection, canonicalization or separator-rewrite guard exists
 *   anywhere on these paths (see detection.json
 *   guardAndTraversalEvidence). Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not
 *   database analyze). This is a plain multi-column select query on
 *   purpose: @kind problem is the wrong shape for candidate tables and
 *   @kind table is not assumed to exist.
 * @id iris/thefuck/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member name ("open" for all open channels,
 *                   "remove", "mkdir", "makedirs", "TarFile", "ZipFile",
 *                   "isfile"/"isdir"/"exists"/"getsize"/"getmtime"/
 *                   "access"/"listdir"/"iterdir" for the stat and listing
 *                   families, "Path" for construction rows, "joinpath"/
 *                   "join" for pipeline rows, "expanduser"/"absolute"/
 *                   "split" for wrapper rows, "load_source", "connect",
 *                   or the function name for file_api_def definition rows)
 *   4. flow_kind  - "file_open" (open(...)/.open(...)/shelve.open - the
 *                   path argument or receiver), "file_remove" (os.remove
 *                   argument 0), "file_mkdir" (.mkdir receiver /
 *                   os.makedirs argument 0), "archive_open" (tarfile.
 *                   TarFile/zipfile.ZipFile argument 0), "file_stat"
 *                   (os.path.* checks, .exists/.is_dir/.is_file/...),
 *                   "file_read" (os.listdir argument 0, .iterdir
 *                   receiver), "path_ctor" (Path() construction),
 *                   "path_join" (.joinpath / os.path.join argument 0),
 *                   "path_wrapper" (os.path.expanduser/os.path.split and
 *                   the .expanduser/.absolute members), "code_load" (
 *                   imp.load_source argument 1 - module file path),
 *                   "socket_connect" (.connect argument 0 - unix socket
 *                   path), "file_api_def" (definition row of a
 *                   path-consuming internal API, carrying the path
 *                   parameter position)
 *   5. receiver   - syntactic receiver hint ("" for builtin/module-level
 *                   calls, "os"/"io"/"shelve"/"os.path"/"tarfile"/
 *                   "zipfile"/"imp" for module-qualified channels, the
 *                   base name of the object expression for member calls
 *                   ("settings_path"/"tracker_path"/"path"/"archive"/
 *                   "client"/"rules_dir"/"root"/...), "<expr>" when the
 *                   object expression is neither Name nor Attribute;
 *                   enclosing class name for file_api_def rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "builtins"/"io"/"os"/"os.path"/"shelve"/
 *                   "tarfile"/"zipfile"/"pathlib"/"thefuck.system"/"imp"/
 *                   "socket" for the stdlib/wrapper channels
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for open/Path/joinpath/join/remove/
 *                   makedirs/TarFile/ZipFile/os.path-check/listdir/
 *                   rows; argument 1 for the load_source rows - the
 *                   module path is the second positional argument; -1
 *                   when the receiver carries the path (.open/.mkdir/
 *                   .expanduser/.absolute/.iterdir/stat-family member
 *                   rows); the parameter position for file_api_def rows,
 *                   including the self slot)
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
 * open channels (os.open/io.open/open/shelve.open/.open), os.remove,
 * mkdir/os.makedirs, the tar/zip archive opens, the os.listdir channel,
 * the stat family, the Path/joinpath/os.path.join construction pipeline
 * feeding them, the os.path.expanduser/split and .expanduser/.absolute
 * wrappers, imp.load_source (module file loading) and the unix socket
 * connect - NOT every path string construction node (the .as_posix()
 * conversions at utils.py:214/:255, .strip('"') at utils.py:65, the
 * os.sep split at cd_correction.py:40 and the shell command-string
 * assembly are pure and are documented in detection.json uncoveredCases
 * instead). mmap.mmap rows are NOT emitted: their argument 0 is the
 * integer fd of the paired os.open row, not a path parameter.
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no sink row is expected to resolve at API level:
 * all file access flows through bare module names (os, os.path, io, shelve,
 * tarfile, zipfile, imp) and instance members on local variables
 * (settings_path, tracker_path, history_file_name, cache_path, archive,
 * client, rules_dir, root) that API graphs cannot bind to stdlib members,
 * and those modules are not part of the database (only the thefuck tree
 * is). Member-name matching is receiver-name-agnostic on purpose;
 * receiver hints are emitted for the labeling step, and name-collision
 * noise (a .exists()/.open() on a non-path object) is left to labeling.
 * The os.path.* families require the syntactic `os.path.` receiver chain,
 * which removes the common false shapes.
 *
 * Excluded paths (applied to every row): /tests/ and /thefuck-db/ (the
 * CodeQL database directory nested inside the source tree). All families
 * are constrained to thefuck/ by construction, so root dev scripts
 * (release.py, fastentrypoints.py, setup.py) produce no rows (documented
 * in detection.json excludedCandidates). utils.py:15 open(os.devnull)
 * IS row-matched and expected to be labeled none/FP.
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
  path.replaceAll("\\", "/").matches("%/thefuck-db/%")
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
  /* family 1a: file_open - os.open(...) module-qualified calls:
     entrypoints/shell_logger.py:74 os.open(output, os.O_CREAT |
     os.O_TRUNC | os.O_RDWR) - THE create/truncate sink, argument 0 is
     the CLI -l/--shell-logger value (the shell_logger entrypoint
     parameter); read_log.py:93 os.open(os.environ[
     'THEFUCK_OUTPUT_LOG'], os.O_RDONLY) - argument 0 is the env path
     (the mmap at :94 operates on the returned fd and is not emitted). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 1b: file_open - io.open(history_file_name, 'r', ...) at
     shells/generic.py:60 inside Generic._get_history_lines: argument 0
     is the HISTFILE env value (or the ~/.bash_history fallback) read
     from bash.py:69 / zsh.py:74 / tcsh.py:29; the os.path.isfile
     check at :59 is the TOCTOU check-then-use evidence. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "io" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "io" and
    moduleHint = "io" and
    matchKind = "ast"
  )
  or
  /* family 1c: file_open - shelve.open(cache_path) at utils.py:217/:222
     inside Cache._setup_db: argument 0 is
     Path(os.getenv('XDG_CACHE_HOME', ~/.cache)).joinpath('thefuck')
     .as_posix() - the dbm backing file is created/opened inside the
     env-controlled cache dir. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "shelve" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "shelve" and
    moduleHint = "shelve" and
    matchKind = "ast"
  )
  or
  /* family 1d: file_open - builtin open(...) calls: ssh_known_hosts.py:33
     open(filepath, 'r') and :36 open(filepath, 'w') - THE read+rewrite
     pair whose path is regex-extracted from the failed command's output
     (side_effect, :31-:36); shells/fish.py:124 open(history_file_name,
     'a') - fish history append (fixed ~/.config/fish/fish_history);
     utils.py:15 open(os.devnull, 'w') - literal device path, expected
     none/FP row. */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* family 1e: file_open - pathlib .open(...) member calls (the receiver
     is the path): conf.py:39 settings_path.open(mode='w') - settings.py
     CREATED inside the XDG_CONFIG_HOME-derived user dir (the is_file
     guard at :38); not_configured.py:42 _get_not_configured_usage_
     tracker_path().open(mode) - tracker write under gettempdir(),
     :62 tracker_path.open('r') - tracker read, :78 path.open('r') and
     :85 path.open('a') - shell-config read/append (Path(configuration_
     details.path).expanduser(), operator-owned literal paths from
     how_to_configure). Objects that are neither Name nor Attribute
     (the :42 Call receiver) and Name receivers other than os/io/shelve
     are matched; os./io./shelve. are covered by families 1a-1c. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    not func.getObject() instanceof Name and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func, Name obj |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    obj = func.getObject().(Name) and
    obj.getId() != "os" and
    obj.getId() != "io" and
    obj.getId() != "shelve" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 2: file_remove - os.remove(...) calls: dirty_untar.py:45
     os.remove(file) and dirty_unzip.py:49 os.remove(file) - argument 0
     is the archive entry name from getnames()/namelist(), passed with
     NO validation of '..', absolute paths or separators (directories
     are silently skipped via the OSError except; a '..' file entry
     deletes outside the CWD); utils.py:221 os.remove(cache_path) -
     argument 0 is the XDG_CACHE_HOME-derived shelve path (the stale
     cache eviction branch). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "remove" and
    func.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_remove" and
    callableName = "remove" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 3a: file_mkdir - .mkdir(...) member calls (receiver is the
     path): conf.py:64 rules_dir.mkdir(parents=True) - the rules
     directory CREATED inside the XDG_CONFIG_HOME-derived user dir
     (Settings._setup_user_dir, :62-:64). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "mkdir" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_mkdir" and
    callableName = "mkdir" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 3b: file_mkdir - os.makedirs(cache_dir) at utils.py:233
     inside Cache._get_cache_dir: argument 0 is the XDG_CACHE_HOME env
     value (OSError-tolerated existence check via os.path.isdir at
     :235). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "makedirs" and
    func.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_mkdir" and
    callableName = "makedirs" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 4: archive_open - tarfile.TarFile(...) at dirty_untar.py:42
     and zipfile.ZipFile(...) at dirty_unzip.py:9 (in _is_bad_zip) / :46
     (in side_effect): argument 0 is the archive path derived from the
     failed command's argv (_tar_file(old_cmd.script_parts)[0] /
     _zip_file(old_cmd)); the entry names then flow to os.remove
     (family 2) via getnames()/namelist(). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "TarFile" or func.getName() = "ZipFile") and
    (func.getObject().(Name).getId() = "tarfile" or
     func.getObject().(Name).getId() = "zipfile") and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "archive_open" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5a: file_stat - os.path.isfile/isdir/exists/getsize/
     getmtime/access calls (argument 0 is the path): the command-derived
     checks fix_file.py:52 (isfile of the output-regex group 'file'),
     cat_dir.py:9, chmod_x.py:8/:10, has_exists_script.py:7,
     grep_arguments_order.py:7 x2, ln_s_order.py:8,
     prove_recursively.py:13, brew_unknown_command.py:36/:50; the env
     path checks read_log.py:65 (getsize of THEFUCK_OUTPUT_LOG),
     output_readers/shell_logger.py:26 (exists of the socket path);
     the HISTFILE isfile at shells/generic.py:59 and fish.py:123; the
     cache getmtime at utils.py:242 and the which() fallback isfile +
     access at utils.py:57; the XDG is_dir at utils.py:235. */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    base = func.getObject().(Attribute) and
    base.getName() = "path" and
    base.getObject().(Name).getId() = "os" and
    (func.getName() = "isfile" or func.getName() = "isdir" or
     func.getName() = "exists" or func.getName() = "getsize" or
     func.getName() = "getmtime" or func.getName() = "access") and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_stat" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 5b: file_stat - pathlib metadata member calls (receiver is
     the path): .exists() at git_add.py:13 (Path(pathspec) over the
     command.output regex pathspec), path_from_history.py:50 (Path(
     path).expanduser() over the history path), not_configured.py:58
     (tracker_path), conf.py:38 (settings_path.is_file()); .is_dir()
     at conf.py:51/:63 (legacy and XDG user dirs), corrector.py:36 (
     contrib_rules), scm_correction.py:18, workon_doesnt_exists.py:9;
     .stat()/.lstat()/.is_file()/.is_symlink() included for shape
     completeness (no call sites observed in this snapshot). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "exists" or func.getName() = "is_dir" or
     func.getName() = "is_file" or func.getName() = "is_symlink" or
     func.getName() = "stat" or func.getName() = "lstat") and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_stat" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 6a: file_read - os.listdir(...) calls (argument 0 is the
     path): cd_correction.py:16 (the cwd spell-correction walk over
     command.script_parts), brew_install.py:15,
     brew_unknown_command.py:17/:38/:49 (the brew prefix + '/Library/...'
     concatenations - the construction nodes themselves are string
     concatenation and are documented in detection.json uncoveredCases). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "listdir" and
    func.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_read" and
    callableName = "listdir" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 6b: file_read - .iterdir() member calls (receiver is the
     path): utils.py:127 Path(path).iterdir() over each PATH env entry
     in get_all_executables, workon_doesnt_exists.py:12 root.iterdir()
     over Path('~/.virtualenvs'). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "iterdir" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "file_read" and
    callableName = "iterdir" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 7: path_ctor - Path(...) constructor calls (func is the bare
     Name `Path`, imported from thefuck.system - a pathlib/pathlib2
     re-export with a monkey-patched expanduser): conf.py:47 Path(
     xdg_config_home, 'thefuck') - THE XDG env construction, :48 Path(
     '~', '.thefuck'); corrector.py:29/:31/:34 (bundled rules, user
     rules, sys.path contrib globs); not_configured.py:31 (gettempdir
     tracker), :77/:84 (shell config); utils.py:214 (cache path), :255
     (cache depends_on name); shells/generic.py:154; rules: git_add.
     py:13 (output-regex pathspec), path_from_history.py:50 (history
     path), scm_correction.py:18, workon_doesnt_exists.py:8. Argument 0
     carries the leading path component. */
  exists(Call c |
    c.getFunc().(Name).getId() = "Path" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "path_ctor" and
    callableName = "Path" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "thefuck.system" and
    matchKind = "ast"
  )
  or
  /* family 8a: path_join - .joinpath(argument 0) member calls:
     conf.py:37 user_dir.joinpath('settings.py') - THE settings.py path
     inside the XDG user dir (written at :39, loaded at :69-:70), :62
     user_dir.joinpath('rules') - the rules dir mkdir'd at :64, :70
     user_dir.joinpath('settings.py') in load_source; corrector.py:29/
     :31/:35 (rules dir joins); not_configured.py:31 (tracker name);
     utils.py:214 Path(cache_dir).joinpath('thefuck') - the shelve
     path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "joinpath" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "path_join" and
    callableName = "joinpath" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 8b: path_join - os.path.join(argument 0) calls: bash.py:46 /
     zsh.py:51 (the instant-mode log path under gettempdir(), whose
     THEFUCK_OUTPUT_LOG value is then opened by the shell-logger
     entrypoint), bash.py:77/:78 (literal ~/.bashrc/.bash_profile
     existence probes in how_to_configure), utils.py:66 (PATH env
     entry + program name in the which() fallback), cd_correction.py:16
     (parent + child in the cd spell-correction walk) and :58 (cwd +
     best_matches[0] - the corrected cd destination). */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    base = func.getObject().(Attribute) and
    base.getName() = "path" and
    base.getObject().(Name).getId() = "os" and
    func.getName() = "join" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "path_join" and
    callableName = "join" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 9a: path_wrapper - os.path.expanduser(argument 0) calls:
     bash.py:70 / zsh.py:75 / tcsh.py:30 (the ~/.bash_history/
     ~/.zsh_history/~/.history HISTFILE fallbacks), fish.py:86
     (~/.config/fish/fish_history), utils.py:227 (~/.cache cache
     fallback). No canonicalization or containment is performed
     anywhere - expanduser only resolves the leading '~'. */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    base = func.getObject().(Attribute) and
    base.getName() = "path" and
    base.getObject().(Name).getId() = "os" and
    func.getName() = "expanduser" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "expanduser" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 9b: path_wrapper - os.path.split(argument 0) calls:
     utils.py:59 (os.path.split(program) in the which() fallback),
     cd_correction.py:54 (cwd = os.path.split(cwd)[0] - the '..'
     segment handling of the cd walk). */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    base = func.getObject().(Attribute) and
    base.getName() = "path" and
    base.getObject().(Name).getId() = "os" and
    func.getName() = "split" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "split" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 9c: path_wrapper - .expanduser() / .absolute() member calls
     (receiver is the path): .expanduser at conf.py:47/:48 (the XDG/
     legacy user dirs), not_configured.py:77/:84 (shell config),
     path_from_history.py:50 and utils.py:255 (cache depends_on names),
     workon_doesnt_exists.py:8, shells/generic.py:154; .absolute at
     utils.py:255. The thefuck.system module monkey-patches
     Path.expanduser on Windows (system/win32.py:38-43). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "expanduser" or func.getName() = "absolute") and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 10: code_load - imp.load_source(name, path) calls (argument 1
     is the module file path): conf.py:69-:70 load_source('settings',
     text_type(self.user_dir.joinpath('settings.py'))) - the settings
     module loaded from inside the XDG_CONFIG_HOME-derived user dir
     (code + values from an env-controlled location); types.py:144
     load_source(name, str(path)) - every rule module, where path is
     globbed from thefuck/rules, the user rules dir and sys.path
     thefuck_contrib_* packages (corrector.py:29-47). */
  exists(Call c |
    c.getFunc().(Name).getId() = "load_source" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "code_load" and
    callableName = "load_source" and
    argIndex = 1 and
    receiver = "" and
    moduleHint = "imp" and
    matchKind = "ast"
  )
  or
  /* family 11: socket_connect - client.connect(...) at
     output_readers/shell_logger.py:31 inside _get_last_n: argument 0
     is _get_socket_path() = os.environ.get(
     const.SHELL_LOGGER_SOCKET_ENV) - a filesystem-path-addressed unix
     socket connection. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "connect" and
    normalizedPathOf(c).matches("%/thefuck/output_readers/%") and
    node = c and
    flowKind = "socket_connect" and
    callableName = "connect" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "socket" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 12: file_api_def - definition rows of the package's own
     path-consuming internal APIs (candidates for summary/propagation
     labeling). Positions include the self slot for methods. */

  /* Rule.from_path(cls, path) - types.py:131, path at position 1: the
     rule module file path consumed by load_source(name, str(path)) at
     types.py:144 */
  exists(Function fn, Parameter p |
    fn.getName() = "from_path" and
    fn.getEnclosingScope().(Class).getName() = "Rule" and
    normalizedPathOf(fn).matches("%/thefuck/types.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "from_path" and
    argIndex = p.getPosition() and
    receiver = "Rule" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* get_loaded_rules(rules_paths) - corrector.py:8, rules_paths at
     position 0: the globbed rule file list iterated into
     Rule.from_path */
  exists(Function fn, Parameter p |
    fn.getName() = "get_loaded_rules" and
    normalizedPathOf(fn).matches("%/thefuck/corrector.py") and
    p = fn.getArgByName("rules_paths") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "get_loaded_rules" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* shell_logger(output) - entrypoints/shell_logger.py:64, output at
     position 0: the CLI -l value opened by os.open at :74 */
  exists(Function fn, Parameter p |
    fn.getName() = "shell_logger" and
    normalizedPathOf(fn).matches("%/thefuck/entrypoints/shell_logger.py") and
    p = fn.getArgByName("output") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "shell_logger" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Settings.init(self, args) - conf.py:17, args at position 1: the
     argparse Namespace whose flags merge into settings at :115-:127 */
  exists(Function fn, Parameter p |
    fn.getName() = "init" and
    fn.getEnclosingScope().(Class).getName() = "Settings" and
    normalizedPathOf(fn).matches("%/thefuck/conf.py") and
    p = fn.getArgByName("args") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "init" and
    argIndex = p.getPosition() and
    receiver = "Settings" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Cache._get_mtime(self, path) - utils.py:240, path at position 1:
     the cache depends_on path stat'ed by os.path.getmtime at :242 */
  exists(Function fn, Parameter p |
    fn.getName() = "_get_mtime" and
    fn.getEnclosingScope().(Class).getName() = "Cache" and
    normalizedPathOf(fn).matches("%/thefuck/utils.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "_get_mtime" and
    argIndex = p.getPosition() and
    receiver = "Cache" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* _tar_file(cmd) - dirty_untar.py:21, cmd at position 0: returns the
     (archive, dir) pair derived from the failed command's script_parts;
     the archive element opens tarfile.TarFile at :42 */
  exists(Function fn, Parameter p |
    fn.getName() = "_tar_file" and
    normalizedPathOf(fn).matches("%/thefuck/rules/dirty_untar.py") and
    p = fn.getArgByName("cmd") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "_tar_file" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* _zip_file(command) - dirty_unzip.py:15, command at position 0:
     returns the .zip path derived from the failed command's argv,
     opened by zipfile.ZipFile at :9/:46 */
  exists(Function fn, Parameter p |
    fn.getName() = "_zip_file" and
    normalizedPathOf(fn).matches("%/thefuck/rules/dirty_unzip.py") and
    p = fn.getArgByName("command") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "_zip_file" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* _get_actual_file(parts) - grep_arguments_order.py:5, parts at
     position 0: the script_parts whose elements are probed with
     os.path.isfile/isdir at :7 */
  exists(Function fn, Parameter p |
    fn.getName() = "_get_actual_file" and
    normalizedPathOf(fn).matches("%/thefuck/rules/grep_arguments_order.py") and
    p = fn.getArgByName("parts") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "_get_actual_file" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* _get_destination(script_parts) - ln_s_order.py:4, script_parts at
     position 0: the argv elements probed with os.path.exists at :8 */
  exists(Function fn, Parameter p |
    fn.getName() = "_get_destination" and
    normalizedPathOf(fn).matches("%/thefuck/rules/ln_s_order.py") and
    p = fn.getArgByName("script_parts") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "_get_destination" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* _get_directory_names_only(path) - brew_unknown_command.py:44, path
     at position 0: the brew taps path walked with os.listdir +
     os.path.isdir at :49/:50 */
  exists(Function fn, Parameter p |
    fn.getName() = "_get_directory_names_only" and
    normalizedPathOf(fn).matches("%/thefuck/rules/brew_unknown_command.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "_get_directory_names_only" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* _get_brew_commands(brew_path_prefix) - brew_unknown_command.py:9,
     brew_path_prefix at position 0: the `brew --prefix` output
     concatenated into the cmd/tap paths listed at :17/:38 */
  exists(Function fn, Parameter p |
    fn.getName() = "_get_brew_commands" and
    normalizedPathOf(fn).matches("%/thefuck/rules/brew_unknown_command.py") and
    p = fn.getArgByName("brew_path_prefix") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "_get_brew_commands" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* _get_destination(command) - path_from_history.py:15, command at
     position 0: the Command whose .output is regex-walked at :18 and
     whose destination is replaced into the corrected script */
  exists(Function fn, Parameter p |
    fn.getName() = "_get_destination" and
    normalizedPathOf(fn).matches("%/thefuck/rules/path_from_history.py") and
    p = fn.getArgByName("command") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "_get_destination" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* _search(output) - fix_file.py:49, output at position 0: the failed
     command's output regex-walked; group 'file' is probed with
     os.path.isfile at :52 and formatted into the editor command */
  exists(Function fn, Parameter p |
    fn.getName() = "_search" and
    normalizedPathOf(fn).matches("%/thefuck/rules/fix_file.py") and
    p = fn.getArgByName("output") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "_search" and
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
