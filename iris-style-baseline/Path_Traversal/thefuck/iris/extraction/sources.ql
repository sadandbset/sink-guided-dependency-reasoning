/**
 * @name thefuck CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   thefuck CodeQL database (thefuck 3.30, creation sha 6da0bc55 - a pure
 *   CLI shell-command corrector with NO web surface; the untrusted
 *   boundaries are the failed command's script+output, the argparse CLI,
 *   the process environment, and tar/zip archive contents consumed by rule
 *   side effects): the environment path family (os.environ.get(
 *   'XDG_CONFIG_HOME') conf.py:46 whose value becomes the user config dir
 *   that settings.py is written to, loaded from and rules/ is created in;
 *   os.environ.get('HISTFILE') bash.py:69 / zsh.py:74 / tcsh.py:29 feeding
 *   the io.open history read at shells/generic.py:60; os.environ[
 *   'THEFUCK_OUTPUT_LOG'] read_log.py:65/:93 feeding os.path.getsize and
 *   os.open; os.environ.get(const.SHELL_LOGGER_SOCKET_ENV)
 *   output_readers/shell_logger.py:13 feeding os.path.exists and
 *   socket.connect; os.getenv('XDG_CACHE_HOME') utils.py:228 feeding
 *   os.makedirs/shelve.open/os.remove; os.environ['PATH']/:.get('PATH')
 *   utils.py:64/:125 feeding os.path.join+isfile and Path(path).iterdir);
 *   the environment content family (os.environ['PS1'] read_log.py:16/:85,
 *   os.environ.get('TF_HISTORY') fix_command.py:16 / os.environ[
 *   'TF_HISTORY'] fix_command.py:19 - the shell history exported by the
 *   alias, os.environ['EDITOR'] fix_file.py:71/:76, and the generic
 *   os.environ[env] THEFUCK_* settings read conf.py:93); the CLI boundary
 *   (self._parser.parse_args(arguments) argument_parser.py:86 - sys.argv
 *   when run via the shell alias; known_args.shell_logger reads
 *   entrypoints/main.py:32/:38 - the -l value opened with O_CREAT|
 *   O_TRUNC|O_RDWR at entrypoints/shell_logger.py:74; known_args.
 *   force_command / known_args.command fix_command.py:14/:15 and
 *   :17); the
 *   process-boundary parameter family (shell_logger(output) pos 0,
 *   fix_command(known_args) pos 0, Command.__init__ script/output pos 1/2,
 *   from_raw_script raw_script pos 1, Rule.from_path path pos 1,
 *   get_loaded_rules rules_paths pos 0, Settings.init args pos 1,
 *   Cache._get_mtime path pos 1); the failed-command payload families
 *   (command.output / old_cmd.output / cmd.output attribute reads across
 *   thefuck/rules/ - the tool's dominant untrusted input, consumed by
 *   path-deriving regexes in fix_file.py:60/:66, git_add.py:12,
 *   ssh_known_hosts.py:31, path_from_history.py:18, no_such_file.py:24;
 *   command.script_parts / old_cmd.script_parts / cmd.script_parts reads
 *   across thefuck/rules/ - the failed command's argv, consumed by the
 *   file-stat checks in cat_dir.py:9, chmod_x.py:8/:10,
 *   has_exists_script.py:7, grep_arguments_order.py:7,
 *   prove_recursively.py:13, the cd walk in cd_correction.py:16/:58 and
 *   the archive paths in dirty_untar.py:42 / dirty_unzip.py:46); and the
 *   archive entry-name family (archive.getnames() dirty_untar.py:43 and
 *   archive.namelist() dirty_unzip.py:10/:47 - entry names passed
 *   unvalidated to os.remove at dirty_untar.py:45 / dirty_unzip.py:49).
 *   Operator-owned inputs that are NOT attacker-controlled (the shell
 *   config paths from how_to_configure, '~/.virtualenvs', os.devnull, the
 *   brew prefix from a local subprocess) are NOT emitted as sources -
 *   documented in detection.json instead. Raw BQRS extraction query: run
 *   with `codeql query run` and decode with `codeql bqrs decode` (not
 *   database analyze). This is a plain multi-column select query on
 *   purpose: @kind problem is the wrong shape for candidate tables and
 *   @kind table is not assumed to exist.
 * @id iris/thefuck/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (e.g. "get", "environ",
 *                   "getenv", "parse_args", "shell_logger", "output",
 *                   "script_parts", "getnames", "namelist", or the
 *                   function name for parameter rows)
 *   4. flow_kind  - "env_path" (environment variable whose VALUE is a
 *                   filesystem path), "env_content" (environment variable
 *                   whose value is command/content input: PS1, TF_HISTORY,
 *                   EDITOR, THEFUCK_* settings), "cli" (argparse boundary
 *                   and known_args field reads), "param" (process-boundary
 *                   function parameters), "command_output" (the failed
 *                   command's terminal output attribute reads in rules),
 *                   "command_script" (the failed command's argv
 *                   script_parts attribute reads in rules),
 *                   "archive_entry_name" (tar/zip entry-name reads)
 *   5. receiver   - syntactic receiver hint ("os.environ" / "os" for the
 *                   env families, "self._parser" for the parse_args row,
 *                   "known_args" for CLI field rows, "command"/"old_cmd"/
 *                   "cmd" for the payload families, "archive" for the
 *                   entry-name rows, "" when none, enclosing class name
 *                   for parameter rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal
 *                   module hint "os" for the environment channels
 *   7. arg_index  - -1 for every non-param row in this query (the value
 *                   is the return value of the call or the attribute /
 *                   subscript read, not a call argument); for "param"
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
 * the environment reads flow through the bare os module name, the CLI fields
 * are argparse Namespace attribute reads, the payload families are
 * duck-typed attribute reads on rule parameters, and os/argparse are not
 * part of the database (only the thefuck tree is). All families below are
 * AST-level matches and the match_kind column is kept "ast" for
 * cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (unit and functional test
 * trees) and /thefuck-db/ (the CodeQL database directory sits inside the
 * source tree). All families are additionally constrained to thefuck/ by
 * construction, so root dev scripts (release.py, fastentrypoints.py,
 * setup.py) produce no rows.
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

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: env_path - os.environ.get(<path env name>, ...) calls.
     XDG_CONFIG_HOME (conf.py:46 - the user config dir: settings.py
     written/opened and rules/ created under it), HISTFILE (bash.py:69,
     zsh.py:74, tcsh.py:29 - the history file read by io.open at
     shells/generic.py:60), PATH (utils.py:125 - walked with
     os.path.join + isfile/access and Path(path).iterdir). The first
     positional argument is a string literal; the value is the call's
     return value (argIndex -1). */
  exists(Call c, Attribute f1, Attribute f2, StringLiteral lit |
    f1 = c.getFunc().(Attribute) and
    f1.getName() = "get" and
    f2 = f1.getObject().(Attribute) and
    f2.getName() = "environ" and
    f2.getObject().(Name).getId() = "os" and
    lit = c.getPositionalArg(0).(StringLiteral) and
    (lit.getText() = "XDG_CONFIG_HOME" or
     lit.getText() = "HISTFILE" or
     lit.getText() = "PATH") and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "env_path" and
    callableName = "get" and
    argIndex = -1 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 1: env_path - os.environ[<path env name>] subscript reads:
     os.environ['THEFUCK_OUTPUT_LOG'] at read_log.py:65 (inside
     os.path.getsize) and :93 (inside os.open) and os.environ["PATH"] at
     utils.py:64 (inside the which() fallback walk). */
  exists(Subscript s, Attribute envattr, StringLiteral idx |
    envattr = s.getObject().(Attribute) and
    envattr.getName() = "environ" and
    envattr.getObject().(Name).getId() = "os" and
    idx = s.getIndex().(StringLiteral) and
    (idx.getText() = "THEFUCK_OUTPUT_LOG" or
     idx.getText() = "PATH") and
    normalizedPathOf(s).matches("%/thefuck/%") and
    node = s and
    flowKind = "env_path" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 1: env_path - os.getenv("XDG_CACHE_HOME", ...) at utils.py:228:
     the cache dir base for os.makedirs (:233), shelve.open (:217/:222) and
     os.remove (:221). */
  exists(Call c, Attribute f, StringLiteral lit |
    f = c.getFunc().(Attribute) and
    f.getName() = "getenv" and
    f.getObject().(Name).getId() = "os" and
    lit = c.getPositionalArg(0).(StringLiteral) and
    lit.getText() = "XDG_CACHE_HOME" and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "env_path" and
    callableName = "getenv" and
    argIndex = -1 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 1: env_path - os.environ.get(const.SHELL_LOGGER_SOCKET_ENV) at
     output_readers/shell_logger.py:13: the unix socket path checked with
     os.path.exists (:26) and connected to at :31; the constant resolves to
     the string 'SHELL_LOGGER_SOCKET' (const.py:89). */
  exists(Call c, Attribute f1, Attribute f2, Attribute arg0 |
    f1 = c.getFunc().(Attribute) and
    f1.getName() = "get" and
    f2 = f1.getObject().(Attribute) and
    f2.getName() = "environ" and
    f2.getObject().(Name).getId() = "os" and
    arg0 = c.getPositionalArg(0).(Attribute) and
    arg0.getName() = "SHELL_LOGGER_SOCKET_ENV" and
    normalizedPathOf(c).matches("%/thefuck/output_readers/%") and
    node = c and
    flowKind = "env_path" and
    callableName = "get" and
    argIndex = -1 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 2: env_content - os.environ.get(<content env name>, ...) calls:
     os.environ.get('PS1') read_log.py:85 and os.environ.get('TF_HISTORY')
     fix_command.py:16 (the shell history exported by the fuck alias). */
  exists(Call c, Attribute f1, Attribute f2, StringLiteral lit |
    f1 = c.getFunc().(Attribute) and
    f1.getName() = "get" and
    f2 = f1.getObject().(Attribute) and
    f2.getName() = "environ" and
    f2.getObject().(Name).getId() = "os" and
    lit = c.getPositionalArg(0).(StringLiteral) and
    (lit.getText() = "PS1" or
     lit.getText() = "TF_HISTORY") and
    normalizedPathOf(c).matches("%/thefuck/%") and
    node = c and
    flowKind = "env_content" and
    callableName = "get" and
    argIndex = -1 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 2: env_content - os.environ[<content env name>] subscript reads:
     os.environ['PS1'] read_log.py:16, os.environ['TF_HISTORY']
     fix_command.py:19, os.environ['EDITOR'] fix_file.py:71/:76. */
  exists(Subscript s, Attribute envattr, StringLiteral idx |
    envattr = s.getObject().(Attribute) and
    envattr.getName() = "environ" and
    envattr.getObject().(Name).getId() = "os" and
    idx = s.getIndex().(StringLiteral) and
    (idx.getText() = "PS1" or
     idx.getText() = "TF_HISTORY" or
     idx.getText() = "EDITOR") and
    normalizedPathOf(s).matches("%/thefuck/%") and
    node = s and
    flowKind = "env_content" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 2: env_content - the generic os.environ[env] THEFUCK_* settings
     read at conf.py:93 in Settings._val_from_env: `env` iterates
     const.ENV_TO_ATTR (THEFUCK_RULES, THEFUCK_PRIORITY, ...) - env-supplied
     settings values, including the rules list that controls which rule
     modules Rule.is_enabled loads. */
  exists(Subscript s, Attribute envattr, Name idx |
    envattr = s.getObject().(Attribute) and
    envattr.getName() = "environ" and
    envattr.getObject().(Name).getId() = "os" and
    idx = s.getIndex().(Name) and
    idx.getId() = "env" and
    normalizedPathOf(s).matches("%/thefuck/conf.py") and
    node = s and
    flowKind = "env_content" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 3: cli - the argparse parse boundary: self._parser.parse_args(
     arguments) at argument_parser.py:86; parser.parse(sys.argv) at
     entrypoints/main.py:18 feeds it sys.argv when thefuck is run through
     the shell alias, and the returned Namespace carries every CLI field
     (including the -l/--shell-logger value). */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    func.getName() = "parse_args" and
    base = func.getObject().(Attribute) and
    base.getName() = "_parser" and
    base.getObject().(Name).getId() = "self" and
    normalizedPathOf(c).matches("%/thefuck/argument_parser.py") and
    node = c and
    flowKind = "cli" and
    callableName = "parse_args" and
    argIndex = -1 and
    receiver = "self._parser" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: cli - known_args field reads in entrypoints:
     known_args.shell_logger (entrypoints/main.py:32 elif condition and
     :38 passed to the shell_logger entrypoint - THE -l/--shell-logger
     value opened with O_CREAT|O_TRUNC|O_RDWR at
     entrypoints/shell_logger.py:74), known_args.force_command
     (fix_command.py:14/:15) and known_args.command (main.py:30,
     fix_command.py:17) - the failed command words. Non-path fields
     (help/version/alias/enable_experimental_instant_mode and the
     yes/debug/repeat flags read in conf.py:_settings_from_args) are not
     matched. */
  exists(Attribute a |
    a.getObject().(Name).getId() = "known_args" and
    (a.getName() = "shell_logger" or
     a.getName() = "force_command" or
     a.getName() = "command") and
    normalizedPathOf(a).matches("%/thefuck/entrypoints/%") and
    node = a and
    flowKind = "cli" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "known_args" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 4: process-boundary parameters (caller-provided values at the
     tool's entry edges; positions include the self slot for methods). */

  /* shell_logger(output) - entrypoints/shell_logger.py:64, output at
     position 0: the CLI -l/--shell-logger value, opened directly with
     os.open(output, os.O_CREAT | os.O_TRUNC | os.O_RDWR) at :74 */
  exists(Function fn, Parameter p |
    fn.getName() = "shell_logger" and
    normalizedPathOf(fn).matches("%/thefuck/entrypoints/shell_logger.py") and
    p = fn.getArgByName("output") and
    node = p and
    flowKind = "param" and
    callableName = "shell_logger" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* fix_command(known_args) - entrypoints/fix_command.py:29, known_args at
     position 0: the argparse Namespace carrying force_command/command and
     the CLI flags merged into settings by Settings.init */
  exists(Function fn, Parameter p |
    fn.getName() = "fix_command" and
    normalizedPathOf(fn).matches("%/thefuck/entrypoints/fix_command.py") and
    p = fn.getArgByName("known_args") and
    node = p and
    flowKind = "param" and
    callableName = "fix_command" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Command.__init__(self, script, output) - types.py:16: script at
     position 1 and output at position 2 store the failed command's script
     and terminal output on the Command object every rule consumes */
  exists(Function fn, Parameter p |
    fn.getName() = "__init__" and
    fn.getEnclosingScope().(Class).getName() = "Command" and
    normalizedPathOf(fn).matches("%/thefuck/types.py") and
    (p = fn.getArgByName("script") or p = fn.getArgByName("output")) and
    node = p and
    flowKind = "param" and
    callableName = "__init__" and
    argIndex = p.getPosition() and
    receiver = "Command" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Command.from_raw_script(cls, raw_script) - types.py:69: raw_script at
     position 1 is the CLI command words list or the TF_HISTORY-derived
     command line */
  exists(Function fn, Parameter p |
    fn.getName() = "from_raw_script" and
    fn.getEnclosingScope().(Class).getName() = "Command" and
    normalizedPathOf(fn).matches("%/thefuck/types.py") and
    p = fn.getArgByName("raw_script") and
    node = p and
    flowKind = "param" and
    callableName = "from_raw_script" and
    argIndex = p.getPosition() and
    receiver = "Command" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Rule.from_path(cls, path) - types.py:131: path at position 1 is the
     rule module file path globbed from thefuck/rules, the XDG user rules
     dir and sys.path thefuck_contrib_* packages (corrector.py:29-47),
     loaded with imp.load_source(name, str(path)) at types.py:144 */
  exists(Function fn, Parameter p |
    fn.getName() = "from_path" and
    fn.getEnclosingScope().(Class).getName() = "Rule" and
    normalizedPathOf(fn).matches("%/thefuck/types.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "param" and
    callableName = "from_path" and
    argIndex = p.getPosition() and
    receiver = "Rule" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* get_loaded_rules(rules_paths) - corrector.py:8: rules_paths at
     position 0 is the list of globbed rule file paths */
  exists(Function fn, Parameter p |
    fn.getName() = "get_loaded_rules" and
    normalizedPathOf(fn).matches("%/thefuck/corrector.py") and
    p = fn.getArgByName("rules_paths") and
    node = p and
    flowKind = "param" and
    callableName = "get_loaded_rules" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Settings.init(self, args) - conf.py:17: args at position 1 is the
     argparse Namespace whose yes/debug/repeat flags merge into settings */
  exists(Function fn, Parameter p |
    fn.getName() = "init" and
    fn.getEnclosingScope().(Class).getName() = "Settings" and
    normalizedPathOf(fn).matches("%/thefuck/conf.py") and
    p = fn.getArgByName("args") and
    node = p and
    flowKind = "param" and
    callableName = "init" and
    argIndex = p.getPosition() and
    receiver = "Settings" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Cache._get_mtime(self, path) - utils.py:240: path at position 1 is a
     cache depends_on file path (the @cache decorator arguments, e.g. the
     fish config paths) stat'ed by os.path.getmtime at :242 */
  exists(Function fn, Parameter p |
    fn.getName() = "_get_mtime" and
    fn.getEnclosingScope().(Class).getName() = "Cache" and
    normalizedPathOf(fn).matches("%/thefuck/utils.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "param" and
    callableName = "_get_mtime" and
    argIndex = p.getPosition() and
    receiver = "Cache" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* family 5: command_output - the failed command's terminal output, the
     tool's dominant untrusted payload: command.output / old_cmd.output /
     cmd.output attribute reads across thefuck/rules/. Rule modules are
     loaded and invoked dynamically (imp.load_source + rule.match(command)
     at types.py:181), so the CONSUMPTION-side reads are emitted instead of
     the entrypoint parameters. Path-deriving consumers include the regex
     extractions in fix_file.py:60/:66 (group 'file' -> os.path.isfile at
     :52), git_add.py:12 (pathspec -> Path(pathspec).exists() at :13),
     ssh_known_hosts.py:31 (filepath -> open(filepath,'r'/'w') at :33/:36),
     path_from_history.py:18 (destination) and no_such_file.py:24. Rules
     whose output never reaches a path are labeled none in Step 3. */
  exists(Attribute a |
    a.getName() = "output" and
    (a.getObject().(Name).getId() = "command" or
     a.getObject().(Name).getId() = "old_cmd" or
     a.getObject().(Name).getId() = "cmd") and
    normalizedPathOf(a).matches("%/thefuck/rules/%") and
    node = a and
    flowKind = "command_output" and
    callableName = "output" and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 6: command_script - the failed command's argv:
     command.script_parts / old_cmd.script_parts / cmd.script_parts
     attribute reads across thefuck/rules/ (script_parts is the
     shell.split_command view of command.script built at types.py:37-46).
     File-op-feeding consumers: cat_dir.py:9 (os.path.isdir of
     script_parts[1]), chmod_x.py:8/:10 (os.path.exists/os.access of
     script_parts[0]), has_exists_script.py:7, grep_arguments_order.py:7,
     prove_recursively.py:13, ln_s_order.py:8, the cd walk
     cd_correction.py:16/:58 and the archive paths dirty_untar.py:42 /
     dirty_unzip.py:46. command.script full-string reads are NOT emitted
     (documented in detection.json: primarily the corrected-command string
     channel). */
  exists(Attribute a |
    a.getName() = "script_parts" and
    (a.getObject().(Name).getId() = "command" or
     a.getObject().(Name).getId() = "old_cmd" or
     a.getObject().(Name).getId() = "cmd") and
    normalizedPathOf(a).matches("%/thefuck/rules/%") and
    node = a and
    flowKind = "command_script" and
    callableName = "script_parts" and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 7: archive_entry_name - tar/zip entry-name reads:
     archive.getnames() at dirty_untar.py:43 and archive.namelist() at
     dirty_unzip.py:10 (in _is_bad_zip) / :47 (in side_effect); the
     returned names are passed UNVALIDATED to os.remove(file) at
     dirty_untar.py:45 / dirty_unzip.py:49 (directories silently skipped
     via the OSError except) - the archive itself is located by a path
     taken from the failed command's argv */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "getnames" or func.getName() = "namelist") and
    func.getObject().(Name).getId() = "archive" and
    normalizedPathOf(c).matches("%/thefuck/rules/%") and
    node = c and
    flowKind = "archive_entry_name" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
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
