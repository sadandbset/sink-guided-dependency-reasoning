/**
 * @name openadapt CWE-89 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   OpenAdapt CodeQL database (snapshot 0a0208e, openadapt 0.1.0 - a desktop
 *   GUI-automation recorder): nicegui widget input (ui.input, the recording
 *   name prompt in openadapt/app/cards.py, and LocalFilePicker dialog calls
 *   whose result carries user-chosen file paths); nicegui event-message
 *   subscript reads (msg["args"] in local_file_picker.py handle_double_click);
 *   python-fire CLI boundaries (the 8 fire.Fire registration sites and the
 *   parameters of the statically resolvable registered functions:
 *   record(task_description), replay(strategy_name, timestamp),
 *   send_recording(recording_id), receive_recording(wormhole_code)) plus the
 *   Popen("python3 -m openadapt.record " + name, shell=True) UI-to-CLI bridge
 *   (cli_spawn); file input (built-in open(), bz2.BZ2File - the DB import/
 *   export channel, Image.open, <obj>.read()/.readlines(), copyfileobj); DB
 *   content reads (recording.<column> attribute reads over the Recording
 *   model's columns, concentrated in export_sql's raw-SQL f-string at
 *   crud.py:142); configuration reads (config.<ATTR>, env_vars[...] /
 *   env_vars.get(...)); environment reads (os.getenv, load_dotenv,
 *   find_dotenv); and positional arguments handed to internal functions whose
 *   bodies directly execute SQL (_insert at crud.py:62/71/80/94, create_db at
 *   crud.py:209). There is NO HTTP/API request boundary in this project
 *   (nicegui runs in native desktop mode; its server internals live in the
 *   external library) - no request families are emitted. Raw BQRS extraction
 *   query: run with `codeql query run` and decode with `codeql bqrs decode`
 *   (not database analyze). This is a plain multi-column select query on
 *   purpose: @kind problem is the wrong shape for candidate tables and
 *   @kind table is not assumed to exist.
 * @id iris/openadapt/extraction/sources
 * @tags sql-injection
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (member name, function name, attribute name,
 *                   widget/picker constructor name, column name for db_read
 *                   rows, "Fire"/"Popen" for cli registration/spawn rows)
 *   4. flow_kind  - "ui_input" (nicegui input widget or file-picker dialog
 *                   call), "ui_event" (nicegui event-message subscript read),
 *                   "cli" (fire.Fire registration or fire-registered function
 *                   parameter), "cli_spawn" (Popen bridge from UI text into
 *                   this app's CLI), "file", "db_read" (Recording column read
 *                   on an object named `recording`), "config", "env",
 *                   "internal_transfer" (positional argument handed to an
 *                   internal function whose body directly executes SQL)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression, e.g. "ui" / "bz2" / "os" / "recording" /
 *                   "config" / "" if none; "<expr>" when the object
 *                   expression is neither Name nor Attribute)
 *   6. moduleHint - module hint: dotted python module path of the containing
 *                   module, or the library module name for external-library
 *                   call shapes (variable intentionally named moduleHint;
 *                   `module` is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index (parameter position in
 *                   the function definition for "cli" parameter rows; index
 *                   of the transferred positional argument for
 *                   "internal_transfer" rows; 0 for keyed/subscript reads and
 *                   for the fire.Fire registration target), -1 if N/A
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
 * a row). In this project NO row is expected to resolve at API level: the
 * only relevant libraries (nicegui, fire, bz2, sqlalchemy, dotenv) are
 * external and not part of the CodeQL database, so import chains cannot
 * resolve to library modules. All families below are AST-level matches and
 * the match_kind column is kept "ast" for cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (5 files of the database
 * snapshot) and /OpenAdapt-db/ (the CodeQL database directory sits inside
 * the source tree).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  (setup.py) have no dotted module name; their file base name is used
 *  instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
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

/** Receiver hint for the callee expression of a call ("" when there is no attribute receiver). */
string receiverHintOfCall(Call c) {
  exists(Attribute a |
    a = c.getFunc() and
    result = receiverHint(a)
  )
  or
  not c.getFunc() instanceof Attribute and result = ""
}

/** Syntactic name of the callee of a call ("<expr>" if it is neither Name nor Attribute). */
string calledNameOf(Call c) {
  result = c.getFunc().(Name).getId()
  or
  result = c.getFunc().(Attribute).getName()
  or
  not c.getFunc() instanceof Name and
  not c.getFunc() instanceof Attribute and
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
  path.replaceAll("\\", "/").matches("%/OpenAdapt-db/%")
}

/* ------------------------------------------------------------------ */
/* Shared SQL-execution shapes (kept consistent with sinks.ql)          */
/* ------------------------------------------------------------------ */

/**
 * SQL execution members observed in this project: only `execute` - the two
 * call sites are db.execute(sa.insert(table), to_insert)
 * (openadapt/crud.py:48, SQLAlchemy Session.execute) and
 * connection.execute(sql) (openadapt/crud.py:180, SQLAlchemy
 * Connection.execute over a raw SQL string). executemany, executescript and
 * callproc are NOT observed anywhere in this snapshot and are deliberately
 * not matched. Matching is receiver-name-agnostic on purpose: the Session
 * (`db`) and the engine.begin() `connection` are local variables, so the
 * receiver identity cannot be proven syntactically.
 */
private predicate sqlExecuteMember(string member) {
  member = "execute"
}

/** Any call site of an SQL execution member (syntax-level, alias-tolerant). */
private predicate sqlExecuteCall(Call c) {
  sqlExecuteMember(c.getFunc().(Attribute).getName())
}

/** Functions whose body directly executes SQL through an execute call:
 *  _insert (openadapt/crud.py:30-53) and create_db (openadapt/crud.py:150-184). */
private predicate sqlWrapperFunction(Function f) {
  exists(Call c |
    sqlExecuteCall(c) and
    c.getScope().(Function) = f
  )
}

/**
 * Holds if c is a call site whose callee plausibly targets the SQL wrapper
 * function f: an attribute call whose member name matches f's name (any
 * receiver), or, for module-level wrapper functions, a bare-name call (the
 * observed shape: _insert(event_data, ActionEvent, action_events) at
 * crud.py:62/71/80/94 and create_db(recording_id, sql) at crud.py:209).
 * Wrapper functions whose own name is an SQL execution member are excluded
 * here: direct .execute(...) call sites are modeled as sinks in sinks.ql, so
 * only calls that hand values INTO the SQL layer through a named wrapper
 * become internal_transfer rows. Name-only resolution is subject to dynamic
 * dispatch ambiguity (documented in detection.json uncoveredCases).
 */
private predicate callsSqlWrapper(Call c, Function f) {
  sqlWrapperFunction(f) and
  not sqlExecuteMember(f.getName()) and
  (
    exists(Attribute a |
      a = c.getFunc() and
      a.getName() = f.getName()
    )
    or
    c.getFunc().(Name).getId() = f.getName() and
    not f.getEnclosingScope() instanceof Class
  )
}

/* ------------------------------------------------------------------ */
/* Source family shapes                                                */
/* ------------------------------------------------------------------ */

/**
 * Recording model columns (openadapt/models.py:27-34) whose reads on an
 * object named `recording` are emitted as db_read rows. These values are
 * DB-derived: task_description/platform originate from the UI/CLI recording
 * name, and the whole table can be replaced through the DB import channel
 * (on_import in openadapt/app/util.py:20-28).
 */
private predicate recordingColumn(string col) {
  col = "id"
  or
  col = "timestamp"
  or
  col = "monitor_width"
  or
  col = "monitor_height"
  or
  col = "double_click_interval_seconds"
  or
  col = "double_click_distance_pixels"
  or
  col = "platform"
  or
  col = "task_description"
}

/** fire.Fire(...) call site: `fire.Fire(target)` with `import fire` (module-level imports in record.py, replay.py, scrub.py, share.py, utils.py). */
private predicate isFireCall(Call c) {
  c.getFunc().(Attribute).getName() = "Fire" and
  c.getFunc().(Attribute).getObject().(Name).getId() = "fire"
}

/**
 * Functions statically registered with fire.Fire and therefore exposed as
 * CLI entry points: fire.Fire(record) / fire.Fire(replay) (bare Name
 * target) and fire.Fire({"send": send_recording, "receive":
 * receive_recording}) (Dict values). Dynamic registrations -
 * fire.Fire(get_functions(__name__)) in scrub.py:281 and utils.py:508/:525 -
 * cannot be resolved statically and are NOT covered here (see
 * detection.json uncoveredCases); the fire.Fire call rows below still
 * register those entry points.
 */
private predicate fireRegisteredFunction(Function f) {
  exists(Call c, Expr target |
    isFireCall(c) and
    target = c.getPositionalArg(0) and
    not f.getEnclosingScope() instanceof Class and
    (
      target.(Name).getId() = f.getName()
      or
      target.(Dict).getAValue().(Name).getId() = f.getName()
    )
  )
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: nicegui input widget call sites - ui.input(...) is the only
     text input in the project (the recording-name prompt,
     openadapt/app/cards.py:44); the typed text arrives through the widget's
     value, so arg_index is -1 (no argument carries it) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "input" and
    func.getObject().(Name).getId() = "ui" and
    node = c and
    flowKind = "ui_input" and
    callableName = "input" and
    argIndex = -1 and
    receiver = "ui" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 1b: LocalFilePicker(...) dialog calls - the await result carries
     user-chosen file paths (openadapt/app/cards.py:21,
     openadapt/app/objects/local_file_picker.py:101); the selected path
     drives the DB import flow */
  exists(Call c |
    c.getFunc().(Name).getId() = "LocalFilePicker" and
    node = c and
    flowKind = "ui_input" and
    callableName = "LocalFilePicker" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 2: nicegui event-message subscript reads - msg["args"] (the
     innermost subscript of msg["args"]["data"]["path"] in
     local_file_picker.py:87 handle_double_click) carries the grid event
     payload; arg_index 0 is the key position */
  exists(Subscript s |
    s.getObject().(Name).getId() = "msg" and
    node = s and
    flowKind = "ui_event" and
    callableName = "msg" and
    argIndex = 0 and
    receiver = "msg" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 3: fire.Fire(...) registration call sites - the CLI entry-point
     registrations (record.py:647/651, replay.py:50/54, share.py:106,
     scrub.py:281, utils.py:508/525); arg_index 0 is the registration target
     argument */
  exists(Call c |
    isFireCall(c) and
    node = c and
    flowKind = "cli" and
    callableName = "Fire" and
    argIndex = 0 and
    receiver = "fire" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 4: parameters of statically registered fire CLI functions -
     record(task_description) (position 0), replay(strategy_name, timestamp)
     (positions 0/1), send_recording(recording_id) (position 0 - the entry
     point that drives export_recording -> export_sql -> create_db ->
     connection.execute), receive_recording(wormhole_code) (position 0);
     self is excluded; arg_index is the 0-based position in the function
     definition */
  exists(Function f, Parameter p |
    fireRegisteredFunction(f) and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "cli" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    receiver = ""
  )
  or
  /* family 5: Popen(...) CLI spawn from the UI - cards.py:76-79
     Popen("python3 -m openadapt.record " + name, shell=True): the
     UI-entered recording name is concatenated into the command string that
     launches this app's own CLI; arg_index 0 is the command string. (The
     shell-concat itself is a Pass-2 command-injection shape - recorded here
     only as the UI->CLI propagation bridge for Pass 5.) */
  exists(Call c |
    c.getFunc().(Name).getId() = "Popen" and
    node = c and
    flowKind = "cli_spawn" and
    callableName = "Popen" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6: file input: built-in open(...) (config.py:37, crud.py:167/:170,
     app/main.py:30, app/build.py:23, app/util.py:21/:36) - path at
     argument 0 */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    node = c and
    flowKind = "file" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* family 6b: bz2.BZ2File(...) - the recording import/export channel
     (app/util.py:22 reads the user-chosen import file, :37 writes the
     export); path at argument 0 */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "BZ2File" and
    func.getObject().(Name).getId() = "bz2" and
    node = c and
    flowKind = "file" and
    callableName = "BZ2File" and
    argIndex = 0 and
    receiver = "bz2" and
    moduleHint = "bz2" and
    matchKind = "ast"
  )
  or
  /* family 6c: Image.open(buffer) (models.py:246) - reads image bytes from a
     DB-derived buffer */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "Image" and
    node = c and
    flowKind = "file" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "Image" and
    moduleHint = "PIL" and
    matchKind = "ast"
  )
  or
  /* family 6d: file content reads - <obj>.read() / <obj>.readlines()
     (app/main.py:30 open(...).read(), crud.py:168 f.readlines()); the return
     value carries file content */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "read" or func.getName() = "readlines") and
    node = c and
    flowKind = "file" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "file" and
    matchKind = "ast"
  )
  or
  /* family 6e: copyfileobj(src, dst) - file content transfer between the
     import/export file objects (app/util.py:23/:38); src at argument 0 */
  exists(Call c |
    c.getFunc().(Name).getId() = "copyfileobj" and
    node = c and
    flowKind = "file" and
    callableName = "copyfileobj" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  /* family 7: DB content reads - recording.<column> attribute reads over the
     Recording model's columns, on an object syntactically named `recording`
     (crud.py:142 - all 8 columns inside export_sql's raw-SQL f-string;
     crud.py:227/231/246; record.py:521; utils.py:309/310/369/370;
     visualize.py:149/248/249). Name-based object matching - see
     detection.json uncoveredCases. */
  exists(Attribute a |
    recordingColumn(a.getName()) and
    a.getObject().(Name).getId() = "recording" and
    node = a and
    flowKind = "db_read" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "recording" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 8: configuration reads - config.<ATTR> (~42 sites across the
     package; operator-level trust: DB_URL/DB_FNAME drive the DB engine,
     ENV_FILE_PATH is read/written by create_db) */
  exists(Attribute a |
    a.getObject().(Name).getId() = "config" and
    node = a and
    flowKind = "config" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "config" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 8b: env_vars[...] / env_vars.get(...) - reads of the parsed .env
     file dictionary (config.py:49 DB_FNAME = env_vars.get("DB_FNAME")) */
  exists(Subscript s |
    s.getObject().(Name).getId() = "env_vars" and
    node = s and
    flowKind = "config" and
    callableName = "env_vars" and
    argIndex = 0 and
    receiver = "env_vars" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Name).getId() = "env_vars" and
    node = c and
    flowKind = "config" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "env_vars" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 9: environment reads - os.getenv(...) (config.py:146, inside
     getenv_fallback; operator-level trust) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "getenv" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = "getenv" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 9b: python-dotenv loading - load_dotenv / find_dotenv
     (config.py:23-24) read the .env file into the environment; argument 0
     when present */
  exists(Call c |
    (
      c.getFunc().(Name).getId() = "load_dotenv"
      or
      c.getFunc().(Name).getId() = "find_dotenv"
    ) and
    node = c and
    flowKind = "env" and
    callableName = calledNameOf(c) and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "dotenv" and
    matchKind = "ast"
  )
  or
  /* family 10: positional arguments handed to internal SQL-executing
     functions (view/processor -> data access layer transfers): the
     _insert(event_data, table, buffer) calls at crud.py:62/71/80/94 (event
     data carries recorded GUI event text) and the
     create_db(recording_id, sql) call at crud.py:209 (argument 1 is the raw
     SQL string built by export_sql); one row per positional argument,
     arg_index is the argument position (i is bound by range membership
     before the indexed getPositionalArg lookup; calls with more than 10
     positional arguments are not scanned). Keyword-argument transfers are
     NOT captured - see detection.json uncoveredCases. */
  exists(Call c, Function f, int i |
    i in [0 .. 9] and
    callsSqlWrapper(c, f) and
    node = c.getPositionalArg(i) and
    flowKind = "internal_transfer" and
    callableName = f.getName() and
    argIndex = i and
    receiver = receiverHintOfCall(c) and
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
