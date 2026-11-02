/**
 * @name whoogle-search CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the
 *   whoogle-search CodeQL database (snapshot 8830615a, whoogle-search
 *   0.8.3, Flask 2.3.2 web app served by waitress): the builtin open(...)
 *   calls with the path at argument 0 - THE /config pair open(config_pkl,
 *   'rb') at routes.py:430 (PUT read-side over config_pkl = os.path.join(
 *   app.config['CONFIG_PATH'], request.args.get('name')) at :427-429) and
 *   open(os.path.join(app.config['CONFIG_PATH'], request.args.get('name')),
 *   'wb') at routes.py:445-447 (POST write-side, fed by
 *   request.form.to_dict() pickle.dump) - both with NO '..'/absolute/
 *   containment validation between the request read and the open; the
 *   session-file maintenance open(file_path, 'rb') routes.py:103 (paths
 *   from os.listdir(SESSION_FILE_DIR) at :93 joined at :94-96); the
 *   app-init settings/secret/bangs opens routes.py:36/:144/:173 and
 *   __init__.py:53/:56/:59/:62/:65/:68 (json.load(open(os.path.join(
 *   STATIC_FOLDER, 'settings/....json')))), :104/:107 (whoogle.key
 *   read/write), :143 (bangs.json create); gen_file_hash's
 *   open(os.path.join(path, static_file), 'rb') misc.py:11 (cache-busting
 *   hash read over listdir results); the tor control conf open(confloc,
 *   'r') request.py:55 (env WHOOGLE_TOR_CONF-checked path); the bangs
 *   write open(bangs_file, 'w') bangs.py:38; the widget open(BASE_DIR /
 *   literal) widgets.py:57; and the dev-script open(f'{file_path}/../
 *   {tl_path}', 'r+') misc/update-translations.py:39 (literal components
 *   with an embedded '../' - mixed traversal literal evidence). The
 *   pathlib construction (the only pathlib use in the app): widgets.py:6
 *   Path(__file__). The os.path.join joins: routes.py:94 (session dir +
 *   listdir entry), :427/:445 (CONFIG_PATH + request.args.get('name') -
 *   THE traversal-relevant joins where an absolute or '..'-prefixed
 *   second argument escapes the base), __init__.py:29/:49/:53/:56/:59/:62/
 *   :65/:68/:72/:73/:77/:84/:102/:152/:155/:157 (config-constant joins),
 *   misc.py:11, config.py:123. The os.path pure ops: abspath
 *   (__init__.py:24/:29/:45), dirname (:23/:29/:45), splitext (misc.py:13).
 *   The stat family: os.path.getsize (routes.py:100/:171), os.path.exists
 *   (routes.py:145/:431 - :431 is the check-then-open TOCTOU companion of
 *   the /config read at :430, __init__.py:33/:89/:92/:95/:98/:103/:142),
 *   os.path.isfile (request.py:48, the WHOOGLE_TOR_CONF check). The delete
 *   os.remove(invalid_session) routes.py:117. The listing os.listdir
 *   (routes.py:93 SESSION_FILE_DIR, __init__.py:153 static css/js). The
 *   directory creation os.makedirs (__init__.py:90/:93/:96/:99). The link
 *   creation os.symlink(full_cb_path, build_path) __init__.py:160
 *   (cache-busting links over internal listdir-derived names). The
 *   file-response wrapper flask send_file(tmp_mem, mimetype=src_type)
 *   routes.py:484 and send_file(io.BytesIO(empty_gif), ...) routes.py:490
 *   - BOTH call sites pass io.BytesIO buffers, NOT filesystem paths
 *   (emitted for the labeling step to judge; no path argument exists, the
 *   file content was fetched over HTTP). And definition rows for the
 *   path-consuming internal helpers gen_file_hash(path, static_file) and
 *   gen_bangs_json(bangs_file) with the true parameter positions. NOT
 *   present (verified, none assumed): archive extraction
 *   (zipfile/tarfile/extractall), multipart upload filenames, static-file
 *   serving by path in project code (Flask's /static route is served by
 *   werkzeug's safe_join outside the database - see detection.json
 *   uncoveredCases). json.load/pickle.load/pickle.dump rows are NOT
 *   emitted (they take file objects, not paths - the open() calls inside
 *   them are the real access points, and class-name danger is not
 *   assumed). Raw BQRS extraction query: run with `codeql query run` and
 *   decode with `codeql bqrs decode` (not database analyze). This is a
 *   plain multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/whoogle-search/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member name ("open" for the builtin opens,
 *                   "Path" for the pathlib construction, "join"/"abspath"/
 *                   "dirname"/"splitext" for the os.path pure ops,
 *                   "getsize"/"exists"/"isfile" for the stat family,
 *                   "remove", "listdir", "makedirs", "symlink",
 *                   "send_file" for the response wrapper, the function
 *                   name for file_api_def definition rows)
 *   4. flow_kind  - "file_open" (builtin open - the path argument 0),
 *                   "path_ctor" (pathlib.Path(...) construction),
 *                   "path_join" (os.path.join - argument 0 reported, both
 *                   arguments can carry path components),
 *                   "path_wrapper" (os.path abspath/dirname/splitext pure
 *                   ops - normalization/validation nodes that can
 *                   participate in traversal semantics),
 *                   "file_stat" (os.path getsize/exists/isfile - argument
 *                   0 is the path; the exists() at routes.py:431 is the
 *                   check-then-open TOCTOU companion of the /config read),
 *                   "file_delete" (os.remove argument 0),
 *                   "file_read" (os.listdir argument 0 - directory
 *                   listing),
 *                   "file_mkdir" (os.makedirs argument 0),
 *                   "file_symlink" (os.symlink argument 0 = link target
 *                   source, argument 1 = link path - documented in the
 *                   family comment),
 *                   "file_send" (flask send_file argument 0 - io.BytesIO
 *                   buffers at both call sites, no path argument),
 *                   "file_api_def" (definition row of a path-consuming
 *                   internal API, carrying the path parameter position)
 *   5. receiver   - syntactic receiver hint ("" for builtin/plain-name
 *                   calls, "os.path" for the os.path member calls, "os"
 *                   for the os member calls, "pathlib" for the Path
 *                   construction, "" for module-level file_api_def rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "builtins"/"os.path"/"os"/"pathlib"/"flask" for
 *                   the stdlib/flask channels, moduleHintOf(node) for
 *                   file_api_def rows
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for open/Path/os.path/os member calls and
 *                   send_file; for os.symlink argument 0 is the link
 *                   target source and argument 1 the link path, both
 *                   documented; -1 never occurs in this query except in
 *                   the file_api_def rows where it is the parameter
 *                   position instead)
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
 * builtin open() channel (THE /config read/write pair, the session-file
 * loop, the settings/secret/bangs plumbing, gen_file_hash, the tor conf,
 * the widget and dev-script opens), the os channel (os.path.getsize/
 * exists/isfile, os.remove, os.listdir, os.makedirs, os.symlink), the
 * pathlib construction, the os.path.join/abspath/dirname/splitext
 * pipeline feeding them, and the send_file response wrapper (kept as a
 * candidate despite the observed io.BytesIO arguments, because the call
 * shape can take a filesystem path) - NOT every path string construction
 * node (the f-string path in misc/update-translations.py:39 is recorded
 * through its open() row; string concatenations like BASE_DIR + '/static'
 * are pure and are documented in detection.json uncoveredCases instead).
 * json.load/pickle.load/pickle.dump are not sinks for pass 1 (they take
 * file objects; the open() inside is the access point).
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project NO sink row is expected to resolve at API level:
 * flask/os/pathlib are external to the database (only the whoogle-search
 * tree is), so every family is an AST-level match on the local import names
 * (`open`/`send_file`/`Path` plain names, `os.path.*`/`os.*` attribute
 * chains); the match_kind column is kept "ast" for cross-project contract
 * consistency.
 *
 * Excluded paths (applied to every row): /test/ (unit test tree - the
 * workflow noise rule) and /whoogle-search-db/ (the CodeQL database
 * directory nested inside the source tree; it contains no .py files, the
 * filter is defensive). misc/ is kept in scope: update-translations.py
 * contributes one literal-path open() row (:39, expected none/FP) and
 * replit.py contributes no pass-1 rows. Ground-truth-looking artifacts at
 * the repo root (WHOOSE-* reports, path_traversal_sinks.csv) were never
 * opened (experiment independence).
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
  path.replaceAll("\\", "/").matches("%/test/%")
  or
  path.replaceAll("\\", "/").matches("%/whoogle-search-db/%")
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
  /* family 1: file_open - builtin open(...) calls, the path at
     argument 0. Key sites: routes.py:430 open(config_pkl, 'rb') - THE
     /config PUT read sink over config_pkl = os.path.join(CONFIG_PATH,
     request.args.get('name')) (:427-429), guarded only by os.path.exists
     at :431 (existence, not containment - check-then-open TOCTOU
     evidence) and followed by pickle.load (pass-6 adjacent);
     routes.py:445-447 open(os.path.join(app.config['CONFIG_PATH'],
     request.args.get('name')), 'wb') - THE /config POST write sink fed by
     pickle.dump(config_data) with config_data = request.form.to_dict()
     (:437); routes.py:103 open(file_path, 'rb') - the session-file loop
     read (paths from os.listdir(SESSION_FILE_DIR) :93 joined :94-96,
     getsize-guarded :100, pickle.load'ed :105, os.remove'd :117);
     routes.py:36/:144/:173 and __init__.py:53/:56/:59/:62/:65/:68 - the
     settings JSON opens over config-constant os.path.join paths;
     __init__.py:104 open(app_key_path, 'r') and :107 open(app_key_path,
     'w') - the whoogle.key secret read/write; __init__.py:143 - bangs.json
     creation; misc.py:11 open(os.path.join(path, static_file), 'rb') -
     gen_file_hash's cache-busting read; request.py:55 open(confloc, 'r') -
     the tor control conf (env WHOOGLE_TOR_CONF path if os.path.isfile,
     else the literal './misc/tor/control.conf', request.py:45-49);
     bangs.py:38 open(bangs_file, 'w') - the DDG bangs write;
     widgets.py:57 open(BASE_DIR / 'app/static/widgets/calculator.html',
     encoding='utf8') - literal widget read;
     misc/update-translations.py:39 open(f'{file_path}/../{tl_path}',
     'r+') - dev script, literal components with an embedded '../'. */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    (normalizedPathOf(c).matches("%/app/%") or
     normalizedPathOf(c).matches("%/misc/%")) and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 2: path_ctor - the pathlib construction. widgets.py:6
     BASE_DIR = Path(__file__).parent.parent.parent - the ONLY pathlib use
     in the app (`from pathlib import Path`, widgets.py:1); operator
     constant, expected none/FP, kept for pipeline completeness. */
  exists(Call c |
    c.getFunc().(Name).getId() = "Path" and
    normalizedPathOf(c).matches("%/app/%") and
    node = c and
    flowKind = "path_ctor" and
    callableName = "Path" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 3: path_join - os.path.join(...) calls, argument 0 reported
     (BOTH arguments can carry path components). Key sites: routes.py:427
     and :445 os.path.join(app.config['CONFIG_PATH'], request.args.get(
     'name')) - THE traversal-relevant joins of the /config route: an
     absolute or '..'-prefixed name escapes CONFIG_PATH (defaults to
     app/static/config) because os.path.join replaces the base entirely
     with an absolute second argument; routes.py:94 os.path.join(
     SESSION_FILE_DIR, user_session) - the session-loop join over listdir
     entries; __init__.py:29/:49/:53/:56/:59/:62/:65/:68/:72/:73/:77/:84/
     :102/:152/:155/:157 - config-constant base joins (app root, static
     folder, settings files, config/session/bangs dirs, whoogle.key,
     cache-busting); misc.py:11 os.path.join(path, static_file) -
     gen_file_hash; config.py:123 os.path.join(current_app.config[
     'STATIC_FOLDER'], 'css/variables.css') - the stylesheet read. */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    func.getName() = "join" and
    base = func.getObject().(Attribute) and
    base.getName() = "path" and
    base.getObject().(Name).getId() = "os" and
    (normalizedPathOf(c).matches("%/app/%") or
     normalizedPathOf(c).matches("%/misc/%")) and
    node = c and
    flowKind = "path_join" and
    callableName = "join" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 4: path_wrapper - os.path pure operations that can
     participate in normalization/validation or traversal semantics:
     os.path.abspath (__init__.py:24/:29/:45 - __file__-based app-root
     resolution), os.path.dirname (__init__.py:23/:29/:45), os.path.
     splitext (misc.py:13 - the gen_file_hash filename split). Argument 0
     is the path. NOTE: no normpath/realpath/basename call exists anywhere
     in this project - there is NO canonicalization guard on the /config
     channel (see detection.json guardAndTraversalEvidence). */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    (func.getName() = "abspath" or func.getName() = "dirname" or
     func.getName() = "splitext") and
    base = func.getObject().(Attribute) and
    base.getName() = "path" and
    base.getObject().(Name).getId() = "os" and
    (normalizedPathOf(c).matches("%/app/%") or
     normalizedPathOf(c).matches("%/misc/%")) and
    node = c and
    flowKind = "path_wrapper" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 5: file_stat - the os.path stat/existence family, argument 0
     is the path: os.path.getsize (routes.py:100 - the session-loop size
     guard, :171 - the bangs file size check), os.path.exists
     (routes.py:145 - DEFAULT_CONFIG check, :431 - THE /config
     check-then-open TOCTOU companion of open(config_pkl, 'rb') at :430;
     __init__.py:33 - dotenv check, :89/:92/:95/:98 - the
     config/session/bangs/build dir checks, :103 - whoogle.key check,
     :142 - bangs.json check), os.path.isfile (request.py:48 - the
     WHOOGLE_TOR_CONF env path check that selects confloc for the
     request.py:55 open). These are filesystem metadata access, and the
     exists()/isfile() checks are the TOCTOU-relevant pre-use probes. */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    (func.getName() = "getsize" or func.getName() = "exists" or
     func.getName() = "isfile") and
    base = func.getObject().(Attribute) and
    base.getName() = "path" and
    base.getObject().(Name).getId() = "os" and
    (normalizedPathOf(c).matches("%/app/%") or
     normalizedPathOf(c).matches("%/misc/%")) and
    node = c and
    flowKind = "file_stat" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 6: file_delete - os.remove(invalid_session) routes.py:117:
     deletion of session files collected from the SESSION_FILE_DIR
     listing (routes.py:93-108) whose names are NOT request-derived but
     ARE directory-content-driven (the in-code comment at :109-113
     documents unrelated files landing in that dir). Argument 0 is the
     path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "remove" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_delete" and
    callableName = "remove" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 7: file_read (directory listing) - os.listdir: routes.py:93
     os.listdir(app.config['SESSION_FILE_DIR']) - the session-maintenance
     listing whose entries feed os.path.join/getsize/open/pickle.load/
     os.remove; __init__.py:153 os.listdir(full_cb_dir) - the static
     css/js listing feeding the cache-busting gen_file_hash/symlink
     channel. Argument 0 is the path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "listdir" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_read" and
    callableName = "listdir" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 8: file_mkdir - os.makedirs: __init__.py:90/:93/:96/:99 -
     creation of CONFIG_PATH/SESSION_FILE_DIR/BANG_PATH/BUILD_FOLDER from
     app config (operator inputs) when missing. Argument 0 is the path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "makedirs" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_mkdir" and
    callableName = "makedirs" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 9: file_symlink - os.symlink(full_cb_path, build_path)
     __init__.py:160: cache-busting link creation over
     listdir/gen_file_hash-derived internal names (FileExistsError-
     tolerated). Argument 0 is the link target source, argument 1 is the
     link path - the row reports argument 0; both are internal
     (operator/listing-driven), expected none/FP, kept for completeness
     because os.symlink is a real link-creation channel. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "symlink" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_symlink" and
    callableName = "symlink" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 10: file_send - flask send_file(...) response wrapper,
     argument 0: routes.py:484 send_file(tmp_mem, mimetype=src_type) and
     routes.py:490 send_file(io.BytesIO(empty_gif), mimetype='image/gif')
     - BOTH call sites pass io.BytesIO buffers (content fetched over
     HTTP), NOT filesystem paths. Emitted as candidates for the labeling
     step to judge (the call shape CAN take a path; here it does not) -
     not assumed dangerous by class name. */
  exists(Call c |
    c.getFunc().(Name).getId() = "send_file" and
    normalizedPathOf(c).matches("%/app/%") and
    node = c and
    flowKind = "file_send" and
    callableName = "send_file" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "flask" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 11: file_api_def - definition rows of the project's own
     path-consuming internal APIs (candidates for summary/propagation
     labeling). Positions include the self slot for methods. */

  /* gen_file_hash(path, static_file) - misc.py:10, path at position 0
     and static_file at position 1: the cache-busting helper whose
     open(os.path.join(path, static_file), 'rb') (misc.py:11) is the real
     read; called from __init__.py:156 with (full_cb_dir, cb_file) from
     os.listdir. */
  exists(Function fn, Parameter p |
    fn.getName() = "gen_file_hash" and
    normalizedPathOf(fn).matches("%/app/utils/misc.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "gen_file_hash" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  exists(Function fn, Parameter p |
    fn.getName() = "gen_file_hash" and
    normalizedPathOf(fn).matches("%/app/utils/misc.py") and
    p = fn.getArgByName("static_file") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "gen_file_hash" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(p) and
    matchKind = "ast"
  )
  or
  /* gen_bangs_json(bangs_file) - bangs.py:8, bangs_file at position 0:
     the output path of the DDG bangs fetch thread (open(bangs_file, 'w')
     at bangs.py:38; content from duckduckgo.com, not request input -
     boundary row for labeling). */
  exists(Function fn, Parameter p |
    fn.getName() = "gen_bangs_json" and
    normalizedPathOf(fn).matches("%/app/utils/bangs.py") and
    p = fn.getArgByName("bangs_file") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "gen_bangs_json" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(p) and
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
