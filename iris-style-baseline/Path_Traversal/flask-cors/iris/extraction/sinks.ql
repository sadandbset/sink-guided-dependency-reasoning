/**
 * @name flask-cors CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the
 *   Flask-Cors 3.0.8 CodeQL database (snapshot 5c6e05e - the flask_cors
 *   library itself is the audit target). EVIDENCE-BASED SCOPE NOTE: the
 *   flask_cors package (all 5 modules, 731 lines, read in full) contains
 *   ZERO filesystem operations - it is a pure CORS response-header filter
 *   whose only path-shaped value, request.path (extension.py:178), is used
 *   solely as a regex match subject. The ONLY filesystem operations in the
 *   entire database snapshot are: builtin open(...) in the packaging
 *   script - setup.py:15 open(join(dirname(__file__),
 *   'flask_cors/version.py'), 'r') (read; its content is then exec'd at
 *   setup.py:16 - Pass 4 material), setup.py:18 open(join(dirname(__file__),
 *   'requirements.txt'), 'r') (read), setup.py:29 open('README.rst') (read,
 *   CWD-relative literal) - all with literal/constant paths; the
 *   os.path.join propagation nodes feeding them (setup.py:15/:18, bare
 *   names via `from os.path import join, dirname` setup.py:13); the
 *   os.path.dirname component extractions (setup.py:15/:18 bare-name on
 *   __file__, and the constant parentdir chains
 *   os.path.dirname(os.path.dirname(os.path.abspath(__file__))) in the 3
 *   examples :17); the os.path.abspath normalizations (examples :17,
 *   docs/conf.py:21); and the import-resolution path manipulations
 *   os.sys.path.insert(0, parentdir) (examples :18) and
 *   sys.path.insert(0, os.path.abspath('..')) (docs/conf.py:21) - not
 *   direct file accesses, but they select the directory the import
 *   machinery subsequently reads files from; the inserted values are
 *   constant __file__-derived paths. No archive extraction, no
 *   send_file/static serving, no uploads, no chdir, no deletion, no
 *   pathlib usage exists anywhere in the snapshot. Raw BQRS extraction
 *   query: run with `codeql query run` and decode with `codeql bqrs
 *   decode` (not database analyze). This is a plain multi-column select
 *   query on purpose: @kind problem is the wrong shape for candidate
 *   tables and @kind table is not assumed to exist.
 * @id iris/flask-cors/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member name ("open" / "join" / "dirname" /
 *                   "basename" / "abspath" / "insert")
 *   4. flow_kind  - "file_open" (builtin open(...) - argument 0 carries the
 *                   path; all three sites are READ opens: 'r' modes at
 *                   setup.py:15/:18 and the default read mode at :29),
 *                   "path_join" (os.path.join - argument 0 is the first
 *                   path component, later positional arguments also carry
 *                   components; matched both in the os.path.join attribute
 *                   form and - the form actually used here - as the bare
 *                   Name join(...) enabled by `from os.path import join,
 *                   dirname` setup.py:13, anchored to setup.py),
 *                   "path_part" (os.path.dirname / os.path.basename -
 *                   component extraction, propagation nodes; bare-name
 *                   form anchored to setup.py, attribute form anywhere),
 *                   "path_canon" (os.path.abspath / realpath / normpath -
 *                   normalization nodes; only abspath is present here, on
 *                   constant inputs),
 *                   "import_path_insert" (sys.path.insert /
 *                   os.sys.path.insert - positional argument 1 carries the
 *                   inserted directory; not a direct file access but the
 *                   import-machinery file-resolution channel)
 *   5. receiver   - syntactic receiver hint ("" for builtin/aliased calls,
 *                   "os.path" for the attribute-form stdlib calls, "path"
 *                   for the sys.path.insert receiver chain)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "builtins"/"os.path"/"sys" for the stdlib
 *                   channels
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (0 for open/join/dirname/abspath; 1 for insert -
 *                   positional 0 is the list index)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): the sink core is the FILE
 * PATH PARAMETER of actual filesystem operations. In this snapshot the
 * only such operations are the three literal-path open() reads in the
 * packaging script; the join/dirname/abspath nodes directly determine
 * those accessed paths (and the constant parentdir of the sys.path hack),
 * so they are emitted as the propagation/validation channel; sys.path
 * .insert is emitted as the import-resolution channel (labeling decides -
 * expected none/FP everywhere: every path argument in this snapshot is a
 * __file__-derived or literal constant with no attacker influence). NOT
 * emitted: string-built paths (none observed), re.match on request.path
 * (core.py:278/:280, extension.py:178 - a regex match subject, not a
 * filesystem path), resp.headers.add (core.py:250 - Pass 10 header
 * material), exec(f.read()) (setup.py:16 - Pass 4 material).
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no sink row is expected to resolve at API level:
 * open is a builtin, the os.path members are stdlib (not part of the
 * database - only the flask-cors tree is), and the setup.py join/dirname
 * calls are bare names imported via `from os.path import join, dirname`
 * (setup.py:13) with no syntactic receiver to resolve. All families below
 * are AST-level matches and the match_kind column is kept "ast" for
 * cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (18 unit-test files), and
 * /flask-cors-db/ (the CodeQL database directory nested inside the source
 * tree). setup.py, examples/ (3 demo Flask apps) and docs/conf.py are kept
 * in scope: they are the ONLY files containing filesystem operations in the
 * whole snapshot; every path argument there is a literal or __file__-derived
 * constant, so their rows are expected to be labeled none/FP (kept for
 * auditability, consistent with prior projects in this series).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  (setup.py, examples/*.py, docs/conf.py) have no dotted module name; their
 *  file base name is used instead. */
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
  path.replaceAll("\\", "/").matches("%/flask-cors-db/%")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: builtin open(...) - the ONLY filesystem operations in the
     whole snapshot, all READ opens of literal/constant paths in the
     packaging script: setup.py:15 open(join(dirname(__file__),
     'flask_cors/version.py'), 'r') (whose content is exec'd at :16 - the
     read is the boundary, the exec is Pass 4 material), setup.py:18
     open(join(dirname(__file__), 'requirements.txt'), 'r'), setup.py:29
     open('README.rst') (CWD-relative literal, default read mode);
     argument 0 carries the path */
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
  /* family 2: os.path.join propagation nodes - argument 0 is the first
     path component, later positional arguments also carry components.
     Two syntactic forms are matched: (a) the attribute form
     os.path.join(...) (0 rows expected in this snapshot - kept for
     cross-project recall) and (b) the bare Name join(...) form, which is
     the form actually used in setup.py (enabled by `from os.path import
     join, dirname` setup.py:13 - the only file that imports it; the match
     is therefore anchored to setup.py): join(dirname(__file__),
     'flask_cors/version.py') at :15 and join(dirname(__file__),
     'requirements.txt') at :18, feeding the open() rows of family 1. */
  exists(Call c, Attribute func, Attribute mid |
    func = c.getFunc().(Attribute) and
    func.getName() = "join" and
    mid = func.getObject().(Attribute) and
    mid.getName() = "path" and
    mid.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "path_join" and
    callableName = "join" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "join" and
    normalizedPathOf(c).matches("%/setup.py") and
    node = c and
    flowKind = "path_join" and
    callableName = "join" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 3: os.path.dirname / os.path.basename component-extraction
     nodes - argument 0 carries the path. Two syntactic forms: (a) the
     attribute form os.path.dirname(...) - the constant parentdir chains
     os.path.dirname(os.path.dirname(os.path.abspath(__file__))) in the
     3 examples (:17 - two nested calls per file, 6 rows; basename kept
     for cross-project recall, 0 rows expected) and (b) the bare Name
     dirname(...) form in setup.py (from-import alias, anchored to
     setup.py): dirname(__file__) at :15 and :18. */
  exists(Call c, Attribute func, Attribute mid |
    func = c.getFunc().(Attribute) and
    (func.getName() = "dirname" or func.getName() = "basename") and
    mid = func.getObject().(Attribute) and
    mid.getName() = "path" and
    mid.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "path_part" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "dirname" and
    normalizedPathOf(c).matches("%/setup.py") and
    node = c and
    flowKind = "path_part" and
    callableName = "dirname" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 4: os.path.abspath / realpath / normpath normalization nodes -
     argument 0 carries the path. Only abspath is present in this
     snapshot, on constant inputs: os.path.abspath(__file__) innermost in
     each example's parentdir chain (examples :17, 3 rows) and
     os.path.abspath('..') in docs/conf.py:21 (Sphinx sys.path setup);
     realpath/normpath kept for cross-project recall, 0 rows expected. */
  exists(Call c, Attribute func, Attribute mid |
    func = c.getFunc().(Attribute) and
    (func.getName() = "abspath" or func.getName() = "realpath" or func.getName() = "normpath") and
    mid = func.getObject().(Attribute) and
    mid.getName() = "path" and
    mid.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "path_canon" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 5: import-resolution path manipulation: sys.path.insert(idx,
     path) / os.sys.path.insert(idx, path) - positional argument 1 carries
     the inserted directory (positional 0 is the list index). Not a direct
     file access, but it selects the directory the import machinery
     subsequently reads module files from. Sites: os.sys.path.insert(0,
     parentdir) in the 3 examples (:18 - the constant __file__-derived
     parentdir; `os.sys` resolves the sys module through the os module
     attribute, hence the two-level attribute-chain match) and
     sys.path.insert(0, os.path.abspath('..')) in docs/conf.py:21.
     Matching: an .insert call whose receiver is a <base>.path attribute
     whose own object is `sys` - either the Name sys (docs/conf.py) or the
     Attribute os.sys (examples). resp.headers.add / f.required_methods
     .add (core.py:184/:250, decorator.py:118) use .add, not .insert, and
     never match. */
  exists(Call c, Attribute func, Attribute pathAttr |
    func = c.getFunc().(Attribute) and
    func.getName() = "insert" and
    pathAttr = func.getObject().(Attribute) and
    pathAttr.getName() = "path" and
    (
      pathAttr.getObject().(Name).getId() = "sys"
      or
      pathAttr.getObject().(Attribute).getName() = "sys"
    ) and
    node = c and
    flowKind = "import_path_insert" and
    callableName = "insert" and
    argIndex = 1 and
    receiver = "path" and
    moduleHint = "sys" and
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
