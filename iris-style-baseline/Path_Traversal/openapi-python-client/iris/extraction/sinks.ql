/**
 * @name openapi-python-client CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the
 *   openapi-python-client CodeQL database (snapshot d6970d6,
 *   openapi-python-client 0.5.2 - the typer CLI tool itself is the audit
 *   target): pathlib file writes (.write_text - 15 sites in
 *   openapi_python_client/__init__.py: :151/:154/:160/:172/:181/:192/:208/
 *   :214/:220/:225/:229 with literal names under the project tree, and the
 *   REMOTE-NAME-CONTROLLED receivers :197 models_dir /
 *   f"{model.reference.module_name}.py", :204 models_dir /
 *   f"{enum.reference.module_name}.py", :235 api_dir / f"{tag}.py" and :237
 *   async_api_dir / f"{tag}.py" - the RAW operation tag is used with NO
 *   name transformation); pathlib directory creation (.mkdir - :109
 *   project_dir = Path.cwd() / project_name (TITLE-DERIVED, the
 *   FileExistsError catch at :110 is an existence guard only), :146
 *   package_dir, :186 models_dir, :218 api_dir, :223 async_api_dir);
 *   recursive deletion (shutil.rmtree(self.package_dir) :125 inside
 *   Project.update() - the TITLE-CONFIG-DERIVED package_dir, preceded only
 *   by the is_dir() existence check at :122 - TOCTOU-shaped); pathlib file
 *   reads (path.read_bytes() :76 - the CLI --path document target - and
 *   path.read_text() config.py:34 - the CLI --config file target); the
 *   guard read (.is_dir() :122); the pathlib base acquisition
 *   (Path.cwd() :95 - the CWD base every generated path resolves against);
 *   the pathlib '/' join family (all 20 true-divide expressions in
 *   __init__.py are pathlib joins - verified: no arithmetic division exists
 *   in the file - including the remote-component joins :95 Path.cwd() /
 *   self.project_name, :98 project_dir / package_name, :196/:203
 *   models_dir / f"{...module_name}.py" and :234/:236 .../ f"{tag}.py");
 *   the subprocess cwd scoping (subprocess.run("isort ."/"black .",
 *   cwd=self.project_dir, shell=True) :133/:136 - the isort/black processes
 *   rewrite files under the Python-supplied project_dir; the command
 *   strings are literals, only the cwd keyword carries the path); and
 *   definition rows for the tool's path/name-taking APIs (file_api_def:
 *   _process_config(path), cli(config), generate(update)/path,
 *   create_new_client/update_existing_client/_get_project_for_url_or_path/
 *   _get_document path, Config.load_from_path(path); name_api_def:
 *   Reference.from_ref(ref) - the '#/schemas/<leaf>' name pipeline turning
 *   remote schema titles/refs into module FILE names -, utils.snake_case/
 *   pascal_case - the name-reshaping steps that neither strip '/' nor '..'
 *   -, and Project.__init__(openapi) - the object boundary carrying
 *   title/version into project_name/project_dir/package_dir) with the true
 *   path/name parameter positions. Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose: @kind
 *   problem is the wrong shape for candidate tables and @kind table is not
 *   assumed to exist.
 * @id iris/openapi-python-client/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql and to the prior projects
 * in this series):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member/field name ("write_text" / "mkdir" /
 *                   "rmtree" / "read_bytes" / "read_text" / "is_dir" /
 *                   "cwd" / "__truediv__" / "run" / the function name for
 *                   file_api_def and name_api_def definition rows)
 *   4. flow_kind  - "file_write" (.write_text - the path is the RECEIVER,
 *                   a pathlib join result; the module-name sites :197/:204
 *                   and the raw-tag sites :235/:237 have REMOTE-name-
 *                   controlled receivers), "dir_create" (.mkdir - the path
 *                   is the RECEIVER), "dir_delete" (shutil.rmtree(argument
 *                   0) - recursive deletion), "file_read" (.read_bytes /
 *                   .read_text - the path is the RECEIVER: the CLI --path
 *                   document at __init__.py:76 and the CLI --config file
 *                   at config.py:34), "path_stat" (.is_dir() - the guard
 *                   read gating the rmtree), "path_ctor" (Path.cwd() - the
 *                   CWD base acquisition), "path_join" (the pathlib '/'
 *                   operator - all 20 Div expressions in __init__.py; BOTH
 *                   operands carry path components: left = base, right =
 *                   appended component - the remote-controlled components
 *                   are the right operands at :95/:98/:196/:203/:234/:236),
 *                   "process_cwd" (subprocess.run with the KEYWORD argument
 *                   cwd=project_dir - the isort/black processes read/
 *                   rewrite files under the Python-supplied cwd; the
 *                   command strings are literals, so this is file-effect
 *                   scoping, not command injection), "file_api_def"
 *                   (definition row of a tool-internal path-taking API,
 *                   carrying the path parameter position), "name_api_def"
 *                   (definition row of a tool-internal name-shaping API -
 *                   the remote-name pipeline that produces module FILE
 *                   names - carrying the name parameter position)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "package_init"/"module_path"/"models_dir"/
 *                   "shutil"/"subprocess"/"Path" etc., or "" if none;
 *                   "<expr>" when the object expression is neither Name
 *                   nor Attribute; for path_join the hint of the LEFT
 *                   operand (the join base); enclosing class name for
 *                   definition rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "pathlib"/"shutil"/"subprocess" for the stdlib
 *                   channels
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for rmtree); -1 when the path is the
 *                   RECEIVER (write_text/mkdir/read_bytes/read_text/
 *                   is_dir), the keyword argument (the subprocess cwd), or
 *                   the operator form (path_join: both operands carry
 *                   components; Path.cwd has no path argument); the
 *                   parameter position for file_api_def/name_api_def rows
 *                   (0-based positional index, or the 0-based index within
 *                   the keyword-only group for keyword-only parameters -
 *                   marked in the site comments - including the self/cls
 *                   slot semantics for positional ones)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): the sink core is the FILE
 * PATH PARAMETER of actual filesystem operations (write_text/mkdir/rmtree/
 * read_bytes/read_text/is_dir, the isort/black cwd scoping) plus the
 * pathlib pipeline nodes that directly determine the accessed path (the
 * '/' join family and the Path.cwd() base) - NOT every path string
 * construction node: the f-string name construction (f"{...module_name}.py"
 * :196/:203, f"{tag}.py" :234/:236, f"{openapi.title...}-client" :94) is
 * indistinguishable from ordinary string formatting at AST level and is
 * anchored by its consuming path_join/file_write rows instead (documented
 * in detection.json uncoveredCases). The jinja2 template renders and the
 * PackageLoader reads use literal names and perform no attacker-controlled
 * file access. There is NO builtin open(), NO os.path.* call and NO
 * archive/zipfile/tarfile usage in this codebase (all file IO is pathlib
 * members + shutil.rmtree + the subprocess cwd channel).
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body (each or-disjunct of sinkCandidate binds ALL
 * output variables), and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one
 * produced a row). In this project no sink row is expected to resolve at
 * API level: the file operations are instance members on local variables
 * (package_init.write_text, project_dir.mkdir, package_dir.is_dir,
 * path.read_bytes), stdlib members matched on the syntactic qualifier
 * (shutil.rmtree, subprocess.run - the stdlib is not part of the database),
 * the operator-form joins (BinaryExpr Div), or calls of tool-internal/local
 * names. The match_kind column is kept "ast" for all families for
 * cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (unit test tree),
 * /end_to_end_tests/ (fastapi fixture app + golden-master generated client
 * + regen script), /openapi-python-client-db/ (the CodeQL database
 * directory nested inside the source tree).
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

/** Base name hint of an arbitrary expression, used as the receiver (join
 *  base) hint for the path_join operator family: the id for a Name, the
 *  attribute name for an Attribute, "<expr>" otherwise (e.g. the
 *  Path.cwd() call receiving the '/' at :95). */
string exprHint(Expr e) {
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
  path.replaceAll("\\", "/").matches("%/tests/%")
  or
  path.replaceAll("\\", "/").matches("%/end_to_end_tests/%")
  or
  path.replaceAll("\\", "/").matches("%/openapi-python-client-db/%")
}

/* ------------------------------------------------------------------ */
/* Shared openapi-python-client shapes (kept consistent with sources.ql) */
/* ------------------------------------------------------------------ */

/** The generator core module (openapi_python_client/__init__.py) where all
 *  filesystem operations of this tool live (Project build/update flow).
 *  bindingset rationale as in excludedPath. */
bindingset[path]
private predicate generatorCoreModule(string path) {
  path.matches("%/openapi_python_client/__init__.py")
}

/** The config module (openapi_python_client/config.py). Same bindingset
 *  rationale as excludedPath. */
bindingset[path]
private predicate configModule(string path) {
  path.matches("%/openapi_python_client/config.py")
}

/** The CLI module (openapi_python_client/cli.py). Same bindingset
 *  rationale as excludedPath. */
bindingset[path]
private predicate cliModule(string path) {
  path.matches("%/openapi_python_client/cli.py")
}

/** The reference module (openapi_python_client/parser/reference.py). Same
 *  bindingset rationale as excludedPath. */
bindingset[path]
private predicate referenceModule(string path) {
  path.matches("%/openapi_python_client/parser/reference.py")
}

/** The utils module (openapi_python_client/utils.py). Same bindingset
 *  rationale as excludedPath. */
bindingset[path]
private predicate utilsModule(string path) {
  path.matches("%/openapi_python_client/utils.py")
}

/** True iff p is a parameter of f, covering BOTH positional parameters
 *  (Function.getAnArg) and keyword-only parameters declared after a bare
 *  `*` (Function.getAKeywordOnlyArg - getAnArg does NOT include them; the
 *  comparison form getAKeywordOnlyArg() = p is the same one the standard
 *  library uses in Parameter.getDefault). */
private predicate isParameterOf(Function f, Parameter p) {
  p = f.getAnArg()
  or
  p = f.getAKeywordOnlyArg()
}

/** The tool's internal path-taking (kind "file_api_def") and name-shaping
 *  (kind "name_api_def") API definitions with their path/name parameter.
 *  Parameter positions are documented per shape in the row-assembly
 *  family; keyword-only parameters (declared after a bare `*`) are indexed
 *  0-based within the keyword-only group. f and p are bound inside this
 *  predicate body (f via getName + module match, p via isParameterOf +
 *  getName), mirroring the shape predicates of the prior projects in this
 *  series. */
private predicate pathOrNameApiDefShape(Function f, Parameter p, string kind) {
  /* openapi_python_client.cli._process_config(path) - cli.py:20 (module
     function, path at position 0) - the --config Option callback target
     invoked by typer with the CLI-provided config file path */
  f.getName() = "_process_config" and
  cliModule(normalizedPathOf(f)) and
  p.getName() = "path" and
  isParameterOf(f, p) and
  kind = "file_api_def"
  or
  /* openapi_python_client.cli.cli(version, config) - cli.py:34 (module
     function, config at position 1) - the typer app callback whose
     --config Option parameter is the config file path boundary */
  f.getName() = "cli" and
  cliModule(normalizedPathOf(f)) and
  p.getName() = "config" and
  isParameterOf(f, p) and
  kind = "file_api_def"
  or
  /* openapi_python_client.cli.generate(url, path) - cli.py:97 (module
     function, path at position 1) - the typer `generate` command whose
     --path Option is the document file path boundary */
  f.getName() = "generate" and
  cliModule(normalizedPathOf(f)) and
  p.getName() = "path" and
  isParameterOf(f, p) and
  kind = "file_api_def"
  or
  /* openapi_python_client.cli.update(url, path) - cli.py:115 (module
     function, path at position 1) - the typer `update` command whose
     --path Option is the document file path boundary */
  f.getName() = "update" and
  cliModule(normalizedPathOf(f)) and
  p.getName() = "path" and
  isParameterOf(f, p) and
  kind = "file_api_def"
  or
  /* openapi_python_client._get_project_for_url_or_path(*, url, path) -
     openapi_python_client/__init__.py:29 (module function, path is
     KEYWORD-ONLY index 1) - carries the document path/url into
     _get_document */
  f.getName() = "_get_project_for_url_or_path" and
  generatorCoreModule(normalizedPathOf(f)) and
  p.getName() = "path" and
  isParameterOf(f, p) and
  kind = "file_api_def"
  or
  /* openapi_python_client.create_new_client(*, url, path) -
     openapi_python_client/__init__.py:39 (module function, path is
     KEYWORD-ONLY index 1) - the `generate` command entry */
  f.getName() = "create_new_client" and
  generatorCoreModule(normalizedPathOf(f)) and
  p.getName() = "path" and
  isParameterOf(f, p) and
  kind = "file_api_def"
  or
  /* openapi_python_client.update_existing_client(*, url, path) -
     openapi_python_client/__init__.py:52 (module function, path is
     KEYWORD-ONLY index 1) - the `update` command entry */
  f.getName() = "update_existing_client" and
  generatorCoreModule(normalizedPathOf(f)) and
  p.getName() = "path" and
  isParameterOf(f, p) and
  kind = "file_api_def"
  or
  /* openapi_python_client._get_document(*, url, path) - openapi_python_
     client/__init__.py:65 (module function, path is KEYWORD-ONLY index 1)
     - the function whose body performs path.read_bytes() at :76 */
  f.getName() = "_get_document" and
  generatorCoreModule(normalizedPathOf(f)) and
  p.getName() = "path" and
  isParameterOf(f, p) and
  kind = "file_api_def"
  or
  /* openapi_python_client.config.Config.load_from_path(path) -
     config.py:33 (staticmethod, path at position 0 - no self/cls slot) -
     the function whose body performs path.read_text() + yaml.safe_load at
     :34 */
  f.getName() = "load_from_path" and
  configModule(normalizedPathOf(f)) and
  p.getName() = "path" and
  isParameterOf(f, p) and
  kind = "file_api_def"
  or
  /* openapi_python_client.parser.reference.Reference.from_ref(ref) -
     parser/reference.py:21 (staticmethod, ref at position 0) - THE remote
     name pipeline: ref.split("/")[-1] + pascal_case + snake_case turn
     remote schema refs/titles into class_name/module_name, which become
     the models_dir / f"{module_name}.py" write targets */
  f.getName() = "from_ref" and
  referenceModule(normalizedPathOf(f)) and
  p.getName() = "ref" and
  isParameterOf(f, p) and
  kind = "name_api_def"
  or
  /* openapi_python_client.utils.snake_case(value) - utils.py:6 (module
     function, value at position 0) - the name-reshaping step applied to
     class names before they become module file names (case reshaping
     only: neither strips '/' nor '..') */
  f.getName() = "snake_case" and
  utilsModule(normalizedPathOf(f)) and
  p.getName() = "value" and
  isParameterOf(f, p) and
  kind = "name_api_def"
  or
  /* openapi_python_client.utils.pascal_case(value) - utils.py:12 (module
     function, value at position 0) - the first name-reshaping step of
     Reference.from_ref */
  f.getName() = "pascal_case" and
  utilsModule(normalizedPathOf(f)) and
  p.getName() = "value" and
  isParameterOf(f, p) and
  kind = "name_api_def"
  or
  /* openapi_python_client.Project.__init__(self, *, openapi) -
     openapi_python_client/__init__.py:90 (method, openapi is KEYWORD-ONLY
     index 0 - self excluded by isSelf) - the object boundary carrying
     openapi.title/version into project_name/project_dir/package_dir
     (:94-:98) */
  f.getName() = "__init__" and
  generatorCoreModule(normalizedPathOf(f)) and
  p.getName() = "openapi" and
  isParameterOf(f, p) and
  kind = "name_api_def"
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. Every or-disjunct binds all predicate
 *  outputs (no shared trailing conjunct after an or). */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: pathlib file writes: .write_text(...) - 15 sites in
     openapi_python_client/__init__.py: package_init :151, pytyped :154,
     pyproject_path :160, readme :172, git_ignore_path :181, types_path
     :192, models_init :208, client_path :214, api_init :220,
     async_api_init :225, api_errors :229 (literal names under the
     title-derived project tree) and the REMOTE-NAME-CONTROLLED receivers
     module_path :197 (= models_dir / f"{model.reference.module_name}.py"),
     module_path :204 (= models_dir / f"{enum.reference.module_name}.py"),
     module_path :235 (= api_dir / f"{tag}.py" - the RAW operation tag),
     async_module_path :237 (= async_api_dir / f"{tag}.py"); the written
     content is rendered jinja template output. The path is the RECEIVER,
     hence argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "write_text" and
    generatorCoreModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "file_write" and
    callableName = "write_text" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 2: pathlib directory creation: .mkdir(...) - __init__.py:109
     project_dir.mkdir() (project_dir = Path.cwd() / project_name - the
     TITLE/config-derived project root; the FileExistsError catch at :110
     is an existence guard, not a traversal guard), :146
     package_dir.mkdir(), :186 models_dir.mkdir(), :218 api_dir.mkdir(),
     :223 async_api_dir.mkdir(); the path is the RECEIVER, hence
     argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "mkdir" and
    generatorCoreModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "dir_create" and
    callableName = "mkdir" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 3: recursive deletion: shutil.rmtree(self.package_dir) -
     __init__.py:125 inside Project.update(): deletes the
     TITLE/config-derived package_dir tree, preceded only by the is_dir()
     existence check at :122 (TOCTOU-shaped, no containment validation);
     argument 0 carries the path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "rmtree" and
    func.getObject().(Name).getId() = "shutil" and
    generatorCoreModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "dir_delete" and
    callableName = "rmtree" and
    argIndex = 0 and
    receiver = "shutil" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  /* family 4: pathlib file reads: path.read_bytes() - __init__.py:76 (the
     CLI --path OpenAPI document, operator-selected target file) and
     path.read_text() - config.py:34 (the CLI --config file,
     operator-selected target file); the path is the RECEIVER, hence
     argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "read_bytes" and
    generatorCoreModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "file_read" and
    callableName = "read_bytes" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "read_text" and
    configModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "file_read" and
    callableName = "read_text" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 5: pathlib guard read: .is_dir() - __init__.py:122
     self.package_dir.is_dir() - the existence check gating the rmtree at
     :125; the path is the RECEIVER, hence argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "is_dir" and
    generatorCoreModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "path_stat" and
    callableName = "is_dir" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 6: pathlib base acquisition: Path.cwd() - __init__.py:95 - the
     CWD base every generated path resolves against (combined with an
     absolute or '..'-bearing project_name it escapes the CWD scoping
     entirely); no path argument (the CWD is implicit), hence argIndex -1.
     Matched via the `from pathlib import Path` import form used in this
     file. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "cwd" and
    func.getObject().(Name).getId() = "Path" and
    generatorCoreModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "path_ctor" and
    callableName = "cwd" and
    argIndex = -1 and
    receiver = "Path" and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 7: the pathlib '/' join family - every true-divide
     (BinaryExpr with operator Div) in openapi_python_client/__init__.py;
     verified by grep that all 20 Div expressions in the file are pathlib
     joins (no arithmetic division exists there): Path.cwd() /
     self.project_name :95 (THE project-root join - remote title/config
     component), self.project_dir / self.package_name :98, and the joins
     appending literal names :148/:153/:159/:170/:179/:185/:187/:191/:212/
     :217/:219/:222/:224/:227 plus the REMOTE-component joins models_dir /
     f"{model.reference.module_name}.py" :196, models_dir /
     f"{enum.reference.module_name}.py" :203, api_dir / f"{tag}.py" :234
     and async_api_dir / f"{tag}.py" :236. Operator form: both operands
     carry path components (left = base - recorded as the receiver hint -,
     right = appended component), hence argIndex -1. */
  exists(BinaryExpr b |
    b.getOp() instanceof Div and
    generatorCoreModule(normalizedPathOf(b)) and
    node = b and
    flowKind = "path_join" and
    callableName = "__truediv__" and
    argIndex = -1 and
    receiver = exprHint(b.getLeft()) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 8: subprocess cwd scoping: subprocess.run("isort .", cwd=
     self.project_dir, shell=True, ...) - __init__.py:133-135 and
     subprocess.run("black .", cwd=self.project_dir, shell=True) :136
     inside Project._reformat(): the isort/black processes read, rewrite
     and delete files under the Python-supplied cwd (the
     TITLE/config-derived project_dir). The command strings are literals
     (no command-injection channel), so the path-relevant argument is the
     KEYWORD argument `cwd`, hence argIndex -1. */
  exists(Call c, Attribute func, Keyword kw |
    func = c.getFunc().(Attribute) and
    func.getName() = "run" and
    func.getObject().(Name).getId() = "subprocess" and
    kw = c.getAKeyword() and
    kw.getArg() = "cwd" and
    generatorCoreModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "process_cwd" and
    callableName = "run" and
    argIndex = -1 and
    receiver = "subprocess" and
    moduleHint = "subprocess" and
    matchKind = "ast"
  )
  or
  /* family 9: definition rows - the tool's internal path-taking
     (file_api_def) and name-shaping (name_api_def) APIs with the true
     parameter positions: _process_config(path) cli.py:20 pos 0, cli
     (config) cli.py:34 pos 1, generate(path) cli.py:97 pos 1,
     update(path) cli.py:115 pos 1, _get_project_for_url_or_path(path)
     __init__.py:29 kw-only 1, create_new_client(path) :39 kw-only 1,
     update_existing_client(path) :52 kw-only 1, _get_document(path) :65
     kw-only 1, Config.load_from_path(path) config.py:33 pos 0
     (staticmethod); Reference.from_ref(ref) parser/reference.py:21 pos 0
     (staticmethod - the remote-name pipeline), utils.snake_case(value)
     utils.py:6 pos 0, utils.pascal_case(value) utils.py:12 pos 0,
     Project.__init__(openapi) __init__.py:90 kw-only 0; these rows give
     the labeling step the summary/propagation backbone between the
     document/config boundaries and the concrete file operations. The
     index is the 0-based positional index for positional parameters (the
     self/cls slot included in the count, self excluded here via isSelf)
     and the 0-based index within the keyword-only group for keyword-only
     parameters. */
  exists(Function f, Parameter p, int idx, string kind |
    pathOrNameApiDefShape(f, p, kind) and
    not p.isSelf() and
    (
      f.getArg(idx) = p
      or
      f.getKeywordOnlyArg(idx) = p
    ) and
    node = p and
    flowKind = kind and
    callableName = f.getName() and
    argIndex = idx and
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
