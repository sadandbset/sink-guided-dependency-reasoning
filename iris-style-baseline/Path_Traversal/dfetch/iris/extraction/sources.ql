/**
 * @name dfetch CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   dfetch CodeQL database (snapshot 81020d5, dfetch 0.5.1 - the dfetch CLI
 *   tool itself is the audit target): the manifest YAML load boundary
 *   (yaml.safe_load at dfetch/manifest/manifest.py:139 - the dfetch.yaml
 *   parse where every project field name/dst/src/patch/url/repo-path/
 *   branch/tag/revision/vcs enters, and yaml.safe_load at
 *   dfetch/project/metadata.py:71 - the .dfetch_data.yaml of a previously
 *   fetched project, remote-influenced content); the manifest root dict
 *   reads (loaded_yaml["manifest"] at manifest.py:129 and
 *   safe_load(metadata_file)["dfetch"] at metadata.py:71); the per-field
 *   manifest value boundaries (yamldata[key] subscripts at
 *   dfetch/manifest/project.py:268 in ProjectEntry.from_yaml - incl. the
 *   dst/src/patch keys - and remote.py:52/:53 in Remote.from_yaml;
 *   kwargs.get(...) reads in ProjectEntry.__init__ project.py:241-252 -
 *   dst defaults to the project name when absent - and Remote.__init__
 *   remote.py:41); the metadata value boundaries (kwargs.get(...) reads in
 *   Metadata.__init__ metadata.py:36-48, incl. "destination" and "patch",
 *   sourced from the fetched project's .dfetch_data.yaml); the
 *   remote-repository subprocess output boundary (.stdout attribute reads
 *   in dfetch/vcs/git.py - the "git submodule foreach" output at :229 whose
 *   sm_path becomes a ProjectEntry dst via commands/import_.py:180, the
 *   "git config --file <toplevel>/.gitmodules" urls at :279, ls-remote at
 *   :67-69, git log/diff at :184/:194/:212, git branch at :296 - and in
 *   dfetch/project/svn.py - the "svn propget svn:externals" output at :46
 *   whose local_path/name become External.path at :70 then a ProjectEntry
 *   dst via import_.py:158, svn list at :252-253, svn info at :268,
 *   svnversion at :287/:298, svn diff at :316); the CLI boundary (sys.argv
 *   at dfetch/__main__.py:80, the parsed argparse Namespace fields
 *   args.projects/force/no_recommendations/revs/outfile/type/verbose read
 *   in dfetch/commands/*.py and __main__.py:63 - OPERATOR-trust level,
 *   recorded for labeling to classify, not automatically attacker sources;
 *   args.func dispatch excluded - and the CLI entry parameters: the `args`
 *   parameters of Command.__call__ in update.py:65, check.py:59,
 *   diff.py:101, freeze.py:67, init.py:29, report.py:61 plus the `argv`
 *   parameter of run() at __main__.py:61). Raw BQRS extraction query: run
 *   with `codeql query run` and decode with `codeql bqrs decode` (not
 *   database analyze). This is a plain multi-column select query on
 *   purpose: @kind problem is the wrong shape for candidate tables and
 *   @kind table is not assumed to exist.
 * @id iris/dfetch/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (e.g. "safe_load",
 *                   "loaded_yaml", "yamldata", "get", "stdout", "argv",
 *                   "projects"/"revs"/"outfile" for the args.<field> reads,
 *                   the function name for parameter rows)
 *   4. flow_kind  - "yaml_load" (yaml.safe_load parse boundary; the RETURN
 *                   VALUE carries the parsed external content),
 *                   "manifest_field" (loaded_yaml/yamldata subscripts and
 *                   kwargs.get reads sourcing the dfetch.yaml manifest),
 *                   "metadata_field" (kwargs.get reads sourcing a fetched
 *                   project's .dfetch_data.yaml),
 *                   "process_stdout" (.stdout reads of git/svn subprocess
 *                   output - remote-repository-controlled data),
 *                   "cli" (sys.argv), "cli_arg" (parsed argparse Namespace
 *                   attribute reads - operator-trust level),
 *                   "param" (CLI entry parameters: the `args` parameters of
 *                   Command.__call__ implementations and the `argv`
 *                   parameter of __main__.run)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "yaml"/"kwargs"/"result"/"args"/"sys" etc.,
 *                   or "" if none; enclosing class name for parameter rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "yaml"/"sys" for the external/stdlib channels
 *   7. arg_index  - 0-based positional argument index (index of the key
 *                   argument for keyed reads such as kwargs.get(key) and
 *                   yamldata[key]; -1 when the tainted value is the return
 *                   value or the attribute itself; parameter position in
 *                   the function definition for "param" rows, including
 *                   the self slot for methods)
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
 * the manifest/metadata boundaries flow through yaml.safe_load results,
 * subscripts on local names and kwargs.get returns; the subprocess boundary
 * flows through instance attributes on local variables (result.stdout); and
 * yaml is an external library not part of the database (only the dfetch tree
 * is). All families below are AST-level matches and the match_kind column is
 * kept "ast" for cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (unit test tree), /features/
 * (behave-BDD step files), /dfetch-db/ (the CodeQL database directory sits
 * inside the source tree), /doc/, /node_modules/ (defensive). setup.py and
 * create_venv.py at the repo root are kept in scope (build/dev scripts -
 * rows, if any, expected to be labeled none/FP).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  (setup.py, scripts/*.py) have no dotted module name; their file base name
 *  is used instead. */
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
  path.replaceAll("\\", "/").matches("%/features/%")
  or
  path.replaceAll("\\", "/").matches("%/dfetch-db/%")
  or
  path.replaceAll("\\", "/").matches("%/doc/%")
  or
  path.replaceAll("\\", "/").matches("%/node_modules/%")
}

/* ------------------------------------------------------------------ */
/* Shared dfetch shapes (kept consistent with sinks.ql)                 */
/* ------------------------------------------------------------------ */

/** Modules whose `kwargs.get(...)` / `yamldata[...]` reads source values from
 *  the dfetch.yaml manifest (ProjectEntry / Remote construction) or from a
 *  fetched project's .dfetch_data.yaml (Metadata construction).
 *  bindingset[path]: the callers pass a bound path (normalizedPathOf of a
 *  bound node); `matches` is a checked position that does not bind its
 *  receiver, so without the annotation the body cannot bind `path`. */
bindingset[path]
private predicate manifestBoundaryModule(string path) {
  path.matches("%/dfetch/manifest/project.py")
  or
  path.matches("%/dfetch/manifest/remote.py")
  or
  path.matches("%/dfetch/project/metadata.py")
}

/** Modules that parse git/svn subprocess output (the remote-repository data
 *  boundary). Same bindingset rationale as manifestBoundaryModule. */
bindingset[path]
private predicate processOutputModule(string path) {
  path.matches("%/dfetch/vcs/git.py")
  or
  path.matches("%/dfetch/project/svn.py")
}

/** The argparse CLI surface modules (command implementations and the
 *  __main__ entry). Same bindingset rationale as manifestBoundaryModule. */
bindingset[path]
private predicate commandModule(string path) {
  path.matches("%/dfetch/commands/%")
  or
  path.matches("%/dfetch/__main__.py")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: manifest/metadata YAML load boundary: yaml.safe_load(...)
     (manifest.py:139 in Manifest._load_yaml - the dfetch.yaml parse feeding
     ProjectEntry/Remote construction via Manifest.from_yaml; metadata.py:71
     in Metadata.from_file - the .dfetch_data.yaml of a previously fetched
     project, remote-influenced content). The RETURN VALUE carries the
     parsed external content, hence argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "safe_load" and
    func.getObject().(Name).getId() = "yaml" and
    node = c and
    flowKind = "yaml_load" and
    callableName = "safe_load" and
    argIndex = -1 and
    receiver = "yaml" and
    moduleHint = "yaml" and
    matchKind = "ast"
  )
  or
  /* family 2: manifest/metadata root dict reads: loaded_yaml["manifest"]
     (manifest.py:129 - the manifest root mapping; the value flows into the
     Manifest ctor and _init_projects -> ProjectEntry.from_yaml) and
     yaml.safe_load(metadata_file)["dfetch"] (metadata.py:71 - the metadata
     root mapping). Index argument 0 carries the key. */
  exists(Subscript s |
    s.getObject().(Name).getId() = "loaded_yaml" and
    normalizedPathOf(s).matches("%/dfetch/manifest/manifest.py") and
    node = s and
    flowKind = "manifest_field" and
    callableName = "loaded_yaml" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  exists(Subscript s, Call base, Attribute func |
    base = s.getObject().(Call) and
    func = base.getFunc().(Attribute) and
    func.getName() = "safe_load" and
    func.getObject().(Name).getId() = "yaml" and
    node = s and
    flowKind = "manifest_field" and
    callableName = "safe_load" and
    argIndex = 0 and
    receiver = "yaml" and
    moduleHint = "yaml" and
    matchKind = "ast"
  )
  or
  /* family 3: per-field manifest value reads: yamldata[...] subscripts -
     project.py:268 kwargs[str(key)] = yamldata[key] in
     ProjectEntry.from_yaml (iterates the ProjectEntryDict keys: name,
     revision, remote, src, dst, url, patch, repo, branch, tag, repo-path,
     vcs - THE per-field manifest boundary) and remote.py:52/:53
     yamldata["name"] / yamldata["url-base"] in Remote.from_yaml. Index
     argument 0 carries the key. */
  exists(Subscript s |
    s.getObject().(Name).getId() = "yamldata" and
    manifestBoundaryModule(normalizedPathOf(s)) and
    node = s and
    flowKind = "manifest_field" and
    callableName = "yamldata" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 4: internal-state boundary: kwargs.get(...) reads - ProjectEntry
     .__init__ (project.py:241-252: revision, remote, default_remote, src,
     dst - defaults to the project name when absent -, url, patch,
     repo-path, branch, tag, vcs) and Remote.__init__ (remote.py:41
     "default"): values sourced from the dfetch.yaml manifest; argument 0
     carries the key. Metadata.__init__ (metadata.py:36-48: branch, tag,
     revision, remote_url, destination, hash, patch) is split off as the
     metadata_field kind: those values are re-read from a fetched project's
     .dfetch_data.yaml (remote-influenced content). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Name).getId() = "kwargs" and
    manifestBoundaryModule(normalizedPathOf(c)) and
    node = c and
    (
      (
        not normalizedPathOf(c).matches("%/dfetch/project/metadata.py") and
        flowKind = "manifest_field"
      )
      or
      normalizedPathOf(c).matches("%/dfetch/project/metadata.py") and
      flowKind = "metadata_field"
    ) and
    callableName = "get" and
    argIndex = 0 and
    receiver = "kwargs" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5: remote-repository subprocess output boundary: .stdout
     attribute reads in the git/svn output-parsing modules - vcs/git.py:24
     (git --version), :67-69 (git ls-remote refs), :184/:194/:212 (git
     log/diff), :229 ("git submodule foreach" output - sm_path becomes a
     ProjectEntry dst via commands/import_.py:180), :279 ("git config
     --file <toplevel>/.gitmodules" urls), :296 (git branch);
     project/svn.py:46 ("svn propget svn:externals" output - local_path/
     name become External.path at svn.py:70 then a ProjectEntry dst via
     import_.py:158), :141 (svn ls tags), :149 (svn --version), :253 (svn
     list license files), :268 (svn info), :287/:298 (svnversion/svn info),
     :316 (svn diff). The attribute VALUE carries the remote-controlled
     output, hence argIndex -1. .stderr reads are error streams, not data
     boundaries, and are not matched. */
  exists(Attribute a |
    a.getName() = "stdout" and
    a.getObject() instanceof Name and
    processOutputModule(normalizedPathOf(a)) and
    node = a and
    flowKind = "process_stdout" and
    callableName = "stdout" and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 6: CLI input: sys.argv (dfetch/__main__.py:80 -
     run(sys.argv[1:]) in main(), the raw CLI argument list; the argparse
     tree in create_parser turns it into the Namespace fields of family 7).
     Operator-trust level - recorded for labeling, not automatically an
     attacker source. */
  exists(Attribute a |
    a.getName() = "argv" and
    a.getObject().(Name).getId() = "sys" and
    node = a and
    flowKind = "cli" and
    callableName = "argv" and
    argIndex = -1 and
    receiver = "sys" and
    moduleHint = "sys" and
    matchKind = "ast"
  )
  or
  /* family 7: parsed CLI argument reads: args.<field> attribute reads of
     the argparse Namespace in the command modules and __main__:
     args.verbose (__main__.py:63), args.projects (update.py:71,
     check.py:65, diff.py:108/:111, report.py:68 - project-name selection
     from the CLI), args.force (update.py:73), args.no_recommendations
     (update.py:75, check.py:69), args.revs (diff.py:104 - flows into git/
     svn diff revisions), args.type (report.py:65), args.outfile
     (report.py:75/:76 - flows into reporter.dump_to_file -> cyclonedx
     output_to_file). args.func (__main__.py:67) is the dispatch callback,
     not data, and is excluded. Operator-trust level: the person invoking
     dfetch is the same trust domain as the manifest it consumes - the
     labeling step decides whether any of these cross a real untrusted
     boundary. */
  exists(Attribute a |
    a.getObject().(Name).getId() = "args" and
    not a.getName() = "func" and
    commandModule(normalizedPathOf(a)) and
    node = a and
    flowKind = "cli_arg" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "args" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 8: CLI entry parameters: the `args: argparse.Namespace`
     parameters of Command.__call__ implementations (update.py:65,
     check.py:59, diff.py:101, freeze.py:67, init.py:29, report.py:61 -
     import/environment/validate take an unused `_` and produce no row) and
     the `argv: Sequence[str]` parameter of run() at __main__.py:61 - the
     boundary carrying all CLI input into the command layer; arg_index is
     the 0-based position in the function definition including the self
     slot for methods. */
  exists(Function f, Parameter p |
    (
      f.getName() = "__call__" and
      commandModule(normalizedPathOf(f)) and
      p.getName() = "args"
      or
      f.getName() = "run" and
      normalizedPathOf(f).matches("%/dfetch/__main__.py") and
      p.getName() = "argv"
    ) and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
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
