/**
 * @name ansible CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   ansible CodeQL database (snapshot cef62967, ansible 2.9.6.post0 - the
 *   ansible controller code base under lib/ansible is the audit target):
 *   the task-argument boundary (self._task.args attribute reads and the
 *   self._task.args.get(...) call sites / self._task.args[...] subscript
 *   reads in the 78 action plugins - task args are post_validate()-templated
 *   at executor/task_executor.py:588 against host variables that include
 *   remote ansible_facts (task_executor.py:694/:758) and CLI --extra-vars,
 *   so playbook variables, inventory values and remote fact values all reach
 *   these reads; e.g. plugins/action/fetch.py:51-:55 src/dest/flat,
 *   copy.py:412-:416, assemble.py:93-:100, template.py:56-:64,
 *   include_vars.py source_dir/source_file, script.py:47-:86,
 *   net_get.py:53-:66); the task-variable boundary (task_vars[...] /
 *   task_vars.get(...) reads, e.g. fetch.py:129 task_vars['inventory_hostname']
 *   which becomes a dest path component at :132, and variables[...] /
 *   variables.get(...) in the lookup plugins; self._play_context.remote_addr
 *   reads in plugins/action/* as the inventory fallback of fetch dest
 *   construction, fetch.py:131); the lookup terms boundary (the `terms`
 *   parameter of LookupModule.run(...) definitions in all 63
 *   plugins/lookup/*.py - terms carry playbook-templated values that the
 *   file/fileglob/filetree/first_found/ini/csvfile/passwordstore/shelvefile
 *   lookups turn into controller-side file paths); the CLI boundary
 *   (sys.argv reads, e.g. cli/pull.py:159/:225; the `args` parameter of
 *   CLI.__init__ and the ten <Name>CLI(CLI) subclass __init__ definitions in
 *   lib/ansible/cli/*.py - bin/ansible* pass sys.argv there; and
 *   context.CLIARGS attribute/subscript/get reads - the parsed CLI options
 *   that carry --roles-path, -i inventory, --vault-password-file, --tree and
 *   -e extra-vars, e.g. galaxy/role.py:210/:308, config/manager.py:215
 *   ANSIBLE_CONFIG via os.getenv); the environment boundary (os.environ /
 *   os.environ[...] / os.environ.get(...) / os.getenv(...) reads across the
 *   controller tree); the remote-result boundary (json.loads(...) calls that
 *   parse module stdout off the wire - plugins/action/__init__.py:990
 *   _parse_returned_data, executor/task_executor.py:1106/:1109,
 *   executor/interpreter_discovery.py:101,
 *   plugins/connection/winrm.py:494, psrp.py:508, network_cli.py:362); the
 *   remote-facts boundary (result['ansible_facts'] subscript reads at
 *   task_executor.py:694/:697/:758/:761 - remote-controlled facts merged
 *   into host variables and re-templated into task args); and the
 *   galaxy-archive entry boundary (member.name attribute reads in
 *   galaxy/role.py - tar member names from a downloaded role archive
 *   iterated at role.py:319-:330). Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose: @kind
 *   problem is the wrong shape for candidate tables and @kind table is not
 *   assumed to exist.
 * @id iris/ansible/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql and to the prior IRIS manual
 * projects aiohttp/airflow):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (e.g. "args", "get",
 *                   "argv", "CLIARGS", "environ", "loads", "run", the
 *                   function name for parameter rows)
 *   4. flow_kind  - "task_args" (self._task.args read), "task_args_get"
 *                   (self._task.args.get(key) - argument 0 carries the key),
 *                   "task_args_item" (self._task.args[key] - index 0 carries
 *                   the key), "task_vars" (task_vars[...] / variables[...]),
 *                   "task_vars_get" (task_vars.get(...)), "lookup_terms"
 *                   (terms parameter of LookupModule.run), "cli" (sys.argv
 *                   family), "cli_args" (args parameter of CLI __init__),
 *                   "cli_options" (context.CLIARGS family), "env"
 *                   (os.environ / os.getenv family), "remote_result"
 *                   (json.loads of module stdout), "remote_facts"
 *                   (result['ansible_facts']), "archive_entry"
 *                   (member.name of a galaxy role tar), "inventory_addr"
 *                   (self._play_context.remote_addr)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "self._task"/"self._task.args"/"task_vars"/
 *                   "sys"/"context"/"os"/"json"/"member"/
 *                   "self._play_context" etc., or "" if none; enclosing
 *                   class name for parameter rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "sys"/"os"/"json"/"ansible.context" for the
 *                   stdlib/context channel families
 *   7. arg_index  - 0-based positional argument index carrying the controlled
 *                   key/value (index 0 for keyed reads and getenv/loads; the
 *                   0-based parameter position in the function definition
 *                   for "param"-like rows, including the self slot for
 *                   methods), -1 if N/A
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
 * a row). No source family in this project resolves at API level with useful
 * precision: the task-argument, task-variable, lookup-term, CLI-argument and
 * remote-result boundaries are framework-injected values on local/self
 * attributes (not module members), so all families below are AST-level
 * matches and the match_kind column is kept "ast" for cross-project contract
 * consistency.
 *
 * Scope (applied to every row): %/lib/ansible/% (the shipped ansible
 * package), EXCLUDING %/lib/ansible/modules/% (modules execute on the
 * managed nodes; their module.params boundary is documented in
 * exploration/detection.json uncoveredCases instead of being extracted:
 * ~28k read sites would drown the candidate table) and EXCLUDING
 * %/ansible-db/% (the CodeQL database directory sits inside the source
 * tree). The top-level test/, hacking/, examples/, docs/, contrib/ and
 * changelogs/ trees are outside the positive scope and thus not extracted;
 * bin/ansible* wrapper scripts only pass sys.argv into lib/ansible/cli and
 * are covered by the cli_args family rows.
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

/** True iff the candidate's file path is inside the audited controller tree
 *  (%/lib/ansible/% but not %/lib/ansible/modules/% and not the nested
 *  %/ansible-db/% database directory). bindingset[path] declares that the
 *  caller passes a bound path (the path only appears in checked positions
 *  such as the receiver of replaceAll/matches inside this predicate). */
bindingset[path]
predicate controllerSourcePath(string path) {
  path.replaceAll("\\", "/").matches("%/lib/ansible/%") and
  not path.replaceAll("\\", "/").matches("%/lib/ansible/modules/%") and
  not path.replaceAll("\\", "/").matches("%/ansible-db/%")
}

/* ------------------------------------------------------------------ */
/* Shared ansible shapes (kept consistent with sinks.ql)                */
/* ------------------------------------------------------------------ */

/** Files whose `json.loads(...)` calls parse remote module output coming
 *  off the wire (the remote trust boundary of the controller).
 *  bindingset[path]: the callers pass a bound path; `matches` is a checked
 *  position that does not bind its receiver. */
bindingset[path]
private predicate remoteResultParseModule(string path) {
  path.matches("%/lib/ansible/plugins/action/__init__.py")
  or
  path.matches("%/lib/ansible/executor/task_executor.py")
  or
  path.matches("%/lib/ansible/executor/interpreter_discovery.py")
  or
  path.matches("%/lib/ansible/plugins/connection/winrm.py")
  or
  path.matches("%/lib/ansible/plugins/connection/psrp.py")
  or
  path.matches("%/lib/ansible/plugins/connection/network_cli.py")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: task-argument boundary: self._task.args attribute reads.
     Task args are fully templated before the action plugin runs
     (executor/task_executor.py:588 self._task.post_validate(templar=...) -
     the templar variables include remote ansible_facts via
     task_executor.py:694/:758 and CLI --extra-vars), so every read of
     self._task.args in an action plugin can observe playbook, inventory,
     extra-vars and remote-fact values. Read sites include
     fetch.py:51/:52/:53, copy.py:412-:416/:221, assemble.py:93-:100,
     template.py:41-:64, script.py:47-:86, net_get.py:53-:66,
     include_vars.py:78-:100 (bare .args iteration for VALID_* keys),
     set_fact.py:42/:44/:45. */
  exists(Attribute a |
    a.getName() = "args" and
    a.getObject().(Attribute).getName() = "task" and
    a.getObject().(Attribute).getObject().(Name).getId() = "self" and
    node = a and
    flowKind = "task_args" and
    callableName = "args" and
    argIndex = -1 and
    receiver = "self._task" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 2: task-argument keyed reads: self._task.args.get(key, ...) -
     argument 0 carries the option key whose value is returned */
  exists(Call c, Attribute get, Attribute args, Attribute task |
    get = c.getFunc().(Attribute) and
    get.getName() = "get" and
    args = get.getObject().(Attribute) and
    args.getName() = "args" and
    task = args.getObject().(Attribute) and
    task.getName() = "task" and
    task.getObject().(Name).getId() = "self" and
    node = c and
    flowKind = "task_args_get" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "self._task.args" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: task-argument keyed reads: self._task.args[key] - the index
     carries the option key (net_get.py:53, copy.py:333, template.py:41) */
  exists(Subscript s, Attribute args |
    args = s.getObject().(Attribute) and
    args.getName() = "args" and
    args.getObject().(Attribute).getName() = "task" and
    args.getObject().(Attribute).getObject().(Name).getId() = "self" and
    node = s and
    flowKind = "task_args_item" and
    callableName = "args" and
    argIndex = 0 and
    receiver = "self._task.args" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 4: task-variable boundary: task_vars[...] subscripts anywhere in
     the controller tree (fetch.py:129 task_vars['inventory_hostname'] - the
     inventory host name that becomes a dest directory component at :132;
     action/network.py:173-:175 task_vars['ansible_facts']['network_os'] -
     remote fact values) and variables[...] subscripts in the lookup plugins
     (the templar variable dict handed to LookupModule.run) */
  exists(Subscript s |
    (
      s.getObject().(Name).getId() = "task_vars"
      or
      s.getObject().(Name).getId() = "variables" and
      normalizedPathOf(s).matches("%/lib/ansible/plugins/lookup/%")
    ) and
    node = s and
    flowKind = "task_vars" and
    callableName = s.getObject().(Name).getId() and
    argIndex = 0 and
    receiver = s.getObject().(Name).getId() and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 5: task-variable keyed reads: task_vars.get(...) /
     variables.get(...) - argument 0 carries the key */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    (
      func.getObject().(Name).getId() = "task_vars"
      or
      func.getObject().(Name).getId() = "variables" and
      normalizedPathOf(c).matches("%/lib/ansible/plugins/lookup/%")
    ) and
    node = c and
    flowKind = "task_vars_get" and
    callableName = "get" and
    argIndex = 0 and
    receiver = func.getObject().(Name).getId() and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6: lookup terms boundary: the `terms` parameter of
     LookupModule.run(self, terms, variables, **kwargs) definitions in the
     63 plugins/lookup/*.py modules - terms carry the playbook-templated
     lookup arguments (with_file/with_fileglob/with_first_found etc.) that
     the file lookups turn into controller-side file paths
     (lookup/file.py:64, fileglob.py:59, filetree.py,
     first_found.py:120-:168). arg_index is the 0-based parameter position
     including the self slot. */
  exists(Function f, Parameter p |
    f.getName() = "run" and
    f.getEnclosingScope() instanceof Class and
    f.getEnclosingScope().(Class).getName() = "LookupModule" and
    normalizedPathOf(f).matches("%/lib/ansible/plugins/lookup/%") and
    p = f.getAnArg() and
    p.getName() = "terms" and
    not p.isSelf() and
    node = p and
    flowKind = "lookup_terms" and
    callableName = "run" and
    argIndex = p.getPosition() and
    receiver = "LookupModule" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 7: CLI argv boundary: sys.argv attribute reads and sys.argv[...]
     subscripts (cli/pull.py:225 os.path.dirname(os.path.abspath(sys.argv[0]))
     and :159 ' '.join(sys.argv),
     cli/arguments/option_helpers.py:181, cli/vault.py:55,
     cli/scripts/ansible_cli_stub.py:69/:116,
     cli/scripts/ansible_connection_cli_stub.py:259) - the operator-supplied
     command line that bin/ansible* forward into the CLI classes */
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
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "argv" and
    base.getObject().(Name).getId() = "sys" and
    node = s and
    flowKind = "cli" and
    callableName = "argv" and
    argIndex = 0 and
    receiver = "sys" and
    moduleHint = "sys" and
    matchKind = "ast"
  )
  or
  /* family 8: CLI entry parameters: the `args` parameter of
     CLI.__init__(self, args, callback=None) (cli/__init__.py:61 - the base
     class that stores self.args and parses it at :367
     self.parser.parse_args(self.args[1:])) and of the ten
     <Name>CLI(CLI) subclass __init__ definitions in lib/ansible/cli/*.py
     (adhoc, config, console, doc, galaxy, inventory, playbook, pull,
     vault). arg_index is the 0-based parameter position including the
     self slot. */
  exists(Function f, Parameter p |
    f.getName() = "__init__" and
    f.getEnclosingScope() instanceof Class and
    (
      f.getEnclosingScope().(Class).getName() = "CLI" and
      normalizedPathOf(f).matches("%/lib/ansible/cli/__init__.py")
      or
      f.getEnclosingScope().(Class).getABase().(Name).getId() = "CLI" and
      normalizedPathOf(f).matches("%/lib/ansible/cli/%")
    ) and
    p = f.getAnArg() and
    p.getName() = "args" and
    not p.isSelf() and
    node = p and
    flowKind = "cli_args" and
    callableName = "__init__" and
    argIndex = p.getPosition() and
    receiver = f.getEnclosingScope().(Class).getName() and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 9: parsed CLI option boundary: context.CLIARGS attribute reads,
     context.CLIARGS[...] subscripts and context.CLIARGS.get(...) calls -
     the global CLI option store carrying --roles-path (galaxy role
     install paths), -i inventory, --vault-password-file, --tree, -e
     extra-vars etc. into library code (galaxy/role.py:210/:308,
     galaxy/__init__.py:60, cli/galaxy.py, utils/display.py) */
  exists(Attribute a |
    a.getName() = "CLIARGS" and
    a.getObject().(Name).getId() = "context" and
    node = a and
    flowKind = "cli_options" and
    callableName = "CLIARGS" and
    argIndex = -1 and
    receiver = "context" and
    moduleHint = "ansible.context" and
    matchKind = "ast"
  )
  or
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "CLIARGS" and
    base.getObject().(Name).getId() = "context" and
    node = s and
    flowKind = "cli_options" and
    callableName = "CLIARGS" and
    argIndex = 0 and
    receiver = "context" and
    moduleHint = "ansible.context" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute get, Attribute base |
    get = c.getFunc().(Attribute) and
    get.getName() = "get" and
    base = get.getObject().(Attribute) and
    base.getName() = "CLIARGS" and
    base.getObject().(Name).getId() = "context" and
    node = c and
    flowKind = "cli_options" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "context" and
    moduleHint = "ansible.context" and
    matchKind = "ast"
  )
  or
  /* family 10: environment boundary: os.environ / os.environ[...] /
     os.environ.get(...) / os.getenv(...) reads - operator/local-process
     trust level; path-relevant entries exist (config/manager.py:215
     ANSIBLE_CONFIG selects the config file, vault password file via
     --vault-password-file env forms, DEFAULT_LOCAL_TMP, ANSIBLE_ROLES_PATH
     in cli/galaxy.py) and labeling classifies the rest */
  exists(Attribute a |
    a.getName() = "environ" and
    a.getObject().(Name).getId() = "os" and
    node = a and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "environ" and
    base.getObject().(Name).getId() = "os" and
    node = s and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute get, Attribute base |
    get = c.getFunc().(Attribute) and
    get.getName() = "get" and
    base = get.getObject().(Attribute) and
    base.getName() = "environ" and
    base.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
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
  /* family 11: remote-result boundary: json.loads(...) calls that parse
     module output coming off the wire - plugins/action/__init__.py:990
     (_parse_returned_data - the result dict of every module execution,
     including slurp's remote file content/source paths),
     executor/task_executor.py:1106/:1109 (async_status stdout),
     executor/interpreter_discovery.py:101, plugins/connection/winrm.py:494,
     psrp.py:508, network_cli.py:362. Argument 0 carries the raw
     remote-controlled text. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "loads" and
    func.getObject().(Name).getId() = "json" and
    remoteResultParseModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "remote_result" and
    callableName = "loads" and
    argIndex = 0 and
    receiver = "json" and
    moduleHint = "json" and
    matchKind = "ast"
  )
  or
  /* family 12: remote-facts boundary: result['ansible_facts'] subscript
     reads in executor/task_executor.py:694/:697/:758/:761 - the fact dict
     produced by the remote module (gather_facts/set_fact/include_vars
     output) that is merged into the host variables
     (vars_copy.update(result['ansible_facts'])) and re-templated into
     later task arguments */
  exists(Subscript s |
    s.getObject().(Name).getId() = "result" and
    s.getIndex().(StringLiteral).getText() = "'ansible_facts'" and
    normalizedPathOf(s).matches("%/lib/ansible/executor/task_executor.py") and
    node = s and
    flowKind = "remote_facts" and
    callableName = "ansible_facts" and
    argIndex = 0 and
    receiver = "result" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 13: galaxy archive entry boundary: member.name attribute reads
     in galaxy/role.py - the tar member names of a downloaded (galaxy API /
     github) role archive, iterated at role.py:319-:330 where they are
     stripped of the parent dir and '..' parts before
     role_tar_file.extract(member, self.path); the raw member name is the
     remote-controlled value (evidence for the CWE-22 sanitizer question:
     role.py:324-:329 filters part == '..' and '~'/'$' in part) */
  exists(Attribute a |
    a.getName() = "name" and
    a.getObject().(Name).getId() = "member" and
    normalizedPathOf(a).matches("%/lib/ansible/galaxy/role.py") and
    node = a and
    flowKind = "archive_entry" and
    callableName = "name" and
    argIndex = -1 and
    receiver = "member" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 14: inventory address boundary: self._play_context.remote_addr
     attribute reads in the action plugins - the inventory host address
     used as the dest path fallback in fetch.py:131
     (target_name = self._play_context.remote_addr) when
     inventory_hostname is not in task_vars, feeding the fetch dest
     construction at :132 */
  exists(Attribute a |
    a.getName() = "remote_addr" and
    a.getObject().(Attribute).getName() = "_play_context" and
    a.getObject().(Attribute).getObject().(Name).getId() = "self" and
    normalizedPathOf(a).matches("%/lib/ansible/plugins/action/%") and
    node = a and
    flowKind = "inventory_addr" and
    callableName = "remote_addr" and
    argIndex = -1 and
    receiver = "self._play_context" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  controllerSourcePath(normalizedPathOf(node))
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
