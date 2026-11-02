/**
 * !! MACHINE-GENERATED from iris/labels/labels.json (pass 1, run ansible-pathtraversal-pass1-step3-20261021) !!
 * !! Do not edit by hand: regenerate with labels/work/build_libraries.py !!
 *
 * Source nodes for the Pass 1 (Path Traversal) taint query of ansible.
 *
 * Every rule below is the CodeQL rendering of reviewed Pass 1 label entries
 * (role=source). The label id -> predicate mapping, with source-code evidence,
 * is documented in report/query_generation_notes.md. Pass key: "path_traversal".
 */

private import python
private import semmle.python.dataflow.new.DataFlow

module MySources {

  /** Holds if AST node n is at (moduleName, line); moduleName is the dotted
      Module.getName() value the labels were extracted with. */
  private predicate sourceSite(AstNode n, string moduleName, int line) {
    n.getScope().getEnclosingModule().getName() = moduleName and
    n.getLocation().getStartLine() = line
  }

  private predicate taskVarName(string name) {
    name = "task_vars" or name = "variables"
  }

  /* ------------------------------------------------------------------
   * S1 - lookup `terms` boundary (labels: p1-src-054, p1-src-074, p1-src-075, p1-src-076, p1-src-077, p1-src-087, p1-src-128, p1-src-129, p1-src-137, p1-src-147)
   * The `terms` parameter (position 1, self = 0) of LookupModule.run in the
   * path-consuming lookup plugins. Trust chain: terms are playbook-templated
   * values whose template variables include remote ansible_facts
   * (executor/task_executor.py:694/:758) and CLI --extra-vars.
   * ------------------------------------------------------------------ */
  private predicate pathLookupModule(string moduleName) {
    moduleName = "ansible.plugins.lookup.csvfile"
    or moduleName = "ansible.plugins.lookup.file"
    or moduleName = "ansible.plugins.lookup.fileglob"
    or moduleName = "ansible.plugins.lookup.filetree"
    or moduleName = "ansible.plugins.lookup.first_found"
    or moduleName = "ansible.plugins.lookup.ini"
    or moduleName = "ansible.plugins.lookup.password"
    or moduleName = "ansible.plugins.lookup.passwordstore"
    or moduleName = "ansible.plugins.lookup.shelvefile"
    or moduleName = "ansible.plugins.lookup.template"
  }

  class LookupTermsParam extends DataFlow::ParameterNode {
    LookupTermsParam() {
      exists(Function run |
        run.getName() = "run" and
        pathLookupModule(run.getScope().getEnclosingModule().getName()) and
        this.getParameter() = run.getArg(1)
      )
    }
  }

  /* ------------------------------------------------------------------
   * S2 - remote module output (label: p1-src-018)
   * json.loads calls that parse module stdout coming off the connection
   * wire; the parsed dict is remote-controlled (feeds fetch.py:100-102
   * slurpres.get('source') and copy.py:355-356 'lnk_source' via the default
   * container/subscript taint steps).
   * ------------------------------------------------------------------ */
  class RemoteResultLoads extends DataFlow::Node {
    RemoteResultLoads() {
      exists(Call c |
        c.getFunc().(Attribute).getName() = "loads" and
        c.getFunc().(Attribute).getObject().(Name).getId() = "json" and
        remoteResultSite(c) and
        this.asExpr() = c
      )
    }
  }

  private predicate remoteResultSite(AstNode c) {
    sourceSite(c, "ansible.executor.interpreter_discovery", 101)
    or sourceSite(c, "ansible.executor.task_executor", 1106)
    or sourceSite(c, "ansible.executor.task_executor", 1109)
    or sourceSite(c, "ansible.plugins.action.__init__", 990)
    or sourceSite(c, "ansible.plugins.connection.network_cli", 362)
    or sourceSite(c, "ansible.plugins.connection.psrp", 508)
    or sourceSite(c, "ansible.plugins.connection.winrm", 494)
    or sourceSite(c, "ansible.plugins.connection.winrm", 624)
  }

  /* ------------------------------------------------------------------
   * S3 - galaxy tar member names (label: p1-src-135)
   * member.name of the downloaded role archive (galaxy/role.py:186-203
   * download, :271 open, filter+extract at :324-:330).
   * ------------------------------------------------------------------ */
  class GalaxyMemberName extends DataFlow::Node {
    GalaxyMemberName() {
      exists(Attribute a |
        a.getName() = "name" and
        a.getObject().(Name).getId() = "member" and
        galaxyMemberSite(a) and
        this.asExpr() = a
      )
    }
  }

  private predicate galaxyMemberSite(AstNode a) {
    sourceSite(a, "ansible.galaxy.role", 278)
    or sourceSite(a, "ansible.galaxy.role", 282)
    or sourceSite(a, "ansible.galaxy.role", 324)
    or sourceSite(a, "ansible.galaxy.role", 329)
  }

  /* ------------------------------------------------------------------
   * S4 - host-variable reads (labels: p1-src-017, p1-src-019, p1-src-042, p1-src-072, p1-src-080, p1-src-088, p1-src-108, p1-src-109, p1-src-112, p1-src-113, p1-src-114, p1-src-115, p1-src-116, p1-src-117, p1-src-119, p1-src-120, p1-src-130, p1-src-142, p1-src-143, p1-src-146, p1-src-148)
   * task_vars[...] / task_vars.get(...) / variables.get(...) reads that the
   * reviewed labels kept as (candidate) remote/host-controlled boundaries.
   * ------------------------------------------------------------------ */
  class TaskVarRead extends DataFlow::Node {
    TaskVarRead() {
      exists(Subscript s, string nm |
        taskVarName(nm) and
        s.getObject().(Name).getId() = nm and
        taskVarSite(s) and
        this.asExpr() = s
      )
      or
      exists(Call g, string nm |
        taskVarName(nm) and
        g.getFunc().(Attribute).getName() = "get" and
        g.getFunc().(Attribute).getObject().(Name).getId() = nm and
        taskVarSite(g) and
        this.asExpr() = g
      )
    }
  }

  private predicate taskVarSite(AstNode n) {
    sourceSite(n, "ansible.executor.interpreter_discovery", 50)
    or sourceSite(n, "ansible.executor.module_common", 575)
    or sourceSite(n, "ansible.executor.module_common", 593)
    or sourceSite(n, "ansible.executor.module_common", 1219)
    or sourceSite(n, "ansible.plugins.action.__init__", 222)
    or sourceSite(n, "ansible.plugins.action.__init__", 728)
    or sourceSite(n, "ansible.plugins.action.__init__", 739)
    or sourceSite(n, "ansible.plugins.action.ce_template", 46)
    or sourceSite(n, "ansible.plugins.action.fetch", 129)
    or sourceSite(n, "ansible.plugins.action.gather_facts", 68)
    or sourceSite(n, "ansible.plugins.action.net_base", 56)
    or sourceSite(n, "ansible.plugins.action.net_base", 58)
    or sourceSite(n, "ansible.plugins.action.net_get", 171)
    or sourceSite(n, "ansible.plugins.action.net_get", 173)
    or sourceSite(n, "ansible.plugins.action.net_put", 214)
    or sourceSite(n, "ansible.plugins.action.net_put", 216)
    or sourceSite(n, "ansible.plugins.action.network", 74)
    or sourceSite(n, "ansible.plugins.action.network", 173)
    or sourceSite(n, "ansible.plugins.action.network", 175)
    or sourceSite(n, "ansible.plugins.action.synchronize", 118)
    or sourceSite(n, "ansible.plugins.action.synchronize", 121)
    or sourceSite(n, "ansible.plugins.action.synchronize", 125)
    or sourceSite(n, "ansible.plugins.action.synchronize", 126)
    or sourceSite(n, "ansible.plugins.action.synchronize", 129)
    or sourceSite(n, "ansible.plugins.action.synchronize", 132)
    or sourceSite(n, "ansible.plugins.action.synchronize", 207)
    or sourceSite(n, "ansible.plugins.action.synchronize", 208)
    or sourceSite(n, "ansible.plugins.action.synchronize", 216)
    or sourceSite(n, "ansible.plugins.action.synchronize", 217)
    or sourceSite(n, "ansible.plugins.action.synchronize", 230)
    or sourceSite(n, "ansible.plugins.action.synchronize", 249)
    or sourceSite(n, "ansible.plugins.action.synchronize", 278)
    or sourceSite(n, "ansible.plugins.action.synchronize", 292)
    or sourceSite(n, "ansible.plugins.action.synchronize", 326)
    or sourceSite(n, "ansible.plugins.action.synchronize", 328)
    or sourceSite(n, "ansible.plugins.action.synchronize", 333)
    or sourceSite(n, "ansible.plugins.action.template", 119)
    or sourceSite(n, "ansible.plugins.action.wait_for_connection", 84)
    or sourceSite(n, "ansible.plugins.lookup.passwordstore", 263)
    or sourceSite(n, "ansible.plugins.lookup.template", 83)
  }

  /* ------------------------------------------------------------------
   * S5 - fetch dest name fallback (label: p1-src-073)
   * self._play_context.remote_addr at fetch.py:131 - the fallback
   * target_name component of the fetch dest path built at fetch.py:132.
   * ------------------------------------------------------------------ */
  class FetchRemoteAddr extends DataFlow::Node {
    FetchRemoteAddr() {
      exists(Attribute a |
        a.getName() = "remote_addr" and
        a.getObject().(Attribute).getName() = "_play_context" and
        a.getObject().(Attribute).getObject().(Name).getId() = "self" and
        fetchAddrSite(a) and
        this.asExpr() = a
      )
    }
  }

  private predicate fetchAddrSite(AstNode a) {
    sourceSite(a, "ansible.plugins.action.fetch", 131)

  }

  /** Pass-1 source predicate. passKey must be "path_traversal". */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and
    (
      source instanceof LookupTermsParam
      or source instanceof RemoteResultLoads
      or source instanceof GalaxyMemberName
      or source instanceof TaskVarRead
      or source instanceof FetchRemoteAddr
    )
  }
}
