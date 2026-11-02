/**
 * @name rtx-cwe89-extract-sinks
 * @description Extract SQL execution sink candidates (DB-API execute family plus SQLAlchemy
 *              text()/engine.execute) from the RTX/ARAX Python codebase for CWE-089
 *              (Pass 5, SQL Injection) taint labeling. Pure multi-column candidate table for
 *              `codeql query run` + `codeql bqrs decode --format=csv`. Not a @kind problem
 *              query; not meant for `codeql database analyze`/SARIF.
 *
 *              Modeling target (per Pass 5 scope): the SQL query text (or SQL-syntax-affecting
 *              fragment) passed as argument 0 of database execute calls:
 *                - sqlite3 cursor.execute / cursor.executemany / cursor.executescript
 *                - sqlite3 connection.execute / connection.executemany / connection.executescript
 *                - SQLAlchemy engine.execute (create_engine chain)
 *                - SQLAlchemy session.execute / any AST `.execute(...)` attribute call
 *                  (module hint resolved via API graphs where possible, else import hints)
 *                - SQLAlchemy text(...) recorded as an intermediate SQL-fragment construction
 *                  node (must be traced to a real execute call during labeling)
 *
 *              Binding-parameter notes for labeling: calls whose arg-0 snippet is a plain
 *              literal and whose values are passed as a separate sequence (e.g. `execute(sql, (v,))`)
 *              are bound-parameter style and are candidate sanitizers, not dangerous sinks;
 *              the arg-0 snippet column makes f-string / %-format / concatenated SQL visible.
 *
 * @id py/rtx-cwe89/extract-sinks
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow

/* ------------------------------------------------------------------ */
/* Shared path filters                                                 */
/* rtx-db lives inside the source root and must never be reported;     */
/* test suites and fixtures are excluded from candidate extraction.    */
/* ------------------------------------------------------------------ */

predicate candidateFile(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    not path.matches("%rtx-db%") and
    not path.matches("%/test/%") and
    not path.matches("%\\test\\%") and
    not path.matches("%test_%.py%")
  )
}

/* ------------------------------------------------------------------ */
/* Resolved API-graph models (semmle.python.ApiGraphs)                  */
/* API::CallNode extends DataFlow::CallCfgNode, so call arguments and   */
/* locations are available directly; AST joins use the CFG node.        */
/* ------------------------------------------------------------------ */

/* sqlite3.connect(...).execute/executemany/executescript(...) */
predicate isSqlite3ConnExecuteApi(API::CallNode cn) {
  cn = API::moduleImport("sqlite3").getMember("connect").getACall().getReturn().getMember("execute").getACall()
  or cn = API::moduleImport("sqlite3").getMember("connect").getACall().getReturn().getMember("executemany").getACall()
  or cn = API::moduleImport("sqlite3").getMember("connect").getACall().getReturn().getMember("executescript").getACall()
}

/* sqlite3.connect(...).cursor().execute/executemany/executescript(...) */
predicate isSqlite3CursorExecuteApi(API::CallNode cn) {
  cn = API::moduleImport("sqlite3").getMember("connect").getACall().getReturn().getMember("cursor").getACall().getReturn().getMember("execute").getACall()
  or cn = API::moduleImport("sqlite3").getMember("connect").getACall().getReturn().getMember("cursor").getACall().getReturn().getMember("executemany").getACall()
  or cn = API::moduleImport("sqlite3").getMember("connect").getACall().getReturn().getMember("cursor").getACall().getReturn().getMember("executescript").getACall()
}

/* sqlalchemy.create_engine(...).execute(...) */
predicate isSqlalchemyEngineExecuteApi(API::CallNode cn) {
  cn = API::moduleImport("sqlalchemy").getMember("create_engine").getACall().getReturn().getMember("execute").getACall()
}

/* Join an AST call site to a resolved API call node via the CFG node. */
predicate resolvedExecuteModule(Call c, string moduleHint) {
  exists(API::CallNode cn |
    cn.getNode() = c.getAFlowNode() and
    (
      (
        (isSqlite3ConnExecuteApi(cn) or isSqlite3CursorExecuteApi(cn)) and
        moduleHint = "sqlite3"
      )
      or
      (isSqlalchemyEngineExecuteApi(cn) and moduleHint = "sqlalchemy")
    )
  )
}

/* ------------------------------------------------------------------ */
/* File-level import hints (fallback when the API graph cannot resolve  */
/* the receiver, e.g. receivers stored in self.<attr> or module globals)*/
/* ------------------------------------------------------------------ */

predicate fileImportsModule(AstNode n, string mod) {
  exists(Import imp |
    imp.getLocation().getFile() = n.getLocation().getFile() and
    imp.getAnImportedModuleName() = mod
  )
}

/* ------------------------------------------------------------------ */
/* AST name-match families                                              */
/* ------------------------------------------------------------------ */

/* Any receiver.execute(...)/executemany(...)/executescript(...) call.   */
/* Covers sqlite3 cursors/connections held in locals, globals, self      */
/* attributes and cross-module aliases; resolution quality is reported   */
/* through the moduleHint column (resolved / import-hint / unresolved).  */
class SqlExecuteAstCall extends Call {
  SqlExecuteAstCall() {
    exists(Attribute f |
      f = this.getFunc() and
      (
        f.getName() = "execute" or
        f.getName() = "executemany" or
        f.getName() = "executescript"
      )
    )
  }
}

/* sqlalchemy text(...) construction: text("...") with sqlalchemy imported,
   or sqlalchemy.text("..."). */
class SqlalchemyTextAstCall extends Call {
  SqlalchemyTextAstCall() {
    (
      this.getFunc().(Name).getId() = "text" and
      fileImportsModule(this, "sqlalchemy")
    )
    or
    exists(Attribute f |
      f = this.getFunc() and
      f.getName() = "text" and
      f.getObject().(Name).getId() = "sqlalchemy"
    )
  }
}

/* ------------------------------------------------------------------ */
/* Candidate binding                                                    */
/* ------------------------------------------------------------------ */

predicate sinkCandidate(
  Call c, string role, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string snippet
) {
  /* execute family: SQL query text is positional argument 0 */
  exists(SqlExecuteAstCall e |
    e = c and
    role = "sink" and
    callableName = e.getFunc().(Attribute).getName() and
    flowKind = "arg" and
    receiver = e.getFunc().(Attribute).getObject().toString() and
    argIndex = 0 and
    (
      exists(Expr sqlarg | sqlarg = e.getArg(0) and snippet = sqlarg.toString())
      or
      (not exists(Expr sqlarg | sqlarg = e.getArg(0)) and snippet = e.toString())
    ) and
    (
      (resolvedExecuteModule(e, "sqlite3") and moduleHint = "sqlite3")
      or
      (not resolvedExecuteModule(e, "sqlite3") and
       resolvedExecuteModule(e, "sqlalchemy") and
       moduleHint = "sqlalchemy")
      or
      (not resolvedExecuteModule(e, "sqlite3") and
       not resolvedExecuteModule(e, "sqlalchemy") and
       fileImportsModule(e, "sqlite3") and
       moduleHint = "sqlite3(import-hint)")
      or
      (not resolvedExecuteModule(e, "sqlite3") and
       not resolvedExecuteModule(e, "sqlalchemy") and
       not fileImportsModule(e, "sqlite3") and
       fileImportsModule(e, "sqlalchemy") and
       moduleHint = "sqlalchemy(import-hint)")
      or
      (not resolvedExecuteModule(e, "sqlite3") and
       not resolvedExecuteModule(e, "sqlalchemy") and
       not fileImportsModule(e, "sqlite3") and
       not fileImportsModule(e, "sqlalchemy") and
       moduleHint = "unresolved")
    )
  )
  or
  /* sqlalchemy text(...) SQL fragment construction (intermediate node) */
  exists(SqlalchemyTextAstCall t |
    t = c and
    role = "intermediate" and
    callableName = "text" and
    flowKind = "arg" and
    receiver = "sqlalchemy" and
    moduleHint = "sqlalchemy" and
    argIndex = 0 and
    (
      exists(Expr sqlfrag | sqlfrag = t.getArg(0) and snippet = sqlfrag.toString())
      or
      (not exists(Expr sqlfrag | sqlfrag = t.getArg(0)) and snippet = t.toString())
    )
  )
}

/* ------------------------------------------------------------------ */
/* Extraction select                                                    */
/* ------------------------------------------------------------------ */

from Call c, string roleVal, string callableName, string flowKind, string receiverVal,
     string moduleHintVal, int argIndex, string snippetVal
where
  sinkCandidate(c, roleVal, callableName, flowKind, receiverVal, moduleHintVal, argIndex, snippetVal) and
  candidateFile(c)
select
  c.toString() as node,
  roleVal as role,
  callableName as callable,
  flowKind as flow_kind,
  receiverVal as receiver,
  moduleHintVal as moduleHint,
  argIndex as arg_index,
  c.getLocation().getFile().getRelativePath() as file,
  c.getLocation().getStartLine() as line,
  snippetVal as snippet
