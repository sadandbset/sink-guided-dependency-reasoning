/**
 * @name rtx-cwe89-extract-sources
 * @description Extract external input boundary and data-access propagation source candidates
 *              from the RTX/ARAX Python codebase for CWE-089 (Pass 5, SQL Injection) taint
 *              labeling. Pure multi-column candidate table for `codeql query run` +
 *              `codeql bqrs decode --format=csv`. Not a @kind problem query; not meant for
 *              `codeql database analyze`/SARIF.
 *
 *              Families (grounded in observed repo evidence, see exploration/detection.json):
 *                1. request.get_json()/get_data()          -> connexion/flask HTTP JSON body
 *                2. request.args/form/headers/... reads     -> connexion/flask HTTP fields
 *                3. get_argument()/get_query_argument()/... -> tornado HTTP query params
 *                4. parameters of functions in .../controllers/ directories -> connexion OpenAPI handlers
 *                5. parameters of tornado RequestHandler get/post/... methods
 *                6. sys.argv / os.environ / os.getenv() / argparse parse_args() -> CLI/env
 *                7. parameters of curated data-access boundary functions -> intermediate
 *                   propagation nodes (values flow on towards SQL execution)
 *
 * @id py/rtx-cwe89/extract-sources
 */

import python

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
/* Family 1: HTTP request JSON body (connexion / flask)                */
/* matches: connexion.request.get_json(), request.get_json(), etc.     */
/* ------------------------------------------------------------------ */

class RequestJsonCall extends Call {
  RequestJsonCall() {
    exists(Attribute f, Expr obj |
      f = this.getFunc() and
      (f.getName() = "get_json" or f.getName() = "get_data") and
      obj = f.getObject() and
      (
        obj.(Name).getId() = "request"
        or obj.(Attribute).getName() = "request"
      )
    )
  }
}

/* ------------------------------------------------------------------ */
/* Family 2: HTTP request field reads (connexion / flask)              */
/* matches: request.args, request.form, connexion.request.headers, ... */
/* ------------------------------------------------------------------ */

class RequestAttrRead extends Attribute {
  RequestAttrRead() {
    (
      this.getName() = "args" or
      this.getName() = "form" or
      this.getName() = "headers" or
      this.getName() = "values" or
      this.getName() = "cookies" or
      this.getName() = "data" or
      this.getName() = "json"
    ) and
    (
      this.getObject().(Name).getId() = "request"
      or this.getObject().(Attribute).getName() = "request"
    )
  }
}

/* ------------------------------------------------------------------ */
/* Family 3: tornado HTTP query parameter access                        */
/* matches: self.get_argument("word"), get_query_argument(...), ...    */
/* ------------------------------------------------------------------ */

class TornadoGetArgumentCall extends Call {
  TornadoGetArgumentCall() {
    exists(Attribute f |
      f = this.getFunc() and
      (
        f.getName() = "get_argument" or
        f.getName() = "get_arguments" or
        f.getName() = "get_query_argument" or
        f.getName() = "get_query_arguments" or
        f.getName() = "get_body_argument" or
        f.getName() = "get_body_arguments"
      )
    )
  }
}

/* ------------------------------------------------------------------ */
/* Family 4: connexion OpenAPI controller handler functions             */
/* ------------------------------------------------------------------ */

class ControllerFunction extends Function {
  ControllerFunction() {
    exists(string path |
      path = this.getLocation().getFile().getRelativePath() and
      path.matches("%controllers%")
    )
  }
}

/* ------------------------------------------------------------------ */
/* Family 5: tornado RequestHandler verb methods                        */
/* identified by method name in files importing tornado modules         */
/* ------------------------------------------------------------------ */

predicate fileImportsModule(AstNode n, string mod) {
  exists(Import imp |
    imp.getLocation().getFile() = n.getLocation().getFile() and
    imp.getAnImportedModuleName() = mod
  )
}

predicate isTornadoHandlerMethod(Function f) {
  (
    f.getName() = "get" or
    f.getName() = "post" or
    f.getName() = "put" or
    f.getName() = "delete" or
    f.getName() = "patch" or
    f.getName() = "head" or
    f.getName() = "options" or
    f.getName() = "prepare"
  ) and
  (
    fileImportsModule(f, "tornado.web") or
    fileImportsModule(f, "tornado.ioloop") or
    fileImportsModule(f, "tornado.httpserver")
  )
}

/* ------------------------------------------------------------------ */
/* Family 6: CLI / environment input                                    */
/* ------------------------------------------------------------------ */

class SysArgvRead extends Attribute {
  SysArgvRead() {
    this.getName() = "argv" and
    this.getObject().(Name).getId() = "sys"
  }
}

class OsEnvironRead extends Attribute {
  OsEnvironRead() {
    this.getName() = "environ" and
    this.getObject().(Name).getId() = "os"
  }
}

class OsGetenvCall extends Call {
  OsGetenvCall() {
    exists(Attribute f |
      f = this.getFunc() and
      f.getName() = "getenv" and
      f.getObject().(Name).getId() = "os"
    )
    or this.getFunc().(Name).getId() = "getenv"
  }
}

class ParseArgsCall extends Call {
  ParseArgsCall() {
    exists(Attribute f |
      f = this.getFunc() and
      f.getName() = "parse_args"
    )
  }
}

/* ------------------------------------------------------------------ */
/* Family 7: data-access boundary functions (intermediate nodes)        */
/* internal functions whose parameters carry externally-influenced      */
/* values onward to SQL execution; grounded in observed call paths.     */
/* ------------------------------------------------------------------ */

predicate isDataAccessBoundaryFunction(Function f) {
  exists(string path |
    path = f.getLocation().getFile().getRelativePath() and
    (
      (
        path.matches("%node_synonymizer.py%") and
        f.getName().regexpMatch("get.*")
      )
      or path.matches("%COHDIndex.py%")
      or (path.matches("%rtxcomplete.py%") and f.getName() = "get_nodes_like")
      or (path.matches("%predictor.py%") and f.getName() = "get_feature")
      or (path.matches("%compute_ngd.py%") and f.getName() = "load_curie_to_pmids_data")
      or (
        path.matches("%ARAX_query.py%") and
        (f.getName() = "query_return_message" or f.getName() = "query_return_stream")
      )
    )
  )
}

/* ------------------------------------------------------------------ */
/* Candidate binding                                                    */
/* ------------------------------------------------------------------ */

predicate sourceCandidate(
  AstNode n, string role, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string snippet
) {
  /* 1. HTTP request JSON body */
  exists(RequestJsonCall c |
    c = n and
    role = "source" and
    callableName = c.getFunc().(Attribute).getName() and
    flowKind = "http_json_return" and
    receiver = "request" and
    moduleHint = "connexion|flask" and
    argIndex = -1 and
    snippet = c.toString()
  )
  or
  /* 2. HTTP request field reads */
  exists(RequestAttrRead a |
    a = n and
    role = "source" and
    callableName = a.getName() and
    flowKind = "http_attr_read" and
    receiver = "request" and
    moduleHint = "connexion|flask" and
    argIndex = -1 and
    snippet = a.toString()
  )
  or
  /* 3. tornado HTTP query parameter access */
  exists(TornadoGetArgumentCall c |
    c = n and
    role = "source" and
    callableName = c.getFunc().(Attribute).getName() and
    flowKind = "http_param_return" and
    receiver = "RequestHandler(self)" and
    moduleHint = "tornado.web" and
    argIndex = 0 and
    snippet = c.toString()
  )
  or
  /* 4. connexion OpenAPI controller handler parameters */
  exists(ControllerFunction f, Parameter p, int i, string pn |
    p = n and
    p = f.getArg(i) and
    pn = p.(Name).getId() and
    pn != "self" and
    pn != "cls" and
    role = "source" and
    callableName = "(handler_param)" and
    flowKind = "handler_param" and
    receiver = f.getName() + "()" and
    moduleHint = "connexion-openapi-controller" and
    argIndex = i and
    snippet = "param " + pn + " of " + f.getName() + "()"
  )
  or
  /* 5. tornado handler method parameters (path/query captures) */
  exists(Function f, Parameter p, int i, string pn |
    p = n and
    isTornadoHandlerMethod(f) and
    p = f.getArg(i) and
    pn = p.(Name).getId() and
    pn != "self" and
    pn != "cls" and
    role = "source" and
    callableName = "(handler_param)" and
    flowKind = "handler_path_param" and
    receiver = f.getName() + "()" and
    moduleHint = "tornado-web-handler" and
    argIndex = i and
    snippet = "param " + pn + " of " + f.getName() + "()"
  )
  or
  /* 6a. sys.argv reads */
  exists(SysArgvRead a |
    a = n and
    role = "source" and
    callableName = "sys.argv" and
    flowKind = "cli_arg" and
    receiver = "sys" and
    moduleHint = "sys" and
    argIndex = -1 and
    snippet = a.toString()
  )
  or
  /* 6b. os.environ reads */
  exists(OsEnvironRead a |
    a = n and
    role = "source" and
    callableName = "os.environ" and
    flowKind = "env_value" and
    receiver = "os" and
    moduleHint = "os" and
    argIndex = -1 and
    snippet = a.toString()
  )
  or
  /* 6c. os.getenv() calls */
  exists(OsGetenvCall c |
    c = n and
    role = "source" and
    callableName = "getenv" and
    flowKind = "env_return" and
    receiver = "os" and
    moduleHint = "os" and
    argIndex = 0 and
    snippet = c.toString()
  )
  or
  /* 6d. argparse parse_args() calls */
  exists(ParseArgsCall c |
    c = n and
    role = "source" and
    callableName = "parse_args" and
    flowKind = "cli_arg_return" and
    receiver = "ArgumentParser" and
    moduleHint = "argparse" and
    argIndex = -1 and
    snippet = c.toString()
  )
  or
  /* 7. data-access boundary function parameters (intermediate nodes) */
  exists(Function f, Parameter p, int i, string pn |
    p = n and
    isDataAccessBoundaryFunction(f) and
    p = f.getArg(i) and
    pn = p.(Name).getId() and
    pn != "self" and
    pn != "cls" and
    role = "intermediate" and
    callableName = f.getName() + "()" and
    flowKind = "data_access_param" and
    receiver = f.getName() + "()" and
    moduleHint = "internal" and
    argIndex = i and
    snippet = "param " + pn + " of " + f.getName() + "()"
  )
}

/* ------------------------------------------------------------------ */
/* Extraction select                                                    */
/* ------------------------------------------------------------------ */

from AstNode n, string roleVal, string callableName, string flowKind, string receiverVal,
     string moduleHintVal, int argIndex, string snippetVal
where
  sourceCandidate(n, roleVal, callableName, flowKind, receiverVal, moduleHintVal, argIndex, snippetVal) and
  candidateFile(n)
select
  n.toString() as node,
  roleVal as role,
  callableName as callable,
  flowKind as flow_kind,
  receiverVal as receiver,
  moduleHintVal as moduleHint,
  argIndex as arg_index,
  n.getLocation().getFile().getRelativePath() as file,
  n.getLocation().getStartLine() as line,
  snippetVal as snippet
