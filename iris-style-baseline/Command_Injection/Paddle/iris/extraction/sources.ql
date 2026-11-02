/**
 * @name Paddle source candidate extraction (Pass 2, CWE-78)
 * @description
 *   Extracts external-input candidate APIs for CWE-78 (OS command injection)
 *   labeling from the PaddlePaddle Python package (python/paddle):
 *   the argparse CLI surface of the distributed launch / fleet / elastic
 *   tooling, raw sys.argv passthrough, environment-variable reads
 *   (including the paddle backup_env wrapper), JSON decoding of
 *   config/message data, socket peer-data reads, etcd cluster-state
 *   reads, httpx download entry points, and builtin open() file input.
 *   Matching is syntactic (AST shape only); whether a site is a real,
 *   import-resolved API and whether the data is attacker-controlled is
 *   decided later by LLM labeling.
 *   Columns: node, kind, callable, flow_kind, receiver, moduleHint,
 *   arg_index, file, line.
 *   NOTE: this is a raw BQRS extraction query meant for
 *   `codeql query run` + `codeql bqrs decode`. It deliberately carries
 *   no @kind annotation: @kind problem is wrong for a multi-column
 *   select and no @kind table exists for this purpose.
 * @id py/augur/paddle/extract-sources
 */

import python

/* ------------------------------------------------------------------ */
/* Scope                                                               */
/* ------------------------------------------------------------------ */

/**
 * Restrict extraction to the shipped PaddlePaddle Python package.
 * tools/ (CI/build scripts), test/, python/unittest_py/ and
 * launch/plugins/test.py are out of scope; see
 * exploration/detection.json for the documented exclusion rationale.
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("python/paddle/%") and
    not path.matches("%/test.py") and
    not path.matches("%/tests/%") and
    not path.matches("%/test_%.py")
  )
}

/* ------------------------------------------------------------------ */
/* Candidate rows                                                      */
/* ------------------------------------------------------------------ */

/**
 * Holds if `n` is a source candidate with the given metadata.
 *
 * `callable`:     best-effort qualified callable name of the input API.
 * `flowKind`:     "field" (CLI option / module field read),
 *                 "return" (value returned by the input API).
 * `receiver`:     receiver expression or container hint, "" if none.
 * `moduleHint`:   module/package family the candidate belongs to.
 * `argIndex`:     relevant argument index, -1 when not applicable.
 *
 * All families below are syntactic matches. Import resolution and
 * attacker-control assessment are deferred to the labeling step.
 */
predicate sourceCandidate(
  AstNode n, string callable, string flowKind, string receiver,
  string moduleHint, int argIndex
) {
  /* 1. argparse argument declarations: the CLI input surface of
   *    `python -m paddle.distributed.launch`, `fleet launch` and the
   *    elastic command (launch/context/args_envs.py, elastic.py,
   *    fleet/launch_utils.py, ipu_controller.py). */
  exists(Call c, Attribute attr |
    n = c and
    attr = c.getFunc() and
    attr.getName() = "add_argument" and
    callable = "argparse.add_argument" and
    flowKind = "field" and
    receiver = attr.getObject().toString() and
    moduleHint = "argparse" and
    argIndex = 0
  )
  or
  /* 2. argparse result parsing: the parsed namespace carries all CLI
   *    values (including training_script_args REMAINDER). */
  exists(Call c, Attribute attr |
    n = c and
    attr = c.getFunc() and
    attr.getName() in ["parse_args", "parse_known_args"] and
    callable = "argparse." + attr.getName() and
    flowKind = "return" and
    receiver = attr.getObject().toString() and
    moduleHint = "argparse" and
    argIndex = -1
  )
  or
  /* 3. raw sys.argv references (e.g. launch/controllers/master.py
   *    extends the launched command with sys.argv[1:]). */
  exists(Attribute attr, Name sysName |
    n = attr and
    attr.getName() = "argv" and
    sysName = attr.getObject() and
    sysName.getId() = "sys" and
    callable = "sys.argv" and
    flowKind = "field" and
    receiver = "sys" and
    moduleHint = "sys" and
    argIndex = -1
  )
  or
  /* 4. os.getenv(...) environment reads. */
  exists(Call c, Attribute attr, Name recv |
    n = c and
    attr = c.getFunc() and
    attr.getName() = "getenv" and
    recv = attr.getObject() and
    recv.getId() = "os" and
    callable = "os.getenv" and
    flowKind = "return" and
    receiver = "os" and
    moduleHint = "os" and
    argIndex = -1
  )
  or
  /* 5. os.environ.get(...) environment reads. */
  exists(Call c, Attribute method, Attribute environ, Name osName |
    n = c and
    method = c.getFunc() and
    method.getName() = "get" and
    environ = method.getObject() and
    environ.getName() = "environ" and
    osName = environ.getObject() and
    osName.getId() = "os" and
    callable = "os.environ.get" and
    flowKind = "return" and
    receiver = "os.environ" and
    moduleHint = "os" and
    argIndex = -1
  )
  or
  /* 6. os.environ[...] environment reads. */
  exists(Subscript s, Attribute environ, Name osName |
    n = s and
    environ = s.getObject() and
    environ.getName() = "environ" and
    osName = environ.getObject() and
    osName.getId() = "os" and
    callable = "os.environ.__getitem__" and
    flowKind = "return" and
    receiver = "os.environ" and
    moduleHint = "os" and
    argIndex = -1
  )
  or
  /* 7. paddle.distributed.backup_env.getenv_or_backup(...) env wrapper
   *    used by role makers / parallel / executor / elastic manager. */
  exists(Call c, Name fn |
    n = c and
    fn = c.getFunc() and
    fn.getId() = "getenv_or_backup" and
    callable = "paddle.distributed.backup_env.getenv_or_backup" and
    flowKind = "return" and
    receiver = "" and
    moduleHint = "paddle.distributed.backup_env" and
    argIndex = -1
  )
  or
  /* 8. json.loads / json.load decoding of config and message data
   *    (auto_tuner strategies, launch controller configs, fleet
   *    index/feature files, ...). */
  exists(Call c, Attribute attr, Name recv |
    n = c and
    attr = c.getFunc() and
    attr.getName() in ["loads", "load"] and
    recv = attr.getObject() and
    recv.getId() = "json" and
    callable = "json." + attr.getName() and
    flowKind = "return" and
    receiver = "json" and
    moduleHint = "json" and
    argIndex = -1
  )
  or
  /* 9. socket peer-data reads: .recv(...) / .recvfrom(...) calls.
   *    This also syntactically matches paddle.distributed.recv-style
   *    tensor communication (receiver string distinguishes them);
   *    those rows are expected to be labeled "none" and are kept for
   *    recall rather than pre-filtered. */
  exists(Call c, Attribute attr |
    n = c and
    attr = c.getFunc() and
    attr.getName() in ["recv", "recvfrom"] and
    callable = "socket." + attr.getName() and
    flowKind = "return" and
    receiver = attr.getObject().toString() and
    moduleHint = "socket" and
    argIndex = -1
  )
  or
  /* 10. etcd cluster-state reads (fleet/elastic/manager.py:
   *     self.etcd.get_prefix(...) over node/endpoint prefixes). */
  exists(Call c, Attribute attr |
    n = c and
    attr = c.getFunc() and
    attr.getName() = "get_prefix" and
    callable = "etcd.get_prefix" and
    flowKind = "return" and
    receiver = attr.getObject().toString() and
    moduleHint = "etcd" and
    argIndex = -1
  )
  or
  /* 11. builtin open(...) file input. */
  exists(Call c, Name fn |
    n = c and
    fn = c.getFunc() and
    fn.getId() = "open" and
    callable = "open" and
    flowKind = "return" and
    receiver = "" and
    moduleHint = "builtins" and
    argIndex = -1
  )
  or
  /* 12. httpx download entry points (utils/download.py:
   *     httpx.stream(...) and response .iter_bytes(...)). */
  exists(Call c, Attribute attr, Name recv |
    n = c and
    attr = c.getFunc() and
    attr.getName() = "stream" and
    recv = attr.getObject() and
    recv.getId() = "httpx" and
    callable = "httpx.stream" and
    flowKind = "return" and
    receiver = "httpx" and
    moduleHint = "httpx" and
    argIndex = -1
  )
  or
  exists(Call c, Attribute attr |
    n = c and
    attr = c.getFunc() and
    attr.getName() = "iter_bytes" and
    callable = "httpx.Response.iter_bytes" and
    flowKind = "return" and
    receiver = attr.getObject().toString() and
    moduleHint = "httpx" and
    argIndex = -1
  )
}

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

from
  AstNode node,
  string callable,
  string flowKind,
  string receiver,
  string moduleHint,
  int argIndex
where
  inAnalysisScope(node) and
  sourceCandidate(node, callable, flowKind, receiver, moduleHint, argIndex)
select
  node,
  "source_candidate",
  callable,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getRelativePath(),
  node.getLocation().getStartLine()
