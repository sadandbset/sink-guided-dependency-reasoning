
/**
 * @name Bikeshed source candidates (Phase 1, Pass 2, CWE-78)
 * @description Syntactic extraction of external-input and project-specific input-boundary candidates for manual LLM labeling. These are candidates, not confirmed attacker-controlled sources.
 * @kind problem
 * @id py/bikeshed/extraction/sources
 * @problem.severity recommendation
 */

import python

/** Exclude test files. */
predicate inProductionCode(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    not path.matches("tests/%") and
    not path.matches("%/tests/%") and
    not path.matches("test/%") and
    not path.matches("%/test/%")
  )
}

from
  AstNode node,
  string callableName,
  string flowKind,
  string receiverHint,
  string moduleHint,
  int argIndex
where
  inProductionCode(node) and
  (
    // 1. argparse CLI argument declarations
    exists(Call c, Attribute attr |
      node = c and
      attr = c.getFunc() and
      attr.getName() = "add_argument" and
      callableName = "add_argument" and
      flowKind = "field" and
      receiverHint = attr.getObject().toString() and
      moduleHint = "argparse" and
      argIndex = 0
    )
    or
    // 2. argparse argument parsing
    exists(Call c, Attribute attr |
      node = c and
      attr = c.getFunc() and
      attr.getName() = "parse_args" and
      callableName = "parse_args" and
      flowKind = "return" and
      receiverHint = attr.getObject().toString() and
      moduleHint = "argparse" and
      argIndex = -1
    )
    or
    // 3. sys.stdin.read/readline/readlines
    exists(Call c, Attribute method, Attribute stdin, Name sysName |
      node = c and
      method = c.getFunc() and
      method.getName() in ["read", "readline", "readlines"] and
      stdin = method.getObject() and
      stdin.getName() = "stdin" and
      sysName = stdin.getObject() and
      sysName.getId() = "sys" and
      callableName = method.getName() and
      flowKind = "return" and
      receiverHint = "sys.stdin" and
      moduleHint = "sys" and
      argIndex = -1
    )
    or
    // 4. Builtin open() - returns a file handle
    exists(Call c, Name func |
      node = c and
      func = c.getFunc() and
      func.getId() = "open" and
      callableName = "open" and
      flowKind = "return" and
      receiverHint = "" and
      moduleHint = "builtins" and
      argIndex = -1
    )
    or
    // 5. requests.get/post
    exists(Call c, Attribute method, Name receiver |
      node = c and
      method = c.getFunc() and
      method.getName() in ["get", "post"] and
      receiver = method.getObject() and
      receiver.getId() = "requests" and
      callableName = method.getName() and
      flowKind = "return" and
      receiverHint = "requests" and
      moduleHint = "requests" and
      argIndex = -1
    )
    or
    // 6. os.getenv
    exists(Call c, Attribute method, Name receiver |
      node = c and
      method = c.getFunc() and
      method.getName() = "getenv" and
      receiver = method.getObject() and
      receiver.getId() = "os" and
      callableName = "getenv" and
      flowKind = "return" and
      receiverHint = "os" and
      moduleHint = "os" and
      argIndex = -1
    )
    or
    // 7. os.environ.get
    exists(Call c, Attribute method, Attribute environ, Name osName |
      node = c and
      method = c.getFunc() and
      method.getName() = "get" and
      environ = method.getObject() and
      environ.getName() = "environ" and
      osName = environ.getObject() and
      osName.getId() = "os" and
      callableName = "get" and
      flowKind = "return" and
      receiverHint = "os.environ" and
      moduleHint = "os" and
      argIndex = -1
    )
    or
    // 8. os.environ[...]
    exists(Subscript s, Attribute environ, Name osName |
      node = s and
      environ = s.getObject() and
      environ.getName() = "environ" and
      osName = environ.getObject() and
      osName.getId() = "os" and
      callableName = "__getitem__" and
      flowKind = "return" and
      receiverHint = "os.environ" and
      moduleHint = "os" and
      argIndex = -1
    )
    or
    // 9. Bikeshed InputSource methods
    exists(Function f, Class cls |
      node = f and
      f.getLocation().getFile().getBaseName() = "InputSource.py" and
      cls = f.getScope() and
      (
        f.getName() = "read" and
        cls.getName() in
          ["StdinInputSource", "FileInputSource", "UrlInputSource"]
        or
        f.getName() = "_fetch" and
        cls.getName() = "UrlInputSource"
      ) and
      callableName = f.getName() and
      flowKind = "return" and
      receiverHint = cls.getName() and
      moduleHint = "InputSource" and
      argIndex = -1
    )
    or
    // 10. Bikeshed metadata parsing functions
    exists(Function f |
      node = f and
      f.getLocation().getFile().getBaseName() = "metadata.py" and
      f.getName() in ["parse", "fromCommandLine", "fromJson"] and
      callableName = f.getName() and
      flowKind = "param" and
      receiverHint = f.getScope().toString() and
      moduleHint = "metadata" and
      argIndex = 0
    )
    or
    // 11. Bikeshed DataFileRequester.fetch
    exists(Function f, Class cls |
      node = f and
      f.getLocation().getFile().getBaseName() = "retrieve.py" and
      f.getName() = "fetch" and
      cls = f.getScope() and
      cls.getName() = "DataFileRequester" and
      callableName = "fetch" and
      flowKind = "return" and
      receiverHint = cls.getName() and
      moduleHint = "retrieve" and
      argIndex = -1
    )
  )
select
  node,
  "source_candidate",
  callableName,
  flowKind,
  receiverHint,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getRelativePath(),
  node.getLocation().getStartLine()