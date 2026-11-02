/**
 * Machine-generated from reviewed Phase 1 labels (iris/labels/labels.json, pass 1).
 * Run: streamlit-pathtraversal-pass1-20261023. Do not edit by hand.
 *
 * Sink nodes for pass key "path_traversal" (Path Traversal, CWE-22/23/36/73).
 *
 * Each predicate is a deduplicated signature covering the labeled entries with that
 * signature; matching is restricted to the Phase 1 extraction scope (lib/streamlit/).
 * Only actual filesystem operations are sinks: the dangerous position is always the
 * path *text* argument (argument 0 for open/remove/makedirs/stat/rmtree/render and
 * tokenize.open/bind_unix_socket), the receiver for Path.glob directory enumeration,
 * or any argument of tempfile.mkdtemp. Path-construction calls (os.path.join,
 * Path(...), string concatenation) are never sinks; they are propagation nodes
 * modeled in MySummaries.qll.
 *
 * Mapping (deduplicated signature -> labels -> predicate):
 *   builtins.open, argument 0            -> sink-009 (tp), sink-010/011/013/014/015/
 *     016/017/018/019/020/021/023/024/025 (fp/candidate) -> builtinOpenPathSink
 *   tokenize.open, argument 0            -> sink-022 (fp)                 -> tokenizeOpenSink
 *   os.remove, argument 0                -> sink-002/003/004/005          -> osRemoveSink
 *   os.makedirs, argument 0              -> sink-026/027                  -> osMakedirsSink
 *   os.stat, argument 0                  -> sink-028/029                  -> osStatSink
 *   shutil.rmtree, argument 0            -> sink-006/007/008              -> shutilRmtreeSink
 *   tornado.netutil.bind_unix_socket, argument 0 -> sink-030              -> bindUnixSocketSink
 *   RequestHandler.render, argument 0    -> sink-031                      -> renderSink
 *   pathlib.Path.glob, receiver          -> sink-032/033                  -> globReceiverSink
 *   tempfile.mkdtemp, any argument       -> sink-001 (keyword-controlled) -> mkdtempArgSink
 *
 * Label classification (tp/candidate/fp) is retained in labels.json for Step 6
 * filtering; it does not change the sink predicates, which are signature-based.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /** Holds if `sink` is a pass 1 (path_traversal) sink node. */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and
    sinkNode(sink)
  }

  private predicate sinkNode(DataFlow::Node sink) {
    builtinOpenPathSink(sink)
    or tokenizeOpenSink(sink)
    or osRemoveSink(sink)
    or osMakedirsSink(sink)
    or osStatSink(sink)
    or shutilRmtreeSink(sink)
    or bindUnixSocketSink(sink)
    or renderSink(sink)
    or globReceiverSink(sink)
    or mkdtempArgSink(sink)
  }

  /**
   * builtins `open(...)` argument 0 (the path text). 16 labeled sites in
   * lib/streamlit; the confirmed traversal sink is components.py:325
   * `open(abspath, "rb")` (sink-009, tp). Matching is by plain `open` name only:
   * `Image.open` (elements/image.py:240) and `webbrowser.open` (util.py:90) are
   * Attribute calls and do not match. The only unlabeled `open`-shaped texts in the
   * package are docstring examples and the `def open` method definition in
   * server.py:752, none of which are Call nodes (verified by grep).
   */
  private predicate builtinOpenPathSink(DataFlow::Node sink) {
    exists(Call call |
      call.getFunc().(Name).getId() = "open" and
      inLibStreamlit(call) and
      sink = DataFlow::exprNode(call.getArg(0))
    )
  }

  /**
   * `tokenize.open(filename)` argument 0 — PEP263-aware source file read inside
   * source_util.open_python_file (source_util.py:41, sink-022, fp: operator-local
   * script paths).
   */
  private predicate tokenizeOpenSink(DataFlow::Node sink) {
    exists(Call call, Attribute func, Name receiver |
      func = call.getFunc().(Attribute) and
      func.getName() = "open" and
      receiver = func.getValue().(Name) and
      receiver.getId() = "tokenize" and
      inLibStreamlit(call) and
      sink = DataFlow::exprNode(call.getArg(0))
    )
  }

  /** `os.remove(path)` argument 0 — file delete (sink-002..005). */
  private predicate osRemoveSink(DataFlow::Node sink) {
    exists(Call call, Attribute func, Name receiver |
      func = call.getFunc().(Attribute) and
      func.getName() = "remove" and
      receiver = func.getValue().(Name) and
      receiver.getId() = "os" and
      inLibStreamlit(call) and
      sink = DataFlow::exprNode(call.getArg(0))
    )
  }

  /** `os.makedirs(path)` argument 0 — directory create (sink-026/027). */
  private predicate osMakedirsSink(DataFlow::Node sink) {
    exists(Call call, Attribute func, Name receiver |
      func = call.getFunc().(Attribute) and
      func.getName() = "makedirs" and
      receiver = func.getValue().(Name) and
      receiver.getId() = "os" and
      inLibStreamlit(call) and
      sink = DataFlow::exprNode(call.getArg(0))
    )
  }

  /** `os.stat(path)` argument 0 — file metadata read (sink-028/029). */
  private predicate osStatSink(DataFlow::Node sink) {
    exists(Call call, Attribute func, Name receiver |
      func = call.getFunc().(Attribute) and
      func.getName() = "stat" and
      receiver = func.getValue().(Name) and
      receiver.getId() = "os" and
      inLibStreamlit(call) and
      sink = DataFlow::exprNode(call.getArg(0))
    )
  }

  /** `shutil.rmtree(path)` argument 0 — directory tree delete (sink-006..008). */
  private predicate shutilRmtreeSink(DataFlow::Node sink) {
    exists(Call call, Attribute func, Name receiver |
      func = call.getFunc().(Attribute) and
      func.getName() = "rmtree" and
      receiver = func.getValue().(Name) and
      receiver.getId() = "shutil" and
      inLibStreamlit(call) and
      sink = DataFlow::exprNode(call.getArg(0))
    )
  }

  /**
   * `tornado.netutil.bind_unix_socket(file_name)` argument 0 — unix socket file
   * creation at the config-derived server.address path (server.py:191, sink-030,
   * fp: operator-local configuration).
   */
  private predicate bindUnixSocketSink(DataFlow::Node sink) {
    exists(Call call, Attribute func, Attribute qual, Name root |
      func = call.getFunc().(Attribute) and
      func.getName() = "bind_unix_socket" and
      qual = func.getValue().(Attribute) and
      qual.getName() = "netutil" and
      root = qual.getValue().(Name) and
      root.getId() = "tornado" and
      inLibStreamlit(call) and
      sink = DataFlow::exprNode(call.getArg(0))
    )
  }

  /**
   * `self.render(index_file)` argument 0 — tornado RequestHandler.render loads and
   * renders a template file from disk. The single call site in lib/streamlit is
   * routes.py:90 with the fixed index.html path (sink-031, fp). Receiver module is
   * inferred (dynamic dispatch; see exploration/detection.json).
   */
  private predicate renderSink(DataFlow::Node sink) {
    exists(Call call, Attribute func |
      func = call.getFunc().(Attribute) and
      func.getName() = "render" and
      inLibStreamlit(call) and
      sink = DataFlow::exprNode(call.getArg(0))
    )
  }

  /**
   * `pathlib.Path.glob(pattern)` receiver — directory enumeration; the enumerated
   * directory is carried by the receiver, not an argument (sink-032/033: source_util
   * .py:161 pages_dir, watcher/util.py:105 watched dirs; both operator-local, fp).
   */
  private predicate globReceiverSink(DataFlow::Node sink) {
    exists(Call call, Attribute func |
      func = call.getFunc().(Attribute) and
      func.getName() = "glob" and
      inLibStreamlit(call) and
      sink = DataFlow::exprNode(func.getValue())
    )
  }

  /**
   * `tempfile.mkdtemp(...)` any positional argument (sink-001). The labeled
   * path-influencing positions are the keyword arguments dir/prefix/suffix
   * (arg_index -1, keyword-controlled, hence no positional index in the label);
   * only positional arguments are modeled here. The single call site
   * (temporary_directory.py:49, `tempfile.mkdtemp(*self._args, **self._kwargs)`)
   * passes no positional (non-starred) arguments, so this predicate is currently
   * vacuous; retained for signature completeness.
   */
  private predicate mkdtempArgSink(DataFlow::Node sink) {
    exists(Call call, Attribute func, Name receiver, Expr arg |
      func = call.getFunc().(Attribute) and
      func.getName() = "mkdtemp" and
      receiver = func.getValue().(Name) and
      receiver.getId() = "tempfile" and
      inLibStreamlit(call) and
      arg = call.getAnArg() and
      sink = DataFlow::exprNode(arg)
    )
  }

  /**
   * Holds if `n` is located in the lib/streamlit package — the Phase 1 extraction
   * scope (excludes lib/tests, e2e, scripts, and the nested streamlit-db directory).
   */
  private predicate inLibStreamlit(AstNode n) {
    exists(File f, string abs |
      f = n.getLocation().getFile() and
      abs = f.getAbsolutePath().replaceAll("\\\\", "/") and
      abs.matches("%.*/lib/streamlit/%")
    )
  }
}
