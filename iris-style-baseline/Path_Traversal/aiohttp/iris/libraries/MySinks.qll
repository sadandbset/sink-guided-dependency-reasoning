/**
 * Augur Pass 1 (Path Traversal) sink model for aiohttp.
 *
 * Generated deterministically from the reviewed Pass 1 labels in
 * iris/labels/labels.json (entries with role=sink and classification=tp).
 * Only real filesystem access / file-response positions are modeled, and
 * path text is distinguished from already-open file objects:
 *   - receiver-position sinks match the path expression that the file API
 *     operates on (Path.stat / Path.is_dir / Path.is_file / Path.open /
 *     Path.iterdir receivers);
 *   - the sendfile channel matches the file-object argument (arg 1) and is
 *     retained for label fidelity only - an open file object, not path
 *     text, flows there (see query_generation_notes.md).
 * Candidate sinks (CookieJar.save/load, netrc read, create_unix_server)
 * and the url_for application-input sinks (fp) are NOT modeled.
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /**
   * Holds if `sink` is a reviewed Pass 1 taint sink for pass key `passKey`.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and (
      staticPathProbeSink(sink) or
      fileResponseConstructorSink(sink) or
      fileStatSink(sink) or
      fileOpenSink(sink) or
      sendfileSink(sink) or
      directoryListingSink(sink)
    )
  }

  /** Restricts an AST node to a file base name and a 1-based start line. */
  private predicate matchLoc(AstNode n, string baseName, int line) {
    n.getLocation().getFile().getBaseName() = baseName and
    n.getLocation().getStartLine() = line
  }

  /**
   * Excludes test fixtures from the generalized sink signature, honoring
   * the Phase 1 extraction contract (tests/ rows were excluded from the
   * reviewed candidate set).
   */
  private predicate notATest(AstNode n) {
    not n.getLocation().getFile().getAbsolutePath().matches("%/tests/%")
  }

  /**
   * p1-sink-072, p1-sink-073 (sink/tp 0.70): filesystem probes on the
   * resolved static path inside StaticResource._handle.
   *
   * web_urldispatcher.py:657  if filepath.is_dir():
   * web_urldispatcher.py:667  elif filepath.is_file():
   *
   * Real file operation: os.stat via pathlib (existence/type oracle).
   * Dangerous position: the receiver `filepath` (the joinpath().resolve()
   * result derived from match_info['filename']).
   */
  private predicate staticPathProbeSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "is_dir" and
      matchLoc(c, "web_urldispatcher.py", 657) and
      sink.asExpr() = f.getObject()
    )
    or
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "is_file" and
      matchLoc(c, "web_urldispatcher.py", 667) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * p1-sink-074 (sink/tp 0.90) and p1-sink-041 (sink/tp 0.85): the
   * file-response sink signature.
   *
   * web_urldispatcher.py:667-668 (StaticResource._handle):
   *   elif filepath.is_file():
   *     return FileResponse(filepath, chunk_size=self._chunk_size)
   * web_fileresponse.py:44-54 (FileResponse.__init__):
   *   def __init__(self, path: PathLike, ...) -> None:
   *     self._path = pathlib.Path(path)
   *
   * Real file operation: FileResponse.prepare() stats the path
   * (web_fileresponse.py:141), optionally its .gz sibling (:136), opens it
   * for reading (:288) and transmits it via loop.sendfile (:93).
   * Dangerous position: the path argument (label arg_index 1 on __init__
   * counts `self`; at call sites this is positional argument 0).
   *
   * The reviewed label records FileResponse.__init__'s path parameter as
   * "THE file-response sink signature of the framework", so the matcher is
   * the construction-call shape FileResponse(<arg 0>) (Name or Attribute
   * callable), restricted to non-test files per the Phase 1 extraction
   * contract. The labeled site web_urldispatcher.py:668 is one instance.
   */
  private predicate fileResponseConstructorSink(DataFlow::Node sink) {
    exists(Call c |
      fileResponseCallable(c) and
      notATest(c) and
      sink.asExpr() = c.getArg(0)
    )
  }

  /** Holds if `c` is a FileResponse construction call. */
  private predicate fileResponseCallable(Call c) {
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = "FileResponse"
    or
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "FileResponse"
  }

  /**
   * p1-sink-048, p1-sink-049 (sink/tp): the stat calls of the serving
   * engine, executed in an executor from FileResponse.prepare().
   *
   * web_fileresponse.py:124-141 (_get_file_path_stat_and_gzip):
   *   filepath = self._path
   *   if check_for_gzipped_file:
   *     gzip_path = filepath.with_name(filepath.name + ".gz")
   *     return gzip_path, gzip_path.stat(), True   // :136
   *   return filepath, filepath.stat(), False      // :141
   *
   * Real file operation: os.stat. Dangerous position: the receiver
   * (gzip_path at :136, filepath at :141 - both derived from the
   * FileResponse path parameter).
   */
  private predicate fileStatSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "stat" and
      (matchLoc(c, "web_fileresponse.py", 136) or matchLoc(c, "web_fileresponse.py", 141)) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * p1-sink-050 (sink/tp 0.90): the actual open of the served file.
   *
   * web_fileresponse.py:288 (FileResponse.prepare):
   *   fobj = await loop.run_in_executor(None, filepath.open, "rb")
   *
   * Real file operation: open() for reading (pathlib .open bound method
   * submitted to the executor). Dangerous position: the receiver `filepath`
   * of the bare `filepath.open` attribute reference - the path text, not
   * the resulting file object.
   */
  private predicate fileOpenSink(DataFlow::Node sink) {
    exists(Attribute a |
      matchLoc(a, "web_fileresponse.py", 288) and
      a.getName() = "open" and
      sink.asExpr() = a.getObject()
    )
  }

  /**
   * p1-sink-046 (sink/tp 0.70): the file transmission channel.
   *
   * web_fileresponse.py:93 (FileResponse._sendfile):
   *   await loop.sendfile(transport, fobj, offset, count)
   *
   * Real file operation: zero-copy transmission of the already-open file.
   * Dangerous position per the reviewed label: argument 1 (fobj) - an
   * already-open file OBJECT, not path text. Retained for label fidelity;
   * by itself it cannot fire on path-text taint (the path was consumed at
   * the open, web_fileresponse.py:288).
   */
  private predicate sendfileSink(DataFlow::Node sink) {
    exists(Call c |
      matchLoc(c, "web_fileresponse.py", 93) and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "sendfile" and
      sink.asExpr() = c.getArg(1)
    )
  }

  /**
   * p1-sink-077 (sink/tp 0.75): the directory listing of show_index.
   *
   * web_urldispatcher.py:657-662, :683 (StaticResource):
   *   if filepath.is_dir():
   *     if self._show_index:
   *       return Response(text=self._directory_as_html(filepath), ...)
   *   ...
   *   dir_index = filepath.iterdir()
   *
   * Real file operation: directory read (scandir). Dangerous position: the
   * receiver `filepath` (the containment-checked resolved path).
   */
  private predicate directoryListingSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "iterdir" and
      matchLoc(c, "web_urldispatcher.py", 683) and
      sink.asExpr() = f.getObject()
    )
  }
}
