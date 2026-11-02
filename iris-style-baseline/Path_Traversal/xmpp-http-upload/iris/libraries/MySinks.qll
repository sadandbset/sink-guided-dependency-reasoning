/**
 * Augur Pass 1 (Path Traversal) sink model for xmpp-http-upload.
 *
 * Generated deterministically from the reviewed Pass 1 labels in
 * iris/labels/labels.json (the 7 entries with role=sink and
 * classification=tp). Only real filesystem access / file-response
 * positions are modeled, and path text is distinguished from the
 * already-open file objects:
 *   - receiver-position sinks match the path expression the pathlib
 *     API operates on (the Path object receivers of .open/.stat/
 *     .mkdir/.unlink, and the dest_path.parent derivation at
 *     xhu.py:137) - never the file handles those calls return (f /
 *     fout at :57/:76/:144);
 *   - the one argument-position sink is flask.send_file argument 0
 *     (xhu.py:228, the str(data_file) path text of the GET response).
 *
 * Rejected sink candidates (NOT modeled, per the reviewed labels):
 * the four setup.py packaging literals (role none/fp), the six
 * DATA_ROOT base-operand rows (:42 param root, :61 param root,
 * :66/:109/:194/:219 pathlib.Path constructions), Path.absolute()
 * (:43, role none - neither file access nor normalizer),
 * load_metadata's parameter row (:56) and write_file's parameter row
 * (:75) - definition rows whose real accesses are the sinks below.
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /**
   * Holds if `sink` is a reviewed Pass 1 taint sink for pass key
   * `passKey`.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and (
      metadataOpenReadSink(sink) or
      dataOpenWriteSink(sink) or
      unlinkRollbackSink(sink) or
      parentMkdirSink(sink) or
      metadataOpenCreateSink(sink) or
      dataStatSink(sink) or
      sendFileSink(sink)
    )
  }

  /** Restricts an AST node to a file base name and a 1-based start line. */
  private predicate matchLoc(AstNode n, string baseName, int line) {
    n.getLocation().getFile().getBaseName() = baseName and
    n.getLocation().getStartLine() = line
  }

  /**
   * sink-013 (sink/tp 0.80): the metadata-file read of the GET/HEAD
   * pipeline.
   *
   *   xhu.py:57: with metadata_file.open("r") as f:
   *
   * Real file operation: file open for reading (the stored metadata
   * JSON, then json.load at :58). Dangerous position: the receiver
   * `metadata_file` (path text - the "<route-path>.meta" Path object;
   * the resulting file handle `f` is NOT a sink). Call relationship:
   * load_metadata (xhu.py:56-58) <- get_info (:71) <- head_file
   * (:192-195) / get_file (:217-220) - both UNAUTHENTICATED routes.
   */
  private predicate metadataOpenReadSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "open" and
      matchLoc(c, "xhu.py", 57) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * sink-019 (sink/tp 0.85): THE uploaded-data write of the PUT
   * pipeline.
   *
   *   xhu.py:76: with at.open("xb") as f:
   *
   * Real file operation: file open for exclusive-create write (mode
   * "xb"), then the request body is streamed into it (stream_file,
   * xhu.py:92-101). Dangerous position: the receiver `at` (path text -
   * the "<route-path>.data" Path object; the yielded file handle is
   * NOT a sink). Call relationship: write_file (xhu.py:74-81, a
   * @contextlib.contextmanager generator) <- put_file (:141), after
   * the HMAC gate (:118-130) and the mkdir (:137). EEXIST surfaces as
   * 409 at :157-163.
   */
  private predicate dataOpenWriteSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "open" and
      matchLoc(c, "xhu.py", 76) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * sink-020 (sink/tp 0.65): the write-rollback deletion.
   *
   *   xhu.py:80: at.unlink()
   *
   * Real file operation: file deletion. Dangerous position: the
   * receiver `at` (path text). Call relationship: the write_file error
   * path only (an exception while streaming the body, e.g. the
   * EOFError raised by stream_file at :100-101, after a successful
   * exclusive create at :76); PUT/HMAC-gated.
   */
  private predicate unlinkRollbackSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "unlink" and
      matchLoc(c, "xhu.py", 80) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * sink-023 (sink/tp 0.80): recursive directory creation of the
   * uploaded path.
   *
   *   xhu.py:137: dest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o770)
   *
   * Real file operation: directory creation (mkdir -p semantics -
   * parents=True walks the whole joined chain). Dangerous position:
   * the receiver `dest_path.parent` (path-text derivation; realized by
   * the parentAttributeStep summary, since pathlib .parent is not a
   * default taint step). Call relationship: put_file, after the HMAC
   * gate and BEFORE the file writes - not suffix-constrained (unlike
   * the .data/.meta sinks), so "../" chains create directories
   * outside DATA_ROOT directly.
   */
  private predicate parentMkdirSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "mkdir" and
      matchLoc(c, "xhu.py", 137) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * sink-024 (sink/tp 0.80): the metadata-file creation of the PUT
   * pipeline.
   *
   *   xhu.py:144: with metadata_file.open("x") as f:
   *
   * Real file operation: file open for exclusive-create write (mode
   * "x") of "<route-path>.meta"; the metadata JSON (the uploader's
   * Content-Type) is dumped into it (:145-150). Dangerous position:
   * the receiver `metadata_file` (path text; the handle is NOT a
   * sink). Call relationship: put_file, inside the write_file block
   * (:141-150); EEXIST -> 409 (:157-163).
   */
  private predicate metadataOpenCreateSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "open" and
      matchLoc(c, "xhu.py", 144) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * sink-026 (sink/tp 0.65): the HEAD-route metadata probe.
   *
   *   xhu.py:197: stat = data_file.stat()
   *
   * Real file operation: stat (existence/size probe - no content
   * read; st_size becomes the Content-Length at :206). Dangerous
   * position: the receiver `data_file` ("<route-path>.data" path
   * text). Call relationship: head_file (:190), UNAUTHENTICATED route,
   * after get_info (:192-195).
   */
  private predicate dataStatSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "stat" and
      matchLoc(c, "xhu.py", 197) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * sink-028 (sink/tp 0.90): THE file-response sink of the GET route.
   *
   *   xhu.py:228: response = flask.make_response(flask.send_file(str(data_file)))
   *
   * Real file operation: framework file-read-into-HTTP-response
   * (flask.send_file opens and streams the file). Dangerous position:
   * argument 0 - str(data_file), the "<route-path>.data" path text
   * (the str() coercion is a default taint step, no summary needed).
   * Call relationship: get_file (:214-235), UNAUTHENTICATED route, via
   * get_info (:217-220). flask.make_response is a response wrapper,
   * not a file access, and is correctly not a sink.
   */
  private predicate sendFileSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "send_file" and
      matchLoc(c, "xhu.py", 228) and
      sink.asExpr() = c.getArg(0)
    )
  }
}
