/*
 * Augur generated sink library - Pass 1 (Path Traversal), Zope 5.2.dev0.
 * Machine-generated from iris/labels/labels.json (pass_id = 1, pass key
 * "path_traversal"; labeling run zope-iris-pass1-step3-20261024, model glm-5.3,
 * reviewed 2026-10-24).  Do not edit by hand: regenerate from labels instead.
 *
 * All 61 sink-role label entries are modeled, deduplicated to their API
 * signatures (the Phase 1 extraction was repo-wide, so a signature match
 * reproduces exactly the labeled call sites; tests/ and Testing/ are excluded
 * from the database).  Every rule matches the PATH-TEXT argument position of a
 * real filesystem access API; values returned by open()/filestream_iterator
 * (file objects) are never treated as sinks.
 *
 * Sink signatures and label ids (see report/query_generation_notes.md):
 *  - open arg 0                       p1-snk-339..349 (11 rows)
 *  - os.path.exists/isdir/isfile/     p1-snk-316..336, 354, 365..374 (32 rows)
 *    getmtime arg 0
 *  - os.stat arg 0                    p1-snk-350, 351
 *  - os.listdir arg 0                 p1-snk-337, 338
 *  - os.walk arg 0                    p1-snk-356
 *  - os.makedirs arg 0                p1-snk-355
 *  - os.remove arg 0                  p1-snk-376
 *  - shutil.copyfile/copymode arg 0/1 p1-snk-357..364 (8 rows)
 *  - filestream_iterator arg 0        p1-snk-352
 *  - connection.importFile arg 0      p1-snk-353 (ZODB, external)
 *  - factory(name, filename) arg 1    p1-snk-375
 *
 * Note on call-shape: every labeled call site passes the path positionally
 * (verified in source: open(f, 'w+b'), os.path.join(...), factory(name,
 * filename), connection.importFile(filepath)); keyword-argument forms are not
 * modeled because no labeled site uses them.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {

  /** Holds if `sink` is a Pass 1 (path traversal) taint sink. */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and isPathTraversalSink(sink)
  }

  private predicate isPathTraversalSink(DataFlow::Node sink) {
    isBuiltinOpenSink(sink) or
    isOsPathCheckSink(sink) or
    isOsModuleSink(sink) or
    isShutilCopySink(sink) or
    isFilestreamIteratorSink(sink) or
    isZodbImportFileSink(sink) or
    isResourceFactorySink(sink)
  }

  /**
   * builtins open(path, ...) - real file read/write/create.  Dangerous
   * argument: index 0 (path text).  Labeled sites include the
   * manage_exportObject write (ObjectManager.py:622, candidate), external-
   * method source read (App/Extensions.py:178), template/image/default-content
   * reads and CLI/startup opens (operator boundary - no source reaches them,
   * so they cannot alert).
   */
  private predicate isBuiltinOpenSink(DataFlow::Node sink) {
    exists(Call c |
      sink.asExpr() = c.getArg(0) and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "open"
    )
  }

  /**
   * os.path.exists / isdir / isfile / getmtime - filesystem existence and
   * metadata probes (TOCTOU-relevant path-text reads).  Dangerous argument:
   * index 0.  Labeled sites include the ++resource++ bridge probes
   * (Products/Five/browser/resource.py:156/:157, candidate) and the
   * manage_importObject existence check (ObjectManager.py:645).
   */
  private predicate isOsPathCheckSink(DataFlow::Node sink) {
    exists(Call c, string fname |
      sink.asExpr() = c.getArg(0) and
      fname in ["exists", "isdir", "isfile", "getmtime"] and
      isOsPathFuncCall(c, fname)
    )
  }

  /**
   * os.stat / os.listdir / os.walk / os.remove / os.makedirs - metadata read,
   * directory enumeration, recursive enumeration, deletion and directory
   * creation.  Dangerous argument: index 0 (path text).
   */
  private predicate isOsModuleSink(DataFlow::Node sink) {
    exists(Call c, string fname |
      sink.asExpr() = c.getArg(0) and
      fname in ["stat", "listdir", "walk", "remove", "makedirs"] and
      isOsFuncCall(c, fname)
    )
  }

  /**
   * shutil.copyfile(src, dst) / shutil.copymode(src, dst) - file copy and mode
   * copy.  Dangerous arguments: index 0 (source path) and index 1
   * (destination path).  Labeled sites are the CLI skeleton copier
   * (operator boundary).
   */
  private predicate isShutilCopySink(DataFlow::Node sink) {
    exists(Call c, string fname, int i |
      sink.asExpr() = c.getArg(i) and
      i in [0, 1] and
      fname in ["copyfile", "copymode"] and
      isShutilFuncCall(c, fname)
    )
  }

  /**
   * ZPublisher.Iterators.filestream_iterator(name, mode) - subclasses
   * io.FileIO, so construction OPENS the file and iteration streams it as the
   * HTTP response body (file-response sink).  Dangerous argument: index 0
   * (path text).  Labeled site: App/ImageFile.py:121 (path fixed at ZCML
   * registration - no source reaches it, so it cannot alert).
   */
  private predicate isFilestreamIteratorSink(DataFlow::Node sink) {
    exists(Call c |
      sink.asExpr() = c.getArg(0) and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "filestream_iterator"
    )
  }

  /**
   * ZODB Connection.importFile(filepath) (external dependency - the ZODB
   * connection performs the actual file open of the zexp/xml file).
   * Dangerous argument: index 0 (path text).  Labeled site:
   * OFS/ObjectManager.py:679 (guarded by the os.path.split dirname rejection
   * at :639-641, modeled as a barrier in MySanitizers).
   */
  private predicate isZodbImportFileSink(DataFlow::Node sink) {
    exists(Call c, Attribute fn |
      sink.asExpr() = c.getArg(0) and
      c.getFunc() = fn and
      fn.getName() = "importFile" and
      fn.getObject() instanceof Name and
      fn.getObject().(Name).getId() = "connection"
    )
  }

  /**
   * DirectoryResource's factory(name, filename) dynamic call
   * (Products/Five/browser/resource.py:170): constructs the external
   * zope.browserresource File/Image/PageTemplate resource which performs the
   * actual file read when served.  Dangerous argument: index 1 (filename =
   * os.path.join(path, name) with the URL-derived ++resource++ segment).
   * Anchored to resource.py because "factory" is a local variable name.
   */
  private predicate isResourceFactorySink(DataFlow::Node sink) {
    exists(Call c |
      sink.asExpr() = c.getArg(1) and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "factory" and
      c.getLocation().getFile().getBaseName() = "resource.py"
    )
  }

  /** Holds if `c` is a call to os.path.<fname>(...). */
  private predicate isOsPathFuncCall(Call c, string fname) {
    exists(Attribute outer, Attribute inner |
      c.getFunc() = outer and
      outer.getName() = fname and
      outer.getObject() = inner and
      inner.getName() = "path" and
      inner.getObject() instanceof Name and
      inner.getObject().(Name).getId() = "os"
    )
  }

  /** Holds if `c` is a call to os.<fname>(...). */
  private predicate isOsFuncCall(Call c, string fname) {
    exists(Attribute a |
      c.getFunc() = a and
      a.getName() = fname and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() = "os"
    )
  }

  /** Holds if `c` is a call to shutil.<fname>(...). */
  private predicate isShutilFuncCall(Call c, string fname) {
    exists(Attribute a |
      c.getFunc() = a and
      a.getName() = fname and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() = "shutil"
    )
  }
}
