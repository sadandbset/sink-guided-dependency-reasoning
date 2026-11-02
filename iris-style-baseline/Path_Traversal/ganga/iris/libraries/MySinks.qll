/**
 * Augur Phase 2 Step 4 - Pass 1 (Path Traversal) sink library for ganga.
 *
 * Deterministically rendered from the reviewed Pass 1 labels in
 * iris/labels/labels.json (run iris-ganga-pathtraversal-pass1-20261022):
 * every predicate below corresponds to a reviewed pass-1 entry with role
 * `sink` and classification `tp`, and to no other candidate. The reviewed
 * label set contains exactly twelve such entries, on the two GUI browser
 * flows, the storage upload write and the two internal-API GPI chains:
 *
 * Job browser (job_browse, GangaGUI/gui/routes.py:636-689):
 *   sink-780 (sink/tp 0.60): os.path.exists(abs_path)  gui/routes.py:665
 *   sink-781 (sink/tp 0.70): os.path.isfile(abs_path)  gui/routes.py:670
 *   sink-782 (sink/tp 0.95): send_file(abs_path)       gui/routes.py:671  PRIMARY read
 *   sink-783 (sink/tp 0.90): os.listdir(abs_path)      gui/routes.py:676
 * Storage browser (storage_page, gui/routes.py:922-992):
 *   sink-798 (sink/tp 0.60): os.path.isdir(abs_path)   gui/routes.py:949  upload gate
 *   sink-803 (sink/tp 0.60): os.path.exists(abs_path)  gui/routes.py:969
 *   sink-804 (sink/tp 0.70): os.path.isfile(abs_path)  gui/routes.py:974
 *   sink-805 (sink/tp 0.95): send_file(abs_path)       gui/routes.py:975  PRIMARY read
 *   sink-806 (sink/tp 0.90): os.listdir(abs_path)      gui/routes.py:980
 *   sink-801 (sink/tp 0.90): storagefile.save(save_path) gui/routes.py:955 PRIMARY write
 * Internal-API GPI chains (GangaCore/GPIDev/Persistency/__init__.py):
 *   sink-492 (sink/tp 0.90): open(filepath, mode)      :85   (export WRITE chain)
 *   sink-495 (sink/tp 0.90): open(filepath)            :190  (load READ chain)
 *
 * All other sink candidates are deliberately NOT sinks here (878 none/fp
 * sink rows: the ~35 GUI fixed-path opens/joins/sends of gangarc/logs/
 * export.txt/job stdout of int-selected jobs, the ~430 GangaCore and ~570
 * plugin/script operator-level job-workspace rows, the archive families,
 * and the sanitizer rows which belong to MySanitizers) - see
 * iris/report/query_generation_notes.md for the full mapping.
 *
 * Path TEXT versus opened file OBJECT: every sink is anchored on the
 * expression that NAMES the file location - the path string/Path-object
 * argument handed to the file API - never on a returned file, response or
 * listing object.
 *
 * Matching is AST-level (shapes already executed by extraction/sinks.ql
 * on this CLI/pack family: 2.25.1 / python-all 7.1.x), constrained to the
 * exact reviewed module and line.
 */

import python

import semmle.python.dataflow.new.DataFlow

module MySinks {

  /**
   * Holds if `sink` is a reviewed Pass 1 taint sink for pass key `passKey`.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and (
      jobBrowseStatProbe(sink) or
      jobBrowseSendFile(sink) or
      jobBrowseListdir(sink) or
      storageUploadGateProbe(sink) or
      storageStatProbe(sink) or
      storageSendFile(sink) or
      storageListdir(sink) or
      storageFileSave(sink) or
      persistencyExportOpen(sink) or
      persistencyLoadOpen(sink)
    )
  }

  /** Forward-slash-normalized absolute path of the file containing n
   *  (same helper shape as extraction/sinks.ql). */
  private string normalizedPathOf(AstNode n) {
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
  }

  bindingset[modulePathPattern]
  private predicate inModule(AstNode n, string modulePathPattern) {
    normalizedPathOf(n).matches(modulePathPattern)
  }

  /* ------------------------------------------------------------------ */
  /* Shared shapes (line-anchored to the exact reviewed call sites)      */
  /* ------------------------------------------------------------------ */

  /** os.path.<member>(path) at a reviewed line of GangaGUI/gui/routes.py:
   *  exists/isfile/isdir with the tainted path as argument 0. */
  private predicate osPathMemberSink(DataFlow::Node sink, string member, int line) {
    exists(Call c, Attribute f, Attribute pathAttr, Name os |
      inModule(c, "%/ganga/GangaGUI/gui/routes.py") and
      c.getLocation().getStartLine() = line and
      f = c.getFunc().(Attribute) and
      f.getName() = member and
      pathAttr = f.getObject().(Attribute) and
      pathAttr.getName() = "path" and
      os = pathAttr.getObject().(Name) and
      os.getId() = "os" and
      sink.asExpr() = c.getArg(0)
    )
  }

  /** os.<member>(path) at a reviewed line of GangaGUI/gui/routes.py:
   *  listdir with the tainted path as argument 0. */
  private predicate osMemberSink(DataFlow::Node sink, string member, int line) {
    exists(Call c, Attribute f, Name os |
      inModule(c, "%/ganga/GangaGUI/gui/routes.py") and
      c.getLocation().getStartLine() = line and
      f = c.getFunc().(Attribute) and
      f.getName() = member and
      os = f.getObject().(Name) and
      os.getId() = "os" and
      sink.asExpr() = c.getArg(0)
    )
  }

  /** send_file(path) at a reviewed line of GangaGUI/gui/routes.py. */
  private predicate sendFileSink(DataFlow::Node sink, int line) {
    exists(Call c |
      inModule(c, "%/ganga/GangaGUI/gui/routes.py") and
      c.getLocation().getStartLine() = line and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "send_file" and
      sink.asExpr() = c.getArg(0)
    )
  }

  /* ------------------------------------------------------------------ */
  /* Job browser flow (job_browse)                                       */
  /* ------------------------------------------------------------------ */

  /**
   * sink-780 (sink/tp 0.60) and sink-781 (sink/tp 0.70): the existence and
   * file-type probes of the job browser.
   *
   * gui/routes.py:665/:670 (job_browse):
   *   if not os.path.exists(abs_path):        # :665
   *     ...
   *   if os.path.isfile(abs_path):            # :670
   *     return send_file(abs_path)            # :671
   *
   * Dangerous position: argument 0 (abs_path = os.path.join(job_base_dir,
   * route path) from :659 - reviewed summary sink-778). Real file
   * operation: stat-family probe; the OS resolves the lexical ".."
   * segments and the absolute-path replacement of the join at stat time,
   * so these nodes are (a) filesystem existence/fstype ORACLEs reaching
   * outside the job directory and (b) the gates for the send_file/listdir
   * disclosure. Access type: metadata read (no content disclosure).
   * Secondary sinks at reduced confidence per the reviewed labels - they
   * also fire on non-file (directory) browse requests, so alerts ending
   * here are expected to be triaged in Step 6.
   */
  private predicate jobBrowseStatProbe(DataFlow::Node sink) {
    osPathMemberSink(sink, "exists", 665) or
    osPathMemberSink(sink, "isfile", 670)
  }

  /**
   * sink-782 (sink/tp 0.95, PRIMARY): send_file(abs_path) at :671.
   *
   * Real file operation: flask send_file opens the file at abs_path (the
   * open happens inside the external flask/werkzeug library, not in this
   * database) and streams the content as the HTTP response. Access type:
   * file READ disclosed to the authenticated GUI client. Called from
   * job_browse (route /job/<int:job_id>/browse/<path:path>, :637) after
   * the isfile gate; no resolve/realpath, no ".." rejection and no
   * base-dir containment exist anywhere on the chain, so the read is
   * bounded only by the GUI process's permissions.
   *
   * The fixed-path send_file of the job-export view (:578, sink reviewed
   * none/fp) is NOT matched - line-anchored to :671 only.
   */
  private predicate jobBrowseSendFile(DataFlow::Node sink) {
    sendFileSink(sink, 671)
  }

  /**
   * sink-783 (sink/tp 0.90): os.listdir(abs_path) at :676.
   *
   * Real file operation: directory listing of the traversal-laden joined
   * path (the OS resolves ".."; an absolute route path replaces the job
   * base entirely), rendered to the authenticated GUI user in the
   * job_dir.html template. Access type: directory metadata read
   * (name/children disclosure, then per-file browsing).
   */
  private predicate jobBrowseListdir(DataFlow::Node sink) {
    osMemberSink(sink, "listdir", 676)
  }

  /* ------------------------------------------------------------------ */
  /* Storage browser / upload flow (storage_page)                        */
  /* ------------------------------------------------------------------ */

  /**
   * sink-798 (sink/tp 0.60): os.path.isdir(abs_path) at :949 - the
   * upload-branch directory check on the traversal-laden joined path:
   * stat oracle + the gate that the write destination "directory" exists
   * before storagefile.save runs (:955).
   */
  private predicate storageUploadGateProbe(DataFlow::Node sink) {
    osPathMemberSink(sink, "isdir", 949)
  }

  /**
   * sink-803 (sink/tp 0.60) and sink-804 (sink/tp 0.70): the existence and
   * file-type probes of the storage browser (:969/:974) - same stat-oracle
   * and gate semantics as the job-browser probes, on
   * abs_path = os.path.join(STORAGE_FOLDER, route path) from :934.
   */
  private predicate storageStatProbe(DataFlow::Node sink) {
    osPathMemberSink(sink, "exists", 969) or
    osPathMemberSink(sink, "isfile", 974)
  }

  /**
   * sink-805 (sink/tp 0.95, PRIMARY): send_file(abs_path) at :975.
   *
   * Real file operation: flask opens and streams the file at abs_path to
   * the authenticated GUI client. Access type: file READ. Called from
   * storage_page (route /storage/<path:path>, :923) after the isfile gate;
   * no containment on the joined path, so the read is bounded only by the
   * GUI process's permissions.
   */
  private predicate storageSendFile(DataFlow::Node sink) {
    sendFileSink(sink, 975)
  }

  /**
   * sink-806 (sink/tp 0.90): os.listdir(abs_path) at :980 - directory
   * listing disclosure of the traversal-laden storage path.
   */
  private predicate storageListdir(DataFlow::Node sink) {
    osMemberSink(sink, "listdir", 980)
  }

  /**
   * sink-801 (sink/tp 0.90, PRIMARY write): storagefile.save(save_path)
   * at gui/routes.py:955 (storage_page POST branch).
   *
   * gui/routes.py:953-955:
   *   filename = secure_filename(storagefile.filename)
   *   save_path = os.path.join(abs_path, filename)
   *   storagefile.save(save_path)
   *
   * Dangerous position: argument 0 (save_path) - the path TEXT naming the
   * write destination; the FileStorage object (receiver) is not the sink.
   * Real file operation: werkzeug FileStorage.save writes the uploaded
   * content to save_path (the open happens inside the external werkzeug
   * library, not in this database). Access type: file WRITE - save_path's
   * DIRECTORY component (abs_path, the route-path-derived join result of
   * :934) is never sanitized, so POST /storage/../../ with a multipart
   * file writes outside gangadir/gui/storage; the filename component is
   * neutralized by the reviewed secure_filename barrier (:953).
   *
   * The fixed-path loadfile.save/runfile.save calls (:302/:328, reviewed
   * none/fp) are NOT matched - receiver- and line-anchored to
   * `storagefile` at :955 only.
   */
  private predicate storageFileSave(DataFlow::Node sink) {
    exists(Call c, Attribute f, Name recv |
      inModule(c, "%/ganga/GangaGUI/gui/routes.py") and
      c.getLocation().getStartLine() = 955 and
      f = c.getFunc().(Attribute) and
      f.getName() = "save" and
      recv = f.getObject().(Name) and
      recv.getId() = "storagefile" and
      sink.asExpr() = c.getArg(0)
    )
  }

  /* ------------------------------------------------------------------ */
  /* Internal-API GPI chains (Persistency)                               */
  /* ------------------------------------------------------------------ */

  /**
   * sink-492 (sink/tp 0.90, PRIMARY write): open(filepath, mode) at
   * GangaCore/GPIDev/Persistency/__init__.py:85 (stripped_export).
   *
   * Persistency/__init__.py:83-85:
   *   filepath = fullpath(filename)
   *   outFile = open(filepath, mode)
   *
   * Dangerous position: argument 0 (filepath) - the path TEXT; the file
   * object returned by open is not a sink. Real file operation: builtin
   * open with mode "w"/"a" - file WRITE. Reached from the request.args
   * 'path' of /internal/jobs/<job_id>/export via the GPI export chain
   * (reviewed summaries sink-490/sink-491/sink-493); fullpath (:140)
   * applies abspath/expandvars/expanduser - normalization WITHOUT
   * containment (abspath collapses ".." but never confines to a base).
   * The same open site is also reached by operator-level GUI/CLI exports
   * with fixed paths; the line anchor keeps the modeled site, the taint
   * flow distinguishes the request-reachable case.
   */
  private predicate persistencyExportOpen(DataFlow::Node sink) {
    exists(Call c |
      inModule(c, "%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
      c.getLocation().getStartLine() = 85 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "open" and
      sink.asExpr() = c.getArg(0)
    )
  }

  /**
   * sink-495 (sink/tp 0.90, PRIMARY read): open(filepath) at
   * GangaCore/GPIDev/Persistency/__init__.py:190 (load).
   *
   * Persistency/__init__.py:188-190:
   *   filepath = getScriptPath(filename, searchPath)
   *   with open(filepath) as inFile:
   *
   * Dangerous position: argument 0 (filepath). Real file operation:
   * builtin open - file READ of the traversal-laden path (getScriptPath,
   * Runtime.py:28, returns the expanded name verbatim when it exists).
   * Reached from the request.args 'path' of /internal/load via the GPI
   * load chain (reviewed summaries sink-494/sink-396). The file CONTENT is
   * subsequently eval'd at :209 (Pass 4 carry-over, outside this pass).
   */
  private predicate persistencyLoadOpen(DataFlow::Node sink) {
    exists(Call c |
      inModule(c, "%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
      c.getLocation().getStartLine() = 190 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "open" and
      sink.asExpr() = c.getArg(0)
    )
  }
}
