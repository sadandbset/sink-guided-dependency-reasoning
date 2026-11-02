/**
 * Augur Phase 2 Step 4 - Pass 1 (Path Traversal) source library for ganga.
 *
 * Deterministically rendered from the reviewed Pass 1 labels in
 * iris/labels/labels.json (run iris-ganga-pathtraversal-pass1-20261022):
 * ONLY entries with role=source and classification=tp are modeled. The
 * reviewed label set contains exactly six such entries:
 *
 *   src-016 (source/tp 0.90): request.args.get('path') at
 *     GangaGUI/api/routes.py:223 - the 'path' query parameter of the
 *     UNAUTHENTICATED, localhost-bound internal API export endpoint
 *     (/internal/jobs/<job_id>/export), which flows into the GPI export
 *     write chain (Persistency stripped_export -> open).
 *   src-045 (source/tp 0.90): request.args.get('path') at
 *     GangaGUI/api/routes.py:977 - the 'path' query parameter of
 *     /internal/load, which flows into the GPI load read chain
 *     (Persistency load -> getScriptPath -> open).
 *   src-065 (source/tp 0.95): the `path` route parameter of job_browse at
 *     GangaGUI/gui/routes.py:639 (Flask path converter of
 *     /job/<int:job_id>/browse/<path:path>).
 *   src-069 (source/tp 0.95): the `path` route parameter of storage_page at
 *     GangaGUI/gui/routes.py:925 (Flask path converter of
 *     /storage/<path:path>, GET+POST).
 *   src-070 (source/tp 0.85): request.files['storagefile'] at
 *     GangaGUI/gui/routes.py:941 - the multipart upload boundary of the
 *     storage write channel.
 *   src-072 (source/tp 0.80): the storagefile.filename attribute read at
 *     GangaGUI/gui/routes.py:953 - feeds secure_filename (its traversal
 *     potential is neutralized by the reviewed barrier; modeled so the
 *     filename component of the upload destination is explicit).
 *
 * All other source candidates are deliberately NOT sources here (see
 * iris/report/query_generation_notes.md for the full mapping and the
 * exclusion rationale):
 *   - src-047 (source/fp 0.80): request.args.get('path') of
 *     /internal/runfile (api/routes.py:1001) - genuine boundary but runpy
 *     execution is Pass 4 material, not path traversal;
 *   - the 9 fixed-path upload/form rows (src-055..src-061, src-071,
 *     src-073, src-074): loadfile/runfile uploads and the
 *     runfile-data/edited-job-info/config-data CONTENT channels write
 *     server-FIXED paths (Pass 4/5 carry-overs);
 *   - src-071 (the :942 filename emptiness check) and the filter/login/
 *     json/header rows: values never reach a filesystem path;
 *   - the 16 os.getenv/os.environ.get rows (S1): operator/deployment trust;
 *   - src-079 (source/candidate 0.50): the job_action dynamic dispatch -
 *     unconfirmed by review, so NOT rendered (no fabrication).
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python

import semmle.python.dataflow.new.DataFlow

module MySources {

  /**
   * Holds if `source` is a reviewed Pass 1 taint source for pass key
   * `passKey`.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and (
      internalApiPathParamSource(source) or
      jobBrowsePathParamSource(source) or
      storagePagePathParamSource(source) or
      storageUploadFileSource(source) or
      storageUploadFilenameSource(source)
    )
  }

  /** Forward-slash-normalized absolute path of the file containing n
   *  (same helper shape as extraction/sources.ql; the replaceAll makes the
   *  line-anchored matches below separator-independent on this Windows
   *  host, where getLocation().getFile().getAbsolutePath() may carry
   *  backslashes). */
  private string normalizedPathOf(AstNode n) {
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
  }

  bindingset[modulePathPattern]
  private predicate inModule(AstNode n, string modulePathPattern) {
    normalizedPathOf(n).matches(modulePathPattern)
  }

  /**
   * src-016 and src-045 (source/tp 0.90): the 'path' query parameters of
   * the internal API export/load endpoints.
   *
   * GangaGUI/api/routes.py:212-232 (job_export) and :966-986 (load_file):
   *   @internal.route("/internal/jobs/<job_id>/export", methods=["GET"])
   *   def job_export(job_id: int):
   *     ...
   *     save_path = request.args.get("path")        # :223  (src-016)
   *     export(jobs(job_id), save_path)             # :227
   *   @internal.route("/internal/load", methods=["GET"])
   *   def load_file():
   *     path = request.args.get("path")             # :977  (src-045)
   *     load(path)                                  # :981
   *
   * External input boundary: the flask query string. The internal Flask app
   * (GangaGUI/api/__init__.py:15) registers NO authentication on any route
   * and is served on an APIServerThread bound to "localhost"
   * (GangaGUI/start.py:99/:109), so the value is controlled by any local
   * process and by a remote drive-by page issuing a cross-origin GET (the
   * export/load executes server-side even though the same-origin policy
   * blocks reading the response). The GUI's own pages call these endpoints
   * with fixed UPLOAD_FOLDER paths, so the arbitrary-path usage is the
   * direct internal request.
   *
   * The source node is the CALL RESULT of request.args.get("path") (the
   * value saved into save_path/path) - not the whole request object.
   * Line-anchored: the ~50 other request.args.get rows in this module are
   * job/template filters (reviewed none/fp) and are NOT matched.
   */
  private predicate internalApiPathParamSource(DataFlow::Node source) {
    exists(Call c, Attribute get, Attribute args, Name req |
      inModule(c, "%/ganga/GangaGUI/api/routes.py") and
      c.getLocation().getStartLine() in [223, 977] and
      get = c.getFunc().(Attribute) and
      get.getName() = "get" and
      args = get.getObject().(Attribute) and
      args.getName() = "args" and
      req = args.getObject().(Name) and
      req.getId() = "request" and
      source.asExpr() = c
    )
  }

  /**
   * src-065 (source/tp 0.95): the `path` route parameter of job_browse.
   *
   * GangaGUI/gui/routes.py:636-639:
   *   @gui.route("/job/<int:job_id>/browse", defaults={"path": ""})
   *   @gui.route("/job/<int:job_id>/browse/<path:path>")
   *   @login_required
   *   def job_browse(job_id: int, path):
   *
   * External input boundary: the Flask path converter captures the entire
   * request path remainder after /job/<id>/browse/. Flask/Werkzeug
   * URL-DECODES the path before routing and the path converter accepts '/'
   * and '..' segments, so the attacker controls the full decoded string
   * (GET /job/1/browse/../../etc/passwd). Access condition:
   * @login_required limits the attacker population to authenticated GUI
   * users, but does not constrain the path value. Downstream:
   * os.path.join(job_base_dir, path) at :659 (reviewed summary, sink-778)
   * -> exists/isfile/send_file/listdir sinks (:665-:676).
   */
  private predicate jobBrowsePathParamSource(DataFlow::Node source) {
    exists(Function f, Parameter p |
      inModule(f, "%/ganga/GangaGUI/gui/routes.py") and
      f.getName() = "job_browse" and
      f.getArgByName("path") = p and
      source = DataFlow::parameterNode(p)
    )
  }

  /**
   * src-069 (source/tp 0.95): the `path` route parameter of storage_page.
   *
   * GangaGUI/gui/routes.py:922-925:
   *   @gui.route("/storage", defaults={"path": ""}, methods=["GET", "POST"])
   *   @gui.route("/storage/<path:path>", methods=["GET", "POST"])
   *   @login_required
   *   def storage_page(path):
   *
   * External input boundary: same Flask path-converter semantics as
   * job_browse - URL-decoded, '/' and '..' accepted, authenticated GUI
   * user. Feeds BOTH the read channel (join :934 -> exists/isfile/
   * send_file/listdir :969-:980) and the POST write channel (join :934 ->
   * join(abs_path, secure_filename(filename)) :954 -> storagefile.save
   * :955) - the DIRECTORY component of the upload destination is this
   * unsanitized route path.
   */
  private predicate storagePagePathParamSource(DataFlow::Node source) {
    exists(Function f, Parameter p |
      inModule(f, "%/ganga/GangaGUI/gui/routes.py") and
      f.getName() = "storage_page" and
      f.getArgByName("path") = p and
      source = DataFlow::parameterNode(p)
    )
  }

  /**
   * src-070 (source/tp 0.85): the multipart upload object of the storage
   * write channel.
   *
   * GangaGUI/gui/routes.py:940-941 (storage_page POST branch):
   *   if "storagefile" in request.files:
   *     storagefile = request.files["storagefile"]
   *
   * External input boundary: the werkzeug FileStorage of the uploaded
   * multipart file (content fully attacker-controlled). The reviewed write
   * chain: storagefile.save(save_path) at :955 where save_path =
   * os.path.join(abs_path, secure_filename(storagefile.filename)) - the
   * save destination's filename component is neutralized by the barrier,
   * the directory component (route path) is not. The source node is the
   * Subscript request.files["storagefile"] itself.
   */
  private predicate storageUploadFileSource(DataFlow::Node source) {
    exists(Subscript s, Attribute files, Name req |
      inModule(s, "%/ganga/GangaGUI/gui/routes.py") and
      s.getLocation().getStartLine() = 941 and
      files = s.getObject().(Attribute) and
      files.getName() = "files" and
      req = files.getObject().(Name) and
      req.getId() = "request" and
      source.asExpr() = s
    )
  }

  /**
   * src-072 (source/tp 0.80): the uploaded filename attribute read on the
   * storage write channel.
   *
   * GangaGUI/gui/routes.py:953:
   *   filename = secure_filename(storagefile.filename)
   *
   * External input boundary: the multipart filename header, fully
   * attacker-controlled. Its own traversal potential ('..'-bearing or
   * absolute filenames) is neutralized by secure_filename BEFORE the join
   * at :954 - the reviewed barrier (MySanitizers::isBarrier) cuts this
   * component, and the CONFIRMED write traversal flows through the route
   * path parameter (src-069) instead. This source is rendered because the
   * reviewed label set marks it tp: it makes the filename component of the
   * upload destination an explicit source->barrier segment, so Phase 2
   * results demonstrate the sanitization instead of silently omitting it.
   * The :942 emptiness-check read (src-071, none/fp) is NOT matched.
   */
  private predicate storageUploadFilenameSource(DataFlow::Node source) {
    exists(Attribute a, Name obj |
      inModule(a, "%/ganga/GangaGUI/gui/routes.py") and
      a.getLocation().getStartLine() = 953 and
      a.getName() = "filename" and
      obj = a.getObject().(Name) and
      obj.getId() = "storagefile" and
      source.asExpr() = a
    )
  }
}
