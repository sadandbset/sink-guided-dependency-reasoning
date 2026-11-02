/**
 * Augur Phase 2 Step 4 — Pass 1 (Path Traversal) sink model for pretalx.
 *
 * Machine-generated from iris/labels/labels.json (run
 * pretalx-pathtraversal-pass1-20261022, pass_id 1). Sink rules render exactly
 * the label entries whose role=sink AND whose classification is tp or
 * candidate. pretalx has no tp-classified sink entries, so the model covers
 * the 10 candidate entries; the 15 classification=fp sink rows and the 8
 * role=none rows are excluded by policy (documented below and in
 * report/query_generation_notes.md section 5).
 *
 * Sinks match the dangerous *path argument* (or the receiver path of
 * Path.mkdir) of real file access / file response / file modification APIs —
 * not path text held in intermediate wrappers, and not file objects returned
 * by opens. The one deliberate exception is K0020 (FileResponse of an already
 * opened file): it is kept because the label marks the file-response position
 * of the get_static chain, but taint on the *path text* does not flow onto the
 * open() file object, so this sink can only alert together with an argument
 * that is itself path text.
 *
 * Excluded by policy (label rationale, no untrusted source can reach them):
 *  - common/tasks.py:37/54/64/108 storage save / open with literal/checksum/
 *    operator-validated event-slug names (fp, conf 0.65-0.75)
 *  - orga/views/schedule.py:124 open/FileResponse of the HTMLEXPORT_ROOT zip
 *    (event slug RegexValidator admits no separators; orga permission; fp)
 *  - common/forms/fields.py:135 open of the Django-assigned upload temp path
 *    (client controls content, not the path; fp)
 *  - common/settings/config.py:155 open of the operator-controlled
 *    PRETALX_CONFIG_FILE env path (fp)
 *  - export_schedule_html.py:168/201/206/213 rmdir/mkdir/rename/make_archive
 *    of HTMLEXPORT_ROOT + event-slug paths (fp; residual ".." slug edge noted
 *    in the label evidence)
 *  - common/mixins/views.py:290/294/296 FileResponse of FieldFile event
 *    assets (storage-validated names, permission-gated; fp)
 *  - role=none rows: BytesIO FileResponse (speaker.py:168), Image.open of a
 *    BytesIO (fields.py:146), NamedTemporaryFile with literal suffix
 *    (cards.py:122), test-settings/makemessages directory creation (dev/test
 *    tooling) — no filesystem path argument at these call sites.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  // --------------------------------------------------------------------------
  // Shared helpers (same shapes as the validated extraction query
  // iris/extraction/sinks.ql).
  // --------------------------------------------------------------------------

  /**
   * Gets the repository-relative path of the file containing this node, e.g.
   * "src/pretalx/common/views.py". On this Windows-created database
   * getRelativePath() may yield backslash forms or no result, so fall back to
   * capturing the "src/pretalx/..." suffix from the absolute path.
   */
  private string relPath(AstNode n) {
    exists(string p |
      p = n.getLocation().getFile().getRelativePath() and
      result = p.replaceAll("\\", "/")
    )
    or
    not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/").regexpCapture(".*/(src/pretalx/.+)$", 1)
  }

  /** Gets the dotted name of a simple name/attribute chain, e.g. "self.file_storage". */
  private string dottedName(Expr e) {
    result = e.(Name).getId()
    or
    result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
  }

  /**
   * Holds for a dynamically dispatched Django storage call on a receiver
   * matching the labeled storage objects (self.file_storage — the cfp wizard
   * FileSystemStorage(MEDIA_ROOT / "cfp_uploads"), flow.py:188 — and
   * default_storage). Restricted to the two files holding the candidate labels
   * (src/pretalx/cfp/flow.py, src/pretalx/common/mixins/forms.py); the
   * common/tasks.py save/open sites are fp labels and excluded.
   */
  private predicate storageCall(Call c, string methodName) {
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = methodName and
    methodName in ["save", "open", "delete"] and
    relPath(c) in ["src/pretalx/cfp/flow.py", "src/pretalx/common/mixins/forms.py"] and
    (
      exists(string recv | recv = dottedName(c.getFunc().(Attribute).getObject()) and recv.matches("%file_storage"))
      or
      exists(string recv | recv = dottedName(c.getFunc().(Attribute).getObject()) and recv.matches("%default_storage"))
    )
  }

  // --------------------------------------------------------------------------
  // openPathArg — labels K0010, K0012, K0013 (candidate, conf 0.5-0.6).
  //
  // K0010: open(path, "rb") in get_static (src/pretalx/common/views.py:56).
  //   File read. path = settings.BASE_DIR / "pretalx/static" / <urlconfig path>
  //   — raw pathlib join, no canonicalization, no base-dir containment, no '..'
  //   rejection; path.exists() at :53 is a plain check-then-use. Line-restricted
  //   to :56 because this is the only open() in the file.
  // K0012: open(path, "wb") in dump_content
  //   (src/pretalx/agenda/management/commands/export_schedule_html.py:121).
  //   File write of fetched content to Path(destination) / path.lstrip("/") —
  //   only leading slashes are stripped, '..' components survive the join.
  // K0013: open(local_path, "rb") in get_mediastatic_content
  //   (export_schedule_html.py:134). File read of STATIC_ROOT/MEDIA_ROOT /
  //   url[len(STATIC_URL):] — raw join with no containment check.
  // Line-restricted because the remaining open() sites in pretalx are
  // fp-labeled (tasks.py:54 literal static file, fields.py:135 Django-assigned
  // upload temp path, config.py:155 env-config path, orga schedule zip).
  // --------------------------------------------------------------------------
  private predicate openPathArg(DataFlow::Node n) {
    exists(Call call, int line |
      call.getFunc() instanceof Name and
      call.getFunc().(Name).getId() = "open" and
      n.asExpr() = call.getArg(0) and
      (
        (
          relPath(call) = "src/pretalx/common/views.py" and
          line = 56
        )
        or
        (
          relPath(call) = "src/pretalx/agenda/management/commands/export_schedule_html.py" and
          line in [121, 134]
        )
      ) and
      call.getLocation().getStartLine() = line
    )
  }

  // --------------------------------------------------------------------------
  // mkdirReceiver — label K0008 (candidate, conf 0.45).
  //
  // path.parent.mkdir(parents=True, exist_ok=True) in dump_content
  // (src/pretalx/agenda/management/commands/export_schedule_html.py:119).
  // Directory creation where path = Path(destination) / path.lstrip("/"): the
  // receiver (path.parent) carries the URL-derived directory components and
  // would create directories outside the export tmp destination for a
  // '../'-bearing URL. The sink node is the RECEIVER expression (path.parent),
  // not an argument — Path.mkdir creates the directory named by the receiver.
  // Line-restricted to :119; the other mkdir sites are fp/none labels
  // (settings.py:58, test_settings.py:23, makemessages.py:25/26 dev tooling,
  // export_schedule_html.py:201 tmp_dir).
  // --------------------------------------------------------------------------
  private predicate mkdirReceiver(DataFlow::Node n) {
    exists(Call call |
      call.getFunc() instanceof Attribute and
      call.getFunc().(Attribute).getName() = "mkdir" and
      relPath(call) = "src/pretalx/agenda/management/commands/export_schedule_html.py" and
      call.getLocation().getStartLine() = 119 and
      n.asExpr() = call.getFunc().(Attribute).getObject()
    )
  }

  // --------------------------------------------------------------------------
  // fileResponseFileArg — label K0020 (candidate, conf 0.55).
  //
  // FileResponse(open(path, "rb"), ...) in get_static
  // (src/pretalx/common/views.py:55). File response: the already-opened file is
  // streamed to the HTTP client, completing the read-and-return chain of the
  // get_static flow. The actual file access happens in the open() call at :56
  // (sink K0010); this sink matches the file-response position of the same
  // chain. Only path-text arguments can alert here (see file header note).
  // The other FileResponse sites are excluded: FieldFile event assets
  // (mixins/views.py:290/294/296, fp) and the BytesIO avatar (speaker.py:168,
  // role=none).
  // --------------------------------------------------------------------------
  private predicate fileResponseFileArg(DataFlow::Node n) {
    exists(Call call |
      call.getFunc() instanceof Name and
      call.getFunc().(Name).getId() = "FileResponse" and
      relPath(call) = "src/pretalx/common/views.py" and
      call.getLocation().getStartLine() = 55 and
      n.asExpr() = call.getArg(0)
    )
  }

  // --------------------------------------------------------------------------
  // storageNameArg — labels K0016, K0030, K0031, K0032, K0033 (candidate,
  // conf 0.45-0.5). Argument 0 is the storage-relative NAME (path text), the
  // traversal-relevant parameter; the file object/content in later arguments
  // is not matched.
  //
  // K0031: FileSystemStorage.save(field_file.name, field_file) in the cfp
  //   wizard (src/pretalx/cfp/flow.py:266) — client-supplied multipart filename
  //   as the storage-relative name under MEDIA_ROOT/cfp_uploads (flow.py:188).
  // K0030: default_storage.save(self.get_new_filename(value.name), value) in
  //   HierarkeyMixin.save (src/pretalx/common/mixins/forms.py:450) —
  //   get_new_filename embeds the raw uploaded name as a path component
  //   (forms.py:470-479).
  // K0016: FileSystemStorage.open(tmp_name) in the cfp wizard
  //   (src/pretalx/cfp/flow.py:260) — storage-relative name from the session
  //   files dict.
  // K0032/K0033: default_storage.delete(fname.name) in HierarkeyMixin.save
  //   (src/pretalx/common/mixins/forms.py:445, 461) — deletion of the
  //   previously stored settings file by its DB-stored storage name.
  // All sites rely on Django-internal name validation (basename + safe_join,
  // Django ~=3.2 pinned in src/setup.py:101), which is outside this CodeQL DB
  // — that is why the labels stay candidate and the alerts need human triage.
  // --------------------------------------------------------------------------
  private predicate storageNameArg(DataFlow::Node n) {
    exists(Call call |
      storageCall(call, "save") and
      n.asExpr() = call.getArg(0)
    )
    or
    exists(Call call |
      storageCall(call, "open") and
      n.asExpr() = call.getArg(0)
    )
    or
    exists(Call call |
      storageCall(call, "delete") and
      n.asExpr() = call.getArg(0)
    )
  }

  /** Holds if `n` is a pass 1 sink node. `passKey` must be "path_traversal". */
  predicate isSink(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      openPathArg(n)
      or mkdirReceiver(n)
      or fileResponseFileArg(n)
      or storageNameArg(n)
    )
  }
}
