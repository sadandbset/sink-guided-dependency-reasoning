/**
 * Augur Phase 2 Step 4 — Pass 1 (Path Traversal) additional taint-step model
 * for pyramid.
 *
 * Machine-generated from iris/labels/labels.json (run
 * pyramid-pass1-pathtraversal-20261023, pass_id 1). The pass contains 7
 * role=summary entries (A003-A008 plus S027); how each one is handled:
 *
 *  A003 traversal_path_info (traversal.py:438)  — NOT rendered as an extra
 *      step: the function body is in the database and calls resolve through
 *      the module-level name, so default interprocedural data flow already
 *      carries PATH_INFO through decode_path_info/split_path_info to the
 *      returned segment tuple (the taint-relevant boundary is the barrier
 *      A002, modeled in MySanitizers.qll).
 *  A004 static_view.get_resource_name (static.py:123) — NOT rendered: the
 *      method is called on `self` inside class static_view and resolves
 *      interprocedurally by default; the request.path_info/subpath inputs
 *      are already sources (S037/S045) and the output is barrier-guarded
 *      (A001).
 *  A005 default_locale_negotiator (i18n.py:132) / A007
 *      LocalizerRequestMixin.localizer (i18n.py:359) / S027 request.localizer
 *      (i18n.py:220) — NOT rendered: the reify + registry-queryUtility
 *      indirection they describe is exactly the gap that the S026 source
 *      rule closes from the other side — `request.locale_name` /
 *      `self.locale_name` attribute reads are themselves audited sources
 *      (pyramid.request.Request mixes in LocalizerRequestMixin,
 *      request.py:144-149; the reified locale_name property is
 *      i18n.py:377-380). Rendering a return-to-attribute edge on top of that
 *      source would duplicate a boundary already present, so per the rule
 *      against unconditional cross-function propagation it is omitted.
 *  A006 make_localizer (i18n.py:169) — the parameter-to-filesystem part is
 *      rendered here as osPathJoinStep + osPathRealpathStep + listAppendStep
 *      (the join(tdir, lname) -> realpath -> isdir -> append -> iterate ->
 *      listdir/isfile -> open chain, i18n.py:189-203); the argument-to-body
 *      part is default interprocedural flow.
 *  A008 call_app_with_subpath_as_path_info (request.py:261) — NOT rendered:
 *      it re-injects request.subpath as the new PATH_INFO of a wrapped WSGI
 *      application through an environ copy; the environ write -> read
 *      indirection has no file sink reachable in this repository (the static
 *      view reads request.subpath directly), and an unconditional
 *      dict-store-to-load edge would create arbitrary propagation. Recorded
 *      as a diagnostic-only gap in report/query_generation_notes.md.
 *
 * The three steps below are code-evidence-based propagation edges required
 * for the reviewed source-to-sink chains to survive the Python taint model;
 * each cites its sites and none introduces unconstrained node-to-node
 * propagation.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  // --------------------------------------------------------------------------
  // Shared helpers.
  // --------------------------------------------------------------------------

  /**
   * Gets the repository-relative path of the file containing this node, e.g.
   * "src/pyramid/i18n.py". On this Windows-created database
   * getRelativePath() may yield backslash forms or no result, so fall back to
   * capturing the "src/pyramid/..." suffix from the absolute path.
   */
  private string relPath(AstNode n) {
    exists(string p |
      p = n.getLocation().getFile().getRelativePath() and
      result = p.replaceAll("\\", "/")
    )
    or
    not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/").regexpCapture(".*/(src/pyramid/.+)$", 1)
  }

  /**
   * Restricts nodes to the extraction scope of iris/extraction/{sources,sinks}.ql:
   * src/pyramid minus the framework testing helpers and interface stubs.
   */
  private predicate inExtractionScope(AstNode n) {
    relPath(n).matches("src/pyramid/%") and
    not relPath(n).matches("src/pyramid/testing.py") and
    not relPath(n).matches("src/pyramid/config/testing.py") and
    not relPath(n).matches("src/pyramid/interfaces.py")
  }

  /** Gets the dotted name of a simple name/attribute chain, e.g. "os.path.join". */
  private string dottedName(Expr e) {
    result = e.(Name).getId()
    or
    result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
  }

  // --------------------------------------------------------------------------
  // 1. osPathJoinStep (renders the join half of label A006).
  //
  // os.path.join is a pure path-text concatenation: the result path is built
  // from the argument paths (an absolute later argument discards the earlier
  // ones — which is exactly the Chain B behavior of
  // os.path.join(tdir, lname) when the locale name is absolute). Sites in
  // scope (all observed in the real code):
  //   i18n.py:192   os.path.join(tdir, lname)           — locale chain (B)
  //   i18n.py:197   os.path.join(locale_dir, 'LC_MESSAGES')
  //   i18n.py:201   os.path.join(messages_dir, mofile)  — locale chain (B)
  //   static.py:152 join(norm_docroot, path)            — static chain (A,
  //                post-barrier)
  //   static.py:156 join(resource_path, self.index)
  //   config/assets.py:268/271  FSAssetSource.get_path
  //   path.py:13-17 caller_path
  //
  // Why a local step is needed: python-all ships an equivalent global step
  // (semmle/python/frameworks/Stdlib.qll,
  // OsPathJoinCallAdditionalTaintStep), but it only registers when
  // semmle.python.Concepts (-> Frameworks -> Stdlib) is imported, which
  // `import python` alone does not do. This query deliberately does not
  // import Concepts, so that every active propagation edge is one of the
  // evidence-scoped steps documented here (deterministic, label-auditable
  // model). This step mirrors the Stdlib rule restricted to src/pyramid.
  // --------------------------------------------------------------------------
  private predicate osPathJoinStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      inExtractionScope(c) and
      dottedName(c.getFunc()) = "os.path.join" and
      nodeTo.asExpr() = c and
      nodeFrom.asExpr() = c.getAnArg()
    )
  }

  // --------------------------------------------------------------------------
  // 2. osPathRealpathStep (renders the canonicalization half of label A006).
  //
  // os.path.realpath is a path-text -> canonical-path-text wrapper (it
  // resolves symlinks). Taint passes through it; it is NOT a sanitizer — it
  // performs no containment (see MySanitizers.qll header and labels
  // K037-K039 role=none). The only in-scope sites are the three
  // make_localizer calls:
  //   i18n.py:192   realpath(join(tdir, lname)) -> ldir
  //   i18n.py:198   realpath(messages_dir)      (isdir argument)
  //   i18n.py:201   realpath(join(messages_dir, mofile)) -> mopath -> open
  // Without this step the chain stops at the realpath call results
  // (realpath is an unmodeled stdlib call: no argument-to-result flow by
  // default).
  // --------------------------------------------------------------------------
  private predicate osPathRealpathStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      inExtractionScope(c) and
      dottedName(c.getFunc()) = "os.path.realpath" and
      nodeTo.asExpr() = c and
      nodeFrom.asExpr() = c.getArg(0)
    )
  }

  // --------------------------------------------------------------------------
  // 3. listAppendStep (container propagation inside make_localizer, label
  // A006 evidence i18n.py:189-196).
  //
  // Two append sites carry the locale chain across list containers:
  //   i18n.py:179  locales_to_try.append(current_locale_name)
  //   i18n.py:194  locale_dirs.append(ldir)
  // followed by iteration:
  //   i18n.py:191/196  for lname in locales_to_try / for locale_dir in locale_dirs
  // python-all's built-in containerStep covers only literal construction
  // ([x, y]) — not .append() — and the for-loop read step
  // (forReadStep) is already built in. This step links the appended element
  // to the list object, restricted to src/pyramid/i18n.py (the only module
  // where the reviewed chain needs it).
  // --------------------------------------------------------------------------
  private predicate listAppendStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      relPath(c) = "src/pyramid/i18n.py" and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "append" and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c.getFunc().(Attribute).getObject()
    )
  }

  /**
   * Holds if taint may step from `nodeFrom` to `nodeTo` for pass 1. `passKey`
   * must be "path_traversal".
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    (
      osPathJoinStep(nodeFrom, nodeTo)
      or osPathRealpathStep(nodeFrom, nodeTo)
      or listAppendStep(nodeFrom, nodeTo)
    )
  }
}
