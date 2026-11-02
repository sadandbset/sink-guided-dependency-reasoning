/**
 * Augur Phase 2 Step 4 - Pass 1 (Path Traversal) additional taint-step
 * library for ganga.
 *
 * Deterministically rendered from the reviewed Pass 1 labels in
 * iris/labels/labels.json (run iris-ganga-pathtraversal-pass1-20261022):
 * the reviewed pass-1 label set contains eight summary entries with
 * classification=tp, rendered here as code-anchored edges. Every edge is
 * pinned to an exact file+line+shape; NO unconditional any-node-to-any-node
 * propagation exists in this file:
 *
 *   sink-778 (summary/tp 0.90): os.path.join(job_base_dir, path)
 *     gui/routes.py:659 - the unchecked join of the JOB browser.
 *   sink-797 (summary/tp 0.90): os.path.join(storage_folder, path)
 *     gui/routes.py:934 - the unchecked join of the STORAGE browser.
 *   sink-800 (summary/tp 0.85): os.path.join(abs_path, filename)
 *     gui/routes.py:954 - the upload-destination join (argument 0 carries
 *     the tainted route path; argument 1 the sanitized filename).
 *   sink-490 (summary/tp 0.90): GPI export(item, filename, mode)
 *     Persistency/__init__.py:35 - the internal-API export write-chain
 *     entry (bridges the call at api/routes.py:227 into the wrapper's
 *     filename parameter).
 *   sink-491 (summary/tp 0.90): stripped_export(item, filename, mode)
 *     Persistency/__init__.py:41 - the export implementation (bridges the
 *     same-module forwarding call at Persistency:36).
 *   sink-493 (summary/tp 0.85): fullpath(filename)
 *     Persistency/__init__.py:140 - abspath/expandvars/expanduser,
 *     normalization WITHOUT containment (two anchored edge forms, see
 *     below).
 *   sink-494 (summary/tp 0.90): load(filename, returnList)
 *     Persistency/__init__.py:154 - the internal-API load read-chain entry
 *     (bridges the call at api/routes.py:981).
 *   sink-396 (summary/tp 0.85): getScriptPath(name, searchPath)
 *     GangaCore/Utility/Runtime.py:28 - script-path resolution that
 *     returns the expanded name verbatim when it exists (two anchored
 *     edge forms, see below).
 *
 * Why the export/load bridge edges are REQUIRED (CodeQL limitation,
 * verified in the real source): the internal API imports the GPI wrappers
 * dynamically-populated at runtime -
 *
 *   api/routes.py:220   from GangaCore.GPI import jobs, export
 *   api/routes.py:974   from GangaCore.GPI import load
 *
 * GangaCore/GPI/__init__.py contains only a docstring; the GPI namespace
 * is assembled at bootstrap via exportToInterface(my_interface, ...)
 * (GangaCore/Runtime/bootstrap.py:147-:163). Static import resolution of
 * `export`/`load` therefore fails, and TaintTracking::Global cannot flow
 * the request argument into the wrapper bodies on its own. The bridge
 * edges anchor exactly the two reviewed call sites (:227 arg 1, :981 arg
 * 0) to exactly the two reviewed wrapper parameters - nothing else.
 *
 * Dual modeling (call-site edge + def-side edge) for fullpath and
 * getScriptPath, mirroring the reviewed wrapper bodies whose value
 * derivation runs through os.path.abspath/expanduser/expandvars (stdlib
 * calls without pack-provided taint summaries): both anchored forms of
 * the same reviewed fact are included; at worst they duplicate a path
 * segment, never fabricate one.
 *
 * Deliberate NON-edges (reviewed and rejected - see
 * iris/report/query_generation_notes.md):
 *   - the fixed-path joins of gui/routes.py (:301, :327, :370, :531-:532,
 *     :570, :597-:598, :783-:784) and the display-only dirname/replace
 *     rows (:662, :966, :682, :986): fixed constants or values consumed
 *     only for template display;
 *   - files.py expandfilename/fullpath (operator-level wrappers): no
 *     request-reachable chain uses them in this pass;
 *   - FileWorkspace.getPath, Sandbox/WNSandbox file_api_def rows,
 *     runfile (Pass 4): operator-level or wrong-pass;
 *   - the whole `request` object as a source (over-tainting, python.md
 *     section 7.4).
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python

import semmle.python.dataflow.new.DataFlow

module MySummaries {

  /**
   * Holds if there is an additional reviewed Pass 1 taint step from
   * `nodeFrom` to `nodeTo` for pass key `passKey`.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and (
      joinStep(nodeFrom, nodeTo) or
      exportBridgeStep(nodeFrom, nodeTo) or
      strippedExportForwardStep(nodeFrom, nodeTo) or
      fullpathCallSiteStep(nodeFrom, nodeTo) or
      fullpathDefSideStep(nodeFrom, nodeTo) or
      loadBridgeStep(nodeFrom, nodeTo) or
      getScriptPathCallSiteStep(nodeFrom, nodeTo) or
      getScriptPathDefSideStep(nodeFrom, nodeTo)
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
  /* sink-778 / sink-797 / sink-800: the three reviewed os.path.join      */
  /* call sites of the two browser flows (any argument -> result).       */
  /* ------------------------------------------------------------------ */

  /**
   * sink-778, sink-797 and sink-800 (summary/tp 0.90/0.90/0.85): the
   * os.path.join calls that carry the route path into the filesystem
   * accesses.
   *
   * gui/routes.py:659 (job_browse):
   *   abs_path = os.path.join(job_base_dir, path)
   * gui/routes.py:934 (storage_page):
   *   abs_path = os.path.join(storage_folder, path)
   * gui/routes.py:954 (storage_page POST branch):
   *   save_path = os.path.join(abs_path, filename)
   *
   * Edge: ANY argument -> the call result, at exactly these three
   * reviewed lines. Value-preservation proof: os.path.join concatenates
   * its arguments with separators and does NOT normalize - ".." segments
   * survive lexically in the result (the OS-level resolution that makes
   * them escape happens later at the exists/isfile/send_file/listdir/
   * save syscalls, the sinks), and an ABSOLUTE argument REPLACES the
   * base entirely (join semantics), which is also traversal-relevant.
   * The tainted arguments in the confirmed flows: `path` (argument 1,
   * from the route sources src-065/src-069) at :659/:934, and `abs_path`
   * (argument 0, the join result of :934) at :954.
   *
   * The many other os.path.join call sites of gui/routes.py (fixed
   * UPLOAD_FOLDER/export.txt/stdout-stderr paths, reviewed none/fp) are
   * NOT matched - line-anchored to 659, 934 and 954 only.
   */
  private predicate joinStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute f, Attribute pathAttr, Name os |
      inModule(c, "%/ganga/GangaGUI/gui/routes.py") and
      c.getLocation().getStartLine() in [659, 934, 954] and
      f = c.getFunc().(Attribute) and
      f.getName() = "join" and
      pathAttr = f.getObject().(Attribute) and
      pathAttr.getName() = "path" and
      os = pathAttr.getObject().(Name) and
      os.getId() = "os" and
      nodeFrom.asExpr() = c.getAnArg() and
      nodeTo.asExpr() = c
    )
  }

  /* ------------------------------------------------------------------ */
  /* sink-490 / sink-494: the GPI export/load bridge edges               */
  /* ------------------------------------------------------------------ */

  /**
   * sink-490 (summary/tp 0.90): the export write-chain entry.
   *
   * GangaGUI/api/routes.py:225-227 (job_export):
   *   try:
   *     # Export job
   *     export(jobs(job_id), save_path)
   *
   * Edge: argument 1 (save_path, tainted from the request.args source
   * src-016 at :223) -> the `filename` parameter of the wrapper
   *
   * GangaCore/GPIDev/Persistency/__init__.py:35:
   *   def export(item=None, filename="", mode="w"):
   *     return stripped_export(stripProxy(item), filename, mode)
   *
   * The GPI namespace is populated at runtime (exportToInterface,
   * bootstrap.py:147-:163), so `from GangaCore.GPI import ... export`
   * cannot be resolved statically and the default global taint tracking
   * does not cross this call. The edge anchors the single reviewed call
   * site to the single reviewed parameter; inside the wrapper everything
   * resolves natively (same-module call at :36 -> stripped_export
   * parameter -> fullpath call -> open sink at :85).
   */
  private predicate exportBridgeStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Function f, Parameter p |
      inModule(c, "%/ganga/GangaGUI/api/routes.py") and
      c.getLocation().getStartLine() = 227 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "export" and
      nodeFrom.asExpr() = c.getArg(1) and
      inModule(f, "%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
      f.getName() = "export" and
      p = f.getArgByName("filename") and
      nodeTo = DataFlow::parameterNode(p)
    )
  }

  /**
   * sink-491 (summary/tp 0.90): the export implementation forwarding.
   *
   * GangaCore/GPIDev/Persistency/__init__.py:36 (inside export):
   *   return stripped_export(stripProxy(item), filename, mode)
   *
   * Edge: argument 1 (filename, the tainted wrapper parameter) -> the
   * `filename` parameter of
   *
   * GangaCore/GPIDev/Persistency/__init__.py:41:
   *   def stripped_export(item=None, filename="", mode="w"):
   *
   * This is a same-module direct call that CodeQL resolves natively; the
   * edge is the code-anchored rendering of the reviewed label so the
   * chain stays connected even if argument-position resolution inside
   * the forwarding call were to fail. Redundant-but-sound, never
   * fabricating (both endpoints are the reviewed wrapper boundary).
   */
  private predicate strippedExportForwardStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Function f, Parameter p |
      inModule(c, "%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
      c.getLocation().getStartLine() = 36 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "stripped_export" and
      nodeFrom.asExpr() = c.getArg(1) and
      inModule(f, "%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
      f.getName() = "stripped_export" and
      p = f.getArgByName("filename") and
      nodeTo = DataFlow::parameterNode(p)
    )
  }

  /* ------------------------------------------------------------------ */
  /* sink-493: fullpath (normalization WITHOUT containment)              */
  /* ------------------------------------------------------------------ */

  /**
   * sink-493 (summary/tp 0.85), edge 1 of 2: the call-site form.
   *
   * GangaCore/GPIDev/Persistency/__init__.py:83 (stripped_export):
   *   filepath = fullpath(filename)
   *
   * Edge: argument 0 -> the call result. The callee body (:149-:151)
   *   filepath = os.path.abspath(
   *       os.path.expandvars(os.path.expanduser(filename)))
   *   return filepath
   * derives its result from the argument; abspath/expandvars/expanduser
   * are stdlib calls with no pack-provided taint summaries, so the result
   * would otherwise be clean. NOTE: this is normalization WITHOUT
   * containment - abspath COLLAPSES ".." (defeating lexical pre-checks)
   * but never confines the result to a base directory; it is modeled as
   * propagation (value-preserving for the traversal), NOT as a barrier.
   */
  private predicate fullpathCallSiteStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      inModule(c, "%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
      c.getLocation().getStartLine() = 83 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "fullpath" and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * sink-493 (summary/tp 0.85), edge 2 of 2: the def-side form.
   *
   * GangaCore/GPIDev/Persistency/__init__.py:149-150 (fullpath):
   *   filepath = os.path.abspath(
   *       os.path.expandvars(os.path.expanduser(filename)))
   *
   * Edge: the `filename` parameter of fullpath -> the OUTER call
   * expression (the os.path.abspath call beginning at :149, whose value
   * is assigned to filepath and returned at :151). This keeps the
   * parameter -> return propagation connected inside the callee even if
   * the same-module call at :83 or the abspath/expandvars/expanduser
   * nesting is not otherwise modeled. Both endpoints are inside the
   * reviewed wrapper; no other fullpath call site exists in the tree.
   */
  private predicate fullpathDefSideStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call abspath, Attribute f, Attribute pathAttr, Name os, Function fn, Parameter p |
      inModule(abspath, "%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
      abspath.getLocation().getStartLine() = 149 and
      f = abspath.getFunc().(Attribute) and
      f.getName() = "abspath" and
      pathAttr = f.getObject().(Attribute) and
      pathAttr.getName() = "path" and
      os = pathAttr.getObject().(Name) and
      os.getId() = "os" and
      nodeTo.asExpr() = abspath and
      inModule(fn, "%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
      fn.getName() = "fullpath" and
      p = fn.getArgByName("filename") and
      nodeFrom = DataFlow::parameterNode(p)
    )
  }

  /* ------------------------------------------------------------------ */
  /* sink-494: the GPI load bridge edge                                  */
  /* ------------------------------------------------------------------ */

  /**
   * sink-494 (summary/tp 0.90): the load read-chain entry.
   *
   * GangaGUI/api/routes.py:979-981 (load_file):
   *   try:
   *     # Load using the load function of ganga GPI
   *     load(path)
   *
   * Edge: argument 0 (path, tainted from the request.args source src-045
   * at :977) -> the `filename` parameter of the wrapper
   *
   * GangaCore/GPIDev/Persistency/__init__.py:154:
   *   def load(filename="", returnList=True):
   *
   * Same GPI runtime-namespace rationale as the export bridge: the
   * dynamic exportToInterface wiring makes `from GangaCore.GPI import
   * load` unresolvable statically. Inside the wrapper the chain resolves
   * natively: filename -> getScriptPath(filename, searchPath) at :188 ->
   * (sink-396 edges) -> open sink at :190.
   */
  private predicate loadBridgeStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Function f, Parameter p |
      inModule(c, "%/ganga/GangaGUI/api/routes.py") and
      c.getLocation().getStartLine() = 981 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "load" and
      nodeFrom.asExpr() = c.getArg(0) and
      inModule(f, "%/ganga/GangaCore/GPIDev/Persistency/__init__.py") and
      f.getName() = "load" and
      p = f.getArgByName("filename") and
      nodeTo = DataFlow::parameterNode(p)
    )
  }

  /* ------------------------------------------------------------------ */
  /* sink-396: getScriptPath (verbatim path resolution)                  */
  /* ------------------------------------------------------------------ */

  /**
   * sink-396 (summary/tp 0.85), edge 1 of 2: the call-site form.
   *
   * GangaCore/GPIDev/Persistency/__init__.py:188 (load):
   *   filepath = getScriptPath(filename, searchPath)
   *
   * Edge: argument 0 -> the call result. The callee
   * (GangaCore/Utility/Runtime.py:28-61) returns the expanded name
   * VERBATIM when it exists:
   *   fullName = os.path.expanduser(os.path.expandvars(name))   # :47
   *   if os.path.exists(fullName):                               # :48
   *     scriptPath = fullName                                    # :49
   * so the result is value-preserving for the attacker path (the
   * expanduser/expandvars stdlib calls have no pack taint summaries,
   * which is what this edge bridges). Only the not-found branch falls
   * back to basename + search-path join (:52-:58) - a REAL partial
   * containment for that branch only, but the exists-branch (:47-:49)
   * keeps the full attacker path, so the wrapper as a whole is not a
   * barrier (modeled as propagation, not sanitization).
   */
  private predicate getScriptPathCallSiteStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      inModule(c, "%/ganga/GPIDev/Persistency/__init__.py") and
      c.getLocation().getStartLine() = 188 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "getScriptPath" and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * sink-396 (summary/tp 0.85), edge 2 of 2: the def-side form.
   *
   * GangaCore/Utility/Runtime.py:47 (getScriptPath):
   *   fullName = os.path.expanduser(os.path.expandvars(name))
   *
   * Edge: the `name` parameter of getScriptPath -> the OUTER call
   * expression (the os.path.expanduser call at :47, whose value flows to
   * fullName -> scriptPath at :49 -> the return at :61 on the
   * exists-branch). Keeps the parameter -> return propagation connected
   * inside the callee regardless of whether the cross-module call at
   * Persistency:188 resolves or the expanduser/expandvars nesting carries
   * taint by default. Both endpoints are inside the reviewed wrapper.
   */
  private predicate getScriptPathDefSideStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call expanduser, Attribute f, Attribute pathAttr, Name os, Function fn, Parameter p |
      inModule(expanduser, "%/ganga/GangaCore/Utility/Runtime.py") and
      expanduser.getLocation().getStartLine() = 47 and
      f = expanduser.getFunc().(Attribute) and
      f.getName() = "expanduser" and
      pathAttr = f.getObject().(Attribute) and
      pathAttr.getName() = "path" and
      os = pathAttr.getObject().(Name) and
      os.getId() = "os" and
      nodeTo.asExpr() = expanduser and
      inModule(fn, "%/ganga/GangaCore/Utility/Runtime.py") and
      fn.getName() = "getScriptPath" and
      p = fn.getArgByName("name") and
      nodeFrom = DataFlow::parameterNode(p)
    )
  }
}
