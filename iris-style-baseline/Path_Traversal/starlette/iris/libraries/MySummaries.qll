/**
 * Name: MySummaries
 * Description: Additional taint steps for the Augur IRIS pipeline, rendered
 *   from iris/labels/labels.json (Pass 1, pass key "path_traversal",
 *   starlette 0.26.1 / starlette_vuln).
 *
 * Every edge below is anchored to concrete statements in the audited source
 * tree - there are no unconditional node-to-node propagations. The steps
 * exist precisely where CodeQL's default Python data flow cannot follow the
 * real code:
 *
 *   1. get_path composite chain (label p1-s-116, with p1-k-024/p1-k-025):
 *      scope['path'] -> .split('/') -> starred os.path.join ->
 *      os.path.normpath -> return value (staticfiles.py:111).
 *   2. os.path.join path propagation inside the serving pipeline
 *      (p1-k-028 staticfiles.py:136, p1-k-033 staticfiles.py:166).
 *   3. os.path.abspath / os.path.realpath canonicalization
 *      (p1-k-034 staticfiles.py:168, p1-k-035 staticfiles.py:170) -
 *      taint-preserving transforms, NOT barriers.
 *   4. anyio.to_thread.run_sync(self.lookup_path, path) thread offload
 *      (p1-k-027 staticfiles.py:121, p1-k-029 staticfiles.py:137):
 *      argument 1 -> lookup_path's `path` parameter, and lookup_path's
 *      returned tuple elements -> the run_sync call result (incl. its
 *      await wrapper).
 *   5. FileResponse.__init__ `self.path = path` field store
 *      (responses.py:298) bridging the constructor's `path` parameter to
 *      the `self.path` reads in FileResponse.__call__ (responses.py:335/353).
 *
 * These steps also carry the propagation that labels p1-k-026 (get_response
 * `path`), p1-k-032 (lookup_path `path`) and p1-k-039 (file_response
 * `full_path`) intended to bridge: those internal wrapper parameters are
 * deliberately NOT rendered as sources (see MySources.qll), so the flow
 * runs from the true external boundary scope['path'] through these edges
 * into the sinks instead.
 *
 * Generated: 2026-10-23, Augur Phase 2 Step 4 (labels v1.0.0,
 * run starlette-pathtraversal-pass1-step3-20261023, model glm-5.3).
 */

import python
import semmle.python.dataflow.new.DataFlow

private predicate inStarletteLibrary(AstNode n) {
  n.getLocation().getFile().getRelativePath().matches("starlette/%") or
  n.getLocation().getFile().getAbsolutePath().matches("%/starlette/%")
}

private predicate inFile(AstNode n, string baseName) {
  n.getLocation().getFile().getBaseName() = baseName
}

/** Matches `os.path.<name>` call sites syntactically. */
private predicate isOsPathCall(Call c, string name) {
  c.getFunc().(Attribute).getName() = name and
  c.getFunc().(Attribute).getObject().(Attribute).getName() = "path" and
  c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "os"
}

module MySummaries {
  /** Holds if taint may flow from `nodeFrom` to `nodeTo` in addition to the normal data-flow steps (pass 1). */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    (
      get_pathChainStep(nodeFrom, nodeTo)
      or pathJoinStep(nodeFrom, nodeTo)
      or canonicalizeStep(nodeFrom, nodeTo)
      or threadOffloadArgStep(nodeFrom, nodeTo)
      or threadOffloadReturnStep(nodeFrom, nodeTo)
      or fileResponseFieldStep(nodeFrom, nodeTo)
    )
  }

  /**
   * StaticFiles.get_path composite chain (statement-local, real code):
   * the scope['path'] subscript is transformed by .split('/'), the starred
   * os.path.join(*...) unpack and os.path.normpath, and returned.
   * Labels: p1-s-116 (get_path scope param -> return, summary/tp 0.90),
   * p1-k-025 (join, :111), p1-k-024 (normpath, :111).
   * Evidence: staticfiles.py:106-111 - exactly one scope['path'] subscript
   * and one return in get_path:
   *   return os.path.normpath(os.path.join(*scope["path"].split("/")))
   */
  private predicate get_pathChainStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function get_path, Return r, Subscript sub |
      get_path.getName() = "get_path" and
      inStarletteLibrary(get_path) and
      inFile(get_path, "staticfiles.py") and
      r.getScope() = get_path and
      sub.getScope() = get_path and
      sub.getIndex().(StringLiteral).getText() = "path" and
      sub.getObject().(Name).getId() = "scope" and
      nodeFrom.asExpr() = sub and
      nodeTo.asExpr() = r.getValue()
    )
  }

  /**
   * os.path.join inside the serving pipeline:
   *   - staticfiles.py:136 get_response: join(path, "index.html")
   *     argument 0 (attacker path) -> result. Label: p1-k-028.
   *   - staticfiles.py:166 lookup_path: join(directory, path)
   *     argument 1 (attacker path) -> result. Label: p1-k-033.
   * The join itself performs no file access; the propagation is required
   * because CodeQL does not model os.path.join argument-to-result taint.
   * Evidence: staticfiles.py:136, :166.
   */
  private predicate pathJoinStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call join, Function f |
      isOsPathCall(join, "join") and
      join.getScope().(Function) = f and
      inStarletteLibrary(join) and
      inFile(join, "staticfiles.py") and
      nodeTo.asExpr() = join and
      (
        (
          f.getName() = "get_response" and
          nodeFrom.asExpr() = join.getPositionalArg(0)
        )
        or
        (
          f.getName() = "lookup_path" and
          nodeFrom.asExpr() = join.getPositionalArg(1)
        )
      )
    )
  }

  /**
   * Canonicalization inside StaticFiles.lookup_path: os.path.abspath
   * (follow_symlink=True branch, staticfiles.py:168) and os.path.realpath
   * (default branch, staticfiles.py:170) argument 0 -> result.
   * Labels: p1-k-034 (abspath, 0.75 - no containment check on that branch),
   * p1-k-035 (realpath, 0.80). Taint-preserving: the resolved path still
   * derives from the attacker-controlled request path. The realpath at
   * :171 (operator directory) shares the call shape and is harmless.
   * Evidence: staticfiles.py:167-171.
   */
  private predicate canonicalizeStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call call, Function lookup |
      isOsPathCall(call, "abspath") or isOsPathCall(call, "realpath")
      |
      lookup.getName() = "lookup_path" and
      inStarletteLibrary(lookup) and
      inFile(lookup, "staticfiles.py") and
      call.getScope() = lookup and
      nodeFrom.asExpr() = call.getPositionalArg(0) and
      nodeTo.asExpr() = call
    )
  }

  /**
   * Thread offload into StaticFiles.lookup_path:
   * anyio.to_thread.run_sync(self.lookup_path, X) at staticfiles.py:121
   * (path), :137 (index_path) and :150 (literal '404.html', no taint):
   * argument 1 -> lookup_path's `path` parameter (position 1).
   * Labels: p1-k-027, p1-k-029 (p1-k-030 is the fixed-literal site).
   * Evidence: staticfiles.py:121-123, :137-139, :150-152, :162-163;
   * the first positional argument is constrained to self.lookup_path so
   * the os.stat offload at staticfiles.py:209 is NOT matched.
   */
  private predicate threadOffloadArgStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call run_sync, Function lookup, Parameter pathParam |
      run_sync.getFunc().(Attribute).getName() = "run_sync" and
      run_sync.getPositionalArg(0).(Attribute).getName() = "lookup_path" and
      inStarletteLibrary(run_sync) and
      inFile(run_sync, "staticfiles.py") and
      lookup.getName() = "lookup_path" and
      inStarletteLibrary(lookup) and
      inFile(lookup, "staticfiles.py") and
      pathParam = lookup.getArg(1) and
      nodeFrom.asExpr() = run_sync.getPositionalArg(1) and
      nodeTo = DataFlow::parameterNode(pathParam)
    )
  }

  /**
   * Thread offload back out of StaticFiles.lookup_path: the elements of
   * lookup_path's returned tuple (full_path, os.stat(full_path)) flow to
   * the anyio.to_thread.run_sync call result (and its await wrapper).
   * Evidence: staticfiles.py:180 (return full_path, os.stat(full_path)),
   * :121/:137/:150 - the result is unpacked as
   *   full_path, stat_result = await anyio.to_thread.run_sync(...).
   */
  private predicate threadOffloadReturnStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call run_sync, Function lookup, Return r |
      run_sync.getFunc().(Attribute).getName() = "run_sync" and
      run_sync.getPositionalArg(0).(Attribute).getName() = "lookup_path" and
      inStarletteLibrary(run_sync) and
      inFile(run_sync, "staticfiles.py") and
      lookup.getName() = "lookup_path" and
      inStarletteLibrary(lookup) and
      inFile(lookup, "staticfiles.py") and
      r.getScope() = lookup and
      nodeFrom.asExpr() = r.getValue().(Tuple).getAnElt() and
      (
        nodeTo.asExpr() = run_sync
        or
        exists(Await aw | aw.getValue() = run_sync | nodeTo.asExpr() = aw)
      )
    )
  }

  /**
   * FileResponse field store: __init__ assigns self.path = path
   * (responses.py:298); the `path` parameter (position 1) flows to the
   * self.path attribute reads in FileResponse.__call__
   * (responses.py:335 run_sync(os.stat, self.path) and :353
   * anyio.open_file(self.path, mode='rb')).
   * Justification: real field store; CodeQL's Python data flow does not
   * reliably track attribute stores into reads across methods of the same
   * class. Label chain: p1-k-016 (param sink) -> p1-k-017/p1-k-018
   * (self.path sinks). Evidence: responses.py:286-298, :332-356.
   */
  private predicate fileResponseFieldStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Parameter p, Function init, Function callFn, Attribute attr |
      init.getName() = "__init__" and
      init.getAnArg() = p and
      p.getName() = "path" and
      init.getEnclosingScope().(Class).getName() = "FileResponse" and
      inStarletteLibrary(init) and
      inFile(init, "responses.py") and
      callFn.getName() = "__call__" and
      callFn.getEnclosingScope().(Class).getName() = "FileResponse" and
      inStarletteLibrary(callFn) and
      inFile(callFn, "responses.py") and
      attr.getName() = "path" and
      attr.getObject().(Name).getId() = "self" and
      attr.getScope() = callFn and
      nodeFrom = DataFlow::parameterNode(p) and
      nodeTo.asExpr() = attr
    )
  }
}
