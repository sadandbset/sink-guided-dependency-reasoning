/**
 * Name: MySinks
 * Description: Sink predicates for the Augur IRIS pipeline, rendered
 *   deterministically from iris/labels/labels.json (Pass 1, pass key
 *   "path_traversal", starlette 0.26.1 / starlette_vuln).
 *
 * Sinks are the dangerous path-argument positions of REAL file access /
 * file response APIs (open, stat, isdir/isfile, FileResponse construction
 * and its path parameter, jinja2 template loading). Pure path text
 * operations (join / normpath / realpath) are not sinks - they are modeled
 * in MySummaries.qll. File-object operations on already-opened handles
 * (file.read etc.) are excluded: the path decision is made at open time,
 * and the open file object is distinct from the path text.
 *
 * Rendered labels: 19 sink-role entries (5 tp, 10 fp, 4 candidate). The
 * fp entries (operator-configured paths: Config env_file, StaticFiles
 * bootstrap checks, template directory) have no untrusted source reaching
 * them in this codebase and are rendered for label fidelity; any alert
 * they could produce is expected to be filtered at Step 6.
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

/** Matches `os.path.<name>` call sites syntactically (os.path.join/normpath/abspath/realpath/isdir/isfile). */
private predicate isOsPathCall(Call c, string name) {
  c.getFunc().(Attribute).getName() = name and
  c.getFunc().(Attribute).getObject().(Attribute).getName() = "path" and
  c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "os"
}

module MySinks {
  /** Holds if `node` is a pass-1 (path_traversal) taint sink per the reviewed labels. */
  predicate isSink(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    (
      anyioOpenFileSink(node)
      or osStatSink(node)
      or runSyncStatSink(node)
      or fileResponseCtorSink(node)
      or fileResponsePathParamSink(node)
      or builtinOpenSink(node)
      or osPathIsfileSink(node)
      or osPathIsdirSink(node)
      or configEnvFileParamSink(node)
      or configReadFileParamSink(node)
      or jinja2LoaderSink(node)
      or getTemplateCallSink(node)
      or templateParamSink(node)
    )
  }

  /**
   * anyio.open_file(self.path, mode='rb') - THE actual file open for HTTP
   * serving. Dangerous path argument index 0.
   * Label: p1-k-018 (responses.py:353, sink/tp, conf 0.95).
   * Evidence: responses.py:352-356 (FileResponse.__call__ chunked read loop).
   */
  private predicate anyioOpenFileSink(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c.getPositionalArg(0) and
      c.getFunc().(Attribute).getName() = "open_file" and
      inStarletteLibrary(c) and
      inFile(c, "responses.py")
    )
  }

  /**
   * os.stat(full_path) in StaticFiles.lookup_path - first filesystem
   * metadata access on the serving path (after the bypassable containment
   * check). Dangerous path argument index 0.
   * Label: p1-k-038 (staticfiles.py:177, sink/tp, conf 0.85).
   * Evidence: staticfiles.py:166-177.
   */
  private predicate osStatSink(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c.getPositionalArg(0) and
      c.getFunc().(Attribute).getName() = "stat" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
      inStarletteLibrary(c) and
      inFile(c, "staticfiles.py")
    )
  }

  /**
   * anyio.to_thread.run_sync(os.stat, self.path) - FileResponse.__call__
   * re-stat offloaded to a thread. Dangerous path argument index 1
   * (argument 0 is the os.stat callable itself, not a path).
   * Labels: p1-k-017 (responses.py:335, sink/tp, conf 0.80 - TOCTOU window
   * vs the staticfiles.py:170-177 check), p1-k-041 (staticfiles.py:209,
   * sink/fp - check_config stats the operator-configured self.directory).
   * Evidence: responses.py:333-342, staticfiles.py:199-217.
   */
  private predicate runSyncStatSink(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c.getPositionalArg(1) and
      c.getFunc().(Attribute).getName() = "run_sync" and
      c.getPositionalArg(0).(Attribute).getName() = "stat" and
      c.getPositionalArg(0).(Attribute).getObject().(Name).getId() = "os" and
      inStarletteLibrary(c) and
      (
        inFile(c, "responses.py") or inFile(c, "staticfiles.py")
      )
    )
  }

  /**
   * FileResponse(full_path, ...) construction in the StaticFiles serving
   * path; FileResponse.__call__ re-stats and opens the file.
   * Dangerous path argument index 0.
   * Labels: p1-k-040 (staticfiles.py:192, sink/tp, conf 0.90 - main serving
   * path), p1-k-031 (staticfiles.py:154, sink/fp - fixed literal '404.html'
   * lookup, fixed filename mapping).
   * Evidence: staticfiles.py:192-194, :148-159; responses.py:332-366.
   */
  private predicate fileResponseCtorSink(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c.getPositionalArg(0) and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "FileResponse" and
      inStarletteLibrary(c) and
      inFile(c, "staticfiles.py")
    )
  }

  /**
   * FileResponse.__init__ `path` parameter (position 1, 0-based including
   * self): stored to self.path (responses.py:298) and consumed by
   * os.stat / anyio.open_file in __call__. Definition-side sink.
   * Label: p1-k-016 (responses.py:288, sink/tp, conf 0.85).
   * Evidence: responses.py:286-298, :335, :353; reached from
   * StaticFiles.file_response (staticfiles.py:192).
   */
  private predicate fileResponsePathParamSink(DataFlow::Node node) {
    exists(Parameter p, Function init |
      node = DataFlow::parameterNode(p) and
      init.getAnArg() = p and
      p.getName() = "path" and
      init.getName() = "__init__" and
      init.getEnclosingScope().(Class).getName() = "FileResponse" and
      inStarletteLibrary(init) and
      inFile(init, "responses.py")
    )
  }

  /**
   * builtin open(file_name) in Config._read_file - env-file read.
   * Dangerous path argument index 0.
   * Label: p1-k-004 (config.py:121, sink/fp: path provenance is the
   * operator-configured env_file, no untrusted source reaches it in-tree).
   * Evidence: config.py:119-129.
   */
  private predicate builtinOpenSink(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c.getPositionalArg(0) and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "open" and
      inStarletteLibrary(c) and
      inFile(c, "config.py")
    )
  }

  /**
   * os.path.isfile(env_file) in Config.__init__. Argument index 0.
   * Label: p1-k-002 (config.py:62, sink/fp - operator-configured path).
   * Evidence: config.py:62-63.
   */
  private predicate osPathIsfileSink(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c.getPositionalArg(0) and
      isOsPathCall(c, "isfile") and
      inStarletteLibrary(c) and
      inFile(c, "config.py")
    )
  }

  /**
   * os.path.isdir(directory) - StaticFiles constructor / package statics
   * bootstrap checks. Argument index 0.
   * Labels: p1-k-020 (staticfiles.py:56, sink/fp), p1-k-023
   * (staticfiles.py:85, sink/fp) - operator input at construction time.
   * Evidence: staticfiles.py:56-57, :82-87.
   */
  private predicate osPathIsdirSink(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c.getPositionalArg(0) and
      isOsPathCall(c, "isdir") and
      inStarletteLibrary(c) and
      inFile(c, "staticfiles.py")
    )
  }

  /**
   * Config.__init__ env_file parameter (position 1) - the operator-
   * configured env-file path consumed via os.path.isfile/open.
   * Label: p1-k-001 (config.py:55, sink/fp).
   * Evidence: config.py:53-63.
   */
  private predicate configEnvFileParamSink(DataFlow::Node node) {
    exists(Parameter p, Function init |
      node = DataFlow::parameterNode(p) and
      init.getAnArg() = p and
      p.getName() = "env_file" and
      init.getName() = "__init__" and
      init.getEnclosingScope().(Class).getName() = "Config" and
      inStarletteLibrary(init) and
      inFile(init, "config.py")
    )
  }

  /**
   * Config._read_file file_name parameter (position 1) - definition-side
   * sink for the env-file open().
   * Label: p1-k-003 (config.py:119, sink/fp).
   * Evidence: config.py:119-121.
   */
  private predicate configReadFileParamSink(DataFlow::Node node) {
    exists(Parameter p, Function fn |
      node = DataFlow::parameterNode(p) and
      fn.getAnArg() = p and
      p.getName() = "file_name" and
      fn.getName() = "_read_file" and
      inStarletteLibrary(fn) and
      inFile(fn, "config.py")
    )
  }

  /**
   * jinja2.FileSystemLoader(directory) - operator-configured template
   * root; actual template loads happen inside jinja2 (outside the DB).
   * Argument index 0.
   * Label: p1-k-043 (templating.py:85, sink/fp).
   * Evidence: templating.py:77-91.
   */
  private predicate jinja2LoaderSink(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c.getPositionalArg(0) and
      c.getFunc().(Attribute).getName() = "FileSystemLoader" and
      inStarletteLibrary(c) and
      inFile(c, "templating.py")
    )
  }

  /**
   * env.get_template(name) / self.get_template(name) call sites - template
   * name joined onto the loader directory inside jinja2. Argument index 0.
   * Labels: p1-k-045 (templating.py:94, sink/candidate), p1-k-047
   * (templating.py:112, sink/candidate) - no in-tree request-derived name;
   * applications passing request-derived template names would be exposed.
   * Evidence: templating.py:93-94, :112.
   */
  private predicate getTemplateCallSink(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c.getPositionalArg(0) and
      c.getFunc().(Attribute).getName() = "get_template" and
      inStarletteLibrary(c) and
      inFile(c, "templating.py")
    )
  }

  /**
   * Definition-side template-name/directory parameters: Jinja2Templates
   * directory, get_template name, TemplateResponse name.
   * Labels: p1-k-042 (templating.py:67, sink/fp - operator template root),
   * p1-k-044 (templating.py:93, sink/candidate), p1-k-046 (templating.py:98,
   * sink/candidate).
   * Evidence: templating.py:65-74, :93, :96-113.
   */
  private predicate templateParamSink(DataFlow::Node node) {
    exists(Parameter p, Function fn |
      node = DataFlow::parameterNode(p) and
      fn.getAnArg() = p and
      (
        (
          fn.getName() = "__init__" and
          p.getName() = "directory" and
          fn.getEnclosingScope().(Class).getName() = "Jinja2Templates"
        )
        or
        (
          fn.getName() = "get_template" and p.getName() = "name"
        )
        or
        (
          fn.getName() = "TemplateResponse" and p.getName() = "name"
        )
      ) and
      inStarletteLibrary(fn) and
      inFile(fn, "templating.py")
    )
  }
}
