/**
 * Augur Phase 2 Step 4 - Pass 1 (Path Traversal) sink library for dfetch.
 *
 * Deterministically rendered from iris/labels/labels.json (run
 * iris-dfetch-pathtraversal-pass1-20261022): every predicate below corresponds
 * to a reviewed pass-1 entry with role `sink` (15 tp + 1 candidate) and to no
 * other candidate. The 50 `none`/fp sink rows (stat-only probes, display-only
 * path functions, walked/literal-path reads and writes, operator-trusted
 * report output) are deliberately NOT matched.
 *
 * Reviewed sink entries rendered here (label id -> dangerous position):
 *   sink-059  commands/diff.py:171    open(patch_name,"w")      arg 0 (write)
 *   sink-015  vcs/git.py:149          open(sparse-checkout,"a") arg 0 (candidate)
 *   sink-020  vcs/git.py:169          shutil.move(src+...,".")  arg 0 (move)
 *   sink-054  project/git.py:70       Path(dst).mkdir(...)      receiver (dir create)
 *   sink-058  project/svn.py:196      Path(dirname(dst)).mkdir  receiver (dir create)
 *   sink-062  project/svn.py:206      os.remove(file)           arg 0 (delete)
 *   sink-064  project/svn.py:245      run_on_cmdline(...dst)    list elem "dst"
 *   sink-071  util/util.py:14         os.chmod(path,...)        arg 0 (perm change)
 *   sink-076  util/util.py:33         os.remove(path)           arg 0 (delete)
 *   sink-079  util/util.py:39         shutil.rmtree(path)       arg 0 (rec. delete)
 *   sink-083  util/util.py:52         os.chdir(path)            arg 0 (cwd escape)
 *   sink-093  util/util.py:107        open(file_path,"rb")      arg 0 (read)
 *   sink-081  project/metadata.py:70  open(path,"r")            arg 0 (read)
 *   sink-089  project/metadata.py:165 open(self.path,"w+")      arg 0 (write)
 *   sink-094  project/vcs.py:134      patch_ng fromfile(patch)  arg 0 (read/parse)
 *   sink-095  project/vcs.py:138      patch_set.apply(root=dst) root= keyword (write)
 *
 * Sinks are the actual file-access APIs at their dangerous path positions.
 * Pure path text operations (Path()/join()/dirname() construction nodes,
 * os.walk/listdir enumeration) are NOT sinks here - they are rendered as
 * propagation steps in MySummaries.qll per their reviewed `summary` labels,
 * and the path TEXT versus the opened/created file OBJECT distinction is kept
 * by anchoring each sink on the argument/receiver expression that names the
 * file location (never on the returned file object).
 *
 * Matching is AST-level (shapes already executed in extraction/sinks.ql on
 * this CLI/pack family), constrained to the module named by each reviewed
 * label; distinguishing argument shapes (Name "path" vs "pwd" for the two
 * chdir sites, Name vs Attribute for the two metadata open sites) keep the
 * pairs of look-alike rows apart.
 */

import python

import semmle.python.dataflow.new.DataFlow

module MySinks {

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
  /* File open (builtin) - 4 reviewed sites                             */
  /* ------------------------------------------------------------------ */

  /** sink-059: open(patch_name, "w") at commands/diff.py:171 - patch write
   *  at <project.name>.patch (manifest-name-controlled, f-string built at
   *  diff.py:114; the f-string itself is anchored by the open arg). */
  private predicate isPatchFileWrite(DataFlow::Node sink) {
    exists(Call c, Name arg |
      c.getFunc().(Name).getId() = "open" and
      arg = c.getArg(0).(Name) and
      arg.getId() = "patch_name" and
      inModule(c, "%/dfetch/commands/diff.py") and
      sink.asExpr() = arg
    )
  }

  /** sink-015 (classification candidate): open('.git/info/sparse-checkout',
   *  "a") at vcs/git.py:149 - the path argument is a fixed literal, so no
   *  taint can reach it; kept because the reviewed label kept it (the
   *  manifest-'src' CONTENT written here is the flagged channel, and that
   *  content is anchored at the MySources 'src' label instead). */
  private predicate isSparseCheckoutAppend(DataFlow::Node sink) {
    exists(Call c, StringLiteral arg |
      c.getFunc().(Name).getId() = "open" and
      arg = c.getArg(0).(StringLiteral) and
      arg.getText() = ".git/info/sparse-checkout" and
      inModule(c, "%/dfetch/vcs/git.py") and
      sink.asExpr() = arg
    )
  }

  /** sink-081: open(path, "r") at project/metadata.py:70 - metadata read at
   *  the dst-derived path (arg 0 is the Name "path" - the from_file
   *  parameter), distinguished from the self.path write at :165. */
  private predicate isMetadataRead(DataFlow::Node sink) {
    exists(Call c, Name arg |
      c.getFunc().(Name).getId() = "open" and
      arg = c.getArg(0).(Name) and
      arg.getId() = "path" and
      inModule(c, "%/dfetch/project/metadata.py") and
      sink.asExpr() = arg
    )
  }

  /** sink-089: open(self.path, "w+") at project/metadata.py:165 - metadata
   *  write at realpath(join(dst, '.dfetch_data.yaml')) (arg 0 is the
   *  self.path attribute read). */
  private predicate isMetadataWrite(DataFlow::Node sink) {
    exists(Call c, Attribute arg |
      c.getFunc().(Name).getId() = "open" and
      arg = c.getArg(0).(Attribute) and
      arg.getName() = "path" and
      inModule(c, "%/dfetch/project/metadata.py") and
      sink.asExpr() = arg
    )
  }

  /** sink-093: open(file_path, "rb") at util/util.py:107 - hash read under
   *  the walked destination root. */
  private predicate isHashFileRead(DataFlow::Node sink) {
    exists(Call c, Name arg |
      c.getFunc().(Name).getId() = "open" and
      arg = c.getArg(0).(Name) and
      arg.getId() = "file_path" and
      inModule(c, "%/dfetch/util/util.py") and
      sink.asExpr() = arg
    )
  }

  /* ------------------------------------------------------------------ */
  /* shutil / os destructive operations                                  */
  /* ------------------------------------------------------------------ */

  /** sink-020: shutil.move(src + "/" + file_to_copy, ".") at
   *  vcs/git.py:169 - moves the manifest-'src' subtree entries into the
   *  checkout root (arg 0 is the concatenated source path). */
  private predicate isSubtreeMove(DataFlow::Node sink) {
    exists(Call c, Attribute func |
      func = c.getFunc().(Attribute) and
      func.getName() = "move" and
      func.getObject().(Name).getId() = "shutil" and
      inModule(c, "%/dfetch/vcs/git.py") and
      sink.asExpr() = c.getArg(0)
    )
  }

  /** sink-062: os.remove(file) at project/svn.py:206 - deletes every
   *  non-matching file under the fetched destination (walk rooted at the
   *  manifest dst). */
  private predicate isSvnNonMatchingRemove(DataFlow::Node sink) {
    exists(Call c, Attribute func |
      func = c.getFunc().(Attribute) and
      func.getName() = "remove" and
      func.getObject().(Name).getId() = "os" and
      inModule(c, "%/dfetch/project/svn.py") and
      sink.asExpr() = c.getArg(0)
    )
  }

  /** sink-076: os.remove(path) at util/util.py:33 - the safe_rm deletion
   *  primitive (safe_rm(local_path) from vcs.py:105 carries the manifest
   *  dst). */
  private predicate isSafeRemove(DataFlow::Node sink) {
    exists(Call c, Attribute func |
      func = c.getFunc().(Attribute) and
      func.getName() = "remove" and
      func.getObject().(Name).getId() = "os" and
      inModule(c, "%/dfetch/util/util.py") and
      sink.asExpr() = c.getArg(0)
    )
  }

  /** sink-079: shutil.rmtree(path, onerror=...) at util/util.py:39 - the
   *  recursive delete reached with the manifest dst (vcs.py:105),
   *  <dst>/.git (project/git.py:80) and PurePath(src).parts[0]
   *  (vcs/git.py:170). The strongest Pass 1 sink. */
  private predicate isRecursiveDelete(DataFlow::Node sink) {
    exists(Call c, Attribute func |
      func = c.getFunc().(Attribute) and
      func.getName() = "rmtree" and
      func.getObject().(Name).getId() = "shutil" and
      inModule(c, "%/dfetch/util/util.py") and
      sink.asExpr() = c.getArg(0)
    )
  }

  /** sink-083: os.chdir(path) at util/util.py:52 - the in_directory CWD
   *  change (arg 0 is the Name "path"; the restore chdir(pwd) at :54 takes
   *  the saved "pwd" and is NOT a sink). */
  private predicate isWorkingDirChange(DataFlow::Node sink) {
    exists(Call c, Attribute func, Name arg |
      func = c.getFunc().(Attribute) and
      func.getName() = "chdir" and
      func.getObject().(Name).getId() = "os" and
      arg = c.getArg(0).(Name) and
      arg.getId() = "path" and
      inModule(c, "%/dfetch/util/util.py") and
      sink.asExpr() = arg
    )
  }

  /** sink-071: os.chmod(path, stat.S_IWUSR) at util/util.py:14 - the
   *  rmtree onerror re-permissioning (arg 0 is the Name "path"). */
  private predicate isChmodOnDelete(DataFlow::Node sink) {
    exists(Call c, Attribute func, Name arg |
      func = c.getFunc().(Attribute) and
      func.getName() = "chmod" and
      func.getObject().(Name).getId() = "os" and
      arg = c.getArg(0).(Name) and
      arg.getId() = "path" and
      inModule(c, "%/dfetch/util/util.py") and
      sink.asExpr() = arg
    )
  }

  /* ------------------------------------------------------------------ */
  /* Directory creation (pathlib mkdir - the path is the RECEIVER)       */
  /* ------------------------------------------------------------------ */

  /** sink-054: pathlib.Path(self.local_path).mkdir(parents=True,
   *  exist_ok=True) at project/git.py:70 - creates the manifest dst and
   *  every missing parent anywhere the path points. The dangerous position
   *  is the receiver (the pathlib.Path(...) construction), not an argument
   *  of the mkdir call. */
  private predicate isDstDirCreate(DataFlow::Node sink) {
    exists(Call mkdir, Attribute func |
      func = mkdir.getFunc().(Attribute) and
      func.getName() = "mkdir" and
      inModule(mkdir, "%/dfetch/project/git.py") and
      sink.asExpr() = func.getObject()
    )
  }

  /** sink-058: pathlib.Path(os.path.dirname(self.local_path)).mkdir(
   *  parents=True, exist_ok=True) at project/svn.py:196 - creates the dst
   *  parent chain (receiver position, same as sink-054). */
  private predicate isDstParentDirCreate(DataFlow::Node sink) {
    exists(Call mkdir, Attribute func |
      func = mkdir.getFunc().(Attribute) and
      func.getName() = "mkdir" and
      inModule(mkdir, "%/dfetch/project/svn.py") and
      sink.asExpr() = func.getObject()
    )
  }

  /* ------------------------------------------------------------------ */
  /* Process file write (svn export) and patch application               */
  /* ------------------------------------------------------------------ */

  /** sink-064: run_on_cmdline(logger, ['svn','export','--force'] +
   *  rev.split(' ') + [url, dst]) at project/svn.py:243-246 - the svn
   *  process writes the exported tree at dst (the `_export` parameter used
   *  as the final list element, svn.py:245). The reviewed label documents
   *  positional index 6 of the flattened list; the dst element is matched
   *  structurally as the Name "dst" inside the argument list of the
   *  run_on_cmdline call in SvnRepo._export. */
  private predicate isSvnExportDst(DataFlow::Node sink) {
    exists(Call c, Name dstElem |
      c.getFunc().(Name).getId() = "run_on_cmdline" and
      dstElem.getId() = "dst" and
      inModule(c, "%/dfetch/project/svn.py") and
      dstElem.getScope().(Function).getName() = "_export" and
      sink.asExpr() = dstElem
    )
  }

  /** sink-094: patch_ng.fromfile(self.__project.patch) at
   *  project/vcs.py:134 - reads and parses the manifest-designated patch
   *  file (arbitrary-path read/parse). */
  private predicate isPatchFileRead(DataFlow::Node sink) {
    exists(Call c |
      c.getFunc().(Name).getId() = "fromfile" and
      inModule(c, "%/dfetch/project/vcs.py") and
      sink.asExpr() = c.getArg(0)
    )
  }

  /** sink-095: patch_set.apply(0, root=self.local_path, fuzz=True) at
   *  project/vcs.py:138 - applies the patch writing target files under the
   *  manifest dst. The dangerous position is the `root=` KEYWORD value
   *  (there is no positional index; the reviewed label records
   *  flow_kind "unknown" for this reason). */
  private predicate isPatchApplyRoot(DataFlow::Node sink) {
    exists(Call c, Attribute func, Keyword rootKw |
      func = c.getFunc().(Attribute) and
      func.getName() = "apply" and
      inModule(c, "%/dfetch/project/vcs.py") and
      rootKw = c.getAKeyword() and
      rootKw.getArg() = "root" and
      sink.asExpr() = rootKw.getValue()
    )
  }

  /** Pass-1 sink predicate. passKey is required to be "path_traversal". */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and
    (
      isPatchFileWrite(sink)
      or
      isSparseCheckoutAppend(sink)
      or
      isMetadataRead(sink)
      or
      isMetadataWrite(sink)
      or
      isHashFileRead(sink)
      or
      isSubtreeMove(sink)
      or
      isSvnNonMatchingRemove(sink)
      or
      isSafeRemove(sink)
      or
      isRecursiveDelete(sink)
      or
      isWorkingDirChange(sink)
      or
      isChmodOnDelete(sink)
      or
      isDstDirCreate(sink)
      or
      isDstParentDirCreate(sink)
      or
      isSvnExportDst(sink)
      or
      isPatchFileRead(sink)
      or
      isPatchApplyRoot(sink)
    )
  }
}
