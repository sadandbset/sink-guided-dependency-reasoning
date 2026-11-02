/**
 * Augur Phase 2 Step 4 - Pass 1 (Path Traversal) summary library for dfetch.
 *
 * Deterministically rendered from iris/labels/labels.json (run
 * iris-dfetch-pathtraversal-pass1-20261022): each additional taint step below
 * corresponds to reviewed pass-1 entries with role `summary` (33 tp rows) or
 * to the propagation documented in a reviewed source/sink label's evidence
 * chain. Every step is evidence-based on the real dfetch code: object field
 * hops through property getters, the pathlib constructors, and the stdlib
 * path functions at their labeled call sites. No arbitrary-node-to-node
 * propagation is created, and no step is added for a label that was reviewed
 * as none/fp.
 *
 * Rendered steps (label ids -> edge):
 *   E1   src-033 (project.py:268)                yamldata[key] -> reads of
 *        ProjectEntry properties .name/.destination/.source/.patch
 *        (project.py:326-343 property getters return the yamldata fields)
 *   E2   sink-013 chain (project.py:246 + vcs.py:177-180)
 *        kwargs.get("dst") -> reads of .destination (ProjectEntry state)
 *   E3   sink-014 chain (project.py:245 + vcs.py:198-200)
 *        kwargs.get("src") -> reads of .source
 *   E4   sink-016 chain (project.py:248 + vcs.py:117-141)
 *        kwargs.get("patch") -> reads of .patch
 *   E5   vcs.py:177-180 (VCS.local_path getter) read of
 *        self.__project.destination -> reads of self.local_path
 *   E6   vcs.py:198-200 (VCS.source getter) read of self.__project.source
 *        -> reads of self.source in dfetch/project/**
 *   E7   sink-025 (metadata.py:46 + 125-134) kwargs.get("destination") ->
 *        reads of self._destination in the Metadata.path getter AND reads
 *        of the Metadata.path property (.path on self / self.__metadata /
 *        the from_project_entry result)
 *   E8   sink-013 (vcs/git.py:114-117) GitLocalRepo.__init__ path parameter
 *        -> reads of self._path in dfetch/vcs/git.py
 *   E9   sink-055/sink-060/sink-021 pathlib.Path/PurePath constructor
 *        argument -> constructor result (project/git.py:70,
 *        project/svn.py:196, vcs/git.py:170)
 *   E10  reviewed os.path.join/dirname/realpath/basename summary sites
 *        (metadata.py:129/:131/:132/:133, vcs/git.py:162/:237, svn.py:70,
 *        project/git.py:80, util.py:25/:51/:95): argument -> result.
 *        These mirror pure stdlib semantics at the labeled sites so the
 *        chains do not depend on stdlib model availability.
 *
 * Explicitly NOT created (documented in report/query_generation_notes.md):
 *  - any edge from the git/svn subprocess stdout sources across the
 *    process boundary (a 'dfetch import' run WRITES the manifest to disk;
 *    the next 'dfetch update' re-parses it - two separate CLI invocations,
 *    not one dataflow path; the intra-update half is covered by the
 *    manifest sources);
 *  - any VCS.metadata_path hop (vcs.py:188-190): its consumers pass the
 *    path to 'git log --' (Pass 2 command material), not to a Pass 1 sink;
 *  - the property getters of Remote (url material, reviewed fp for this
 *    pass).
 */

import python

import semmle.python.dataflow.new.DataFlow

module MySummaries {

  /** Forward-slash-normalized absolute path of the file containing n
   *  (same helper shape as the extraction queries). */
  private string normalizedPathOf(AstNode n) {
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
  }

  bindingset[modulePathPattern]
  private predicate inModule(AstNode n, string modulePathPattern) {
    normalizedPathOf(n).matches(modulePathPattern)
  }

  /* ------------------------------------------------------------------ */
  /* E1: ProjectEntry manifest fields -> property getter read sites      */
  /* ------------------------------------------------------------------ */

  /** Attribute read of a ProjectEntry property whose value is a manifest
   *  field: .name / .destination / .source / .patch (the property getters
   *  at project.py:326-343 return exactly these fields). Only reads inside
   *  the dfetch package are connected. */
  private predicate isProjectEntryPropertyRead(Attribute read) {
    (
      read.getName() = "name"
      or
      read.getName() = "destination"
      or
      read.getName() = "source"
      or
      read.getName() = "patch"
    ) and
    inModule(read, "%/dfetch/%")
  }

  /** E1 (label src-033): the per-field manifest value read
   *  yamldata[key] in ProjectEntry.from_yaml (project.py:268) is the
   *  provenance of every ProjectEntry field, so manifest taint flows to
   *  the property read sites. */
  private predicate fromYamldataToPropertyRead(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Subscript s, Attribute read |
      s.getObject().(Name).getId() = "yamldata" and
      inModule(s, "%/dfetch/manifest/project.py") and
      s = nodeFrom.asExpr().(Subscript) and
      read = nodeTo.asExpr().(Attribute) and
      isProjectEntryPropertyRead(read)
    )
  }

  /** E2/E3/E4 (labels src-028/src-027/src-029): kwargs.get("dst"/"src"/
   *  "patch") in ProjectEntry.__init__ (project.py:245/246/248) stores the
   *  manifest path fields into ProjectEntry state; each key flows to its
   *  matching property read (dst -> .destination, src -> .source, patch ->
   *  .patch; project.py:331-343). */
  private predicate fromManifestPathFieldToPropertyRead(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute func, StringLiteral key, Attribute read |
      func = c.getFunc().(Attribute) and
      func.getName() = "get" and
      func.getObject().(Name).getId() = "kwargs" and
      key = c.getArg(0).(StringLiteral) and
      inModule(c, "%/dfetch/manifest/project.py") and
      c = nodeFrom.asExpr().(Call) and
      read = nodeTo.asExpr().(Attribute) and
      isProjectEntryPropertyRead(read) and
      (
        key.getText() = "dst" and read.getName() = "destination"
        or
        key.getText() = "src" and read.getName() = "source"
        or
        key.getText() = "patch" and read.getName() = "patch"
      )
    )
  }

  /* ------------------------------------------------------------------ */
  /* E5/E6: VCS property getters (vcs.py:177-180 / 198-200)              */
  /* ------------------------------------------------------------------ */

  /** E5 (VCS.local_path, vcs.py:177-180): taint on the
   *  self.__project.destination read inside the getter flows to every
   *  self.local_path read (the property's value). The from-node is the
   *  destination read at vcs.py:180 (itself a to-node of E1/E2). */
  private predicate fromProjectDestinationToLocalPath(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Attribute destRead, Attribute localPathRead |
      destRead.getName() = "destination" and
      destRead.getObject().(Attribute).getName() = "__project" and
      inModule(destRead, "%/dfetch/project/vcs.py") and
      destRead = nodeFrom.asExpr().(Attribute) and
      localPathRead.getName() = "local_path" and
      localPathRead.getObject().(Name).getId() = "self" and
      inModule(localPathRead, "%/dfetch/%") and
      localPathRead = nodeTo.asExpr().(Attribute)
    )
  }

  /** E6 (VCS.source, vcs.py:198-200): taint on the self.__project.source
   *  read inside the getter flows to every self.source read in
   *  dfetch/project/** (SvnRepo._fetch_impl, GitRepo._fetch_impl pass
   *  self.source into the fetch pipelines). */
  private predicate fromProjectSourceToVcsSource(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Attribute srcRead, Attribute vcsSourceRead |
      srcRead.getName() = "source" and
      srcRead.getObject().(Attribute).getName() = "__project" and
      inModule(srcRead, "%/dfetch/project/vcs.py") and
      srcRead = nodeFrom.asExpr().(Attribute) and
      vcsSourceRead.getName() = "source" and
      vcsSourceRead.getObject().(Name).getId() = "self" and
      inModule(vcsSourceRead, "%/dfetch/project/%") and
      vcsSourceRead = nodeTo.asExpr().(Attribute)
    )
  }

  /* ------------------------------------------------------------------ */
  /* E7: Metadata destination -> Metadata.path (metadata.py:46,125-134)  */
  /* ------------------------------------------------------------------ */

  /** E7 (label src-025/sink-025 chain): kwargs.get("destination") in
   *  Metadata.__init__ (metadata.py:46) feeds Metadata.path - either the
   *  self._destination reads inside the path getter (metadata.py:128-133,
   *  where join/realpath build the final location) or the .path property
   *  read sites enumerated by the reviewed labels (metadata.py:165
   *  self.path; project/vcs.py:129/:188/:190/:232/:244 self.__metadata.path;
   *  commands/report.py:105 .path on the from_project_entry result). */
  private predicate fromMetadataDestinationToPath(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute func, StringLiteral key, Attribute pathRead |
      func = c.getFunc().(Attribute) and
      func.getName() = "get" and
      func.getObject().(Name).getId() = "kwargs" and
      key = c.getArg(0).(StringLiteral) and
      key.getText() = "destination" and
      inModule(c, "%/dfetch/project/metadata.py") and
      c = nodeFrom.asExpr().(Call) and
      pathRead = nodeTo.asExpr().(Attribute) and
      (
        /* self._destination read inside the Metadata.path getter */
        (
          pathRead.getName() = "_destination" and
          pathRead.getObject().(Name).getId() = "self" and
          inModule(pathRead, "%/dfetch/project/metadata.py")
        )
        or
        /* Metadata.path property read sites (labels: metadata.py:165,
           vcs.py:129/188/190/232/244, report.py:105) */
        (
          pathRead.getName() = "path" and
          (
            inModule(pathRead, "%/dfetch/project/metadata.py")
            or
            inModule(pathRead, "%/dfetch/project/vcs.py")
            or
            inModule(pathRead, "%/dfetch/commands/report.py")
          )
        )
      )
    )
  }

  /* ------------------------------------------------------------------ */
  /* E8: GitLocalRepo path parameter -> self._path reads                */
  /* ------------------------------------------------------------------ */

  /** E8 (label sink-013): the `path` parameter of GitLocalRepo.__init__
   *  (vcs/git.py:114, called with self.local_path at project/git.py:27 and
   *  with join(os.getcwd(), sm_path) at vcs/git.py:236-237) is stored as
   *  self._path and read at vcs/git.py:121/:142/:178/:198/:285/:288 - the
   *  in_directory()/chdir and '.git' join consumers. */
  private predicate fromGitLocalRepoPathParamToFieldRead(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Parameter p, Function f, Attribute fieldRead |
      f.getName() = "__init__" and
      inModule(f, "%/dfetch/vcs/git.py") and
      f.getEnclosingScope() instanceof Class and
      f.getEnclosingScope().(Class).getName() = "GitLocalRepo" and
      p = f.getAnArg() and
      p.getName() = "path" and
      not p.isSelf() and
      p = nodeFrom.asExpr().(Parameter) and
      fieldRead.getName() = "_path" and
      fieldRead.getObject().(Name).getId() = "self" and
      inModule(fieldRead, "%/dfetch/vcs/git.py") and
      fieldRead = nodeTo.asExpr().(Attribute)
    )
  }

  /* ------------------------------------------------------------------ */
  /* E9: pathlib constructors (labels sink-055/sink-060/sink-021)        */
  /* ------------------------------------------------------------------ */

  /** E9: pathlib.Path(...) / pathlib.PurePath(...) argument -> constructor
   *  result, at the reviewed sites only (project/git.py:70,
   *  project/svn.py:196, vcs/git.py:170 - the mkdir receivers and the
   *  PurePath(src).parts[0] amplifier). Pure path-object conversion, no
   *  content transformation. */
  private predicate isReviewedPathlibCtor(Call c) {
    (
      c.getFunc().(Attribute).getName() = "Path" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "pathlib"
      or
      c.getFunc().(Attribute).getName() = "PurePath" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "pathlib"
      or
      c.getFunc().(Name).getId() = "PurePath"
    ) and
    (
      inModule(c, "%/dfetch/project/git.py")
      or
      inModule(c, "%/dfetch/project/svn.py")
      or
      inModule(c, "%/dfetch/vcs/git.py")
    )
  }

  private predicate fromPathlibArgToResult(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      isReviewedPathlibCtor(c) and
      nodeFrom.asExpr() = c.getAnArg() and
      nodeTo.asExpr() = c
    )
  }

  /* ------------------------------------------------------------------ */
  /* E10: stdlib path functions at the reviewed summary sites            */
  /* ------------------------------------------------------------------ */

  /** E10: os.path.join / os.path.dirname / os.path.realpath /
   *  os.path.basename argument -> call result, restricted to the reviewed
   *  summary sites (metadata.py:129/:131/:132/:133, vcs/git.py:162/:237,
   *  project/svn.py:70, project/git.py:80, util/util.py:25/:51/:95).
   *  Pure path-text semantics - these propagate the attacker-controlled
   *  component (including '..' and absolute prefixes, which os.path.join
   *  preserves) toward the dangerous sinks; they are flow steps, never
   *  barriers (see MySanitizers.qll). */
  private predicate isReviewedStdlibPathCall(Call c) {
    (
      (
        c.getFunc().(Attribute).getName() = "join" or
        c.getFunc().(Attribute).getName() = "dirname" or
        c.getFunc().(Attribute).getName() = "realpath" or
        c.getFunc().(Attribute).getName() = "basename"
      ) and
      c.getFunc().(Attribute).getObject().(Attribute).getName() = "path" and
      c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "os"
    ) and
    (
      inModule(c, "%/dfetch/project/metadata.py")
      or
      inModule(c, "%/dfetch/vcs/git.py")
      or
      inModule(c, "%/dfetch/project/svn.py")
      or
      inModule(c, "%/dfetch/project/git.py")
      or
      inModule(c, "%/dfetch/util/util.py")
    )
  }

  private predicate fromStdlibPathArgToResult(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      isReviewedStdlibPathCall(c) and
      nodeFrom.asExpr() = c.getAnArg() and
      nodeTo.asExpr() = c
    )
  }

  /** Pass-1 additional taint step. passKey is required to be
   *  "path_traversal". */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    (
      fromYamldataToPropertyRead(nodeFrom, nodeTo)
      or
      fromManifestPathFieldToPropertyRead(nodeFrom, nodeTo)
      or
      fromProjectDestinationToLocalPath(nodeFrom, nodeTo)
      or
      fromProjectSourceToVcsSource(nodeFrom, nodeTo)
      or
      fromMetadataDestinationToPath(nodeFrom, nodeTo)
      or
      fromGitLocalRepoPathParamToFieldRead(nodeFrom, nodeTo)
      or
      fromPathlibArgToResult(nodeFrom, nodeTo)
      or
      fromStdlibPathArgToResult(nodeFrom, nodeTo)
    )
  }
}
