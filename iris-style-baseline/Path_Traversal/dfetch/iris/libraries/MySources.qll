/**
 * Augur Phase 2 Step 4 - Pass 1 (Path Traversal) source library for dfetch.
 *
 * Deterministically rendered from iris/labels/labels.json (run
 * iris-dfetch-pathtraversal-pass1-20261022): every predicate below corresponds
 * to a reviewed `source`/`tp` entry of pass_id 1 and to no other candidate.
 * The 50 `none`/fp source candidates of the pass (23 CLI/operator-boundary
 * rows, 8 non-path subprocess rows, 17 non-path manifest/metadata field rows,
 * 2 serialization rows) are deliberately NOT matched.
 *
 * Reviewed source entries rendered here (label id -> shape):
 *   src-022  manifest.py:139  yaml.safe_load        dfetch.yaml parse boundary
 *   src-023  manifest.py:129  loaded_yaml[...]      manifest root-dict read
 *   src-027  project.py:245   kwargs.get("src")     manifest 'src' field
 *   src-028  project.py:246   kwargs.get("dst")     manifest 'dst' field
 *   src-029  project.py:248   kwargs.get("patch")   manifest 'patch' field
 *   src-033  project.py:268   yamldata[key]         per-field manifest read
 *   src-032  metadata.py:71   yaml.safe_load        .dfetch_data.yaml parse
 *   src-031  metadata.py:71   safe_load(...)["dfetch"]  metadata root-dict read
 *   src-025  metadata.py:46   kwargs.get("destination")  manifest dst into Metadata
 *   src-017  vcs/git.py:229   result.stdout        git submodule foreach output
 *   src-046  svn.py:46        result.stdout        svn propget svn:externals output
 *
 * Trust model (per labels/phase1_review.md): dfetch has no web surface; the
 * attacker-relevant boundaries are manifest/metadata file content and git/svn
 * subprocess output. CLI/argparse rows are operator-trust (invoker == config
 * author) and are excluded on purpose - a file-handling wrapper's parameter is
 * NOT a source here.
 *
 * Matching is AST-level (same shapes already executed in
 * iris/extraction/sources.ql on this CLI/pack family): call/subscript/attribute
 * structure constrained to the dfetch modules named by the reviewed labels.
 * No API::Node values are mixed with DataFlow::Node, and no variable is named
 * `module`.
 */

import python

import semmle.python.dataflow.new.DataFlow

module MySources {

  /** Forward-slash-normalized absolute path of the file containing n, so path
   *  matching works with both CodeQL path styles on Windows (same helper
   *  shape as extraction/sources.ql). */
  private string normalizedPathOf(AstNode n) {
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
  }

  /** True iff n is in the given dfetch module (path pattern is matched on the
   *  normalized forward-slash path). */
  bindingset[modulePathPattern]
  private predicate inModule(AstNode n, string modulePathPattern) {
    normalizedPathOf(n).matches(modulePathPattern)
  }

  /** src-022 / src-032: the yaml.safe_load parse boundaries.
   *  manifest.py:139 - Manifest._load_yaml: the dfetch.yaml parse feeding
   *  ProjectEntry/Remote construction (child-manifests are read out of
   *  FETCHED remote trees via get_childmanifests, manifest.py:263-280).
   *  metadata.py:71 - Metadata.from_file: the .dfetch_data.yaml inside a
   *  fetched destination (a malicious repo can ship/modify it). The RETURN
   *  VALUE of the call carries the parsed external content, so the source
   *  node is the Call itself. */
  private predicate isYamlSafeLoadBoundary(DataFlow::Node source) {
    exists(Call c, Attribute func |
      func = c.getFunc().(Attribute) and
      func.getName() = "safe_load" and
      func.getObject().(Name).getId() = "yaml" and
      c = source.asExpr().(Call) and
      (
        inModule(c, "%/dfetch/manifest/manifest.py")
        or
        inModule(c, "%/dfetch/project/metadata.py")
      )
    )
  }

  /** src-023: loaded_yaml["manifest"] at manifest.py:129 - the manifest root
   *  dict read (container of all project/remote field values). */
  private predicate isManifestRootRead(DataFlow::Node source) {
    exists(Subscript s |
      s.getObject().(Name).getId() = "loaded_yaml" and
      inModule(s, "%/dfetch/manifest/manifest.py") and
      s = source.asExpr().(Subscript)
    )
  }

  /** src-031: yaml.safe_load(metadata_file)["dfetch"] at metadata.py:71 - the
   *  metadata root-dict read (Subscript whose object is a yaml.safe_load
   *  call). */
  private predicate isMetadataRootRead(DataFlow::Node source) {
    exists(Subscript s, Call base, Attribute func |
      base = s.getObject().(Call) and
      func = base.getFunc().(Attribute) and
      func.getName() = "safe_load" and
      func.getObject().(Name).getId() = "yaml" and
      inModule(s, "%/dfetch/project/metadata.py") and
      s = source.asExpr().(Subscript)
    )
  }

  /** src-033: yamldata[key] at project.py:268 - ProjectEntry.from_yaml
   *  per-field manifest value read (loop over ProjectEntryDict keys,
   *  including name/dst/src/patch). Taints every manifest field value. */
  private predicate isProjectEntryFieldRead(DataFlow::Node source) {
    exists(Subscript s |
      s.getObject().(Name).getId() = "yamldata" and
      inModule(s, "%/dfetch/manifest/project.py") and
      s = source.asExpr().(Subscript)
    )
  }

  /** src-027/src-028/src-029: kwargs.get("src"/"dst"/"patch") in
   *  ProjectEntry.__init__ (project.py:245/246/248) - where the manifest
   *  path fields become ProjectEntry state. Keyed by the literal key
   *  argument so the non-path fields (branch/tag/revision/url/...) of the
   *  same __init__ are NOT matched (they are reviewed fp rows). */
  private predicate isProjectEntryPathField(DataFlow::Node source) {
    exists(Call c, Attribute func, StringLiteral key |
      func = c.getFunc().(Attribute) and
      func.getName() = "get" and
      func.getObject().(Name).getId() = "kwargs" and
      key = c.getArg(0).(StringLiteral) and
      (
        key.getText() = "src"
        or
        key.getText() = "dst"
        or
        key.getText() = "patch"
      ) and
      inModule(c, "%/dfetch/manifest/project.py") and
      c = source.asExpr().(Call)
    )
  }

  /** src-025: kwargs.get("destination") in Metadata.__init__
   *  (metadata.py:46) - the manifest dst entering Metadata state via
   *  from_project_entry, or the 'destination' field of a re-read
   *  .dfetch_data.yaml via from_file. Only the "destination" key is matched;
   *  the other metadata keys (branch/tag/revision/hash/patch/remote_url)
   *  are reviewed fp rows (the metadata 'patch' field is never used as a
   *  file path). */
  private predicate isMetadataDestinationField(DataFlow::Node source) {
    exists(Call c, Attribute func, StringLiteral key |
      func = c.getFunc().(Attribute) and
      func.getName() = "get" and
      func.getObject().(Name).getId() = "kwargs" and
      key = c.getArg(0).(StringLiteral) and
      key.getText() = "destination" and
      inModule(c, "%/dfetch/project/metadata.py") and
      c = source.asExpr().(Call)
    )
  }

  /** src-017: result.stdout of the "git submodule foreach" output at
   *  vcs/git.py:217-250 (GitLocalRepo.submodules) - sm_path is remote
   *  .gitmodules content that becomes an imported ProjectEntry dst. Only
   *  the .stdout read inside submodules() is a reviewed source; the other
   *  .stdout reads in the module (version/SHA/branch/diff text) are fp. */
  private predicate isSubmoduleStdout(DataFlow::Node source) {
    exists(Attribute a |
      a.getName() = "stdout" and
      a.getObject() instanceof Name and
      a.getScope().(Function).getName() = "submodules" and
      inModule(a, "%/dfetch/vcs/git.py") and
      a = source.asExpr().(Attribute)
    )
  }

  /** src-046: result.stdout of the "svn propget svn:externals" output at
   *  svn.py:29-79 (SvnRepo.externals) - the parsed local_path/name become
   *  External.path (svn.py:70) then an imported ProjectEntry dst. Only the
   *  .stdout read inside externals() is a reviewed source; the other svn
   *  .stdout reads (tags/version) are fp. */
  private predicate isExternalsStdout(DataFlow::Node source) {
    exists(Attribute a |
      a.getName() = "stdout" and
      a.getObject() instanceof Name and
      a.getScope().(Function).getName() = "externals" and
      inModule(a, "%/dfetch/project/svn.py") and
      a = source.asExpr().(Attribute)
    )
  }

  /** Pass-1 source predicate. passKey is required to be "path_traversal"
   *  (the single pass rendered from this library). */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and
    (
      isYamlSafeLoadBoundary(source)
      or
      isManifestRootRead(source)
      or
      isMetadataRootRead(source)
      or
      isProjectEntryFieldRead(source)
      or
      isProjectEntryPathField(source)
      or
      isMetadataDestinationField(source)
      or
      isSubmoduleStdout(source)
      or
      isExternalsStdout(source)
    )
  }
}
