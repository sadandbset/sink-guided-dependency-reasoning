/**
 * Augur Phase 2 Step 4 - Pass 1 (Path Traversal) sanitizer library for fides.
 *
 * Deterministically rendered from the reviewed Pass 1 labels in
 * iris/labels/labels.json (run iris-fides-pathtraversal-pass1-20261022):
 * the reviewed pass-1 label set contains ZERO sanitizer entries with
 * classification=tp, and this library reflects that exactly.
 *
 * The two sanitizer candidates in the label set were both REJECTED
 * (classification=fp) and are NOT rendered as barriers:
 *
 *   sink-106 (sanitizer/fp 0.90): path_is_in_ui_directory(path)
 *     at src/fides/api/ui.py:134
 *   sink-107 (sanitizer/fp 0.90): the `path.parents` attribute read
 *     at src/fides/api/ui.py:141
 *
 * Why the guard cannot be a barrier (verified against the real source and
 * against pathlib semantics; per labels/phase1_review.md section 3):
 *
 *   ui.py:134-141:
 *     def path_is_in_ui_directory(path: Path) -> bool:
 *       ui_directory = get_path_to_admin_ui_file()
 *       if not ui_directory:
 *         return False
 *       return ui_directory in path.parents
 *
 *   - The check `ui_directory in path.parents` is a LEXICAL comparison on
 *     the UNRESOLVED pathlib object. pathlib keeps ".." as an ordinary
 *     path component, so for ui_directory/'..'/'..'/'secret the
 *     successively truncated lexical parents still contain ui_directory
 *     exactly (verified: Path("/a/b/c") in
 *     (Path("/a/b/c")/".."/".."/"x").parents is True). The guard
 *     therefore PASSES for precisely the ".." payloads that escape the
 *     UI root at OS level when is_file()/FileResponse resolve them.
 *   - The only case the guard rejects is the absolute-path replacement
 *     (base / "/abs" replaces the whole base) - unreachable anyway,
 *     because the Starlette router strips the leading "/" from the
 *     catch-all parameter.
 *   - No canonicalization runs before the comparison (no resolve(), no
 *     normpath, no relative_to on resolved paths), and no ".." rejection,
 *     basename extraction or separator whitelist exists anywhere on the
 *     chain. Treating this node as isBarrier would SUPPRESS the
 *     confirmed catch-all traversal flow (source src-044 -> sinks
 *     sink-063/sink-064); the reviewed labels explicitly record this
 *     instruction.
 *   - Symlinks: no symlink creation or link-following policy exists in
 *     the audited code, and the packaged admin-UI directory is not
 *     attacker-writable, so symlink/TOCTOU neutralization is not
 *     applicable (recorded as not observed) - and the lexical guard would
 *     not neutralize a symlink escape either.
 *
 * isBarrier therefore resolves to none() (the WORKFLOW.md section 5.2.3
 * mandated empty fallback). No path node is treated as a barrier, so no
 * real flow can be suppressed by this library.
 */

import python

import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /** Pass-1 barrier predicate: always empty - no reviewed sanitizer with
   *  classification=tp exists for path_traversal in the fides label set.
   *  The passKey parameter is accepted for interface uniformity with
   *  MySources/MySinks/MySummaries. */
  predicate isBarrier(DataFlow::Node node, string passKey) { none() }
}
