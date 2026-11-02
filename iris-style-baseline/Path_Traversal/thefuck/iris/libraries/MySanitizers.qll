/**
 * Augur Pass 1 (Path Traversal, CWE-022/023/036/073) sanitizer (barrier)
 * model for thefuck 3.30 (`thefuck_vuln` source tree).
 *
 * Generated in Phase 2 Step 4 from the reviewed Phase 1 labels
 * (`iris/labels/labels.json`, pass 1, run `iris-thefuck-pass1-step3-20261023`,
 * model glm-5.3): the pass contains ZERO sanitizer entries, and the Phase 1
 * review (phase1_review.md Q5/Q6) verified against the real source that no
 * barrier exists anywhere between the labeled sources and sinks.
 *
 * `MySanitizers::isBarrier` therefore resolves to `none()`, and the pass
 * query keeps an explicit empty `isBarrier` per the WORKFLOW contract.
 *
 * Why each candidate filter was REJECTED as a barrier (source evidence):
 *
 * - No base-directory containment exists at any sink: neither
 *   `dirty_untar.py:45` / `dirty_unzip.py:49` (`os.remove(file)` per archive
 *   entry name) nor `ssh_known_hosts.py:33/:36` (`open(filepath, ...)`) is
 *   preceded by a `startswith(base)`, `abspath/realpath` containment,
 *   `relative_to()`, fixed-filename mapping or allow-list; there is no
 *   declared allowed root anywhere in the package (the tp cases are
 *   arbitrary-path, not base-escape).
 * - `os.path.expanduser` / `Path.expanduser` (bash.py:70, zsh.py:75,
 *   tcsh.py:30, fish.py:86, conf.py:47/:48, utils.py:227/:255,
 *   not_configured.py:77/:84, generic.py:154) EXPANDS `~` - it performs no
 *   validation and cannot neutralize `..` or absolute paths; it is a path
 *   wrapper, not a sanitizer.
 * - `os.path.split` (utils.py:59, cd_correction.py:54) splits a path for
 *   cwd walking / name separation, not basename-extraction sanitization.
 * - `cd_correction.py:56` `get_close_matches(directory, _get_sub_dirs(cwd),
 *   cutoff=0.6)` implicitly constrains its own `os.listdir` argument to
 *   names of real subdirectories, but it is not a canonicalize/containment
 *   guard on any labeled source-to-sink path (its data comes from
 *   `command.script_parts`, which is not a rendered source), so it is not
 *   modeled as a barrier.
 * - The existence stats preceding some opens (`generic.py:59`
 *   `os.path.isfile` before `io.open` at :60, `conf.py:38` `is_file()`
 *   before `.open('w')` at :39, `not_configured.py:58` `exists()` before
 *   `open('r')` at :62) are availability probes (check-then-use), not
 *   authorization checks; they block nothing.
 * - No URL decoding exists anywhere in the package (no web surface), so
 *   decode-then-validate ordering questions do not arise.
 * - No symlink handling exists: no symlink creation, no `readlink`, no
 *   follow-policy; a symlink-based barrier is therefore not applicable.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /**
   * Holds if `node` blocks path-traversal taint for pass key
   * `path_traversal`. No sanitizer was labeled in the reviewed pass-1
   * labels and none is provable from the source (see the file-level
   * documentation), so this intentionally resolves to `none()`.
   */
  predicate isBarrier(DataFlow::Node node, string passKey) { none() }
}
