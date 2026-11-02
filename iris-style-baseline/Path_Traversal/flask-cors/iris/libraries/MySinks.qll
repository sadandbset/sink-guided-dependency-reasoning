/**
 * Machine-generated from iris/labels/labels.json (Pass 1 - Path Traversal),
 * run flask-cors-path-traversal-pass1-20261022, model glm-5.3.
 * DO NOT EDIT BY HAND - regenerate from labels instead (WORKFLOW.md 5.1.4).
 *
 * Sink labels rendered here (role=sink, classification=fp; signature deduplicated
 * to one rule: builtin open, dangerous path argument index 0, flow_kind argument):
 *
 *   - sink-011: setup.py:15  open(join(dirname(__file__), 'flask_cors/version.py'), 'r')
 *                          (read; content exec'd at setup.py:16 - Pass 4 material, out of Pass 1 scope)
 *   - sink-014: setup.py:18  open(join(dirname(__file__), 'requirements.txt'), 'r')
 *                          (read; feeds install_requires)
 *   - sink-017: setup.py:29  open('README.rst')
 *                          (read; CWD-relative literal, feeds long_description)
 *
 * The sink node is the PATH TEXT - argument 0 of the call - not the opened file
 * object ('f' / .read() results). All three audited instances are real file-read
 * API calls whose path arguments are literal/__file__-derived constants in the
 * setuptools packaging script (classification fp: unreachable from any untrusted
 * source; setup.py executes at packaging time only). The role is kept as sink so
 * the pass query would still catch any future taint reaching the path argument.
 *
 * Scope verification (this run, grep over the whole database snapshot excluding
 * only the nested flask-cors-db directory): bare-name 'open' calls exist exactly
 * at setup.py:15/:18/:29 (setup.py:18 is 'open (join(...))' - whitespace before
 * the parenthesis, still a Call whose func is Name 'open') and nowhere else;
 * flask_cors package modules contain zero filesystem calls and tests/ contain no
 * open() calls, so this rule matches exactly the three audited sink instances.
 * No file-response / file-write / delete / archive-extraction sink family exists
 * anywhere in the snapshot.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /** Sink nodes filtered by pass key. Only pass "path_traversal" (Pass 1) is carried by this pack. */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and fileOpenPathArgument(sink)
  }

  /**
   * builtin open(path, ...) - the only actual file-access API in this database
   * snapshot. Dangerous path argument: index 0 (the path text). Path-object
   * variants (io.open / os.open / pathlib) do not occur in the audited labels
   * nor in the snapshot and are deliberately not matched.
   */
  private predicate fileOpenPathArgument(DataFlow::Node sink) {
    exists(Call c |
      c.getFunc().(Name).getId() = "open" and
      sink.asExpr() = c.getArg(0)
    )
  }
}
