/**
 * Machine-generated from reviewed Phase 1 labels (iris/labels/labels.json, pass 1).
 * Run: streamlit-pathtraversal-pass1-20261023. Do not edit by hand.
 *
 * Barrier (sanitizer) nodes for pass key "path_traversal" (Path Traversal,
 * CWE-22/23/36/73).
 *
 * The reviewed pass 1 labels contain ZERO entries with role=sanitizer, so this
 * predicate resolves to none() — the empty barrier required by WORKFLOW 3.6/5.2.3
 * (keep an isBarrier predicate in query configs even when empty).
 *
 * No sanitizer was invented here, per the labeling evidence:
 *  - string_util.clean_filename (string_util.py:64-78) genuinely neutralizes `..`
 *    and path characters, but it sanitizes the Content-Disposition *header filename*
 *    (routes.py:131), never a filesystem path, and it is not on any source->sink
 *    path in this query — not a barrier.
 *  - UploadFileRequestHandler._is_valid_session_id validates session membership,
 *    not paths.
 *  - StaticFileHandler.parse_url_path page-name allowlist rewrites known page names
 *    to "index.html" but passes every other path through to the superclass
 *    unchanged — not a barrier on the deferral path.
 *  - tornado's StaticFileHandler.validate_absolute_path containment lives in the
 *    tornado library, outside this database — nothing in-repo to bind to.
 *  - os.path.basename/normpath/realpath and startswith guards: none appear between
 *    the /component/(.*) route capture and open() (components.py:310-325), so there
 *    is no in-repo barrier to model for the confirmed flow.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /** Holds if `node` blocks path-traversal taint for pass 1. Currently always false. */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    none()
  }
}
