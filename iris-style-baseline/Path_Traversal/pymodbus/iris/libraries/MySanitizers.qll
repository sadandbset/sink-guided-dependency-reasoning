/**
 * Augur-generated taint barrier models (Phase 2, Step 4).
 *
 * Project : pymodbus (pymodbus_vuln snapshot, 3.6.0dev)
 * Pass    : 1 - Path Traversal (CWE-022 / CWE-023 / CWE-036 / CWE-073)
 * Labels  : iris/labels/labels.json, pass_id=1 - NO sanitizer entries
 *           (role sanitizer count = 0).
 *
 * Deliberately empty: no sanitizer is provable for the Pass 1 flows from
 * the real source code.
 *
 *   - The static-file handler (http_server.py:258-267) performs no
 *     canonicalization (normpath/abspath/realpath/resolve), no
 *     relative_to/startswith containment check, no basename extraction and
 *     no ".." rejection between the request.path source and the
 *     open()/FileResponse() sinks. Its try/except only converts
 *     FileNotFoundError/IsADirectoryError into HTTP 404 - that is error
 *     handling, not path validation.
 *   - The only input filter anywhere on the flow is the aiohttp route
 *     regex "/{tail:[a-z0-9.]*}" (http_server.py:172). It lives in the
 *     external aiohttp router, not in database code, and whether its
 *     whole-path anchored matching constrains request.path to
 *     separator-free values depends on the deployed aiohttp version.
 *     Per the labeling contract ("barriers must be proven to block from
 *     real source code; do not treat a regex or a function name as a
 *     filter mechanically"), it is NOT asserted as a barrier; it is
 *     recorded as manual-review point R1 in report/query_generation_notes.md.
 *
 * The predicate resolves to none() for every pass key, which satisfies the
 * mandatory-barrier-hook contract (WORKFLOW.md 5.2.3) without inventing
 * unproven edges.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * Holds if data flow through `node` is prohibited for the given pass key.
   * Empty by design: no provable sanitizer exists for any pass in this
   * project (see file header). `passKey` is only referenced to keep the
   * interface shape of the shared pass-key dispatch.
   */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    none()
  }
}
