/**
 * Augur Phase 2 - Pass 3 (CWE-918 SSRF) sanitizer (barrier) library.
 * Generated from reviewed labels: iris/labels/labels.json (pass 3; ZERO
 * sanitizer/tp entries - the supplemental review entry p3-sup-0001 records
 * the REJECTED sanitizer candidate).
 *
 * No barrier is modeled, with the following reviewed evidence:
 *   - is_url(path) (dtale/cli/clickutils.py:234-235): only an http:// /
 *     https:// PREFIX check. It restricts the scheme (blocking file:/data:/
 *     ftp: cross-protocol use) but places NO restriction on host, port, IP
 *     range, userinfo or redirects, so it does not neutralize the SSRF path
 *     through handle_path (arbitrary internal/external http(s) endpoints
 *     remain reachable from /web-upload). Reviewed verdict: none/fp
 *     (p3-sup-0001) - NOT a barrier.
 *   - auth.requires_auth (dtale/auth.py:37-51): route-level access control
 *     that is DISABLED by default (global_state.py:38 AUTH_SETTINGS
 *     active=False; requires_auth returns f(...) unchanged when inactive).
 *     It is an optional deployment access gate, not a data-flow sanitizer;
 *     not modeled as a barrier.
 *   - authenticate() (auth.py:30-34): credential comparison, no URL path.
 *   - No host allow-list, DNS-resolver/private-IP check, redirect control or
 *     scheme allow-list beyond the is_url prefix exists anywhere on the
 *     funnel path in this tree.
 *
 * The predicate is kept (resolving to none() for the "ssrf" pass key) so the
 * pass query can always delegate isBarrier, per the Augur workflow rule
 * "keep an isBarrier predicate in query configs even when empty".
 *
 * Not yet compiled (query execution deferred per operator instruction).
 * Written against the codeql/python-all 7.1.2 API surface, which resolves from
 * the local pack cache for iris/qlpack.yml (same surface as the validated
 * SSRF/core sibling libraries; the `passKey = ... and none()` conjunction form
 * matches the validated binderhub form). No API surface beyond
 * DataFlow::Node is required.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /* ------------------------------------------------------------------
   * Public interface (pass key: "ssrf")
   *
   * No sanitizer label survived review for this pass: isBarrier resolves to
   * none() for every node. Nothing is barrier-gated on evidence-free grounds.
   * ------------------------------------------------------------------ */

  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "ssrf" and
    none()
  }
}
