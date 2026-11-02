/**
 * Augur-generated sanitizer (barrier) model for the matrix-sydent
 * CWE-918 (SSRF) pass.
 *
 * Machine-generated in Phase 2 Step 4 from the reviewed labels in
 * iris/labels/labels.json (run sydent-ssrf-pass3-20261020, pass_id 3,
 * pass key "ssrf"). Do not edit by hand; regenerate from the labels.
 *
 * The reviewed pass-3 labels contain ZERO sanitizer entries. Verified
 * against sydent source (labels/phase1_review.md, sanitizer assessment):
 *  - is_valid_hostname (sydent/util/stringutils.py:39, applied at
 *    registerservlet.py:52, threepid/bind.py:146, verifier.py:208):
 *    hostname syntax + port-range check ONLY. It accepts IP literals,
 *    'localhost', RFC1918/private ranges and an explicit port - it does
 *    not restrict the URL scheme, host allow-list, redirects, or
 *    post-resolution private addresses. Not a CWE-918 sanitizer.
 *  - is_valid_client_secret (stringutils.py:27): alphanumeric format
 *    check on client_secret, unrelated to URL control.
 *  - authV2 bearer auth (sydent/http/auth.py:55), X-Matrix signature
 *    verification (verifier.py:211) and replication mutual-TLS CN
 *    matching (replication.py:42-51): caller authentication, not URL
 *    neutralization. In the verifier chain the key fetch (verifier.py:80)
 *    happens BEFORE the signature check.
 *  - next_link startswith('file:///') rejection (emailservlet.py:65/:106):
 *    open-redirect guard (Pass 9); msisdnservlet.py:129 has no such
 *    check. Neither applies to any server-side fetch URL.
 * No scheme allow-list, fixed-host whitelist, redirect control, DNS
 * pinning, or private-IP blocking exists on the modeled SSRF paths.
 *
 * The barrier therefore resolves to none(). The predicate keeps the
 * passKey dispatch shape so the query's mandatory isBarrier hook stays
 * wired to the library (WORKFLOW.md 5.2.3); adding a barrier requires a
 * label re-review, not an edit here.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /** No proven CWE-918 sanitizer exists in the reviewed labels. */
  predicate isBarrier(DataFlow::Node node, string passKey) { none() }

}
