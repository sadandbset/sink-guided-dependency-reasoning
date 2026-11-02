/**
 * Augur Phase 2 Step 4 - sanitizer (barrier) models for django, pass 3
 * (CWE-918 SSRF).
 *
 * Machine-generated from iris/labels/labels.json (run
 * `django-iris-pass3-step3-20261020`, pass 3, pass key "ssrf").
 *
 * The reviewed pass-3 labels contain ZERO entries with role "sanitizer"
 * (the extraction CSVs contained no sanitizer candidates and none were
 * invented during labeling). This predicate therefore resolves to none()
 * for every pass key - the mandatory empty barrier hook required by
 * WORKFLOW.md rule 6. No unconditional taint propagation is introduced.
 *
 * Advisory sanitizer-shaped code that was reviewed and deliberately NOT
 * modeled (each is documented in labels/phase1_review.md section 5 and
 * report/query_generation_notes.md, none blocks the modeled fetch paths):
 *
 *   - TemplateCommand.is_url() scheme allowlist ['http','https','ftp']
 *     (django/core/management/templates.py:33, 325-330): blocks file:/data:
 *     at the urlretrieve call site but imposes no host, private-address or
 *     redirect restriction - not a sufficient CWE-918 barrier. It is also
 *     bypassed upstream: handle_template() strips a 'file://' prefix before
 *     the check (templates.py:194-195) and routes the value to a local-path
 *     branch instead.
 *   - HttpRequest.get_host() ALLOWED_HOSTS validation
 *     (django/http/request.py:119-137): validates the client Host header for
 *     request parsing and response URL construction; it never validates
 *     outbound fetch destinations.
 *   - url_has_allowed_host_and_scheme checks (django/views/i18n.py:37-50,
 *     django/contrib/auth/views.py:75-80, 143-147): open-redirect (Pass 9 /
 *     CWE-601) response validation, unrelated to server-side fetches.
 *   - Login/authentication, CSRF and staff permission checks, and general
 *     input format validation were per the labeling rubric NOT treated as
 *     SSRF sanitizers.
 */

import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * Holds if data flow through `node` is prohibited for the given pass key.
   * No sanitizer entries exist in the reviewed pass-3 labels, so this
   * predicate is empty (none()) for every pass key.
   */
  predicate isBarrier(DataFlow::Node node, string passKey) { none() }
}
