/**
 * Augur Phase 2 Step 4 - source models for django, pass 3 (CWE-918 SSRF).
 *
 * Machine-generated from iris/labels/labels.json (run
 * `django-iris-pass3-step3-20261020`, pass 3, pass key "ssrf").
 * Only label entries with role "source" are modeled. No other sources are
 * invented: all request.<field> / environ / scope candidates were labeled
 * role "none" with per-site verification that they never reach an outbound
 * network request, so they are deliberately absent from this model.
 *
 * Label -> predicate mapping (all flow_kind "param"):
 *   src-001  ping_google.sitemap_url                    (candidate, 0.55) -> 1st disjunct of isSsrfSource/1
 *   src-002  ping_google.ping_url                       (candidate, 0.55) -> 2nd disjunct
 *   src-005  ManagementUtility.__init__.argv            (candidate, 0.60) -> 3rd disjunct
 *   src-007  execute_from_command_line.argv             (candidate, 0.60) -> 4th disjunct
 *
 * GAP (recorded, not silently resolved): labels/review_decision.json does not
 * exist; the four source entries carry classification "candidate" (human review
 * requested in labels/phase1_review.md section 7) and were carried into this
 * model verbatim from the reviewed labels.json. The review record should be
 * written before the pass queries are executed.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /** Holds if `node` is a taint source for the given pass key. */
  predicate isSource(DataFlow::Node node, string passKey) {
    passKey = "ssrf" and isSsrfSource(node)
  }

  /**
   * Pass 3 (CWE-918) sources for the django framework tree.
   *
   * Attacker/operator control scopes are deliberately kept distinct
   * (labels record them separately; see report/query_generation_notes.md):
   *   - src-001 sitemap_url: query-string value only (fixed ping host in-tree)
   *   - src-002 ping_url:    host-forming prefix of the fetched URL
   *   - src-005/src-007 argv: CLI boundary, root of both fetch flows
   */
  private predicate isSsrfSource(DataFlow::Node node) {
    // src-001: ping_google(sitemap_url=None, ping_url=PING_URL, ...) parameter 0.
    // Control scope when a caller supplies it: the value becomes the urlencode'd
    // 'sitemap' QUERY-STRING VALUE of the outbound request (sitemaps/__init__.py:25-27);
    // it does not control scheme/host/port of the request.
    node = DataFlow::parameterNode(pingGoogleFunction().getArg(0))
    or
    // src-002: ping_google(sitemap_url, ping_url, ...) parameter 1.
    // Control scope: the host-forming prefix of urlopen('%s?%s' % (ping_url, params))
    // (sitemaps/__init__.py:27) - a caller-supplied value fully controls the fetched
    // scheme/host/port/path. No in-tree caller passes it (default: fixed PING_URL
    // constant, sitemaps/__init__.py:11).
    node = DataFlow::parameterNode(pingGoogleFunction().getArg(1))
    or
    // src-005: ManagementUtility.__init__(self, argv=None) parameter 1 ('argv').
    // Genuine CLI boundary: self.argv = argv or sys.argv[:] (management/__init__.py:176);
    // root origin of both fetch flows via execute() -> run_from_argv(self.argv)
    // (line 395) -> parse_args(argv[2:]) -> Command.execute(**vars(options))
    // (base.py:322-330) -> ping_google / TemplateCommand.handle_template.
    node = DataFlow::parameterNode(managementUtilityInitArgv())
    or
    // src-007: execute_from_command_line(argv=None) parameter 0 ('argv').
    // Thin CLI entry point delegating to ManagementUtility(argv) (line 400).
    node = DataFlow::parameterNode(executeFromCommandLineArgv())
  }

  /** The ping_google function defined in django/contrib/sitemaps/__init__.py (label location :18). */
  private Function pingGoogleFunction() {
    result.getName() = "ping_google" and
    result.getLocation().getFile().getRelativePath() = "django/contrib/sitemaps/__init__.py"
  }

  /**
   * The 'argv' parameter (index 1) of ManagementUtility.__init__ in
   * django/core/management/__init__.py (label location :175).
   * The parameter-name guard disambiguates from any other __init__ in the file.
   */
  private Parameter managementUtilityInitArgv() {
    result = managementUtilityInitFunction().getArg(1) and
    result.asName().getId() = "argv"
  }

  private Function managementUtilityInitFunction() {
    result.getName() = "__init__" and
    result.getLocation().getFile().getRelativePath() = "django/core/management/__init__.py"
  }

  /**
   * The 'argv' parameter (index 0) of execute_from_command_line in
   * django/core/management/__init__.py (label location :398).
   */
  private Parameter executeFromCommandLineArgv() {
    result = executeFromCommandLineFunction().getArg(0) and
    result.asName().getId() = "argv"
  }

  private Function executeFromCommandLineFunction() {
    result.getName() = "execute_from_command_line" and
    result.getLocation().getFile().getRelativePath() = "django/core/management/__init__.py"
  }
}
