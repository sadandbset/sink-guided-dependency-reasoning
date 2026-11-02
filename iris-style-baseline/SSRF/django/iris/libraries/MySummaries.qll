/**
 * Augur Phase 2 Step 4 - additional taint steps (summaries) for django,
 * pass 3 (CWE-918 SSRF).
 *
 * Machine-generated from iris/labels/labels.json (run
 * `django-iris-pass3-step3-20261020`, pass 3, pass key "ssrf").
 * All three label entries with role "summary" are modeled. Every edge below
 * is backed by a concrete source-code transfer verified in Phase 1; no
 * unconditional propagation is introduced, and no edge is created for a
 * wrapper that the labels did not review.
 *
 * Label -> predicate mapping:
 *   src-003  _get_sitemap_full_url.sitemap_url (param 0, tp, 0.80) -> 1st disjunct
 *            of isSsrfAdditionalTaintStep/2
 *   src-209  TemplateCommand.handle_template   (param 1, tp, 0.75) -> 2nd disjunct
 *   src-210  TemplateCommand.download          (param 1, tp, 0.80) -> 3rd disjunct
 *
 * Note: each of these transfers is additionally covered by the standard
 * interprocedural steps of TaintTracking::Global (argument-to-parameter,
 * return-value flow, and in-body argument use). The explicit edges are kept
 * because they materialize the reviewed summary labels and make the model
 * robust if a native step is missed (e.g. flows through **kwargs).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /** Holds if taint may additionally flow from `nodeFrom` to `nodeTo` for the given pass key. */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "ssrf" and isSsrfAdditionalTaintStep(nodeFrom, nodeTo)
  }

  /**
   * Pass 3 (CWE-918) additional taint steps for the django framework tree.
   */
  private predicate isSsrfAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    // src-003: _get_sitemap_full_url(sitemap_url, sitemap_uses_https=True)
    // parameter 0 -> value of any call to _get_sitemap_full_url.
    // Source basis: the function returns '%s://%s%s' % (scheme,
    // current_site.domain, sitemap_url) (django/contrib/sitemaps/__init__.py:51),
    // so its sitemap_url argument is transferred into the returned URL string
    // that ping_google() urlencodes into the outbound request
    // (sitemaps/__init__.py:25-26; sole in-tree call site).
    nodeFrom = DataFlow::parameterNode(getSitemapFullUrlFunction().getArg(0)) and
    nodeTo = DataFlow::exprNode(getSitemapFullUrlCall())
    or
    // src-209: TemplateCommand.handle_template(self, template, subdir)
    // parameter 1 -> argument 0 of the self.download(template) call.
    // Source basis: django/core/management/templates.py:200-202 - after the
    // is_url() check, handle_template passes `template` straight into
    // self.download(template), whose url parameter reaches urlretrieve
    // (templates.py:265). A 'file://' prefix is stripped at lines 194-195
    // before the is_url() branch (local-path branch, not network).
    nodeFrom = DataFlow::parameterNode(handleTemplateFunction().getArg(1)) and
    nodeTo = DataFlow::exprNode(downloadCall().getArg(0))
    or
    // src-210: TemplateCommand.download(self, url) parameter 1 -> argument 0
    // of the urlretrieve call.
    // Source basis: django/core/management/templates.py:265 - download(url)
    // passes its url parameter directly as urlretrieve's first (URL)
    // argument; the local filename is also derived from it (lines 248-260).
    nodeFrom = DataFlow::parameterNode(downloadFunction().getArg(1)) and
    nodeTo = DataFlow::exprNode(urlretrieveCall().getArg(0))
  }

  /** The _get_sitemap_full_url function defined in django/contrib/sitemaps/__init__.py (label location :30). */
  private Function getSitemapFullUrlFunction() {
    result.getName() = "_get_sitemap_full_url" and
    result.getLocation().getFile().getRelativePath() = "django/contrib/sitemaps/__init__.py"
  }

  /** A call to _get_sitemap_full_url(...) in django/contrib/sitemaps/__init__.py (in-tree call site :25). */
  private Call getSitemapFullUrlCall() {
    exists(Name func | func = result.getFunc() and func.getId() = "_get_sitemap_full_url") and
    result.getLocation().getFile().getRelativePath() = "django/contrib/sitemaps/__init__.py"
  }

  /** The handle_template method defined in django/core/management/templates.py (label location :185). */
  private Function handleTemplateFunction() {
    result.getName() = "handle_template" and
    result.getLocation().getFile().getRelativePath() = "django/core/management/templates.py"
  }

  /** The download method defined in django/core/management/templates.py (label location :244). */
  private Function downloadFunction() {
    result.getName() = "download" and
    result.getLocation().getFile().getRelativePath() = "django/core/management/templates.py"
  }

  /** The self.download(template) call in django/core/management/templates.py (call site :202). */
  private Call downloadCall() {
    exists(Attribute func | func = result.getFunc() and func.getName() = "download") and
    result.getLocation().getFile().getRelativePath() = "django/core/management/templates.py"
  }

  /** The urlretrieve(...) call in django/core/management/templates.py (label location :265). */
  private Call urlretrieveCall() {
    exists(Name func | func = result.getFunc() and func.getId() = "urlretrieve") and
    result.getLocation().getFile().getRelativePath() = "django/core/management/templates.py"
  }
}
