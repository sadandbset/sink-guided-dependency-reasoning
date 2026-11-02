/**
 * Augur Phase 2 Step 4 - sink models for django, pass 3 (CWE-918 SSRF).
 *
 * Machine-generated from iris/labels/labels.json (run
 * `django-iris-pass3-step3-20261020`, pass 3, pass key "ssrf").
 * All three label entries with role "sink" are modeled (one of them with
 * classification "fp", see below). Sinks are pinned to the reviewed call
 * sites (label location) rather than to every same-named call in the
 * database, so no unreviewed call site (e.g. in tests/) can produce alerts.
 *
 * Label -> predicate mapping (flow_kind "argument"):
 *   snk-001  urllib.request.urlopen   arg 0 (tp, 0.90) -> 1st disjunct of isSsrfSink/1
 *   snk-003  urllib.request.urlretrieve arg 0 (tp, 0.90) -> 2nd disjunct
 *   snk-002  smtplib.SMTP              arg 0 (fp, 0.75) -> 3rd disjunct
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /** Holds if `node` is a taint sink for the given pass key. */
  predicate isSink(DataFlow::Node node, string passKey) {
    passKey = "ssrf" and isSsrfSink(node)
  }

  /**
   * Pass 3 (CWE-918) sinks for the django framework tree.
   */
  private predicate isSsrfSink(DataFlow::Node node) {
    // snk-001 (tp): urllib.request.urlopen positional argument 0 - the full
    // requested URL. Call site: django/contrib/sitemaps/__init__.py:27,
    // urlopen('%s?%s' % (ping_url, params)) inside ping_google(). The URL
    // expression (scheme/host/port/path from ping_url, query string from the
    // urlencode'd sitemap URL) is argument 0.
    node = DataFlow::exprNode(urlopenCall().getArg(0))
    or
    // snk-003 (tp): urllib.request.urlretrieve positional argument 0 - the
    // downloaded URL. Call site: django/core/management/templates.py:265,
    // the_path, info = urlretrieve(url, os.path.join(tempdir, filename))
    // inside TemplateCommand.download(url); `url` traces to the --template
    // CLI option. Scheme is restricted to http/https/ftp by is_url()
    // (templates.py:33, 325-330); no host/private-address/redirect restriction.
    node = DataFlow::exprNode(urlretrieveCall().getArg(0))
    or
    // snk-002 (fp): outbound SMTP network connection, host at positional
    // argument 0. Label signature is smtplib.SMTP argument 0; the actual
    // construction site is the dynamic dispatch
    // self.connection = self.connection_class(self.host, self.port, ...)
    // (django/core/mail/backends/smtp.py:62), where the connection_class
    // property returns smtplib.SMTP or SMTP_SSL (smtp.py:37-39) and
    // self.host/self.port come from EmailBackend arguments or
    // settings.EMAIL_HOST/EMAIL_PORT (smtp.py:21-22). Classification fp per
    // the reviewed labels: non-HTTP protocol, operator-configured destination,
    // no web-request boundary reaches the call. Modeled for auditability; any
    // alert from this sink must be filtered in Step 6.
    node = DataFlow::exprNode(smtpConnectionCall().getArg(0))
  }

  /** The urlopen(...) call in django/contrib/sitemaps/__init__.py (label location :27). */
  private Call urlopenCall() {
    exists(Name func | func = result.getFunc() and func.getId() = "urlopen") and
    result.getLocation().getFile().getRelativePath() = "django/contrib/sitemaps/__init__.py"
  }

  /** The urlretrieve(...) call in django/core/management/templates.py (label location :265). */
  private Call urlretrieveCall() {
    exists(Name func | func = result.getFunc() and func.getId() = "urlretrieve") and
    result.getLocation().getFile().getRelativePath() = "django/core/management/templates.py"
  }

  /**
   * The self.connection_class(self.host, self.port, ...) call in
   * django/core/mail/backends/smtp.py (label location :62). The callee is the
   * connection_class property returning smtplib.SMTP/SMTP_SSL (smtp.py:37-39).
   */
  private Call smtpConnectionCall() {
    exists(Attribute func | func = result.getFunc() and func.getName() = "connection_class") and
    result.getLocation().getFile().getRelativePath() = "django/core/mail/backends/smtp.py"
  }
}
