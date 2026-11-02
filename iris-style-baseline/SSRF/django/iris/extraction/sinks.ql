
/**
 * @name Django sink candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate outbound-network request call sites
 *              from the Django 3.1.12 framework source for subsequent
 *              LLM labeling.
 * @id py/augur/django/pass3-sinks
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * Only server-side network I/O call sites that exist in this source
 * tree are extracted. requests / httpx / aiohttp are not imported
 * anywhere in this project and are therefore absent (documented as a
 * coverage gap in detection.json, not fabricated). The complete list
 * of genuine outbound fetch sites in the Django framework source:
 *
 *   - urlopen()    django/contrib/sitemaps/__init__.py:27
 *                  (ping_google, hardcoded Google ping endpoint by
 *                   default, driven by the `ping_google` management
 *                   command)
 *   - urlretrieve() django/core/management/templates.py:265
 *                  (TemplateCommand.download, driven by the
 *                   `startproject/startapp --template` CLI option)
 *   - smtplib SMTP connection construction in
 *     django/core/mail/backends/smtp.py:62 (non-HTTP network I/O,
 *     recorded separately because it is not an HTTP(S) request)
 *
 * Things deliberately NOT extracted as CWE-918 sinks:
 *   - HttpResponseRedirect / shortcuts.redirect / contrib.redirects:
 *     these return redirect responses for client-side navigation
 *     (Pass 9 / CWE-601 material), they do not make the server fetch
 *     anything.
 *   - urljoin / urlparse / urlsplit / URLValidator: URL parsing and
 *     construction only; dangerous only when tied to a real fetch.
 *   - dev-server socket usage (django/core/servers/basehttp.py):
 *     server-side accept loop.
 *   - Database/cache client construction (django/db/backends/*,
 *     django/core/cache/backends/*): endpoints come from settings and
 *     the network I/O lives in third-party libraries not present in
 *     this database.
 *   - geoip2 .mmdb loads: local file reads (Pass 1), not CWE-918.
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("sink_candidate")
 *  3. callable            (dotted signature hint)
 *  4. flow kind           (argument)
 *  5. receiver            (receiver/type hint)
 *  6. module hint         (dotted module path; variable named moduleHint,
 *                          "module" is a QL keyword and must not be used)
 *  7. argument index      (0-based positional index of the URL/host
 *                          argument; -1 when not applicable)
 *  8. line
 *  9. file:line
 * 10. expression text
 *
 * flow kind vocabulary:
 *   argument - the tainted URL/host position is a positional argument
 *              of the network call
 */

import python

// ------------------------------------------------------------
// 1. Scope and location helpers
// ------------------------------------------------------------

/**
 * Restrict extraction to the Django framework package.
 *
 * The CodeQL database source root is the repository root, so relative
 * paths of framework files look like "django/http/request.py".
 * "django/%" cannot match the nested "django-db/" database directory
 * (position 6 is '-' vs '/'), and tests are additionally excluded
 * (django/test/ tree, tests/ tree, and any module named tests.py
 * at any depth).
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("django/%") and
    not path.matches("django/test/%") and
    not path.matches("tests/%") and
    not path.matches("%/tests.py")
  )
}

/**
 * Restrict a candidate to one framework module. The path string is
 * bound by equality before any comparison, so no unbound-variable
 * error can occur.
 */
predicate inModule(AstNode n, string relPath) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path = relPath
  )
}

/** Dotted module name of a candidate. */
string moduleOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
}

/** Human-readable file and line location. */
string locationOf(AstNode n) {
  result =
    n.getLocation().getFile().getRelativePath() +
    ":" +
    n.getLocation().getStartLine().toString()
}

// ------------------------------------------------------------
// 2. Candidate extraction
// ------------------------------------------------------------

from
  AstNode n,
  string callableName,
  string flowKind,
  string receiverHint,
  string moduleHint,
  int argIndex
where
  inAnalysisScope(n) and
  moduleHint = moduleOf(n) and
  (
    // --------------------------------------------------------
    // (1) urlopen(<url>, ...) - urllib.request.urlopen
    //     imported via `from urllib.request import urlopen`
    //     (django/contrib/sitemaps/__init__.py:2), single call site
    //     at line 27 inside ping_google():
    //       urlopen('%s?%s' % (ping_url, params))
    //     URL at positional argument 0.
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc() and
      fn.getId() = "urlopen" and
      callableName = "urllib.request.urlopen" and
      flowKind = "argument" and
      receiverHint = "urllib.request" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (2) urlretrieve(<url>, <filename>) - urllib.request.urlretrieve
    //     imported via `from urllib.request import urlretrieve`
    //     (django/core/management/templates.py:9), single call site
    //     at line 265 inside TemplateCommand.download():
    //       the_path, info = urlretrieve(url, os.path.join(tempdir, filename))
    //     URL at positional argument 0; the value originates from the
    //     `--template` CLI option (handle_template at line 185).
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc() and
      fn.getId() = "urlretrieve" and
      callableName = "urllib.request.urlretrieve" and
      flowKind = "argument" and
      receiverHint = "urllib.request" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (3) smtplib SMTP connection construction (NON-HTTP network):
    //     self.connection = self.connection_class(self.host,
    //         self.port, **connection_params)
    //     django/core/mail/backends/smtp.py:62; connection_class is a
    //     property (lines 38-39) returning smtplib.SMTP or
    //     smtplib.SMTP_SSL. Host at positional argument 0, port at 1.
    //     Host/port default to settings.EMAIL_HOST / EMAIL_PORT -
    //     operator-configured endpoints; recorded separately from the
    //     HTTP fetch sinks because CWE-918 concerns server-side
    //     request forgery, and SMTP is a different protocol family.
    // --------------------------------------------------------

    exists(Call c, Attribute attr, Name selfName |
      n = c and
      attr = c.getFunc() and
      attr.getName() = "connection_class" and
      selfName = attr.getObject() and
      selfName.getId() = "self" and
      inModule(c, "django/core/mail/backends/smtp.py") and
      callableName = "smtplib.SMTP" and
      flowKind = "argument" and
      receiverHint = "django.core.mail.backends.smtp.EmailBackend" and
      argIndex = 0
    )
  )

select
  n,
  "sink_candidate",
  callableName,
  flowKind,
  receiverHint,
  moduleHint,
  argIndex,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()
