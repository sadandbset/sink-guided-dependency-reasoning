/**
 * Augur Phase 2 - Pass 3 (CWE-918 SSRF) sanitizer (barrier) library.
 * Generated from reviewed labels: iris/labels/labels.json (pass 3, 9 sanitizer/tp
 * supplemental entries with concrete source evidence).
 *
 * Label -> predicate mapping (barrier node = argument 0 of the guard call site):
 *   p3-san-01 color_extractor/__init__.py:106     is_allowed_external_url(url)  default-deny URL allow-list
 *   p3-san-02 discord/notify.py:74                is_allowed_external_url(url)  default-deny URL allow-list
 *   p3-san-03 slack/notify.py:181                 is_allowed_external_url(url)  default-deny URL allow-list
 *   p3-san-04 signal_messenger/notify.py:139      is_allowed_external_url(url)  default-deny URL allow-list
 *   p3-san-05 blueprint/importer.py:65            url.startswith prefix check (raw.githubusercontent.com)
 *   p3-san-06 blueprint/importer.py:68            GITHUB_FILE_PATTERN.match(url)
 *   p3-san-07 blueprint/importer.py:81            COMMUNITY_TOPIC_PATTERN.match(url)
 *   p3-san-08 blueprint/importer.py:185           url.startswith prefix check (gist.github.com)
 *   p3-san-09 blueprint/importer.py:236           WEBSITE_PATTERN.match(url)
 *
 * Semantics and known limitation (documented in report/query_generation_notes.md):
 * isBarrier(n) removes `n` from the data flow graph. The barrier node here is the
 * URL argument of the guard call, which is the reviewed evidence site of the check.
 * Because the fetch site uses a *different* AST node for the same variable, this
 * placement marks the guard and prunes flows that pass through the checked
 * argument itself, but it does NOT implement branch-sensitive pruning of the
 * downstream fetch (the installed new-dataflow ConfigSig has no isBarrierGuard
 * concept). Guarded sinks therefore carry their scope strings (see MySinks) so
 * Phase 2 triage can see the allow-list context. No unevidenced sanitizer is
 * modeled; login/auth gates, HTML escaping and cv.url format checks are
 * deliberately NOT barriers (per label review).
 *
 * Verified against codeql/python-all 7.1.2 (matches() patterns are string
 * literals only, as required by the QL binding rules).
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /* ------------------------------------------------------------------
   * Public interface (pass key: "ssrf")
   * ------------------------------------------------------------------ */

  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "ssrf" and guardCheckedArg(node)
  }

  /* ------------------------------------------------------------------
   * Barrier sites: the checked URL argument of each reviewed guard
   * ------------------------------------------------------------------ */

  private predicate guardCheckedArg(DataFlow::Node node) {
    // p3-san-01: color_extractor - allow-list gate before session.get(url)
    exists(Call c, Attribute func |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/color_extractor/__init__.py") and
      c.getLocation().getStartLine() = 106 and
      func = c.getFunc() and
      func.getName() = "is_allowed_external_url" and
      node = DataFlow::exprNode(c.getArg(0))
    )
    or
    // p3-san-02: discord notify - allow-list gate before async_get_file_from_url
    exists(Call c, Attribute func |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/discord/notify.py") and
      c.getLocation().getStartLine() = 74 and
      func = c.getFunc() and
      func.getName() = "is_allowed_external_url" and
      node = DataFlow::exprNode(c.getArg(0))
    )
    or
    // p3-san-03: slack notify - allow-list gate before the remote-file fetch
    exists(Call c, Attribute func |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/slack/notify.py") and
      c.getLocation().getStartLine() = 181 and
      func = c.getFunc() and
      func.getName() = "is_allowed_external_url" and
      node = DataFlow::exprNode(c.getArg(0))
    )
    or
    // p3-san-04: signal_messenger notify - allow-list gate before attachment fetch
    exists(Call c, Attribute func |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/signal_messenger/notify.py") and
      c.getLocation().getStartLine() = 139 and
      func = c.getFunc() and
      func.getName() = "is_allowed_external_url" and
      node = DataFlow::exprNode(c.getArg(0))
    )
    or
    // p3-san-05: blueprint importer - raw.githubusercontent.com prefix guard
    exists(Call c, Attribute func |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/blueprint/importer.py") and
      c.getLocation().getStartLine() = 65 and
      func = c.getFunc() and
      func.getName() = "startswith" and
      node = DataFlow::exprNode(c.getArg(0))
    )
    or
    // p3-san-06: blueprint importer - GITHUB_FILE_PATTERN host guard
    exists(Call c, Attribute func |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/blueprint/importer.py") and
      c.getLocation().getStartLine() = 68 and
      func = c.getFunc() and
      func.getName() = "match" and
      node = DataFlow::exprNode(c.getArg(0))
    )
    or
    // p3-san-07: blueprint importer - COMMUNITY_TOPIC_PATTERN host guard
    exists(Call c, Attribute func |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/blueprint/importer.py") and
      c.getLocation().getStartLine() = 81 and
      func = c.getFunc() and
      func.getName() = "match" and
      node = DataFlow::exprNode(c.getArg(0))
    )
    or
    // p3-san-08: blueprint importer - gist.github.com prefix guard
    exists(Call c, Attribute func |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/blueprint/importer.py") and
      c.getLocation().getStartLine() = 185 and
      func = c.getFunc() and
      func.getName() = "startswith" and
      node = DataFlow::exprNode(c.getArg(0))
    )
    or
    // p3-san-09: blueprint importer - WEBSITE_PATTERN host guard
    exists(Call c, Attribute func |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/blueprint/importer.py") and
      c.getLocation().getStartLine() = 236 and
      func = c.getFunc() and
      func.getName() = "match" and
      node = DataFlow::exprNode(c.getArg(0))
    )
  }
}
