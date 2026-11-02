/**
 * Augur Phase 2 - Pass 3 (CWE-918 SSRF) sink library.
 * Generated from reviewed labels: iris/labels/labels.json (pass 3, 20 sink entries:
 * 13 tp + 7 candidate). Sinks are pinned to the exact reviewed call sites and
 * argument positions - the labels marked every other requests and session-method
 * location in the tree as fixed-URL/config-URL false positives, so only the 20
 * reviewed positions are modeled (no generic requests.get signature).
 *
 * Label -> predicate mapping (label id | site | arg index | controllability scope):
 *   p3-snk-3603 downloader/__init__.py:81              get     arg0  full URL (authenticated service data)
 *   p3-snk-3601 telegram_bot/__init__.py:310           get     arg0  full URL (authenticated service data)
 *   p3-snk-3639 pushsafer/notify.py:157                get     arg0  full URL (notify attachment)
 *   p3-snk-3640 pushsafer/notify.py:159                get     arg0  full URL (notify attachment)
 *   p3-snk-3646 nfandroidtv/notify.py:183              get     arg0  full URL (notify image/icon)
 *   p3-snk-3647 nfandroidtv/notify.py:186              get     arg0  full URL (notify image/icon)
 *   p3-snk-3650 xmpp/notify.py:270                     get     arg0  full URL (notify upload url)
 *   p3-snk-3641 signal_messenger/notify.py:143         get     arg0  full URL (allow-list guarded)
 *   p3-snk-3734 auth/indieauth.py:95                   get     arg0  full URL incl. host (unauth-origin client_id)
 *   p3-snk-3730 blueprint/importer.py:155              get     arg0  host locked to community.home-assistant.io
 *   p3-snk-3731 blueprint/importer.py:168              get     arg0  host locked to raw.githubusercontent.com
 *   p3-snk-3732 blueprint/importer.py:192              get     arg0  fixed host api.github.com (gist id path only)
 *   p3-snk-3733 blueprint/importer.py:237              get     arg0  host locked to *.home-assistant.io
 *   p3-snk-3735 hassio/ingress.py:134                  ws_connect arg0 fixed supervisor host (path/query only)
 *   p3-snk-3736 hassio/ingress.py:159                  request arg1  fixed supervisor host (path/query only)
 *   p3-snk-3749 mobile_app/notify.py:168               post    arg0  registrant-chosen push_url
 *   p3-snk-3725 cast/helpers.py:252                    get     arg0  full URL via media resolution
 *   p3-snk-3693 media_player/__init__.py:1262          get     arg0  full URL via media browse/artwork
 *   p3-snk-3717 helpers/config_entry_oauth2_flow.py:523 request arg1 parameterized wrapper (in-tree callers fixed)
 *   p3-snk-3831 rest_command/__init__.py:121           getattr arg0  template-rendered URL (admin template + service data)
 *
 * getSinkAlertMessage() returns the full alert message for a sink, embedding the
 * reviewed attacker-controllability scope so the query distinguishes full-URL
 * control from host-restricted and path-only control instead of mixing severities.
 *
 * Verified against codeql/python-all 7.1.2 (Call.getArg(int), Location API; the
 * database stores forward-slash absolute paths - proven by the Phase 1 CSV output;
 * matches() patterns are string literals only, as required by the QL binding rules).
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySinks {

  /* ------------------------------------------------------------------
   * Public interface (pass key: "ssrf")
   * ------------------------------------------------------------------ */

  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "ssrf" and sinkSite(sink, _)
  }

  /** Gets the full CWE-918 alert message for `sink`, embedding its reviewed controllability scope. */
  string getSinkAlertMessage(DataFlow::Node sink, string passKey) {
    passKey = "ssrf" and sinkSite(sink, result)
  }

  /* ------------------------------------------------------------------
   * The 20 reviewed sink sites (label-pinned location + URL argument)
   * ------------------------------------------------------------------ */

  private predicate sinkSite(DataFlow::Node sink, string message) {
    // p3-snk-3603: downloader.download_file service - url = service.data[ATTR_URL]
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/downloader/__init__.py") and
      c.getLocation().getStartLine() = 81 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL controlled by any authenticated user (downloader service data, cv.url format check only)."
    )
    or
    // p3-snk-3601: telegram_bot send_file - url = service data ATTR_URL
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/telegram_bot/__init__.py") and
      c.getLocation().getStartLine() = 310 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL controlled by any authenticated user (telegram_bot service data, no allow-list)."
    )
    or
    // p3-snk-3639: pushsafer notify picture1.url (basic-auth branch)
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/pushsafer/notify.py") and
      c.getLocation().getStartLine() = 157 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL controlled by any authenticated user (pushsafer notify attachment URL, no allow-list)."
    )
    or
    // p3-snk-3640: pushsafer notify picture1.url (no-auth branch)
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/pushsafer/notify.py") and
      c.getLocation().getStartLine() = 159 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL controlled by any authenticated user (pushsafer notify attachment URL, no allow-list)."
    )
    or
    // p3-snk-3646: nfandroidtv notify image url (auth branch)
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/nfandroidtv/notify.py") and
      c.getLocation().getStartLine() = 183 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL controlled by any authenticated user (nfandroidtv notify image URL, no allow-list)."
    )
    or
    // p3-snk-3647: nfandroidtv notify image url (no-auth branch)
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/nfandroidtv/notify.py") and
      c.getLocation().getStartLine() = 186 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL controlled by any authenticated user (nfandroidtv notify image URL, no allow-list)."
    )
    or
    // p3-snk-3650: xmpp notify http-upload source url
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/xmpp/notify.py") and
      c.getLocation().getStartLine() = 270 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL controlled by any authenticated user (xmpp notify message url, no allow-list)."
    )
    or
    // p3-snk-3641: signal_messenger notify attachments (allow-list guarded)
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/signal_messenger/notify.py") and
      c.getLocation().getStartLine() = 143 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL, guarded by default-deny is_allowed_external_url allow-list (sanitizer p3-san-04)."
    )
    or
    // p3-snk-3734: auth/indieauth client_id page fetch
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/auth/indieauth.py") and
      c.getLocation().getStartLine() = 95 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL including host; unauthenticated-origin client_id (login flow / onboarding); internal IPs explicitly allowed; 10kB read cap."
    )
    or
    // p3-snk-3730: blueprint community-post import
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/blueprint/importer.py") and
      c.getLocation().getStartLine() = 155 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: host locked to community.home-assistant.io by COMMUNITY_TOPIC_PATTERN (sanitizer p3-san-07); attacker chooses topic/post path."
    )
    or
    // p3-snk-3731: blueprint github raw import
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/blueprint/importer.py") and
      c.getLocation().getStartLine() = 168 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: host locked to raw.githubusercontent.com (sanitizers p3-san-05/06); attacker chooses repo/path."
    )
    or
    // p3-snk-3732: blueprint gist import
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/blueprint/importer.py") and
      c.getLocation().getStartLine() = 192 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: fixed host api.github.com; attacker only chooses gist id (path); source url must start with gist.github.com."
    )
    or
    // p3-snk-3733: blueprint website import
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/blueprint/importer.py") and
      c.getLocation().getStartLine() = 237 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: host locked to home-assistant.io subdomains by WEBSITE_PATTERN (sanitizer p3-san-09)."
    )
    or
    // p3-snk-3735: hassio ingress websocket proxy
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/hassio/ingress.py") and
      c.getLocation().getStartLine() = 134 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: fixed supervisor host; attacker controls only path/query (ingress-authenticated session)."
    )
    or
    // p3-snk-3736: hassio ingress http proxy
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/hassio/ingress.py") and
      c.getLocation().getStartLine() = 159 and
      sink = DataFlow::exprNode(c.getArg(1)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: fixed supervisor host; attacker controls only path/query/method (ingress-authenticated session)."
    )
    or
    // p3-snk-3749: mobile_app push notification
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/mobile_app/notify.py") and
      c.getLocation().getStartLine() = 168 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: registrant-chosen push_url from device registration app_data (webhook-updatable)."
    )
    or
    // p3-snk-3725: cast playlist fetch
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/cast/helpers.py") and
      c.getLocation().getStartLine() = 252 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL via media resolution (media_content_id of authenticated user); _is_url is format check only."
    )
    or
    // p3-snk-3693: media_player artwork fetch
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/media_player/__init__.py") and
      c.getLocation().getStartLine() = 1262 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL via media browse/artwork (authenticated user)."
    )
    or
    // p3-snk-3717: oauth2 session request wrapper
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/helpers/config_entry_oauth2_flow.py") and
      c.getLocation().getStartLine() = 523 and
      sink = DataFlow::exprNode(c.getArg(1)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: parameterized wrapper URL; all in-tree callers pass fixed vendor/config endpoints."
    )
    or
    // p3-snk-3831: rest_command dynamic dispatch
    exists(Call c |
      c.getLocation().getFile().getAbsolutePath().matches("%/homeassistant/components/rest_command/__init__.py") and
      c.getLocation().getStartLine() = 121 and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: template-rendered URL; admin YAML template with authenticated service data variables; host control only if template references a variable in scheme or host."
    )
  }
}
