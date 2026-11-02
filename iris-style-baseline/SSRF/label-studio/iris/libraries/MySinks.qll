/**
 * Augur Phase 2 - Pass 3 (CWE-918 SSRF) sink library for label-studio.
 * Generated from reviewed labels: iris/labels/labels.json (pass 3, 9 sink
 * entries: 5 tp + 1 candidate + 3 fp). Only the reviewed non-false-positive
 * HTTP request sites are modeled:
 *
 *   p3-snk-005 core/utils/io.py:224          requests.get  arg0 (positional URL)
 *   p3-snk-007 webhooks/utils.py:52          requests.post arg0 (positional URL)
 *   p3-snk-002 ml/api_connector.py:81        requests.Session.request transport -
 *                                            URL arrives as keyword `url=` through
 *                                            **kwargs; sink node = the **kwargs
 *                                            forwarding argument of the pinned call
 *                                            (Call.getKwargs()).
 *   p3-snk-008 io_storages/s3/utils.py:38    boto3 Session.client('s3', **settings) -
 *                                            endpoint_url forwarded via **settings;
 *                                            sink node = Call.getKwargs().
 *   p3-snk-009 io_storages/s3/utils.py:39    boto3 Session.resource('s3', **settings) -
 *                                            same as above.
 *
 * Deliberately NOT modeled (recorded as gaps in report/query_generation_notes.md):
 *   p3-snk-006 io_storages/redis/models.py:56 redis.StrictRedis(**redis_config) -
 *     reviewed classification=candidate: a non-HTTP Redis protocol connection.
 *     The formal CWE-918 query models HTTP request URL arguments only, and the
 *     Phase 1 review (phase1_review.md section 5.1) left the non-HTTP scope
 *     decision to human review; the matching source family (redis_field) is
 *     still modeled in MySources so the flow activates if the sink is added.
 *   p3-snk-001 core/utils/windows_sqlite_fix/__init__.py:28, p3-snk-003
 *     core/utils/common.py:376, p3-snk-004 core/utils/contextlog.py:312 -
 *     reviewed classification=fp (operator env-configured sqlite.org download,
 *     hardcoded pypi.org version check, fixed tele.labelstud.io telemetry):
 *     fixed destinations, no attacker control of the URL.
 *
 * Sink nodes sit exactly on the network-request URL argument (or, for the
 * kwargs-shaped transports, on the **kwargs forwarding argument of the pinned
 * transport call - the position through which the reviewed URL value reaches
 * requests.Session.request / botocore; CodeQL's Call.getArg cannot express
 * keyword/double-star positions, which the labels already recorded as a
 * modeling gap).
 *
 * getSinkAlertMessage() embeds the reviewed attacker-controllability scope of
 * each sink so the query distinguishes full-URL control from endpoint/host
 * control instead of mixing severities:
 *   - full URL (scheme constrained to http/https by an always-on check):
 *     p3-snk-005, p3-snk-007, p3-snk-002;
 *   - full endpoint URL for a protocol client (boto3): p3-snk-008/009.
 *
 * Verified against codeql/python-all 7.1.2 (Call.getArg(int)/getKwargs()/
 * getFunc(), Attribute.getName()/getObject(), Name.getId(), File.getRelativePath(),
 * Location.getStartLine(); matches() patterns are string literals only).
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
   * The 5 reviewed sink sites (label-pinned location + URL argument)
   * ------------------------------------------------------------------ */

  private predicate sinkSite(DataFlow::Node sink, string message) {
    // p3-snk-005: ssrf_safe_get fetch for import-by-URL - url comes from
    // request.data['url'] (uploader.py:239 / data_import/api.py:282)
    exists(Call c, Attribute func |
      c.getLocation().getFile().getRelativePath().matches("label_studio/core/utils/io.py") and
      c.getLocation().getStartLine() = 224 and
      func = c.getFunc() and
      func.getName() = "get" and
      func.getObject() instanceof Name and func.getObject().(Name).getId() = "requests" and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches the URL argument of a server-side HTTP request (requests.get inside ssrf_safe_get). Attacker control: full URL (host, port, path; scheme restricted to http/https by validate_upload_url) supplied by any authenticated projects_change user via POST /api/projects/{pk}/import; private-IP blocking and the post-connection peer check are disabled by default (SSRF_PROTECTION_ENABLED=False)."
    )
    or
    // p3-snk-007: webhook delivery - webhook.url is an org-member-writable
    // URLField with no delivery-side validation
    exists(Call c, Attribute func |
      c.getLocation().getFile().getRelativePath().matches("label_studio/webhooks/utils.py") and
      c.getLocation().getStartLine() = 52 and
      func = c.getFunc() and
      func.getName() = "post" and
      func.getObject() instanceof Name and func.getObject().(Name).getId() = "requests" and
      sink = DataFlow::exprNode(c.getArg(0)) and
      message = "SSRF (CWE-918): untrusted input reaches the URL argument of a server-side HTTP request (webhook delivery requests.post). Attacker control: full URL (Webhook.url URLField syntax check only, no scheme allow-list / host / private-IP validation on delivery) supplied by any authenticated organization member via /api/webhooks; Webhook.headers additionally gives control over the outbound request headers."
    )
    or
    // p3-snk-002: requests.Session.request transport for ALL ML backend
    // traffic - URL keyword forwarded through **kwargs
    exists(Call c, Attribute func |
      c.getLocation().getFile().getRelativePath().matches("label_studio/ml/api_connector.py") and
      c.getLocation().getStartLine() = 81 and
      func = c.getFunc() and
      func.getName() = "request" and
      func.getObject() instanceof Attribute and
      func.getObject().(Attribute).getName() = "http" and
      sink = DataFlow::exprNode(c.getKwargs()) and
      message = "SSRF (CWE-918): untrusted input reaches the request parameters of the ML-backend HTTP transport (requests.Session.request, URL keyword forwarded via **kwargs). Attacker control: full URL = MLBackend.url (API-writable TextField) joined with a fixed path suffix, supplied by any authenticated projects_change user via /api/ml; validate_upload_url enforces http/https but local-IP blocking is disabled by default (ML_BLOCK_LOCAL_IP=False)."
    )
    or
    // p3-snk-008: boto3 S3 client construction - endpoint_url forwarded via
    // **settings from the API-writable s3_endpoint field
    exists(Call c, Attribute func |
      c.getLocation().getFile().getRelativePath().matches("label_studio/io_storages/s3/utils.py") and
      c.getLocation().getStartLine() = 38 and
      func = c.getFunc() and
      func.getName() = "client" and
      func.getObject() instanceof Name and func.getObject().(Name).getId() = "session" and
      sink = DataFlow::exprNode(c.getKwargs()) and
      message = "SSRF (CWE-918): untrusted input reaches the endpoint configuration of a boto3 S3 client (session.client('s3', **settings) with endpoint_url; server-side HTTP performed by botocore). Attacker control: full endpoint URL (host, port, base path) from the API-writable S3ImportStorage/S3ExportStorage.s3_endpoint TextField (projects_change) or the operator S3_ENDPOINT environment fallback."
    )
    or
    // p3-snk-009: boto3 S3 resource construction - same endpoint forwarding
    exists(Call c, Attribute func |
      c.getLocation().getFile().getRelativePath().matches("label_studio/io_storages/s3/utils.py") and
      c.getLocation().getStartLine() = 39 and
      func = c.getFunc() and
      func.getName() = "resource" and
      func.getObject() instanceof Name and func.getObject().(Name).getId() = "session" and
      sink = DataFlow::exprNode(c.getKwargs()) and
      message = "SSRF (CWE-918): untrusted input reaches the endpoint configuration of a boto3 S3 resource (session.resource('s3', **settings) with endpoint_url; server-side HTTP performed by botocore). Attacker control: full endpoint URL (host, port, base path) from the API-writable S3ImportStorage/S3ExportStorage.s3_endpoint TextField (projects_change) or the operator S3_ENDPOINT environment fallback."
    )
  }
}
