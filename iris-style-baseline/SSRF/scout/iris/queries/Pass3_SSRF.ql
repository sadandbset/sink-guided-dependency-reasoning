/**
 * @name Pass 3: Server-side request forgery via request-derived URLs
 * @description Finds untrusted web-request inputs of the Flask routes (the
 *   /remote/cors/<path:remote_url> route variable that the CORS proxy
 *   forwards verbatim to requests.request, the Host-header-derived
 *   request.url_root base URL of the chanjo coverage report POST, and the
 *   url_for(..., _external=True) URL of the MT coverage stats POST) flowing
 *   into the URL argument positions of the server-side network requests of
 *   scout: the remote CORS proxy requests.request, the chanjo coverage
 *   requests.post calls, the shared scout_requests wrapper egress sites,
 *   the ftp urlopen, the Ensembl/LoqusDB/rank-model fixed-host fetches, and
 *   the MatchMaker host-pinned wrapper invocations. Rendered by Augur
 *   Phase 2 Steps 4-5 from the human-reviewed Pass 3 labels in
 *   iris/labels/labels.json (CWE-918).
 * @id py/augur/scout/pass3-ssrf
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

module Pass3Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "ssrf")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "ssrf")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "ssrf")
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "ssrf")
  }
}

module Pass3Flow = TaintTracking::Global<Pass3Config>;
import Pass3Flow::PathGraph

from Pass3Flow::PathNode source, Pass3Flow::PathNode sink, string msg
where
  Pass3Flow::flowPath(source, sink) and
  ssrfMessage(sink.getNode(), msg)
select sink.getNode(), source, sink, msg

/**
 * The alert message, differentiated by the attacker's URL control scope at
 * the reviewed sink sites (per the labeling rubric: full target control,
 * host-only control via the Host header, fixed-host path/query embedding,
 * host-pinned server-issued path ids, and generic wrapper egress must not
 * be conflated into one severity).
 *
 * Branches are mutually exclusive by (database-relative sink file, sink
 * expression line):
 *   - alignviewers/views.py (remote CORS proxy, snk-044): full target
 *     control - the route variable is the entire outbound URL.
 *   - cases/controllers.py:94-95 (coverage report POST, snk-004): host-only
 *     control - request.url_root derives from the Host header.
 *   - cases/controllers.py:548/554 (MT stats POST, snk-005/snk-006):
 *     host-only control - url_for(..., _external=True) host derives from
 *     the Host header unless SERVER_NAME is configured.
 *   - cases/controllers.py:1163/1206/1257 (MatchMaker wrappers,
 *     snk-010/011/013): host pinned to admin MME_URL, path parts are
 *     server-issued patient/node ids.
 *   - scout_requests.py:34-110 (shared wrapper egress, snk-025..032):
 *     URL argument of the wrapper's requests.* call; audited callers pass
 *     admin-config URLs - an alert flags an unmodeled flow.
 *   - scout_requests.py:141 (ftp urlopen, snk-033): cross-protocol ftp
 *     branch, only constant ftp URLs audited to reach it.
 *   - scout_requests.py:438 (refseq version lookup, snk-042): fixed
 *     eutils.ncbi host, DB-derived refseq id in the query.
 *   - ensembl_rest_clients.py:81 (snk-014): constant Ensembl host,
 *     DB-derived genomic coordinates in path/query.
 *   - loqus_extension.py:242 (snk-018): admin LoqusDB host, DB-derived
 *     variant coordinates/ids in path/query.
 *   - rank_model.py:23 (snk-024): config-pinned github raw host, case
 *     rank_model_version as the variable path segment.
 */
private predicate ssrfMessage(DataFlow::Node sink, string msg) {
  exists(string relPath, int line |
    relPath = sink.asExpr().getLocation().getFile().getRelativePath() and
    line = sink.asExpr().getLocation().getStartLine() and
    (
      (
        relPath = "scout/server/blueprints/alignviewers/views.py" and
        line in [42, 44]
      ) and
      msg = "SSRF (full target control): the client-supplied /remote/cors/<path:remote_url> route variable is forwarded verbatim as the url of requests.request with allow_redirects=True (scout/server/blueprints/alignviewers/views.py:42). " +
        "Any authenticated user controls scheme, host, port and path of the outbound request; inbound headers (minus Host), body and cookies are also forwarded. " +
        "No scheme/host validation or allowlist exists anywhere on this path."
      or
      (
        relPath = "scout/server/blueprints/cases/controllers.py" and
        line in [94, 95]
      ) and
      msg = "SSRF (host control via Host header): request.url_root (Host-header-derived, scout/server/blueprints/cases/views.py:225) is concatenated with 'reports/report' and POSTed server-side (cases/controllers.py:94). " +
        "An authenticated user with case access steers the outbound host (and port via the Host header) when the chanjo coverage integration is enabled; the path is fixed. " +
        "Requires SQLALCHEMY_DATABASE_URI to be configured."
      or
      (
        relPath = "scout/server/blueprints/cases/controllers.py" and
        line in [548, 554]
      ) and
      msg = "SSRF (host control via Host header / SERVER_NAME): url_for('report.json_chrom_coverage', _external=True) (cases/controllers.py:544) builds the POST target host from the request Host header unless SERVER_NAME is configured (scout/server/config.py defines none). " +
        "The path is fixed to the app's own chanjo MT coverage endpoint; host-only control by an authenticated user."
      or
      (
        relPath = "scout/server/blueprints/cases/controllers.py" and
        line in [1163, 1206, 1257]
      ) and
      msg = "SSRF (path-only, host pinned): the MatchMaker patient_delete/patient_matches/match_external wrapper embeds a server-issued patient id (and node id filtered against the connected MME nodes) into the URL path on the admin-configured MME_URL host (matchmaker_extension.py:90/122/150). " +
        "The attacker controls neither scheme, host nor port - second-order path control only; triage as likely false positive unless patient ids can be forged."
      or
      (
        relPath = "scout/utils/scout_requests.py" and
        line in [34, 36, 59, 61, 85, 87, 89, 110]
      ) and
      msg = "SSRF (wrapper egress): taint reached the URL argument (positional 0) of the requests.post/get/delete call inside the shared scout_requests HTTP wrapper (post_request_json/get_request_json/delete_request_json/get_request). " +
        "All wrapper call sites audited in Phase 1 pass admin-configured or constant URLs, so this alert indicates an unmodeled flow and needs manual triage."
      or
      (
        relPath = "scout/utils/scout_requests.py" and
        line = 141
      ) and
      msg = "SSRF (ftp urlopen, cross-protocol): taint reached the URL argument of urllib.request.urlopen in the ftp branch of fetch_resource (scout/utils/scout_requests.py:141). " +
        "Only constant ftp:// URLs (HGNC, ExAC) were audited to reach this branch; urlopen would also honor file:/data: schemes, so verify the reaching value before dismissing."
      or
      (
        relPath = "scout/utils/scout_requests.py" and
        line = 438
      ) and
      msg = "SSRF (fixed-host query embedding): the refseq accession from case/variant DB content is embedded into the query string of the fixed https://eutils.ncbi.nlm.nih.gov URL passed to get_request (scout/utils/scout_requests.py:438, fetch_refseq_version, web-reachable via variant/controllers.py:659). " +
        "Host and scheme are pinned; only the query component is data-derived."
      or
      (
        relPath = "scout/utils/ensembl_rest_clients.py" and
        line = 81
      ) and
      msg = "SSRF (fixed-host path/query): genomic coordinates (chrom/start/end) from case/variant DB content are embedded into the URL of the Ensembl REST fetch on the hard-constant grch37/rest.ensembl.org host (scout/utils/ensembl_rest_clients.py:81, web-reachable via the variant liftover calls). " +
        "Host and scheme are pinned; only path/query components are data-derived."
      or
      (
        relPath = "scout/server/extensions/loqus_extension.py" and
        line = 242
      ) and
      msg = "SSRF (admin host, DB-derived path/query): variant category/coordinates/ids from the database are appended to the admin-configured LoqusDB api_url (loqus_extension.py:229-242, get_api_loqus_variant, web-reachable from variant pages). " +
        "The host is deployment configuration; only path/query components are data-derived."
      or
      (
        relPath = "scout/adapter/mongo/rank_model.py" and
        line = 23
      ) and
      msg = "SSRF (config-pinned host, version path segment): the case rank_model_version from DB content is concatenated between the admin-config RANK_MODEL_LINK_PREFIX and postfix (rank_model.py:75-77, web-reachable via variant/controllers.py:412). " +
        "The host is pinned by configuration (default raw.githubusercontent.com); only the version path segment is data-derived."
    )
  )
}
