
/**
 * @name GeoNode sink candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate outbound-network request call sites
 *              from the GeoNode application source for subsequent
 *              LLM labeling.
 * @id py/augur/geonode/pass3-sinks
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * Only server-side network-request call sites that exist in this
 * source tree are extracted. The application's HTTP client is the
 * `requests` library; there is no httpx / aiohttp / grequests /
 * httplib2 anywhere in the geonode package, and urllib urlopen /
 * urlretrieve appear only in the repo-root build script pavement.py
 * and in tests (both outside the extraction scope; documented as a
 * coverage boundary in detection.json, not fabricated).
 *
 * Sink families, all verified against this source:
 *
 *  A. http_client.request/get/post(url, ...) - the central GeoNode
 *     HttpClient wrapper (geonode/utils.py:1163-1282, singleton
 *     `http_client` at :1282). 16 call sites; URL at positional
 *     argument 0. Includes the PRIMARY SSRF sink of the application:
 *       geonode/proxy/views.py:194
 *         http_client.request(_url, method=request.method, ...)
 *       where _url derives from request.GET["url"] (:97)
 *     and the remote-service probe:
 *       geonode/services/serviceprocessors/base.py:81
 *         http_client.request(self.url)
 *  B. The final requests dispatch inside HttpClient.request itself:
 *       geonode/utils.py:1236  action(url=url, ...)  (keyword `url`)
 *       geonode/utils.py:1248  session.get(url, ...)
 *  C. requests.get/post/put/delete(...) module-level calls (~34 sites:
 *     geoserver security/geofence/createlayer/commands, br
 *     backup/restore, monitoring, updategeoip CLI, people OIDC
 *     profile, serviceprocessors wms, harvesting download).
 *  D. Harvester requests.Session calls: self.http_session.get/post(...)
 *     and http_session.get(...) in geonode/harvesting/harvesters/*
 *     (13 sites; base = Harvester.remote_url DB value).
 *  E. importlayers management-command session client.post(...).
 *  F. Library wrapper fetches - the network I/O happens inside the
 *     external library (OWSLib / arcrest / smart_open), which is not
 *     part of this database; the call sites are recorded as wrapper
 *     sink candidates:
 *       WebMapService(...) factory (harvesters/wms.py:54, called from
 *         serviceprocessors/wms.py:96/:272 and harvesters/wms.py:157)
 *         -> wms111.WebMapService_1_1_1 / wms130.WebMapService_1_3_0
 *       WebCoverageService (geoserver/helpers.py:1312)
 *       WebFeatureService (layers/views.py:271)
 *       owslib openURL (thumbs/utils.py:421 - thumbnail GetMap)
 *       owslib http_post (catalogue/backends/generic.py:146)
 *       CatalogueServiceWeb.__init__(url=...) (catalogue/backends/
 *         generic.py:56, keyword url, skip_caps defaults to True)
 *       arcrest.MapService/ImageService/Catalog (harvesters/arcgis.py)
 *       smart_open.open(uri=...) (storage/data_retriever.py:115,
 *         keyword uri - remote file URI download)
 *
 * Things deliberately NOT extracted as CWE-918 sinks:
 *   - HttpResponseRedirect / document_embed redirects: HTTP redirect
 *     responses for client-side navigation (Pass 9 / CWE-601
 *     material), the server fetches nothing.
 *   - urljoin / urlparse / urlsplit / URL.from_text / geturl: URL
 *     parsing and construction only; recorded in detection.json's
 *     url_construction_surfaces, dangerous only when tied to a real
 *     fetch call site.
 *   - requests.Session() / requests.adapters.HTTPAdapter / Retry
 *     constructions: session setup, no request is issued.
 *   - requests.request("PUT", ...) at layers/api/views.py:118: inside
 *     an endpoint docstring, not executable code.
 *   - settings.* attribute reads (operator-configured endpoints are
 *     labeling-stage FP material per the SSRF heuristics, not sinks).
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("sink_candidate")
 *  3. callable            (dotted signature hint)
 *  4. flow kind           (argument)
 *  5. receiver            (receiver/type hint)
 *  6. module hint         (dotted module path; variable named moduleHint,
 *                          "module" is a QL keyword and must not be used)
 *  7. argument index      (0-based positional index of the URL
 *                          argument; -1 when the URL is passed as a
 *                          keyword argument - see families B, F)
 *  8. line
 *  9. file:line
 * 10. expression text
 *
 * flow kind vocabulary:
 *   argument - the tainted URL position is an argument of the
 *              network call (positional, or keyword for argIndex -1)
 *
 * Verified API usage (codeql/python-all 7.1.2, CLI 2.25.1):
 *   Call.getFunc(), Attribute.getName()/getObject(), Name.getId(),
 *   AstNode.getLocation().getFile().getRelativePath() /
 *   getStartLine(); the module path strings are always bound by
 *   equality before any matches() comparison.
 */

import python

// ------------------------------------------------------------
// 1. Scope and location helpers
// ------------------------------------------------------------

/**
 * Restrict extraction to the GeoNode application package.
 *
 * The CodeQL database source root is the repository root, so relative
 * paths of application files look like "geonode/proxy/views.py".
 * "geonode/%" cannot match the nested "geonode-db/" database
 * directory (position 7 is '-' vs '/'). Tests, migrations and locale
 * catalogs are excluded (FP / generated code per global heuristics).
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("geonode/%") and
    not path.matches("geonode/tests/%") and
    not path.matches("%/tests/%") and
    not path.matches("%/tests.py") and
    not path.matches("%/test_%.py") and
    not path.matches("%/migrations/%") and
    not path.matches("geonode/locale/%")
  )
}

/**
 * Restrict a candidate to one application module. The path string is
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
    // (A) http_client.request/get/post(url, ...) - the central
    //     GeoNode HttpClient wrapper. Call sites (all verified):
    //       geonode/proxy/views.py:194 (proxy target URL - PRIMARY),
    //       geonode/services/serviceprocessors/base.py:81 (probe of
    //         the user-registered remote service URL),
    //       geonode/utils.py:1883 (is_monochromatic_image fetch of
    //         resource.thumbnail_url),
    //       geonode/thumbs/background.py:351 (XYZ tile URL),
    //       geonode/maps/views.py:414, geonode/geoserver/views.py:623,
    //       geonode/geoserver/helpers.py:127/1012/1030/1066/1082/1617/
    //         1648/1665/1680, geonode/geoserver/ows.py:182
    //     URL is positional argument 0 in every call shape.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name client |
      n = c and
      fn = c.getFunc() and
      (fn.getName() = "request" or fn.getName() = "get" or fn.getName() = "post") and
      client = fn.getObject() and
      client.getId() = "http_client" and
      callableName = "geonode.utils.HttpClient." + fn.getName() and
      flowKind = "argument" and
      receiverHint = "geonode.utils.http_client (HttpClient singleton; composes requests.Session with verify=False)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (B1) action(url=url, ...) - the FINAL requests dispatch inside
    //      HttpClient.request (geonode/utils.py:1236):
    //        action = getattr(session, method.lower(), None)
    //        response = action(url=url, data=data, ...)
    //      The URL is the `url` keyword argument, hence argIndex -1.
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc() and
      fn.getId() = "action" and
      inModule(c, "geonode/utils.py") and
      callableName = "requests.Session.<verb> (dispatched via action())" and
      flowKind = "argument" and
      receiverHint = "requests.Session method bound by getattr(session, method.lower()) - URL passed as the `url` keyword argument" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (B2) session.get(url, ...) - the fallback dispatch inside
    //      HttpClient.request (geonode/utils.py:1248)
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name sess |
      n = c and
      fn = c.getFunc() and
      fn.getName() = "get" and
      sess = fn.getObject() and
      sess.getId() = "session" and
      inModule(c, "geonode/utils.py") and
      callableName = "requests.Session.get" and
      flowKind = "argument" and
      receiverHint = "requests.Session (created in geonode.utils.HttpClient.request)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (C) requests.get/post/put/delete(url, ...) - direct
    //     module-level calls. Verified sites:
    //       geonode/harvesting/harvesters/base.py:334
    //         requests.get(url, stream=True) - download of the
    //         remote-declared download_url (no host check)
    //       geonode/services/serviceprocessors/wms.py:284
    //         requests.get(f"{base_url}api/ows_endpoints/", ...,
    //         verify=False) - user-supplied service URL
    //       geonode/monitoring/service_handlers.py:196/:215 and
    //         monitoring/utils.py:140/:157 (service URLs, verify=False)
    //       geonode/monitoring/management/commands/updategeoip.py:61
    //         (CLI --url option)
    //       geonode/people/adapters.py:265 (OIDC profile URL,
    //         settings-derived)
    //       geonode/geoserver/security.py:94/157/188/216,
    //         geoserver/geofence.py:253/292/316/342/369,
    //         geoserver/createlayer/utils.py:219,
    //         geoserver/management/commands/set_default_gridsets.py:50/85,
    //         geonode/br/management/commands/create_tile_layers.py:97/107,
    //         backup.py:342-396, restore.py:719-759
    //       (OGC_SERVER LOCATION config URLs; backup/restore also
    //        follow href values parsed from geoserver responses)
    //     URL is positional argument 0 in every call shape.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name req |
      n = c and
      fn = c.getFunc() and
      (fn.getName() = "get" or fn.getName() = "post" or fn.getName() = "put" or fn.getName() = "delete") and
      req = fn.getObject() and
      req.getId() = "requests" and
      callableName = "requests." + fn.getName() and
      flowKind = "argument" and
      receiverHint = "requests (module-level API)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (D1) self.http_session.get/post(url, ...) - harvester workers
    //      keeping a requests.Session on self.http_session:
    //        geonode/harvesting/harvesters/wms.py:203 (GetCapabilities
    //          of the harvester remote_url),
    //        geonode/harvesting/harvesters/geonodeharvester.py:145/159/
    //          201/578/674/701/758/939 (f"{self.remote_url}/api[v2]..."
    //          URL constructions),
    //        geonode/harvesting/harvesters/arcgis.py:156/:277
    //          (DB-stored remote layer unique_identifier URLs)
    //      URL is positional argument 0.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Attribute hs, Name selfName |
      n = c and
      fn = c.getFunc() and
      (fn.getName() = "get" or fn.getName() = "post") and
      hs = fn.getObject() and
      hs.getName() = "http_session" and
      selfName = hs.getObject() and
      selfName.getId() = "self" and
      callableName = "requests.Session." + fn.getName() and
      flowKind = "argument" and
      receiverHint = "self.http_session (requests.Session created in harvester __init__)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (D2) http_session.get(url, ...) - the module-level
    //      _check_availability(http_session, url, ...) helper
    //      (geonode/harvesting/harvesters/geonodeharvester.py:1274),
    //      called with URLs derived from the harvester remote_url.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name sess |
      n = c and
      fn = c.getFunc() and
      (fn.getName() = "get" or fn.getName() = "post") and
      sess = fn.getObject() and
      sess.getId() = "http_session" and
      callableName = "requests.Session." + fn.getName() and
      flowKind = "argument" and
      receiverHint = "http_session (requests.Session passed as a function parameter)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (E) client.post(urljoin(self.host, "/api/v2/uploads/upload/"), ...)
    //     - geonode/geoserver/management/commands/importlayers.py:152,
    //     a requests.session() kept in the local variable `client`;
    //     self.host comes from the CLI --host option or SITEURL.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name cl |
      n = c and
      fn = c.getFunc() and
      (fn.getName() = "get" or fn.getName() = "post" or fn.getName() = "put") and
      cl = fn.getObject() and
      cl.getId() = "client" and
      inModule(c, "geonode/geoserver/management/commands/importlayers.py") and
      callableName = "requests.Session." + fn.getName() and
      flowKind = "argument" and
      receiverHint = "client (requests.session() local variable; host from CLI --host option or settings.SITEURL)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (F1) WebMapService(url, version=...) - GeoNode's OWSLib factory
    //      (geonode/harvesting/harvesters/wms.py:54, lru_cache) that
    //      constructs wms111/wms130 clients, which fetch remote
    //      GetCapabilities inside the OWSLib library. Call sites:
    //        geonode/services/serviceprocessors/wms.py:96/:272
    //          (user-supplied service URL from CreateServiceForm),
    //        geonode/harvesting/harvesters/wms.py:157
    //          (get_wms_operations on a passed-in URL).
    //      URL is positional argument 0.
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc() and
      fn.getId() = "WebMapService" and
      callableName = "geonode.harvesting.harvesters.wms.WebMapService" and
      flowKind = "argument" and
      receiverHint = "OWSLib wrapper factory (network I/O inside the external owslib library)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (F2) wms111.WebMapService_1_1_1(clean_url, ...) /
    //      wms130.WebMapService_1_3_0(clean_url, ...) - the OWSLib
    //      client constructors invoked by the factory above
    //      (geonode/harvesting/harvesters/wms.py:78/:92). These issue
    //      the GetCapabilities request inside the OWSLib library.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name mod |
      n = c and
      fn = c.getFunc() and
      (fn.getName() = "WebMapService_1_1_1" or fn.getName() = "WebMapService_1_3_0") and
      mod = fn.getObject() and
      (mod.getId() = "wms111" or mod.getId() = "wms130") and
      callableName = "owslib." + mod.getId() + "." + fn.getName() and
      flowKind = "argument" and
      receiverHint = "OWSLib WMS client constructor (GetCapabilities fetch inside the external owslib library)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (F3) WebCoverageService(f"{ogc_server_settings.LOCATION}wcs", ...)
    //      - geonode/geoserver/helpers.py:1312 (owslib.wcs) and
    //      WebFeatureService(location, version="1.1.0", ...)
    //      - geonode/layers/views.py:271 (owslib.wfs; location is the
    //        settings OGC_SERVER LOCATION wms endpoint)
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc() and
      (fn.getId() = "WebCoverageService" or fn.getId() = "WebFeatureService") and
      callableName = "owslib." + fn.getId() and
      flowKind = "argument" and
      receiverHint = "OWSLib client constructor (capabilities fetch inside the external owslib library)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (F4) openURL(base_url, data, method, ...) - owslib.util.openURL,
    //      called in geonode/thumbs/utils.py:421 getmap(); base_url is
    //      the WMS thumbnail base (ogc_server LOCATION or a remote
    //      service / Dataset.ows_url derived value).
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc() and
      fn.getId() = "openURL" and
      callableName = "owslib.util.openURL" and
      flowKind = "argument" and
      receiverHint = "OWSLib URL opener (network I/O inside the external owslib library)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (F5) http_post(self.url, md_doc, ...) - owslib.util.http_post,
    //      called in geonode/catalogue/backends/generic.py:146
    //      Catalogue.csw_request (settings.CATALOGUE URL).
    // --------------------------------------------------------

    exists(Call c, Name fn |
      n = c and
      fn = c.getFunc() and
      fn.getId() = "http_post" and
      callableName = "owslib.util.http_post" and
      flowKind = "argument" and
      receiverHint = "OWSLib HTTP POST helper (network I/O inside the external owslib library)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (F6) CatalogueServiceWeb.__init__(self, url=self.url, ...) -
    //      geonode/catalogue/backends/generic.py:56 (class Catalogue
    //      subclasses CatalogueServiceWeb). The URL is the `url`
    //      keyword argument (positional argument 0 is `self`), hence
    //      argIndex -1; skip_caps defaults to True so GetCapabilities
    //      is only fetched when explicitly enabled.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name cls |
      n = c and
      fn = c.getFunc() and
      fn.getName() = "__init__" and
      cls = fn.getObject() and
      cls.getId() = "CatalogueServiceWeb" and
      callableName = "owslib.catalogue.csw2.CatalogueServiceWeb.__init__" and
      flowKind = "argument" and
      receiverHint = "OWSLib CSW client constructor (URL passed as the `url` keyword argument; capabilities fetch inside the external owslib library)" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (F7) arcrest.MapService/ImageService(resource_unique_identifier)
    //      (geonode/harvesting/harvesters/arcgis.py:347/:350) and
    //      arcrest.Catalog(self.remote_url) (:410) - the arcrest
    //      library fetches the REST catalog/layer JSON over HTTP.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name mod |
      n = c and
      fn = c.getFunc() and
      (fn.getName() = "MapService" or fn.getName() = "ImageService" or fn.getName() = "Catalog") and
      mod = fn.getObject() and
      mod.getId() = "arcrest" and
      callableName = "arcrest." + fn.getName() and
      flowKind = "argument" and
      receiverHint = "arcrest client constructor (network I/O inside the external arcrest library)" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (F8) smart_open.open(uri=..., mode="rb") -
    //      geonode/storage/data_retriever.py:115-117
    //      DataItemRetriever.transfer_remote_file: smart_open fetches
    //      remote http(s):// file URIs (the `_original_file_uri` comes
    //      from remote_files values passed through the storage
    //      manager from upload/metadata endpoints). The URI is the
    //      `uri` keyword argument, hence argIndex -1.
    // --------------------------------------------------------

    exists(Call c, Attribute fn, Name mod |
      n = c and
      fn = c.getFunc() and
      fn.getName() = "open" and
      mod = fn.getObject() and
      mod.getId() = "smart_open" and
      callableName = "smart_open.open" and
      flowKind = "argument" and
      receiverHint = "smart_open remote URI reader (URI passed as the `uri` keyword argument; network I/O inside the external smart_open library)" and
      argIndex = -1
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
