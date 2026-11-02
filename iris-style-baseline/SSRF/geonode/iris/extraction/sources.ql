
/**
 * @name GeoNode source candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate external-input source nodes from the
 *              GeoNode application source for subsequent LLM labeling.
 * @id py/augur/geonode/pass3-sources
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * This database contains the full GeoNode Django application (the
 * geonode/ package: views, DRF/tastypie APIs, forms, celery tasks and
 * models). Source candidates therefore anchor on the application's own
 * request boundaries rather than framework internals:
 *
 *   (1)  request.<field> / self.request.<field> reads for client-controlled
 *        Django fields (GET/POST/COOKIES/META/FILES/body/headers/path/
 *        path_info/method/scheme) and DRF fields (data/query_params)
 *   (2)  URL-shaped request-entry subscripts request.GET/POST/data[...]
 *        whose string key is URL-ish (captures proxy request.GET["url"]
 *        and set_thumbnail request.data["file"])
 *   (3)  self.cleaned_data[...] / self.cleaned_data.get(...) URL-ish reads
 *        in forms modules (CreateServiceForm url handling)
 *   (4)  caller-controlled resource-locator parameters, anchored to the
 *        verified handler/wrapper definitions only (proxy url, geoserver
 *        route paths, service-handler url, get_service_handler base_url,
 *        harvester remote_url, download_resource_file url,
 *        is_monochromatic_image image_url, thumbs get_map/getmap bases)
 *   (5)  CreateServiceForm.url form-field definition (user POST input)
 *   (6)  DB-content URL model field definitions (Service.base_url,
 *        Harvester.remote_url, ResourceBase.thumbnail_url, Link.url,
 *        Document.doc_url, Dataset.ows_url, MapLayer.ows_url,
 *        monitoring Service.url) - populated from user input or remote
 *        metadata, later re-fetched server-side
 *   (7)  CLI option boundaries (updategeoip --url, importlayers --host)
 *
 * Verified API usage (codeql/python-all 7.1.2, CLI 2.25.1):
 *   - Parameter is a Name-or-Tuple AST node; parameter names are read
 *     via p.asName().getId(); parameter positions include `self` as
 *     index 0 for methods.
 *   - Subscript exposes getObject()/getIndex(); StringLiteral.getText()
 *     returns the unquoted string value.
 *   - AssignStmt (plain `x = expr` statements) exposes getATarget()/
 *     getValue(); class-scope membership is read via AstNode.getScope()
 *     (a Class, whose Scope.getName() is the class name).
 *   - Call.getArg(int) returns the positional argument at an index.
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("source_candidate")
 *  3. callable name       (dotted signature hint)
 *  4. flow kind           (param | return | field)
 *  5. receiver hint       (receiver/type hint)
 *  6. module hint         (dotted module path; variable named moduleHint,
 *                          "module" is a QL keyword and must not be used)
 *  7. argument index      (-1 when not applicable)
 *  8. line
 *  9. file:line
 * 10. expression text
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
 * "geonode/%" cannot match the nested "geonode-db/" database directory
 * (position 7 is '-' vs '/'). Tests, migrations and locale catalogs are
 * excluded (FP / generated code per global heuristics). Repo-root build
 * tooling (pavement.py etc.) is outside the geonode/ package and not
 * part of the deployed application.
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
// 2. Source-shape signatures (verified against this source)
// ------------------------------------------------------------

/**
 * Django HttpRequest fields whose contents originate from the HTTP
 * client (query string, form body, cookies, headers, request line,
 * scheme via the server/proxy). Framework-internal fields
 * (resolver_match, user, session, content_type, ...) are excluded.
 * The DRF fields `data` and `query_params` carry the parsed body /
 * query string of REST requests.
 */
predicate isClientRequestField(string name) {
  name in [
    "GET",
    "POST",
    "COOKIES",
    "META",
    "FILES",
    "body",
    "headers",
    "path",
    "path_info",
    "method",
    "scheme",
    "data",
    "query_params"
  ]
}

/** Django request-mapping fields (query string / form body). */
predicate isRequestMappingField(string name) {
  name = "GET" or name = "POST" or name = "data"
}

/**
 * String keys of request-entry reads that carry URL-shaped values -
 * used to keep the subscript families small and high-signal
 * (e.g. proxy request.GET["url"], set_thumbnail request.data["file"],
 * CreateServiceForm cleaned_data["url"]).
 */
predicate isUrlishKey(string name) {
  name in [
    "url",
    "host",
    "file",
    "doc_url",
    "remote_url",
    "base_url",
    "download_url",
    "href",
    "link",
    "sitemap_url",
    "thumbnail_url"
  ]
}

/**
 * Receiver hint binding for request-object field reads, expressed
 * as a plain disjunction (the QL grammar does not accept an inline
 * if-then-else value on the right-hand side of `=`): DRF fields
 * data/query_params carry the parsed body / query string of REST
 * requests, every other client field is a plain Django
 * HttpRequest field. The negation is binding-safe because the
 * Attribute `a` is bound in each enclosing branch.
 */
predicate requestReceiverHint(Attribute a, string hint) {
  (a.getName() = "data" or a.getName() = "query_params") and
  hint = "rest_framework.request.Request"
  or
  not (a.getName() = "data" or a.getName() = "query_params") and
  hint = "django.http.HttpRequest"
}

// ------------------------------------------------------------
// 3. Candidate extraction
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
    // (1) request.<field> reads on a `request` name
    //     e.g. geonode/proxy/views.py:97 request.GET["url"],
    //          geonode/security/views.py:127 request.GET.get(...),
    //          geonode/base/api/views.py:1346 request.data["file"],
    //          geonode/api/views.py:103 request.POST.get("token")
    //     The Attribute node itself is the materialization of the
    //     client-controlled value, whether it is read directly,
    //     chained (.get(...)), or subscripted.
    // --------------------------------------------------------

    exists(Attribute a, Name req |
      n = a and
      isClientRequestField(a.getName()) and
      req = a.getObject() and
      req.getId() = "request" and
      callableName = "request." + a.getName() and
      flowKind = "field" and
      requestReceiverHint(a, receiverHint) and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (2) self.request.<field> reads (class-based views / DRF
    //     viewsets / autocomplete views)
    //     e.g. geonode/base/views.py:338 self.request.GET.get("sysid")
    // --------------------------------------------------------

    exists(Attribute a, Attribute reqAttr, Name selfName |
      n = a and
      isClientRequestField(a.getName()) and
      reqAttr = a.getObject() and
      reqAttr.getName() = "request" and
      selfName = reqAttr.getObject() and
      selfName.getId() = "self" and
      callableName = "request." + a.getName() and
      flowKind = "field" and
      requestReceiverHint(a, receiverHint) and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (3) URL-shaped request-entry subscripts:
    //     request.<GET|POST|data>["<url-ish key>"]
    //     - geonode/proxy/views.py:97 raw_url = url or
    //       request.GET["url"] - the proxy target URL (PRIMARY
    //       source of the application)
    //     - geonode/base/api/views.py:1346
    //       file_data = request.data["file"] - set_thumbnail
    //       accepts an arbitrary image URL string here
    //     - geonode/views.py:174 url = request.POST["url"]
    //       (metadata_update_redirect)
    // --------------------------------------------------------

    exists(Subscript s, Attribute a, Name req, StringLiteral idx |
      n = s and
      a = s.getObject() and
      isRequestMappingField(a.getName()) and
      req = a.getObject() and
      req.getId() = "request" and
      idx = s.getIndex() and
      isUrlishKey(idx.getText()) and
      callableName = "request." + a.getName() + "[" + idx.getText() + "]" and
      flowKind = "field" and
      requestReceiverHint(a, receiverHint) and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (4) URL-shaped form cleaned_data reads:
    //     - geonode/services/forms.py:55
    //       proposed_url = self.cleaned_data["url"] (clean_url)
    //       and :64 url = self.cleaned_data.get("url") (clean)
    //       - the user-registered remote service URL that is
    //         fetched DURING form validation (forms.py:68/:72)
    //     - geonode/documents/forms.py:211
    //       doc_url = self.cleaned_data.get("doc_url")
    // --------------------------------------------------------

    exists(Subscript s, Attribute cd, Name selfName, StringLiteral idx |
      n = s and
      cd = s.getObject() and
      cd.getName() = "cleaned_data" and
      selfName = cd.getObject() and
      selfName.getId() = "self" and
      idx = s.getIndex() and
      isUrlishKey(idx.getText()) and
      callableName = "self.cleaned_data[" + idx.getText() + "]" and
      flowKind = "field" and
      receiverHint = "django.forms.Form.cleaned_data" and
      argIndex = -1
    )

    or

    exists(Call c, Attribute getAttr, Attribute cd, Name selfName, StringLiteral key |
      n = c and
      getAttr = c.getFunc() and
      getAttr.getName() = "get" and
      cd = getAttr.getObject() and
      cd.getName() = "cleaned_data" and
      selfName = cd.getObject() and
      selfName.getId() = "self" and
      key = c.getArg(0) and
      isUrlishKey(key.getText()) and
      callableName = "self.cleaned_data.get" and
      flowKind = "return" and
      receiverHint = "django.forms.Form.cleaned_data" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (5) Caller-controlled resource-locator parameters, anchored
    //     to the verified handler/wrapper definitions in this
    //     source (NOT a blanket url-parameter family):
    //
    //     a) proxy(request, url=None, ...) - geonode/proxy/views.py:70
    //        the /proxy/ target URL; in-tree callers pass the
    //        geoserver-prefixed URL built from the request route
    //        (geoserver/views.py:466), the query-string value
    //        request.GET["url"] wins when url is None.
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "proxy" and
      p.asName().getId() = "url" and
      inModule(f, "geonode/proxy/views.py") and
      callableName = "geonode.proxy.views.proxy.url" and
      flowKind = "param" and
      receiverHint = "geonode.proxy.views" and
      argIndex = i
    )

    or

    //     b) geoserver_proxy(request, proxy_path, downstream_path,
    //        workspace, layername) - geonode/geoserver/views.py:417
    //        route-derived URL path components (mounted at /gs/,
    //        URL base confined to the geoserver backend LOCATION)

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "geoserver_proxy" and
      (p.asName().getId() = "proxy_path" or p.asName().getId() = "downstream_path") and
      inModule(f, "geonode/geoserver/views.py") and
      callableName = "geonode.geoserver.views.geoserver_proxy." + p.asName().getId() and
      flowKind = "param" and
      receiverHint = "geonode.geoserver.views" and
      argIndex = i
    )

    or

    //     c) ServiceHandlerBase.__init__(self, url, ...) -
    //        geonode/services/serviceprocessors/base.py:69
    //        the user-supplied remote service URL (probe() fetches
    //        it at base.py:81)

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "__init__" and
      p.asName().getId() = "url" and
      inModule(f, "geonode/services/serviceprocessors/base.py") and
      f.getScope().getName() = "ServiceHandlerBase" and
      callableName = "ServiceHandlerBase.__init__.url" and
      flowKind = "param" and
      receiverHint = "geonode.services.serviceprocessors.base.ServiceHandlerBase" and
      argIndex = i
    )

    or

    //     d) WmsServiceHandler / GeoNodeServiceHandler /
    //        ArcMapServiceHandler / ArcImageServiceHandler
    //        __init__(self, url, ...) - concrete handlers whose url
    //        comes from the CreateServiceForm POST input

    exists(Parameter p, Function f, int i, string className |
      n = p and
      p = f.getArg(i) and
      f.getName() = "__init__" and
      p.asName().getId() = "url" and
      className = f.getScope().getName() and
      className in [
        "WmsServiceHandler",
        "GeoNodeServiceHandler",
        "ArcMapServiceHandler",
        "ArcImageServiceHandler"
      ] and
      (
        inModule(f, "geonode/services/serviceprocessors/wms.py") or
        inModule(f, "geonode/services/serviceprocessors/arcgis.py")
      ) and
      callableName = className + ".__init__.url" and
      flowKind = "param" and
      receiverHint = "geonode.services.serviceprocessors." + className and
      argIndex = i
    )

    or

    //     e) get_service_handler(base_url, ...) -
    //        geonode/services/serviceprocessors/__init__.py:60
    //        dispatcher called with the form url during validation

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "get_service_handler" and
      p.asName().getId() = "base_url" and
      inModule(f, "geonode/services/serviceprocessors/__init__.py") and
      callableName = "geonode.services.serviceprocessors.get_service_handler.base_url" and
      flowKind = "param" and
      receiverHint = "geonode.services.serviceprocessors" and
      argIndex = i
    )

    or

    //     f) BaseHarvesterWorker.__init__(self, remote_url, ...) -
    //        geonode/harvesting/harvesters/base.py:79
    //        and ArcgisHarvesterWorker.__init__(self, remote_url, ...)
    //        - geonode/harvesting/harvesters/arcgis.py:374
    //        harvester record URL (DRF admin API / service
    //        registration) fetched by every harvester worker

    exists(Parameter p, Function f, int i, string className |
      n = p and
      p = f.getArg(i) and
      f.getName() = "__init__" and
      p.asName().getId() = "remote_url" and
      className = f.getScope().getName() and
      (
        (className = "BaseHarvesterWorker" and inModule(f, "geonode/harvesting/harvesters/base.py"))
        or
        (className = "ArcgisHarvesterWorker" and inModule(f, "geonode/harvesting/harvesters/arcgis.py"))
      ) and
      callableName = className + ".__init__.remote_url" and
      flowKind = "param" and
      receiverHint = "geonode.harvesting.harvesters." + className and
      argIndex = i
    )

    or

    //     g) download_resource_file(url, target_name) -
    //        geonode/harvesting/harvesters/base.py:324
    //        remote-declared download URL fetched via
    //        requests.get(url, stream=True) at :334

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "download_resource_file" and
      p.asName().getId() = "url" and
      inModule(f, "geonode/harvesting/harvesters/base.py") and
      callableName = "geonode.harvesting.harvesters.base.download_resource_file.url" and
      flowKind = "param" and
      receiverHint = "geonode.harvesting.harvesters.base" and
      argIndex = i
    )

    or

    //     h) is_monochromatic_image(image_url, ...) -
    //        geonode/utils.py:1844 - resource thumbnail_url (can be
    //        an arbitrary user-set URL via the set_thumbnail API)
    //        fetched via http_client.get at utils.py:1883

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "is_monochromatic_image" and
      p.asName().getId() = "image_url" and
      inModule(f, "geonode/utils.py") and
      callableName = "geonode.utils.is_monochromatic_image.image_url" and
      flowKind = "param" and
      receiverHint = "geonode.utils" and
      argIndex = i
    )

    or

    //     i) thumbs get_map(ogc_server_location, ...) -
    //        geonode/thumbs/utils.py:148 and
    //        getmap(base_url, ...) - :318 - WMS thumbnail bases that
    //        can be remote service URLs (Dataset.ows_url /
    //        remote_service.service_url)

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "get_map" and
      p.asName().getId() = "ogc_server_location" and
      inModule(f, "geonode/thumbs/utils.py") and
      callableName = "geonode.thumbs.utils.get_map.ogc_server_location" and
      flowKind = "param" and
      receiverHint = "geonode.thumbs.utils" and
      argIndex = i
    )

    or

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      f.getName() = "getmap" and
      p.asName().getId() = "base_url" and
      inModule(f, "geonode/thumbs/utils.py") and
      callableName = "geonode.thumbs.utils.getmap.base_url" and
      flowKind = "param" and
      receiverHint = "geonode.thumbs.utils" and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (6) CreateServiceForm.url field definition -
    //     geonode/services/forms.py:36 - plain forms.CharField
    //     (max_length=512, widget type=url only; no scheme/host
    //     validation), bound from the register_service POST body
    // --------------------------------------------------------

    exists(AssignStmt a, Name target |
      n = a and
      target = a.getATarget() and
      target.getId() = "url" and
      a.getValue() instanceof Call and
      inModule(a, "geonode/services/forms.py") and
      a.getScope().getName() = "CreateServiceForm" and
      callableName = "CreateServiceForm.url" and
      flowKind = "field" and
      receiverHint = "django.forms.Form input field" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (7) DB-content URL model field definitions (class-scope
    //     `x = models.URLField/TextField(...)` assignments). These
    //     fields carry URLs that originate from user input or
    //     remote-service metadata and are later re-fetched
    //     server-side (documented in detection.json).
    //     Display-only fields (License.url, MenuItem.url) are
    //     intentionally excluded.
    // --------------------------------------------------------

    exists(AssignStmt a, Name target, Class cls |
      n = a and
      target = a.getATarget() and
      a.getValue() instanceof Call and
      cls = a.getScope() and
      (
        (inModule(a, "geonode/services/models.py") and cls.getName() = "Service" and target.getId() = "base_url")
        or
        (inModule(a, "geonode/harvesting/models.py") and cls.getName() = "Harvester" and target.getId() = "remote_url")
        or
        (inModule(a, "geonode/base/models.py") and cls.getName() = "ResourceBase" and target.getId() = "thumbnail_url")
        or
        (inModule(a, "geonode/base/models.py") and cls.getName() = "Link" and target.getId() = "url")
        or
        (inModule(a, "geonode/documents/models.py") and cls.getName() = "Document" and target.getId() = "doc_url")
        or
        (inModule(a, "geonode/layers/models.py") and cls.getName() = "Dataset" and target.getId() = "ows_url")
        or
        (inModule(a, "geonode/maps/models.py") and cls.getName() = "MapLayer" and target.getId() = "ows_url")
        or
        (inModule(a, "geonode/monitoring/models.py") and cls.getName() = "Service" and target.getId() = "url")
      ) and
      callableName = cls.getName() + "." + target.getId() and
      flowKind = "field" and
      receiverHint = "django.db.models field (DB content)" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (8) CLI option boundaries of management commands:
    //     - geonode/monitoring/management/commands/updategeoip.py:61
    //       requests.get(options['url'], ...) - the --url CLI
    //       option (default is the hardcoded GeoLite2 constant)
    //     - geonode/geoserver/management/commands/importlayers.py:63
    //       host = options.get("host") or settings.SITEURL - the
    //       --host CLI option whose value is fetched at :152
    // --------------------------------------------------------

    exists(Subscript s, Name opts, StringLiteral idx |
      n = s and
      opts = s.getObject() and
      opts.getId() = "options" and
      idx = s.getIndex() and
      idx.getText() = "url" and
      inModule(s, "geonode/monitoring/management/commands/updategeoip.py") and
      callableName = "options[url]" and
      flowKind = "field" and
      receiverHint = "django.core.management command options (CLI)" and
      argIndex = -1
    )

    or

    exists(Call c, Attribute getAttr, Name opts, StringLiteral key |
      n = c and
      getAttr = c.getFunc() and
      getAttr.getName() = "get" and
      opts = getAttr.getObject() and
      opts.getId() = "options" and
      key = c.getArg(0) and
      key.getText() = "host" and
      inModule(c, "geonode/geoserver/management/commands/importlayers.py") and
      callableName = "options.get(host)" and
      flowKind = "return" and
      receiverHint = "django.core.management command options (CLI)" and
      argIndex = -1
    )
  )

select
  n,
  "source_candidate",
  callableName,
  flowKind,
  receiverHint,
  moduleHint,
  argIndex,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()
