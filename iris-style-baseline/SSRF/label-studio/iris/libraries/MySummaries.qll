/**
 * Augur Phase 2 - Pass 3 (CWE-918 SSRF) additional taint-step library for
 * label-studio. Generated from reviewed labels: iris/labels/labels.json
 * (pass 3) and the flow evidence recorded in the labels' evidence fields.
 * Every edge below is pinned to a concrete call shape or a concrete reviewed
 * source location; there is no unconditional taint propagation.
 *
 * Edge -> source-code evidence mapping:
 *
 * 1. requestPayloadAccessStep  (request-field attribute -> extracted value)
 *    request.<field> is a DRF QueryDict/dict-like mapping; the reviewed flows
 *    extract the payload with the standard mapping accessors. Evidence:
 *      label_studio/data_import/uploader.py:239  url = request.data.get('url')
 *      label_studio/data_import/api.py:282        url = request.data.get('url')
 *      label_studio/ml/api.py:77                  self.request.query_params.get('project')
 *      label_studio/data_import/api.py:639        filepath = unquote(request.GET['filepath'])
 *    Edge: `request.<field>` node -> result of `.get(k)`/`.getlist(k)` called on
 *    that exact attribute, and -> `request.<field>['k']` subscript reads.
 *    rest_framework is not part of this database, so this accessor edge is the
 *    "request parameter parsing" propagation the reviewed flows rely on.
 *
 * 2. mlBackendUrlStep  (BaseHTTPAPI constructor url -> urljoin base argument)
 *    The reviewed ML flow stores the constructor URL on the instance and
 *    re-reads it in another method (cross-method attribute store/load, which
 *    the data-flow library does not track through `self`). Evidence:
 *      label_studio/ml/api_connector.py:41-42  def __init__(self, url, ...): self._url = url
 *      label_studio/ml/api_connector.py:126-129 url = self._url; ... url += '/';
 *                                               return urllib.parse.urljoin(url, url_suffix)
 *    Edge: `url` parameter of BaseHTTPAPI.__init__ (api_connector.py:41) ->
 *    argument 0 of the urllib.parse.urljoin call (api_connector.py:129).
 *    All ML traffic funnels through this single construction path
 *    (MLApi.__init__ -> super().__init__).
 *
 * 3. urlJoinStep  (urljoin argument 0 -> joined result)
 *    urllib.parse is stdlib and not part of this database, so the join result
 *    would otherwise drop taint. Evidence:
 *      label_studio/ml/api_connector.py:129  urllib.parse.urljoin(url, url_suffix)
 *    Edge: argument 0 of any urljoin call -> the call result. Only argument 0
 *    (the base URL) is modeled; the joined suffix is a fixed string at every
 *    reviewed call site.
 *
 * 4. s3EndpointKwargsStep  (s3_endpoint parameter -> boto3 **settings)
 *    The reviewed S3 endpoint flow writes the endpoint into the `settings`
 *    dict and forwards it as **settings to the boto3 client/resource calls;
 *    container-element store plus double-star unpacking is not a default
 *    data-flow step. Evidence:
 *      label_studio/io_storages/s3/utils.py:17-19 def get_client_and_resource(..., s3_endpoint=None)
 *      label_studio/io_storages/s3/utils.py:35-37 s3_endpoint = s3_endpoint or get_env('S3_ENDPOINT');
 *                                               if s3_endpoint: settings['endpoint_url'] = s3_endpoint
 *      label_studio/io_storages/s3/utils.py:38-39 session.client('s3', ..., **settings);
 *                                               session.resource('s3', ..., **settings)
 *    Edge: `s3_endpoint` parameter of get_client_and_resource (s3/utils.py:17)
 *    -> the **settings argument (Call.getKwargs()) of the pinned client and
 *    resource calls at s3/utils.py:38 and :39 (which are exactly the modeled
 *    sink nodes).
 *
 * 5. ssrfSafeGetBridge  (ssrf_safe_get call argument 0 -> its url parameter)
 *    This database's module table only contains label_studio.*-prefixed
 *    module names (the DB source root is the repository root), so the
 *    application's bare-prefix app-internal imports are NOT resolved for
 *    call dispatch. uploader.py imports ssrf_safe_get with
 *    `from core.utils.io import ssrf_safe_get` (uploader.py:15) and calls it
 *    at uploader.py:131-133; without this bridge the reviewed import-by-URL
 *    flow stops at the call argument. Evidence:
 *      label_studio/data_import/uploader.py:15    from core.utils.io import ssrf_safe_get
 *      label_studio/data_import/uploader.py:131-133 ssrf_safe_get(url, verify=..., ...)
 *      label_studio/core/utils/io.py:220           def ssrf_safe_get(url, *args, **kwargs)
 *    Edge: argument 0 of any `ssrf_safe_get(...)` call (callee by Name) ->
 *    the `url` parameter of ssrf_safe_get.
 *
 * 6. mlApiConstructorBridge  (MLApi(...) url keyword -> BaseHTTPAPI url param)
 *    Same bare-import issue (`from ml.api_connector import MLApi`,
 *    ml/models.py:12), compounded by MLApi.__init__(**kwargs) forwarding
 *    through super(MLApi, self).__init__(**kwargs) (api_connector.py:121-122),
 *    whose keyword-binding the default dispatch does not track (verified by
 *    isolated probes). Evidence:
 *      label_studio/ml/models.py:12            from ml.api_connector import MLApi
 *      label_studio/ml/models.py:101/109/122   MLApi(url=url) / MLApi(url=self.url, ...)
 *      label_studio/ml/api_connector.py:120-123 class MLApi(BaseHTTPAPI): __init__(**kwargs)
 *      label_studio/ml/api_connector.py:41-42  def __init__(self, url, ...): self._url = url
 *    Edge: the `url` keyword value of any `MLApi(...)` constructor call ->
 *    the `url` parameter of BaseHTTPAPI.__init__.
 *
 * 7. mlKwargsForwardBridge  (self.post/self.get url keyword -> the **kwargs
 *    argument of the transport call at :81)
 *    BaseHTTPAPI.post/get forward their keyword arguments to
 *    self.request('POST'|'GET', *args, **kwargs), which forwards them to
 *    self.http.request(method, *args, **kwargs) at :81 (the modeled sink);
 *    keyword-argument -> **kwargs -> **kwargs element/container forwarding
 *    is not tracked by the default dispatch (verified by isolated probes).
 *    The edge targets the transport call's **kwargs argument expression
 *    rather than a `**kwargs` parameter because Function.getArgByName casts
 *    parameters to Name and cannot bind star/double-star parameters.
 *    Evidence:
 *      label_studio/ml/api_connector.py:83-87  def post/get: return self.request(..., *args, **kwargs)
 *      label_studio/ml/api_connector.py:79-81  def request: self.http.request(method, *args, **kwargs)
 *      label_studio/ml/api_connector.py:141/143 self.post(url=url, ...) / self.get(url=url, ...)
 *    Edge: the `url` keyword value of self.post/self.get calls in
 *    api_connector.py -> the **kwargs argument (Call.getKwargs()) of the
 *    pinned self.http.request transport call at api_connector.py:81.
 *
 * 8. s3ClientBridge  (get_client_and_resource argument 4 -> its s3_endpoint
 *    parameter)
 *    Same bare-import issue: io_storages/s3/models.py:22 imports
 *    get_client_and_resource with `from io_storages.s3.utils import ...`
 *    (unresolved), so the positional call at models.py:61-67 does not
 *    dispatch. (The get_blob_metadata path at models.py:179 works through
 *    the `label_studio.io_storages.s3.utils`-prefixed AWS import at
 *    models.py:26 and needs no bridge.) Evidence:
 *      label_studio/io_storages/s3/models.py:22     from io_storages.s3.utils import get_client_and_resource
 *      label_studio/io_storages/s3/models.py:61-67  get_client_and_resource(..., self.s3_endpoint)
 *      label_studio/io_storages/s3/utils.py:17      def get_client_and_resource(..., s3_endpoint=None)
 *    Edge: argument 4 of any `get_client_and_resource(...)` call (callee by
 *    Name) -> the `s3_endpoint` parameter of get_client_and_resource.
 *
 * Not re-modeled (per review): plain interprocedural call/return propagation
 * (e.g. load_tasks -> tasks_from_url) is already handled by standard data
 * flow; the tasks_from_url `url` parameter and every other internal wrapper
 * parameter was reviewed role=none and receives no edge or source here.
 * Same-module dispatches that resolve normally (tasks_from_url,
 * MLBackend.healthcheck_/setup_ staticmethods, AWS.get_blob_metadata,
 * the in-module get_client_and_resource call at utils.py:90) get no bridge.
 *
 * Verified against codeql/python-all 7.1.2 (Call.getArg(int)/getFunc()/
 * getAKeyword().getArg()/getValue()/getKwargs(), Attribute.getName()/
 * getObject(), Subscript.getObject(), Assign.getATarget()/getValue(),
 * Function.getName()/getArgByName(), File.getRelativePath(),
 * Location.getStartLine(); matches() patterns are string literals only).
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {

  /* ------------------------------------------------------------------
   * Public interface (pass key: "ssrf")
   * ------------------------------------------------------------------ */

  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "ssrf" and
    (
      requestPayloadAccessStep(nodeFrom, nodeTo)
      or mlBackendUrlStep(nodeFrom, nodeTo)
      or urlJoinStep(nodeFrom, nodeTo)
      or s3EndpointKwargsStep(nodeFrom, nodeTo)
      or ssrfSafeGetBridge(nodeFrom, nodeTo)
      or mlApiConstructorBridge(nodeFrom, nodeTo)
      or mlKwargsForwardBridge(nodeFrom, nodeTo)
      or s3ClientBridge(nodeFrom, nodeTo)
    )
  }

  /* ------------------------------------------------------------------
   * 1. Request payload extraction: request.<field> ->
   *    .get(k)/.getlist(k) result and subscript reads
   * ------------------------------------------------------------------ */

  private predicate requestPayloadAccessStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    // request.<field>.get(k) / request.<field>.getlist(k)
    exists(Call c, Attribute func, Attribute reqAttr |
      func = c.getFunc() and
      func.getObject() = reqAttr and
      isRequestFieldAttribute(reqAttr) and
      func.getName() in ["get", "getlist"] and
      nodeFrom = DataFlow::exprNode(reqAttr) and
      nodeTo = DataFlow::exprNode(c)
    )
    or
    // request.<field>['k']
    exists(Subscript s, Attribute reqAttr |
      s.getObject() = reqAttr and
      isRequestFieldAttribute(reqAttr) and
      nodeFrom = DataFlow::exprNode(reqAttr) and
      nodeTo = DataFlow::exprNode(s)
    )
  }

  /** Holds if `a` is a request-object field read inside application code (same shape as MySources). */
  private predicate isRequestFieldAttribute(Attribute a) {
    a.getName() in ["data", "GET", "POST", "FILES", "META", "body", "query_params"] and
    (
      a.getObject() instanceof Name and a.getObject().(Name).getId() = "request"
      or
      a.getObject() instanceof Attribute and
      a.getObject().(Attribute).getName() = "request" and
      a.getObject().(Attribute).getObject() instanceof Name and
      a.getObject().(Attribute).getObject().(Name).getId() = "self"
    ) and
    inAppScope(a)
  }

  /* ------------------------------------------------------------------
   * 2. ML backend URL: BaseHTTPAPI.__init__ url parameter ->
   *    urljoin base argument (api_connector.py:41 -> :129)
   * ------------------------------------------------------------------ */

  private predicate mlBackendUrlStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function init, Parameter urlParam, Call join, Attribute func |
      init.getName() = "__init__" and
      init.getLocation().getFile().getRelativePath().matches("label_studio/ml/api_connector.py") and
      init.getLocation().getStartLine() = 41 and
      urlParam = init.getArgByName("url") and
      join.getLocation().getFile().getRelativePath().matches("label_studio/ml/api_connector.py") and
      join.getLocation().getStartLine() = 129 and
      func = join.getFunc() and
      func.getName() = "urljoin" and
      nodeFrom = DataFlow::parameterNode(urlParam) and
      nodeTo = DataFlow::exprNode(join.getArg(0))
    )
  }

  /* ------------------------------------------------------------------
   * 3. URL construction: urljoin argument 0 -> joined result
   * ------------------------------------------------------------------ */

  private predicate urlJoinStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      isUrlJoinCall(c) and
      nodeFrom = DataFlow::exprNode(c.getArg(0)) and
      nodeTo = DataFlow::exprNode(c)
    )
  }

  /** Holds if `c` is a urljoin(...) call: `urljoin(...)` or `<expr>.urljoin(...)`. */
  private predicate isUrlJoinCall(Call c) {
    c.getFunc() instanceof Name and c.getFunc().(Name).getId() = "urljoin"
    or
    c.getFunc() instanceof Attribute and c.getFunc().(Attribute).getName() = "urljoin"
  }

  /* ------------------------------------------------------------------
   * 4. S3 endpoint: get_client_and_resource s3_endpoint parameter ->
   *    **settings of the pinned boto3 client/resource calls
   * ------------------------------------------------------------------ */

  private predicate s3EndpointKwargsStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function f, Parameter endpoint, Call client, Call resource |
      f.getName() = "get_client_and_resource" and
      f.getLocation().getFile().getRelativePath().matches("label_studio/io_storages/s3/utils.py") and
      f.getLocation().getStartLine() = 17 and
      endpoint = f.getArgByName("s3_endpoint") and
      client.getLocation().getFile().getRelativePath().matches("label_studio/io_storages/s3/utils.py") and
      client.getLocation().getStartLine() = 38 and
      client.getFunc() instanceof Attribute and
      client.getFunc().(Attribute).getName() = "client" and
      resource.getLocation().getFile().getRelativePath().matches("label_studio/io_storages/s3/utils.py") and
      resource.getLocation().getStartLine() = 39 and
      resource.getFunc() instanceof Attribute and
      resource.getFunc().(Attribute).getName() = "resource" and
      nodeFrom = DataFlow::parameterNode(endpoint) and
      (
        nodeTo = DataFlow::exprNode(client.getKwargs())
        or nodeTo = DataFlow::exprNode(resource.getKwargs())
      )
    )
  }

  /* ------------------------------------------------------------------
   * 5. ssrf_safe_get dispatch bridge: call argument 0 -> url parameter
   *    (bare `from core.utils.io import ssrf_safe_get` is unresolved here)
   * ------------------------------------------------------------------ */

  private predicate ssrfSafeGetBridge(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function f, Call c |
      f.getName() = "ssrf_safe_get" and
      f.getLocation().getFile().getRelativePath().matches("label_studio/core/utils/io.py") and
      f.getLocation().getStartLine() = 220 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "ssrf_safe_get" and
      inAppScope(c) and
      nodeFrom = DataFlow::exprNode(c.getArg(0)) and
      nodeTo = DataFlow::parameterNode(f.getArgByName("url"))
    )
  }

  /* ------------------------------------------------------------------
   * 6. MLApi constructor bridge: `url` keyword -> BaseHTTPAPI.__init__
   *    url parameter (bare import + **kwargs/super forwarding)
   * ------------------------------------------------------------------ */

  private predicate mlApiConstructorBridge(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function init, Call c, Keyword kw |
      init.getName() = "__init__" and
      init.getLocation().getFile().getRelativePath().matches("label_studio/ml/api_connector.py") and
      init.getLocation().getStartLine() = 41 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "MLApi" and
      inAppScope(c) and
      kw = c.getAKeyword() and
      kw.getArg() = "url" and
      nodeFrom = DataFlow::exprNode(kw.getValue()) and
      nodeTo = DataFlow::parameterNode(init.getArgByName("url"))
    )
  }

  /* ------------------------------------------------------------------
   * 7. ML kwargs forwarding bridge: self.post/self.get `url` keyword ->
   *    the **kwargs argument of the transport call at api_connector.py:81
   * ------------------------------------------------------------------ */

  private predicate mlKwargsForwardBridge(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Keyword kw, Attribute func, Call transport |
      c.getLocation().getFile().getRelativePath().matches("label_studio/ml/api_connector.py") and
      func = c.getFunc() and
      func.getObject() instanceof Name and
      func.getObject().(Name).getId() = "self" and
      func.getName() in ["post", "get"] and
      kw = c.getAKeyword() and
      kw.getArg() = "url" and
      nodeFrom = DataFlow::exprNode(kw.getValue()) and
      transport.getLocation().getFile().getRelativePath().matches("label_studio/ml/api_connector.py") and
      transport.getLocation().getStartLine() = 81 and
      transport.getFunc() instanceof Attribute and
      transport.getFunc().(Attribute).getName() = "request" and
      nodeTo = DataFlow::exprNode(transport.getKwargs())
    )
  }

  /* ------------------------------------------------------------------
   * 8. get_client_and_resource dispatch bridge: call argument 4 ->
   *    s3_endpoint parameter (bare from-import unresolved here)
   * ------------------------------------------------------------------ */

  private predicate s3ClientBridge(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function f, Call c |
      f.getName() = "get_client_and_resource" and
      f.getLocation().getFile().getRelativePath().matches("label_studio/io_storages/s3/utils.py") and
      f.getLocation().getStartLine() = 17 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "get_client_and_resource" and
      inAppScope(c) and
      nodeFrom = DataFlow::exprNode(c.getArg(4)) and
      nodeTo = DataFlow::parameterNode(f.getArgByName("s3_endpoint"))
    )
  }

  /* ------------------------------------------------------------------
   * Shared scope guard (identical to the Phase 1 extraction scope)
   * ------------------------------------------------------------------ */

  private predicate inAppScope(AstNode n) {
    exists(string path |
      path = n.getLocation().getFile().getRelativePath() and
      path.matches("label_studio/%") and
      not path.matches("label_studio/tests/%") and
      not path.matches("label_studio/%/tests.py") and
      not path.matches("label_studio/%/migrations/%") and
      not path.matches("label_studio/%/examples/%")
    )
  }
}
