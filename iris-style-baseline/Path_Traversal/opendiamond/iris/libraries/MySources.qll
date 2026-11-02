/**
 * Augur Phase 2 - Pass 1 source models (machine-generated from reviewed labels).
 *
 * Generated from: iris/labels/labels.json, pass 1 (Path Traversal,
 * CWE-022/023/036/073), run opendiamond-pass1-labeling-20261022, model glm-5.3.
 *
 * Only reviewed `source`-role label entries classified tp or candidate are
 * modeled (54 of the 137 source-role labels). Families reviewed as fp or
 * none are deliberately NOT matched:
 *   - int-converter route params (gigapan_id/lvl/col/row, index/total,
 *     start/limit, stride/span, seq_no, divisor) - numeric, cannot carry
 *     path characters;
 *   - default string-converter params that never reach a join as a
 *     multi-segment path (gididx/baseidx/mixeridx under the 'GIDIDX' prefix,
 *     params/keywords/expression, dataset);
 *   - Tornado route params constrained to [0-9a-f]{64} by the blaster route
 *     regexes (blaster/__init__.py:51-58) and the query params
 *     (get_argument 'jsonp'/'tint', request.args 'slice'/'distribute');
 *   - self.request.headers (content-type only);
 *   - PostBlobHandler's self.request.body (labeled fp: raw blob bytes are
 *     hashed by BlobCache.add before any use);
 *   - env reads (TMPDIR - set by the server itself at server/child.py:62,
 *     DIAMOND_CONFIG/HOME - operator config lookup, client-side HOME);
 *   - the os.environ write at server/child.py:62 and the internal
 *     mixer_list parameters (never URL-bound);
 *   - RPC params reviewed fp (send_blobs - hashed blobs; start;
 *     session_variables_set) and proxy RPC retrain/reexecute/start.
 *
 * Label families covered (54 modeled entries):
 *   - flask_route_param (17): path-converter and reviewed string route
 *     params of the dataretriever store handlers (15 tp + 2 candidate
 *     `classes` params);
 *   - xdr_rpc_param    (3): setup/reexecute_filters `params` on
 *     server/search.py (tp) and setup on proxy/search.py (candidate);
 *   - json_body/http_body (5): json.loads results and self.request.body
 *     reads in blaster/handlers.py (tp);
 *   - socket_message   (2): sockjs on_message(data) and the unconstrained
 *     SearchConnection.start(search_key) event parameter (tp);
 *   - cookie_parse     (1): ScopeCookie.parse result in _SearchSpec
 *     (candidate - signature-verified cookie content);
 *   - django http_view_request/http_form (26): the `request` parameter of
 *     the 11 reviewed scopeserver view functions and the 15 reviewed
 *     request.POST/request.GET attribute reads.
 *
 * Pass key: "path_traversal".
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /**
   * Holds if `source` is a reviewed pass-1 taint source for the given pass key.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and
    (
      isFlaskRouteParamSource(source)
      or
      isCandidateClassesParamSource(source)
      or
      isXdrRpcSource(source)
      or
      isBlasterBodySource(source)
      or
      isBlasterJsonLoadsSource(source)
      or
      isSockjsEventSource(source)
      or
      isScopeCookieParseSource(source)
      or
      isDjangoViewSource(source)
    )
  }

  /**
   * True iff `f` is defined in the dataretriever store file named `base`.
   *
   * QL has no string concatenation, so the short store names map to full
   * path-match patterns through a literal table (storeFilePattern).
   */
  private predicate inStoreFile(Function f, string base) {
    exists(string pattern |
      storeFilePattern(base, pattern) and
      f.getLocation().getFile().getAbsolutePath().matches(pattern)
    )
  }

  /** Literal short-name -> path-pattern table for the reviewed store files. */
  private predicate storeFilePattern(string base, string pattern) {
    (base = "augment_store.py" and
     pattern = "%/opendiamond/dataretriever/augment_store.py")
    or
    (base = "diamond_store.py" and
     pattern = "%/opendiamond/dataretriever/diamond_store.py")
    or
    (base = "mixer_store.py" and
     pattern = "%/opendiamond/dataretriever/mixer_store.py")
    or
    (base = "test_store.py" and
     pattern = "%/opendiamond/dataretriever/test_store.py")
    or
    (base = "yfcc100m_mysql_store.py" and
     pattern = "%/opendiamond/dataretriever/yfcc100m_mysql_store.py")
    or
    (base = "video_store.py" and
     pattern = "%/opendiamond/dataretriever/video_store.py")
  }

  /**
   * Source family `flask_route_param` (15 reviewed tp entries): route
   * parameters of the Flask dataretriever store handlers. Each table row is
   * (handler function, parameter, defining file); the param names are unique
   * per handler, and the handler + file pair pins the reviewed site:
   *
   *   diamond_store.py  get_object_id(object_path)      tp 0.85  /id/<path:...>
   *   diamond_store.py  get_object_meta(object_path)    tp 0.95  /meta/<path:...>
   *   diamond_store.py  get_object_src_http(obj_path)   tp 0.98  /obj/<path:...>
   *   mixer_store.py    get_object_id(object_path)      tp 0.85
   *   mixer_store.py    get_object_meta(object_path)    tp 0.80
   *   mixer_store.py    get_object_src_http(obj_path)   tp 0.98
   *   test_store.py     get_object_id(object_path)      tp 0.85
   *   test_store.py     get_object_meta(object_path)    tp 0.80
   *   test_store.py     get_object_src_http(obj_path)   tp 0.98
   *   augment_store.py  get_object_id(object_path)      tp 0.90  (safe_join-guarded)
   *   augment_store.py  get_object_src_http(obj_path)   tp 0.95  (safe_join-guarded)
   *   augment_store.py  get_scope(rootdir)              tp 0.85  /root/<rootdir>/...
   *   yfcc100m_mysql_store.py get_object_src_http(rel_path) tp 0.98
   *                                               /obj/<dataset>/<path:rel_path>
   *   video_store.py    get_object_id(video)            tp 0.85  <path:video>
   *   video_store.py    get_object(video)               tp 0.95
   *
   * The path-converter parameters accept '/' and are percent-decoded by
   * Werkzeug before routing; `rootdir` is a string-converter segment (no
   * '/'). The handlers' get_scope parameters (gididx, dataset, ...) are
   * reviewed fp and NOT matched. Verified against the source tree: the
   * (function, file) pairs below are exactly the reviewed sites.
   */
  private predicate isFlaskRouteParamSource(DataFlow::Node source) {
    exists(string fname, string pname, string base |
      reviewedRouteParam(fname, pname, base) and
      exists(Function f |
        f.getName() = fname and
        inStoreFile(f, base) and
        source = DataFlow::parameterNode(f.getArgByName(pname))
      )
    )
  }

  /** The reviewed (handler, parameter, store file) table; see above. */
  private predicate reviewedRouteParam(string fname, string pname, string base) {
    // tp 0.85-0.98: path-converter object params of the four local stores
    (base = "diamond_store.py" or base = "mixer_store.py" or
     base = "test_store.py" or base = "augment_store.py")
    and
    (
      fname = "get_object_id" and pname = "object_path"
      or
      fname = "get_object_src_http" and pname = "obj_path"
    )
    or
    // tp 0.80-0.95: meta handlers (augment's get_object_meta takes `present`,
    // reviewed fp, and is not matched)
    (base = "diamond_store.py" or base = "mixer_store.py" or base = "test_store.py")
    and fname = "get_object_meta" and pname = "object_path"
    or
    // tp 0.85: augment rootdir (string-converter segment, no '/')
    base = "augment_store.py" and fname = "get_scope" and pname = "rootdir"
    or
    // tp 0.98: yfcc100m mysql rel_path (dataset is reviewed fp and excluded)
    base = "yfcc100m_mysql_store.py" and fname = "get_object_src_http" and
    pname = "rel_path"
    or
    // tp 0.85/0.95: video path-converter param (start/span are int params, fp)
    base = "video_store.py" and
    (
      (fname = "get_object_id" or fname = "get_object") and pname = "video"
    )
  }

  /**
   * Source family `flask_route_param`, candidate entries (2): the `classes`
   * parameter of get_mixer_classes in mixer_store.py and test_store.py
   * (labels S-dataretriever_mixer_store-63-get_mixer_classes-a5 and
   * S-dataretriever_test_store-65-get_mixer_classes-a5, candidate 0.55).
   *
   * Evidence: class names reach
   * _get_obj_absolute_path(dataset_path + '/' + c.strip()) and
   * glob(os.path.join(path, "*.jpg")) (mixer_store.py:186-200,
   * test_store.py:210-229); a '..' class name lists parent-directory images.
   * Modeled as candidate per the reviewed labels; no file-access sink is
   * expected to fire from this family (glob is not a reviewed sink).
   */
  private predicate isCandidateClassesParamSource(DataFlow::Node source) {
    exists(Function f |
      f.getName() = "get_mixer_classes" and
      (inStoreFile(f, "mixer_store.py") or inStoreFile(f, "test_store.py")) and
      source = DataFlow::parameterNode(f.getArgByName("classes"))
    )
  }

  /**
   * Source family `xdr_rpc_param` (3 entries): the `params` parameter of the
   * XDR-decoded RPC handlers over raw sockets - unauthenticated clients on
   * the diamondserver control port (5874) and the proxy port (5904).
   *
   *   server/search.py setup(params)             tp 0.80   (XDR_setup,
   *     @RPCHandlers.handler(25): params.filters[].code/blob carry
   *     'sha256:<sig>' URIs consumed by BlobCache paths, server/search.py:128-204)
   *   server/search.py reexecute_filters(params) tp 0.75   (XDR_reexecute,
   *     @RPCHandlers.handler(30): params.object_id -> Object(...) ->
   *     ObjectLoader.load -> file: URI opens, server/search.py:246-280)
   *   proxy/search.py setup(params)              candidate 0.60 (in-memory
   *     blob_map on the proxy; forwarded downstream - no local file sink)
   *
   * The other RPC `params` handlers (send_blobs - blobs hashed by
   * BlobCache.add; start; session_variables_set; proxy retrain/reexecute)
   * are reviewed fp and NOT matched. Verified: these are the only functions
   * named setup/reexecute_filters in these two files.
   */
  private predicate isXdrRpcSource(DataFlow::Node source) {
    exists(Function f |
      f.getName() in ["setup", "reexecute_filters"] and
      f.getLocation().getFile().getAbsolutePath()
        .matches("%/opendiamond/server/search.py") and
      source = DataFlow::parameterNode(f.getArgByName("params"))
    )
    or
    exists(Function f |
      f.getName() = "setup" and
      f.getLocation().getFile().getAbsolutePath()
        .matches("%/opendiamond/proxy/search.py") and
      source = DataFlow::parameterNode(f.getArgByName("params"))
    )
  }

  /**
   * Source family `http_body` (2 tp entries): self.request.body reads in
   * blaster/handlers.py - SearchHandler.post (line 313, the raw JSON search
   * spec) and EvaluateHandler.post (line 360, the evaluate JSON request).
   *
   * PostBlobHandler.post's identical body read (line 335) is reviewed fp
   * (raw blob bytes are sha256-hashed by BlobCache.add before any use) and
   * is excluded by constraining the enclosing handler class. Access
   * conditions: the blaster listens on :8080; handlers are subject to the
   * @_restricted decorator (IP allow-list option), which limits the attacker
   * population, not the content (contextual, not sanitization).
   */
  private predicate isBlasterBodySource(DataFlow::Node source) {
    exists(Attribute body, Attribute request, Name selfName |
      body.getName() = "body" and
      body.getObject() = request and
      request.getName() = "request" and
      request.getObject() = selfName and
      selfName.getId() = "self" and
      body.getLocation().getFile().getAbsolutePath()
        .matches("%/opendiamond/blaster/handlers.py") and
      body.getScope().(Function).getScope().(Class).getName()
        in ["SearchHandler", "EvaluateHandler"] and
      source = DataFlow::exprNode(body)
    )
  }

  /**
   * Source family `json_body` (3 tp entries): json.loads results in
   * blaster/handlers.py - _SearchSpec.__init__ (line 245, POST /search body),
   * EvaluateHandler.post (line 360) and _StructuredSocketConnection
   * .on_message (line 507, the sockjs event decode).
   *
   * These are the decode boundaries of the reviewed request-body/websocket
   * channels; the config carries filter blob URIs ('blob:<sig>') whose path
   * part indexes the BlobCache. Verified: exactly 3 json.loads call sites
   * exist in blaster/handlers.py.
   */
  private predicate isBlasterJsonLoadsSource(DataFlow::Node source) {
    exists(Call loads, Attribute func, Name jsonModule |
      loads.getFunc() = func and
      func.getName() = "loads" and
      func.getObject() = jsonModule and
      jsonModule.getId() = "json" and
      loads.getLocation().getFile().getAbsolutePath()
        .matches("%/opendiamond/blaster/handlers.py") and
      source = DataFlow::exprNode(loads)
    )
  }

  /**
   * Source family `socket_message` (2 tp entries): the sockjs websocket
   * boundary in blaster/handlers.py.
   *
   *   on_message(data)        (line 505): JSON events dispatched dynamically
   *                            via getattr(self, event) at handlers.py:512-520;
   *   start(search_key)       (line 553): SearchConnection.start - the sockjs
   *                            'start' event data with NO [0-9a-f]{64} route
   *                            constraint (unlike the HTTP routes): search_key
   *                            reaches SearchCache.get_search ->
   *                            os.path.join(basedir, search_key, 'search') ->
   *                            open()/pickle.load (blaster/cache.py:124-126).
   *
   * Verified: on_message and start are the only reviewed event-handler
   * parameters in this file (pause/resume/pong are not labeled).
   */
  private predicate isSockjsEventSource(DataFlow::Node source) {
    exists(Function f, string pname |
      f.getLocation().getFile().getAbsolutePath()
        .matches("%/opendiamond/blaster/handlers.py") and
      (
        (f.getName() = "on_message" and pname = "data")
        or
        (f.getName() = "start" and pname = "search_key")
      ) and
      source = DataFlow::parameterNode(f.getArgByName(pname))
    )
  }

  /**
   * Source family `cookie_parse` (1 candidate entry): the ScopeCookie.parse
   * result over cookie strings taken from the POST /search JSON body
   * (blaster/handlers.py:253). The cookies are signature-verified
   * (scope.py:96-136), so the content is cookie-issuer-controlled; the
   * review kept it candidate (cross-service chain to downstream diamond
   * servers, no local file sink in the blaster). Included per the reviewed
   * candidate label; no sink is expected to fire from it.
   */
  private predicate isScopeCookieParseSource(DataFlow::Node source) {
    exists(Call parse, Attribute func, Name scopeCookie |
      parse.getFunc() = func and
      func.getName() = "parse" and
      func.getObject() = scopeCookie and
      scopeCookie.getId() = "ScopeCookie" and
      parse.getLocation().getFile().getAbsolutePath()
        .matches("%/opendiamond/blaster/handlers.py") and
      source = DataFlow::exprNode(parse)
    )
  }

  /**
   * Source families `http_view_request` / `http_form` (26 tp entries): the
   * Django scopeserver request boundary across the seven apps (cocktail,
   * core, flickr, gatekeeper, gigapan, metadata, mirage).
   *
   *   (a) the `request` parameter of the 11 reviewed view functions
   *       (generate, browse, index, manage) - labels S-scopeserver_...-0
   *       entries, tp 0.8;
   *   (b) the 15 reviewed request.POST / request.GET attribute reads
   *       (labels S-scopeserver_...-POST / -GET, tp 0.8).
   *
   * Form-cleaned data flows into generate_cookie scopeurls - a cross-service
   * chain (scope cookies -> dataretriever objectlists) with no direct file
   * access in any view, so no local sink is expected to fire. All views are
   * @permission_required-protected: attacker-population limits, not
   * sanitization (django.md section 8). Verified: generate/browse/index/
   * manage are the only view functions taking `request`, and the POST/GET
   * attribute reads in the seven apps are exactly the reviewed 15 lines.
   */
  private predicate isDjangoViewSource(DataFlow::Node source) {
    exists(Function f |
      f.getName() in ["generate", "browse", "index", "manage"] and
      f.getLocation().getFile().getAbsolutePath()
        .matches("%/opendiamond/scopeserver/%/views.py") and
      source = DataFlow::parameterNode(f.getArgByName("request"))
    )
    or
    exists(Attribute field |
      field.getName() in ["POST", "GET"] and
      field.getObject().(Name).getId() = "request" and
      field.getLocation().getFile().getAbsolutePath()
        .matches("%/opendiamond/scopeserver/%/views.py") and
      source = DataFlow::exprNode(field)
    )
  }
}
