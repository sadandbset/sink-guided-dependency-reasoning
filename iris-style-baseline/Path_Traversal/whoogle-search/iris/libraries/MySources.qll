/**
 * Augur / IRIS generated source library — whoogle-search, pass 1 (path_traversal).
 *
 * Rendered deterministically from the reviewed Phase 1 labels
 * (iris/labels/labels.json, pass_id 1). Only candidates whose reviewed role is
 * "source" appear here; env / CLI rows (role "none", operator trust) and pure
 * path wrappers are deliberately NOT sources.
 *
 * Label coverage (81 source entries):
 *   - requestLayerAttribute / requestLayerCallResult: 59 tp entries
 *     (flask request.args/.form/.data/.headers/.method/.authorization/.url_root
 *      reads and .get()/.to_dict() call results, incl. the self.request.<layer>
 *      variants in app/utils/search.py and the /config 'name' reads at
 *     app/routes.py:429/:447, src-110/src-111/src-118/src-119, conf 0.97)
 *   - requestParamsAlias / requestParamsAliasCallResult: tp 0.75 alias rows
 *     (g.request_params / self.request_params reads and .get() calls; the alias
 *      is assigned from request.args|request.form in before_request,
 *      app/routes.py:140-142)
 *   - sessionSubscript: 16 candidate entries (flask session[...] reads; values
 *      attacker-settable via POST /config, signed with the instance SECRET_KEY)
 *   - proxyRequestRead / proxyRequestCallResult / proxyEnvironSubscript:
 *     5 candidate entries (r.environ / r.headers / r.full_path on the flask
 *      Request parameter r in app/utils/misc.py:28-45)
 *
 * Machine-generated; do not hand-edit without re-running the label review.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /* ---------- flask request layer (reviewed tp sources) ---------- */

  /**
   * An attribute read of a reviewed request layer on the flask request object.
   * Matches `request.<layer>` where `request` is the flask request name
   * (module import in app/routes.py, or the Search.__init__ parameter), and
   * `self.request.<layer>` in app/utils/search.py.
   */
  predicate flaskRequestLayerAttr(Attribute a) {
    a.getName() in ["args", "form", "data", "headers", "method", "authorization", "url_root"] and
    (
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() = "request"
      or
      a.getObject() instanceof Attribute and
      a.getObject().(Attribute).getName() = "request" and
      a.getObject().(Attribute).getObject() instanceof Name and
      a.getObject().(Attribute).getObject().(Name).getId() = "self"
    )
  }

  /** Value of a direct `request.<layer>` / `self.request.<layer>` read. */
  predicate requestLayerAttribute(DataFlow::Node n) {
    exists(Attribute a | flaskRequestLayerAttr(a) and n.asExpr() = a)
  }

  /**
   * Result of `.get(...)` / `.to_dict()` called on a request layer
   * (request.args.get('name'), request.headers.get('User-Agent'),
   *  request.form.to_dict()).
   */
  predicate requestLayerCallResult(DataFlow::Node n) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() in ["get", "to_dict"] and
      f.getObject() instanceof Attribute and
      flaskRequestLayerAttr(f.getObject().(Attribute)) and
      n.asExpr() = c
    )
  }

  /* ---------- g.request_params / self.request_params alias (reviewed tp 0.75) ---------- */

  /**
   * `g.request_params` / `self.request_params` read: the before_request alias of
   * request.args / request.form (app/routes.py:140-142, app/utils/search.py:61).
   */
  predicate requestParamsAlias(DataFlow::Node n) {
    exists(Attribute a |
      a.getName() = "request_params" and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() in ["g", "self"] and
      n.asExpr() = a
    )
  }

  /** Result of `.get(...)` on the g.request_params / self.request_params alias. */
  predicate requestParamsAliasCallResult(DataFlow::Node n) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "get" and
      f.getObject() instanceof Attribute and
      f.getObject().(Attribute).getName() = "request_params" and
      f.getObject().(Attribute).getObject() instanceof Name and
      f.getObject().(Attribute).getObject().(Name).getId() in ["g", "self"] and
      n.asExpr() = c
    )
  }

  /* ---------- flask session store (reviewed candidate, semi-trusted) ---------- */

  /**
   * `session[...]` subscript read: signed-cookie store whose 'config' values are
   * written from POST /config request.form data (app/routes.py:449) and reloaded
   * in before_request (app/routes.py:155). No session value reaches a file path
   * in the audited tree; kept as candidate sources for recall.
   */
  predicate sessionSubscript(DataFlow::Node n) {
    exists(Subscript s |
      s.getObject() instanceof Name and
      s.getObject().(Name).getId() = "session" and
      n.asExpr() = s
    )
  }

  /* ---------- proxy/Wsgi fields on the flask Request parameter r (reviewed candidate) ---------- */

  /**
   * `r.environ` / `r.headers` / `r.full_path` reads on the flask Request
   * parameter `r` of get_client_ip / get_proxy_host_url (app/utils/misc.py).
   * Client-supplied when ProxyFix is active (app/__init__.py:26); feeds URL/IP
   * construction only.
   */
  predicate proxyRequestRead(DataFlow::Node n) {
    exists(Attribute a |
      a.getName() in ["environ", "headers", "full_path"] and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() = "r" and
      n.asExpr() = a
    )
  }

  /** Result of `.get(...)` on r.environ / r.headers (misc.py:28/:42/:43). */
  predicate proxyRequestCallResult(DataFlow::Node n) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "get" and
      f.getObject() instanceof Attribute and
      f.getObject().(Attribute).getName() in ["environ", "headers"] and
      f.getObject().(Attribute).getObject() instanceof Name and
      f.getObject().(Attribute).getObject().(Name).getId() = "r" and
      n.asExpr() = c
    )
  }

  /** `r.environ[...]` subscript read (misc.py:29/:31). */
  predicate proxyEnvironSubscript(DataFlow::Node n) {
    exists(Subscript s |
      s.getObject() instanceof Attribute and
      s.getObject().(Attribute).getName() = "environ" and
      s.getObject().(Attribute).getObject() instanceof Name and
      s.getObject().(Attribute).getObject().(Name).getId() = "r" and
      n.asExpr() = s
    )
  }

  /* ---------- pass dispatch ---------- */

  predicate isSource(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      requestLayerAttribute(n)
      or requestLayerCallResult(n)
      or requestParamsAlias(n)
      or requestParamsAliasCallResult(n)
      or sessionSubscript(n)
      or proxyRequestRead(n)
      or proxyRequestCallResult(n)
      or proxyEnvironSubscript(n)
    )
  }
}
