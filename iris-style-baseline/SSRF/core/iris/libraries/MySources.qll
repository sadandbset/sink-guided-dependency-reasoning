/**
 * Augur Phase 2 - Pass 3 (CWE-918 SSRF) source library.
 * Generated from reviewed labels: iris/labels/labels.json (pass 3, 1468 source/tp
 * entries, 16 batches, model glm-5.3, 2026-10-19).
 *
 * Label-family -> predicate mapping:
 *   service_data      (723 entries) -> serviceDataRead:       `service.data` / `call.data` reads in service handlers
 *   websocket_msg     (287 entries) -> websocketMsgRead:       msg["<key>"] / msg.get("<key>") payload reads (routing keys id/type excluded)
 *   http_handler_param(129 entries) -> handlerRequestParam:   `request` parameter of aiohttp view handler verbs
 *                                                                     (require_admin-gated handlers excluded, matching
 *                                                                     the none/fp labels on admin views)
 *   mqtt_payload      (113 entries) -> mqttPayloadRead:        msg.payload reads in MQTT callbacks
 *   request_attr      (144 entries) -> requestFieldRead:       request.query/remote/headers/path/content/query_string/match_info
 *   request_json      ( 33 entries) -> requestBodyRead:        await request.json()
 *   request_post      ( 12 entries) -> requestBodyRead:        await request.post()
 *   webhook_handler   ( 24 entries) -> webhookHandlerParam:    `request` parameter of (hass, webhook_id, request) webhook handlers
 *   config_flow / env / config_file / template_render rows are NOT sources: they were
 *   reviewed as admin-supplied, deployment-set, or summary-role labels.
 *
 * Trust boundaries (per label rationales): webhook handlers and requires_auth=False
 * views are unauthenticated HTTP; handler/request-field families without
 * requires_auth=False are reachable by any authenticated HA user (incl. non-admin);
 * MQTT payloads are external device-bus input (broker access required).
 * Internal network-wrapper parameters are deliberately NOT modeled as sources.
 *
 * Verified against codeql/python-all 7.1.2 (DataFlow::exprNode/parameterNode,
 * Attribute.getName()/getObject(), Call.getFunc()/getArg(), Subscript.getObject()/
 * getIndex(), StringLiteral.getText(), Function.getArgByName()/getADecorator()).
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySources {

  /* ------------------------------------------------------------------
   * Public interface (pass key: "ssrf")
   ------------------------------------------------------------------ */

  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "ssrf" and
    (
      serviceDataRead(source)
      or requestFieldRead(source)
      or requestBodyRead(source)
      or handlerRequestParam(source)
      or websocketMsgRead(source)
      or mqttPayloadRead(source)
      or webhookHandlerParam(source)
    )
  }

  /* ------------------------------------------------------------------
   * service_data family: (<service|call>).data
   ------------------------------------------------------------------ */

  private predicate serviceDataRead(DataFlow::Node source) {
    exists(Attribute a |
      a.getName() = "data" and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() in ["service", "call"] and
      source = DataFlow::exprNode(a)
    )
  }

  /* ------------------------------------------------------------------
   * request_attr family: request.<field>
   ------------------------------------------------------------------ */

  private predicate requestFieldRead(DataFlow::Node source) {
    exists(Attribute a |
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() = "request" and
      a.getName() in ["query", "remote", "headers", "path", "content", "query_string", "match_info"] and
      source = DataFlow::exprNode(a)
    )
  }

  /* ------------------------------------------------------------------
   * request_json / request_post families:
   * await request.json() / await request.post()
   ------------------------------------------------------------------ */

  private predicate requestBodyRead(DataFlow::Node source) {
    exists(Call c, Attribute func |
      func = c.getFunc() and
      func.getObject() instanceof Name and
      func.getObject().(Name).getId() = "request" and
      func.getName() in ["json", "post"] and
      source = DataFlow::exprNode(c)
    )
  }

  /* ------------------------------------------------------------------
   * http_handler_param family: view handler
   * `request` parameters (admin-gated excluded)
   ------------------------------------------------------------------ */

  private predicate handlerRequestParam(DataFlow::Node source) {
    exists(Function f, Parameter p |
      f.getName() in ["get", "post", "put", "delete", "patch", "head", "options", "_handle"] and
      p = f.getArgByName("request") and
      not adminGated(f) and
      source = DataFlow::parameterNode(p)
    )
  }

  /** The handler carries a @require_admin decorator (reviewed none/fp labels). */
  private predicate adminGated(Function f) {
    exists(Expr d | d = f.getADecorator() |
      (d instanceof Name and d.(Name).getId() = "require_admin")
      or
      (d instanceof Call and d.(Call).getFunc() instanceof Name and d.(Call).getFunc().(Name).getId() = "require_admin")
    )
  }

  /* ------------------------------------------------------------------
   * websocket_msg family: msg["<key>"] /
   * msg.get("<key>") (routing keys excluded)
   ------------------------------------------------------------------ */

  private predicate websocketMsgRead(DataFlow::Node source) {
    exists(Subscript s |
      s.getObject() instanceof Name and
      s.getObject().(Name).getId() = "msg" and
      s.getIndex() instanceof StringLiteral and
      not s.getIndex().(StringLiteral).getText() in ["id", "type"] and
      source = DataFlow::exprNode(s)
    )
    or
    exists(Call c, Attribute func, StringLiteral key |
      func = c.getFunc() and
      func.getObject() instanceof Name and
      func.getObject().(Name).getId() = "msg" and
      func.getName() = "get" and
      key = c.getArg(0) and
      not key.getText() in ["id", "type"] and
      source = DataFlow::exprNode(c)
    )
  }

  /* ------------------------------------------------------------------
   * mqtt_payload family: msg.payload
   ------------------------------------------------------------------ */

  private predicate mqttPayloadRead(DataFlow::Node source) {
    exists(Attribute a |
      a.getName() = "payload" and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() = "msg" and
      source = DataFlow::exprNode(a)
    )
  }

  /* ------------------------------------------------------------------
   * webhook_handler family: (hass, webhook_id,
   * request) handler entry points
   ------------------------------------------------------------------ */

  private predicate webhookHandlerParam(DataFlow::Node source) {
    exists(Function f |
      exists(Parameter w | w = f.getArgByName("webhook_id")) and
      source = DataFlow::parameterNode(f.getArgByName("request"))
    )
  }
}
