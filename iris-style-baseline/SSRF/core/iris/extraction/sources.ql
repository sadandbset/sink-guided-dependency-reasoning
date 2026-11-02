/**
 * @name core (Home Assistant) CWE-918 source candidate extraction
 * @description Extract source candidates from the Home Assistant core CodeQL
 *   database (snapshot e2dd7f2): input boundaries of a home-automation server
 *   for Pass 3 / CWE-918 (SSRF). Source families derived from real source
 *   inspection (all line evidence verified against the checked-out snapshot):
 *     1. HTTP view handler parameters: methods named get/post/put/delete/
 *        patch/head/options/_handle that take a `request` parameter, in view
 *        classes registered through hass.http.register_view
 *        (components/http/__init__.py:386; HomeAssistantView base class
 *        components/http/view.py:37; default requires_auth=True view.py:41,
 *        WebhookView overrides it to False at components/webhook/__init__.py:204)
 *     2. request body reads: await request.json() / await request.post()
 *        (52 call sites under components/)
 *     3. request field reads: request.query / match_info / headers / content /
 *        remote / query_string / path attribute reads (constrained to scopes
 *        that actually have a `request` parameter, which excludes look-alike
 *        local variables such as the hassio handler's response variable)
 *     4. webhook handler functions: functions with a webhook_id parameter
 *        (handler(hass, webhook_id, request), registered via
 *        components/webhook/__init__.py:52 async_register; dispatch at :182;
 *        the webhook URL is unauthenticated)
 *     5. service-call data reads: call.data / service.data attribute reads in
 *        functions taking a call/service parameter (service handlers; e.g.
 *        components/downloader/__init__.py:67 url = service.data[ATTR_URL])
 *     6. websocket API message reads: msg["<key>"] subscripts and
 *        msg.get("<key>") calls with literal keys other than the routing keys
 *        type/id (e.g. components/blueprint/websocket_api.py:76 msg["url"])
 *     7. config-flow user input: user_input parameters of async_step_* /
 *        validate_input functions (285 sites; UI form input, admin-facing)
 *     8. MQTT message payloads: msg.payload / message.payload attribute reads
 *        in functions taking a msg/message parameter
 *     9. template render calls: .async_render(...) / .render(...) /
 *        .async_render_complex(...) (e.g. rest_command renders the request URL
 *        from service.data variables at components/rest_command/__init__.py:103)
 *    10. environment variable reads: os.environ[...] / os.environ.get(...) /
 *        os.getenv(...)
 *    11. YAML configuration loads: yaml.safe_load / yaml.parse_yaml /
 *        yaml.load / yaml.load_yaml attribute calls and bare
 *        load_yaml / load_yaml_config_file calls
 *   Internal helper url parameters that merely forward already-derived URLs
 *   are NOT listed as sources here (they are covered on the sink side as
 *   wrapper candidates). config-entry data (entry.data, 3391 sites) and
 *   entity-state reads are deliberately not extracted (admin-config /
 *   weak-attacker-control classes; see detection.json exclusions).
 *   Rows under tests/ and core-db/ are excluded by path.
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain multi-column
 *   select query on purpose: @kind problem is the wrong shape for candidate
 *   tables and @kind table is not assumed to exist.
 * @id iris/core-cwe918/extraction/sources
 * @tags ssrf
 */

import python

/* ------------------------------------------------------------------ */
/* Column contract (identical order to sinks.ql):                      */
/* ------------------------------------------------------------------ */

/*
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/parameter/attribute/subscript name at the boundary
 *   4. flow_kind  - "http_handler_param" (view handler request parameter)
 *                   "request_json"       (await request.json())
 *                   "request_post"       (await request.post() form read)
 *                   "request_attr"       (request.query/match_info/... read)
 *                   "webhook_handler"    (webhook handler function definition)
 *                   "service_data"       (call.data / service.data read)
 *                   "websocket_msg"      (msg["key"] / msg.get("key") read)
 *                   "config_flow"        (async_step_* and validate_input
 *                                        user_input parameter)
 *                   "mqtt_payload"       (msg.payload / message.payload read)
 *                   "template_render"    (.async_render/.render call result)
 *                   "env"                (os.environ / os.getenv read)
 *                   "config_file"        (yaml load call)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression, enclosing class name for definition rows,
 *                   "" if none)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module` is
 *                   not a valid QL variable name here)
 *   7. arg_index  - 0-based positional index of the input where applicable
 *                   (parameter position for parameter rows; getPosition()
 *                   counts `self` as index 0 for methods), -1 when the
 *                   candidate is a value read / function definition
 *   8. file       - absolute file path, obtained through the Location API
 *                   (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "ast" (every input boundary in this codebase is internal
 *                   framework code: HomeAssistantView handlers, webhook
 *                   dispatch, service/websocket registration; the aiohttp
 *                   Request type itself never appears as an import that
 *                   needs API-graph resolution, so no "api" rows exist in
 *                   this query)
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/**
 * Path filter (Augur candidate strategy: exclude tests/fixtures and the
 * nested CodeQL database directory). Both forward-slash and backslash
 * separators are covered; `string` is an infinite-domain QL type, so the
 * predicate is only called with paths obtained from CodeQL File locations
 * (input binding set declared explicitly).
 */
bindingset[p]
predicate isExcludedPath(string p) {
  p.matches("%/tests/%")
  or
  p.matches("%\\tests\\%")
  or
  p.matches("%/test_%.py")
  or
  p.matches("%\\test_%.py")
  or
  p.matches("%/conftest.py")
  or
  p.matches("%\\conftest.py")
  or
  p.matches("%core-db%")
}

/** Dotted path of the python module containing n (used as moduleHint).
 *  Files that are not on an import path (top-level scripts) have no dotted
 *  module name; their file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getBaseName()
}

/** Base name of the object expression of an attribute access, used as a
 *  receiver hint. */
string receiverHint(Attribute a) {
  result = a.getObject().(Name).getId()
  or
  result = a.getObject().(Attribute).getName()
  or
  not a.getObject() instanceof Name and
  not a.getObject() instanceof Attribute and
  result = "<expr>"
}

/**
 * Holds if some function in the scope chain of n (n's own scope or any
 * enclosing scope, covering direct handlers and closures over handler
 * parameters) has a parameter with the given name. Used to constrain
 * request/call/service/msg reads to functions that actually receive such a
 * parameter, which excludes look-alike local variables (e.g. the local
 * `request` response variable in components/hassio/handler.py:534).
 */
bindingset[name]
predicate scopeChainHasParam(AstNode n, string name) {
  exists(Function f, Parameter p |
    f = n.getScope().getEnclosingScope*() and
    p = f.getArgByName(name)
  )
}

/** 0-based positional parameter index (counts `self` for methods), -1 for
 *  keyword-only parameters. */
int paramPosition(Parameter p) {
  result = p.getPosition()
  or
  not exists(p.getPosition()) and result = -1
}

/** Enclosing class name of a function, "" for module-level functions. */
string enclosingClassName(Function f) {
  f.getEnclosingScope() instanceof Class and
  result = f.getEnclosingScope().(Class).getName()
  or
  not f.getEnclosingScope() instanceof Class and
  result = ""
}

/* ------------------------------------------------------------------ */
/* Source family 1: HTTP view handler request parameters               */
/* ------------------------------------------------------------------ */

/** aiohttp/HA view handler method names; WebhookView dispatches through
 *  _handle (components/webhook/__init__.py:207) and binds get/head/post/put
 *  to it via class-level aliases. */
predicate handlerVerb(string name) {
  name in ["get", "post", "put", "delete", "patch", "head", "options", "_handle"]
}

/** Methods (in a class) with a handler-verb name that take a `request`
 *  parameter. 104 verb-named sites plus _handle under components/. */
predicate httpHandler(Function f) {
  handlerVerb(f.getName()) and
  f.isMethod() and
  exists(Parameter p | p = f.getArgByName("request"))
}

/* ------------------------------------------------------------------ */
/* Source families 2+3: request body / field reads                     */
/* ------------------------------------------------------------------ */

/** await request.json() / await request.post() call sites on a `request`
 *  parameter (body/form input). */
predicate requestBodyRead(Call c, string callableName, string flowKind) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() in ["json", "post"] and
  c.getFunc().(Attribute).getObject() instanceof Name and
  c.getFunc().(Attribute).getObject().(Name).getId() = "request" and
  scopeChainHasParam(c, "request") and
  callableName = c.getFunc().(Attribute).getName() and
  flowKind = "request_" + callableName
}

/** request attribute fields that carry caller-controlled data (query string,
 *  route match values, headers, body stream, peer address, path). */
predicate requestFieldName(string name) {
  name in ["query", "match_info", "headers", "content", "remote", "query_string", "path"]
}

predicate requestAttrRead(Attribute a, string fieldName) {
  requestFieldName(fieldName) and
  a.getName() = fieldName and
  a.getObject() instanceof Name and
  a.getObject().(Name).getId() = "request" and
  scopeChainHasParam(a, "request")
}

/* ------------------------------------------------------------------ */
/* Source family 4: webhook handler functions                          */
/* ------------------------------------------------------------------ */

/**
 * Webhook handlers: functions with a webhook_id parameter (signature
 * handler(hass, webhook_id, request) per components/webhook/__init__.py:52
 * async_register; dispatched unauthenticated at :182 from WebhookView,
 * requires_auth=False at :204). 37 sites under components/.
 */
predicate webhookHandler(Function f) {
  exists(Parameter w | w = f.getArgByName("webhook_id"))
}

/* ------------------------------------------------------------------ */
/* Source family 5: service-call data reads                            */
/* ------------------------------------------------------------------ */

/** call.data / service.data attribute reads in functions that take a
 *  call/service parameter (ServiceCall handlers; e.g.
 *  components/downloader/__init__.py:67 url = service.data[ATTR_URL]).
 *  443 sites under components/. */
predicate serviceDataRead(Attribute a, string receiverName) {
  receiverName in ["call", "service"] and
  a.getName() = "data" and
  a.getObject() instanceof Name and
  a.getObject().(Name).getId() = receiverName and
  scopeChainHasParam(a, receiverName)
}

/* ------------------------------------------------------------------ */
/* Source family 6: websocket API message reads                        */
/* ------------------------------------------------------------------ */

/** msg["<key>"] subscript reads with a literal key that is not one of the
 *  websocket routing keys type/id. */
predicate websocketMsgSubscript(Subscript s) {
  s.getValue() instanceof Name and
  s.getValue().(Name).getId() = "msg" and
  s.getIndex() instanceof StringLiteral and
  s.getIndex().(StringLiteral).getText() != "type" and
  s.getIndex().(StringLiteral).getText() != "id" and
  scopeChainHasParam(s, "msg")
}

/** msg.get("<key>") reads with a literal key that is not type/id. */
predicate websocketMsgGet(Call c) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = "get" and
  c.getFunc().(Attribute).getObject() instanceof Name and
  c.getFunc().(Attribute).getObject().(Name).getId() = "msg" and
  c.getPositionalArg(0) instanceof StringLiteral and
  c.getPositionalArg(0).(StringLiteral).getText() != "type" and
  c.getPositionalArg(0).(StringLiteral).getText() != "id" and
  scopeChainHasParam(c, "msg")
}

/* ------------------------------------------------------------------ */
/* Source family 7: config-flow user input                             */
/* ------------------------------------------------------------------ */

/** Config flow / options flow steps and validation helpers taking a
 *  user_input dict (UI form input; admin-facing). 285 sites. */
predicate configFlowFunction(Function f) {
  f.getName().matches("async_step_%")
  or
  f.getName() = "validate_input"
}

/* ------------------------------------------------------------------ */
/* Source family 8: MQTT message payload reads                         */
/* ------------------------------------------------------------------ */

/** msg.payload / message.payload attribute reads in functions that take a
 *  msg/message parameter (MQTT subscription callbacks and mqtt platform
 *  message receivers). */
predicate mqttPayloadRead(Attribute a, string receiverName) {
  receiverName in ["msg", "message"] and
  a.getName() = "payload" and
  a.getObject() instanceof Name and
  a.getObject().(Name).getId() = receiverName and
  scopeChainHasParam(a, receiverName)
}

/* ------------------------------------------------------------------ */
/* Source family 9: template render calls                              */
/* ------------------------------------------------------------------ */

/** Template render invocations; the rendered result can carry variables
 *  (service data, entity state) into URLs (rest_command builds its request
 *  URL this way, components/rest_command/__init__.py:103). Receiver is any
 *  template-like object; disambiguation is left to labeling. */
predicate templateRenderCall(Call c) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() in ["async_render", "render", "async_render_complex"]
}

/* ------------------------------------------------------------------ */
/* Source families 10+11: environment and YAML configuration reads     */
/* ------------------------------------------------------------------ */

/** os.environ[...] subscripts, os.environ.get(...) and os.getenv(...) calls. */
predicate envRead(AstNode n, string callableName, string receiver, int argIndex) {
  exists(Subscript s |
    s.getValue() instanceof Attribute and
    s.getValue().(Attribute).getName() = "environ" and
    s.getValue().(Attribute).getObject() instanceof Name and
    s.getValue().(Attribute).getObject().(Name).getId() = "os" and
    n = s and
    callableName = "environ" and
    receiver = "os" and
    argIndex = -1
  )
  or
  exists(Call c |
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    c.getFunc().(Attribute).getObject() instanceof Attribute and
    c.getFunc().(Attribute).getObject().(Attribute).getName() = "environ" and
    c.getFunc().(Attribute).getObject().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "os" and
    n = c and
    callableName = "get" and
    receiver = "os.environ" and
    argIndex = 0
  )
  or
  exists(Call c |
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "getenv" and
    c.getFunc().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
    n = c and
    callableName = "getenv" and
    receiver = "os" and
    argIndex = 0
  )
}

/** YAML loads: yaml.safe_load/parse_yaml/load/load_yaml attribute calls and
 *  bare load_yaml/load_yaml_config_file calls (homeassistant.util.yaml
 *  loader and configuration.yaml bootstrap). */
predicate yamlLoadCall(Call c, string callableName, string receiver) {
  exists(Attribute attr |
    attr = c.getFunc() and
    attr.getName() in ["safe_load", "load", "parse_yaml", "load_yaml"] and
    attr.getObject() instanceof Name and
    attr.getObject().(Name).getId() = "yaml" and
    callableName = attr.getName() and
    receiver = "yaml"
  )
  or
  exists(Name nm |
    nm = c.getFunc() and
    nm.getId() in ["load_yaml", "load_yaml_config_file"] and
    callableName = nm.getId() and
    receiver = ""
  )
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: HTTP view handler `request` parameters */
  exists(Function f, Parameter p |
    httpHandler(f) and
    p = f.getArgByName("request") and
    node = p and
    callableName = "request" and
    flowKind = "http_handler_param" and
    receiver = enclosingClassName(f) and
    argIndex = paramPosition(p) and
    matchKind = "ast" and
    moduleHint = moduleHintOf(p)
  )
  or
  /* family 2: request body/form reads */
  exists(Call c |
    requestBodyRead(c, callableName, flowKind) and
    node = c and
    receiver = "request" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 3: request field attribute reads */
  exists(Attribute a, string fieldName |
    requestAttrRead(a, fieldName) and
    node = a and
    callableName = fieldName and
    flowKind = "request_attr" and
    receiver = "request" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(a)
  )
  or
  /* family 4: webhook handler function definitions */
  exists(Function f |
    webhookHandler(f) and
    node = f and
    callableName = f.getName() and
    flowKind = "webhook_handler" and
    receiver = enclosingClassName(f) and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    (
      exists(Parameter rp |
        rp = f.getArgByName("request") and
        argIndex = paramPosition(rp)
      )
      or
      not exists(f.getArgByName("request")) and
      argIndex = -1
    )
  )
  or
  /* family 5: service-call data reads */
  exists(Attribute a, string receiverName |
    serviceDataRead(a, receiverName) and
    node = a and
    callableName = "data" and
    flowKind = "service_data" and
    receiver = receiverName and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(a)
  )
  or
  /* family 6: websocket message reads */
  exists(Subscript s |
    websocketMsgSubscript(s) and
    node = s and
    callableName = "__getitem__" and
    flowKind = "websocket_msg" and
    receiver = "msg" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(s)
  )
  or
  exists(Call c |
    websocketMsgGet(c) and
    node = c and
    callableName = "get" and
    flowKind = "websocket_msg" and
    receiver = "msg" and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 7: config-flow user_input parameters */
  exists(Function f, Parameter p |
    configFlowFunction(f) and
    p = f.getArgByName("user_input") and
    node = p and
    callableName = "user_input" and
    flowKind = "config_flow" and
    receiver = enclosingClassName(f) and
    argIndex = paramPosition(p) and
    matchKind = "ast" and
    moduleHint = moduleHintOf(p)
  )
  or
  /* family 8: MQTT message payload reads */
  exists(Attribute a, string receiverName |
    mqttPayloadRead(a, receiverName) and
    node = a and
    callableName = "payload" and
    flowKind = "mqtt_payload" and
    receiver = receiverName and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(a)
  )
  or
  /* family 9: template render calls */
  exists(Call c |
    templateRenderCall(c) and
    node = c and
    callableName = c.getFunc().(Attribute).getName() and
    flowKind = "template_render" and
    receiver = receiverHint(c.getFunc().(Attribute)) and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 10: environment variable reads */
  exists(AstNode n |
    envRead(n, callableName, receiver, argIndex) and
    node = n and
    flowKind = "env" and
    matchKind = "ast" and
    moduleHint = moduleHintOf(n)
  )
  or
  /* family 11: YAML configuration loads */
  exists(Call c |
    yamlLoadCall(c, callableName, receiver) and
    node = c and
    flowKind = "config_file" and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint,
    argIndex, matchKind) and
  not isExcludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "source_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
