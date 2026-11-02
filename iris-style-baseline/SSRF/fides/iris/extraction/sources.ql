
/**
 * @name Fides source candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate external-input source APIs from the
 *              Fides FastAPI application for subsequent LLM labeling.
 * @id py/augur/fides/pass3-sources
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * Scope: relative paths under src/fides/ only. This excludes the
 * nested fides-db CodeQL database directory, the repo-root tests/
 * harness trees, scripts/ and clients/ by construction.
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("source_candidate")
 *  3. callable            (handler name / dotted signature hint)
 *  4. flow kind           (param | return | field)
 *  5. receiver            (receiver/type hint)
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

/** Restrict extraction to the Fides application package. */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("src/fides/%")
  )
}

/**
 * Restrict a candidate to the FastAPI endpoints package
 * (route-decorated handler functions).
 * The path string is bound by equality before matches(), so no
 * unbound-variable error can occur.
 */
predicate inEndpointsModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("src/fides/api/api/%")
  )
}

/** Restrict a candidate to the API layer (endpoints + middleware). */
predicate inApiModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("src/fides/api/%")
  )
}

/** Restrict a candidate to the service layer (connectors, dispatch). */
predicate inServiceModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("src/fides/api/service/%")
  )
}

/** Restrict a candidate to the messaging dispatch service module. */
predicate inMessagingServiceModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path = "src/fides/api/service/messaging/message_dispatch_service.py"
  )
}

/** Restrict a candidate to the CLI and core client packages. */
predicate inCliOrCoreModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    (
      path.matches("src/fides/cli/%")
      or
      path.matches("src/fides/core/%")
    )
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
// 2. FastAPI handler detection (verified against this source)
// ------------------------------------------------------------

/**
 * FastAPI route handlers are decorated with `@<router>.<verb>(...)`
 * where <router> is an APIRouter instance (router, ADMIN_ROUTER,
 * SYSTEM_ROUTER, nested factory routers, ...).
 *
 * Python CodeQL has no Decorator AST type; Function.getADecorator()
 * returns the decorator func expression (e.g. the `router.put`
 * attribute for `@router.put(...)`).
 */
predicate isRouteMethod(string verb) {
  verb in ["get", "post", "put", "patch", "delete"]
}

predicate isRouteHandler(Function f) {
  exists(Expr dec |
    dec = f.getADecorator() and
    dec instanceof Attribute and
    isRouteMethod(dec.(Attribute).getName())
  )
}

/**
 * Dependency-injected handler parameters (default value is a
 * Depends(...) or Security(...) call) are framework wiring, not
 * client payload, and are excluded from source extraction.
 */
predicate isDependencyInjected(Parameter p) {
  exists(Call c, Expr func |
    c = p.getDefault() and
    func = c.getFunc() and
    (
      (
        func instanceof Name and
        func.(Name).getId() in ["Depends", "Security"]
      )
      or
      (
        func instanceof Attribute and
        func.(Attribute).getName() in ["Depends", "Security"]
      )
    )
  )
}

// ------------------------------------------------------------
// 3. Candidate extraction
// ------------------------------------------------------------

from
  AstNode n,
  string callable,
  string flow_kind,
  string receiver,
  string moduleHint,
  int arg_index
where
  inAnalysisScope(n) and
  moduleHint = moduleOf(n) and
  (
    // --------------------------------------------------------
    // (1) Positional parameters of FastAPI route handlers
    //     (path variables, query parameters and request-body
    //      models; URL-bearing bodies include connection
    //      secrets HttpsSchema.url / FidesConnectorSchema.uri,
    //      SaaS secrets, saas_config client_config host,
    //      messaging details/secrets)
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      f.getArg(i) = p and
      isRouteHandler(f) and
      inEndpointsModule(p) and
      not isDependencyInjected(p) and
      callable = f.getName() and
      flow_kind = "param" and
      receiver = "fastapi.handler" and
      arg_index = i
    )

    or

    // --------------------------------------------------------
    // (1b) Keyword-only parameters of FastAPI route handlers
    //      (e.g. verify: Optional[bool] = True on
    //       put_connection_config_secrets, which triggers an
    //       immediate live connection test)
    // --------------------------------------------------------

    exists(Parameter p, Function f |
      n = p and
      f.getAKeywordOnlyArg() = p and
      isRouteHandler(f) and
      inEndpointsModule(p) and
      not isDependencyInjected(p) and
      callable = f.getName() and
      flow_kind = "param" and
      receiver = "fastapi.handler" and
      arg_index = -1
    )

    or

    // --------------------------------------------------------
    // (2) request.headers.get(...) calls
    //     e.g. saas_config_endpoints.py:267
    //          referer = request.headers.get("Referer")
    // --------------------------------------------------------

    exists(Call call, Attribute method, Attribute hdrs, Name req |
      n = call and
      method = call.getFunc() and
      method.getName() = "get" and
      hdrs = method.getObject() and
      hdrs.getName() = "headers" and
      req = hdrs.getObject() and
      req.getId() = "request" and
      inApiModule(n) and
      callable = "request.headers.get" and
      flow_kind = "return" and
      receiver = "starlette.request" and
      arg_index = -1
    )

    or

    // --------------------------------------------------------
    // (2b) Plain request.headers reads not consumed as the base
    //      of a further attribute access, call, or subscript
    //      (those are covered by family (2))
    //      e.g. privacy_preference_endpoints.py:298
    //           request_headers = request.headers
    // --------------------------------------------------------

    exists(Attribute a, Name req |
      n = a and
      a.getName() = "headers" and
      req = a.getObject() and
      req.getId() = "request" and
      inApiModule(n) and
      not exists(Attribute outer | outer.getObject() = a) and
      not exists(Call c | c.getFunc() = a) and
      not exists(Subscript s | s.getObject() = a) and
      callable = "request.headers" and
      flow_kind = "field" and
      receiver = "starlette.request" and
      arg_index = -1
    )

    or

    // --------------------------------------------------------
    // (3) config.cli.server_url attribute reads
    //     (env/toml-configured Fides webserver URL; pydantic
    //      settings build it from FIDES__* env vars,
    //      fides/config/cli_settings.py:33-53)
    //     e.g. fides/cli/utils.py:106
    //          get(f"{config.cli.server_url}...{REGISTRATION}")
    // --------------------------------------------------------

    exists(Attribute urlAttr, Attribute cliAttr, Name cfg |
      n = urlAttr and
      urlAttr.getName() = "server_url" and
      cliAttr = urlAttr.getObject() and
      cliAttr.getName() = "cli" and
      cfg = cliAttr.getObject() and
      cfg.getId() = "config" and
      inCliOrCoreModule(n) and
      callable = "config.cli.server_url" and
      flow_kind = "field" and
      receiver = "fides.config.CLISettings" and
      arg_index = -1
    )

    or

    // --------------------------------------------------------
    // (4) server_url / org_url parameters of CLI and core
    //     client functions (click options such as --org-url,
    //      fides/cli/options.py:174-191, or caller-supplied
    //      config values)
    //     e.g. fides/cli/utils.py:59 check_server_health(server_url),
    //          fides/cli/utils.py:281 handle_okta_credentials_options(org_url),
    //          fides/core/user.py:34 login(server_url, ...)
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      f.getArg(i) = p and
      p.asName().getId() in ["server_url", "org_url"] and
      inCliOrCoreModule(p) and
      callable = f.getName() and
      flow_kind = "param" and
      receiver = "click_or_config_boundary" and
      arg_index = i
    )

    or

    // --------------------------------------------------------
    // (5) ConnectionConfig .secrets attribute reads in the
    //     service layer - earliest project-internal
    //     materialization of the URL/uri/domain-bearing request
    //     bodies persisted through the connection secrets
    //     endpoints (HttpsSchema.url, FidesConnectorSchema.uri,
    //      SaaS secrets domain/host placeholders)
    //     e.g. http_connector.py:26/33/43
    //          HttpsSchema(**self.configuration.secrets or {})
    //          saas_connector.py self.secrets (assigned from
    //          configuration.secrets at __init__)
    //          authentication_strategy_oauth2_base.py:89
    //          connection_config.secrets
    // --------------------------------------------------------

    exists(Attribute a |
      n = a and
      a.getName() = "secrets" and
      inServiceModule(n) and
      not exists(Assign asg | asg.getATarget() = a) and
      (
        (
          a.getObject() instanceof Name and
          a.getObject().(Name).getId() in ["self", "connection_config"]
        )
        or
        (
          a.getObject() instanceof Attribute and
          a.getObject().(Attribute).getName() = "configuration"
        )
      ) and
      callable = "ConnectionConfig.secrets" and
      flow_kind = "field" and
      receiver = "ConnectionConfig" and
      arg_index = -1
    )

    or

    // --------------------------------------------------------
    // (6) messaging_config.details / messaging_config.secrets
    //     reads in the messaging dispatch service (email/SMS
    //      dispatch config persisted from the messaging
    //      endpoints; carries mailgun domain / twilio keys)
    //     e.g. message_dispatch_service.py:406/408
    //          messaging_config.details[...],
    //          messaging_config.secrets[...]
    // --------------------------------------------------------

    exists(Attribute a, Name mc |
      n = a and
      a.getName() in ["details", "secrets"] and
      mc = a.getObject() and
      mc.getId() = "messaging_config" and
      inMessagingServiceModule(n) and
      not exists(Assign asg | asg.getATarget() = a) and
      callable = "MessagingConfig." + a.getName() and
      flow_kind = "field" and
      receiver = "MessagingConfig" and
      arg_index = -1
    )

    or

    // --------------------------------------------------------
    // (7) get_saas_config() call results in the service layer
    //     (SaaS config incl. client_config protocol/host,
    //      persisted from PUT /connection/{key}/saas_config)
    //     e.g. saas_connector.py:29 configuration.get_saas_config(),
    //          authentication_strategy_oauth2_base.py:64
    //          connection_config.get_saas_config()
    // --------------------------------------------------------

    exists(Call call, Attribute method |
      n = call and
      method = call.getFunc() and
      method.getName() = "get_saas_config" and
      inServiceModule(n) and
      callable = "ConnectionConfig.get_saas_config" and
      flow_kind = "return" and
      receiver = "ConnectionConfig" and
      arg_index = -1
    )
  )

select
  n,
  "source_candidate",
  callable,
  flow_kind,
  receiver,
  moduleHint,
  arg_index,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()
