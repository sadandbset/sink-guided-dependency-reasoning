/**
 * @name pyramid Pass 1 source candidates (Path Traversal)
 * @description Extracts untrusted-input source candidates for CWE-22/23/36/73
 *   from the Pyramid 2.0.1 framework source (src/pyramid): WSGI environ
 *   parameters of WSGI application entry points, 'request' parameters of
 *   request-entry methods and (context, request) view-callable functions,
 *   request object field reads (path_info, path, path_url, url, subpath,
 *   query_string, matchdict, matched_route, params, GET, POST, cookies,
 *   headers, environ, accept_encoding, locale_name, localizer), .get()
 *   lookups and subscripts on request fields and on local 'environ' /
 *   'matchdict' aliases, getattr(request, ...) dynamic reads, CLI argv
 *   parameters and self.args argparse reads (operator boundary), os.environ
 *   reads (operator boundary), .get() on local 'settings' in the CLI
 *   scripts, and config/asset-spec parameters of configuration-facing
 *   constructors whose values reach filesystem operations (static_view
 *   root_dir, ManifestCacheBuster manifest_spec, asset override and
 *   descriptor paths, AssetResolver.resolve spec,
 *   abspath_from_asset_spec spec, StaticURLInfo.add spec,
 *   override_asset to_override/override_with, _override path). Evidence
 *   derived from src/pyramid/static.py, router.py, traversal.py,
 *   urldispatch.py, i18n.py, request.py, response.py, predicates.py,
 *   csrf.py, authentication.py, renderers.py, view.py, viewderivers.py,
 *   config/views.py, config/assets.py, asset.py, path.py and scripts/*.py.
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/pyramid-cwe22/extract-sources
 */

import python

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Gets the dotted name of a simple name/attribute chain,
 * e.g. "os.environ.get" or "self.pkg_resources.resource_filename". Yields no
 * result for expressions whose object part is not a simple name/attribute
 * chain.
 */
private string dottedName(Expr e) {
  result = e.(Name).getId()
  or
  result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
}

/**
 * Gets the repository-relative path of the file containing this node,
 * e.g. "src/pyramid/static.py". The primary source is
 * File.getRelativePath(); on this Windows-created database the stored source
 * location prefix uses backslashes while file paths are forward-slash
 * normalized, so getRelativePath() may yield backslash forms or no result -
 * in that case fall back to capturing the "src/pyramid/..." suffix from the
 * absolute path (verified forward-slash format in the database string pool).
 */
private string relPath(AstNode n) {
  exists(string p |
    p = n.getLocation().getFile().getRelativePath() and
    result = p.replaceAll("\\", "/")
  )
  or
  not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/").regexpCapture(".*/(src/pyramid/.+)$", 1)
}

/**
 * Derives a module hint such as "pyramid.static" from the file path. The
 * ".py" suffix is stripped with an escaped-dot anchored regex: a plain
 * ".py" pattern would also match the "/py" inside "src/pyramid" because the
 * unescaped dot matches any character.
 */
private string moduleHintOf(AstNode n) {
  result = relPath(n).replaceAll("\\.py$", "").replaceAll("/", ".")
}

/**
 * Restricts candidates to the pyramid package itself. This structurally
 * excludes the nested pyramid-db CodeQL database directory (repo root), the
 * tests/ tree, setup.py and repository-root scripts; per the Augur noise
 * policy the framework's own testing helper modules are excluded, and
 * interfaces.py (zope.interface declaration stubs with no executable logic)
 * is excluded to keep interface method declarations out of the candidate set.
 */
private predicate inPyramidPackage(AstNode n) {
  relPath(n).matches("src/pyramid/%") and
  not relPath(n).matches("src/pyramid/testing.py") and
  not relPath(n).matches("src/pyramid/config/testing.py") and
  not relPath(n).matches("src/pyramid/interfaces.py")
}

/** Gets the enclosing class name for methods, or "" for plain functions. */
private string receiverOf(Function f) {
  f.isMethod() and result = f.getEnclosingScope().(Class).getName()
  or
  not f.isMethod() and result = ""
}

/** Request object fields whose reads carry HTTP-controlled data. */
private predicate isRequestField(string fieldName) {
  fieldName in [
    "path_info", "path", "path_url", "url", "subpath", "query_string",
    "matchdict", "matched_route", "params", "GET", "POST", "cookies",
    "headers", "environ", "accept_encoding", "locale_name", "localizer"
  ]
}

/**
 * Holds for attribute reads of a request field, matching both
 * "request.<field>" and "self.request.<field>" chains. Only these chains are
 * accepted, so unrelated local variables named "request" cannot match unless
 * they shadow the framework request object.
 */
private predicate requestFieldAttr(Attribute a, string fieldName) {
  isRequestField(fieldName) and
  a.getName() = fieldName and
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

/** Maps a request field name to a flow-kind label for the labeling stage. */
private string requestFieldFlowKind(string fieldName) {
  fieldName in ["path_info", "path"] and result = "http_path"
  or
  fieldName in ["path_url", "url"] and result = "request_url"
  or
  fieldName = "subpath" and result = "http_subpath"
  or
  fieldName = "query_string" and result = "request_query_string"
  or
  fieldName = "matchdict" and result = "route_matchdict"
  or
  fieldName = "matched_route" and result = "route_matched_route"
  or
  fieldName = "params" and result = "request_params"
  or
  fieldName = "GET" and result = "request_query"
  or
  fieldName = "POST" and result = "request_form"
  or
  fieldName = "cookies" and result = "request_cookies"
  or
  fieldName = "headers" and result = "request_headers"
  or
  fieldName = "environ" and result = "wsgi_environ"
  or
  fieldName = "accept_encoding" and result = "request_header_accept_encoding"
  or
  fieldName = "locale_name" and result = "request_locale_name"
  or
  fieldName = "localizer" and result = "request_localizer"
}

/** Maps a request field name to a short context description. */
private string requestFieldContext(string fieldName) {
  fieldName in ["path_info", "path"] and
  result = "raw HTTP request URL path (webob PATH_INFO-derived, attacker-controlled); feeds static_view file selection and resource tree traversal, passing through traversal_path_info URL decoding and the _secure_path '..'/'.'-rejection guard"
  or
  fieldName in ["path_url", "url"] and
  result = "full request URL (attacker-controlled host/path); used for redirect construction and debug logging, not directly for file paths"
  or
  fieldName = "subpath" and
  result = "request.subpath: URL *subpath route star-arg segments (already URL-decoded by routing); static_view uses it as the file-selection path when use_subpath=True"
  or
  fieldName = "query_string" and
  result = "raw HTTP query string; appended to redirect URLs only"
  or
  fieldName = "matchdict" and
  result = "URL route match dictionary: URL path segments bound by route patterns, URL-decoded by routing before entering matchdict"
  or
  fieldName = "matched_route" and
  result = "matched route object for the current URL (pattern, predicates)"
  or
  fieldName = "params" and
  result = "merged query/form parameters (attacker-controlled); request.params.get('_LOCALE_') feeds locale-name negotiation which reaches translation-directory path joining"
  or
  fieldName = "GET" and
  result = "query-string parameters (attacker-controlled)"
  or
  fieldName = "POST" and
  result = "form body parameters (attacker-controlled); CSRF token checks"
  or
  fieldName = "cookies" and
  result = "request cookies (attacker-controlled); cookies.get('_LOCALE_') feeds locale-name negotiation which reaches translation-directory path joining"
  or
  fieldName = "headers" and
  result = "request headers (attacker-controlled); used for CSRF tokens, auth, route predicates and Accept-Encoding negotiation"
  or
  fieldName = "environ" and
  result = "WSGI environ dictionary (raw server-provided request metadata, incl. HTTP_* headers); HTTP_X_VHM_ROOT virtual-root header is read from it by the traverser"
  or
  fieldName = "accept_encoding" and
  result = "Accept-Encoding header (attacker-controlled); only selects among already-existing pre-encoded files in static_view.find_best_match, it does not control the file location"
  or
  fieldName = "locale_name" and
  result = "negotiated locale name (attacker-influenced via _LOCALE_ param/cookie); flows into make_localizer's os.path.join(tdir, lname) translation directory path"
  or
  fieldName = "localizer" and
  result = "reified localizer built from the negotiated locale name (second-order, request-derived)"
}

/** Maps a request-field flow kind to the context for .get() lookup rows. */
private string lookupFlowContext(string objKind) {
  objKind = "route_matchdict" and
  result = "route match value lookup via matchdict.get() (URL path segment bound by a route pattern, URL-decoded by routing, e.g. 'traverse'/'subpath' star-args in the traverser)"
  or
  objKind = "request_params" and
  result = "query/form parameter lookup via request.params.get() (attacker-controlled); observed _LOCALE_ lookup feeds locale negotiation that reaches translation-directory path joining"
  or
  objKind = "request_cookies" and
  result = "cookie value lookup via request.cookies.get() (attacker-controlled); observed _LOCALE_ lookup feeds locale negotiation that reaches translation-directory path joining"
  or
  objKind = "request_headers" and
  result = "header value lookup via request.headers.get() (attacker-controlled)"
  or
  objKind = "request_query" and
  result = "query parameter lookup via request.GET.get() (attacker-controlled; observed JSONP callback use is not path-relevant)"
  or
  objKind = "request_form" and
  result = "form parameter lookup via request.POST.get() (attacker-controlled; CSRF token use)"
  or
  objKind = "wsgi_environ" and
  result = "WSGI environ value lookup via request.environ.get() / local environ.get() (local 'environ' is bound from request.environ or is the WSGI app environ at the observed sites)"
  or
  /* Remaining request-field flow kinds without a dedicated description;
     enumerating them keeps this function single-valued and binds objKind in
     every branch (a bare default branch would leave the parameter unbound
     and make the function return two results for the same input). */
  objKind in [
    "http_path", "request_url", "http_subpath", "request_query_string",
    "route_matched_route", "request_header_accept_encoding",
    "request_locale_name", "request_localizer"
  ] and
  result = "request field .get() lookup (attacker-controlled)"
}

/**
 * The (class, method, parameter) tuples of configuration-facing APIs whose
 * values reach filesystem operations inside this repository. Developer /
 * operator boundary: set by application code at config time, not per
 * request.
 */
private predicate configParamSpec(
  string className, string methodName, string paramName, string specDesc
) {
  className = "static_view" and methodName = "__init__" and paramName = "root_dir" and
  specDesc = "static file root directory; joined with the request-derived path in static_view.get_resource_name (normcase(normpath(join(norm_docroot, path))) or the package resource prefix)"
  or
  className = "ManifestCacheBuster" and methodName = "__init__" and paramName = "manifest_spec" and
  specDesc = "cache-buster manifest asset spec; resolved to manifest_path via abspath_from_asset_spec and opened at static.py:394"
  or
  className = "FSAssetSource" and methodName = "__init__" and paramName = "prefix" and
  specDesc = "filesystem asset override prefix; joined with resource_name in get_path (os.path.join(self.prefix, resource_name)) and opened/existence-checked in FSAssetSource methods"
  or
  className = "PackageAssetSource" and methodName = "__init__" and paramName = "prefix" and
  specDesc = "package asset override prefix; concatenated with resource_name and resolved via pkg_resources resource_* calls"
  or
  className = "DirectoryOverride" and methodName = "__init__" and paramName = "path" and
  specDesc = "asset override path prefix; startswith-matched against incoming resource_name in DirectoryOverride.__call__"
  or
  className = "FileOverride" and methodName = "__init__" and paramName = "path" and
  specDesc = "asset override file path; equality-matched against incoming resource_name in FileOverride.__call__"
  or
  className = "FSAssetDescriptor" and methodName = "__init__" and paramName = "path" and
  specDesc = "absolute filesystem asset path; stored as self.path = os.path.abspath(path), opened in stream() (path.py:436)"
  or
  className = "PkgResourcesAssetDescriptor" and methodName = "__init__" and paramName = "path" and
  specDesc = "package-relative resource path; resolved via self.pkg_resources.resource_filename/resource_stream (path.py:406-412)"
  or
  className = "AssetResolver" and methodName = "resolve" and paramName = "spec" and
  specDesc = "asset specification; absolute specs become FSAssetDescriptor (direct fs path), package specs become PkgResourcesAssetDescriptor (path.py:200-214)"
  or
  className = "StaticURLInfo" and methodName = "add" and paramName = "spec" and
  specDesc = "add_static_view spec; becomes the static_view root_dir which is joined with the request-derived subpath (config/views.py:2253-2260)"
  or
  className = "AssetsConfiguratorMixin" and methodName = "override_asset" and paramName = "to_override" and
  specDesc = "asset spec being overridden; split into package and path, prefix-matched against incoming resource names"
  or
  className = "AssetsConfiguratorMixin" and methodName = "override_asset" and paramName = "override_with" and
  specDesc = "replacement asset spec or absolute path; absolute paths become FSAssetSource prefixes joined with resource_name, package specs become PackageAssetSource prefixes"
  or
  className = "AssetsConfiguratorMixin" and methodName = "_override" and paramName = "path" and
  specDesc = "override path prefix inserted into PackageOverrides (config/assets.py:306-316)"
}

/* ------------------------------------------------------------------ */
/* Source candidate relation                                           */
/* ------------------------------------------------------------------ */

/**
 * Holds for each untrusted-input source candidate. `argIndex` is the real
 * 0-based parameter index (including `self` for methods) for `param` rows,
 * and -1 for field-read/lookup candidates where no positional index applies.
 */
private predicate sourceCandidate(
  string nodeRepr, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string context, AstNode node
) {
  /* Family 1a: WSGI environ parameters of WSGI application entry points.
     The raw untrusted WSGI environ dict - every request-derived value
     (PATH_INFO, HTTP_* headers, query string) originates here. */
  exists(Function f, Parameter p |
    inPyramidPackage(f) and
    f.isMethod() and
    f.getName() in ["__call__", "request_context"] and
    f.getArg(1) = p and
    p.asName().getId() = "environ" and
    node = p.asName() and
    nodeRepr = "parameter 'environ' of WSGI entry " + receiverOf(f) + "." + f.getName() and
    callableName = f.getName() and
    flowKind = "wsgi_environ_param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = 1 and
    context = "raw WSGI environ parameter of a WSGI application entry point (Router/HTTPException __call__ or Router.request_context); the outermost untrusted boundary - PATH_INFO, SCRIPT_NAME and HTTP_* header values come from the HTTP client"
  )
  or
  /* Family 1b: 'request' parameters of request-entry methods
     (__call__/handle_request/invoke_request/invoke_subrequest/__init__
     with a 'request' parameter). The request object carries all
     HTTP-controlled data. */
  exists(Function f, Parameter p, int i |
    inPyramidPackage(f) and
    f.isMethod() and
    f.getName() in ["__call__", "handle_request", "invoke_request", "invoke_subrequest", "__init__"] and
    f.getArg(i) = p and
    p.asName().getId() = "request" and
    node = p.asName() and
    nodeRepr = "parameter 'request' of entry " + receiverOf(f) + "." + f.getName() and
    callableName = f.getName() and
    flowKind = "http_request_param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    context = "request-object parameter of a request-entry method (static_view.__call__, traverser, routes mapper, router handlers, root factory); the request carries path_info/subpath/matchdict/params/headers/environ attacker-controlled values"
  )
  or
  /* Family 1c: view-callable-shaped functions with parameters
     (context, request) at indices 0 and 1 - the Pyramid view calling
     convention; framework-internal view wrappers and helpers. Only the
     'request' parameter is extracted (context is URL-derived too, recorded
     in exploration/detection.json instead). */
  exists(Function f, Parameter pc, Parameter p |
    inPyramidPackage(f) and
    not f.isMethod() and
    f.getArg(0) = pc and
    pc.asName().getId() = "context" and
    f.getArg(1) = p and
    p.asName().getId() = "request" and
    node = p.asName() and
    nodeRepr = "parameter 'request' of view callable " + f.getName() and
    callableName = f.getName() and
    flowKind = "http_request_param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = 1 and
    context = "request-object parameter of a (context, request) view-callable-shaped function (Pyramid view convention, incl. framework view wrappers and derived views); the request carries all attacker-controlled request data"
  )
  or
  /* Family 2: request object field reads, e.g. request.path_info,
     request.subpath, request.matchdict, request.environ. */
  exists(Attribute a, string fieldName, string chain |
    inPyramidPackage(a) and
    requestFieldAttr(a, fieldName) and
    chain = dottedName(a) and
    node = a and
    nodeRepr = "attribute access " + chain and
    callableName = fieldName and
    flowKind = requestFieldFlowKind(fieldName) and
    receiver = chain and
    moduleHint = "webob/pyramid.request" and
    argIndex = -1 and
    context = requestFieldContext(fieldName)
  )
  or
  /* Family 3: .get() lookups on request fields and on local 'environ' /
     'matchdict' variables (bound from request.environ / request.matchdict
     in the same functions - convention-based, hand-verified sites). */
  exists(Call c, string dotted, string objKind |
    inPyramidPackage(c) and
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    (
      exists(Attribute obj, string fieldName |
        obj = c.getFunc().(Attribute).getObject() and
        requestFieldAttr(obj, fieldName) and
        dotted = dottedName(obj) and
        objKind = requestFieldFlowKind(fieldName)
      )
      or
      exists(Name obj |
        obj = c.getFunc().(Attribute).getObject().(Name) and
        obj.getId() = "environ" and
        dotted = "environ" and
        objKind = "wsgi_environ"
      )
      or
      exists(Name obj |
        obj = c.getFunc().(Attribute).getObject().(Name) and
        obj.getId() = "matchdict" and
        dotted = "matchdict" and
        objKind = "route_matchdict"
      )
    ) and
    node = c and
    nodeRepr = "field access " + dotted + ".get" and
    callableName = dotted + ".get" and
    flowKind = objKind + "_get" and
    receiver = dotted and
    moduleHint = "webob/pyramid.request" and
    argIndex = 0 and
    context = lookupFlowContext(objKind)
  )
  or
  /* Family 4: subscripts on request fields and on local 'environ'
     (reads and, in prequest, CLI-controlled environ mutations). */
  exists(Subscript s, string objKind, string objRepr |
    inPyramidPackage(s) and
    (
      exists(Attribute obj, string fieldName |
        obj = s.getObject().(Attribute) and
        requestFieldAttr(obj, fieldName) and
        objKind = requestFieldFlowKind(fieldName) and
        (
          objRepr = dottedName(obj)
          or
          not exists(string d | d = dottedName(obj)) and objRepr = obj.toString()
        )
      )
      or
      exists(Name obj |
        obj = s.getObject().(Name) and
        obj.getId() = "environ" and
        objKind = "wsgi_environ" and
        objRepr = "environ"
      )
    ) and
    node = s and
    nodeRepr = "subscript of " + objRepr and
    callableName = objRepr and
    flowKind = objKind + "_subscript" and
    receiver = objRepr and
    moduleHint = "webob/pyramid.request" and
    argIndex = 0 and
    context = "request/environ subscript access: the index selects the WSGI/field entry (e.g. HTTP_X_VHM_ROOT virtual-root header, PATH_INFO); prequest sites that assign environ[name] = value are CLI-controlled environ mutations (operator boundary)"
  )
  or
  /* Family 5: dynamic attribute reads on the request object. */
  exists(Call c |
    inPyramidPackage(c) and
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = "getattr" and
    c.getPositionalArg(0) instanceof Name and
    c.getPositionalArg(0).(Name).getId() = "request" and
    node = c and
    nodeRepr = "call getattr(request, ...)" and
    callableName = "getattr" and
    flowKind = "request_dynamic_attr" and
    receiver = "request" and
    moduleHint = "builtins" and
    argIndex = 1 and
    context = "dynamic attribute read on the request object (observed: getattr(request, '_LOCALE_', None) in the default locale negotiator; the attribute is settable by views/listeners from request data)"
  )
  or
  /* Family 6a: argv parameters of module-level console-script main()
     entry points. */
  exists(Function f, Parameter p |
    inPyramidPackage(f) and
    not f.isMethod() and
    f.getName() = "main" and
    f.getArg(0) = p and
    p.asName().getId() = "argv" and
    node = p.asName() and
    nodeRepr = "parameter 'argv' of CLI entry main" and
    callableName = f.getName() and
    flowKind = "cli_argv" and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    argIndex = 0 and
    context = "CLI argv parameter of a pyramid console script main() (pserve/pshell/prequest/pviews/proutes/ptweens/pdistreport); operator-controlled boundary, NOT attacker input - config_uri and URL path values flow into plaster config loading and Request.blank"
  )
  or
  /* Family 6b: argv parameters of console-script command classes. */
  exists(Function f, Parameter p |
    inPyramidPackage(f) and
    f.isMethod() and
    f.getName() = "__init__" and
    f.getArg(1) = p and
    p.asName().getId() = "argv" and
    node = p.asName() and
    nodeRepr = "parameter 'argv' of CLI entry " + receiverOf(f) + ".__init__" and
    callableName = f.getName() and
    flowKind = "cli_argv" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = 1 and
    context = "CLI argv parameter of a pyramid console-script command class (PServeCommand/PShellCommand/PRequestCommand/PViewsCommand/PRoutesCommand/PTweensCommand); operator-controlled boundary, NOT attacker input"
  )
  or
  /* Family 6c: argparse result reads, self.args.<name>. */
  exists(Attribute a, Attribute argsAttr, string argName |
    inPyramidPackage(a) and
    a.getName() = argName and
    argsAttr = a.getObject().(Attribute) and
    argsAttr.getName() = "args" and
    argsAttr.getObject() instanceof Name and
    argsAttr.getObject().(Name).getId() = "self" and
    node = a and
    nodeRepr = "attribute access self.args." + argName and
    callableName = "args." + argName and
    flowKind = "cli_argparse_value" and
    receiver = "self.args" and
    moduleHint = moduleHintOf(a) and
    argIndex = -1 and
    context = "argparse-parsed CLI value (config_uri, request path, app name, headers); operator-controlled boundary, NOT attacker input"
  )
  or
  /* Family 7: environment variable reads. */
  exists(Call c, string dotted |
    inPyramidPackage(c) and
    c.getFunc() instanceof Attribute and
    dotted = dottedName(c.getFunc()) and
    dotted in ["os.environ.get", "os.getenv"] and
    node = c and
    nodeRepr = "call " + dotted and
    callableName = dotted and
    flowKind = "env_config" and
    receiver = "os" and
    moduleHint = "os" and
    argIndex = 0 and
    (
      exists(c.getPositionalArg(0)) and
      context = "environment variable read (operator/deployment configuration, NOT attacker-controlled input in standard deployments); observed: PYTHONSTARTUP in pshell, later opened and exec'd"
      or
      not exists(c.getPositionalArg(0)) and
      context = "environment variable read via keyword-controlled variable name (operator/deployment configuration, not attacker-controlled)"
    )
  )
  or
  exists(Subscript s, Attribute environAttr |
    inPyramidPackage(s) and
    environAttr = s.getObject().(Attribute) and
    dottedName(environAttr) = "os.environ" and
    node = s and
    nodeRepr = "subscript of os.environ" and
    callableName = "os.environ" and
    flowKind = "env_config" and
    receiver = "os" and
    moduleHint = "os" and
    argIndex = 0 and
    context = "environment variable subscript read (operator/deployment configuration, NOT attacker-controlled input in standard deployments)"
  )
  or
  /* Family 8: .get() lookups on local 'settings' inside the CLI scripts
     (ini-file settings that influence filesystem paths). */
  exists(Call c |
    inPyramidPackage(c) and
    relPath(c).matches("src/pyramid/scripts/%") and
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    c.getFunc().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Name).getId() = "settings" and
    node = c and
    nodeRepr = "field access settings.get" and
    callableName = "settings.get" and
    flowKind = "config_settings_lookup" and
    receiver = "settings" and
    moduleHint = moduleHintOf(c) and
    argIndex = 0 and
    context = "ini-file settings lookup in a CLI script (operator configuration, NOT attacker input); observed: watch_files entries are resolved via AssetResolver and watched by hupper, open_url"
  )
  or
  /* Family 9a: config/asset-spec parameters of configuration-facing
     classes. Developer/operator boundary (set at config time, not per
     request). */
  exists(Function f, Parameter p, int i, string className, string specDesc |
    inPyramidPackage(f) and
    f.isMethod() and
    f.getEnclosingScope().(Class).getName() = className and
    configParamSpec(className, f.getName(), p.asName().getId(), specDesc) and
    f.getArg(i) = p and
    node = p.asName() and
    nodeRepr = "parameter '" + p.asName().getId() + "' of " + className + "." + f.getName() and
    callableName = f.getName() and
    flowKind = "config_asset_spec_param" and
    receiver = className and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    context = "configuration-facing parameter whose value reaches filesystem operations (developer/operator boundary, set by application code at config time, NOT per-request attacker input); " + specDesc
  )
  or
  /* Family 9b: module-level asset spec resolution function. */
  exists(Function f, Parameter p |
    inPyramidPackage(f) and
    not f.isMethod() and
    f.getName() = "abspath_from_asset_spec" and
    f.getArg(0) = p and
    p.asName().getId() = "spec" and
    node = p.asName() and
    nodeRepr = "parameter 'spec' of abspath_from_asset_spec" and
    callableName = "abspath_from_asset_spec" and
    flowKind = "config_asset_spec_param" and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    argIndex = 0 and
    context = "asset spec resolved via pkg_resources.resource_filename (developer/operator boundary, config-time input, NOT per-request attacker input)"
  )
}

/* ------------------------------------------------------------------ */
/* Select                                                              */
/* ------------------------------------------------------------------ */

from AstNode node, string nodeRepr, string role, string callableName,
     string flowKind, string receiver, string moduleHint, int argIndex,
     string filePath, int line, string context
where
  role = "source_candidate" and
  sourceCandidate(nodeRepr, callableName, flowKind, receiver, moduleHint, argIndex, context, node) and
  inPyramidPackage(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
