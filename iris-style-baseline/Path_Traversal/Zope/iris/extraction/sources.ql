/**
 * @name Zope Pass 1 source candidates (Path Traversal)
 * @description Extracts untrusted-input source candidates for CWE-22/23/36/73
 *   from the Zope 5.2.dev0 framework source (src/): the raw WSGI environ
 *   parameter of publish_module (WSGIPublisher.py:302) and the
 *   stdin/environ parameters of HTTPRequest.__init__ (HTTPRequest.py:306),
 *   the request-object parameters of publish(request) (WSGIPublisher.py:234)
 *   and of WebDAV verb handlers (PUT/MKCOL/LOCK/... with a REQUEST parameter)
 *   plus dav__init, PATH_INFO reads (environ.get / request.get with literal
 *   key), .get()/get_header()/form.get() lookups and subscripts on
 *   request/REQUEST chains and on the raw environ (incl. the get_env =
 *   environ.get alias at HTTPRequest.py:323), request.form / request.cookies
 *   / request.environ attribute reads, path parameters of traversal entries
 *   (BaseRequest.traverse, HTTPRequest.resolve_url,
 *   OFS.Traversable.unrestrictedTraverse/restrictedTraverse,
 *   HTTPRequest.physicalPathFromURL), path/file-relevant parameters of ZMI
 *   manage_* published methods (manage_importObject file,
 *   manage_exportObject id, manage_addFile/manage_addImage id/file,
 *   manage_upload file - ZPublisher marshals request form/query values into
 *   published-method parameters via mapply, WSGIPublisher.py:271), URL
 *   traversal segments becoming names (NullResource.__init__ name from the
 *   last URL segment, DirectoryResource.get name from ++resource++
 *   traversal), multipart upload filenames (FileUpload.filename assignment
 *   HTTPRequest.py:1664, cookId basename extraction OFS/Image.py:1004),
 *   XML-RPC request args (xmlrpc.parse_input HTTPRequest.py:513), CLI argv
 *   reads and console-utility path parameters (zconsole runscript,
 *   copyzopeskel copyskel/copydir/copyin, mkwsgiinstance write_inituser,
 *   serve Command/main - operator boundary), environment variable reads
 *   (operator boundary), and configuration-facing path parameters of
 *   ZCML-registered file resources (ImageFile path, ClassicHTMLFile/DTMLFile
 *   name, PageTemplateFile filename, ResourceFactory/Directory path) and the
 *   App.Extensions external-method lookup functions (getPath/_getPath/
 *   getObject - legacy ZMI boundary with no in-repo request caller).
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/zope-cwe22/extract-sources
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
 * e.g. "src/OFS/ObjectManager.py". The primary source is
 * File.getRelativePath(); on this Windows-created database the stored source
 * location prefix uses backslashes while file paths are forward-slash
 * normalized, so getRelativePath() may yield backslash forms or no result -
 * in that case fall back to capturing the "src/..." suffix from the absolute
 * path (verified forward-slash format in the database string pool).
 */
private string relPath(AstNode n) {
  exists(string p |
    p = n.getLocation().getFile().getRelativePath() and
    result = p.replaceAll("\\", "/")
  )
  or
  not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/").regexpCapture(".*/(src/.+)$", 1)
}

/**
 * Derives a module hint such as "OFS.ObjectManager" from the file path. The
 * ".py" suffix is stripped with an escaped-dot anchored regex.
 */
private string moduleHintOf(AstNode n) {
  result = relPath(n).replaceAll("\\.py$", "").replaceAll("/", ".")
}

/**
 * Restricts candidates to the Zope src/ tree. This structurally excludes the
 * nested Zope-db CodeQL database directory (repo root), repo-root files
 * (setup.py, util.py, reports, CSVs) and the src/Testing/ test-scaffolding
 * package; per the Augur noise policy all tests/ directories, test_*.py
 * files and interfaces.py declaration stubs are excluded as well.
 */
private predicate inZopeSrc(AstNode n) {
  relPath(n).matches("src/%") and
  not relPath(n).matches("%/tests/%") and
  not relPath(n).matches("src/Testing/%") and
  not relPath(n).matches("%/test_%.py") and
  not relPath(n).matches("%/interfaces.py") and
  not relPath(n).matches("%/testing.py")
}

/** Gets the enclosing class name for methods, or "" for plain functions. */
private string receiverOf(Function f) {
  f.isMethod() and result = f.getEnclosingScope().(Class).getName()
  or
  not f.isMethod() and result = ""
}

/**
 * Gets the literal value of a string-literal expression, stripping the
 * source-text quotes and any prefix. Yields no result for non-literals.
 */
private string literalValue(Expr e) {
  e instanceof StringLiteral and
  result = e.(StringLiteral).getText().regexpCapture("^[bBfFrRuU]{0,2}\"(.*)\"$", 1)
  or
  e instanceof StringLiteral and
  result = e.(StringLiteral).getText().regexpCapture("^[bBfFrRuU]{0,2}'(.*)'$", 1)
}

/**
 * Holds for request-object chains: a local name 'request'/'REQUEST' or a
 * one-level attribute chain like 'self.request'. Convention-based, as in
 * prior projects: unrelated local variables named 'request' would shadow.
 */
private predicate requestChain(Expr e, string chain) {
  (
    e instanceof Name and
    e.(Name).getId() in ["request", "REQUEST"] and
    chain = e.(Name).getId()
  )
  or
  (
    e instanceof Attribute and
    e.(Attribute).getName() in ["request", "REQUEST"] and
    e.(Attribute).getObject() instanceof Name and
    chain = e.(Attribute).getObject().(Name).getId() + "." + e.(Attribute).getName()
  )
}

/* ------------------------------------------------------------------ */
/* Source candidate relation                                           */
/* ------------------------------------------------------------------ */

/**
 * Holds for each untrusted-input source candidate. `argIndex` is the real
 * 0-based parameter index (including `self` for methods) for `param` rows,
 * and -1 for field-read/lookup/call-result candidates where no positional
 * index applies (or 0 where the lookup key itself is the tainted selector).
 */
private predicate sourceCandidate(
  string nodeRepr, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string context, AstNode node
) {
  /* Family 1a: raw WSGI environ parameter of the WSGI application entry. */
  exists(Function f, Parameter p |
    inZopeSrc(f) and
    not f.isMethod() and
    f.getName() = "publish_module" and
    f.getArg(0) = p and
    p.asName().getId() = "environ" and
    node = p.asName() and
    nodeRepr = "parameter 'environ' of WSGI entry publish_module" and
    callableName = "publish_module" and
    flowKind = "wsgi_environ_param" and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    argIndex = 0 and
    context = "raw WSGI environ parameter of the Zope WSGI application entry (ZPublisher/WSGIPublisher.py:302); the outermost untrusted boundary - PATH_INFO (re-encoded latin-1 to utf-8 per PEP 3333 at :312-338), QUERY_STRING, HTTP_* headers, CONTENT_LENGTH and the body stream all originate here; the WebDAV source-port GET rewrite at :352 also reads/writes environ['PATH_INFO']"
  )
  or
  /* Family 1b: stdin/environ parameters of the HTTPRequest constructor. */
  exists(Function f, Parameter p, int i, string paramName |
    inZopeSrc(f) and
    f.isMethod() and
    f.getName() = "__init__" and
    f.getEnclosingScope().(Class).getName() = "HTTPRequest" and
    f.getArg(i) = p and
    p.asName().getId() = paramName and
    paramName in ["stdin", "environ"] and
    node = p.asName() and
    nodeRepr = "parameter '" + paramName + "' of HTTPRequest.__init__" and
    callableName = "__init__" and
    receiver = "HTTPRequest" and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    (
      paramName = "environ" and
      flowKind = "wsgi_environ_param" and
      context = "raw environ parameter of HTTPRequest.__init__ (ZPublisher/HTTPRequest.py:306); the request object copies it (self.environ at :322, get_env = environ.get at :323) and scrubs it via sane_environment; all HTTP_* header/PATH_INFO values are attacker-controlled"
      or
      paramName = "stdin" and
      flowKind = "request_body_stdin_param" and
      context = "request body stream parameter of HTTPRequest.__init__ (ZPublisher/HTTPRequest.py:306); consumed by processInputs/ZopeFieldStorage for form parsing, file uploads and XML-RPC bodies (self._file at :518)"
    )
  )
  or
  /* Family 2a: request-object parameter of the publisher entry. */
  exists(Function f, Parameter p |
    inZopeSrc(f) and
    not f.isMethod() and
    f.getName() = "publish" and
    relPath(f).matches("src/ZPublisher/WSGIPublisher.py") and
    f.getArg(0) = p and
    p.asName().getId() = "request" and
    node = p.asName() and
    nodeRepr = "parameter 'request' of publisher entry publish" and
    callableName = "publish" and
    flowKind = "http_request_param" and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    argIndex = 0 and
    context = "request-object parameter of the publish entry (ZPublisher/WSGIPublisher.py:234); drives processInputs, PATH_INFO traversal at :252-255 and mapply(obj, request.args, request, ...) at :271 which marshals request form/query/XML-RPC values into published-method parameters"
  )
  or
  /* Family 2b: REQUEST parameters of WebDAV/HTTP verb handlers. */
  exists(Function f, Parameter p, int i |
    inZopeSrc(f) and
    f.isMethod() and
    f.getName() in ["PUT", "MKCOL", "LOCK", "UNLOCK", "PROPFIND", "PROPPATCH",
                    "COPY", "MOVE", "DELETE", "TRACE", "OPTIONS", "HEAD", "GET"] and
    f.getArg(i) = p and
    p.asName().getId() = "REQUEST" and
    node = p.asName() and
    nodeRepr = "parameter 'REQUEST' of verb handler " + receiverOf(f) + "." + f.getName() and
    callableName = f.getName() and
    flowKind = "http_request_param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    context = "REQUEST parameter of a WebDAV/HTTP verb handler published by ZPublisher (webdav/Resource.py, webdav/NullResource.py, webdav/Collection.py, OFS/Image.py File.PUT:641, OFS/DTMLMethod.py PUT:371); the request carries BODY/BODYFILE (HTTPRequest.py:1331/:1339), headers, form, cookies and environ - the PUT body path reads request data that is stored into ZODB objects"
  )
  or
  /* Family 2c: request parameter of the WebDAV init hook. */
  exists(Function f, Parameter p |
    inZopeSrc(f) and
    f.isMethod() and
    f.getName() = "dav__init" and
    f.getArg(1) = p and
    p.asName().getId() = "request" and
    node = p.asName() and
    nodeRepr = "parameter 'request' of " + receiverOf(f) + ".dav__init" and
    callableName = "dav__init" and
    flowKind = "http_request_param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = 1 and
    context = "request-object parameter of the WebDAV dispatch init hook (webdav/Resource.py:88, webdav/Collection.py:48); every WebDAV verb handler starts with dav__init(REQUEST, RESPONSE)"
  )
  or
  /* Family 3a: .get() lookups on request/REQUEST chains with a literal key.
     The key-to-flowKind mapping is inlined here (with an explicit negative
     default branch) because a helper function default branch cannot bind its
     parameter: 'key' is bound by the literalValue conjunct above, so the
     negated membership test is legal at this position. */
  exists(Call c, string chain, string key |
    inZopeSrc(c) and
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    requestChain(c.getFunc().(Attribute).getObject(), chain) and
    key = literalValue(c.getPositionalArg(0)) and
    node = c and
    nodeRepr = "field access " + chain + ".get" and
    callableName = chain + ".get" and
    (
      key = "PATH_INFO" and flowKind = "http_path"
      or
      key = "BODY" and flowKind = "request_body"
      or
      key = "BODYFILE" and flowKind = "request_bodyfile"
      or
      key = "URL" and flowKind = "request_url"
      or
      key = "REQUEST_METHOD" and flowKind = "http_method"
      or
      not key in ["PATH_INFO", "BODY", "BODYFILE", "URL", "REQUEST_METHOD"] and
      flowKind = "request_lookup_get"
    ) and
    receiver = chain and
    moduleHint = "ZPublisher.HTTPRequest" and
    argIndex = 0 and
    context = "request-object .get('" + key + "') lookup (HTTPRequest.get at ZPublisher/HTTPRequest.py:1250 merges other/URL/env/common/lazy/form/cookies; the value is attacker-controlled when the key is form/cookie/header-derived; observed: request.get('PATH_INFO') in WSGIPublisher.py:252 and ZPublisher/utils.py:52, REQUEST.get('CONTENT_LENGTH')/('BODY') in webdav PUT)"
  )
  or
  /* Family 3b: .get() lookups on request/REQUEST chains with a dynamic key. */
  exists(Call c, string chain |
    inZopeSrc(c) and
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    requestChain(c.getFunc().(Attribute).getObject(), chain) and
    not exists(string k | k = literalValue(c.getPositionalArg(0))) and
    node = c and
    nodeRepr = "field access " + chain + ".get" and
    callableName = chain + ".get" and
    flowKind = "request_lookup_get" and
    receiver = chain and
    moduleHint = "ZPublisher.HTTPRequest" and
    argIndex = 0 and
    context = "request-object .get() lookup with a dynamic key (HTTPRequest.get at ZPublisher/HTTPRequest.py:1250 merges other/URL/env/common/lazy/form/cookies namespaces; the key or the value is attacker-controlled when form/cookie/header-derived)"
  )
  or
  /* Family 3c: header reads via get_header/getHeader on request chains. */
  exists(Call c, string chain, string mname |
    inZopeSrc(c) and
    c.getFunc() instanceof Attribute and
    mname = c.getFunc().(Attribute).getName() and
    mname in ["get_header", "getHeader"] and
    requestChain(c.getFunc().(Attribute).getObject(), chain) and
    node = c and
    nodeRepr = "field access " + chain + ".get_header" and
    callableName = chain + "." + mname and
    flowKind = "request_header" and
    receiver = chain and
    moduleHint = "ZPublisher.HTTPRequest" and
    argIndex = 0 and
    context = "HTTP header read via REQUEST.get_header (HTTPRequest.getHeader at ZPublisher/HTTPRequest.py:1231, get_header alias at :1248; reads environ[HTTP_*], attacker-controlled); observed: webdav If/Depth/Timeout/Lock-Token/content-type headers, OFS/Image.py:152/:184/:190 If-Modified-Since/Range/Request-Range/If-Range, OFS/EtagSupport.py:91"
  )
  or
  /* Family 3d: .get() lookups on request.form. */
  exists(Call c, string chain, Attribute formAttr |
    inZopeSrc(c) and
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    formAttr = c.getFunc().(Attribute).getObject().(Attribute) and
    formAttr.getName() = "form" and
    requestChain(formAttr.getObject(), chain) and
    node = c and
    nodeRepr = "field access " + chain + ".form.get" and
    callableName = chain + ".form.get" and
    flowKind = "request_form_get" and
    receiver = chain + ".form" and
    moduleHint = "ZPublisher.HTTPRequest" and
    argIndex = 0 and
    context = "form parameter lookup via REQUEST.form.get() (attacker-controlled form/URL query values; observed: OFS/PropertyManager.py:303 REQUEST.form.get(name, []), OFS/PropertySheets.py:346-style property editing)"
  )
  or
  /* Family 3e: .get() lookups on the raw environ (local variable or
     request.environ chain). reqName is introduced by a nested exists in the
     second branch only, so both or-branches bind the same outer variables. */
  exists(Call c, string objRepr, Attribute funcAttr |
    inZopeSrc(c) and
    funcAttr = c.getFunc().(Attribute) and
    funcAttr.getName() = "get" and
    (
      (
        funcAttr.getObject() instanceof Name and
        funcAttr.getObject().(Name).getId() = "environ" and
        objRepr = "environ"
      )
      or
      exists(string reqName |
        funcAttr.getObject() instanceof Attribute and
        funcAttr.getObject().(Attribute).getName() = "environ" and
        requestChain(funcAttr.getObject().(Attribute).getObject(), reqName) and
        objRepr = reqName + ".environ"
      )
    ) and
    node = c and
    nodeRepr = "field access " + objRepr + ".get" and
    callableName = objRepr + ".get" and
    flowKind = "wsgi_environ_get" and
    receiver = objRepr and
    moduleHint = "ZPublisher.HTTPRequest" and
    argIndex = 0 and
    context = "raw WSGI environ lookup (local 'environ' is the request environ or the WSGI app environ at the observed sites - HTTPRequest.__init__/processInputs and WSGIPublisher.publish_module:312 environ.get('PATH_INFO')); server-provided metadata and HTTP_* header values, attacker-controlled where header-derived"
  )
  or
  /* Family 3f: the get_env = environ.get alias inside HTTPRequest. */
  exists(Call c |
    inZopeSrc(c) and
    relPath(c).matches("src/ZPublisher/HTTPRequest.py") and
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = "get_env" and
    node = c and
    nodeRepr = "call get_env (environ.get alias)" and
    callableName = "get_env" and
    flowKind = "wsgi_environ_get" and
    receiver = "environ" and
    moduleHint = "ZPublisher.HTTPRequest" and
    argIndex = 0 and
    context = "raw WSGI environ lookup through the local alias get_env = environ.get (HTTPRequest.py:323); observed keys: SERVER_URL, HTTP_COOKIE (:436), HTTPS, SERVER_PORT, REQUEST_SCHEME, wsgi.url_scheme (HTTPRequest.__init__ :360-405)"
  )
  or
  /* Family 4a: subscripts on request/REQUEST chains. */
  exists(Subscript s, string chain |
    inZopeSrc(s) and
    requestChain(s.getObject(), chain) and
    node = s and
    nodeRepr = "subscript of " + chain and
    callableName = chain and
    flowKind = "request_subscript" and
    receiver = chain and
    moduleHint = "ZPublisher.HTTPRequest" and
    argIndex = 0 and
    context = "request-object subscript access (HTTPRequest.__getitem__ at ZPublisher/HTTPRequest.py:1381; same merged namespaces as get()); observed keys: REQUEST['BODYFILE'] and REQUEST['BODY'] in webdav PUT (webdav/NullResource.py:160/:166, OFS/DTMLMethod.py:376), REQUEST['URL'] (webdav/NullResource.py:380), REQUEST['id'] (ObjectManager.manage_hasId:725)"
  )
  or
  /* Family 4b: subscripts on the local raw environ. */
  exists(Subscript s |
    inZopeSrc(s) and
    s.getObject() instanceof Name and
    s.getObject().(Name).getId() = "environ" and
    node = s and
    nodeRepr = "subscript of environ" and
    callableName = "environ" and
    flowKind = "wsgi_environ_subscript" and
    receiver = "environ" and
    moduleHint = "ZPublisher.HTTPRequest" and
    argIndex = 0 and
    context = "raw WSGI environ subscript access; observed keys: HTTP_AUTHORIZATION (HTTPRequest.py:316), HTTP_HOST (:388), HTTP_X_FORWARDED_FOR (:337), SERVER_NAME/SERVER_PORT (:404-405), PATH_INFO writes in WSGIPublisher.publish_module (:338/:352 - request-derived values assigned back into environ)"
  )
  or
  /* Family 4c: attribute reads of request.form / request.cookies /
     request.environ. */
  exists(Attribute a, string chain, string fieldName |
    inZopeSrc(a) and
    fieldName = a.getName() and
    fieldName in ["form", "cookies", "environ"] and
    requestChain(a.getObject(), chain) and
    node = a and
    nodeRepr = "attribute access " + chain + "." + fieldName and
    callableName = fieldName and
    receiver = chain and
    moduleHint = "ZPublisher.HTTPRequest" and
    argIndex = -1 and
    (
      fieldName = "form" and
      flowKind = "request_form" and
      context = "request.form attribute read - the parsed request form (attacker-controlled query/form values; observed: OFS/Cache.py:518 props = REQUEST.form whose 'associate_<path>' keys drive parent.restrictedTraverse(path) at :522, OFS/PropertyManager.py:327 props = REQUEST.form)"
      or
      fieldName = "cookies" and
      flowKind = "request_cookies" and
      context = "request.cookies attribute read - parsed cookies (attacker-controlled; HTTP_COOKIE parsed at ZPublisher/HTTPRequest.py:436-449 with unquote at :1745)"
      or
      fieldName = "environ" and
      flowKind = "wsgi_environ" and
      context = "request.environ attribute read - the raw WSGI environ (attacker-controlled HTTP_* entries; fed to _p_jar.setDebugInfo at WSGIPublisher.py:262)"
    )
  )
  or
  /* Family 5: path parameters of traversal entry points. */
  exists(Function f, Parameter p, int i, string className, string fnName, string paramName |
    inZopeSrc(f) and
    f.isMethod() and
    f.getName() = fnName and
    f.getEnclosingScope().(Class).getName() = className and
    f.getArg(i) = p and
    p.asName().getId() = paramName and
    traversalParamSpec(className, fnName, paramName) and
    node = p.asName() and
    nodeRepr = "parameter '" + paramName + "' of " + className + "." + fnName and
    callableName = fnName and
    flowKind = "route_path_param" and
    receiver = className and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    context = "path parameter of a traversal entry point (the Zope route-variable equivalent); BaseRequest.traverse is called with request.get('PATH_INFO') at WSGIPublisher.py:255 and pops URL segments to traverse the OBJECT TREE (ZODB, not the filesystem); resolve_url/physicalPathFromURL convert URLs into traversal paths (unquote at HTTPRequest.py:271); restrictedTraverse is observed called with a REQUEST.form-derived path at OFS/Cache.py:522 - traversal names reach the request-to-filesystem bridges (NullResource names, ++resource++ segments)"
  )
  or
  /* Family 6a: path/file-relevant parameters of ZMI manage_* methods. */
  exists(Function f, Parameter p, int i, string pName, string display |
    inZopeSrc(f) and
    /* regexpMatch instead of matches("manage_%"): the glob '_' is a
       single-character wildcard that would also match e.g. 'manager...' */
    f.getName().regexpMatch("manage_.*") and
    f.getArg(i) = p and
    p.asName().getId() = pName and
    pName in ["id", "file", "filename", "name", "path", "filepath"] and
    (
      (f.isMethod() and display = receiverOf(f) + "." + f.getName())
      or
      (not f.isMethod() and display = f.getName())
    ) and
    node = p.asName() and
    nodeRepr = "parameter '" + pName + "' of ZMI method " + display and
    callableName = f.getName() and
    flowKind = "zmi_form_param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    context = "path/file-relevant parameter of a ZMI manage_* published method; ZPublisher marshals request form/query values directly into published-method parameters (HTTPRequest form processing + mapply at WSGIPublisher.py:271), so this parameter is request-controlled (permission-gated, e.g. import_export_objects on ObjectManager.py:588); observed flows: manage_importObject 'file' -> os.path.join(import dir) + connection.importFile (ObjectManager.py:636-679), manage_exportObject 'id' -> os.path.join(CONFIG.clienthome, '{id}.zexp') + open (ObjectManager.py:621-622), manage_addFile/manage_addImage 'id'/'file' -> cookId multipart-filename basename (OFS/Image.py:76/:753)"
  )
  or
  /* Family 6b: URL traversal segments that become object/resource names. */
  exists(Function f, Parameter p, int i, string className, string fnName, string paramName |
    inZopeSrc(f) and
    f.isMethod() and
    f.getName() = fnName and
    f.getEnclosingScope().(Class).getName() = className and
    f.getArg(i) = p and
    p.asName().getId() = paramName and
    urlSegmentParamSpec(className, fnName, paramName, i) and
    node = p.asName() and
    nodeRepr = "parameter '" + paramName + "' of " + className + "." + fnName and
    callableName = fnName and
    flowKind = "url_traversal_segment" and
    receiver = className and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    context = "URL path segment entering as a name: NullResource is constructed with the not-found URL segment (ObjectManager.py:739 NullResource(self, key, request)) and its name selects the object created by WebDAV PUT/MKCOL (webdav/NullResource.py:125); DirectoryResource.get(name) receives the next URL segment under ++resource++<dirname>/ traversal and joins it onto the registered filesystem directory path (Products/Five/browser/resource.py:155 os.path.join(path, name), existence-checked at :156-157) - THE request-to-filesystem bridge of the resource subsystem"
  )
  or
  /* Family 7a: multipart upload filename attribute reads. */
  exists(Attribute a, string objName |
    inZopeSrc(a) and
    a.getName() = "filename" and
    a.getObject() instanceof Name and
    objName = a.getObject().(Name).getId() and
    (
      (
        relPath(a).matches("src/ZPublisher/HTTPRequest.py") and
        objName in ["aFieldStorage", "item"]
      )
      or
      (
        relPath(a).matches("src/OFS/Image.py") and
        objName = "file"
      )
    ) and
    node = a and
    nodeRepr = "attribute access " + objName + ".filename" and
    callableName = "filename" and
    flowKind = "multipart_filename" and
    receiver = objName and
    moduleHint = "cgi.FieldStorage" and
    argIndex = -1 and
    context = "multipart upload filename from the cgi FieldStorage (client-controlled, fully path-shaped); FileUpload.filename is assigned from aFieldStorage.filename (HTTPRequest.py:1664, FileUpload wrapper :1653-1697) and processInputs wraps file+filename items into FileUpload (:536-537); cookId derives the Zope object id from file.filename with basename extraction over '/', '\\' and ':' (OFS/Image.py:1002-1010) - the id feeds _setObject (ZODB) and later the manage_exportObject clienthome path join"
  )
  or
  /* Family 7b: XML-RPC request arguments. */
  exists(Call c |
    inZopeSrc(c) and
    c.getFunc() instanceof Attribute and
    dottedName(c.getFunc()) = "xmlrpc.parse_input" and
    node = c and
    nodeRepr = "call xmlrpc.parse_input" and
    callableName = "xmlrpc.parse_input" and
    flowKind = "xmlrpc_request_args" and
    receiver = "xmlrpc" and
    moduleHint = "ZPublisher.xmlrpc" and
    argIndex = -1 and
    context = "XML-RPC request arguments parsed from the text/xml POST body (HTTPRequest.py:513 meth, self.args = xmlrpc.parse_input(fs.value)); request.args is then marshalled into published-method parameters by mapply (WSGIPublisher.py:271), making published-method parameters request-controlled for XML-RPC clients"
  )
  or
  /* Family 8a: sys.argv subscript reads in the console utilities. */
  exists(Subscript s, Attribute argvAttr |
    inZopeSrc(s) and
    argvAttr = s.getObject().(Attribute) and
    argvAttr.getName() = "argv" and
    argvAttr.getObject() instanceof Name and
    argvAttr.getObject().(Name).getId() = "sys" and
    node = s and
    nodeRepr = "subscript of sys.argv" and
    callableName = "sys.argv" and
    flowKind = "cli_argv" and
    receiver = "sys" and
    moduleHint = "sys" and
    argIndex = -1 and
    context = "CLI argv subscript read (operator-controlled boundary, NOT attacker input); observed: copyzopeskel.py:72 sys.argv[1:] -> copyskel(sourcedir, targetdir), mkwsgiinstance.py:42/:50, serve.py:249 main(argv=sys.argv)"
  )
  or
  /* Family 8b: path parameters of the console utilities. */
  exists(Function f, Parameter p, int i, string fnName, string pName, string pathFrag |
    inZopeSrc(f) and
    cliParamSpec(fnName, pName, i, pathFrag) and
    f.getName() = fnName and
    relPath(f).matches(pathFrag) and
    f.getArg(i) = p and
    p.asName().getId() = pName and
    node = p.asName() and
    nodeRepr = "parameter '" + pName + "' of CLI entry " + fnName and
    callableName = fnName and
    flowKind = "cli_argv_param" and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    context = "CLI path parameter (operator-controlled boundary, NOT attacker input); observed flows: zconsole runscript script_name -> open + exec (zconsole.py:20-22); copyzopeskel copyskel/copydir/copyin sourcedir/targetdir/src/dst -> os.makedirs/shutil.copyfile/open (copyzopeskel.py:172/:214/:221/:226); mkwsgiinstance write_inituser fn -> open(fn, 'wb') (:191); serve pid_filename -> open (:236)"
  )
  or
  /* Family 9a: environment variable reads. */
  exists(Call c, string dotted |
    inZopeSrc(c) and
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
    context = "environment variable read (operator/deployment configuration, NOT attacker-controlled input in standard deployments); observed: ZOPE_DTML_REQUEST_AUTOQUOTE (HTTPRequest.py:78), DONT_GZIP_MAJOR_MIME_TYPES (HTTPResponse.py:92)"
  )
  or
  exists(Subscript s, Attribute environAttr |
    inZopeSrc(s) and
    environAttr = s.getObject().(Attribute) and
    dottedName(environAttr) = "os.environ" and
    node = s and
    nodeRepr = "subscript of os.environ" and
    callableName = "os.environ" and
    flowKind = "env_config" and
    receiver = "os" and
    moduleHint = "os" and
    argIndex = 0 and
    context = "environment variable subscript read (operator/deployment configuration, NOT attacker-controlled input); observed: INSTANCE_HOME/CLIENT_HOME bootstrap paths (App/FindHomes.py:18/:30)"
  )
  or
  /* Family 10: configuration-facing path parameters of file-resource
     constructors and the App.Extensions lookup functions. */
  exists(Function f, Parameter p, int i, string className, string fnName, string paramName, string specDesc, string display |
    inZopeSrc(f) and
    f.getName() = fnName and
    f.getArg(i) = p and
    p.asName().getId() = paramName and
    configParamSpec(className, fnName, paramName, specDesc) and
    (
      (
        className = "" and
        not f.isMethod() and
        display = fnName
      )
      or
      (
        className != "" and
        f.isMethod() and
        f.getEnclosingScope().(Class).getName() = className and
        display = className + "." + fnName
      )
    ) and
    node = p.asName() and
    nodeRepr = "parameter '" + paramName + "' of " + display and
    callableName = fnName and
    flowKind = "config_path_param" and
    receiver = className and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    context = "configuration-facing path parameter whose value reaches filesystem operations (developer/operator boundary, set at ZCML registration/config time, NOT per-request attacker input); " + specDesc
  )
}

/**
 * The (class, method, parameter) tuples of traversal entry points whose
 * path parameter carries URL-derived traversal names.
 */
private predicate traversalParamSpec(string className, string methodName, string paramName) {
  className = "BaseRequest" and methodName = "traverse" and paramName = "path"
  or
  className = "HTTPRequest" and methodName = "resolve_url" and paramName = "url"
  or
  className = "HTTPRequest" and methodName = "physicalPathFromURL" and paramName = "URL"
  or
  className = "Traversable" and methodName = "unrestrictedTraverse" and paramName = "path"
  or
  className = "Traversable" and methodName = "restrictedTraverse" and paramName = "path"
}

/**
 * The (class, method, parameter, index) tuples of URL-segment name
 * parameters: the NullResource name (last URL segment) and the
 * DirectoryResource.get name (++resource++ traversal segment).
 */
private predicate urlSegmentParamSpec(
  string className, string methodName, string paramName, int index
) {
  className = "NullResource" and methodName = "__init__" and paramName = "name" and index = 2
  or
  className = "LockNullResource" and methodName = "__init__" and paramName = "name" and index = 1
  or
  className = "DirectoryResource" and methodName = "get" and paramName = "name" and index = 1
}

/**
 * The (function, parameter, index, path) tuples of console-utility path
 * parameters (CLI operator boundary).
 */
private predicate cliParamSpec(
  string fnName, string paramName, int index, string pathFrag
) {
  fnName = "runscript" and paramName = "zopeconf" and index = 0 and
  pathFrag = "src/Zope2/utilities/zconsole.py"
  or
  fnName = "runscript" and paramName = "script_name" and index = 1 and
  pathFrag = "src/Zope2/utilities/zconsole.py"
  or
  fnName = "copyskel" and paramName = "sourcedir" and index = 0 and
  pathFrag = "src/Zope2/utilities/copyzopeskel.py"
  or
  fnName = "copyskel" and paramName = "targetdir" and index = 1 and
  pathFrag = "src/Zope2/utilities/copyzopeskel.py"
  or
  fnName = "copydir" and paramName = "sourcedir" and index = 0 and
  pathFrag = "src/Zope2/utilities/copyzopeskel.py"
  or
  fnName = "copydir" and paramName = "targetdir" and index = 3 and
  pathFrag = "src/Zope2/utilities/copyzopeskel.py"
  or
  fnName = "copyin" and paramName = "src" and index = 0 and
  pathFrag = "src/Zope2/utilities/copyzopeskel.py"
  or
  fnName = "copyin" and paramName = "dst" and index = 1 and
  pathFrag = "src/Zope2/utilities/copyzopeskel.py"
  or
  fnName = "write_inituser" and paramName = "fn" and index = 0 and
  pathFrag = "src/Zope2/utilities/mkwsgiinstance.py"
  or
  fnName = "__init__" and paramName = "argv" and index = 1 and
  pathFrag = "src/Zope2/Startup/serve.py"
  or
  fnName = "main" and paramName = "argv" and index = 0 and
  pathFrag = "src/Zope2/Startup/serve.py"
  or
  fnName = "main" and paramName = "args" and index = 0 and
  pathFrag = "src/Zope2/utilities/zconsole.py"
}

/**
 * The (class-or-empty, function, parameter) tuples of configuration-facing
 * APIs whose values reach filesystem operations inside this repository.
 * Developer/operator boundary: set by ZCML registration or instance
 * configuration, not per request. App.Extensions entries are the legacy
 * External Method lookup chain (its ZMI caller Products.ExternalMethod is a
 * separate distribution, not in this repo).
 */
private predicate configParamSpec(
  string className, string fnName, string paramName, string specDesc
) {
  className = "ImageFile" and fnName = "__init__" and paramName = "path" and
  specDesc = "registered image file path; joined with _prefix/PREFIX at ImageFile.py:57 (isabs branch at :52), opened at :72, stat'd at :84 and served per request via filestream_iterator at :121"
  or
  className = "ImageFile" and fnName = "__init__" and paramName = "_prefix" and
  specDesc = "base directory for relative image paths (package_home or the realpath'd Zope2 prefix, ImageFile.py:32-33/:55)"
  or
  className = "ClassicHTMLFile" and fnName = "__init__" and paramName = "name" and
  specDesc = "DTML file name; joined as os.path.join(_prefix, name + '.dtml') at special_dtml.py:69, stat'd per request in debug mode at :78 and read by the external DocumentTemplate.HTMLFile"
  or
  className = "ClassicHTMLFile" and fnName = "__init__" and paramName = "_prefix" and
  specDesc = "base directory for the DTML file name (PREFIX realpath or package_home, special_dtml.py:64-68)"
  or
  className = "DTMLFile" and fnName = "__init__" and paramName = "name" and
  specDesc = "DTML file name; DTMLFile.__init__ delegates to ClassicHTMLFile.__init__ (special_dtml.py:131-134) reaching the same join/stat/read chain"
  or
  className = "DTMLFile" and fnName = "__init__" and paramName = "_prefix" and
  specDesc = "base directory for the DTML file name (special_dtml.py:131-134)"
  or
  className = "PageTemplateFile" and fnName = "__init__" and paramName = "filename" and
  specDesc = "page template file name; joined with _prefix/package_home at PageTemplateFile.py:95/:97 ('.zpt' appended at :100), getmtime'd at :160 and opened at :194 on _cook_check (request-time in debug mode)"
  or
  className = "ResourceFactory" and fnName = "__init__" and paramName = "path" and
  specDesc = "registered resource directory path (ZCML browser:resource / five:resource); becomes Directory.path and is joined with URL traversal segments in DirectoryResource.get (resource.py:127/:155)"
  or
  className = "ResourceFactory" and fnName = "__init__" and paramName = "name" and
  specDesc = "registered resource name (resource.py:83-87)"
  or
  className = "Directory" and fnName = "__init__" and paramName = "path" and
  specDesc = "resource directory path consumed by DirectoryResource.get's os.path.join(path, name) at resource.py:155"
  or
  className = "" and fnName = "getPath" and paramName = "prefix" and
  specDesc = "App.Extensions.getPath prefix (Extensions.py:65); joins home/prefix/name and existence-checks at :61, the external-method lookup boundary"
  or
  className = "" and fnName = "getPath" and paramName = "name" and
  specDesc = "App.Extensions.getPath name (Extensions.py:65); rejected if it contains a directory component (os.path.split guard at :92-95)"
  or
  className = "" and fnName = "_getPath" and paramName = "prefix" and
  specDesc = "App.Extensions._getPath prefix (Extensions.py:44); joined at :46/:50 with paranoia ValueError checks at :47-54"
  or
  className = "" and fnName = "_getPath" and paramName = "name" and
  specDesc = "App.Extensions._getPath name (Extensions.py:44); joined at :50, existence-checked at :61"
  or
  className = "" and fnName = "getObject" and paramName = "module" and
  specDesc = "App.Extensions.getObject module name (Extensions.py:153); historically supplied via the External Method ZMI form (Products.ExternalMethod, external distribution); resolved through getPath('Extensions', module) at :170 and opened + exec'd at :178/:184 - no in-repo request-boundary caller exists in Zope 5"
  or
  className = "" and fnName = "getObject" and paramName = "name" and
  specDesc = "App.Extensions.getObject object name (Extensions.py:153); looked up in the exec'd module_dict at :193"
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
  inZopeSrc(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
