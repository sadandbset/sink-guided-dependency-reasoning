/*
 * Augur generated source library - Pass 1 (Path Traversal), Zope 5.2.dev0.
 * Machine-generated from iris/labels/labels.json (pass_id = 1, pass key
 * "path_traversal"; labeling run zope-iris-pass1-step3-20261024, model glm-5.3,
 * reviewed 2026-10-24).  Do not edit by hand: regenerate from labels instead.
 *
 * Every rule below corresponds one-to-one to reviewed label entries (label ids
 * given per rule; see report/query_generation_notes.md for the full mapping and
 * source evidence).  The 45 label rows with role "none"
 * (env_config p1-src-001..004, 007..014; cli_argv p1-src-019..023;
 * cli_argv_param p1-src-245..256; config_path_param p1-src-228..243) are
 * operator/developer boundaries and are deliberately NOT modeled here.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {

  /** Holds if `source` is a Pass 1 (path traversal) taint source. */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and isPathTraversalSource(source)
  }

  /**
   * Reviewed label entries modeled here (270 of 315 source rows):
   *  - wsgi_boundary_param            p1-src-005, 006, 244
   *  - published_entry_param          p1-src-188
   *  - webdav_verb_request_param      p1-src-024, 025, 257-286
   *  - zmi_form_param                 p1-src-298-315
   *  - route_path_param               p1-src-287-291
   *  - url_traversal_segment          p1-src-292-294
   *  - request_get_lookup             p1-src-026-058, 083-085, 176-187, 189
   *  - request_subscript              p1-src-059-080, 086-169
   *  - request_form                   p1-src-081, 082, 170-174
   *  - request_environ_attr           p1-src-015-018
   *  - request_header                 p1-src-190-227
   *  - multipart_filename             p1-src-295-297
   *  - xmlrpc_args                    p1-src-175
   */
  private predicate isPathTraversalSource(DataFlow::Node source) {
    isWsgiBoundaryParameter(source) or
    isPublishedEntryRequestParameter(source) or
    isWebDavVerbRequestParameter(source) or
    isZmiFormParameter(source) or
    isTraversalPathParameter(source) or
    isUrlSegmentParameter(source) or
    isRequestGetLookupValue(source) or
    isRequestSubscriptValue(source) or
    isRequestFormFieldValue(source) or
    isRequestEnvironmentValue(source) or
    isRequestHeaderValue(source) or
    isMultipartFilenameValue(source) or
    isXmlRpcArgumentsValue(source)
  }

  /**
   * Outermost untrusted boundaries: the raw WSGI environ / body stream.
   * Labels p1-src-005 (HTTPRequest.__init__ stdin), p1-src-006
   * (HTTPRequest.__init__ environ), p1-src-244 (publish_module environ).
   * Evidence: ZPublisher/HTTPRequest.py:306, WSGIPublisher.py:302.
   */
  private predicate isWsgiBoundaryParameter(DataFlow::Node source) {
    exists(Parameter p, Function f |
      source.(DataFlow::ParameterNode).getParameter() = p and
      f.getAnArg() = p and
      (
        (
          f.getName() = "__init__" and
          f.getLocation().getFile().getBaseName() = "HTTPRequest.py" and
          p.getName() in ["stdin", "environ"]
        )
        or
        (
          f.getName() = "publish_module" and
          f.getLocation().getFile().getBaseName() = "WSGIPublisher.py" and
          p.getName() = "environ"
        )
      )
    )
  }

  /**
   * The request-object parameter of the ZPublisher publish entry.
   * Label p1-src-188.  Evidence: ZPublisher/WSGIPublisher.py:234
   * def publish(request, module_info) - drives processInputs, PATH_INFO
   * traversal at :252-255 and mapply at :271.
   */
  private predicate isPublishedEntryRequestParameter(DataFlow::Node source) {
    exists(Parameter p, Function f |
      source.(DataFlow::ParameterNode).getParameter() = p and
      f.getAnArg() = p and
      f.getName() = "publish" and
      f.getLocation().getFile().getBaseName() = "WSGIPublisher.py" and
      p.getName() = "request"
    )
  }

  /**
   * REQUEST/request parameter of WebDAV verb handlers and dav__init hooks.
   * Labels p1-src-024, 025, 257-286.  The file-name set deliberately excludes
   * webdav/interfaces.py (interface stubs, not labeled and not executable).
   * Evidence: webdav/Resource.py:203-665, webdav/NullResource.py:90-473,
   * webdav/Collection.py:63/76/85, OFS/Application.py:158/163,
   * OFS/DTMLMethod.py:371, OFS/Image.py:641, App/ImageFile.py:124,
   * Products/PageTemplates/ZopePageTemplate.py:348.
   */
  private predicate isWebDavVerbRequestParameter(DataFlow::Node source) {
    exists(Parameter p, Function f |
      source.(DataFlow::ParameterNode).getParameter() = p and
      f.getAnArg() = p and
      f.getName() in [
          "HEAD", "PUT", "OPTIONS", "TRACE", "DELETE", "PROPFIND",
          "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "dav__init"
        ] and
      p.getName() in ["REQUEST", "request"] and
      f.getLocation().getFile().getBaseName() in [
          "Resource.py", "NullResource.py", "Collection.py", "Application.py",
          "DTMLMethod.py", "Image.py", "ZopePageTemplate.py", "ImageFile.py"
        ]
    )
  }

  /**
   * id/file parameters of ZMI manage_* published methods, marshalled from
   * request form values by mapply (WSGIPublisher.py:271); permission-gated
   * (e.g. import_export_objects, ObjectManager.py:588) but HTTP-reachable.
   * Labels p1-src-298-315.  File set excludes OFS/interfaces.py stubs.
   * Evidence: OFS/ObjectManager.py:636 (manage_importObject file),
   * OFS/ObjectManager.py:589 (manage_exportObject id), OFS/Image.py:58/:734.
   */
  private predicate isZmiFormParameter(DataFlow::Node source) {
    exists(Parameter p, Function f |
      source.(DataFlow::ParameterNode).getParameter() = p and
      f.getAnArg() = p and
      f.getName() in [
          "manage_addFolder", "manage_addFile", "manage_addImage",
          "manage_addOrderedFolder", "manage_addVirtualHostMonster",
          "manage_addPageTemplate", "manage_renameObject", "manage_clone",
          "manage_upload", "manage_exportObject", "manage_importObject",
          "manage_addProperty", "manage_addPropertySheet"
        ] and
      p.getName() in ["id", "file"] and
      f.getLocation().getFile().getBaseName() in [
          "Folder.py", "Image.py", "OrderedFolder.py", "VirtualHostMonster.py",
          "ZopePageTemplate.py", "CopySupport.py", "DTMLMethod.py",
          "ObjectManager.py", "OrderSupport.py", "PropertyManager.py",
          "PropertySheets.py"
        ]
    )
  }

  /**
   * URL-derived path parameters of object-tree traversal entries (labels
   * p1-src-287-291, classification candidate: they traverse the ZODB object
   * tree, not the filesystem; kept because traversal segments feed the
   * request-to-filesystem bridges).  File set excludes OFS/interfaces.py.
   * Evidence: ZPublisher/BaseRequest.py:353 traverse, called with
   * request.get('PATH_INFO') at WSGIPublisher.py:255;
   * ZPublisher/HTTPRequest.py:1161 resolve_url, :253 physicalPathFromURL;
   * OFS/Traversable.py:152/:362 restricted/unrestrictedTraverse
   * (request-driven call observed at OFS/Cache.py:522).
   */
  private predicate isTraversalPathParameter(DataFlow::Node source) {
    exists(Parameter p, Function f |
      source.(DataFlow::ParameterNode).getParameter() = p and
      f.getAnArg() = p and
      p.getName() in ["path", "url", "URL"] and
      (
        (
          f.getName() = "traverse" and
          f.getLocation().getFile().getBaseName() = "BaseRequest.py"
        )
        or
        (
          f.getName() in ["resolve_url", "physicalPathFromURL"] and
          f.getLocation().getFile().getBaseName() = "HTTPRequest.py"
        )
        or
        (
          f.getName() in ["unrestrictedTraverse", "restrictedTraverse"] and
          f.getLocation().getFile().getBaseName() = "Traversable.py"
        )
      )
    )
  }

  /**
   * URL path segments entering as object/resource names.
   * Labels p1-src-292 (NullResource.__init__ name), p1-src-293
   * (LockNullResource.__init__ name) - both feed ZODB object ids via
   * _setObject/checkValidId, no direct filesystem flow;
   * p1-src-294 (DirectoryResource.get name) - THE request-to-filesystem
   * bridge: Products/Five/browser/resource.py:155
   * filename = os.path.join(path, name) with no in-repo filtering.
   * In resource.py only the "get" function is matched (the __init__
   * functions there are config_path_param rows labeled none).
   */
  private predicate isUrlSegmentParameter(DataFlow::Node source) {
    exists(Parameter p, Function f |
      source.(DataFlow::ParameterNode).getParameter() = p and
      f.getAnArg() = p and
      p.getName() = "name" and
      (
        (
          f.getName() = "__init__" and
          f.getLocation().getFile().getBaseName() = "NullResource.py"
        )
        or
        (
          f.getName() = "get" and
          f.getLocation().getFile().getBaseName() = "resource.py"
        )
      )
    )
  }

  /**
   * Request-object .get() lookups and the get_env = environ.get alias
   * (HTTPRequest.get merges other/URL/env/common/lazy/form/cookies).
   * Labels p1-src-026-058, 083-085, 176-187, 189.
   * Evidence: ZPublisher/HTTPRequest.py:1250 (get), :323 (get_env alias).
   */
  private predicate isRequestGetLookupValue(DataFlow::Node source) {
    exists(Call c, Attribute fn |
      source.asExpr() = c and
      c.getFunc() = fn and
      fn.getName() = "get" and
      isRequestLikeObject(fn.getObject())
    )
    or
    exists(Call c |
      source.asExpr() = c and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "get_env" and
      c.getLocation().getFile().getBaseName() = "HTTPRequest.py"
    )
  }

  /**
   * request/environ subscript reads (HTTPRequest.__getitem__ namespace).
   * Labels p1-src-059-080, 086-169.  Evidence:
   * ZPublisher/HTTPRequest.py:1381 (observed keys BODYFILE, BODY, URL, id).
   */
  private predicate isRequestSubscriptValue(DataFlow::Node source) {
    exists(Subscript s |
      source.asExpr() = s and
      isRequestLikeObject(s.getObject())
    )
  }

  /**
   * REQUEST.form / request.form attribute reads (parsed request form).
   * Labels p1-src-081, 082, 170-174.  Evidence:
   * OFS/Cache.py:518 props = REQUEST.form (drives restrictedTraverse at :522),
   * OFS/PropertyManager.py:327, Products/Five/component/browser.py:29.
   */
  private predicate isRequestFormFieldValue(DataFlow::Node source) {
    exists(Attribute a |
      source.asExpr() = a and
      a.getName() = "form" and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() in ["request", "REQUEST"]
    )
  }

  /**
   * request.environ attribute reads (raw WSGI environ at request time).
   * Labels p1-src-015-018.  Evidence: ZPublisher/BaseRequest.py:709/:710,
   * ZPublisher/WSGIPublisher.py:262 (request.environ -> setDebugInfo).
   */
  private predicate isRequestEnvironmentValue(DataFlow::Node source) {
    exists(Attribute a |
      source.asExpr() = a and
      a.getName() = "environ" and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() = "request"
    )
  }

  /**
   * HTTP header reads via REQUEST.get_header (environ['HTTP_*']).
   * Labels p1-src-190-227.  Evidence: ZPublisher/HTTPRequest.py:1231
   * (getHeader, get_header alias at :1248); webdav If/Depth/Timeout/
   * content-type headers; OFS/Image.py:152/:184/:190.
   */
  private predicate isRequestHeaderValue(DataFlow::Node source) {
    exists(Call c, Attribute fn |
      source.asExpr() = c and
      c.getFunc() = fn and
      fn.getName() = "get_header" and
      isRequestLikeObject(fn.getObject())
    )
  }

  /**
   * Multipart upload filenames from the cgi FieldStorage (client-controlled,
   * path-shaped).  Labels p1-src-295-297.  Evidence:
   * ZPublisher/HTTPRequest.py:1664 (self.filename = aFieldStorage.filename),
   * :536-537 (FileUpload wrapping), OFS/Image.py:1004 (cookId input).
   */
  private predicate isMultipartFilenameValue(DataFlow::Node source) {
    exists(Attribute a |
      source.asExpr() = a and
      a.getName() = "filename" and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() in ["file", "item", "aFieldStorage"] and
      a.getLocation().getFile().getBaseName() in ["Image.py", "HTTPRequest.py"]
    )
  }

  /**
   * XML-RPC request arguments parsed from the text/xml POST body.
   * Label p1-src-175.  Evidence: ZPublisher/HTTPRequest.py:513
   * meth, self.args = xmlrpc.parse_input(fs.value).
   */
  private predicate isXmlRpcArgumentsValue(DataFlow::Node source) {
    exists(Call c, Attribute fn |
      source.asExpr() = c and
      c.getFunc() = fn and
      fn.getName() = "parse_input" and
      fn.getObject() instanceof Name and
      fn.getObject().(Name).getId() = "xmlrpc"
    )
  }

  /**
   * Holds if `obj` is a request-object receiver as labeled: a bare
   * request/REQUEST/environ name, or an attribute chain ending in
   * request/REQUEST/environ (self.request, root.REQUEST, app.REQUEST,
   * self.REQUEST) or form (REQUEST.form, request.environ).
   */
  private predicate isRequestLikeObject(Expr obj) {
    obj.(Name).getId() in ["request", "REQUEST", "environ"]
    or
    obj.(Attribute).getName() in ["request", "REQUEST", "environ", "form"]
  }
}
