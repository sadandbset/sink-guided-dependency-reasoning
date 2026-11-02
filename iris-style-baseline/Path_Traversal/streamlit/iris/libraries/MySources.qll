/**
 * Machine-generated from reviewed Phase 1 labels (iris/labels/labels.json, pass 1).
 * Run: streamlit-pathtraversal-pass1-20261023. Do not edit by hand.
 *
 * Source nodes for pass key "path_traversal" (Path Traversal, CWE-22/23/36/73).
 *
 * Every predicate below corresponds to one or more labels/labels.json entries with
 * role=source. Sites are restricted to the Phase 1 extraction scope (lib/streamlit/)
 * and to the exact reviewed AST shapes; no internal wrapper parameter is treated as
 * a source. Label provenance is given in the comment on each predicate.
 *
 * Mapping (label id -> predicate):
 *   src-012 -> componentRoutePath   (ComponentRequestHandler.get path param, components.py:310)
 *   src-016 -> staticRoutePath      (StaticFileHandler.parse_url_path url_path param, routes.py:64)
 *   src-018 -> websocketMessage     (_BrowserWebSocketHandler.on_message payload param, server.py:774)
 *   src-007, src-008, src-009 -> requestFieldRead (self.request.body / self.request.headers)
 *   src-010, src-011 -> requestArgumentCall (self.get_argument(...), routes.py:129/298)
 *   src-019, src-020 -> requireArgCall (self._require_arg(...), upload_file_request_handler.py:121/122)
 *   src-022 -> multipartFilenameRead (file["filename"], upload_file_request_handler.py:144)
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /** Holds if `source` is a pass 1 (path_traversal) source node. */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and
    sourceNode(source)
  }

  private predicate sourceNode(DataFlow::Node source) {
    componentRoutePath(source)
    or staticRoutePath(source)
    or websocketMessage(source)
    or requestFieldRead(source)
    or requestArgumentCall(source)
    or requireArgCall(source)
    or multipartFilenameRead(source)
  }

  /**
   * src-012 (tp, 0.97): the `path` parameter of ComponentRequestHandler.get is the
   * decoded tornado route capture from `/component/(.*)` (server.py:391-395). It is
   * joined into `os.path.join(component_root, filename)` and opened
   * (components.py:319-325) with no containment check. Unauthenticated GET route;
   * requires a registered component (parts[0] lookup) to be exploitable.
   */
  private predicate componentRoutePath(DataFlow::Node source) {
    exists(Function get, Class handler, Parameter path |
      get.getName() = "get" and
      get.getScope() = handler and
      handler.getName() = "ComponentRequestHandler" and
      path = get.getArg(1) and
      path.getName() = "path" and
      inLibStreamlit(path) and
      source = DataFlow::parameterNode(path)
    )
  }

  /**
   * src-016 (tp, 0.80): the `url_path` parameter of StaticFileHandler.parse_url_path
   * is the decoded path from the catch-all static route `/(.*)` (server.py:417-432).
   * Page-name lookup rewrites known first segments to index.html; other paths defer
   * to the tornado superclass, whose disk read and validate_absolute_path containment
   * live outside this database.
   */
  private predicate staticRoutePath(DataFlow::Node source) {
    exists(Function parse, Class handler, Parameter urlPath |
      parse.getName() = "parse_url_path" and
      parse.getScope() = handler and
      handler.getName() = "StaticFileHandler" and
      urlPath = parse.getArg(1) and
      urlPath.getName() = "url_path" and
      inLibStreamlit(urlPath) and
      source = DataFlow::parameterNode(urlPath)
    )
  }

  /**
   * src-018 (candidate, 0.60): the `payload` parameter of
   * _BrowserWebSocketHandler.on_message is the raw WebSocket message bytes from the
   * browser, parsed as a BackMsg protobuf (server.py:789). Protobuf field reads are
   * not modeled as plain attribute flows; this source can only produce a finding if
   * an explicit summary step is added later (recorded in query_generation_notes.md).
   */
  private predicate websocketMessage(DataFlow::Node source) {
    exists(Function onMessage, Class handler, Parameter payload |
      onMessage.getName() = "on_message" and
      onMessage.getScope() = handler and
      handler.getName() = "_BrowserWebSocketHandler" and
      payload = onMessage.getArg(1) and
      payload.getName() = "payload" and
      inLibStreamlit(payload) and
      source = DataFlow::parameterNode(payload)
    )
  }

  /**
   * src-007 (tp, 0.90), src-008 (candidate, 0.60), src-009 (tp, 0.85):
   * `self.request.body` (upload_file_request_handler.py:115, multipart POST body)
   * and `self.request.headers` (upload_file_request_handler.py:114 Content-Type,
   * stats.py:116 Accept) field reads on the tornado HTTPServerRequest object.
   * Restricted to the `self.request.<field>` spelling: the only other
   * `<x>.request.headers` read in the package (server.py:677, `ws.request.headers`)
   * was not extracted or labeled, so it is deliberately NOT matched here
   * (extraction omission recorded for Phase 1 re-review).
   */
  private predicate requestFieldRead(DataFlow::Node source) {
    exists(Attribute field, Attribute request, Name selfName |
      field.getName() in ["body", "headers"] and
      request = field.getValue().(Attribute) and
      request.getName() = "request" and
      selfName = request.getValue().(Name) and
      selfName.getId() = "self" and
      inLibStreamlit(field) and
      source = DataFlow::exprNode(field)
    )
  }

  /**
   * src-010 (candidate, 0.65), src-011 (candidate, 0.60): the return values of
   * `self.get_argument(...)` at routes.py:129 ("title", MediaFileHandler) and
   * routes.py:298 ("hash", MessageCacheHandler) — the only two `self.get_argument`
   * call sites in lib/streamlit (verified by grep).
   */
  private predicate requestArgumentCall(DataFlow::Node source) {
    exists(Call call, Attribute func, Name receiver |
      func = call.getFunc().(Attribute) and
      func.getName() = "get_argument" and
      receiver = func.getValue().(Name) and
      receiver.getId() = "self" and
      inLibStreamlit(call) and
      source = DataFlow::exprNode(call)
    )
  }

  /**
   * src-019 (candidate, 0.70), src-020 (candidate, 0.70): the return values of
   * `self._require_arg(args, "sessionId"/"widgetId")` at
   * upload_file_request_handler.py:121-122 — decoded request-body values on the
   * unauthenticated /upload_file route. Modeled as source nodes per the reviewed
   * labels (avoids modeling the parse_body_arguments output dicts).
   */
  private predicate requireArgCall(DataFlow::Node source) {
    exists(Call call, Attribute func, Name receiver |
      func = call.getFunc().(Attribute) and
      func.getName() = "_require_arg" and
      receiver = func.getValue().(Name) and
      receiver.getId() = "self" and
      inLibStreamlit(call) and
      source = DataFlow::exprNode(call)
    )
  }

  /**
   * src-022 (tp, 0.80): the `file["filename"]` subscript read at
   * upload_file_request_handler.py:144 — the client-supplied multipart upload
   * filename stored into UploadedFileRec.name. Only the "filename" key is a source:
   * file["content_type"] and file["body"] are role=none in the labels (src-023,
   * src-024). The `file[...]` subscript shape occurs only at this one loop in
   * lib/streamlit (verified by grep).
   */
  private predicate multipartFilenameRead(DataFlow::Node source) {
    exists(Subscript sub, StringLiteral key, Name fileList |
      key = sub.getIndex().(StringLiteral) and
      key.getS() = "filename" and
      fileList = sub.getObject().(Name) and
      fileList.getId() = "file" and
      inLibStreamlit(sub) and
      source = DataFlow::exprNode(sub)
    )
  }

  /**
   * Holds if `n` is located in the lib/streamlit package — the Phase 1 extraction
   * scope (excludes lib/tests, e2e, scripts, and the nested streamlit-db directory).
   * Absolute paths are backslash-normalized before matching because this database
   * was created on Windows (paths are stored forward-slash normalized; see
   * exploration/detection.json, database_content_and_path_format).
   */
  private predicate inLibStreamlit(AstNode n) {
    exists(File f, string abs |
      f = n.getLocation().getFile() and
      abs = f.getAbsolutePath().replaceAll("\\\\", "/") and
      abs.matches("%.*/lib/streamlit/%")
    )
  }
}
