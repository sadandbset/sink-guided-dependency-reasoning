/**
 * Augur Pass 1 (Path Traversal) source model for aiohttp.
 *
 * Generated deterministically from the reviewed Pass 1 labels in
 * iris/labels/labels.json (entries with role=source and classification=tp).
 * Only confirmed remotely-attacker-controlled input nodes are modeled;
 * candidate/pending-review entries (NETRC env, raw wire `feed_data` params,
 * url_for paths) are deliberately NOT sources here - see
 * iris/report/query_generation_notes.md for the full label-ID mapping and
 * the exclusion rationale.
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /**
   * Holds if `source` is a reviewed Pass 1 taint source for pass key
   * `passKey`.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and (
      requestLinePathSource(source) or
      multipartFilenameSource(source) or
      requestPathAttributeSource(source) or
      matchInfoFilenameSource(source)
    )
  }

  /** Restricts an AST node to a file base name and a 1-based start line. */
  private predicate matchLoc(AstNode n, string baseName, int line) {
    n.getLocation().getFile().getBaseName() = baseName and
    n.getLocation().getStartLine() = line
  }

  /**
   * p1-src-013 (source/tp 0.90): the request-line path off the wire.
   *
   * http_parser.py:554-556
   *   line = lines[0].decode("utf-8", "surrogateescape")
   *   method, path, version = line.split(" ", maxsplit=2)
   * `path` is the attacker-controlled request target; it is fed into
   * URL.build(path=path_part, ...) (http_parser.py:589) and becomes
   * request.rel_url. External input boundary: the HTTP request line of the
   * pure-Python parser (the Cython parser feeds the same yarl URL boundary).
   */
  private predicate requestLinePathSource(DataFlow::Node source) {
    exists(Call c |
      matchLoc(c, "http_parser.py", 556) and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "split" and
      source.asExpr() = c
    )
  }

  /**
   * p1-src-018, p1-src-019, p1-src-020, p1-src-021, p1-src-066, p1-src-067
   * (source/tp): the multipart Content-Disposition filename family.
   *
   * multipart.py:531-541 (BodyPartReader.name/.filename reify properties):
   *   _, params = parse_content_disposition(self.headers.get(CONTENT_DISPOSITION))
   *   return content_disposition_filename(params, "name")     // :532
   *   return content_disposition_filename(params, "filename") // :541
   * multipart.py:552-553 (BodyPartReaderPayload.__init__):
   *   params["name"] = value.name          // :552
   *   params["filename"] = value.filename  // :553
   * web_request.py:724 and :745 (Request.post()):
   *   if field.filename: ... ff = FileField(field.name, field.filename, ...)
   *
   * External input boundary: the Content-Disposition header of a
   * multipart/form-data body part; the attacker controls the full filename
   * string. In-tree the value never becomes a filesystem path (upload
   * content goes to an auto-named tempfile.TemporaryFile,
   * web_request.py:726); these sources exist for downstream consumers of
   * FileField.filename.
   */
  private predicate multipartFilenameSource(DataFlow::Node source) {
    exists(Call c |
      (matchLoc(c, "multipart.py", 532) or matchLoc(c, "multipart.py", 541)) and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "content_disposition_filename" and
      source.asExpr() = c
    )
    or
    exists(Attribute a |
      (
        (matchLoc(a, "multipart.py", 552) and a.getName() = "name") or
        (matchLoc(a, "multipart.py", 553) and a.getName() = "filename")
      ) and
      source.asExpr() = a
    )
    or
    exists(Attribute a |
      (matchLoc(a, "web_request.py", 724) or matchLoc(a, "web_request.py", 745)) and
      a.getName() = "filename" and
      source.asExpr() = a
    )
  }

  /**
   * p1-src-049 (web_middlewares.py:86), p1-src-050 (:87), p1-src-051 (:91),
   * p1-src-054 (:109), p1-src-052 (:95, decoded request.path),
   * p1-src-053 (:97, decoded request.path), p1-src-083 (web_urldispatcher.py:350),
   * p1-src-084 (:350 rel_url), p1-src-087 (:616), p1-src-088 (:616 rel_url),
   * p1-src-101 (:997), p1-src-102 (:997 rel_url) (source/tp): raw/decoded
   * request path reads.
   *
   * web_urldispatcher.py:616 (StaticResource.resolve):
   *   path = request.rel_url.raw_path
   * web_urldispatcher.py:350 (Resource.resolve):
   *   match_dict = self._match(request.rel_url.raw_path)
   * web_urldispatcher.py:997 (UrlDispatcher.resolve):
   *   url_part = request.rel_url.raw_path
   * web_middlewares.py:86-109 (normalize_path_middleware):
   *   request.raw_path reads (:86, :87, :91, :109) and request.path reads
   *   (:95, :97), which feed the candidate paths re-resolved via
   *   request.clone(rel_url=path) (web_middlewares.py:23).
   *
   * External input boundary: the request target path (raw = undecoded,
   * path = percent-decoded), readable by any routed request.
   */
  private predicate requestPathAttributeSource(DataFlow::Node source) {
    exists(Attribute a |
      a.getName() = "raw_path" and
      (
        matchLoc(a, "web_urldispatcher.py", 350) or
        matchLoc(a, "web_urldispatcher.py", 616) or
        matchLoc(a, "web_urldispatcher.py", 997) or
        matchLoc(a, "web_middlewares.py", 86) or
        matchLoc(a, "web_middlewares.py", 87) or
        matchLoc(a, "web_middlewares.py", 91) or
        matchLoc(a, "web_middlewares.py", 109)
      ) and
      source.asExpr() = a
    )
    or
    exists(Attribute a |
      a.getName() = "rel_url" and
      (
        matchLoc(a, "web_urldispatcher.py", 350) or
        matchLoc(a, "web_urldispatcher.py", 616) or
        matchLoc(a, "web_urldispatcher.py", 997)
      ) and
      source.asExpr() = a
    )
    or
    exists(Attribute a |
      a.getName() = "path" and
      (matchLoc(a, "web_middlewares.py", 95) or matchLoc(a, "web_middlewares.py", 97)) and
      source.asExpr() = a
    )
  }

  /**
   * p1-src-091, p1-src-092 (source/tp): the routed static filename.
   *
   * web_urldispatcher.py:635 (StaticResource._handle):
   *   rel_url = request.match_info["filename"]
   *
   * External input boundary: the percent-decoded remainder of the request
   * URL after the static prefix (decoded exactly once by _unquote_path in
   * StaticResource.resolve, web_urldispatcher.py:625), so the attacker
   * controls the entire relative path string, including "../" sequences
   * and (from %2f) literal separators. This is the dominant source feeding
   * the static-file pipeline.
   */
  private predicate matchInfoFilenameSource(DataFlow::Node source) {
    exists(Subscript s |
      matchLoc(s, "web_urldispatcher.py", 635) and
      s.getObject() instanceof Attribute and
      s.getObject().(Attribute).getName() = "match_info" and
      source.asExpr() = s
    )
    or
    exists(Attribute a |
      matchLoc(a, "web_urldispatcher.py", 635) and
      a.getName() = "match_info" and
      source.asExpr() = a
    )
  }
}
