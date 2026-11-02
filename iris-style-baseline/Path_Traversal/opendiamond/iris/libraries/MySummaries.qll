/**
 * Augur Phase 2 - Pass 1 additional taint steps (machine-generated from
 * reviewed labels).
 *
 * Generated from: iris/labels/labels.json, pass 1 (Path Traversal,
 * CWE-022/023/036/073), run opendiamond-pass1-labeling-20261022, model glm-5.3.
 *
 * Only propagation edges that are NOT already provided by the local
 * codeql/python-all 7.1.2 standard library are modeled here, and each is
 * backed by a reviewed summary-role label and by the real code path:
 *
 *  Modeled in this file (3 step families):
 *   - str(x) builtin conversion                arg 0 -> result
 *     (part of the labeled video-store chains: video_store.py:55 and :87
 *      wrap the join result in str() before the Popen/stat sinks; without
 *      this step the reviewed `<path:video>` route-param channel breaks at
 *      the str() call. Coderedcms-style precedent.)
 *   - helpers.split_scheme(url)                arg 0 -> result
 *     (labels K-server_object_-235/251/259/334-split_scheme and
 *      K-server_filter-647/662/789-split_scheme, summary tp 0.75-0.85:
 *      the first-party wrapper at helpers.py:122-127 returns
 *      (scheme, path) derived from the input URL; its body ends in the
 *      external urlparse, whose result is not tainted by default.)
 *   - blaster dict subscript read            receiver -> result
 *     (scoped to blaster/handlers.py: the json.loads results labeled as
 *      sources reach their fields only through subscripts - config['cookies'],
 *      config['filters'] elements, f['code'], request['object'],
 *      req_obj['uri'] - the container exits of the reviewed json_body
 *      channel. Scope-limited to this one file to avoid unconditional
 *      cross-function container pollution.)
 *
 *  Already modeled by codeql/python-all 7.1.2 (NOT duplicated here - the
 *  labeled summary families resolve through the standard library):
 *   - os.path.join (all args -> result), os.path.dirname/basename/split/
 *     splitext: Stdlib.qll OsPathComputationAdditionalTaintStep. Covers the
 *     reviewed join labels in the dataretriever stores (diamond_store.py:123,
 *     mixer_store.py:252, test_store.py:282, video_store.py:125,
 *     yfcc100m_mysql_store.py:137), blaster/cache.py:75/:78/:81/:84 and
 *     blobcache.py:60/:177, dataretriever/util.py:44.
 *   - string concatenation (`path + suffix`, `dataset_path + '/' + c`) and
 *     container element <-> container steps (the video Popen command list):
 *     standard string/container taint steps.
 *   - first-party function calls: TaintTracking::Global is interprocedural
 *     over the extracted code - actual arguments flow into formal
 *     parameters, through bodies, and back from return expressions. The
 *     reviewed path_join_wrapper / internal_file_wrapper functions
 *     (_get_obj_absolute_path, _get_index_absolute_path,
 *     _get_obj_abosolute_path, BlobCache._path / __getitem__ /
 *     executable_path, SearchCache._search_dir_path / _search_path /
 *     _search_expiration_path / _object_path, ObjectLoader.load /
 *     _load_localfile / _load_attrbutes_localfile, Filter._resolve_code /
 *     _resolve_blob, DiamondTextAttr.__enter__) are fully in the database
 *     and need NO param->return edges: their bodies contain only
 *     stdlib-modeled operations. Adding unconditional param->return edges
 *     would be evidence-free cross-function pollution (same rationale as
 *     the coderedcms project).
 *     In particular augment_store._get_obj_absolute_path deliberately gets
 *     NO edge: its body is the external safe_join call, so by default its
 *     return is untainted and the guarded store stays quiet - the safe_join
 *     barrier in MySanitizers.qll provides defense in depth.
 *
 *  NOT modeled (documented limitations, see report/query_generation_notes.md):
 *   - urlparse result -> parts.scheme/parts.path attributes (external
 *     urllib): the blaster 'blob:<sig>' chain stops at urlparse in
 *     _BlasterBlob.fetch (handlers.py:204-209);
 *   - dunder __getitem__ dispatch (blob_cache[parts.path] does not connect
 *     to BlobCache.__getitem__'s sig parameter): the blobcache open/link/
 *     utime sinks are included per the reviewed labels but are not
 *     expected to fire without this edge;
 *   - XDR-decoded parameter object attribute content (params.filters[].code,
 *     params.object_id): attribute reads of a tainted parameter object are
 *     not tainted by default, so the XDR setup/reexecute sources are
 *     recorded but not expected to reach the object_/filter/blobcache sinks
 *     in a single pass;
 *   - str.lower()/upper() case folding on blob signatures (needed only by
 *     the already-unreachable blobcache chains).
 *
 * Pass key: "path_traversal".
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /**
   * Holds if taint may flow from `nodeFrom` to `nodeTo` in one additional
   * step for the given pass key, beyond the standard data-flow steps.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    (
      strConversionStep(nodeFrom, nodeTo)
      or
      splitSchemeStep(nodeFrom, nodeTo)
      or
      blasterDictSubscriptStep(nodeFrom, nodeTo)
    )
  }

  /**
   * The audit scope: the opendiamond package as extracted in Phase 1 Step 2
   * (the nested opendiamond-db tree and tests are excluded).
   */
  private predicate inAuditScopeAst(AstNode n) {
    n.getLocation().getFile().getAbsolutePath().matches("%/opendiamond/%")
  }

  /**
   * True iff `n` is located in the opendiamond file named by `subpath`.
   *
   * QL has no string concatenation, so the short subpaths map to full
   * path-match patterns through a literal table (filePattern).
   */
  private predicate inFile(AstNode n, string subpath) {
    exists(string pattern |
      filePattern(subpath, pattern) and
      n.getLocation().getFile().getAbsolutePath().matches(pattern)
    )
  }

  /** Literal subpath -> path-pattern table for the reviewed files. */
  private predicate filePattern(string subpath, string pattern) {
    (subpath = "server/object_.py" and
     pattern = "%/opendiamond/server/object_.py")
    or
    (subpath = "server/filter.py" and
     pattern = "%/opendiamond/server/filter.py")
    or
    (subpath = "blaster/handlers.py" and
     pattern = "%/opendiamond/blaster/handlers.py")
  }

  /**
   * str(...) builtin conversion in the audit scope: preserves its argument
   * value as a string.
   *
   * Evidence - the two reviewed video-store destination constructions wrap
   * the join result in str() before the file accesses:
   *   video_store.py:55  video_path = str(_get_obj_absolute_path(video))
   *                     (get_scope index channel -> _ffprobe)
   *   video_store.py:87  video_path = str(_get_obj_absolute_path(video))
   *                     (get_object -> os.stat :104, ffmpeg :136/:162)
   * Without this step the taint chain from the reviewed `<path:video>`
   * route parameter through os.path.join (stdlib step) to the
   * Popen/stat sinks breaks at the str() call. Other str() calls in the
   * audit scope (e.g. server/object_.py str(obj)) are inert for reviewed
   * flows and harmless to match.
   */
  private predicate strConversionStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "str" and
      inAuditScopeAst(c) and
      nodeFrom = DataFlow::exprNode(c.getArg(0)) and
      nodeTo = DataFlow::exprNode(c)
    )
  }

  /**
   * helpers.split_scheme(url) -> (scheme, path): argument 0 taints the
   * returned pair (the path element IS the input URL's path text).
   *
   * Evidence: helpers.py:120-127 - split_scheme is a first-party urlparse
   * wrapper whose body ends in the external urllib call, so the standard
   * library does not taint its result; the reviewed summary labels
   * (server/object_.py:235/:251/:259/:334 - source_available, load's meta/src
   * dispatch, _load_src_maybe_meta; server/filter.py:647/:662/:789 -
   * _resolve_code, _resolve_blob, source_available) mark it as the
   * URI-to-path boundary. Scoped to those two files (all reviewed
   * split_scheme call sites); the tuple unpack `scheme, path = ...` is
   * handled by standard local flow.
   *
   * Note: split_scheme performs NO percent-decoding (urlparse splits only),
   * so this step introduces no double-decode hazard. Under the current
   * models the upstream XDR parameter attributes are not tainted (see file
   * header), so this step mainly serves the documented diagnostic channels.
   */
  private predicate splitSchemeStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "split_scheme" and
      (inFile(c, "server/object_.py") or inFile(c, "server/filter.py")) and
      nodeFrom = DataFlow::exprNode(c.getArg(0)) and
      nodeTo = DataFlow::exprNode(c)
    )
  }

  /**
   * Dict member subscript read in blaster/handlers.py: `x[key]` receiver ->
   * result, i.e. taint on the loaded JSON container flows to the element
   * value.
   *
   * Evidence: the reviewed json_body sources (json.loads at handlers.py:245,
   * :360, :507) return dicts/lists whose values are reached only through
   * subscripts - config['cookies'] (:253-254), the config['filters'] loop
   * variable's f['code'] (:272-279), request['object'] (:366) and
   * req_obj['uri'] (:367). This is the single container-content step for
   * that channel, scoped to blaster/handlers.py only (coderedcms-style
   * scoped .get() precedent). Without it, none of the reviewed blaster
   * json.loads source entries could propagate at all.
   *
   * The channel deliberately stops at the urlparse call inside
   * _BlasterBlob.fetch (external, unmodeled - see file header); no
   * unconditional edge is added from the subscript values into the blob
   * cache.
   */
  private predicate blasterDictSubscriptStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Subscript sub |
      inFile(sub, "blaster/handlers.py") and
      nodeFrom = DataFlow::exprNode(sub.getObject()) and
      nodeTo = DataFlow::exprNode(sub)
    )
  }
}
