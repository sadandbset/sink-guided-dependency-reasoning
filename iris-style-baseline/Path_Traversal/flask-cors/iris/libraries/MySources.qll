/**
 * Machine-generated from iris/labels/labels.json (Pass 1 - Path Traversal),
 * run flask-cors-path-traversal-pass1-20261022, model glm-5.3.
 * DO NOT EDIT BY HAND - regenerate from labels instead (WORKFLOW.md 5.1.4).
 *
 * Source labels rendered here (role=source, classification=tp), deduplicated by
 * signature into two name-anchored AST branches:
 *
 *   request.<attr> attribute reads on the Flask request proxy (5 label instances):
 *     - src-045: flask_cors/extension.py:178  request.path   (regex match subject)
 *     - src-046: flask_cors/extension.py:180  request.path   (LOG.debug argument)
 *     - src-023: flask_cors/core.py:245        request.headers
 *     - src-024: flask_cors/core.py:245        request.method
 *     - src-037: flask_cors/decorator.py:125   request.method
 *
 *   request_headers.get(...) header value reads in get_cors_headers (3 label instances):
 *     - src-011: flask_cors/core.py:177  request_headers.get('Origin')
 *     - src-014: flask_cors/core.py:194  request_headers.get(ACL_REQUEST_METHOD, '')
 *     - src-016: flask_cors/core.py:203  request_headers.get(ACL_REQUEST_HEADERS)
 *
 * Scope verification (this run, grep over the whole database snapshot excluding only
 * the nested flask-cors-db directory): the two structural patterns below match
 * exactly these 10 AST nodes and nothing else - tests/ contain no request.* attribute
 * reads, no request_headers.get calls, and no open() calls. No file-path string
 * constraints are used, so the Windows/Unix separator question does not arise.
 *
 * Only audited, genuinely attacker-controlled external input nodes are modeled as
 * sources. The 38 remaining source-file label rows (config_param, config_field,
 * request_value_param, wrapper_param, response_header families - operator-trust
 * configuration or internal helper parameters) are intentionally NOT sources.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /** Source nodes filtered by pass key. Only pass "path_traversal" (Pass 1) is carried by this pack. */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and flaskRequestBoundary(source)
  }

  /** The Flask 'request' proxy is the library's only untrusted input boundary. */
  private predicate flaskRequestBoundary(DataFlow::Node source) {
    requestAttributeRead(source)
    or
    requestHeaderValueRead(source)
  }

  /**
   * Attribute reads on the Flask request proxy: request.path / request.headers /
   * request.method. Name-anchored on the syntactic base name 'request'
   * (from flask import request - core.py:20, decorator.py:13, extension.py:11).
   * request.path is the only path-shaped source; headers/method are retained for
   * conservative recall per the audited labels.
   */
  private predicate requestAttributeRead(DataFlow::Node source) {
    exists(Attribute a |
      a.getObject().(Name).getId() = "request" and
      (a.getName() = "path" or a.getName() = "headers" or a.getName() = "method") and
      source.asExpr() = a
    )
  }

  /**
   * Header value reads request_headers.get(...) inside get_cors_headers
   * (flask_cors/core.py). request_headers is the function parameter carrying
   * request.headers (set_cors_headers, core.py:245); the Call node models the
   * returned header value (label flow_kind 'return'). The receiver name is
   * anchored exactly as in the audited code.
   */
  private predicate requestHeaderValueRead(DataFlow::Node source) {
    exists(Call c |
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "request_headers" and
      source.asExpr() = c
    )
  }
}
