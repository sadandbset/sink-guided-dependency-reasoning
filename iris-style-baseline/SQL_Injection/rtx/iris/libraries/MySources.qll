/**
 * Augur Phase 2 Step 4 - generated source library.
 *
 * Pass 5 (CWE-89, SQL Injection) for the RTX/ARAX project.
 *
 * Machine-generated from `iris/labels/labels.json` (pass_id 5, role=source,
 * classification=tp - 11 reviewed entries). Only the reviewed
 * attacker-controlled input boundaries whose taint can reach raw SQL text
 * are modeled:
 *
 *   pass5-src-120, pass5-src-121  asyncquery_controller.py:11  request_body
 *                                (openapi_server + KG2 variant)
 *   pass5-src-122, pass5-src-123  query_controller.py:75       request_body
 *                                (openapi_server + KG2 variant)
 *   pass5-src-240, pass5-src-241  asyncquery_controller.py:24  connexion.request.get_json()
 *   pass5-src-242, pass5-src-243  query_controller.py:88       connexion.request.get_json()
 *   pass5-src-253, pass5-src-254, pass5-src-255
 *                                autocomplete/server.py:101/102/103
 *                                self.get_argument("limit"/"word"/"callback")
 *                                in nodesLikeSearch (GET /nodeslike)
 *
 * The 33 role=source / classification=fp entries are intentionally NOT
 * modeled: their values only reach ORM bound parameters (x-forwarded-for
 * header, response_id, post_response body), parameterized NodeSynonymizer
 * lookups (entity q/body), non-SQL services (pubmed_mesh_ngd terms,
 * meta_knowledge_graph format_, get_logs mode), or handlers whose downstream
 * functions are absent from this snapshot (the /auto, /fuzzy, /autofuzzy
 * get_argument calls). Modeling them would not produce CWE-89 paths (their
 * execute calls are parameterized and not sinks in MySinks.qll).
 *
 * Notes:
 * - The KG2 variant controller files share basenames and line numbers with
 *   the non-KG2 controllers; basename + line matching covers both reviewed
 *   variants with one branch per family (documented in
 *   report/query_generation_notes.md).
 * - File restriction uses basename matching (File.getShortName()), which is
 *   path-separator safe; combined with the function/parameter/line
 *   restrictions from the labels each branch is project-unique.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {

  /** Restricts `n` to the rtx source file with the given basename. */
  private predicate inPyFile(AstNode n, string basename) {
    n.getLocation().getFile().getShortName() = basename
  }

  /**
   * Labels pass5-src-120..123: the `request_body` parameter (position 0) of
   * the connexion OpenAPI handlers `query()` and `asyncquery()` - the
   * schema-validated POST /query and POST /asyncquery JSON bodies.
   *
   *   query_controller.py:75        def query(request_body):
   *   asyncquery_controller.py:11   def asyncquery(request_body):
   *
   * Both the openapi_server and the KG2 variant controllers are covered by
   * the basename match.
   */
  private predicate openApiHandlerBodyParam(DataFlow::Node source) {
    exists(Function f, Parameter p |
      (
        inPyFile(f, "query_controller.py") or
        inPyFile(f, "asyncquery_controller.py")
      ) and
      (f.getName() = "query" or f.getName() = "asyncquery") and
      p = f.getArg(0) and
      p.(Name).getId() = "request_body" and
      source = DataFlow::parameterNode(p)
    )
  }

  /**
   * Labels pass5-src-240..243: the `connexion.request.get_json()` call
   * results that actually feed the ARAX pipeline.
   *
   *   asyncquery_controller.py:24   query = connexion.request.get_json()
   *   query_controller.py:88        query = connexion.request.get_json()
   *
   * The translate_controller.py get_json call (pass5-src-239, labeled fp) is
   * NOT modeled: POST /translate returns 501 before any data access.
   */
  private predicate requestJsonBodyCall(DataFlow::Node source) {
    exists(Call c |
      (
        inPyFile(c, "query_controller.py") or
        inPyFile(c, "asyncquery_controller.py")
      ) and
      c.getLocation().getStartLine() in [24, 88] and
      c.getFunc().(Attribute).getName() = "get_json" and
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "request" or
        c.getFunc().(Attribute).getObject().(Attribute).getName() = "request"
      ) and
      source.asExpr() = c
    )
  }

  /**
   * Labels pass5-src-253..255: the `self.get_argument(...)` call results in
   * the live tornado handler `nodesLikeSearch` (GET /nodeslike).
   *
   *   server.py:101   limit = self.get_argument("limit")
   *   server.py:102   word = self.get_argument("word")
   *   server.py:103   callback = self.get_argument("callback")
   *
   * `word` flows unescaped into the sqlite f-strings at rtxcomplete.py:49/
   * 76/88/112; `limit` is neutralized by the int() cast at rtxcomplete.py:34
   * (MySanitizers). The dead /auto, /fuzzy, /autofuzzy get_argument calls
   * (pass5-src-244..252, labeled fp) are NOT modeled.
   */
  private predicate tornadoNodeslikeArguments(DataFlow::Node source) {
    exists(Call c |
      inPyFile(c, "server.py") and
      c.getLocation().getStartLine() in [101, 102, 103] and
      c.getFunc().(Attribute).getName() = "get_argument" and
      source.asExpr() = c
    )
  }

  /**
   * Holds if `source` is a CWE-89 taint source for the given pass key.
   * Only `passKey = "sql_injection"` (Pass 5) is defined in this round.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "sql_injection" and
    (
      openApiHandlerBodyParam(source)
      or
      requestJsonBodyCall(source)
      or
      tornadoNodeslikeArguments(source)
    )
  }
}
