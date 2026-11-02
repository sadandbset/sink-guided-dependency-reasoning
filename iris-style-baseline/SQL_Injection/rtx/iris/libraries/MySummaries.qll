/**
 * Augur Phase 2 Step 4 - generated taint-summary (additional flow step)
 * library.
 *
 * Pass 5 (CWE-89, SQL Injection) for the RTX/ARAX project.
 *
 * Machine-generated from `iris/labels/labels.json` (pass_id 5, role=summary,
 * classification=tp - the 13 reviewed propagation entries). Every edge below
 * is a conditional node-pair edge between two precisely anchored reviewed
 * nodes; no unconditional propagation relation is established.
 *
 * Reviewed summary entries and their edge assignment:
 *
 *   pass5-src-147, pass5-src-167  rtxcomplete.py:29  word / requested_limit
 *                                params of get_nodes_like
 *     -> Edge A (from the /nodeslike get_argument sources)
 *
 *   pass5-src-159..164  query_controller.py:23/61/71  query_dict params of
 *                       run_query_dict_in_child_process and the two
 *                       _run_query_and_return_json_generator_* helpers
 *   pass5-src-065, pass5-src-066  ARAX_query.py:100/216  query params of
 *                       query_return_stream / query_return_message
 *     -> Edges B1 (controller get_json -> pipeline entry, asyncquery direct
 *        call) and B2 (query_dict plumbing -> pipeline entry)
 *
 *   pass5-src-053, pass5-src-054, pass5-src-064
 *                       node_synonymizer.py:1899/1905  curies / names params
 *                       of get_equivalent_nodes / get_canonical_curies
 *     -> Edge C (pipeline entry -> canonicalization hub)
 *
 * The three role=summary / classification=fp entries (get_normalizer_results
 * entities, get_concepts_by_first_word entities, load_curie_to_pmids_data
 * canonicalized_curies) are NOT given edges: their channels end in
 * bound-parameter lookups or quote-filtered interpolation and cannot reach a
 * modeled sink, so no propagation edge is needed for CWE-89.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {

  /** Restricts `n` to the rtx source file with the given basename. */
  private predicate inPyFile(AstNode n, string basename) {
    n.getLocation().getFile().getShortName() = basename
  }

  /**
   * Edge A - labels pass5-src-147 and pass5-src-167 (word / requested_limit
   * parameters of rtxcomplete.get_nodes_like):
   *
   *   server.py:101-103  limit/word/callback = self.get_argument(...)
   *   server.py:104       result = rtxcomplete.get_nodes_like(word, limit)
   *
   * `server.py` imports the sibling module `rtxcomplete` (code/autocomplete/
   * rtxcomplete.py) without a package context; if import resolution does not
   * link the two files, the argument hand-off at server.py:104 is invisible
   * to default data flow. This edge connects each get_argument call result
   * node (the reviewed tp sources) to the `word` (position 0) and
   * `requested_limit` (position 1) parameter nodes of get_nodes_like. The
   * `limit` channel is then cut by the int() barrier at rtxcomplete.py:34;
   * the `word` channel proceeds to the f-string sinks.
   */
  private predicate tornadoWordHandoff(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call arg, Function getNodesLike, Parameter word, Parameter limit |
      inPyFile(arg, "server.py") and
      arg.getLocation().getStartLine() in [101, 102, 103] and
      arg.getFunc().(Attribute).getName() = "get_argument" and
      nodeFrom.asExpr() = arg and
      inPyFile(getNodesLike, "rtxcomplete.py") and
      getNodesLike.getName() = "get_nodes_like" and
      word = getNodesLike.getArg(0) and
      word.(Name).getId() = "word" and
      limit = getNodesLike.getArg(1) and
      limit.(Name).getId() = "requested_limit" and
      (nodeTo = DataFlow::parameterNode(word) or nodeTo = DataFlow::parameterNode(limit))
    )
  }

  /**
   * Edge B1 - labels pass5-src-240/241 (asyncquery_controller.py:24
   * get_json) into pass5-src-066 (ARAX_query.query_return_message query):
   *
   *   asyncquery_controller.py:24  query = connexion.request.get_json()
   *   asyncquery_controller.py:34  envelope = araxq.query_return_message(
   *                                 query, mode='asynchronous')
   *
   * Bridges the cross-module `from ARAX_query import ARAXQuery` instance
   * call, which relies on import resolution across the sys.path-based
   * layout of the ARAX tree.
   */
  private predicate asyncqueryJsonToAraxEntry(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call jsonCall, Function entry, Parameter q, int i |
      inPyFile(jsonCall, "asyncquery_controller.py") and
      jsonCall.getLocation().getStartLine() = 24 and
      jsonCall.getFunc().(Attribute).getName() = "get_json" and
      nodeFrom.asExpr() = jsonCall and
      inPyFile(entry, "ARAX_query.py") and
      entry.getName() = "query_return_message" and
      q = entry.getArg(i) and
      q.(Name).getId() = "query" and
      nodeTo = DataFlow::parameterNode(q)
    )
  }

  /**
   * Edge B2 - labels pass5-src-159..164 (query_dict params of the
   * query_controller.py plumbing) into pass5-src-065/066 (ARAX entry query
   * params):
   *
   *   query_controller.py:61/71   def _run_query_and_return_json_generator_*
   *                               (query_dict: dict)
   *   query_controller.py:23      def run_query_dict_in_child_process(
   *                               query_dict: dict, query_runner: Callable)
   *   query_controller.py:107/108 run_query_dict_in_child_process(query,
   *                               _run_query_and_return_json_generator_stream)
   *   query_controller.py:43      json_string_generator = query_runner(
   *                               query_dict)   <- indirect call
   *   query_controller.py:62/72   ARAX_query.ARAXQuery().query_return_message(
   *                               query_dict) / query_return_stream(query_dict)
   *
   * The child-process wrapper invokes its `query_runner` function-valued
   * parameter, an indirect call that default taint tracking does not
   * reliably resolve, and the ARAX entry is reached cross-module. This edge
   * family carries taint from any of the three plumbing `query_dict`
   * parameters to the `query` parameter (position 1) of
   * query_return_message/query_return_stream.
   */
  private predicate controllerQueryDictToAraxEntry(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function plumbing, Parameter qd, Function entry, Parameter q, int i, int j |
      inPyFile(plumbing, "query_controller.py") and
      plumbing.getName() in [
        "run_query_dict_in_child_process",
        "_run_query_and_return_json_generator_stream",
        "_run_query_and_return_json_generator_nonstream"
      ] and
      qd = plumbing.getArg(i) and
      qd.(Name).getId() = "query_dict" and
      nodeFrom = DataFlow::parameterNode(qd) and
      inPyFile(entry, "ARAX_query.py") and
      entry.getName() in ["query_return_message", "query_return_stream"] and
      q = entry.getArg(j) and
      q.(Name).getId() = "query" and
      nodeTo = DataFlow::parameterNode(q)
    )
  }

  /**
   * Edge C - labels pass5-src-053/054/064 (curies/names params of
   * node_synonymizer get_equivalent_nodes/get_canonical_curies) fed from
   * pass5-src-065/066 (ARAX entry query params):
   *
   * The ARAX pipeline parses the user query dict (TRAPI query graph and/or
   * the operations.actions DSL strings via ActionsParser), resolves qnode
   * ids/curies through expand/overlay machinery and canonicalizes them with
   * the NodeSynonymizer (detection.json propagation_notes; e.g.
   * fisher_exact_test.py:451, DTD_querier.py:337-414 call
   * nodesynonymizer.get_canonical_curies with pipeline curies). This parsing
   * and dispatch is not trackable by default data flow, so the reviewed
   * summary labels authorize one conditional edge from the pipeline entry
   * `query` parameters to the canonicalization-hub `curies`/`names`
   * parameters.
   *
   * Downstream of the hub, the IN-list path is cut by the quote-doubling
   * barrier (node_synonymizer.py:1931/1952) before the execute at :1987/:2048
   * - matching the reviewed escaped-sink/fp classification.
   */
  private predicate araxEntryToSynonymizerHub(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function entry, Parameter q, Function hub, Parameter c, int i, int j |
      inPyFile(entry, "ARAX_query.py") and
      entry.getName() in ["query_return_message", "query_return_stream"] and
      q = entry.getArg(i) and
      q.(Name).getId() = "query" and
      nodeFrom = DataFlow::parameterNode(q) and
      inPyFile(hub, "node_synonymizer.py") and
      (hub.getName() = "get_canonical_curies" or hub.getName() = "get_equivalent_nodes") and
      c = hub.getArg(j) and
      c.(Name).getId() in ["curies", "names"] and
      nodeTo = DataFlow::parameterNode(c)
    )
  }

  /**
   * Holds if taint may additionally flow from `nodeFrom` to `nodeTo` for
   * the given pass key. Only `passKey = "sql_injection"` (Pass 5) is defined
   * in this round; every edge is a reviewed, node-pair-specific propagation.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "sql_injection" and
    (
      tornadoWordHandoff(nodeFrom, nodeTo)
      or
      asyncqueryJsonToAraxEntry(nodeFrom, nodeTo)
      or
      controllerQueryDictToAraxEntry(nodeFrom, nodeTo)
      or
      araxEntryToSynonymizerHub(nodeFrom, nodeTo)
    )
  }
}
