/**
 * Augur Phase 2 Step 4 - generated sanitizer (barrier) library.
 *
 * Pass 5 (CWE-89, SQL Injection) for the RTX/ARAX project.
 *
 * Machine-generated from `iris/labels/labels.json` (pass_id 5,
 * role=sanitizer - the 7 reviewed code-evidence entries). Each barrier is
 * the DataFlow node of the exact neutralizing expression reviewed in Phase 1;
 * taint that reaches the barrier node cannot continue toward the SQL-text
 * sinks.
 *
 *   pass5-san-001  rtxcomplete.py:34           int(requested_limit)
 *   pass5-san-002  node_synonymizer.py:1931    re.sub(r"'","''",uc_curie)
 *                 (same pattern at :1608, :1952, :2038)
 *   pass5-san-003  ARAX_decorator.py:67        node_key.replace("'","''")
 *                 (same pattern at :149)
 *   pass5-san-004  fisher_exact_test.py:456    curie_id.replace("'","''")
 *   pass5-san-005  compute_ngd.py:346          f"'{curie}'" construction with
 *                 quote-exclusion filter
 *   pass5-san-006  COHDIndex.py:554            dataset_id in {1,2,3} value
 *                 whitelist (control-flow guard, modeled on the parameter
 *                 nodes of the guarded functions)
 *   pass5-san-007  ARAX_query_tracker.py:284   .params(n=last_n_hours) named
 *                 binds (same pattern at :288, :291)
 *
 * Why these are genuine SQL-context sanitizers (not HTML escaping or naive
 * replace): doubling a single quote is the correct escape for SQLite
 * single-quoted string literals, which is exactly the SQL context of every
 * guarded interpolation (IN-lists `('...','...')` and `= '...'` predicates);
 * the quote-exclusion comprehension admits only values that cannot contain
 * the literal terminator; int() enforces a numeric type; the dataset_id
 * whitelist restricts the channel to {1,2,3}; .params() is SQLAlchemy's
 * named-bind channel.
 *
 * Deliberately NOT barriers (reviewed and rejected in Phase 1):
 *   - isinstance(int/list) type guards in COHDIndex: they reject scalar
 *     strings, but list elements still flow into tuple-repr interpolation -
 *     the pair-branch sinks remain classification=candidate, not sanitized.
 *   - fisher_exact_test convert_string_* helpers: string re-casing, no
 *     whitelist - the sink at :579 stays a modeled tp sink.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /** Restricts `n` to the rtx source file with the given basename. */
  private predicate inPyFile(AstNode n, string basename) {
    n.getLocation().getFile().getShortName() = basename
  }

  /**
   * Label pass5-san-001: the `int()` cast of the HTTP `limit` parameter at
   * rtxcomplete.py:34, guarding the LIMIT interpolation of the /nodeslike
   * sink at rtxcomplete.py:49.
   *
   *   rtxcomplete.py:34  requested_limit = int(requested_limit)
   *
   * Non-numeric input raises before any SQL executes; only the limit channel
   * is neutralized - the `word` channel of the same sink is NOT protected
   * (by design of the reviewed label).
   */
  private predicate intCastLimit(DataFlow::Node node) {
    exists(Call c |
      inPyFile(c, "rtxcomplete.py") and
      c.getLocation().getStartLine() = 34 and
      c.getFunc().(Name).getId() = "int" and
      node.asExpr() = c
    )
  }

  /**
   * Label pass5-san-002: the SQLite single-quote doubling applied to
   * curies/names before IN-list construction in node_synonymizer.py - the
   * representative reviewed site plus the three identical sites listed in
   * the label's evidence:
   *
   *   node_synonymizer.py:1608  uc_curie = re.sub(r"'","''",uc_curie)
   *   node_synonymizer.py:1931  uc_curie = re.sub(r"'","''",uc_curie)
   *   node_synonymizer.py:1952  lc_name = re.sub(r"'","''",lc_name)
   *   node_synonymizer.py:2038  uc_curie = re.sub(r"'","''",uc_curie)
   *
   * These guard the IN-list SQL executed at :1618, :1987 and :2048
   * (classification=sink/fp in the reviewed labels).
   */
  private predicate synonymizerQuoteDoubling(DataFlow::Node node) {
    exists(Call c |
      inPyFile(c, "node_synonymizer.py") and
      c.getLocation().getStartLine() in [1608, 1931, 1952, 2038] and
      c.getFunc().(Attribute).getName() = "sub" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "re" and
      node.asExpr() = c
    )
  }

  /**
   * Label pass5-san-003: the `.replace("'", "''")` quote doubling applied to
   * KG node keys / edge search keys before the KG2c sqlite IN-list SQL in
   * ARAX_decorator.py, guarding the execute calls at :72 and :154:
   *
   *   ARAX_decorator.py:67   node_keys = set(node_key.replace("'", "''")
   *                          for node_key in message.knowledge_graph.nodes)
   *   ARAX_decorator.py:149  search_keys_set = set(search_key.replace("'", "''")
   *                          for search_key in ...)
   */
  private predicate decoratorQuoteDoubling(DataFlow::Node node) {
    exists(Call c |
      inPyFile(c, "ARAX_decorator.py") and
      c.getLocation().getStartLine() in [67, 149] and
      c.getFunc().(Attribute).getName() = "replace" and
      node.asExpr() = c
    )
  }

  /**
   * Label pass5-san-004: the conditional `.replace("'", "''")` applied to
   * canonicalized curies before the neighbor-count IN-list SQL at
   * fisher_exact_test.py:468:
   *
   *   fisher_exact_test.py:456  query_nodes = [curie_id.replace("'", "''")
   *                             if "'" in curie_id else curie_id
   *                             for curie_id in query_nodes]
   */
  private predicate fisherQuoteDoubling(DataFlow::Node node) {
    exists(Call c |
      inPyFile(c, "fisher_exact_test.py") and
      c.getLocation().getStartLine() = 456 and
      c.getFunc().(Attribute).getName() = "replace" and
      node.asExpr() = c
    )
  }

  /**
   * Label pass5-san-005: the quote-exclusion IN-list builder at
   * compute_ngd.py:346 - an f-string construction that only wraps curies
   * containing no single quote, so the produced literal cannot be
   * terminated early; guards the execute at compute_ngd.py:347.
   *
   *   compute_ngd.py:346  curie_list_str = ", ".join(
   *                       [f"'{curie}'" for curie in chunk
   *                        if "'" not in curie])
   *
   * The barrier is the f-string expression node itself: taint entering the
   * per-element construction cannot continue to the joined list string.
   */
  private predicate ngdQuoteExclusion(DataFlow::Node node) {
    exists(Fstring f |
      inPyFile(f, "compute_ngd.py") and
      f.getLocation().getStartLine() = 346 and
      node.asExpr() = f
    )
  }

  /**
   * Label pass5-san-006: the `dataset_id` value whitelist (1, 2 or 3) of the
   * COHD query methods - reviewed representative guard at
   * COHDIndex.py:550-558; the identical guard was verified at :864-872
   * (get_paired_concept_freq), :1096-1104 (get_individual_concept_freq),
   * :1174-1182 (get_associated_concept_domain_freq) and :1495-1509
   * (get_most_frequent_concepts).
   *
   *   COHDIndex.py:550-558  if not isinstance(dataset_id, int): return []
   *                         else:
   *                           if dataset_id == 1 or dataset_id == 2 or
   *                              dataset_id == 3: pass
   *                           else: return []
   *
   * This is a control-flow (value) guard rather than an expression-level
   * barrier, so it is modeled on the `dataset_id` parameter nodes of the
   * guarded functions: taint arriving through this channel cannot reach the
   * SQL f-strings because only the whitelisted values survive the guard.
   * No modeled source currently reaches this channel (the dataset_id
   * candidates were labeled none/fp), so the branch is dormant but faithful
   * to the reviewed label.
   */
  private predicate cohdDatasetIdWhitelist(DataFlow::Node node) {
    exists(Function f, Parameter p, int i |
      inPyFile(f, "COHDIndex.py") and
      f.getName() in [
        "get_all_concept_pair_info",
        "get_paired_concept_freq",
        "get_individual_concept_freq",
        "get_associated_concept_domain_freq",
        "get_most_frequent_concepts"
      ] and
      p = f.getArg(i) and
      p.(Name).getId() = "dataset_id" and
      node = DataFlow::parameterNode(p)
    )
  }

  /**
   * Label pass5-san-007: the SQLAlchemy named-bind channel for the static
   * text() fragments of the query tracker - `.params(n=last_n_hours)` at
   * ARAX_query_tracker.py:284, :288 and :291. The user-controlled
   * `last_n_hours` from GET /status never enters SQL text.
   *
   *   ARAX_query_tracker.py:284  .filter(text("""... < :n""")).params(
   *                              n=last_n_hours)
   */
  private predicate trackerNamedBind(DataFlow::Node node) {
    exists(Call c |
      inPyFile(c, "ARAX_query_tracker.py") and
      c.getLocation().getStartLine() in [284, 288, 291] and
      c.getFunc().(Attribute).getName() = "params" and
      node.asExpr() = c
    )
  }

  /**
   * Holds if `node` is a CWE-89 sanitizer barrier for the given pass key.
   * Only `passKey = "sql_injection"` (Pass 5) is defined in this round.
   */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "sql_injection" and
    (
      intCastLimit(node)
      or
      synonymizerQuoteDoubling(node)
      or
      decoratorQuoteDoubling(node)
      or
      fisherQuoteDoubling(node)
      or
      ngdQuoteExclusion(node)
      or
      cohdDatasetIdWhitelist(node)
      or
      trackerNamedBind(node)
    )
  }
}
