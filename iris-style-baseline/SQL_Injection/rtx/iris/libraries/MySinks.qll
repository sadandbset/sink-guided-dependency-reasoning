/**
 * Augur Phase 2 Step 4 - generated sink library.
 *
 * Pass 5 (CWE-89, SQL Injection) for the RTX/ARAX project.
 *
 * Machine-generated from `iris/labels/labels.json` (pass_id 5, role=sink):
 * the 11 classification=tp entries and the 9 classification=candidate
 * entries. In every modeled sink, argument 0 of a DB-API `execute` call is
 * the dynamically constructed SQL text (f-string, %-format or an
 * intermediate `sql`/`sql_query` variable built from unescaped
 * interpolation) - never a bound-parameter value tuple.
 *
 * Modeled (tp):
 *   pass5-sink-055..057, -059  rtxcomplete.py:49/76/88/112
 *                               cursor.execute(f"...{word}...") / % format
 *   pass5-sink-001             predictor.py:65
 *                               self.graph_cur.execute(f"...curie='{curie_name}'")
 *   pass5-sink-063..067        predictor.py:328/348/350/370/372
 *                               cursor.execute(f"... disease/drug ...")
 *   pass5-sink-054             fisher_exact_test.py:579
 *                               cursor.execute(sql_query)  (f-string built at
 *                               :575-577 from the user qnode category)
 *
 * Modeled (candidate - second-order, flagged for human review):
 *   pass5-sink-128..136        COHDIndex.py:983/986/1007/1021/1023/1027/
 *                              1029/1051/1053 (get_paired_concept_freq
 *                              pair-branch; inputs are cohd.io-mapped
 *                              "omop1_omop2" strings).
 *
 * Intentionally NOT modeled as sinks (role none in the reviewed labels):
 *   - All parameterized `cursor.execute(sql, (values,))` / `executemany`
 *     calls (node_synonymizer access methods :1747-2320, rtxcomplete.py:106/
 *     127, KGNodeIndex, kg2c, GraphSage, ngd build, create_load_db,
 *     record_kg2c, COHD static literals): argument 0 is a static SQL string
 *     and values are bound - the bound VALUES channel is never a SQL-text
 *     sink.
 *   - The quote-escaped IN-list executions (node_synonymizer.py:1618/1987/
 *     2048, ARAX_decorator.py:72/154, fisher_exact_test.py:468,
 *     compute_ngd.py:347): raw SQL text, but taint is neutralized by the
 *     reviewed sanitizers (MySanitizers.qll barriers) - see the notes.
 *   - ARAX_query_tracker.py:283/288/291 `sqlalchemy.text(...)`: argument 0
 *     is a static SQL fragment; the user value is bound via `.params(n=...)`
 *     named binds - not a raw-SQL sink.
 *   - neo4j Cypher session.run() is out of CWE-89 scope.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {

  /** Restricts `n` to the rtx source file with the given basename. */
  private predicate inPyFile(AstNode n, string basename) {
    n.getLocation().getFile().getShortName() = basename
  }

  /**
   * Labels pass5-sink-055, -056, -057, -059: `cursor.execute(...)` argument 0
   * in rtxcomplete.py - the autocomplete sqlite lookups whose SQL text
   * interpolates the raw HTTP `word` (and derived floor/ceiling/word_part)
   * into double-quoted string literals:
   *
   *   rtxcomplete.py:49   cursor.execute(f"SELECT term FROM terms WHERE ...
   *                        term > \"{floor}\" ... LIKE \"{word}%%\" ...
   *                        LIMIT {requested_limit}")
   *   rtxcomplete.py:76   cursor.execute(f"SELECT rowid, fragment FROM
   *                        cached_fragments WHERE fragment == \"{word_part}\"")
   *   rtxcomplete.py:88   cursor.execute(f"SELECT term FROM
   *                        cached_fragment_terms WHERE fragment_id =
   *                        {fragment_id} AND term LIKE \"%%{word}%%\"")
   *   rtxcomplete.py:112  cursor.execute("SELECT term FROM terms WHERE term
   *                        LIKE \"%%%s%%\" ... LIMIT %s" % (word,10000))
   *
   * Receiver `cursor` is the module-global sqlite3 cursor created in
   * `load()` (rtxcomplete.py:25), matched by name. Line 112's argument 0 is
   * the %-format expression.
   */
  private predicate rtxcompleteExecuteArg0(DataFlow::Node sink) {
    exists(Call c |
      inPyFile(c, "rtxcomplete.py") and
      c.getLocation().getStartLine() in [49, 76, 88, 112] and
      c.getFunc().(Attribute).getName() = "execute" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "cursor" and
      sink.asExpr() = c.getArg(0)
    )
  }

  /**
   * Label pass5-sink-001: `self.graph_cur.execute(...)` argument 0 at
   * predictor.py:65 - the feature-vector lookup with an unescaped curie:
   *
   *   predictor.py:65  row = self.graph_cur.execute(
   *                     f"select * from GRAPH where curie='{curie_name}'")
   *
   * Receiver is the `self.graph_cur` sqlite cursor attribute, matched by
   * attribute name.
   */
  private predicate predictorGraphCurieLookup(DataFlow::Node sink) {
    exists(Call c |
      inPyFile(c, "predictor.py") and
      c.getLocation().getStartLine() = 65 and
      c.getFunc().(Attribute).getName() = "execute" and
      c.getFunc().(Attribute).getObject().(Attribute).getName() = "graph_cur" and
      sink.asExpr() = c.getArg(0)
    )
  }

  /**
   * Labels pass5-sink-063..067: `cursor.execute(...)` argument 0 - the DTD
   * probability database lookups with unescaped disease/drug interpolation:
   *
   *   predictor.py:328  f"select * from DTD_PROBABILITY where disease =
   *                     '{disease}' and drug = '{drug}'"
   *   predictor.py:348  f"select * from DTD_PROBABILITY where
   *                     disease='{disease_id_list[0]}'"
   *   predictor.py:350  f"select * from DTD_PROBABILITY where disease in
   *                     {tuple(set(disease_id_list))}"
   *   predictor.py:370  f"select * from DTD_PROBABILITY where
   *                     drug='{drug_id_list[0]}'"
   *   predictor.py:372  f"select * from DTD_PROBABILITY where drug in
   *                     {tuple(set(drug_id_list))}"
   *
   * Receiver `cursor` is the local `self.connection.cursor()`.
   */
  private predicate predictorDtdLookups(DataFlow::Node sink) {
    exists(Call c |
      inPyFile(c, "predictor.py") and
      c.getLocation().getStartLine() in [328, 348, 350, 370, 372] and
      c.getFunc().(Attribute).getName() = "execute" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "cursor" and
      sink.asExpr() = c.getArg(0)
    )
  }

  /**
   * Label pass5-sink-054: `cursor.execute(sql_query)` argument 0 at
   * fisher_exact_test.py:579 - the category-count lookup whose SQL text is
   * built at :575-577 from the user-supplied qnode category:
   *
   *   fisher_exact_test.py:575  sql_query = f"SELECT C.count " \
   *                              f"FROM category_counts AS C " \
   *                              f"WHERE C.category = '{node_type}'"
   *   fisher_exact_test.py:579  cursor.execute(sql_query)
   *
   * `node_type` reaches this function (size_of_given_type_in_KP,
   * fisher_exact_test.py:331) from
   * `self.message.query_graph.nodes[...].categories` (:102) - user-supplied
   * TRAPI fields; convert_string_to_snake_case/biolinkformat (:617-650) only
   * re-case the string and are NOT a whitelist.
   */
  private predicate fisherCategoryCountLookup(DataFlow::Node sink) {
    exists(Call c |
      inPyFile(c, "fisher_exact_test.py") and
      c.getLocation().getStartLine() = 579 and
      c.getFunc().(Attribute).getName() = "execute" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "cursor" and
      sink.asExpr() = c.getArg(0)
    )
  }

  /**
   * Labels pass5-sink-128..136 (classification=candidate): the
   * `get_paired_concept_freq` pair-branch `cursor.execute(...)` argument 0
   * calls, whose SQL text interpolates `concept_id_pair` strings unescaped:
   *
   *   COHDIndex.py:1023  f"select ... from PAIRED_CONCEPT_COUNTS_ASSOCIATIONS
   *                      where concept_pair_id in {tuple(set(concept_id_pair1))};"
   *   COHDIndex.py:983   f"... where concept_pair_id='{concept_id_pair1}';"
   *
   * The only live caller (overlay_clinical_info.py:176-178) passes
   * "omop1_omop2" strings produced by the trusted cohd.io mapping API from
   * user curies (COHDIndex.get_concept_ids -> requests.post) - a second-order
   * channel that currently yields numeric strings. Included for recall;
   * findings here require the human review recorded in
   * labels/phase1_review.md (section 5).
   */
  private predicate cohdPairBranchLookups(DataFlow::Node sink) {
    exists(Call c |
      inPyFile(c, "COHDIndex.py") and
      c.getLocation().getStartLine() in [983, 986, 1007, 1021, 1023, 1027, 1029, 1051, 1053] and
      c.getFunc().(Attribute).getName() = "execute" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "cursor" and
      sink.asExpr() = c.getArg(0)
    )
  }

  /**
   * Holds if `sink` is a CWE-89 taint sink for the given pass key.
   * Only `passKey = "sql_injection"` (Pass 5) is defined in this round.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "sql_injection" and
    (
      rtxcompleteExecuteArg0(sink)
      or
      predictorGraphCurieLookup(sink)
      or
      predictorDtdLookups(sink)
      or
      fisherCategoryCountLookup(sink)
      or
      cohdPairBranchLookups(sink)
    )
  }
}
