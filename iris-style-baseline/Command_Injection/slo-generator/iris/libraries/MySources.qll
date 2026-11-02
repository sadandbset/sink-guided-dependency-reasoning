/**
 * Name: MySources (Augur Phase 2 Step 4 - generated taint source library)
 * Description: Source predicates for Pass 2 / CWE-78 (Command Injection) of
 *   the slo-generator target, rendered deterministically from the reviewed
 *   Phase 1 labels in iris/labels/labels.json
 *   (run `slo-generator-iris-pass2-cwe78-20261016`, LLM model glm-5.3,
 *   27 `source` entries: 6 tp, 17 candidate, 4 unknown).
 *
 * Generation rules:
 *   - One predicate branch per label entry; the branch comment carries the
 *     label ID, classification and confidence for audit traceability.
 *   - Every branch is anchored to the label's verified source location
 *     (file relative path + start line) and to the structural shape recorded
 *     in the label signature (callable, receiver, flow kind, argument index).
 *   - Library calls (json/yaml/base64) are matched by AST shape
 *     (module-attribute callee). No aliased imports of these modules exist in
 *     the target (verified in exploration/detection.json), so AST matching is
 *     equivalent to API-graph resolution here while staying type-safe.
 *   - Location anchors use the same 1-based start lines as the extraction CSV
 *     (verified against the slo-generator-db snapshot, creation sha 50ce1bf).
 *
 * Label -> predicate mapping and per-entry evidence:
 *   see iris/report/query_generation_notes.md.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {

  /**
   * Holds if `loc` is located in the file whose path relative to the analyzed
   * source root is `relpath` (with an absolute-path fallback anchored to the
   * database sourceLocationPrefix).
   */
  private predicate inFile(Location loc, string relpath) {
    loc.getFile().getRelativePath() = relpath
    or
    loc.getFile().getAbsolutePath() =
      "C:/Users/lzh/Desktop/github/PyVul-main/dataset/codeql_databases/slo-generator_vuln/" + relpath
  }

  /** Holds if `loc` starts at `line` in the file matching `relpath`. */
  private predicate at(Location loc, string relpath, int line) {
    inFile(loc, relpath) and
    loc.getStartLine() = line
  }

  /**
   * Externally reachable entry-point parameters: Functions Framework target
   * functions, click CLI commands, and the migrator entry point.
   * Internal wrapper parameters are deliberately NOT modeled here
   * (see labels/phase1_review.md section 6 and the diagnostics query).
   */
  private predicate entryParamSource(DataFlow::Node source) {
    exists(Function f, Parameter p |
      // S136 (tp, 0.90): run_compute(request) - Functions Framework entry point
      f.getName() = "run_compute" and
      f.getArg(0) = p and
      p.getName() = "request" and
      at(p.getLocation(), "slo_generator/api/main.py", 41) and
      source = DataFlow::parameterNode(p)
    )
    or
    exists(Function f, Parameter p |
      // S145 (tp, 0.85): run_export(request) - Functions Framework entry point
      f.getName() = "run_export" and
      f.getArg(0) = p and
      p.getName() = "request" and
      at(p.getLocation(), "slo_generator/api/main.py", 80) and
      source = DataFlow::parameterNode(p)
    )
    or
    exists(Function f, Parameter p |
      // S023 (candidate, 0.60): compute CLI command --slo-config value
      f.getName() = "compute" and
      f.getArg(0) = p and
      p.getName() = "slo_config" and
      at(p.getLocation(), "slo_generator/cli.py", 77) and
      source = DataFlow::parameterNode(p)
    )
    or
    exists(Function f, Parameter p |
      // S024 (candidate, 0.60): compute CLI command --config value
      f.getName() = "compute" and
      f.getArg(1) = p and
      p.getName() = "config" and
      at(p.getLocation(), "slo_generator/cli.py", 77) and
      source = DataFlow::parameterNode(p)
    )
    or
    exists(Function f, Parameter p |
      // S038 (candidate, 0.50): api CLI command --config (envvar CONFIG_PATH)
      f.getName() = "api" and
      f.getArg(1) = p and
      p.getName() = "config" and
      at(p.getLocation(), "slo_generator/cli.py", 133) and
      source = DataFlow::parameterNode(p)
    )
    or
    exists(Function f, Parameter p |
      // S040 (candidate, 0.50): api CLI command --target (Functions Framework target name)
      f.getName() = "api" and
      f.getArg(3) = p and
      p.getName() = "target" and
      at(p.getLocation(), "slo_generator/cli.py", 133) and
      source = DataFlow::parameterNode(p)
    )
    or
    exists(Function f, Parameter p |
      // S159 (candidate, 0.65): do_migrate --version - interpolated into getattr names
      f.getName() = "do_migrate" and
      f.getArg(4) = p and
      p.getName() = "version" and
      at(p.getLocation(), "slo_generator/migrations/migrator.py", 48) and
      source = DataFlow::parameterNode(p)
    )
  }

  /**
   * Decode boundaries of external content: base64 request payloads, YAML
   * config parses, and remote API response decoding (json.loads).
   */
  private predicate decodeSource(DataFlow::Node source) {
    exists(Call c, Attribute fn |
      // S139 (tp, 0.85): base64.b64decode(request.data) - CloudEvent payload
      c.getFunc() = fn and
      fn.getName() = "b64decode" and
      fn.getObject().(Name).getId() = "base64" and
      at(c.getLocation(), "slo_generator/api/main.py", 59) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c, Attribute fn |
      // S148 (tp, 0.80): base64.b64decode(request.data) - CloudEvent payload
      c.getFunc() = fn and
      fn.getName() = "b64decode" and
      fn.getObject().(Name).getId() = "base64" and
      at(c.getLocation(), "slo_generator/api/main.py", 94) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c, Attribute fn |
      // S147 (candidate, 0.60): yaml.safe_load on request-derived bytes
      c.getFunc() = fn and
      fn.getName() = "safe_load" and
      fn.getObject().(Name).getId() = "yaml" and
      at(c.getLocation(), "slo_generator/api/main.py", 94) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c, Attribute fn |
      // S217 (candidate, 0.60): yaml.safe_load on config file content
      c.getFunc() = fn and
      fn.getName() = "safe_load" and
      fn.getObject().(Name).getId() = "yaml" and
      at(c.getLocation(), "slo_generator/utils.py", 145) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c, Attribute fn |
      // S012 (unknown, 0.45): json.loads on BigQuery API response
      c.getFunc() = fn and
      fn.getName() = "loads" and
      fn.getObject().(Name).getId() = "json" and
      at(c.getLocation(), "slo_generator/exporters/bigquery.py", 166) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c, Attribute fn |
      // S078 (unknown, 0.45): json.loads on Cloud Service Monitoring API response
      c.getFunc() = fn and
      fn.getName() = "loads" and
      fn.getObject().(Name).getId() = "json" and
      at(c.getLocation(), "slo_generator/backends/cloud_service_monitoring.py", 683) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c, Attribute fn |
      // S125 (unknown, 0.45): json.loads on Dynatrace API response
      c.getFunc() = fn and
      fn.getName() = "loads" and
      fn.getObject().(Name).getId() = "json" and
      at(c.getLocation(), "slo_generator/backends/dynatrace.py", 339) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c, Attribute fn |
      // S193 (unknown, 0.45): json.loads on Prometheus API response
      c.getFunc() = fn and
      fn.getName() = "loads" and
      fn.getObject().(Name).getId() = "json" and
      at(c.getLocation(), "slo_generator/backends/prometheus.py", 151) and
      source = DataFlow::exprNode(c)
    )
  }

  /**
   * Functions Framework request-object accessors (flask.Request /
   * cloudevent.CloudEvent). `request` is a framework object that static
   * analysis cannot resolve, matching the AST-level extraction rows.
   */
  private predicate requestObjectSource(DataFlow::Node source) {
    exists(Call c, Attribute fn |
      // S137 (tp, 0.90): request.get_data() - raw request body -> SLO config string
      c.getFunc() = fn and
      fn.getName() = "get_data" and
      fn.getObject().(Name).getId() = "request" and
      at(c.getLocation(), "slo_generator/api/main.py", 54) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c, Attribute fn |
      // S146 (tp, 0.85): request.get_json() - JSON request body -> SLO report
      c.getFunc() = fn and
      fn.getName() = "get_json" and
      fn.getObject().(Name).getId() = "request" and
      at(c.getLocation(), "slo_generator/api/main.py", 92) and
      source = DataFlow::exprNode(c)
    )
  }

  /** File-content boundaries: local config files, migration input files, GCS blobs. */
  private predicate fileReadSource(DataFlow::Node source) {
    exists(Call c, Attribute fn |
      // S162 (candidate, 0.55): source_path.open().read() - migration input file
      c.getFunc() = fn and
      fn.getName() = "read" and
      at(c.getLocation(), "slo_generator/migrations/migrator.py", 117) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c, Attribute fn |
      // S164 (candidate, 0.50): yaml.util.load_yaml_guess_indent(slo_config_str)
      c.getFunc() = fn and
      fn.getName() = "load_yaml_guess_indent" and
      at(c.getLocation(), "slo_generator/migrations/migrator.py", 118) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c, Attribute fn |
      // S216 (candidate, 0.55): config.read() - local config file content
      c.getFunc() = fn and
      fn.getName() = "read" and
      fn.getObject().(Name).getId() = "config" and
      at(c.getLocation(), "slo_generator/utils.py", 142) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c, Attribute fn |
      // S224 (candidate, 0.55): blob.download_as_string() - GCS-fetched config
      c.getFunc() = fn and
      fn.getName() = "download_as_string" and
      at(c.getLocation(), "slo_generator/utils.py", 450) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c |
      // S226 (candidate, 0.55): open(exp_path) - exporters migration file
      // content (migrator.py:227-229); deserialized one line later by the
      // unsafe yaml.load(conf, Loader=yaml.Loader) sink (K043) in
      // exporters_v1tov2. Added in the v2 post-triage remediation.
      c.getFunc().(Name).getId() = "open" and
      at(c.getLocation(), "slo_generator/migrations/migrator.py", 228) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Call c |
      // S227 (candidate, 0.55): open(ebp_path) - error budget policy
      // migration file content (migrator.py:262-264); deserialized one line
      // later by the unsafe yaml.load(conf, Loader=yaml.Loader) sink (K044)
      // in ebp_v1tov2. Added in the v2 post-triage remediation.
      c.getFunc().(Name).getId() = "open" and
      at(c.getLocation(), "slo_generator/migrations/migrator.py", 263) and
      source = DataFlow::exprNode(c)
    )
  }

  /**
   * Environment-variable boundaries: config path selection (api/main.py) and
   * the ${VAR} substitution context feeding config content (utils.py).
   */
  private predicate envSource(DataFlow::Node source) {
    exists(Subscript s |
      // S130 (candidate, 0.50): os.environ['CONFIG_PATH']
      s.getObject().(Attribute).getName() = "environ" and
      s.getObject().(Attribute).getObject().(Name).getId() = "os" and
      at(s.getLocation(), "slo_generator/api/main.py", 33) and
      source = DataFlow::exprNode(s)
    )
    or
    exists(Call c, Attribute fn |
      // S132 (candidate, 0.50): os.environ.get('EXPORTERS_PATH')
      c.getFunc() = fn and
      fn.getName() = "get" and
      fn.getObject().(Attribute).getName() = "environ" and
      fn.getObject().(Attribute).getObject().(Name).getId() = "os" and
      at(c.getLocation(), "slo_generator/api/main.py", 34) and
      source = DataFlow::exprNode(c)
    )
    or
    exists(Attribute a |
      // S204 / S207 / S213 (candidate, 0.50): os.environ used as the ${VAR}
      // substitution context (ctx defaults of load_configs/load_config/parse_config)
      a.getName() = "environ" and
      a.getObject().(Name).getId() = "os" and
      a.getLocation().getStartLine() in [45, 63, 103] and
      inFile(a.getLocation(), "slo_generator/utils.py") and
      source = DataFlow::exprNode(a)
    )
    or
    exists(Subscript s |
      // S214 (candidate, 0.50): ctx[var] - env value substituted into config content
      s.getObject().(Name).getId() = "ctx" and
      at(s.getLocation(), "slo_generator/utils.py", 132) and
      source = DataFlow::exprNode(s)
    )
  }

  /**
   * Holds if `source` is a taint source for the given pass.
   * Only pass "command_injection" (Pass 2 / CWE-78) is enabled in this run.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "command_injection" and
    (
      entryParamSource(source)
      or
      decodeSource(source)
      or
      requestObjectSource(source)
      or
      fileReadSource(source)
      or
      envSource(source)
    )
  }
}
