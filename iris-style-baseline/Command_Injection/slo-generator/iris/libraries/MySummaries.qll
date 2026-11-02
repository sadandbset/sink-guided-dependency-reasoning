/**
 * Name: MySummaries (Augur Phase 2 Step 4 - generated summary / glue library)
 * Description: Additional taint propagation steps for Pass 2 / CWE-78
 *   (Command Injection) of the slo-generator target, rendered from the
 *   reviewed Phase 1 `summary` labels in iris/labels/labels.json
 *   (run `slo-generator-iris-pass2-cwe78-20261016`, LLM model glm-5.3,
 *   67 `summary` entries).
 *
 * Only propagation gaps that CodeQL cannot bridge on its own are modeled
 * (WORKFLOW.md 5.1.3 / references/python.md section 6: "For wrappers and
 *   utilities, emit summary steps"). All steps are anchored to verified call
 *   sites and parameter definitions; there is no unconditional propagation.
 * Direct calls (load_config, compute, export, do_migrate, SLOReport, the
 * get_backend_cls -> import_cls -> import_dynamic chain) are resolved
 * natively by the data flow library and need NO summary edge.
 *
 * Modeled edge families (label evidence in brackets):
 *
 *   1. Backend dispatch glue (report.py:216 `method(timestamp, window,
 *      config)` -> %Backend method `slo_config` parameters): the callee is a
 *      getattr-resolved method, invisible to interprocedural analysis.
 *      [S057, S063, S096, S099, S104, S108, S116, S120, S128, S186, S190]
 *
 *   2. Exporter dispatch glue (compute.py:119 `instance().export(data,
 *      **config)` -> %Exporter `export` data parameters): the callee is an
 *      attribute of an import-resolved class instance.
 *      [S001, S007, S101, S195]
 *
 *   3. Metrics dispatch glue (exporters/base.py:109
 *      `self.export_metric(metric)` -> %MetricsExporter `export_metric` data
 *      parameters): the callee is a child-class method reached through the
 *      abstract base class.
 *      [S006, S060, S100, S112, S113, S194]
 *
 *   4. re.sub string transformation (utils.py name-derivation helpers):
 *      the default taint steps cover string methods (split/join/replace...)
 *      but not calls to the `re` module, so taint on the class name breaks at
 *      capitalize / snake_to_caml / caml_to_snake / the import_cls filename
 *      derivation. The step carries taint from the input string (arg 2) of
 *      the four anchored re.sub call sites to the transformation result.
 *      [K035, K036, K037, K038, K039, K040 - name-resolution chain]
 *
 * Label -> predicate mapping and per-entry evidence:
 *   see iris/report/query_generation_notes.md.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {

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

  /** report.py:216 - `data = method(self.timestamp, self.window, config)`. */
  private predicate isDispatchedBackendCall(Call c) {
    c.getFunc().(Name).getId() = "method" and
    at(c.getLocation(), "slo_generator/report.py", 216)
  }

  /** compute.py:119 - `response = instance().export(data, **config)`. */
  private predicate isDispatchedExporterCall(Call c) {
    c.getFunc().(Attribute).getName() = "export" and
    at(c.getLocation(), "slo_generator/compute.py", 119)
  }

  /** exporters/base.py:109 - `ret = self.export_metric(metric)`. */
  private predicate isDispatchedMetricCall(Call c) {
    c.getFunc().(Attribute).getName() = "export_metric" and
    at(c.getLocation(), "slo_generator/exporters/base.py", 109)
  }

  /**
   * Family 1: backend dispatch glue. Taint on the `config` argument
   * (positional index 2) of the getattr-dispatched backend call flows into
   * the `slo_config` parameter of every labeled backend interface method.
   */
  private predicate backendDispatchStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Function f, Parameter p, Expr arg |
      isDispatchedBackendCall(c) and
      arg = c.getArg(2) and
      f.getArg(3) = p and
      p.getName() = "slo_config" and
      (
        // S057 (candidate, 0.50): CloudMonitoringBackend.good_bad_ratio
        (f.getName() = "good_bad_ratio" and at(p.getLocation(), "slo_generator/backends/cloud_monitoring.py", 46))
        or
        // S063 (candidate, 0.50): CloudServiceMonitoringBackend.good_bad_ratio
        (f.getName() = "good_bad_ratio" and at(p.getLocation(), "slo_generator/backends/cloud_service_monitoring.py", 61))
        or
        // S096 (unknown, 0.45): samples/custom CustomBackend.good_bad_ratio
        (f.getName() = "good_bad_ratio" and at(p.getLocation(), "samples/custom/custom_backend.py", 28))
        or
        // S099 (unknown, 0.45): samples/custom CustomBackend.query_sli
        (f.getName() = "query_sli" and at(p.getLocation(), "samples/custom/custom_backend.py", 41))
        or
        // S104 (candidate, 0.50): DatadogBackend.good_bad_ratio
        (f.getName() = "good_bad_ratio" and at(p.getLocation(), "slo_generator/backends/datadog.py", 45))
        or
        // S108 (candidate, 0.50): DatadogBackend.query_sli
        (f.getName() = "query_sli" and at(p.getLocation(), "slo_generator/backends/datadog.py", 80))
        or
        // S116 (candidate, 0.50): DynatraceBackend.query_sli
        (f.getName() = "query_sli" and at(p.getLocation(), "slo_generator/backends/dynatrace.py", 43))
        or
        // S120 (candidate, 0.50): DynatraceBackend.good_bad_ratio
        (f.getName() = "good_bad_ratio" and at(p.getLocation(), "slo_generator/backends/dynatrace.py", 64))
        or
        // S128 (candidate, 0.50): ElasticsearchBackend.good_bad_ratio
        (f.getName() = "good_bad_ratio" and at(p.getLocation(), "slo_generator/backends/elasticsearch.py", 44))
        or
        // S186 (candidate, 0.50): PrometheusBackend.query_sli
        (f.getName() = "query_sli" and at(p.getLocation(), "slo_generator/backends/prometheus.py", 43))
        or
        // S190 (candidate, 0.50): PrometheusBackend.good_bad_ratio
        (f.getName() = "good_bad_ratio" and at(p.getLocation(), "slo_generator/backends/prometheus.py", 61))
      ) and
      nodeFrom = DataFlow::exprNode(arg) and
      nodeTo = DataFlow::parameterNode(p)
    )
  }

  /**
   * Family 2: exporter dispatch glue. Taint on the `data` argument
   * (positional index 0) of the import-resolved exporter call flows into the
   * `data` parameter of every labeled exporter `export` method.
   */
  private predicate exporterDispatchStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Function f, Parameter p, Expr arg |
      isDispatchedExporterCall(c) and
      arg = c.getArg(0) and
      f.getArg(1) = p and
      p.getName() = "data" and
      (
        // S001 (candidate, 0.55): MetricsExporter.export (abstract base)
        (f.getName() = "export" and at(p.getLocation(), "slo_generator/exporters/base.py", 70))
        or
        // S007 (candidate, 0.50): BigqueryExporter.export
        (f.getName() = "export" and at(p.getLocation(), "slo_generator/exporters/bigquery.py", 37))
        or
        // S101 (unknown, 0.45): samples/custom CustomSLOExporter.export
        (f.getName() = "export" and at(p.getLocation(), "samples/custom/custom_exporter.py", 44))
        or
        // S195 (candidate, 0.50): PubsubExporter.export
        (f.getName() = "export" and at(p.getLocation(), "slo_generator/exporters/pubsub.py", 34))
      ) and
      nodeFrom = DataFlow::exprNode(arg) and
      nodeTo = DataFlow::parameterNode(p)
    )
  }

  /**
   * Family 3: metrics dispatch glue. Taint on the `metric` argument
   * (positional index 0) of the abstract-base-class dispatch flows into the
   * `data` parameter of every labeled `export_metric` implementation.
   */
  private predicate metricDispatchStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Function f, Parameter p, Expr arg |
      isDispatchedMetricCall(c) and
      arg = c.getArg(0) and
      f.getArg(1) = p and
      p.getName() = "data" and
      (
        // S006 (candidate, 0.50): MetricsExporter.export_metric (abstract)
        (f.getName() = "export_metric" and at(p.getLocation(), "slo_generator/exporters/base.py", 225))
        or
        // S060 (candidate, 0.50): CloudMonitoringExporter.export_metric
        (f.getName() = "export_metric" and at(p.getLocation(), "slo_generator/exporters/cloud_monitoring.py", 36))
        or
        // S100 (unknown, 0.45): samples/custom CustomMetricExporter.export_metric
        (f.getName() = "export_metric" and at(p.getLocation(), "samples/custom/custom_exporter.py", 26))
        or
        // S112 (candidate, 0.50): DatadogExporter.export_metric
        (f.getName() = "export_metric" and at(p.getLocation(), "slo_generator/exporters/datadog.py", 42))
        or
        // S113 (candidate, 0.50): DynatraceExporter.export_metric
        (f.getName() = "export_metric" and at(p.getLocation(), "slo_generator/exporters/dynatrace.py", 42))
        or
        // S194 (candidate, 0.50): PrometheusExporter.export_metric
        (f.getName() = "export_metric" and at(p.getLocation(), "slo_generator/exporters/prometheus.py", 37))
      ) and
      nodeFrom = DataFlow::exprNode(arg) and
      nodeTo = DataFlow::parameterNode(p)
    )
  }

  /**
   * Family 4: re.sub string transformation in the config name-derivation
   * helpers (utils.py:320 import_cls filename, :362 capitalize, :374
   * snake_to_caml, :386 caml_to_snake). Taint on the input string
   * (positional argument 2) flows to the transformation result, mirroring
   * the default taint steps that exist for string methods.
   */
  private predicate reSubStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute fn, Expr arg |
      c.getFunc() = fn and
      fn.getName() = "sub" and
      fn.getObject().(Name).getId() = "re" and
      inFile(c.getLocation(), "slo_generator/utils.py") and
      c.getLocation().getStartLine() in [320, 362, 374, 386] and
      arg = c.getArg(2) and
      nodeFrom = DataFlow::exprNode(arg) and
      nodeTo = DataFlow::exprNode(c)
    )
  }

  /**
   * Holds if taint may additionally flow from `nodeFrom` to `nodeTo` for the
   * given pass. Only pass "command_injection" (Pass 2 / CWE-78) is enabled.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "command_injection" and
    (
      backendDispatchStep(nodeFrom, nodeTo)
      or
      exporterDispatchStep(nodeFrom, nodeTo)
      or
      metricDispatchStep(nodeFrom, nodeTo)
      or
      reSubStep(nodeFrom, nodeTo)
    )
  }
}
