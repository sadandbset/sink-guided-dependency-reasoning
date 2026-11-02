/**
 * Augur-generated source library - Pass 2 (CWE-078) for AutoGluon.
 *
 * Generated from iris/labels/labels.json (run_id autogluon-pass2-phase1-20261012,
 * generated 2026-10-12, reviewed labels). Only role=source label entries are
 * rendered here. The 6453 role=none entries are deliberately NOT part of the
 * model (see iris/report/query_generation_notes.md).
 *
 * All rendered source labels are classification=candidate: they are input
 * boundaries with code evidence, but NOT confirmed attacker-controlled input.
 * The model is therefore split into a strict and a diagnostic variant:
 *
 *   - isSourceStrict:    external environment-variable reads. Used by the
 *                        formal pass-2 query (Pass2_CommandInjection.ql).
 *   - isSourceSyncTrainingProcessId: label p2-src-4863 only. Used by the
 *                        diagnostic query (Pass2_DiagnosticParameter.ql).
 *   - isSourceDiagnostic: strict + p2-src-4863 + the four argparse-fed
 *                        main(args) parameters. Diagnostic use only.
 *
 * Label provenance:
 *   - p2-supp-001: os.environ["SM_CURRENT_HOST"], sync_remote.py:13,
 *                  source/candidate, confidence 0.50
 *   - p2-supp-002: os.environ["SM_HOSTS"], sync_remote.py:14,
 *                  source/candidate, confidence 0.50
 *   - p2-src-4863: sync_training_processes.proccess_id_string (arg 0),
 *                  sync_remote.py:46, source/candidate, confidence 0.50
 *   - p2-src-0971: main(args) (arg 0), examples/automm/distillation/
 *                  automm_distillation.py:19, source/candidate, confidence 0.45
 *   - p2-src-1912: main(args) (arg 0), examples/automm/tabular_dl/
 *                  example_tabular.py:55, source/candidate, confidence 0.45
 *   - p2-src-2326: main(args) (arg 0), examples/text_prediction/
 *                  generate_submission.py:24, source/candidate, confidence 0.45
 *   - p2-src-4091: main(args) (arg 0), examples/text_prediction/
 *                  prepare_glue.py:614, source/candidate, confidence 0.45
 */

private import python
private import semmle.python.ApiGraphs
private import semmle.python.dataflow.new.DataFlow

module MySources {
  /**
   * Strict source model. Environment-variable reads are a genuine external
   * input boundary (values are set by the SageMaker platform context), and the
   * two reads below are the only external inputs that co-locate with the
   * pass-2 sink file. They are still label candidates (confidence 0.50):
   * a query hit from these sources means "external environment data reached a
   * shell command", not "confirmed attacker control".
   *
   * Labels: p2-supp-001, p2-supp-002 (signature os.environ.__getitem__,
   * flow_kind return; the two locations are the only reads of these keys in
   * the repository, so the signature-level rule and the labeled locations
   * coincide).
   */
predicate isSourceStrict(DataFlow::Node source) {
  source =
    API::moduleImport("os")
      .getMember("environ")
      .getSubscript("SM_CURRENT_HOST")
      .asSource()
  or
  source =
    API::moduleImport("os")
      .getMember("environ")
      .getSubscript("SM_HOSTS")
      .asSource()
}

  /**
   * Label p2-src-4863 only: the parameter proccess_id_string (arg 0) of the
   * module-level function sync_training_processes in sync_remote.py. This
   * parameter is interpolated into the shell=True command strings at
   * sync_remote.py:50 and :52, so it is the only realistic taint entry for
   * the pass-2 sink - but the sole in-repo caller passes the fixed literal
   * 'dask-scheduler' and the module __all__ only exports sagemaker_setup.
   * Diagnostic use only; a hit does NOT prove external attacker control.
   */
  predicate isSourceSyncTrainingProcessId(DataFlow::Node source) {
    exists(Function f, Parameter p |
      f.getName() = "sync_training_processes" and
      p = f.getArg(0) and
      p.getName() = "proccess_id_string" and
      p.getLocation().getFile().getRelativePath() =
        "core/src/autogluon/core/utils/sync_remote.py" and
      source = DataFlow::parameterNode(p)
    )
  }

  /**
   * Diagnostic source model: strict model plus p2-src-4863 and the four
   * argparse-fed main(args) CLI boundaries. For diagnostic taint tracking
   * only; results must not be reported as confirmed vulnerabilities.
   */
  predicate isSourceDiagnostic(DataFlow::Node source) {
    isSourceStrict(source)
    or
    isSourceSyncTrainingProcessId(source)
    or
    exists(Function f, Parameter p |
      f.getName() = "main" and
      p = f.getArg(0) and
      p.getName() = "args" and
      source = DataFlow::parameterNode(p) and
      (
        // p2-src-0971
        p.getLocation().getFile().getRelativePath() =
          "examples/automm/distillation/automm_distillation.py"
        or
        // p2-src-1912
        p.getLocation().getFile().getRelativePath() =
          "examples/automm/tabular_dl/example_tabular.py"
        or
        // p2-src-2326
        p.getLocation().getFile().getRelativePath() =
          "examples/text_prediction/generate_submission.py"
        or
        // p2-src-4091
        p.getLocation().getFile().getRelativePath() =
          "examples/text_prediction/prepare_glue.py"
      )
    )
  }

  /**
   * v2 post-triage remediation (label p2-supp-004): file-content boundary
   * feeding the unsafe YAML deserialization sink (label p2-sink-013).
   *
   * open(best_k_models_yaml_path, "r") in _top_k_average
   * (multimodal/src/autogluon/multimodal/predictor.py:1123) - the
   * best_k_models.yaml artifact file whose content is deserialized one line
   * later by yaml.load(f, Loader=yaml.Loader). An attacker controlling the
   * model-artifact directory (e.g. a shared/untrusted predictor checkpoint
   * folder) controls the YAML stream entirely.
   *
   * Line anchors are CodeQL-DB-version lines: the database was created at
   * sha 1a62b445 (the vulnerable parent of fix commit 23a37e7); the disk
   * working tree is checked out at the fixed commit, where this location
   * already reads yaml.safe_load.
   */
  predicate isSourceFileContent(DataFlow::Node source) {
    exists(Call c |
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "open" and
      c.getLocation().getFile().getRelativePath() =
        "multimodal/src/autogluon/multimodal/predictor.py" and
      c.getLocation().getStartLine() = 1123 and
      source = DataFlow::exprNode(c)
    )
  }

  /**
   * Pass-key dispatch used by generated pass queries. For pass 2
   * ("command_injection") this resolves to the STRICT model plus the v2
   * remediation file-content source (p2-supp-004), keeping the unconfirmed
   * candidates of the diagnostic model out of the formal query.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "command_injection" and
    (
      isSourceStrict(source)
      or
      isSourceFileContent(source)
    )
  }
}
