/**
 * Augur-generated sink library - Pass 2 (CWE-078) for AutoGluon.
 *
 * Generated from iris/labels/labels.json (run_id autogluon-pass2-phase1-20261012).
 *
 * Effective sink labels (both render to ONE deduplicated signature-level rule):
 *   - p2-sink-002: subprocess.check_output(arg 0), sync_remote.py:50,
 *                  sink/tp, confidence 0.90
 *   - p2-sink-003: subprocess.check_output(arg 0), sync_remote.py:52,
 *                  sink/tp, confidence 0.90
 *
 * Excluded by design (role=none in the labels; do NOT turn every check_output
 * call into an equally dangerous sink):
 *   - sync_remote.py:16   Popen(["/usr/sbin/sshd", "-D"])          - fixed literal list, no shell
 *   - utils.py:890        check_output(COMMAND.split())            - fixed nvidia-smi literal, no shell
 *   - 9x tests/test_check_style.py Popen(['flake8', ...])          - test files, fixed literal list, no shell
 *
 * The rendered rule is intentionally narrow: it matches only
 * subprocess.check_output calls that (a) pass a literal shell=True keyword,
 * (b) occur in core/src/autogluon/core/utils/sync_remote.py. In this
 * repository those constraints resolve exactly to the two labeled call sites
 * (lines 50 and 52), which are the only shell-enabled command executions in
 * the entire codebase.
 */

private import python
private import semmle.python.ApiGraphs
private import semmle.python.dataflow.new.DataFlow

module MySinks {
  /**
   * Matches subprocess.check_output calls with shell=True in
   * core/src/autogluon/core/utils/sync_remote.py.
   * Labels: p2-sink-002 (line 50), p2-sink-003 (line 52) - one rule, two
   * locations, both flagged sink/tp with the exploitability caveat recorded
   * in the label rationale (in-repo callers pass fixed literals).
   */
  predicate isShellEnabledCheckOutputCall(DataFlow::CallCfgNode call) {
    call = API::moduleImport("subprocess").getMember("check_output").getACall() and
    call.getLocation().getFile().getRelativePath() =
      "core/src/autogluon/core/utils/sync_remote.py" and
    // Require the literal keyword argument shell=True
    exists(DataFlow::Node shellArg |
      shellArg = call.getArgByName("shell") and
      shellArg.asExpr() instanceof True
    )
  }

  /**
   * The dangerous input position of the labeled sink: argument 0 (the command
   * string, an f-string interpolating proccess_id_string at lines 50 and 52).
   */
  predicate isShellCommandSinkArg(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call |
      isShellEnabledCheckOutputCall(call) and
      sink = call.getArg(0)
    )
  }

  /**
   * v2 post-triage remediation (label p2-sink-013): unsafe YAML
   * deserialization sink - the project's actual code-execution boundary,
   * invisible to the v1 model (which covered only subprocess shell=True).
   *
   * yaml.load(f, Loader=yaml.Loader) in _top_k_average
   * (multimodal/src/autogluon/multimodal/predictor.py:1124): PyYAML's
   * yaml.Loader is the UNSAFE full loader - it constructs arbitrary Python
   * objects from !!python/* tags while parsing, so deserializing a crafted
   * best_k_models.yaml executes code in the autogluon process (CWE-502-class
   * mechanism; the CWE-78-recorded impact). Verified as the ONLY unsafe
   * yaml.load in the entire DB source archive. The taint-relevant event is
   * the stream argument (arg 0) reaching the unsafe loader.
   *
   * Line anchors are CodeQL-DB-version lines (DB created at the vulnerable
   * parent sha 1a62b445 of fix commit 23a37e7, which changes exactly this
   * line to yaml.safe_load(f); the disk working tree is checked out at the
   * fixed commit).
   */
  predicate unsafeYamlLoadSink(DataFlow::Node sink) {
    exists(Call c, Attribute fn, Keyword kw, Attribute loader |
      fn = c.getFunc() and
      fn.getName() = "load" and
      fn.getObject().(Name).getId() = "yaml" and
      kw = c.getANamedArg() and
      kw.getArg() = "Loader" and
      loader = kw.getValue() and
      loader.getObject() instanceof Name and
      (
        loader.getName() = "Loader"
        or
        loader.getName() = "UnsafeLoader"
        or
        loader.getName() = "FullLoader"
      ) and
      c.getLocation().getFile().getRelativePath() =
        "multimodal/src/autogluon/multimodal/predictor.py" and
      c.getLocation().getStartLine() = 1124 and
      sink = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * Pass-key dispatch used by generated pass queries.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "command_injection" and
    (
      isShellCommandSinkArg(sink)
      or
      unsafeYamlLoadSink(sink)
    )
  }
}
