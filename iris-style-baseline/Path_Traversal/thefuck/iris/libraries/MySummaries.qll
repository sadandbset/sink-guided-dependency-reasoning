/**
 * Augur Pass 1 (Path Traversal, CWE-022/023/036/073) additional taint-step
 * model for thefuck 3.30 (`thefuck_vuln` source tree).
 *
 * Generated in Phase 2 Step 4 from the reviewed Phase 1 labels
 * (`iris/labels/labels.json`, pass 1, run `iris-thefuck-pass1-step3-20261023`,
 * model glm-5.3): exactly the 3 reviewed `summary/tp` entries are rendered.
 * They bridge the `Command` object construction in `thefuck/types.py` to the
 * rule modules, which CodeQL cannot connect on its own:
 *
 *   1. p1-379 (types.py:69): `Command.from_raw_script(cls, raw_script)` -
 *      the raw CLI/env command words become the `Command` script. The
 *      intermediate `shell.from_shell(script)` (`types.py:81`) dispatches
 *      through the `shell` module variable, which `shells/__init__.py`
 *      assigns at import time from the `TF_SHELL` environment (Bash/Zsh/
 *      Tcsh/Fish/... chosen dynamically), so the call target is not
 *      statically resolvable.
 *   2. p1-377 (types.py:16, `script` param): `Command.__init__(self, script,
 *      output)` stores `self.script` (`types.py:23`); rule modules read it
 *      back as `command.script` and `command.script_parts` (the
 *      `script_parts` property at `types.py:37-46` splits `self.script`).
 *      The store/load edge crosses the DYNAMICALLY INVOKED rule functions:
 *      rules are loaded with `imp.load_source` (`types.py:144`) and called
 *      as `self.match(command)` (`types.py:181`),
 *      `self.get_new_command(command)` (`:193`) and
 *      `self.side_effect(old_cmd, self.script)` (`:255`) - callees CodeQL
 *      cannot resolve.
 *   3. p1-378 (types.py:16, `output` param): same store/load edge for
 *      `self.output` (`types.py:24`) read back as `command.output` /
 *      `old_cmd.output` inside the rules.
 *
 * Every edge binds BOTH endpoints to concrete nodes proven in the source
 * (function parameters and attribute reads on the `command`/`old_cmd`/`cmd`
 * variables inside `thefuck.rules.*`); no arbitrary node-to-node step is
 * created. Steps already covered natively (e.g. argument-to-parameter flow
 * into `Command.from_raw_script`, `re.findall` result taint - modeled by
 * python-all 7.1.2 `Stdlib.qll` "re" summaries - and for-loop/tuple-
 * unpacking iteration) are deliberately NOT duplicated here.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {

  /**
   * Holds if taint may additionally flow from `nodeFrom` to `nodeTo` for
   * pass key `path_traversal`. Renders exactly the three reviewed summary
   * labels (p1-377, p1-378, p1-379).
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    (
      rawScriptToCommandScriptStep(nodeFrom, nodeTo)
      or commandScriptToRuleFieldReadsStep(nodeFrom, nodeTo)
      or commandOutputToRuleFieldReadsStep(nodeFrom, nodeTo)
    )
  }

  /**
   * Holds if `n` occurs in the module named `moduleName`.
   */
  private predicate inModule(AstNode n, string moduleName) {
    n.getScope().getEnclosingModule().getName() = moduleName
  }

  /**
   * The `Command.__init__(self, script, output)` function in
   * `thefuck/types.py`. `thefuck.types` contains three `__init__` functions
   * (Command, Rule, CorrectedCommand); requiring BOTH a `script` and an
   * `output` parameter pins this to `Command.__init__` (Rule has name/match/
   * ... and CorrectedCommand has script/side_effect/priority).
   */
  private predicate isCommandInit(Function f) {
    f.getName() = "__init__" and
    inModule(f, "thefuck.types") and
    exists(Parameter scriptParam | scriptParam = f.getArgByName("script")) and
    exists(Parameter outputParam | outputParam = f.getArgByName("output"))
  }

  /**
   * p1-379 (summary/tp, 0.70): the `raw_script` parameter of
   * `Command.from_raw_script(cls, raw_script)` (`types.py:69`) taints the
   * `script` parameter of `Command.__init__` (`types.py:16`).
   *
   * Source evidence for the bridge (`types.py:77-83`):
   *   script = format_raw_script(raw_script)      // utils.py, resolvable
   *   expanded = shell.from_shell(script)         // dynamic dispatch
   *   output = get_output(script, expanded)       // dynamic reader choice
   *   return cls(expanded, output)                // -> __init__(script, output)
   * The `shell.from_shell` target is selected at import time in
   * `shells/__init__.py` from the `TF_SHELL` environment, so this step is
   * not natively resolvable and needs the explicit edge.
   */
  private predicate rawScriptToCommandScriptStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function fromRawScript, Parameter rawScript, Function init, Parameter scriptParam |
      fromRawScript.getName() = "from_raw_script" and
      inModule(fromRawScript, "thefuck.types") and
      rawScript = fromRawScript.getArgByName("raw_script") and
      isCommandInit(init) and
      scriptParam = init.getArgByName("script") and
      nodeFrom = DataFlow::parameterNode(rawScript) and
      nodeTo = DataFlow::parameterNode(scriptParam)
    )
  }

  /**
   * p1-377 (summary/tp, 0.70): the `script` parameter of
   * `Command.__init__` (`types.py:16`, stored to `self.script` at :23,
   * re-exposed as `command.script_parts` by the property at :37-46) taints
   * the `command.script` / `command.script_parts` attribute reads inside
   * `thefuck.rules.*`.
   *
   * The rule functions receive the `Command` instance exclusively through
   * the dynamic calls at `types.py:181/:193/:255`
   * (`self.match(command)`, `self.get_new_command(command)`,
   * `self.side_effect(old_cmd, self.script)`), whose callees are
   * `imp.load_source`-loaded modules - unresolvable by CodeQL. The read
   * side is therefore restricted to attribute reads on the conventional
   * `command`/`old_cmd`/`cmd` receiver names inside `thefuck.rules.*`,
   * matching the reviewed label rationale.
   */
  private predicate commandScriptToRuleFieldReadsStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function init, Parameter scriptParam, Attribute a |
      isCommandInit(init) and
      scriptParam = init.getArgByName("script") and
      nodeFrom = DataFlow::parameterNode(scriptParam) and
      a.getName() in ["script", "script_parts"] and
      a.getObject().(Name).getId() in ["command", "old_cmd", "cmd"] and
      a.getScope().getEnclosingModule().getName().matches("thefuck.rules.%") and
      nodeTo = DataFlow::exprNode(a)
    )
  }

  /**
   * p1-378 (summary/tp, 0.70): the `output` parameter of
   * `Command.__init__` (`types.py:16`, stored to `self.output` at :24)
   * taints the `command.output` / `old_cmd.output` attribute reads inside
   * `thefuck.rules.*` (same dynamic-invocation gap as above).
   */
  private predicate commandOutputToRuleFieldReadsStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function init, Parameter outputParam, Attribute a |
      isCommandInit(init) and
      outputParam = init.getArgByName("output") and
      nodeFrom = DataFlow::parameterNode(outputParam) and
      a.getName() = "output" and
      a.getObject().(Name).getId() in ["command", "old_cmd", "cmd"] and
      a.getScope().getEnclosingModule().getName().matches("thefuck.rules.%") and
      nodeTo = DataFlow::exprNode(a)
    )
  }
}
