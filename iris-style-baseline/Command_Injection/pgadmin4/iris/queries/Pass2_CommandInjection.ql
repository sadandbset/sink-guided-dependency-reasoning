/**
 * @name Pass 2: Command/Argument Injection (CWE-78)
 * @description Tracks pgAdmin 4's reviewed attacker-controlled inputs (Flask
 *   HTTP request state and field reads, the json.loads request-body decodes
 *   of the tool/browser endpoints, @blueprint.route URL path parameters,
 *   @sio.on /pty socket payloads, user import files, and the
 *   process_executor sys.argv command transport) into command-execution
 *   sites. Sources, sinks, barriers and additional taint steps are rendered
 *   from the human-reviewed labels in iris/labels/labels.json (run
 *   pgadmin4-iris-pass2-20261016, pass 2, classification tp only). The two
 *   confirmed (tp) sinks: misc/__init__.py:274 — subprocess.getoutput shell
 *   probe whose full_path derives from the validate_binary_path POST body
 *   (partial dquote-doubling + os.path.exists mitigations only) — and
 *   process_executor.py:330 — Popen over the BatchProcess command list
 *   (request-derived backup/restore/maintenance/import_export/cloud/view
 *   arguments) with the Windows shell=True toggle at :324; the only
 *   shell-relevant protection, escape_dquotes_process_arg, is #DQ# double-
 *   quote marker handling stripped in the executor, not shell quoting. The
 *   confirmed sanitizer set is empty (no shlex/quote/escape construct exists
 *   in the snapshot), so the barrier predicate resolves to none().
 * @id py/augur/pgadmin4/pass2-command-injection
 * @kind path-problem
 * @problem.severity error
 * @precision low
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

/**
 * Pass 2 (CWE-78) flow configuration. The pass key "command_injection"
 * selects the reviewed (tp) label set. The barrier predicate always exists
 * (WORKFLOW.md 5.2.3) — it delegates to MySanitizers, whose confirmed set is
 * EMPTY (no shlex.quote/pipes.quote/shlex.join anywhere in the snapshot;
 * escape_dquotes_process_arg is #DQ# marker handling, the dquote doubling
 * and os.path.exists gates are partial mitigations recorded in the sink
 * rationales, and PasswordExec.get's SERVER_MODE NotImplementedError is a
 * deployment-mode gate), so it resolves to none(); it never blocks
 * unconditionally.
 */
module Pass2Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "command_injection")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "command_injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "command_injection")
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "command_injection")
  }
}

module Pass2Flow = TaintTracking::Global<Pass2Config>;
import Pass2Flow::PathGraph

from Pass2Flow::PathNode source, Pass2Flow::PathNode sink
where Pass2Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Command injection: attacker-controlled value (HTTP request body/field, " +
  "URL path parameter, /pty socket payload, imported file content, or the " +
  "batch-job command transported through process_executor sys.argv) flows " +
  "into a command-execution site (shell command string via getoutput, or " +
  "the BatchProcess command list executed with shell=True on Windows)."
