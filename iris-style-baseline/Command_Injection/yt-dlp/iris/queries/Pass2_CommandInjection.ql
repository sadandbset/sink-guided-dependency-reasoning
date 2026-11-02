/**
 * @name Pass 2: Command/Argument Injection (CWE-78)
 * @description Tracks yt-dlp's external input boundaries — remote decode/fetch
 *   results (json.loads, the factory-generated _download_* extractor methods,
 *   .read()/.recv()/urlopen results), file inputs (open, cookie jars, config
 *   files, info.json) and the CLI/env/config surface (sys.argv, parse_args,
 *   get_param, _configuration_args, the command-relevant opts.* templates) —
 *   into process execution: the three shell=True string-command sites
 *   (postprocessor/exec.py:31 --exec, extractor/common.py:1311 --netrc-cmd,
 *   update.py:376 Windows updater delayed delete) and the non-shell argv-list
 *   sites of the yt_dlp.utils.Popen wrapper and the internal ffmpeg/external-
 *   downloader/rtmpdump/xattr builders. Sources, sinks, barriers and additional
 *   taint steps are rendered from the human-reviewed pass-2 labels in
 *   iris/labels/labels.json (run yt-dlp-pass2-cwe78-20261019): 64 formal source
 *   signatures, 12 candidate sink signatures, an empty confirmed sanitizer set
 *   (no quoting/escaping exists on any command path; the exec.py:24 shlex
 *   quoting covers only the legacy {} placeholder and common.py:1309
 *   substitutes netrc_machine unquoted), and 19 label-mandated summary steps.
 * @id py/augur/yt-dlp/pass2-command-injection
 * @kind path-problem
 * @problem.severity error
 * @precision medium
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
 * Pass 2 (CWE-78) flow configuration. The pass key "command_injection" selects
 * the reviewed label set: external input boundaries as sources, the 12
 * candidate command-execution sink signatures as sinks. The barrier predicate
 * always exists (WORKFLOW.md 5.2.3) — it delegates to MySanitizers, whose
 * confirmed set is EMPTY, so it resolves to none() and never blocks
 * unconditionally. Internal wrapper parameters (_real_extract url,
 * real_download info_dict, PostProcessor.run info) are deliberately NOT
 * sources here; their propagation to the sinks is verified by the separate
 * diagnostics query (diagnostics/Pass2_WrapperPropagation.ql) whose results
 * are not formal findings.
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
  "Command injection: untrusted input (remote content, file input or CLI/config " +
  "value) flows into a process execution API " +
  "(shell command string or child-process argv) without quoting or validation."
