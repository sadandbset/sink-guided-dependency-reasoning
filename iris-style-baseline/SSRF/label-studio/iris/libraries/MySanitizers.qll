/**
 * Augur Phase 2 - Pass 3 (CWE-918 SSRF) sanitizer (barrier) library for
 * label-studio. Generated from reviewed labels: iris/labels/labels.json (pass 3,
 * 2 supplementary sanitizer entries, both classification=candidate).
 *
 * Label -> predicate mapping (barrier node = argument 0 of the guard call):
 *   p3-supp-001 core/utils/io.py:172 validate_upload_url:
 *     - call site label_studio/core/utils/io.py:221 (inside ssrf_safe_get,
 *       block_local_urls=settings.SSRF_PROTECTION_ENABLED)
 *     - call site label_studio/ml/serializers.py:11
 *       (MLBackendSerializer.validate_url,
 *       block_local_urls=settings.ML_BLOCK_LOCAL_IP)
 *   p3-supp-002 core/utils/io.py:199 validate_ip: NO barrier node is emitted.
 *     Its argument is the DNS-resolved IP string (socket.gethostbyname result,
 *       io.py:189 / response peer address, io.py:228), which never lies on a
 *       URL data-flow path; modeling it would be an unevidenced barrier.
 *
 * Reviewed effectiveness of validate_upload_url (phase1_review.md section 4):
 *   - http/https scheme rejection is UNCONDITIONAL (io.py:184-185) - it blocks
 *     file:/data: and other cross-protocol targets for both reviewed flows;
 *   - private-IP blocking (0.0.0.0, 127/8, 10/8, 172.16/12, 192.168/16) is
 *     conditional: gated by SSRF_PROTECTION_ENABLED (default False,
 *     core/settings/base.py:405) for import URLs and ML_BLOCK_LOCAL_IP
 *     (default False, base.py:601) for ML backend URLs;
 *   - even when enabled it misses IPv6 loopback/ULA, IPv6-mapped IPv4,
 *     link-local 169.254.169.254 (cloud metadata) and CGNAT 100.64/10, and
 *     resolves DNS separately from the fetch (TOCTOU; only partially mitigated
 *     by ssrf_safe_get's post-connection peer re-check, itself default-off).
 *
 * Semantics and deliberate limitation (same as the reviewed recommendation):
 * isBarrier(n) removes node `n` from the flow graph. The barrier here is the
 * checked URL argument at each guard call site. The downstream fetch uses a
 * different AST node for the same variable, so this placement marks the guard
 * without pruning the fetch path - which is intentional: with both gating
 * settings defaulting to False, the private-IP component of the guard is NOT
 * an effective neutralization and must not suppress the reviewed default-
 * configuration flows. No unevidenced sanitizer is modeled; Django/DRF
 * authentication, URLField syntax checks and permission decorators are
 * deliberately NOT barriers (per label review - they limit attacker identity,
 * not URL control).
 *
 * Verified against codeql/python-all 7.1.2 (Call.getArg(int)/getFunc(),
 * Attribute.getName(), File.getRelativePath(), Location.getStartLine();
 * matches() patterns are string literals only).
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /* ------------------------------------------------------------------
   * Public interface (pass key: "ssrf")
   * ------------------------------------------------------------------ */

  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "ssrf" and guardCheckedArg(node)
  }

  /* ------------------------------------------------------------------
   * Barrier sites: the checked URL argument of each reviewed
   * validate_upload_url guard call (label p3-supp-001)
   * ------------------------------------------------------------------ */

  private predicate guardCheckedArg(DataFlow::Node node) {
    // p3-supp-001, call site 1: ssrf_safe_get -> validate_upload_url(url, ...)
    // (core/utils/io.py:221, block_local_urls=settings.SSRF_PROTECTION_ENABLED)
    exists(Call c, Attribute func |
      c.getLocation().getFile().getRelativePath().matches("label_studio/core/utils/io.py") and
      c.getLocation().getStartLine() = 221 and
      func = c.getFunc() and
      func.getName() = "validate_upload_url" and
      node = DataFlow::exprNode(c.getArg(0))
    )
    or
    // p3-supp-001, call site 2: MLBackendSerializer.validate_url ->
    // validate_upload_url(value, block_local_urls=settings.ML_BLOCK_LOCAL_IP)
    // (ml/serializers.py:11)
    exists(Call c, Attribute func |
      c.getLocation().getFile().getRelativePath().matches("label_studio/ml/serializers.py") and
      c.getLocation().getStartLine() = 11 and
      func = c.getFunc() and
      func.getName() = "validate_upload_url" and
      node = DataFlow::exprNode(c.getArg(0))
    )
  }
}
