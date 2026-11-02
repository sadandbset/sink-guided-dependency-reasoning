/**
 * Augur Phase 2 - Pass 3 (CWE-918 SSRF) source library for label-studio.
 * Generated from reviewed labels: iris/labels/labels.json (pass 3, 143 source
 * entries: 14 tp + 129 candidate; model glm-5.3, 2026-10-20, human-review gate
 * iris/labels/phase1_review.md - labels/review_decision.json is absent, so the
 * run follows the WORKFLOW automated-mode rule and treats phase1_review.md as
 * the review record).
 *
 * Label-family -> predicate mapping (all 143 source-role entries are covered):
 *   request_field (128 entries: request.data 48 / request.GET 47 /
 *                  request.query_params 14 / request.FILES 8 / request.POST 5 /
 *                  request.META 4 / request.body 2, incl. self.request.<field>)
 *                  -> requestFieldRead:  `request.<field>` / `self.request.<field>`
 *                     attribute reads in application (non-test, non-migration) code.
 *                     tp rows: p3-src-251 (data_import/uploader.py:239, import URL),
 *                     p3-src-031/032 (data_import/api.py:280/282, async import URL),
 *                     p3-src-064/065 (io_storages/api.py:142/150, storage config).
 *   webhook_field (2 tp)      -> webhookFieldRead:   webhook.url / webhook.headers
 *                                reads at webhooks/utils.py:53/54 (DB-mediated).
 *   ml_self_url (4 tp)        -> mlBackendUrlRead:   self.url at ml/models.py:115/118/122/325
 *                                (p3-src-218..221; the __str__-only read at :97 was
 *                                reviewed role=none and is NOT a source).
 *   s3_endpoint (2 tp)        -> s3EndpointRead:     self.s3_endpoint at
 *                                io_storages/s3/models.py:66/186 (p3-src-214/215; the
 *                                cache-key-only read at :57 was reviewed role=none).
 *   redis_field (6 candidate) -> redisFieldRead:     self.host/.port/.password at
 *                                io_storages/redis/models.py:64-69 (p3-src-222..227;
 *                                kept because the fields are reviewed sources even
 *                                though the Redis sink is deferred, see MySinks).
 *   ml_validate_url_param (1 tp) -> mlValidateUrlParam: `value` parameter of
 *                                MLBackendSerializer.validate_url (ml/serializers.py:10,
 *                                p3-src-235) - framework-dispatched DRF field hook.
 *
 * NOT sources (per review; deliberately excluded):
 *   - all get_env / os.environ.get / os.getenv rows (137 entries) - operator env config;
 *   - all sys.argv rows (4 entries) - local CLI boundary;
 *   - tasks_from_url's `url` parameter (uploader.py:125) and every other internal
 *     wrapper parameter: taint reaches them via ordinary interprocedural flow from
 *     the request_field sources, so modeling them would double-count.
 *
 * Trust boundaries (per label rationales): every source requires authentication.
 * request_field inputs are writable by any DRF-authenticated user reaching the
 * given view (import/storage/ML endpoints additionally require projects_change,
 * i.e. project-collaborator, NOT admin); webhook url/headers are writable by any
 * authenticated organization member; no anonymous/unauthenticated source exists
 * in this application. Authentication limits attacker identity, not value control.
 *
 * Scope guard mirrors the Phase 1 extraction scope exactly (label_studio/% minus
 * tests, per-app tests.py, migrations, examples), so the predicate matches the
 * reviewed candidate set and nothing else.
 *
 * Verified against codeql/python-all 7.1.2 (DataFlow::exprNode/parameterNode,
 * Attribute.getName()/getObject(), Name.getId(), Function.getName()/
 * getArgByName(), File.getRelativePath(), Location.getStartLine(); matches()
 * patterns are string literals only, as required by the QL binding rules).
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySources {

  /* ------------------------------------------------------------------
   * Public interface (pass key: "ssrf")
   * ------------------------------------------------------------------ */

  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "ssrf" and
    (
      requestFieldRead(source)
      or webhookFieldRead(source)
      or mlBackendUrlRead(source)
      or s3EndpointRead(source)
      or redisFieldRead(source)
      or mlValidateUrlParam(source)
    )
  }

  /* ------------------------------------------------------------------
   * request_field family: request.<field> / self.request.<field>
   * ------------------------------------------------------------------ */

  private predicate requestFieldRead(DataFlow::Node source) {
    exists(Attribute a |
      isRequestFieldAttribute(a) and
      source = DataFlow::exprNode(a)
    )
  }

  /** Holds if `a` is a DRF/Django request-object field read inside application code. */
  private predicate isRequestFieldAttribute(Attribute a) {
    a.getName() in ["data", "GET", "POST", "FILES", "META", "body", "query_params"] and
    (
      a.getObject() instanceof Name and a.getObject().(Name).getId() = "request"
      or
      a.getObject() instanceof Attribute and
      a.getObject().(Attribute).getName() = "request" and
      a.getObject().(Attribute).getObject() instanceof Name and
      a.getObject().(Attribute).getObject().(Name).getId() = "self"
    ) and
    inAppScope(a)
  }

  /* ------------------------------------------------------------------
   * webhook_field family: webhook.url / webhook.headers (p3-src-258/259)
   * ------------------------------------------------------------------ */

  private predicate webhookFieldRead(DataFlow::Node source) {
    exists(Attribute a |
      a.getObject() instanceof Name and a.getObject().(Name).getId() = "webhook" and
      a.getLocation().getFile().getRelativePath().matches("label_studio/webhooks/utils.py") and
      a.getLocation().getStartLine() = 53 and
      a.getName() = "url" and
      source = DataFlow::exprNode(a)
    )
    or
    exists(Attribute a |
      a.getObject() instanceof Name and a.getObject().(Name).getId() = "webhook" and
      a.getLocation().getFile().getRelativePath().matches("label_studio/webhooks/utils.py") and
      a.getLocation().getStartLine() = 54 and
      a.getName() = "headers" and
      source = DataFlow::exprNode(a)
    )
  }

  /* ------------------------------------------------------------------
   * ml_self_url family: MLBackend self.url (p3-src-218..221)
   * ------------------------------------------------------------------ */

  private predicate mlBackendUrlRead(DataFlow::Node source) {
    exists(Attribute a |
      a.getName() = "url" and
      a.getObject() instanceof Name and a.getObject().(Name).getId() = "self" and
      a.getLocation().getFile().getRelativePath().matches("label_studio/ml/models.py") and
      a.getLocation().getStartLine() in [115, 118, 122, 325] and
      source = DataFlow::exprNode(a)
    )
  }

  /* ------------------------------------------------------------------
   * s3_endpoint family: S3Storage self.s3_endpoint (p3-src-214/215)
   * ------------------------------------------------------------------ */

  private predicate s3EndpointRead(DataFlow::Node source) {
    exists(Attribute a |
      a.getName() = "s3_endpoint" and
      a.getObject() instanceof Name and a.getObject().(Name).getId() = "self" and
      a.getLocation().getFile().getRelativePath().matches("label_studio/io_storages/s3/models.py") and
      a.getLocation().getStartLine() in [66, 186] and
      source = DataFlow::exprNode(a)
    )
  }

  /* ------------------------------------------------------------------
   * redis_field family: RedisStorage self.host/.port/.password
   * (p3-src-222..227; candidate labels, sink deferred - see MySinks)
   * ------------------------------------------------------------------ */

  private predicate redisFieldRead(DataFlow::Node source) {
    exists(Attribute a |
      a.getName() in ["host", "port", "password"] and
      a.getObject() instanceof Name and a.getObject().(Name).getId() = "self" and
      a.getLocation().getFile().getRelativePath().matches("label_studio/io_storages/redis/models.py") and
      a.getLocation().getStartLine() in [64, 65, 66, 67, 68, 69] and
      source = DataFlow::exprNode(a)
    )
  }

  /* ------------------------------------------------------------------
   * ml_validate_url_param family: MLBackendSerializer.validate_url
   * `value` parameter (p3-src-235)
   * ------------------------------------------------------------------ */

  private predicate mlValidateUrlParam(DataFlow::Node source) {
    exists(Function f |
      f.getName() = "validate_url" and
      f.getLocation().getFile().getRelativePath().matches("label_studio/ml/serializers.py") and
      f.getLocation().getStartLine() = 10 and
      source = DataFlow::parameterNode(f.getArgByName("value"))
    )
  }

  /* ------------------------------------------------------------------
   * Shared scope guard (identical to the Phase 1 extraction scope)
   * ------------------------------------------------------------------ */

  private predicate inAppScope(AstNode n) {
    exists(string path |
      path = n.getLocation().getFile().getRelativePath() and
      path.matches("label_studio/%") and
      not path.matches("label_studio/tests/%") and
      not path.matches("label_studio/%/tests.py") and
      not path.matches("label_studio/%/migrations/%") and
      not path.matches("label_studio/%/examples/%")
    )
  }
}
