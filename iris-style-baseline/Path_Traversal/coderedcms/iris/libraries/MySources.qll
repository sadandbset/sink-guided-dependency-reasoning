/**
 * Augur Phase 2 - Pass 1 source models (machine-generated from reviewed labels).
 *
 * Generated from: iris/labels/labels.json, pass 1 (Path Traversal,
 * CWE-022/023/036/073), run coderedcms-pass1-labeling-20261021, model glm-5.3.
 * Every predicate below corresponds one-to-one to reviewed `source`-role label
 * entries; sites labeled `none` (cr_settings config, CLI/operator options,
 * session/session_key reads, upload file content, mailchimp JSON) are
 * deliberately NOT matched.
 *
 * Label families covered (57 source-role entries):
 *   - route_param   (1 entry)  : S-views-110-serve_protected_file (tp, 0.97)
 *   - http          (45 entries): request GET/POST/FILES/META attribute, .get()
 *                                and subscript reads across coderedcms views,
 *                                page_models, wagtail_flexible_forms, hooks
 *   - upload_name   (5 entries) : S-page_models-1211-name, S-wff_models-232-name,
 *                                S-wff_models-244-name, S-forms-68-name,
 *                                S-forms-73-name
 *   - db_json       (6 entries) : json.loads results at coderedcms/wagtail_flexible_forms/
 *                                models.py:204/327/356/377/444/605 (candidate)
 *
 * Pass key: "path_traversal".
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /**
   * Holds if `source` is a reviewed pass-1 taint source for the given pass key.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and
    (
      isRouteParamSource(source)
      or
      isHttpRequestSource(source)
      or
      isUploadNameSource(source)
      or
      isDbJsonSource(source)
    )
  }

  /**
   * The audit scope: the coderedcms package as extracted in Phase 1 Step 2 -
   * excludes generated migrations, tests, the project scaffolding template and
   * the nested CodeQL database tree (WORKFLOW.md 4.3.2).
   */
  private predicate inAuditScope(AstNode n) {
    exists(string path |
      path = n.getLocation().getFile().getAbsolutePath() and
      path.matches("%/coderedcms/%") and
      not path.matches("%/migrations/%") and
      not path.matches("%/tests/%") and
      not path.matches("%/project_template/%") and
      not path.matches("%/coderedcms-db/%")
    )
  }

  /**
   * Source family `route_param` (label S-views-110-serve_protected_file, tp,
   * 0.97): the `path` parameter of serve_protected_file(request, path) in
   * coderedcms/views.py.
   *
   * Evidence: coderedcms/urls.py:21-25 registers
   *   re_path(r'^{PROTECTED_MEDIA_URL}(?P<path>.*)$', serve_protected_file)
   * so the entire (percent-decoded) URL path below /protected/ is injected as
   * the `path` kwarg; views.py:114 joins it onto PROTECTED_MEDIA_ROOT and
   * views.py:117 opens the result. @login_required (views.py:109) gates WHO
   * can request, not WHAT path is opened (django.md section 8: contextual,
   * not sanitization).
   */
  private predicate isRouteParamSource(DataFlow::Node source) {
    exists(Function f |
      f.getName() = "serve_protected_file" and
      f.getLocation().getFile().getAbsolutePath().matches("%/coderedcms/views.py") and
      source = DataFlow::parameterNode(f.getArgByName("path"))
    )
  }

  /**
   * A request field attribute read: `request.<field>` where <field> is one of
   * GET/POST/FILES/META and the object is a plain `request` local/parameter.
   */
  private predicate isRequestField(Attribute field) {
    field.getName() in ["GET", "POST", "FILES", "META"] and
    field.getObject().(Name).getId() = "request" and
    inAuditScope(field)
  }

  /**
   * Source family `http` (45 reviewed entries, tp, 0.8-0.9): the Django
   * request boundary. Three shapes, mirroring the extraction rows:
   *   (1) request.<field> attribute reads            (e.g. views.py:33, :238;
   *        page_models.py:484, :1404; wff models.py:218; hooks :228, :275)
   *   (2) request.<field>.get(...) call results      (e.g. views.py:86, :188,
   *        :208-:214; page_models.py:487/:493/:511, :1411, :1941/:1947;
   *        wff models.py:213, :656; hooks :222, :239)
   *   (3) request.<field>[...] subscript reads       (views.py:143/:145/:146,
   *        :167; hooks :275)
   *
   * `self.request.session` reads (wff models.py:180/:190) are NOT matched -
   * they were reviewed as `none` (server-written session state).
   * Verified: 28 request-field read lines in the audit scope, all covered by
   * the reviewed http labels.
   */
  private predicate isHttpRequestSource(DataFlow::Node source) {
    // (1) request.<field>
    exists(Attribute field |
      isRequestField(field) and
      source = DataFlow::exprNode(field)
    )
    or
    // (2) request.<field>.get(...)
    exists(Call getCall, Attribute getFunc |
      getCall.getFunc() = getFunc and
      getFunc.getName() = "get" and
      isRequestField(getFunc.getObject().(Attribute)) and
      source = DataFlow::exprNode(getCall)
    )
    or
    // (3) request.<field>[...]
    exists(Subscript sub, Attribute field |
      sub.getObject() = field and
      isRequestField(field) and
      source = DataFlow::exprNode(sub)
    )
  }

  /**
   * Source family `upload_name` (labels S-page_models-1211-name,
   * S-wff_models-232-name, S-wff_models-244-name, S-forms-68-name,
   * S-forms-73-name; tp, 0.9-0.95): the client-supplied multipart filename
   * `file.name` / `val.name` / `value.name` of uploaded files.
   *
   * Evidence: page_models.py:1211 str(Path(directory) / val.name);
   * wff models.py:244 str(Path(directory) / file.name);
   * wff models.py:232 form.cleaned_data[name] = file.name;
   * forms.py:68/:73 os.path.splitext(value.name) (extension check - the
   * filename itself remains client-controlled).
   * Verified: exactly these 5 sites read `.name` on locals named
   * file/val/value in the audit scope; Path(value).name (wff:403, object is a
   * Call) is not matched, matching its reviewed `none` label.
   */
  private predicate isUploadNameSource(DataFlow::Node source) {
    exists(Attribute nameAttr |
      nameAttr.getName() = "name" and
      nameAttr.getObject().(Name).getId() in ["file", "val", "value"] and
      inAuditScope(nameAttr) and
      source = DataFlow::exprNode(nameAttr)
    )
  }

  /**
   * Source family `db_json` (6 reviewed entries, candidate, 0.6): the return
   * value of json.loads over DB-persisted submission data in
   * coderedcms/wagtail_flexible_forms/models.py - :204 (submission.form_data),
   * :327/:356/:377 (thumbnails_by_path), :444 (form_data steps),
   * :605 (SubmissionRevision.data).
   *
   * These values were user-influenced at form-submission time and are re-used
   * as file paths by get_thumbnail_path / delete_file / delete_files
   * (second-order boundary). json.loads in integration_models.py is NOT
   * matched (reviewed `none`: admin-configured mailchimp JSON, no path use).
   * Verified: exactly 6 json.loads call sites exist in this file.
   */
  private predicate isDbJsonSource(DataFlow::Node source) {
    exists(Call loads, Attribute func, Name jsonModule |
      loads.getFunc() = func and
      func.getName() = "loads" and
      func.getObject() = jsonModule and
      jsonModule.getId() = "json" and
      loads.getLocation().getFile().getAbsolutePath()
        .matches("%/coderedcms/wagtail_flexible_forms/models.py") and
      source = DataFlow::exprNode(loads)
    )
  }
}
