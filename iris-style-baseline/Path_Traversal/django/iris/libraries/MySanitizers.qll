/**
 * Augur Pass 1 (Path Traversal, CWE-22/23/36/73) - barrier model for the
 * Django 2.2.26 (django_vuln) CodeQL database.
 *
 * Rendered deterministically from the reviewed Phase 1 labels
 * (iris/labels/labels.json): the 17 sanitizer entries with
 * classification=tp are modeled (the 2 candidate-classified archive
 * target_filename barriers, snk-0035/snk-0046, are NOT modeled - unreviewed
 * and CLI-only reachable; see labels/phase1_review.md §4).
 *
 * Every barrier here is proven against the real source to block a specific
 * traversal mechanism BEFORE the file access, and is modeled as the call
 * node whose RESULT is the sanitized value (isBarrier removes the node from
 * the flow graph, so taint can no longer pass from the guarded call's
 * arguments onward through its result):
 *
 *   safe_join (snk-0376/0223/0429/0220/0059/0511) - abspath(join(base,
 *     *paths)) + normcase prefix containment with separator/equality/root
 *     exceptions (django/utils/_os.py:32-:47), raising
 *     SuspiciousFileOperation before any file access. Blocks direct '../'
 *     sequences, absolute-path replacement and case-variant escapes
 *     (normcase). NOT claimed to block: symlinks inside the base (no
 *     realpath) - documented residual in the labels.
 *   validate_file_name (snk-0399/0492/0217) - rejects '', '.', '..' and
 *     any name containing path elements (django/core/files/utils.py:7-:24).
 *   sanitize_file_name (snk-0346) - html.unescape + rsplit('/')/rsplit
 *     ('\\') basename extraction + dangerous-name rejection (django/http/
 *     multipartparser.py:296-:315); the only surviving shapes are
 *     separator-free (Windows drive-relative names remain and are handled
 *     by the storage-layer barriers).
 *   os.path.basename guards (snk-0490/0500/0502) - the labeled guard
 *     implementations strip/compare the basename so no directory component
 *     survives (django/core/files/uploadedfile.py:43, django/core/files/
 *     utils.py:9/:21).
 *   PurePath/PurePosixPath '..' guards (snk-0398/0404/0501) - `if '..' in
 *     PurePath(dir_name).parts: raise SuspiciousFileOperation` and the
 *     is_absolute()/'..'-parts rejection with allow_relative_path
 *     (django/core/files/storage.py:71/:106, django/core/files/utils.py:
 *     16-:20). NOTE: these are control-flow guards (the checked value and
 *     the sink value are different expressions); the barrier is emitted on
 *     the guard's constructor call node and is therefore mostly inert on
 *     data-flow paths - documented in report/query_generation_notes.md.
 *   get_valid_filename (snk-0396) - regex strips every character outside
 *     [-\w.] (django/utils/text.py:220-:223), removing '/' and '\\'; called
 *     from Storage.get_valid_name (storage.py:58-:63) and reached from
 *     generate_filename via self.get_valid_name(...) (storage.py:108).
 *
 * Deliberately NOT barriers (labels marked them none/fp): posixpath.
 * normpath (canonicalization only - 'a/../../b' survives as '../b'),
 * abspath/realpath/normcase outside safe_join, str.startswith prefix
 * checks (django/core/cache/backends/filebased.py:82, utils/archive.py:
 * 141 - no trailing separator), os.path.dirname/split.
 *
 * AST idioms identical to the Step 2 extraction queries (compiled against
 * codeql/python-all 7.1.2). `module` is never a variable name; API::Node
 * and DataFlow::Node are never mixed.
 *
 * Label-rule mapping:
 *   isSafeJoinBarrier       snk-0376 (views/static.py:36), snk-0223
 *                           (staticfiles/finders.py:121), snk-0429
 *                           (core/files/storage.py:330), snk-0220
 *                           (template/loaders/filesystem.py:36), snk-0059
 *                           (template/backends/base.py:77), snk-0511
 *                           (contrib/admindocs/views.py:332)
 *   isValidateFileNameBarrier  snk-0399 (storage.py:73), snk-0492
 *                           (uploadedfile.py:51), snk-0217
 *                           (db/models/fields/files.py:308)
 *   isSanitizeFileNameBarrier  snk-0346 (multipartparser.py:208)
 *   isBasenameGuardBarrier  snk-0490 (uploadedfile.py:43), snk-0500/0502
 *                           (files/utils.py:9/:21)
 *   isPurePathGuardBarrier  snk-0398 (storage.py:71), snk-0404
 *                           (storage.py:106), snk-0501 (files/utils.py:16)
 *   isValidFilenameBarrier  snk-0396 (storage.py:63 + the self.
 *                           get_valid_name wrapper call at :108)
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {


  /** Forward-slash-normalized absolute path of the file containing n. */
  private string normalizedPathOf(AstNode n) {
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
  }

  /** True iff n is inside the audited django package scope. */
  private predicate inAuditedDjangoTree(AstNode n) {
    normalizedPathOf(n).matches("%/django_vuln/django/%") and
    not normalizedPathOf(n).matches("%/django-db/%") and
    not normalizedPathOf(n).matches("%/django_vuln/django/test/%") and
    not normalizedPathOf(n).matches("%/django_vuln/django/contrib/admin/bin/%")
  }

  /**
   * safe_join(...) call barriers. The 6 labeled call sites are the only
   * safe_join calls in the audited tree (verified by grep: views/static.py
   * :36, contrib/staticfiles/finders.py:121, core/files/storage.py:330,
   * template/loaders/filesystem.py:36, template/backends/base.py:77,
   * contrib/admindocs/views.py:332).
   *
   * Blocking mechanism (django/utils/_os.py:24-:47):
   *   final_path = abspath(join(base, *paths))                  - normalizes
   *   base_path  = abspath(base)                                  - the root
   *   blocked unless normcase(final).startswith(normcase(base + sep))
   *   or normcase(final) == normcase(base)
   *   or dirname(normcase(base)) == normcase(base)               - root path
   * joined-path escapes ('..' past the root, absolute replacement of the
   * base, case-variant prefixes on Windows) raise SuspiciousFileOperation
   * before the caller's exists()/stat()/open(). Residual (per labels):
   * symlinked directories inside the base are not resolved, so a symlink
   * planted inside document_root can point outside - not blocked here.
   */
  private predicate isSafeJoinBarrier(DataFlow::Node n) {
    exists(Call c |
      c.getFunc().(Name).getId() = "safe_join" and
      inAuditedDjangoTree(c) and
      n.asExpr() = c
    )
  }

  /**
   * validate_file_name(...) call barriers. The 3 labeled call sites are the
   * only validate_file_name calls in the audited tree (verified by grep:
   * core/files/storage.py:73, core/files/uploadedfile.py:51,
   * db/models/fields/files.py:308).
   *
   * Blocking mechanism (core/files/utils.py:7-:24): rejects basenames in
   * {'', '.', '..'} and - without allow_relative_path - any name that is not
   * its own basename (path elements); with allow_relative_path=True
   * (FileField.generate_filename) rejects absolute paths and any '..' part
   * via PurePosixPath. Effect: a validated name cannot change directory.
   * Note: storage.py:73 and files.py:308 are validation-only calls whose
   * result is not used; their guard is control-flow (raise), so the emitted
   * result-node barrier does not cut every path - see
   * report/query_generation_notes.md.
   */
  private predicate isValidateFileNameBarrier(DataFlow::Node n) {
    exists(Call c |
      c.getFunc().(Name).getId() = "validate_file_name" and
      inAuditedDjangoTree(c) and
      n.asExpr() = c
    )
  }

  /**
   * MultiPartParser.sanitize_file_name barrier (multipartparser.py:208,
   * label snk-0346). html.unescape + rsplit('/')[-1] + rsplit('\\')[-1] +
   * {'', '.', '..'} rejection (multipartparser.py:296-:315): the returned
   * filename contains no path separators at all, so the value can no longer
   * traverse directories (documented residual: Windows drive-relative
   * shapes such as 'C:file' survive and are left to the storage-layer
   * barriers).
   */
  private predicate isSanitizeFileNameBarrier(DataFlow::Node n) {
    exists(Call c, Attribute func |
      normalizedPathOf(c).matches("%/django/http/multipartparser.py") and
      func = c.getFunc().(Attribute) and
      func.getName() = "sanitize_file_name" and
      func.getObject().(Name).getId() = "self" and
      n.asExpr() = c
    )
  }

  /**
   * os.path.basename guard barriers. Labels snk-0490 (uploadedfile.py:43:
   * name = os.path.basename(name) in _set_name - the docstring says "Just
   * use the basename of the file -- anything else is dangerous") and
   * snk-0500/0502 (files/utils.py:9/:21 - the basename membership and
   * path-element comparisons inside validate_file_name). The result of
   * basename extraction cannot contain a directory component.
   */
  private predicate isBasenameGuardBarrier(DataFlow::Node n) {
    exists(Call c, Attribute func, Attribute funcPath |
      (
        normalizedPathOf(c).matches("%/django/core/files/uploadedfile.py")
        or
        normalizedPathOf(c).matches("%/django/core/files/utils.py")
      ) and
      func = c.getFunc().(Attribute) and
      func.getName() = "basename" and
      funcPath = func.getObject().(Attribute) and
      funcPath.getName() = "path" and
      funcPath.getObject().(Name).getId() = "os" and
      n.asExpr() = c
    )
  }

  /**
   * pathlib PurePath/PurePosixPath '..'-guard barriers. Labels snk-0398
   * (storage.py:71, get_available_name), snk-0404 (storage.py:106,
   * generate_filename), snk-0501 (files/utils.py:16, the
   * allow_relative_path branch of validate_file_name).
   *
   * Blocking mechanism: `if '..' in PurePath(dir_name).parts: raise
   * SuspiciousFileOperation` / `if path.is_absolute() or '..' in path.
   * parts: raise` - a directory part containing '..' or an absolute name
   * aborts the upload-name processing before any storage access. These are
   * control-flow guards on a value that is used separately at the sink, so
   * the emitted constructor-call barrier is largely inert on data-flow
   * paths (documented limitation, not a false claim of sanitization).
   */
  private predicate isPurePathGuardBarrier(DataFlow::Node n) {
    exists(Call c, Attribute func |
      (
        (
          normalizedPathOf(c).matches("%/django/core/files/storage.py") and
          func = c.getFunc().(Attribute) and
          func.getName() = "PurePath"
        )
        or
        (
          normalizedPathOf(c).matches("%/django/core/files/utils.py") and
          func = c.getFunc().(Attribute) and
          func.getName() = "PurePosixPath"
        )
      ) and
      func.getObject().(Name).getId() = "pathlib" and
      n.asExpr() = c
    )
  }

  /**
   * get_valid_filename barrier (label snk-0396). django/utils/text.py:220
   * strips every character outside [-\w.] (forward and back slashes removed),
   * so the produced basename cannot contain path separators. The labeled row
   * is the definition site Storage.get_valid_name (storage.py:63); the
   * barrier is emitted both at that inner get_valid_filename(name) call and
   * at the self.get_valid_name(filename) wrapper call in generate_filename
   * (storage.py:108), which is the only other use of the wrapper in the
   * audited tree (verified by grep).
   */
  private predicate isValidFilenameBarrier(DataFlow::Node n) {
    exists(Call c |
      normalizedPathOf(c).matches("%/django/core/files/storage.py") and
      (
        c.getFunc().(Name).getId() = "get_valid_filename"
        or
        (c.getFunc().(Attribute).getName() = "get_valid_name" and
         c.getFunc().(Attribute).getObject().(Name).getId() = "self")
      ) and
      n.asExpr() = c
    )
  }

  /**
   * Pass-1 barrier dispatch. The pass key is checked so the same library
   * shape can serve later passes; only "path_traversal" is enabled in this
   * run.
   */
  predicate isBarrier(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      isSafeJoinBarrier(n)
      or
      isValidateFileNameBarrier(n)
      or
      isSanitizeFileNameBarrier(n)
      or
      isBasenameGuardBarrier(n)
      or
      isPurePathGuardBarrier(n)
      or
      isValidFilenameBarrier(n)
    )
  }

}
