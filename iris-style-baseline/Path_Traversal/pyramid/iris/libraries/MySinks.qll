/**
 * Augur Phase 2 Step 4 — Pass 1 (Path Traversal) sink model for pyramid.
 *
 * Machine-generated from iris/labels/labels.json (run
 * pyramid-pass1-pathtraversal-20261023, pass_id 1). Sink rules render exactly
 * the label entries with role=sink AND classification tp or candidate
 * (46 + 1 = 47 of the 55 sink rows). Excluded by the reviewed labeling
 * decisions (see iris/labels/phase1_review.md section 2 and
 * iris/labels/label_stats.md section 3):
 *  - K024/K041 (fp): pshell PYTHONSTARTUP isfile/open — operator environment
 *    boundary, no untrusted source can reach it.
 *  - K020/K032 (fp): override_asset exists/isdir of override_with — config
 *    time validation of an operator-supplied override path, executed before
 *    any request handling.
 *  - K003 (none): pkg_resources.resource_filename(pkg, '') at path.py:71 —
 *    the dangerous argument is a constant empty string.
 *  - K037/K038/K039 (none): os.path.realpath at i18n.py:192/198/201 —
 *    canonicalization only; the filesystem access of the locale chain is
 *    carried by the isdir/listdir/isfile/open entries, and realpath is NOT
 *    a containment check (it is modeled as a propagation step in
 *    MySummaries.qll instead).
 *
 * Sinks match the dangerous PATH ARGUMENT (path text) of real file
 * read/enumeration/metadata APIs, of the pkg_resources resource-resolution
 * APIs that perform the actual filesystem access inside setuptools, and of
 * the FileResponse file-serving constructor. Objects opened by open() are
 * not matched (the FileResponse argument at static.py:112 is the filepath
 * path text, not a file object). All sites are line-restricted to the
 * audited call locations, so unlabeled call sites of the same APIs (e.g.
 * open in scripts/) cannot alert.
 *
 * Rule groups and their label IDs:
 *  openPathArg            K022, K023, K025, K026, K027, K028  (open, arg 0)
 *  osListdirArg           K034, K035, K036                     (os.listdir, arg 0)
 *  osPathMetadataArg      K019, K021, K029, K030, K031, K033,
 *                         K040 (os.path.exists/isdir/isfile, arg 0)
 *  aliasMetadataArg       K047, K048, K049, K052, K055 (from-import aliases
 *                         getmtime/getsize/isdir/exists, arg 0)
 *  pkgResourcesArg        K001, K002, K010-K018 (pkg_resources.resource_*,
 *                         dotted form, arg 1)
 *  selfPkgResourcesArg    K042-K046 (self.pkg_resources.resource_*, arg 1)
 *  defaultProviderArg     K004-K009 (pkg_resources.DefaultProvider.* super
 *                         delegations, arg 1/2)
 *  staticAliasArg         K051, K053, K054 (static.py from-import aliases
 *                         resource_isdir/resource_exists/resource_filename,
 *                         arg 1)
 *  fileResponseArg        K050 (FileResponse, arg 0)
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  // --------------------------------------------------------------------------
  // Shared helpers (same shapes as the validated extraction query
  // iris/extraction/sinks.ql).
  // --------------------------------------------------------------------------

  /**
   * Gets the repository-relative path of the file containing this node, e.g.
   * "src/pyramid/static.py". On this Windows-created database
   * getRelativePath() may yield backslash forms or no result, so fall back to
   * capturing the "src/pyramid/..." suffix from the absolute path.
   */
  private string relPath(AstNode n) {
    exists(string p |
      p = n.getLocation().getFile().getRelativePath() and
      result = p.replaceAll("\\", "/")
    )
    or
    not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/").regexpCapture(".*/(src/pyramid/.+)$", 1)
  }

  /** Gets the dotted name of a simple name/attribute chain, e.g. "os.path.realpath". */
  private string dottedName(Expr e) {
    result = e.(Name).getId()
    or
    result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
  }

  // --------------------------------------------------------------------------
  // openPathArg — labels K022, K023, K025, K026, K027, K028.
  //
  // K022 i18n.py:203   open(mopath, 'rb') in make_localizer — file READ of
  //                    the .mo path built from the request-negotiated locale
  //                    name (join(tdir, lname) with no '..' filtering): the
  //                    Chain B sink. mopath = realpath(join(messages_dir,
  //                    mofile)), reached only when isdir/listdir succeeded.
  // K023 i18n.py:272   open(filename, 'rb') in Translations.load — file READ
  //                    of the gettext.find result; no in-repo request-derived
  //                    caller found (candidate, human review).
  // K025 response.py:57 open(path, 'rb') in FileResponse.__init__ — file READ
  //                    serving the HTTP response body; path comes from
  //                    static_view after the _secure_path guard (Chain A).
  // K026 config/assets.py:281 open(path, 'rb') in FSAssetSource.get_stream —
  //                    file READ of join(self.prefix, resource_name) in the
  //                    asset-override machinery.
  // K027 path.py:436   open(self.path, 'rb') in FSAssetDescriptor.stream —
  //                    file READ of an abspath from a config-time asset spec.
  // K028 static.py:394 open(self.manifest_path, 'rb') in
  //                    ManifestCacheBuster.get_manifest — file READ of the
  //                    config-time manifest spec.
  // --------------------------------------------------------------------------
  private predicate openPathArg(DataFlow::Node n) {
    exists(Call c |
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "open" and
      n.asExpr() = c.getArg(0) and
      (
        relPath(c) = "src/pyramid/i18n.py" and
        c.getLocation().getStartLine() in [203, 272]
        or
        relPath(c) = "src/pyramid/response.py" and
        c.getLocation().getStartLine() = 57
        or
        relPath(c) = "src/pyramid/config/assets.py" and
        c.getLocation().getStartLine() = 281
        or
        relPath(c) = "src/pyramid/path.py" and
        c.getLocation().getStartLine() = 436
        or
        relPath(c) = "src/pyramid/static.py" and
        c.getLocation().getStartLine() = 394
      )
    )
  }

  // --------------------------------------------------------------------------
  // osListdirArg — labels K034, K035, K036.
  //
  // K034 i18n.py:200   os.listdir(messages_dir) in make_localizer — directory
  //                    ENUMERATION of the locale-derived directory (Chain B).
  // K035 config/assets.py:302 FSAssetSource.listdir — enumeration of the
  //                    joined override path.
  // K036 path.py:442   FSAssetDescriptor.listdir — enumeration of a
  //                    config-time abspath.
  // --------------------------------------------------------------------------
  private predicate osListdirArg(DataFlow::Node n) {
    exists(Call c |
      dottedName(c.getFunc()) = "os.listdir" and
      n.asExpr() = c.getArg(0) and
      (
        relPath(c) = "src/pyramid/i18n.py" and
        c.getLocation().getStartLine() = 200
        or
        relPath(c) = "src/pyramid/config/assets.py" and
        c.getLocation().getStartLine() = 302
        or
        relPath(c) = "src/pyramid/path.py" and
        c.getLocation().getStartLine() = 442
      )
    )
  }

  // --------------------------------------------------------------------------
  // osPathMetadataArg — labels K019, K021, K029, K030, K031, K033, K040.
  //
  // K029 i18n.py:193   os.path.isdir(realpath(join(tdir, locale_name))) —
  //                    existence PROBE of the locale-derived directory; an
  //                    attacker-usable oracle and the gate of Chain B.
  // K030 i18n.py:198   os.path.isdir(realpath(messages_dir)) — same chain.
  // K040 i18n.py:202   os.path.isfile(mopath) — .mo existence check (Chain B).
  // K019 config/assets.py:275 / K031 :297 — FSAssetSource exists/isdir of
  //                    join(prefix, resource_name).
  // K021 path.py:445 / K033 path.py:439 — FSAssetDescriptor exists/isdir of
  //                    a config-time abspath.
  // --------------------------------------------------------------------------
  private predicate osPathMetadataArg(DataFlow::Node n) {
    exists(Call c, string fn |
      dottedName(c.getFunc()) = "os.path." + fn and
      fn in ["exists", "isdir", "isfile"] and
      n.asExpr() = c.getArg(0) and
      (
        relPath(c) = "src/pyramid/i18n.py" and
        c.getLocation().getStartLine() in [193, 198, 202]
        or
        relPath(c) = "src/pyramid/config/assets.py" and
        c.getLocation().getStartLine() in [275, 297]
        or
        relPath(c) = "src/pyramid/path.py" and
        c.getLocation().getStartLine() in [439, 445]
      )
    )
  }

  // --------------------------------------------------------------------------
  // aliasMetadataArg — labels K047, K048, K049, K052, K055.
  //
  // From-import bare aliases of os.path functions:
  //   response.py:2  "from os.path import getmtime, getsize"
  //     K047 response.py:55 getmtime(path), K048 response.py:56 getsize(path)
  //     — metadata reads of the served file in FileResponse.__init__ (last-
  //       modified / content-length; companions of the open at :57).
  //   static.py:5  "from os.path import exists, getmtime, getsize, isdir,
  //   join, normcase, normpath"
  //     K052 static.py:153 isdir(resource_path) — guarded request-derived
  //     joined path (Chain A).
  //     K055 static.py:170 exists(name) — find_resource_path existence
  //     check of the guarded request-derived path (Chain A).
  //     K049 static.py:201 getsize(x[0]) — size ordering of the candidate
  //     files; TOCTOU window between this and the later FileResponse open.
  // --------------------------------------------------------------------------
  private predicate aliasMetadataArg(DataFlow::Node n) {
    exists(Call c, string fn |
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = fn and
      fn in ["getmtime", "getsize", "isdir", "exists"] and
      n.asExpr() = c.getArg(0) and
      (
        relPath(c) = "src/pyramid/response.py" and
        c.getLocation().getStartLine() in [55, 56]
        or
        relPath(c) = "src/pyramid/static.py" and
        c.getLocation().getStartLine() in [153, 170, 201]
      )
    )
  }

  // --------------------------------------------------------------------------
  // pkgResourcesArg — labels K001, K002, K010-K018 (dotted pkg_resources.*).
  //
  // External setuptools APIs performing real filesystem access (arg 1 is the
  // package-relative resource path):
  //   K001 asset.py:43        resource_filename(pname, filename) in
  //                           abspath_from_asset_spec (config-time specs).
  //   K002 config/assets.py:229 PackageAssetSource.get_filename.
  //   K010-K015 config/assets.py:228/233/238/243/248/253 resource_exists —
  //                           PackageAssetSource.exists/isdir/listdir paths.
  //   K016 :234 resource_stream, K017 :249 resource_isdir,
  //   K018 :254 resource_listdir.
  // --------------------------------------------------------------------------
  private predicate pkgResourcesArg(DataFlow::Node n) {
    exists(Call c, string fn |
      dottedName(c.getFunc()) = "pkg_resources." + fn and
      fn in ["resource_filename", "resource_stream", "resource_exists",
             "resource_isdir", "resource_listdir"] and
      n.asExpr() = c.getArg(1) and
      relPath(c) in ["src/pyramid/asset.py", "src/pyramid/config/assets.py"] and
      c.getLocation().getStartLine() in [43, 228, 229, 233, 234, 238, 243,
                                         248, 249, 253, 254]
    )
  }

  // --------------------------------------------------------------------------
  // selfPkgResourcesArg — labels K042-K046 (path.py PkgResourcesAssetDescriptor
  // methods, arg 1 = self.path, the package-relative resource path of a
  // config-time asset spec):
  //   K042 :408 resource_filename (abspath), K043 :412 resource_stream
  //   (file READ), K044 :415 resource_isdir, K045 :418 resource_listdir,
  //   K046 :421 resource_exists.
  // --------------------------------------------------------------------------
  private predicate selfPkgResourcesArg(DataFlow::Node n) {
    exists(Call c, string fn |
      dottedName(c.getFunc()) = "self.pkg_resources." + fn and
      fn in ["resource_filename", "resource_stream", "resource_exists",
             "resource_isdir", "resource_listdir"] and
      n.asExpr() = c.getArg(1) and
      relPath(c) = "src/pyramid/path.py" and
      c.getLocation().getStartLine() in [408, 412, 415, 418, 421]
    )
  }

  // --------------------------------------------------------------------------
  // defaultProviderArg — labels K004-K009 (config/assets.py OverrideProvider
  // delegations to pkg_resources.DefaultProvider, i.e. the resource path
  // entering the setuptools provider's real filesystem access):
  //   K004 :32 get_resource_filename (arg 2, after self/manager),
  //   K005 :43 get_resource_stream (arg 2), K006 :54 get_resource_string
  //   (arg 2), K007 :64 has_resource (arg 1), K008 :72 resource_isdir
  //   (arg 1), K009 :82 resource_listdir (arg 1).
  // --------------------------------------------------------------------------
  private predicate defaultProviderArg(DataFlow::Node n) {
    exists(Call c, string fn |
      dottedName(c.getFunc()) = "pkg_resources.DefaultProvider." + fn and
      n.asExpr() = c.getArg(_) and
      (
        fn in ["get_resource_filename", "get_resource_stream",
               "get_resource_string"] and
        n.asExpr() = c.getArg(2)
        or
        fn in ["has_resource", "resource_isdir", "resource_listdir"] and
        n.asExpr() = c.getArg(1)
      ) and
      relPath(c) = "src/pyramid/config/assets.py" and
      c.getLocation().getStartLine() in [32, 43, 54, 64, 72, 82]
    )
  }

  // --------------------------------------------------------------------------
  // staticAliasArg — labels K051, K053, K054 (static.py:6
  // "from pkg_resources import resource_exists, resource_filename,
  // resource_isdir"; arg 1 is the resource path):
  //   K051 static.py:142 resource_isdir(package, resource_path) — package-
  //           mode dir check of the guarded request-derived path (Chain A).
  //   K053 static.py:167 resource_exists(package, name) — find_resource_path
  //           existence check (Chain A).
  //   K054 static.py:168 resource_filename(package, name) — resolution of the
  //           guarded request-derived name to an absolute filename that is
  //           then served via FileResponse (Chain A).
  // --------------------------------------------------------------------------
  private predicate staticAliasArg(DataFlow::Node n) {
    exists(Call c, string fn |
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = fn and
      fn in ["resource_isdir", "resource_exists", "resource_filename"] and
      n.asExpr() = c.getArg(1) and
      relPath(c) = "src/pyramid/static.py" and
      c.getLocation().getStartLine() in [142, 167, 168]
    )
  }

  // --------------------------------------------------------------------------
  // fileResponseArg — label K050.
  //
  // FileResponse(filepath, request, cache_max_age, content_type,
  // content_encoding) at static.py:112 (arg 0 = filepath, PATH TEXT —
  // normcase(normpath(join(norm_docroot, path))) in filesystem mode or the
  // resource_filename result in package mode). The real file access happens
  // inside FileResponse.__init__ (response.py:55-57 getmtime/getsize/open,
  // sinks K047/K048/K025); this is the framework-level file-RESPONSE position
  // of Chain A.
  // --------------------------------------------------------------------------
  private predicate fileResponseArg(DataFlow::Node n) {
    exists(Call c |
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "FileResponse" and
      n.asExpr() = c.getArg(0) and
      relPath(c) = "src/pyramid/static.py" and
      c.getLocation().getStartLine() = 112
    )
  }

  /** Holds if `n` is a pass 1 sink node. `passKey` must be "path_traversal". */
  predicate isSink(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      openPathArg(n)
      or osListdirArg(n)
      or osPathMetadataArg(n)
      or aliasMetadataArg(n)
      or pkgResourcesArg(n)
      or selfPkgResourcesArg(n)
      or defaultProviderArg(n)
      or staticAliasArg(n)
      or fileResponseArg(n)
    )
  }
}
