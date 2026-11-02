/**
 * Augur Phase 2 - Pass 1 sink models (machine-generated from reviewed labels).
 *
 * Generated from: iris/labels/labels.json, pass 1 (Path Traversal,
 * CWE-022/023/036/073), run opendiamond-pass1-labeling-20261022, model glm-5.3.
 *
 * All 38 reviewed sink-role entries are covered. Only real file accesses are
 * sinks - path construction and resolution calls (os.path.join, dirname,
 * basename, split, split_scheme, isfile/exists/isdir checks), in-memory
 * ZipFile(BytesIO(...)) archives, and send_file over an already-fetched
 * stream object (gigapan_store.py:108) are modeled in MySummaries.qll / by
 * the standard library / labeled none, NOT as sinks:
 *
 *   Predicate          | Labels covered (site - classification)          | Access / path arg
 *   -------------------+-------------------------------------------------+------------------
 *   isSendFileSink     | augment_store.py:165 (fp, safe_join-guarded),    | file serve, arg 0
 *                      | diamond_store.py:137, mixer_store.py:266,        |
 *                      | test_store.py:296 (tp 0.98),                    |
 *                      | yfcc100m_mysql_store.py:128 (tp 0.97)            |
 *   isBuiltinOpenSink  | 19 builtin open() sites:                         | read/write, arg 0
 *                      | diamond 48/54, augment 184, mixer 83/182/203,    |
 *                      | test 106/211/233, video 52 (fp - converter/      |
 *                      | prefix constrained), blobcache 99,               |
 *                      | blaster/cache 126 (candidate),                   |
 *                      | server/filter 685/702 (candidate),               |
 *                      | server/object_ 293/314 (tp),                     |
 *                      | dataretriever/util 48 (tp), 82/94 (fp,           |
 *                      | safe_join-guarded upstream)                      |
 *   isPopenSink        | video_store.py:136 (tp 0.88), :162 (tp 0.90)     | ffprobe/ffmpeg read
 *                      |                                                 | of the path inside
 *                      |                                                 | the cmd list (arg 0)
 *   isOsStatSink       | video_store.py:104 (candidate 0.65)              | stat, arg 0
 *   isOsUtimeSink      | blobcache.py:83 (candidate 0.60)                 | mtime update, arg 0
 *   isOsRenameSink     | blobcache.py:71 (candidate), :197 (candidate);   | move, arg 0/1
 *                      | blaster/cache.py:117/118/142 (fp, server keys)   |
 *   isOsLinkSink       | blobcache.py:115 (fp, server key), :189           | hardlink, arg 0/1
 *                      | (candidate); dataretriever/util.py:55 (cand.)    |
 *   isCopyfileSink     | blobcache.py:195 (candidate 0.60)                | copy, arg 0
 *   isZipFileSink      | blaster/cache.py:50 (fp 0.70, hex keys)           | archive open, arg 0
 *
 * Structural matching is pinned per reviewed site by file and, where a file
 * contains additional calls of the same name that the labels reviewed as
 * none (blaster/cache.py open at :161 in prune, ZipFile at :136 over a
 * NamedTemporaryFile handle, blobcache.py rename at :134 in the GC prune
 * pass), by the enclosing function name. All function/parameter names were
 * verified against the real source tree.
 *
 * Pass key: "path_traversal".
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /**
   * Holds if `sink` is a reviewed pass-1 taint sink for the given pass key.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and
    (
      isSendFileSink(sink)
      or
      isBuiltinOpenSink(sink)
      or
      isPopenSink(sink)
      or
      isOsStatSink(sink)
      or
      isOsUtimeSink(sink)
      or
      isOsRenameSink(sink)
      or
      isOsLinkSink(sink)
      or
      isCopyfileSink(sink)
      or
      isZipFileSink(sink)
    )
  }

  /**
   * True iff `n` is located in the opendiamond file named by `subpath`
   * (e.g. "blobcache.py", "dataretriever/util.py").
   *
   * QL has no string concatenation, so the short subpaths map to full
   * path-match patterns through a literal table (filePattern).
   */
  private predicate inFile(AstNode n, string subpath) {
    exists(string pattern |
      filePattern(subpath, pattern) and
      n.getLocation().getFile().getAbsolutePath().matches(pattern)
    )
  }

  /** Literal subpath -> path-pattern table for the reviewed sink files. */
  private predicate filePattern(string subpath, string pattern) {
    (subpath = "dataretriever/augment_store.py" and
     pattern = "%/opendiamond/dataretriever/augment_store.py")
    or
    (subpath = "dataretriever/diamond_store.py" and
     pattern = "%/opendiamond/dataretriever/diamond_store.py")
    or
    (subpath = "dataretriever/mixer_store.py" and
     pattern = "%/opendiamond/dataretriever/mixer_store.py")
    or
    (subpath = "dataretriever/test_store.py" and
     pattern = "%/opendiamond/dataretriever/test_store.py")
    or
    (subpath = "dataretriever/video_store.py" and
     pattern = "%/opendiamond/dataretriever/video_store.py")
    or
    (subpath = "dataretriever/yfcc100m_mysql_store.py" and
     pattern = "%/opendiamond/dataretriever/yfcc100m_mysql_store.py")
    or
    (subpath = "dataretriever/util.py" and
     pattern = "%/opendiamond/dataretriever/util.py")
    or
    (subpath = "blobcache.py" and
     pattern = "%/opendiamond/blobcache.py")
    or
    (subpath = "server/filter.py" and
     pattern = "%/opendiamond/server/filter.py")
    or
    (subpath = "server/object_.py" and
     pattern = "%/opendiamond/server/object_.py")
    or
    (subpath = "blaster/cache.py" and
     pattern = "%/opendiamond/blaster/cache.py")
  }

  /**
   * flask send_file(path) in the five reviewed dataretriever stores
   * (augment_store.py:165, diamond_store.py:137, mixer_store.py:266,
   * test_store.py:296, yfcc100m_mysql_store.py:128). The path argument
   * (index 0) is the dangerous operand: it is served as file content.
   * gigapan_store.py:108 send_file(result, ...) is NOT matched - its
   * argument is a StringIO/urlopen stream object, not a filesystem path
   * (reviewed none). Verified: each of these five store files contains
   * exactly one send_file call.
   */
  private predicate isSendFileSink(DataFlow::Node sink) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "send_file" and
      (
        inFile(c, "dataretriever/augment_store.py") or
        inFile(c, "dataretriever/diamond_store.py") or
        inFile(c, "dataretriever/mixer_store.py") or
        inFile(c, "dataretriever/test_store.py") or
        inFile(c, "dataretriever/yfcc100m_mysql_store.py")
      ) and
      sink = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * Builtin open(path, ...) at the 19 reviewed sites. The path argument
   * (index 0) is the dangerous operand; the access types are reads
   * (index/meta/object loaders, DiamondTextAttr attributes, blob reads)
   * and writes (augment index files via write_data). Site scoping:
   *
   *   - dataretriever stores (augment 184; diamond 48/54; mixer 83/182/203;
   *     test 106/211/233; video 52): file-level match - these files contain
   *     no other builtin open.
   *   - blobcache.py:99 (BlobCache.__getitem__ blob read, candidate),
   *     server/filter.py:685/:702 (filter code/config read, candidate),
   *     server/object_.py:293/:314 (file: URI object/meta read, tp),
   *     dataretriever/util.py:48/:82/:94 (DiamondTextAttr read tp 0.90;
   *     read_file_list/write_data fp - upstream safe_join): file-level
   *     match - no other builtin open in these files.
   *   - blaster/cache.py:126 (get_search pickle cache read, candidate
   *     0.75): constrained to the enclosing function get_search - the
   *     open at :161 in prune() (listdir-derived names) is reviewed none
   *     and NOT matched.
   */
  private predicate isBuiltinOpenSink(DataFlow::Node sink) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "open" and
      (
        inFile(c, "dataretriever/augment_store.py") or
        inFile(c, "dataretriever/diamond_store.py") or
        inFile(c, "dataretriever/mixer_store.py") or
        inFile(c, "dataretriever/test_store.py") or
        inFile(c, "dataretriever/video_store.py") or
        inFile(c, "blobcache.py") or
        inFile(c, "server/filter.py") or
        inFile(c, "server/object_.py") or
        inFile(c, "dataretriever/util.py")
        or
        (inFile(c, "blaster/cache.py") and
         c.getScope().(Function).getName() = "get_search")
      ) and
      sink = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * subprocess.Popen(cmd_l) in video_store.py (_ffprobe :136,
   * _create_ffmpeg_segment_proc :162, both tp). The dangerous path travels
   * inside the command list (argument index 0): ffprobe/ffmpeg read the
   * attacker-chosen video file ('-show_format' video_path / '-i'
   * video_path) and ffmpeg streams its content to the HTTP response.
   * Element-to-container taint of the list literal is provided by the
   * standard container steps. Verified: exactly two subprocess.Popen
   * calls exist in video_store.py.
   */
  private predicate isPopenSink(DataFlow::Node sink) {
    exists(Call c, Attribute fn, Name subprocessModule |
      c.getFunc() = fn and
      fn.getName() = "Popen" and
      fn.getObject() = subprocessModule and
      subprocessModule.getId() = "subprocess" and
      inFile(c, "dataretriever/video_store.py") and
      sink = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * os.stat(video_path) in video_store.py get_object (:104, candidate
   * 0.65): metadata access on the unguarded join(DATAROOT, video) path -
   * mtime/size leak that also drives the response caching headers.
   * Verified: the only os.stat in video_store.py.
   */
  private predicate isOsStatSink(DataFlow::Node sink) {
    exists(Call c, Attribute fn, Name osModule |
      c.getFunc() = fn and
      fn.getName() = "stat" and
      fn.getObject() = osModule and
      osModule.getId() = "os" and
      inFile(c, "dataretriever/video_store.py") and
      sink = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * os.utime(self._path(sig)) in BlobCache._access (blobcache.py:83,
   * candidate 0.60): mtime refresh on a sig-derived path - a file
   * existence oracle on a client-influenced signature. Verified: the only
   * os.utime in blobcache.py.
   */
  private predicate isOsUtimeSink(DataFlow::Node sink) {
    exists(Call c, Attribute fn, Name osModule |
      c.getFunc() = fn and
      fn.getName() = "utime" and
      fn.getObject() = osModule and
      osModule.getId() = "os" and
      inFile(c, "blobcache.py") and
      sink = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * os.rename at the five reviewed sites. Both the source and destination
   * arguments (indexes 0 and 1) are cache-path operands derived from
   * sigs/search keys, so both are matched:
   *
   *   - blobcache.py:71 (in _try_with_rescue, candidate 0.55: rename of
   *     _path(sig) + GC_SUFFIX to _path(sig));
   *   - blobcache.py:197 (in make_dest, candidate 0.60: rename to
   *     join(_executable_dir, sig) - reviewed dangerous arg index 1);
   *   - blaster/cache.py:117/:118 (put_search, fp 0.75: NamedTemporaryFile
   *     to server-generated-key cache paths) and :142 (put_search_result,
   *     fp 0.75).
   *
   * The rename at blobcache.py:134 (prune GC pass over listdir names,
   * reviewed none) is excluded by constraining blobcache renames to the
   * enclosing functions _try_with_rescue / make_dest. Verified: no other
   * os.rename in blaster/cache.py.
   */
  private predicate isOsRenameSink(DataFlow::Node sink) {
    exists(Call c, Attribute fn, Name osModule |
      c.getFunc() = fn and
      fn.getName() = "rename" and
      fn.getObject() = osModule and
      osModule.getId() = "os" and
      (
        (inFile(c, "blobcache.py") and
         c.getScope().(Function).getName() in ["_try_with_rescue", "make_dest"])
        or
        inFile(c, "blaster/cache.py")
      ) and
      (sink = DataFlow::exprNode(c.getArg(0)) or
       sink = DataFlow::exprNode(c.getArg(1)))
    )
  }

  /**
   * os.link at the three reviewed sites (both operands are path arguments,
   * indexes 0 and 1):
   *
   *   - blobcache.py:115 (in add, fp 0.70: destination sig is the
   *     server-computed sha256 hexdigest);
   *   - blobcache.py:189 (in make_dest, candidate 0.60: source is
   *     _path(sig) with a client-influenced sig - hardlinks an arbitrary
   *     file into the executable dir, reviewed dangerous arg index 0);
   *   - dataretriever/util.py:55 (in DiamondTextAttr.__exit__, candidate
   *     0.65: os.link(temp_name, self.path) write channel, dangerous arg
   *     index 1).
   *
   * Verified: these are the only os.link calls in blobcache.py
   * (add/make_dest) and dataretriever/util.py (__exit__).
   */
  private predicate isOsLinkSink(DataFlow::Node sink) {
    exists(Call c, Attribute fn, Name osModule |
      c.getFunc() = fn and
      fn.getName() = "link" and
      fn.getObject() = osModule and
      osModule.getId() = "os" and
      (
        (inFile(c, "blobcache.py") and
         c.getScope().(Function).getName() in ["add", "make_dest"])
        or
        (inFile(c, "dataretriever/util.py") and
         c.getScope().(Function).getName() = "__exit__")
      ) and
      (sink = DataFlow::exprNode(c.getArg(0)) or
       sink = DataFlow::exprNode(c.getArg(1)))
    )
  }

  /**
   * shutil.copyfile(src, dest_tmp) in blobcache.py make_dest (:195,
   * candidate 0.60): fallback copy of _path(sig) into the executable dir.
   * Verified: the only shutil.copyfile in blobcache.py.
   */
  private predicate isCopyfileSink(DataFlow::Node sink) {
    exists(Call c, Attribute fn, Name shutilModule |
      c.getFunc() = fn and
      fn.getName() = "copyfile" and
      fn.getObject() = shutilModule and
      shutilModule.getId() = "shutil" and
      inFile(c, "blobcache.py") and
      sink = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * zipfile.ZipFile(path, 'r') in _CachedSearchResult.__init__
   * (blaster/cache.py:50, fp 0.70): archive open over
   * _object_path(search_key, object_key) - both keys are
   * [0-9a-f]{64}-constrained by the only calling routes
   * (blaster/__init__.py:53-57). Constrained to the enclosing __init__
   * function: the ZipFile at :136 over a NamedTemporaryFile handle
   * (put_search_result) is reviewed none and NOT matched. The in-memory
   * ZipFile(BytesIO(...)) sites (filter/__init__.py:121/:126,
   * proxy/search.py:214, client/util.py:33) and the CLI bundle output
   * (bundle.py:107) are not sinks and are not matched.
   */
  private predicate isZipFileSink(DataFlow::Node sink) {
    exists(Call c, Attribute fn, Name zipfileModule |
      c.getFunc() = fn and
      fn.getName() = "ZipFile" and
      fn.getObject() = zipfileModule and
      zipfileModule.getId() = "zipfile" and
      inFile(c, "blaster/cache.py") and
      c.getScope().(Function).getName() = "__init__" and
      sink = DataFlow::exprNode(c.getArg(0))
    )
  }
}
