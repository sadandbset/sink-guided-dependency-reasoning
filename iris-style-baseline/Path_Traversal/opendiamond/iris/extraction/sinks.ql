/**
 * @name opendiamond CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the
 *   opendiamond CodeQL database (OpenDiamond 10.1.1, snapshot sha
 *   d2f20ffff793f88335f2c0244679d7193295abe2): the real file operations -
 *   builtin open() (the pickle search cache keyed by the websocket-supplied
 *   search_key at blaster/cache.py:126, the blob-cache read keyed by the
 *   client-supplied sha256/blob URI sig at blobcache.py:99, the file:/meta:
 *   object loads from scope-list URIs at server/object_.py:293/:314, the
 *   filter code reads at server/filter.py:685/:702, the dataretriever
 *   index/meta/attribute loads at diamond_store.py:48/:54, video_store.py:52,
 *   augment_store.py:184, mixer_store.py:83/:182/:203, DiamondTextAttr
 *   dataretriever/util.py:48, plus client-local reads), os.open/os.fdopen
 *   (filter fifos opendiamond/filter/__init__.py:191-:192,
 *   server/filter.py:772-:773), flask send_file (the '/obj/<path:...>'
 *   object download handlers at diamond_store.py:137, test_store.py:296,
 *   mixer_store.py:266, augment_store.py:165 (safe_join-guarded),
 *   yfcc100m_mysql_store.py:128, gigapan_store.py:108), os.stat on the
 *   video route param path (video_store.py:104), the cache mutation syscalls
 *   keyed by search_key/object_key/sig (os.rename/os.link/os.unlink/
 *   os.utime/os.makedirs/os.mkdir at blaster/cache.py:71/:115/:117/:118/:142
 *   and blobcache.py:71/:83/:115/:120/:134/:147/:197), os.listdir
 *   (blobcache.py:129/:141, blaster/cache.py:156), shutil.rmtree/copyfile
 *   (blaster/cache.py:167, blobcache.py:195, server/child.py:117),
 *   zipfile.ZipFile on the object-cache path (blaster/cache.py:50), and the
 *   subprocess ffmpeg/ffprobe invocations whose command list carries the
 *   '<path:video>' route param (video_store.py:136/:162); the
 *   os.path.join/abspath/normpath/realpath/isfile/exists propagation and
 *   validation nodes (the DATAROOT/INDEXDIR store joins, the
 *   search_key/object_key cache joins at blaster/cache.py:75/:78/:81/:84,
 *   the blob sig join at blobcache.py:60) - os.path.join is matched BOTH
 *   via API graphs and via the qualified os.path.join syntax shape, so one
 *   call site can legitimately yield one api and one ast row; the
 *   werkzeug.utils safe_join sanitizer row (augment_store.py:156, the only
 *   store not using raw os.path.join); the split_scheme URI-to-path decode
 *   boundary (server/object_.py:235/:251/:259/:334, server/filter.py:647/:662);
 *   and the first-party path-builder functions (_get_obj_absolute_path/
 *   _get_index_absolute_path per store, SearchCache._search_dir_path/
 *   _search_path/_search_expiration_path/_object_path, BlobCache._path) and
 *   filesystem-touching wrapper functions (SearchCache get_search/
 *   get_search_result/put_search/put_search_result/prune, BlobCache
 *   __getitem__/_access/add/_try_with_rescue/executable_path/prune,
 *   ObjectLoader load/_load_localfile/_load_attrbutes_localfile/
 *   _load_blobcache, filter _resolve_code/_resolve_blob/_resolve_mode,
 *   dataretriever read_file_list/write_data/DiamondTextAttr.__enter__,
 *   client create_filter_from_files/get_default_scopecookies, scope
 *   generate_cookie). flow_kind marks real file operations (file_open,
 *   fs_open, file_serve, fs_stat, fs_utime, fs_unlink, fs_link, fs_rename,
 *   fs_mkdir, fs_listdir, fs_delete, fs_copy, archive_open,
 *   process_file_arg), path propagation/validation (path_join,
 *   path_resolve, path_check, uri_split), a sanitizer (path_sanitize), and
 *   wrapper definitions (path_join_wrapper, internal_file_wrapper); only
 *   rows that actually access the filesystem with a controlled path
 *   argument are expected to label as sinks - the propagation rows are
 *   candidates for summary/sanitizer labels. Raw BQRS extraction query:
 *   run with `codeql query run` and decode with `codeql bqrs decode` (not
 *   database analyze). This is a plain multi-column select query on
 *   purpose: the problem query kind is the wrong shape for candidate
 *   tables and no table kind is assumed to exist.
 * @id iris/opendiamond/extraction/sinks
 * @tags path-traversal
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql and to the prior IRIS manual
 * Path_Traversal projects aiohttp/airflow/ansible/coderedcms/copyparty):
 *   1. node       - candidate AST node (Call/Function; location-backed,
 *                   decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name (API member name, function name)
 *   4. flow_kind  - see the @description: real fs operations (file_open,
 *                   fs_open, file_serve, fs_stat, fs_utime, fs_unlink,
 *                   fs_link, fs_rename, fs_mkdir, fs_listdir, fs_delete,
 *                   fs_copy, archive_open, process_file_arg), path
 *                   propagation/validation/decode (path_join, path_resolve,
 *                   path_check, uri_split), sanitizer (path_sanitize),
 *                   wrapper definitions (path_join_wrapper,
 *                   internal_file_wrapper)
 *   5. receiver   - syntactic receiver hint ("os", "os.path", "shutil",
 *                   "zipfile", "subprocess", "flask", "werkzeug.utils",
 *                   "" for builtin open, the enclosing class name for
 *                   method wrappers, the function name for plain wrappers)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here), or a literal
 *                   module hint for external families ("os", "os.path",
 *                   "shutil", "zipfile", "subprocess", "flask",
 *                   "werkzeug.utils", "opendiamond.helpers")
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (os.rename: 0 = src, dst sits at 1; os.link: 0 = src,
 *                   dst at 1; shutil.copyfile: 0 = src, dst at 1;
 *                   process_file_arg: 0 = the cmd list whose element
 *                   carries the video path; safe_join: 1 = the relative
 *                   path, 0 = the base dir; path_join: -1 = any segment
 *                   can be controlled, base and rel segments both occur;
 *                   -1 for attribute-less wrapper rows)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs; only the
 *                   os.path.join family resolves at API level here - all
 *                   other families are bare names or first-party wrappers)
 *                   or "ast" (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates/functions), does
 * not assign API::Node values to DataFlow::Node variables (the API call
 * node is immediately lowered to its syntactic Call), keeps every variable
 * bound through a positive body, and keeps resolved-API matching strictly
 * separate from AST syntax matching (the match_kind column records which
 * one produced a row).
 *
 * Verified non-sinks (not emitted): proxy/utils.py load_dataset_from_zipfile
 * zf.read(entry) reads zip members from an in-memory archive (no filesystem
 * write by entry name; no extract/extractall anywhere in the audited tree);
 * PIL.Image.open sites take BytesIO/streams (attributes.py:123,
 * blaster/handlers.py:456, gigapan_store.py:77); the blaster
 * _CachedSearchResult.__getitem__ zf.read(member) is an archive member
 * lookup; yfcc100m_simple/vdms '/id/<path:suffix>' handlers only build S3
 * URLs via urljoin (no local file access).
 *
 * Scope (applied to every row): %/opendiamond_vuln/opendiamond/% (the
 * shipped opendiamond package) or the root entry script
 * %/opendiamond_vuln/proxy.py, EXCLUDING the nested %/opendiamond-db/%
 * database directory (also outside the positive scope by construction).
 * tests/, setup.py and the root audit artifacts are outside the positive
 * scope.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Forward-slash-normalized absolute path of the file containing n, so path
 *  matching works with both CodeQL path styles on Windows. */
string normalizedPathOf(AstNode n) {
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
}

/** Dotted module-name hint for the module containing n (opendiamond.x.y);
 *  scripts without a dotted module name (the root proxy.py entry) fall back
 *  to the file base name. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
}

/** True iff the candidate's file path is inside the audited opendiamond
 *  package (or is the root proxy.py entry script), excluding the nested
 *  opendiamond-db CodeQL database directory. bindingset[path] declares that
 *  the caller passes a bound path. */
bindingset[path]
predicate opendiamondSinkPath(string path) {
  (
    path.replaceAll("\\", "/").matches("%/opendiamond_vuln/opendiamond/%")
    or
    path.replaceAll("\\", "/").matches("%/opendiamond_vuln/proxy.py")
  ) and
  not path.replaceAll("\\", "/").matches("%/opendiamond-db/%")
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. Every family is grounded in code actually
 *  present in the audited tree (see the file/line anchors in the comments;
 *  line numbers refer to the opendiamond_vuln snapshot). */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: builtin open(path, mode) - the read/write workhorse.
     Highlight sites: blaster/cache.py:126 (search pickle keyed by the
     websocket search_key), blobcache.py:99 (blob keyed by the
     client-supplied sig from the blob:/sha256: URI), server/object_.py:293
     (file: src URI from the scope list) and :314 (meta: attributes file),
     server/filter.py:685/:702 (filter code file), dataretriever index and
     attribute loads (diamond_store.py:48/:54, video_store.py:52,
     augment_store.py:184, mixer_store.py:83/:182/:203,
     dataretriever/util.py:48), client-local reads (client/util.py:66/:75/:96)
     and operator config reads (config.py:186/:244, scope.py:270/:346/:352)
     - the labeling step separates the networked sites from the local ones. */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 2: os.open(path, flags) / os.fdopen(fd, mode) - filter fifo
     creation (opendiamond/filter/__init__.py:191-:192 with flags.fifo_out/
     flags.fifo_in, server/filter.py:772-:773 with the TMPDIR fifo join).
     os.fdopen argument 0 is the fd produced by the paired os.open. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["open", "fdopen"] and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "fs_open" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 3: flask send_file(path) - the object download boundary of the
     dataretriever stores. diamond_store.py:137, test_store.py:296,
     mixer_store.py:266, yfcc100m_mysql_store.py:128 receive
     os.path.join(DATAROOT, <path:obj_path>/'<path:rel_path>') results;
     augment_store.py:165 is safe_join-guarded; gigapan_store.py:108 sends
     a transcode temp file (int-only route params). */
  exists(Call c |
    c.getFunc().(Name).getId() = "send_file" and
    node = c and
    flowKind = "file_serve" and
    callableName = "send_file" and
    argIndex = 0 and
    receiver = "flask" and
    moduleHint = "flask" and
    matchKind = "ast"
  )
  or
  /* family 4-10: the cache mutation and inspection syscalls, keyed by
     search_key/object_key (blaster SearchCache), blob sig (BlobCache) or
     route-derived paths. os.stat: video_store.py:104 (the video route
     param path - also the ffmpeg input). os.utime: blobcache.py:83 (blob
     mtime touch - the sig path). os.unlink: blobcache.py:120/:147,
     blaster/cache.py:120/:121. os.link: blobcache.py:115 (sig -> dest),
     dataretriever/util.py:55. os.rename: blaster/cache.py:117/:118/:142,
     blobcache.py:71/:134/:197 (arg 0 = src, dst at 1).
     os.mkdir/os.makedirs: config.py:221, blaster/__init__.py:98,
     blaster/cache.py:71/:115. os.listdir: blobcache.py:129/:141,
     blaster/cache.py:156. */
  (
    exists(Call c, Attribute func |
      func = c.getFunc().(Attribute) and
      func.getObject().(Name).getId() = "os" and
      (
        (func.getName() = "stat" and flowKind = "fs_stat")
        or
        (func.getName() = "utime" and flowKind = "fs_utime")
        or
        (func.getName() = "unlink" and flowKind = "fs_unlink")
        or
        (func.getName() = "link" and flowKind = "fs_link")
        or
        (func.getName() = "rename" and flowKind = "fs_rename")
        or
        (func.getName() in ["mkdir", "makedirs"] and flowKind = "fs_mkdir")
        or
        (func.getName() = "listdir" and flowKind = "fs_listdir")
      ) and
      node = c and
      callableName = func.getName() and
      argIndex = 0 and
      receiver = "os" and
      moduleHint = "os" and
      matchKind = "ast"
    )
    or
    /* family 11-12: shutil.rmtree (blaster/cache.py:167 search dir,
       server/child.py:117 tempdir) and shutil.copyfile (blobcache.py:195
       blob rescue copy; arg 0 = src, dst at 1). */
    exists(Call c, Attribute func |
      func = c.getFunc().(Attribute) and
      func.getObject().(Name).getId() = "shutil" and
      (
        (func.getName() = "rmtree" and flowKind = "fs_delete")
        or
        (func.getName() = "copyfile" and flowKind = "fs_copy")
      ) and
      node = c and
      callableName = func.getName() and
      argIndex = 0 and
      receiver = "shutil" and
      moduleHint = "shutil" and
      matchKind = "ast"
    )
  )
  or
  /* family 13: zipfile.ZipFile(path, ...) - blaster/cache.py:50 opens the
     object cache zip at os.path.join(basedir, search_key, object_key) (the
     URL/websocket-keyed cache read), blaster/cache.py:136 and bundle.py:107
     write temp/new archives, client/util.py:33 and proxy/search.py:214
     build in-memory archives. Both the bare name (from zipfile import
     ZipFile) and the qualified zipfile.ZipFile form occur. */
  exists(Call c |
    (
      c.getFunc().(Name).getId() = "ZipFile"
      or
      (c.getFunc().(Attribute).getName() = "ZipFile" and
       c.getFunc().(Attribute).getObject().(Name).getId() = "zipfile")
    ) and
    node = c and
    flowKind = "archive_open" and
    callableName = "ZipFile" and
    argIndex = 0 and
    receiver = "zipfile" and
    moduleHint = "zipfile" and
    matchKind = "ast"
  )
  or
  /* family 14: subprocess.Popen(cmd_list, ...) in video_store.py - the
     command list built at :133-:134 (ffprobe) and :153-:160 (ffmpeg)
     carries _get_obj_absolute_path(video) where video is the
     '/obj/start/.../<path:video>' route param; the filesystem access
     happens inside the child process. argIndex 0 = the cmd list. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "Popen" and
    func.getObject().(Name).getId() = "subprocess" and
    normalizedPathOf(c).matches("%/opendiamond/dataretriever/video_store.py") and
    node = c and
    flowKind = "process_file_arg" and
    callableName = "Popen" and
    argIndex = 0 and
    receiver = "subprocess" and
    moduleHint = "subprocess" and
    matchKind = "ast"
  )
  or
  /* family 15a: os.path.join(...) resolved via API graphs (alias-aware;
 *     all uses in this codebase are qualified os.path.join, so this and
 *     the ast family 15b below produce one api + one ast row per call
 *     site - identical to the airflow/coderedcms/copyparty projects of
 *     this series). Controlled segments vary: DATAROOT/INDEXDIR base +
 *     route params (stores), basedir + search_key/object_key
 *     (blaster/cache.py:75/:78/:81/:84), basedir + sig (blobcache.py:60),
 *     TMPDIR + fifo names (server/filter.py:772-:773). argIndex -1: any
 *     segment can be the controlled one. */
  exists(API::CallNode cn |
    cn = API::moduleImport("os").getMember("path").getMember("join").getACall() and
    node = astCallOf(cn) and
    flowKind = "path_join" and
    callableName = "join" and
    argIndex = -1 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "api"
  )
  or
  /* family 15b: syntax-level os.path.join(...) (qualified form). */
  exists(Call c, Attribute func, Attribute pattr |
    func = c.getFunc().(Attribute) and
    func.getName() = "join" and
    pattr = func.getObject().(Attribute) and
    pattr.getName() = "path" and
    pattr.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "path_join" and
    callableName = "join" and
    argIndex = -1 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 16: os.path resolution/normalization (abspath, normpath,
     realpath, dirname, basename, split) - propagation/validation nodes.
     Observed: pyramid.py:135/:136 (root + rel_path), video_store.py:55,
     dataretriever/util.py:44 (mkstemp dir), blaster/__init__.py:69-:70
     (static/template paths - operator-fixed). */
  exists(Call c, Attribute func, Attribute pattr |
    func = c.getFunc().(Attribute) and
    func.getName() in ["abspath", "normpath", "realpath", "dirname", "basename", "split"] and
    pattr = func.getObject().(Attribute) and
    pattr.getName() = "path" and
    pattr.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "path_resolve" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 17: os.path existence/size checks (isfile, isdir, exists,
     getsize) - the existence gates in the stores (diamond_store.py:104,
     test_store.py:262, mixer_store.py:232, augment_store.py:190,
     yfcc100m_simple_store.py:79 - read_file_list path check) and
     ExecutableBlobCache (blobcache.py:199). TOCTOU-relevant validation
     nodes. */
  exists(Call c, Attribute func, Attribute pattr |
    func = c.getFunc().(Attribute) and
    func.getName() in ["isfile", "isdir", "exists", "getsize"] and
    pattr = func.getObject().(Attribute) and
    pattr.getName() = "path" and
    pattr.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "path_check" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 18: the werkzeug.utils safe_join sanitizer -
     augment_store.py:156 _get_obj_absolute_path is the ONLY store path
     builder that guards the DATAROOT join (every other store uses raw
     os.path.join). argIndex 1 = the untrusted relative path (0 = base). */
  exists(Call c |
    c.getFunc().(Name).getId() = "safe_join" and
    node = c and
    flowKind = "path_sanitize" and
    callableName = "safe_join" and
    argIndex = 1 and
    receiver = "werkzeug.utils" and
    moduleHint = "werkzeug.utils" and
    matchKind = "ast"
  )
  or
  /* family 19: split_scheme(uri) from opendiamond.helpers - the
     URI-to-path decode boundary that turns 'file:<path>'/'sha256:<sig>'
     object URIs (from scope lists and RPC filter configs) into the paths
     consumed by ObjectLoader._load_localfile/_load_blobcache and
     Filter._resolve_code/_resolve_blob. Sites: server/object_.py:235/:251/
     :259/:334, server/filter.py:647/:662. A summary-step candidate for the
     Phase 2 taint config. */
  exists(Call c |
    c.getFunc().(Name).getId() = "split_scheme" and
    node = c and
    flowKind = "uri_split" and
    callableName = "split_scheme" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "opendiamond.helpers" and
    matchKind = "ast"
  )
  or
  /* family 20: first-party path-builder functions (Function rows). The
     store builders join DATAROOT/INDEXDIR with route params:
     diamond_store.py:123/:127, test_store.py:282/:286, mixer_store.py:252/
     :256, video_store.py:125/:129, augment_store.py:155 (safe_join inside),
     yfcc100m_mysql_store.py:136 (_get_obj_abosolute_path). The cache
     builders join the base dir with the client-supplied keys:
     blaster/cache.py:74-:84 (_search_dir_path/_search_path/
     _search_expiration_path/_object_path), blobcache.py:59 (_path: sig
     lowercased into the join). */
  exists(Function f |
    (
      (
        f.getName() in ["_get_obj_absolute_path", "_get_index_absolute_path",
                        "_get_obj_abosolute_path"] and
        normalizedPathOf(f).matches("%/opendiamond/dataretriever/%")
      )
      or
      (
        f.getName() in ["_search_dir_path", "_search_path",
                        "_search_expiration_path", "_object_path"] and
        normalizedPathOf(f).matches("%/opendiamond/blaster/cache.py")
      )
      or
      (
        f.getName() = "_path" and
        normalizedPathOf(f).matches("%/opendiamond/blobcache.py")
      )
    ) and
    node = f and
    flowKind = "path_join_wrapper" and
    callableName = f.getName() and
    argIndex = -1 and
    receiver = f.getName() and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 21: first-party filesystem-touching wrapper functions (Function
     rows). blaster/cache.py: get_search :124 (open+pickle.load on the
     search_key path), get_search_result :145 (ZipFile on the
     search_key/object_key path), put_search :99, put_search_result :133,
     prune :152 (rmtree keyed by listed dir names); blobcache.py:
     __getitem__ :96 (open on the sig path), _access :77 (utime), add :102
     (mkstemp+link), _try_with_rescue :62 (rename), executable_path :170
     (link/copy to the executable dir), prune :124; server/object_.py:
     load :241, _load_localfile :292 (open on the file: URI path),
     _load_attrbutes_localfile :312, _load_blobcache :271 (blob_cache[sig]);
     server/filter.py: _resolve_code :645 (executable_path on the
     sha256:sig), _resolve_blob :660 (blob_cache[sig]), _resolve_mode :673
     (open on code_path); dataretriever/util.py: read_file_list :77,
     write_data :86, DiamondTextAttr.__enter__ :40 (open on
     path+'.text_attr'); client/util.py: create_filter_from_files :40,
     get_default_scopecookies :90; scope.py: generate_cookie :253 (opens
     the settings-configured keyfile). */
  exists(Function f |
    (
      (
        f.getName() in ["get_search", "get_search_result", "put_search",
                        "put_search_result", "prune"] and
        normalizedPathOf(f).matches("%/opendiamond/blaster/cache.py")
      )
      or
      (
        f.getName() in ["__getitem__", "_access", "add", "_try_with_rescue",
                        "executable_path", "prune"] and
        normalizedPathOf(f).matches("%/opendiamond/blobcache.py")
      )
      or
      (
        f.getName() in ["load", "_load_localfile", "_load_attrbutes_localfile",
                        "_load_blobcache"] and
        normalizedPathOf(f).matches("%/opendiamond/server/object_.py")
      )
      or
      (
        f.getName() in ["_resolve_code", "_resolve_blob", "_resolve_mode"] and
        normalizedPathOf(f).matches("%/opendiamond/server/filter.py")
      )
      or
      (
        f.getName() in ["read_file_list", "write_data", "__enter__"] and
        normalizedPathOf(f).matches("%/opendiamond/dataretriever/util.py")
      )
      or
      (
        f.getName() in ["create_filter_from_files", "get_default_scopecookies"] and
        normalizedPathOf(f).matches("%/opendiamond/client/util.py")
      )
      or
      (
        f.getName() = "generate_cookie" and
        normalizedPathOf(f).matches("%/opendiamond/scope.py")
      )
    ) and
    node = f and
    flowKind = "internal_file_wrapper" and
    callableName = f.getName() and
    argIndex = -1 and
    (
      /* methods: receiver is the enclosing class name */
      (f.getEnclosingScope() instanceof Class and
       receiver = f.getEnclosingScope().(Class).getName())
      or
      /* module-level functions (read_file_list, write_data,
         create_filter_from_files, get_default_scopecookies,
         generate_cookie): receiver is the function name itself */
      (not (f.getEnclosingScope() instanceof Class) and
       receiver = f.getName())
    ) and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  opendiamondSinkPath(normalizedPathOf(node))
select
  node,
  "sink_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
