/**
 * @name nltk CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the nltk
 *   CodeQL database (NLTK 3.4.4 natural language toolkit library - the
 *   nltk/ package tree is the audit target): the central resource read
 *   (FileSystemPathPointer.open -> open(self._path, 'rb') at
 *   nltk/data.py:345, fed by find()'s unchecked join+percent-decode
 *   os.path.join(path_, url2pathname(resource_name)) :650/:657 and by the
 *   pointer .join(fileid) :354 - no containment anywhere); the hand-rolled
 *   zip-slip write channel of the downloader (nltk/downloader.py:2287
 *   filepath = os.path.join(root, *filename.split('/')) from the namelist
 *   entries :2264 -> open(filepath, 'wb') :2290, plus the directory writes
 *   os.path.join(root, *pieces) :2281 -> os.mkdir :2283 - NO entry-name
 *   filtering); the download write chain (downloader.py:700 join of the
 *   XML-index filename -> os.mkdir :708/:710, open(filepath, 'wb') :718,
 *   os.remove :704, status joins/walks :888/:902/:922/:923); retrieve()'s
 *   write (data.py:732 open(filename, 'wb') with the URL-derived filename
 *   :718/:720); the HTTP request path channel of the wordnet browser
 *   (app/wordnet_app.py:118 unquote_plus percent-decode -> :121-:122
 *   isfile + open(usp, 'r') - guarded by an exact literal equality);
 *   the corpus reader fileid channels (corpus/reader/api.py root+fileid
 *   via the data.py pointer join; crubadan.py:78/:97 bare path.join ->
 *   open :83/:104; mte.py joins; nkjp.py:253/:258; framenet.py locpath
 *   joins; panlex_lite.py:46 sqlite3.connect(join(root, 'db.sqlite')));
 *   StreamBackedCorpusView's stat+open on the fileid
 *   (corpus/reader/util.py:181/:218/:221); the twitter output writes
 *   (twitterclient.py:497 mkdir, :499 join, :518/:520 open;
 *   common.py:144/:150 gzip.open; twitter/util.py:84-:91 normpath+join+
 *   isfile+open of the credentials file); the gz-variant resource reads
 *   (data.py:482/:484 GzipFileSystemPathPointer.open); the archive openers
 *   (zipfile.ZipFile downloader.py:2255/:2471, OpenOnDemandZipFile
 *   data.py:506, the weka jar check classify/weka.py:74); os.remove/
 *   unlink/rmdir (22 sites, incl. the stale-package removal
 *   downloader.py:704 driven by the XML-index filename); os.listdir/
 *   os.walk (incl. the internals.py env-dir searches :770/:788/:809/:862
 *   and find_corpus_fileids' followlinks=True walk
 *   corpus/reader/util.py:821); codecs.open (8 sites); and the
 *   os.path join/stat/normalize/decode propagation nodes scoped to the
 *   traversal-relevant modules. Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not
 *   database analyze). This is a plain multi-column select query on
 *   purpose: @kind problem is the wrong shape for candidate tables and
 *   @kind table is not assumed to exist.
 * @id iris/nltk/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member/field name ("open" / "GzipFile" /
 *                   "BufferedGzipFile" / "ZipFile" / "OpenOnDemandZipFile" /
 *                   "connect" / "mkdir" / "remove" / "unlink" / "rmdir" /
 *                   "listdir" / "walk" / "join" / "exists" / "isfile" /
 *                   "isdir" / "isabs" / "stat" / "access" / "abspath" /
 *                   "normpath" / "expanduser" / "url2pathname" /
 *                   "unquote_plus")
 *   4. flow_kind  - "file_open" (builtin open(...) - argument 0 carries
 *                   the path),
 *                   "codecs_open" (codecs.open(argument 0)),
 *                   "gzip_open" (GzipFile(...)/BufferedGzipFile(...) Name
 *                   forms in data.py and gzip.open(argument 0) in twitter -
 *                   the gz-variant reads and the tweet output writes),
 *                   "archive_open" (zipfile.ZipFile(...) /
 *                   OpenOnDemandZipFile(...) - argument 0 carries the
 *                   archive path),
 *                   "db_open" (sqlite3.connect(argument 0) - the sqlite
 *                   database file),
 *                   "dir_create" (os.mkdir - argument 0),
 *                   "file_remove" (os.remove/os.unlink/os.rmdir -
 *                   argument 0),
 *                   "dir_list" (os.listdir - argument 0),
 *                   "dir_walk" (os.walk - argument 0),
 *                   "path_join" (os.path.join argument 0 - the
 *                   propagation join, scoped to the traversal-relevant
 *                   modules; includes the bare path.join of crubadan/
 *                   senna and the bare join of tag/mapping, verified
 *                   against their import statements),
 *                   "path_stat" (os.path.exists/isfile/isdir/isabs +
 *                   os.stat/os.access argument 0 - guard reads, TOCTOU
 *                   shape; the bare path.isfile of crubadan/senna),
 *                   "path_normalize" (os.path.abspath/normpath/realpath/
 *                   expanduser argument 0 - normalization WITHOUT
 *                   containment; the bare path.normpath of senna),
 *                   "path_decode" (url2pathname(argument 0) in data.py
 *                   and unquote_plus(argument 0) in wordnet_app.py - the
 *                   percent-decode nodes, CWE-36 mixed decoder)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "os"/"os.path"/"zipfile"/"sqlite3"/
 *                   "gzip"/"codecs"/"tar handle name" etc., or "" if
 *                   none; "<expr>" for receivers that are neither Name
 *                   nor Attribute)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "builtins"/"codecs"/"gzip"/"zipfile"/"sqlite3"/
 *                   "os"/"os.path"/"urllib" for the stdlib channels
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for every positional family here)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): the sink core is the FILE
 * PATH PARAMETER of actual filesystem operations (open, codecs.open,
 * gzip open, zipfile.ZipFile, sqlite3.connect, mkdir, remove/unlink/rmdir,
 * listdir, walk) - NOT every path string construction node. The
 * os.path join/stat/normalize/decode families are therefore scoped to the
 * modules where they sit inside the traversal-relevant flows (the resource
 * resolver data.py, the downloader data.py channel downloader.py, the
 * twitter helpers, the corpus reader tree, the internals/weka/senna
 * env-dir searches, the stanford_segmenter/tag-mapping lookup joins, the
 * chat80 db guards, and app/wordnet_app.py for the percent-decode); across
 * the rest of the tree the remaining os.path.join / exists sites are pure
 * app/sem/draw/tgrep plumbing anchored by their consuming open/remove rows
 * - a MySummaries taint step must be added in Phase 2 if one of those
 * flows needs tracing. dirname/basename/split/splitext part-extraction
 * nodes are NOT emitted (anchored by their consuming rows; documented in
 * detection.json uncoveredCases).
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching out entirely
 * (all channels are builtin/stdlib module members matched on the syntactic
 * qualifier - the stdlib, six and gzip are not part of this database - or
 * instance member calls on local names; the match_kind column is kept
 * "ast" for cross-project contract consistency with the prior projects of
 * this series). The builtin open() family matches only the Name form
 * (c.getFunc() is a Name "open"), so zipfile.ZipFile, GzipFile and any
 * X.open(...) member calls are never double-counted; the gzip.open family
 * (Attribute "open" on Name "gzip") cannot collide with the Name form; the
 * namelist-derived member reads (zf.open(filename) downloader.py:2290)
 * read in-memory entry content and are anchored by the :2290 open() row.
 * Bare-name os members (from os import path - crubadan.py:25, senna.py:43;
 * from os.path import join - tag/mapping.py:34) are matched through the
 * per-module import allowlists below, mirroring the actual import
 * statements of those files.
 *
 * Not observed anywhere in the tree (recorded in detection.json
 * notObserved): os.open, os.rename, os.symlink, os.chmod, os.makedirs,
 * glob, pathlib, tarfile/extractall (the downloader unpack is the
 * hand-rolled join+mkdir+open loop at downloader.py:2281/:2283/:2287/:2290)
 * and shutil path operations (the single shutil call is copyfileobj on
 * streams at downloader.py:2291).
 *
 * Excluded paths (applied to every row, in addition to the positive scope):
 * nltk/test/ (the package's test tree). The CodeQL database nltk-db sits in
 * the source ROOT as a sibling of the nltk/ package, so the positive scope
 * %/nltk/% excludes it by construction (the path component "nltk-db" never
 * matches "/nltk/"); a defensive filter is kept in excludedPath anyway.
 * Repo-root build/site tooling (setup.py, tools/, web/, Makefile, jenkins*)
 * is never a candidate.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  have no dotted module name; their file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
}

/** Forward-slash-normalized absolute path of the file containing n, so path
 *  matching works with both CodeQL path styles on Windows. */
string normalizedPathOf(AstNode n) {
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
}

/** True iff the candidate's file path is one of the excluded trees. Path is
 *  normalized to forward slashes before matching so the query works on both
 *  CodeQL path styles. bindingset[path] declares that the caller passes a
 *  bound path (the path only appears in checked positions such as the
 *  receiver of replaceAll/matches inside this predicate). */
bindingset[path]
predicate excludedPath(string path) {
  path.replaceAll("\\", "/").matches("%/nltk-db/%")
  or
  path.replaceAll("\\", "/").matches("%/nltk/test/%")
}

/** True iff the candidate is inside the audited nltk package tree (positive
 *  scope; the whole shipped python package). Same bindingset rationale as
 *  excludedPath. */
bindingset[path]
predicate inScope(string path) {
  path.replaceAll("\\", "/").matches("%/nltk/%")
}

/** True iff the candidate is inside one of the traversal-relevant modules
 *  where the os.path propagation families (path_join / path_stat /
 *  path_normalize) sit inside real file-access flows: the resource
 *  resolver (data.py), the downloader channel (downloader.py), the twitter
 *  helpers (twitter/), the corpus reader tree (corpus/reader/), the
 *  external-tool env-dir searches (internals.py, classify/weka.py,
 *  classify/senna.py, tokenize/stanford_segmenter.py), the tag-mapping
 *  data-load join (tag/mapping.py), the chat80 db guards (sem/chat80.py)
 *  and the wordnet browser decode (app/wordnet_app.py). Same bindingset
 *  rationale as excludedPath. */
bindingset[path]
predicate inPropagationScope(string path) {
  path.replaceAll("\\", "/").matches("%/nltk/data.py")
  or
  path.replaceAll("\\", "/").matches("%/nltk/downloader.py")
  or
  path.replaceAll("\\", "/").matches("%/nltk/twitter/%")
  or
  path.replaceAll("\\", "/").matches("%/nltk/corpus/reader/%")
  or
  path.replaceAll("\\", "/").matches("%/nltk/internals.py")
  or
  path.replaceAll("\\", "/").matches("%/nltk/classify/weka.py")
  or
  path.replaceAll("\\", "/").matches("%/nltk/classify/senna.py")
  or
  path.replaceAll("\\", "/").matches("%/nltk/tokenize/stanford_segmenter.py")
  or
  path.replaceAll("\\", "/").matches("%/nltk/tag/mapping.py")
  or
  path.replaceAll("\\", "/").matches("%/nltk/sem/chat80.py")
  or
  path.replaceAll("\\", "/").matches("%/nltk/app/wordnet_app.py")
}

/** True iff the candidate's file uses a bare-name os.path alias that the
 *  qualified families cannot match: corpus/reader/crubadan.py:25
 *  `from os import path` (path.join :78/:97, path.isfile :99) and
 *  classify/senna.py:43 `from os import path, sep, environ`
 *  (path.join :91-:97, path.normpath :62/:71, path.isfile :67/:73/:126).
 *  Same bindingset rationale as excludedPath. */
bindingset[path]
private predicate bareOsPathAliasModule(string path) {
  path.matches("%/nltk/corpus/reader/crubadan.py")
  or
  path.matches("%/nltk/classify/senna.py")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: builtin open(...) - ~60 in-scope Name-form sites. The
     traversal-relevant ones: data.py:345 open(self._path, 'rb') inside
     FileSystemPathPointer.open - THE central resource read (fed by
     find()'s os.path.join(path_, url2pathname(resource_name)) :650/:657
     and the pointer join :354, NO containment); downloader.py:2290
     open(filepath, 'wb') - THE zip-slip write (filepath =
     os.path.join(root, *filename.split('/')) :2287 from a namelist entry,
     NO filtering); downloader.py:718 open(filepath, 'wb') - the package
     download write (filepath = os.path.join(download_dir, info.filename)
     :700 with the XML-index filename); data.py:732 open(filename, 'wb') -
     retrieve's write (filename from the resource_url :718/:720);
     app/wordnet_app.py:122 open(usp, 'r') - the HTTP request path
     (guarded by the exact literal 'NLTK Wordnet Browser Database Info.html'
     at :119); twitter/util.py:91/:138 - the credentials read/append;
     the corpus reader opens (crubadan :83/:104, ipipan :72/:203, lin :44,
     nkjp :258, pl196x :114, xmldocs :173, util :218/:221); perceptron
     :111/:235/:322, transitionparser :542/:556, weka :282, agreement :468
     (CLI demo), the app-dialog saves/loads, tbl/demo.py, the
     maxent/malt/stanford-family tempfiles, tree :821, draw :1871,
     distance :265, util :208, __init__ :31 (fixed VERSION read) and
     punkt :1492 (fixed /tmp/punkt.new). Only the Name form matches, so
     zipfile.ZipFile, GzipFile and member .open(...) calls are never
     counted here. */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* family 2: codecs.open(...) (argument 0 carries the path) - 8 sites:
     corpus/reader/dependency.py:45 (the fileid read of the dependency
     corpus reader - same fileid traversal channel as family 1's corpus
     opens), sem/util.py:147, sentiment/util.py:280/:303/:394/:465/:486
     (sentiment model/vocab/csv file channels) and toolbox.py:46 (the
     SFM corpus file read). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "codecs" and
    node = c and
    flowKind = "codecs_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "codecs" and
    moduleHint = "codecs" and
    matchKind = "ast"
  )
  or
  /* family 3: the gz-variant reads and the tweet output writes -
     GzipFile(...)/BufferedGzipFile(...) Name forms in data.py and
     gzip.open(...) Attribute calls in twitter. data.py:484
     GzipFile(self._path, 'rb') and :482 BufferedGzipFile(self._path, 'rb')
     inside GzipFileSystemPathPointer.open (:477) - the gz-variant of the
     central resource read; data.py:557/:559 BufferedGzipFile/GzipFile(
     self._entry, ...) inside ZipFilePathPointer.open (in-zip entry names -
     content read, no fs path); data.py:135 GzipFile(filename, mode, ...)
     inside BufferedGzipFile.__init__; twitter/twitterclient.py:518
     gzip.open(self.fname, 'w') - the tweet output write (fname =
     os.path.join(subdir, fprefix) :499); twitter/common.py:144/:150
     gzip.open(outfile, ...) - the json2csv gz output writes. Argument 0
     carries the path (or the in-zip entry name). */
  exists(Call c |
    (c.getFunc().(Name).getId() = "GzipFile"
     or c.getFunc().(Name).getId() = "BufferedGzipFile") and
    node = c and
    flowKind = "gzip_open" and
    callableName = c.getFunc().(Name).getId() and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "gzip" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "gzip" and
    node = c and
    flowKind = "gzip_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "gzip" and
    moduleHint = "gzip" and
    matchKind = "ast"
  )
  or
  /* family 4: archive openers - zipfile.ZipFile(...) (downloader.py:2255
     zf = zipfile.ZipFile(filename) in _unzip_iter - opens the DOWNLOADED
     package whose entry names then drive the extraction writes; :2471 in
     the index builder; classify/weka.py:74 ZipFile(jar) - the WEKAHOME
     jar check) and the locally-defined OpenOnDemandZipFile(...)
     (data.py:506 in ZipFilePathPointer.__init__ - os.path.abspath(zipfile)
     then the namelist entry scan :515/:522). Argument 0 carries the
     archive path. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "ZipFile" and
    func.getObject().(Name).getId() = "zipfile" and
    node = c and
    flowKind = "archive_open" and
    callableName = "ZipFile" and
    argIndex = 0 and
    receiver = "zipfile" and
    moduleHint = "zipfile" and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "OpenOnDemandZipFile" and
    node = c and
    flowKind = "archive_open" and
    callableName = "OpenOnDemandZipFile" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5: sqlite database opens - sqlite3.connect(argument 0):
     corpus/reader/panlex_lite.py:46 sqlite3.connect(os.path.join(root,
     'db.sqlite')) - the PanLex corpus DB (root is a CorpusReader
     parameter); sem/chat80.py:431 sqlite3.connect(dbname) and :462
     sqlite3.connect(str(nltk.data.find(dbname))) - the chat80 query DB
     (find resolves the resource name); sem/relextract.py:329
     sqlite3.connect(':memory:') - a constant, non-path (emitted for
     completeness; the labeling step filters). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "connect" and
    func.getObject().(Name).getId() = "sqlite3" and
    node = c and
    flowKind = "db_open" and
    callableName = "connect" and
    argIndex = 0 and
    receiver = "sqlite3" and
    moduleHint = "sqlite3" and
    matchKind = "ast"
  )
  or
  /* family 6: directory creation - os.mkdir (argument 0): downloader.py:708
     os.mkdir(download_dir) and :710 os.mkdir(os.path.join(download_dir,
     info.subdir)) - the package install dirs (subdir from the XML index);
     downloader.py:2275 os.mkdir(root) and :2283 os.mkdir(dirpath) with
     dirpath = os.path.join(root, *pieces[:i+1]) :2281 - THE zip-slip
     DIRECTORY writes from entry names; twitter/twitterclient.py:497
     os.mkdir(subdir) - the TweetWriter output dir (subdir is a
     constructor parameter). os.makedirs does not appear anywhere in the
     tree. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "mkdir" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "dir_create" and
    callableName = "mkdir" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 7: file removal - os.remove/os.unlink/os.rmdir (argument 0) -
     22 sites: downloader.py:704 os.remove(filepath) - the stale-package
     removal (filepath from the XML-index filename join :700);
     corpus/reader/util.py:540 - the PickleCorpusView GC delete of its
     fileid; corpus/reader/nkjp.py:282; the tempfile teardowns
     (classify/maxent.py:1493/:1560/:1561, classify/weka.py:140-:141/
     :247-:248 incl. the rmdir temp-dir removal, parse/malt.py:225/:226/
     :299, parse/stanford.py:273, sem/boxer.py:241, tag/stanford.py:121,
     tokenize/stanford.py:117, tokenize/stanford_segmenter.py:277) and
     tree.py:823/:824. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "remove" or func.getName() = "unlink"
     or func.getName() = "rmdir") and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "file_remove" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 8: directory listings - os.listdir (argument 0): internals.py:770
     (the CLASSPATH jar scan), :788 (the jar_env scan) and :809 (the
     search-path scan of find_binary_iter/find_jar_iter - env-var-derived
     dirs); classify/weka.py:139/:246 (the temp-dir cleanup scans). The
     compat.py:167 _listdir = staticmethod(_os.listdir) aliases are Assign
     targets on the name _os, not os-qualified Calls - never matched. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "listdir" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "dir_list" and
    callableName = "listdir" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 9: directory walks - os.walk (argument 0):
     corpus/reader/util.py:821 os.walk(root.path, followlinks=True) in
     find_corpus_fileids - the corpus fileid discovery that FOLLOWS
     SYMLINKS; chunk/named_entity.py:215; downloader.py:923 (the
     unzipped-size status check over unzipdir), :2443/:2464 (the index
     builder); internals.py:862 (the recursive jar discovery of
     find_jars_within_path). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "walk" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "dir_walk" and
    callableName = "walk" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 10: the os.path.join propagation nodes, scoped to the
     traversal-relevant modules (inPropagationScope): data.py:650/:657
     os.path.join(path_, url2pathname(resource_name)) - THE unchecked
     resource join of find(); :354 _path = os.path.join(self._path,
     fileid) - the pointer join (no containment); :99-:112 the search-path
     list construction joins (sys.prefix/APPDATA constants);
     downloader.py:270 (XML-index filename), :700, :710, :740, :888, :922,
     :2281, :2287 (the zip-slip joins); the corpus reader joins (crubadan
     :78/:97 via the bare path alias, mte's 9 root+fileid joins,
     framenet :1403/:1488/:1832, nkjp :68/:253, panlex_lite :46);
     twitter/util.py:85/:130, twitterclient.py:499; internals.py's 14
     env-dir/jar search joins; classify/weka.py:52/:53/:106/:223;
     tokenize/stanford_segmenter.py:139; tag/mapping.py:60 via the bare
     join alias (from os.path import join) - join(_UNIVERSAL_DATA, fileid
     + '.map') feeding the nltk data load with the fileid parameter.
     Argument 0 carries the base; argument 1+ the appended components. */
  exists(Call c, Attribute func, Attribute mid |
    func = c.getFunc().(Attribute) and
    func.getName() = "join" and
    mid = func.getObject().(Attribute) and
    mid.getName() = "path" and
    mid.getObject().(Name).getId() = "os" and
    inPropagationScope(normalizedPathOf(c)) and
    node = c and
    flowKind = "path_join" and
    callableName = "join" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "join" and
    func.getObject().(Name).getId() = "path" and
    bareOsPathAliasModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "path_join" and
    callableName = "join" and
    argIndex = 0 and
    receiver = "path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "join" and
    normalizedPathOf(c).matches("%/nltk/tag/mapping.py") and
    node = c and
    flowKind = "path_join" and
    callableName = "join" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 11: the guard/validation reads (TOCTOU shape) -
     os.path.exists/isfile/isdir/isabs + os.stat/os.access, scoped to the
     traversal-relevant modules: data.py:640/:648/:651/:658 (the find()
     path checks - separate syscalls from the :345 open), :721/:732
     (retrieve), :332 (the FileSystemPathPointer existence check vs the
     :345 open); downloader.py:701/:707/:709/:716/:743, :897/:902 (os.stat),
     :916/:918; twitter/util.py:88 (the creds isfile check);
     corpus/reader/util.py:181 (os.stat on the fileid);
     sem/chat80.py:638/:817 (os.access on the dbname); the
     internals.py:763 / senna.py:67/:73/:126 / crubadan.py:99 isfile
     guards of the env-dir and corpus-ngram lookups. */
  exists(Call c, Attribute func, Attribute mid |
    func = c.getFunc().(Attribute) and
    (func.getName() = "exists" or func.getName() = "isfile"
     or func.getName() = "isdir" or func.getName() = "isabs") and
    mid = func.getObject().(Attribute) and
    mid.getName() = "path" and
    mid.getObject().(Name).getId() = "os" and
    inPropagationScope(normalizedPathOf(c)) and
    node = c and
    flowKind = "path_stat" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "stat" or func.getName() = "access") and
    func.getObject().(Name).getId() = "os" and
    inPropagationScope(normalizedPathOf(c)) and
    node = c and
    flowKind = "path_stat" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "isfile" and
    func.getObject().(Name).getId() = "path" and
    bareOsPathAliasModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "path_stat" and
    callableName = "isfile" and
    argIndex = 0 and
    receiver = "path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 12: the normalization-without-containment nodes -
     os.path.abspath/normpath/realpath/expanduser, scoped to the
     traversal-relevant modules: data.py:331 abspath in
     FileSystemPathPointer.__init__ (resolves '..' but confines to
     NOTHING), :506 abspath(zipfile), :257 normpath in
     normalize_resource_name (KEEPS a leading '..'), :261 abspath(join(
     relative_path, resource_name)), :575 normpath, :722 abspath in
     retrieve, :94/:103 expanduser; twitter/util.py:84 normpath (the
     creds path), :152 expanduser (guess_path);
     classify/senna.py:62/:71 path.normpath (the SENNA executable dir)
     via the bare alias. realpath does not appear anywhere in the tree -
     there is NO canonicalize-and-contain check in any flow. */
  exists(Call c, Attribute func, Attribute mid |
    func = c.getFunc().(Attribute) and
    (func.getName() = "abspath" or func.getName() = "normpath"
     or func.getName() = "realpath" or func.getName() = "expanduser") and
    mid = func.getObject().(Attribute) and
    mid.getName() = "path" and
    mid.getObject().(Name).getId() = "os" and
    inPropagationScope(normalizedPathOf(c)) and
    node = c and
    flowKind = "path_normalize" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "normpath" and
    func.getObject().(Name).getId() = "path" and
    bareOsPathAliasModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "path_normalize" and
    callableName = "normpath" and
    argIndex = 0 and
    receiver = "path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 13: the percent-decode nodes (CWE-36 mixed decoder):
     data.py:650 p = os.path.join(path_, url2pathname(resource_name)) and
     :657 - the resource name is percent-decoded (%XX) BEFORE the join, so
     '%2e%2e%2f' decodes to '../' and bypasses any naive '..' string
     check (url2pathname imported at data.py:49 from
     six.moves.urllib.request); app/wordnet_app.py:99/:118
     usp = unquote_plus(sp) - the HTTP request path decode (imported at
     :66). Argument 0 carries the encoded value; the RETURN VALUE is the
     decoded path that flows into the join/open families. */
  exists(Call c |
    c.getFunc().(Name).getId() = "url2pathname" and
    normalizedPathOf(c).matches("%/nltk/data.py") and
    node = c and
    flowKind = "path_decode" and
    callableName = "url2pathname" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "urllib" and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "unquote_plus" and
    normalizedPathOf(c).matches("%/nltk/app/wordnet_app.py") and
    node = c and
    flowKind = "path_decode" and
    callableName = "unquote_plus" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "urllib" and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  inScope(node.getLocation().getFile().getAbsolutePath()) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
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
