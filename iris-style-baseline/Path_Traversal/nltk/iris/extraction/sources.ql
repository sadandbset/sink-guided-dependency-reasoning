/**
 * @name nltk CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   nltk CodeQL database (NLTK 3.4.4 natural language toolkit library - the
 *   nltk/ package tree is the audit target). nltk is a LIBRARY with no web
 *   framework; the untrusted boundaries observed first-hand are: the wordnet
 *   browser HTTP request path (the raw self.path read of
 *   MyServerHandler.do_GET at nltk/app/wordnet_app.py:98 - the only
 *   BaseHTTPRequestHandler subclass in the tree, served by
 *   HTTPServer(('', port), MyServerHandler) at :247 which binds ALL
 *   interfaces - percent-decoded by unquote_plus at :99/:118 and fed to
 *   open(usp, 'r') at :122 (guarded by an exact literal equality) and the
 *   exact-literal dispatcher get_static_page_by_path at :813); the
 *   downloader's NETWORK inputs (the XML index: ElementTree.parse(urlopen(
 *   self._url)) at nltk/downloader.py:962 -> Package.fromxml xml.attrib reads
 *   :286-:288 -> Package(id, url, subdir,...) with
 *   self.filename = os.path.join(subdir, id + ext) at :270; the package zip
 *   ENTRY NAMES: namelist = zf.namelist() at :2264 in _unzip_iter, which are
 *   joined onto the extraction root with NO filtering at :2281/:2287 and
 *   written with os.mkdir :2283 / open(filepath, 'wb') :2290 - the hand-rolled
 *   zip-slip channel; the urlopen response bodies written to disk at :718);
 *   the library's PUBLIC API parameters (the application-facing boundary of
 *   a library: data.find(resource_name), data.load/_open/retrieve(
 *   resource_url, filename), FileSystemPathPointer/ZipFilePathPointer
 *   constructors and .join(fileid), CorpusReader(root, fileids)/.open(file)/
 *   .abspath(fileid), StreamBackedCorpusView(fileid), LazyCorpusLoader(name),
 *   unzip/_unzip_iter(filename, root), Downloader.download(..., download_dir),
 *   the twitter helper params, the perceptron/transitionparser/stanford model
 *   file params and the chat80 dbname params) - emitted as definition-side
 *   Parameter rows so the labeling step can classify which wrapper entries
 *   are true boundaries; the environment variables (os.environ.get NLTK_DATA
 *   data.py:91, APPDATA :102, NLTK_DOWNLOAD_URL downloader.py:2568 -
 *   OPERATOR trust level); and the DownloaderShell interactive inputs
 *   (input('  New Directory> ') downloader.py:1276 - the interactive
 *   download-dir boundary, input('  New URL> ') :1284 - the data server URL,
 *   plus 6 package-identifier/confirmation/menu prompts - INTERACTIVE trust
 *   level). Raw BQRS extraction query: run with `codeql query run` and
 *   decode with `codeql bqrs decode` (not database analyze). This is a
 *   plain multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/nltk/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name ("path", "urlopen",
 *                   "attrib", "namelist", the wrapper function name for
 *                   lib_api_param rows, "get", "input")
 *   4. flow_kind  - "http_request_path" (the self.path read of the wordnet
 *                   browser's do_GET),
 *                   "net_fetch" (urlopen(...) - the XML index / package /
 *                   http-resource fetches; the RESPONSE body carries the
 *                   untrusted data),
 *                   "net_xml_attr" (the xml.attrib reads of
 *                   Package.fromxml / Collection.fromxml - data-server
 *                   controlled id/subdir/url path components),
 *                   "archive_entry" (.namelist() - the zip entry names that
 *                   drive the _unzip_iter extraction destinations; the
 *                   downloader ones are network-origin, the data.py /
 *                   corpus reader ones are archive-content-origin),
 *                   "lib_api_param" (definition-side Parameter rows of the
 *                   library's path-taking public APIs - the
 *                   application-facing boundary of a library),
 *                   "env" (os.environ.get reads - operator trust level),
 *                   "cli_input" (input() reads of the downloader interactive
 *                   shell - interactive trust level)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "self"/"zf"/"os.environ" etc., or "" if
 *                   none; "" for lib_api_param rows of module-level
 *                   functions, the class name for methods, the enclosing
 *                   function name is reported via callable)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "urllib" (six.moves.urllib.request), "zipfile",
 *                   "os", "builtins" for the external channels
 *   7. arg_index  - 0-based positional argument index (index of the key
 *                   argument for keyed reads such as environ.get(name); -1
 *                   when the tainted value is the return value or the
 *                   attribute itself; the parameter position in the
 *                   function definition for lib_api_param rows, self
 *                   occupies position 0 for methods)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching out entirely:
 * http.server, urllib (via six.moves), zipfile, gzip, sqlite3 and os are
 * stdlib and six is external - none of them are part of this database (only
 * the nltk/ tree is) - so no source row can resolve at API level. All
 * families are AST-level matches and the match_kind column is kept "ast"
 * for cross-project contract consistency with the prior projects of this
 * series (aiohttp/airflow/ansible/coderedcms/copyparty/dfetch/django/
 * fides/ganga).
 *
 * Receiver-name scoping: the http family matches the self.path attribute
 * read scoped to app/wordnet_app.py (the only BaseHTTPRequestHandler
 * subclass in the tree); the net/cli families match bare names (urlopen /
 * input) scoped by file (verified import style: `from six.moves.urllib.
 * request import urlopen` data.py:49 / downloader.py:189, builtin input);
 * the archive family matches the .namelist() member call scoped to the
 * three files that actually use it. A module aliasing these imports
 * differently would be missed (recorded in detection.json
 * uncoveredCases).
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

/** Base name of the object expression of an attribute access, used as a receiver hint. */
string receiverHint(Attribute a) {
  result = a.getObject().(Name).getId()
  or
  result = a.getObject().(Attribute).getName()
  or
  not a.getObject() instanceof Name and
  not a.getObject() instanceof Attribute and
  result = "<expr>"
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

/** The library's path-taking public API definitions with their
 *  path-relevant parameter (function, parameter) - definition rows for the
 *  lib_api_param family. The entries are the wrapper boundaries an
 *  application can steer into filesystem access (see detection.json
 *  inputBoundaryInventory for the trust chains). Parameter positions are
 *  0-based; for methods, self occupies position 0. Module-level functions
 *  are matched by name + file; methods by name + file + enclosing class
 *  name (data.py defines two join methods and perceptron.py two load
 *  methods, so the class constraint is required). */
private predicate fileApiParamShape(Function f, Parameter p) {
  /* ---------------- nltk.data - the resource path machinery ------------- */
  /* nltk.data.find(resource_name, paths=None) - data.py:589 (position 0) -
     THE resource resolver: normalize_resource_name (normpath KEEPS a
     leading '..') then os.path.join(path_, url2pathname(resource_name))
     (:650/:657 - percent-decoded join, NO containment) then
     FileSystemPathPointer -> open (:345). */
  f.getName() = "find" and
  normalizedPathOf(f).matches("%/nltk/data.py") and
  p.getName() = "resource_name" and
  p = f.getAnArg()
  or
  /* nltk.data.retrieve(resource_url, filename, verbose) - data.py:704
     (resource_url position 0, filename position 1) - the resource copy
     helper: filename defaults to the URL basename (:718/:720) and is
     written with open(filename, 'wb') (:732) - no containment. */
  f.getName() = "retrieve" and
  normalizedPathOf(f).matches("%/nltk/data.py") and
  (p.getName() = "resource_url" or p.getName() = "filename") and
  p = f.getAnArg()
  or
  /* nltk.data.load(resource_url, format, ...) - data.py:780 (position 0) -
     the resource loader: delegates to _open (:975) -> find/urlopen. */
  f.getName() = "load" and
  normalizedPathOf(f).matches("%/nltk/data.py") and
  p.getName() = "resource_url" and
  p = f.getAnArg()
  or
  /* nltk.data.FileSystemPathPointer.__init__(self, _path) - data.py:324
     (_path position 1) - the pointer constructor: os.path.abspath(_path)
     (:331 - normalization WITHOUT confinement) + exists check (:332). */
  f.getName() = "__init__" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "FileSystemPathPointer" and
  normalizedPathOf(f).matches("%/nltk/data.py") and
  p.getName() = "_path" and
  p = f.getAnArg()
  or
  /* FileSystemPathPointer.join(self, fileid) - data.py:353 (fileid at
     position 1) - _path = os.path.join(self._path, fileid) (:354, NO
     containment) -> returned pointer's open (:345). */
  f.getName() = "join" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "FileSystemPathPointer" and
  normalizedPathOf(f).matches("%/nltk/data.py") and
  p.getName() = "fileid" and
  p = f.getAnArg()
  or
  /* nltk.data.ZipFilePathPointer.__init__(self, zipfile, entry) - data.py:497
     (zipfile position 1, entry position 2) - os.path.abspath(zipfile)
     (:506) + the entry existence check over namelist (:515/:522). */
  f.getName() = "__init__" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "ZipFilePathPointer" and
  normalizedPathOf(f).matches("%/nltk/data.py") and
  (p.getName() = "zipfile" or p.getName() = "entry") and
  p = f.getAnArg()
  or
  /* ZipFilePathPointer.join(self, fileid) - data.py:567 (fileid at
     position 1) - entry = '%s/%s' % (self._entry, fileid) (:568) - the
     in-zip path constructor (content-boundary, not fs-boundary). */
  f.getName() = "join" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "ZipFilePathPointer" and
  normalizedPathOf(f).matches("%/nltk/data.py") and
  p.getName() = "fileid" and
  p = f.getAnArg()
  or
  /* ---------------- nltk.corpus - the corpus reader API ---------------- */
  /* nltk.corpus.reader.api.CorpusReader.__init__(self, root, fileids,
     encoding, tagset) - corpus/reader/api.py:47 (root position 1, fileids
     position 2) - root is converted via the .zip regex into a
     ZipFilePathPointer / FileSystemPathPointer (:81-:84); fileids may be a
     regexp expanded by find_corpus_fileids. */
  f.getName() = "__init__" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "CorpusReader" and
  normalizedPathOf(f).matches("%/nltk/corpus/reader/api.py") and
  (p.getName() = "root" or p.getName() = "fileids") and
  p = f.getAnArg()
  or
  /* CorpusReader.abspath(self, fileid) - api.py:159 (fileid position 1) -
     returns self._root.join(fileid) - the fileid traversal channel. */
  f.getName() = "abspath" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "CorpusReader" and
  normalizedPathOf(f).matches("%/nltk/corpus/reader/api.py") and
  p.getName() = "fileid" and
  p = f.getAnArg()
  or
  /* CorpusReader.open(self, file) - api.py:204 (file position 1) -
     self._root.join(file).open(encoding) (:213) -> FileSystemPathPointer
     join (:354) -> open (:345) - the corpus read entry. */
  f.getName() = "open" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "CorpusReader" and
  normalizedPathOf(f).matches("%/nltk/corpus/reader/api.py") and
  p.getName() = "file" and
  p = f.getAnArg()
  or
  /* nltk.corpus.reader.util.StreamBackedCorpusView.__init__(self, fileid,
     block_reader, startpos, encoding) - corpus/reader/util.py:131 (fileid
     position 1) - os.stat(self._fileid) (:181) and open(self._fileid, 'rb')
     (:218/:221) - the view-level file open. */
  f.getName() = "__init__" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "StreamBackedCorpusView" and
  normalizedPathOf(f).matches("%/nltk/corpus/reader/util.py") and
  p.getName() = "fileid" and
  p = f.getAnArg()
  or
  /* nltk.corpus.util.LazyCorpusLoader.__init__(self, name, reader_cls,
     *args, **kwargs) - corpus/util.py:53 (name position 1) - the lazy
     corpus name feeds data.find on first access. */
  f.getName() = "__init__" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "LazyCorpusLoader" and
  normalizedPathOf(f).matches("%/nltk/corpus/util.py") and
  p.getName() = "name" and
  p = f.getAnArg()
  or
  /* ---------------- nltk.downloader - the archive channel -------------- */
  /* nltk.downloader.unzip(filename, root, verbose) - downloader.py:2239
     (filename position 0, root position 1) - the public unzip helper that
     delegates to _unzip_iter. */
  f.getName() = "unzip" and
  normalizedPathOf(f).matches("%/nltk/downloader.py") and
  (p.getName() = "filename" or p.getName() = "root") and
  p = f.getAnArg()
  or
  /* nltk.downloader._unzip_iter(filename, root, verbose) -
     downloader.py:2249 (filename position 0, root position 1) - THE
     hand-rolled zip-slip unpack loop: zipfile.ZipFile(filename) (:2255),
     namelist (:2264), os.path.join(root, *pieces) (:2281/:2287) ->
     os.mkdir (:2283) / open(filepath, 'wb') (:2290) - NO entry-name
     filtering, NO containment. */
  f.getName() = "_unzip_iter" and
  normalizedPathOf(f).matches("%/nltk/downloader.py") and
  (p.getName() = "filename" or p.getName() = "root") and
  p = f.getAnArg()
  or
  /* Downloader.download(self, info_or_id, download_dir, ...) -
     downloader.py:753 (download_dir position 2) - the download
     destination dir (feeds the mkdir/open/unzip chain). */
  f.getName() = "download" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "Downloader" and
  normalizedPathOf(f).matches("%/nltk/downloader.py") and
  p.getName() = "download_dir" and
  p = f.getAnArg()
  or
  /* Downloader.incr_download(self, info_or_id, download_dir, force) -
     downloader.py:622 (download_dir position 2) - the generator driving
     _download_package with the same destination dir. */
  f.getName() = "incr_download" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "Downloader" and
  normalizedPathOf(f).matches("%/nltk/downloader.py") and
  p.getName() = "download_dir" and
  p = f.getAnArg()
  or
  /* Downloader._download_package(self, info, download_dir, force) -
     downloader.py:684 (download_dir position 2) - filepath =
     os.path.join(download_dir, info.filename) (:700) -> os.remove (:704) /
     os.mkdir (:708/:710) / open(filepath, 'wb') (:718) / zipdir join
     (:740) -> _unzip_iter (:745). */
  f.getName() = "_download_package" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "Downloader" and
  normalizedPathOf(f).matches("%/nltk/downloader.py") and
  p.getName() = "download_dir" and
  p = f.getAnArg()
  or
  /* nltk.downloader.build_index(root, base_url) - downloader.py:2309 (root
     position 0) - the operator-side index builder that walks a local
     corpus root and zips it (os.walk :2443/:2464, zipfile.ZipFile :2471,
     namelist :2491). */
  f.getName() = "build_index" and
  normalizedPathOf(f).matches("%/nltk/downloader.py") and
  p.getName() = "root" and
  p = f.getAnArg()
  or
  /* ---------------- nltk.twitter - the helper surface ------------------ */
  /* nltk.twitter.util.Authenticate.load_creds(self, creds_file, subdir,
     verbose) - twitter/util.py:47 (creds_file position 1, subdir
     position 2) - creds_fullpath = os.path.normpath(os.path.join(subdir,
     creds_file)) (:84-:86) -> open (:91 read / :138 append). */
  f.getName() = "load_creds" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "Authenticate" and
  normalizedPathOf(f).matches("%/nltk/twitter/util.py") and
  (p.getName() = "creds_file" or p.getName() = "subdir") and
  p = f.getAnArg()
  or
  /* nltk.twitter.util.add_access_token(creds_file) - twitter/util.py:123
     (position 0) - the credentials append channel (open :138). */
  f.getName() = "add_access_token" and
  normalizedPathOf(f).matches("%/nltk/twitter/util.py") and
  p.getName() = "creds_file" and
  p = f.getAnArg()
  or
  /* nltk.twitter.twitterclient.TweetWriter.__init__(self, limit,
     upper_date_limit, lower_date_limit, fprefix, subdir, repeat,
     gzip_compress) - twitterclient.py:442 (fprefix position 4, subdir
     position 5) - subdir = guess_path(subdir) (:481), os.mkdir(subdir)
     (:497), fname = os.path.join(subdir, fprefix) (:499) -> open/gzip.open
     write (:518/:520). */
  f.getName() = "__init__" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "TweetWriter" and
  normalizedPathOf(f).matches("%/nltk/twitter/twitterclient.py") and
  (p.getName() = "fprefix" or p.getName() = "subdir") and
  p = f.getAnArg()
  or
  /* nltk.twitter.common.json2csv(fp, outfile, fields, ...) - common.py:92
     (outfile position 1; fp is an open stream) - the CSV output write
     target (open/gzip.open via outf_writer_compat :144/:150). */
  f.getName() = "json2csv" and
  normalizedPathOf(f).matches("%/nltk/twitter/common.py") and
  p.getName() = "outfile" and
  p = f.getAnArg()
  or
  /* nltk.twitter.common.json2csv_entities(tweets_file, outfile,
     main_fields, entity_type, entity_fields, ...) - common.py:156
     (outfile position 1). */
  f.getName() = "json2csv_entities" and
  normalizedPathOf(f).matches("%/nltk/twitter/common.py") and
  p.getName() = "outfile" and
  p = f.getAnArg()
  or
  /* nltk.twitter.common.outf_writer_compat(outfile, encoding, errors,
     gzip_compress) - common.py:137 (outfile position 0) - THE writer
     opener: gzip.open(outfile, ...) / open(outfile, 'w') (:144/:150). */
  f.getName() = "outf_writer_compat" and
  normalizedPathOf(f).matches("%/nltk/twitter/common.py") and
  p.getName() = "outfile" and
  p = f.getAnArg()
  or
  /* ---------------- model save/load channels --------------------------- */
  /* nltk.tag.perceptron.AveragedPerceptron.save(self, path) :109 and
     .load(self, path) :114 - perceptron.py (path position 1) - open(path,
     'wb')/:322 open(filename, 'rb') pickle channels (Pass 6 adjacent; the
     path parameter is the pass-1 concern). */
  (f.getName() = "save" or f.getName() = "load") and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "AveragedPerceptron" and
  normalizedPathOf(f).matches("%/nltk/tag/perceptron.py") and
  p.getName() = "path" and
  p = f.getAnArg()
  or
  /* nltk.tag.perceptron.PerceptronTagger.load(self, loc) :239 - (loc
     position 1) - open(loc, 'rb') via AveragedPerceptron.load (:235/:322). */
  f.getName() = "load" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "PerceptronTagger" and
  normalizedPathOf(f).matches("%/nltk/tag/perceptron.py") and
  p.getName() = "loc" and
  p = f.getAnArg()
  or
  /* nltk.parse.transitionparser.TransitionParser.train(self, depgraphs,
     modelfile, verbose) :505 / .parse(self, depgraphs, modelFile) :546 -
     (model file position 2) - pickle.dump(open(modelfile, 'wb')) :542 /
     pickle.load(open(modelFile, 'rb')) :556. */
  (f.getName() = "train" or f.getName() = "parse") and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "TransitionParser" and
  normalizedPathOf(f).matches("%/nltk/parse/transitionparser.py") and
  (p.getName() = "modelfile" or p.getName() = "modelFile") and
  p = f.getAnArg()
  or
  /* nltk.tag.stanford.StanfordTagger.__init__(self, model_filename,
     path_to_jar, encoding, ...) - tag/stanford.py:48 (model_filename
     position 1, path_to_jar position 2) - the external-tool jar/model
     paths (searched via find_jar over env-var dirs). */
  f.getName() = "__init__" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "StanfordTagger" and
  normalizedPathOf(f).matches("%/nltk/tag/stanford.py") and
  (p.getName() = "model_filename" or p.getName() = "path_to_jar") and
  p = f.getAnArg()
  or
  /* ---------------- nltk.sem.chat80 - the sqlite channel ---------------- */
  /* nltk.sem.chat80.cities2table(filename, rel_name, dbname, ...) :410
     (dbname position 2) and sql_query(dbname, query) :450 (dbname
     position 0) - sem/chat80.py - sqlite3.connect(dbname) :431 /
     sqlite3.connect(str(nltk.data.find(dbname))) :462. */
  (f.getName() = "cities2table" or f.getName() = "sql_query") and
  normalizedPathOf(f).matches("%/nltk/sem/chat80.py") and
  p.getName() = "dbname" and
  p = f.getAnArg()
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: the wordnet browser HTTP request path - the self.path
     attribute read inside MyServerHandler.do_GET (app/wordnet_app.py:98,
     sp = self.path[1:]). The server is HTTPServer(('', port),
     MyServerHandler) (:247 - binds ALL interfaces), so the request path is
     remotely reachable. Downstream: unquote_plus percent-decode (:99/:118
     - the path_decode sink family), open(usp, 'r') :122 (guarded by an
     EXACT literal equality - the only fs-reaching branch) and the
     exact-literal dispatcher get_static_page_by_path (:813). The attribute
     VALUE carries the raw request path, hence argIndex -1. This is the
     only `self.path` read in the tree (grep-verified). */
  exists(Attribute a |
    a.getName() = "path" and
    a.getObject().(Name).getId() = "self" and
    normalizedPathOf(a).matches("%/nltk/app/wordnet_app.py") and
    node = a and
    flowKind = "http_request_path" and
    callableName = "path" and
    argIndex = -1 and
    receiver = "self" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 2: network fetches - bare-name urlopen(...) calls (verified
     import style: `from six.moves.urllib.request import urlopen` at
     data.py:49 and downloader.py:189). downloader.py:717
     infile = urlopen(info.url) - the package zip download whose response
     body is written to disk at :718; downloader.py:962
     ElementTree.parse(urlopen(self._url)) - the XML INDEX download (the
     source of the net_xml_attr family); data.py:998
     return urlopen(resource_url) in _open - the http:-protocol resource
     read. The RETURN VALUE carries the untrusted data, hence argIndex -1. */
  exists(Call c |
    c.getFunc().(Name).getId() = "urlopen" and
    (normalizedPathOf(c).matches("%/nltk/data.py")
     or normalizedPathOf(c).matches("%/nltk/downloader.py")) and
    node = c and
    flowKind = "net_fetch" and
    callableName = "urlopen" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = "urllib" and
    matchKind = "ast"
  )
  or
  /* family 3: the XML index attributes - the xml.attrib attribute reads
     inside Package.fromxml (downloader.py:286/:287/:288 - the for loop, the
     subscript target and the **kwargs expansion) and Collection.fromxml
     (:327/:328/:330). The XML is downloaded from the data server
     (ElementTree.parse(urlopen(self._url)) :962), so id/subdir/url are
     DATA-SERVER-controlled path components: Package.__init__ joins them
     into self.filename = os.path.join(subdir, id + ext) (:270), which
     feeds os.path.join(download_dir, info.filename) (:700) -> os.remove
     (:704) / os.mkdir (:708/:710) / open(filepath, 'wb') (:718) and the
     extraction destination zipdir (:740). The attribute VALUE carries the
     attributes, hence argIndex -1. The xml.attrib reads of the CORPUS
     readers (bnc/mte/nkjp/rte/...) are corpus-file content, not index
     attributes - not matched (scoped to downloader.py). */
  exists(Attribute a |
    a.getName() = "attrib" and
    a.getObject().(Name).getId() = "xml" and
    normalizedPathOf(a).matches("%/nltk/downloader.py") and
    node = a and
    flowKind = "net_xml_attr" and
    callableName = "attrib" and
    argIndex = -1 and
    receiver = "xml" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 4: archive entry names - .namelist() member calls on zipfile
     handles. downloader.py:2264 namelist = zf.namelist() in _unzip_iter
     (zf opened on the DOWNLOADED package :2255 - NETWORK-origin entry names
     that drive the os.path.join(root, *pieces) :2281/:2287 ->
     os.mkdir :2283 / open(filepath, 'wb') :2290 extraction with NO
     filtering - the zip-slip channel); downloader.py:2410 and :2491 (the
     index-builder side - operator tooling reading local corpus dirs);
     data.py:522 zipfile.namelist() in ZipFilePathPointer.__init__ (entry
     existence scan) and corpus/reader/util.py:807
     root.zipfile.namelist() in find_corpus_fileids (corpus fileid
     discovery - archive-content origin). The RETURN VALUE carries the
     entry names, hence argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "namelist" and
    (normalizedPathOf(c).matches("%/nltk/downloader.py")
     or normalizedPathOf(c).matches("%/nltk/data.py")
     or normalizedPathOf(c).matches("%/nltk/corpus/reader/util.py")) and
    node = c and
    flowKind = "archive_entry" and
    callableName = "namelist" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "zipfile" and
    matchKind = "ast"
  )
  or
  /* family 5: library API parameters - definition-side Parameter rows of
     the path-taking public APIs listed in fileApiParamShape (find/load/
     retrieve/_open chain, the path pointer constructors and joins, the
     corpus reader entries, the unzip/_unzip_iter archive channel, the
     downloader destination dirs, the twitter helper params, the model
     save/load params, the chat80 db params). For a LIBRARY the
     application-facing API is the input boundary; the labeling step
     decides which of these entries are true untrusted boundaries. argIndex
     is the 0-based parameter position (self occupies position 0 for
     methods). */
  exists(Function f, Parameter p |
    fileApiParamShape(f, p) and
    not p.isSelf() and
    node = p and
    flowKind = "lib_api_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    (
      f.getEnclosingScope() instanceof Class and
      receiver = f.getEnclosingScope().(Class).getName()
      or
      not f.getEnclosingScope() instanceof Class and
      receiver = ""
    )
  )
  or
  /* family 6: environment-variable reads - os.environ.get(...) calls
     (data.py:91 NLTK_DATA - the resource search-path list; data.py:102
     APPDATA - the Windows nltk_data location; downloader.py:2568
     NLTK_DOWNLOAD_URL - the __main__ default for the data server URL -
     inside the optparse add_option default, a real call node).
     OPERATOR trust level - emitted for labeling to classify, not assumed
     attacker sources. Argument 0 carries the variable name. The
     os.environ[...] SUBSCRIPT reads (TWITTER/WEKAHOME/SENNA/CLASSPATH/
     MALT_PARSER/APPDATA/APPENGINE_RUNTIME - see detection.json
     inputBoundaryInventory) are NOT emitted: the AST Subscript node is
     identical for read and write targets (same shape-ambiguity policy as
     the prior projects of this series). */
  exists(Call c, Attribute func, Attribute environ |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    environ = func.getObject().(Attribute) and
    environ.getName() = "environ" and
    environ.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 7: the downloader interactive shell inputs - bare-name
     input(...) calls in downloader.py (the DownloaderShell / _interactive
     flows). Of the 8 rows, the path/URL-relevant ones are :1276
     new_dl_dir = input('  New Directory> ') - THE interactive
     download-dir boundary (feeds _download_dir -> the mkdir/open/unzip
     chain) - and :1284 new_url = input('  New URL> ') - the data server
     URL (feeds the XML index download); :1154/:1195/:1232 select package
     identifiers (what, not where), :1272 is the Config menu choice and
     :575/:798 are y/n confirmations.
     INTERACTIVE trust level - emitted for labeling to classify. The
     RETURN VALUE carries the user input, hence argIndex -1. input() calls
     in other modules (chat/util.py:122 chat text,
     stem/snowball.py:5910 demo language prompt) are NOT path channels and
     are not matched (scoped to downloader.py). */
  exists(Call c |
    c.getFunc().(Name).getId() = "input" and
    normalizedPathOf(c).matches("%/nltk/downloader.py") and
    node = c and
    flowKind = "cli_input" and
    callableName = "input" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  inScope(node.getLocation().getFile().getAbsolutePath()) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "source_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
