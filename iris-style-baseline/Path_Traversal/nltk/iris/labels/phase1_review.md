# Phase 1 Step 3 - Human Review Summary (Pass 1: Path Traversal, nltk)

Advisory checkpoint per WORKFLOW.md 4.5. Interactive mode: STOP here; do not proceed to Phase 2 without explicit approval.

## 1. Label counts (pass 1)

| role | count | tp | fp | candidate |
| --- | --- | --- | --- | --- | --- |
| source | 46 | 40 | 0 | 6 |
| sink | 128 | 54 | 56 | 18 |
| sanitizer | 0 | 0 | 0 | 0 |
| summary | 92 | 47 | 33 | 12 |
| none | 71 | 0 | 69 | 2 |

Total unique entries: 337 (from 339 CSV rows, 2 duplicates merged).

## 2. Top high-risk sinks (classification=tp, conf >= 0.8)

- **p1-k-081** `nltk/sem/chat80.py:462` (connect, tp, conf 0.80) - sqlite3.connect(str(nltk.data.find(dbname))) in sql_query - dbname resolved through the unchecked find() channel (db_open channel).
- **p1-k-116** `nltk/data.py:345` (open, tp, conf 0.95) - THE central resource read: open(self._path, 'rb') in FileSystemPathPointer.open
- **p1-k-119** `nltk/data.py:482` (BufferedGzipFile, tp, conf 0.80) - GzipFileSystemPathPointer.open reads the same pointer path produced by find() (no containment upstream).
- **p1-k-120** `nltk/data.py:484` (GzipFile, tp, conf 0.80) - GzipFileSystemPathPointer.open reads the same pointer path produced by find() (no containment upstream).
- **p1-k-137** `nltk/data.py:732` (open, tp, conf 0.80) - retrieve() write target: open(filename, 'wb') where filename is the explicit parameter or URL-derived (:718/:720) - unrestricted write channel (CWE-22).
- **p1-k-157** `nltk/downloader.py:718` (open, tp, conf 0.85) - Package download write: open(filepath, 'wb') where filepath = join(download_dir, info.filename) (:700) and info.filename = join(subdir, id+ext) (:270) from the network XML index - arbitrary relative/absolute path, no validation.
- **p1-k-174** `nltk/downloader.py:2255` (ZipFile, tp, conf 0.80) - zipfile.ZipFile(filename) in _unzip_iter - opens the DOWNLOADED package (path from join(download_dir, info.filename) :700); its namelist then drives the unfiltered extraction writes (:2281/:2287/:2290).
- **p1-k-179** `nltk/downloader.py:2283` (mkdir, tp, conf 0.90) - zip-slip DIRECTORY write: os.mkdir(dirpath) with dirpath = join(root, *pieces) (:2281) from network-controlled zip entry names - no entry-name filtering, no containment (CWE-22).
- **p1-k-181** `nltk/downloader.py:2290` (open, tp, conf 0.95) - zip-slip WRITE: open(filepath, 'wb') with filepath = join(root, *filename.split('/')) (:2287) from a network-controlled zip entry name - hand-rolled extraction with NO entry-name filtering and NO containment; the strongest CWE-22 channel of this target.

## 3. Top broad sources (classification=tp, conf >= 0.8)

- **p1-s-001** `nltk/corpus/reader/api.py:47` (param/field __init__, conf 0.80) - CorpusReader.__init__ root: a string root is converted to FileSystemPathPointer/ZipFilePathPointer (api.py:81-84) and defines the corpus base directory; it is a public library-API parameter (application-supplied) and every downstream file access is relative to it.
- **p1-s-002** `nltk/corpus/reader/api.py:47` (param/field __init__, conf 0.80) - CorpusReader.__init__ fileids: fileids select files within the root and reach the filesystem via self._root.join(file) -> os.path.join(self._path, fileid) (data.py:354) with NO containment, so a '..'-laden or absolute fileid escapes the corpus root (CWE-23)
- **p1-s-003** `nltk/corpus/reader/api.py:159` (param/field abspath, conf 0.80) - CorpusReader.abspath(fileid) -> self._root.join(fileid) -> data.py:354 join without containment -> FileSystemPathPointer
- **p1-s-004** `nltk/corpus/reader/api.py:204` (param/field open, conf 0.85) - CorpusReader.open(file) -> self._root.join(file).open() -> open(self._path, 'rb') (data.py:345)
- **p1-s-006** `nltk/sem/chat80.py:450` (param/field sql_query, conf 0.80) - sql_query(dbname, query): dbname is resolved through nltk.data.find(dbname) (:461) - the unchecked find() channel - then sqlite3.connect(str(path)) (:462)
- **p1-s-012** `nltk/data.py:324` (param/field __init__, conf 0.85) - FileSystemPathPointer(_path): constructor applies only os.path.abspath (:331) + existence check (:332) - normalization WITHOUT confinement - then open(self._path, 'rb') (:345)
- **p1-s-013** `nltk/data.py:353` (param/field join, conf 0.90) - FileSystemPathPointer.join(fileid): _path = os.path.join(self._path, fileid) (:354) with no containment; a fileid containing '..' or an absolute path escapes the pointer root and is then opened (:345)
- **p1-s-018** `nltk/data.py:589` (param/field find, conf 0.90) - THE resource-resolution boundary: find(resource_name) -> normalize_resource_name (os.path.normpath keeps a leading '..' at :257) -> p = os.path.join(path_, url2pathname(resource_name)) (:650/:657 - percent-decoded, CWE-36) -> FileSystemPathPointer(p) -> open (:345)
- **p1-s-020** `nltk/data.py:704` (param/field retrieve, conf 0.80) - retrieve(..., filename): explicit write target, an unrestricted caller-controlled path -> open(filename, 'wb') (:732)
- **p1-s-023** `nltk/downloader.py:286` (param/field attrib, conf 0.85) - xml.attrib values come from the data-server index XML (ElementTree.parse(urlopen(self._url)) downloader.py:962) and are passed as **xml.attrib into Package/Collection, whose fields become path components: Package.filename = os.path.join(subdir, id + ext) (:270) -> filepath = os.path.join(download_dir, info.filename) (:700) -> open (:718) / os.mkdir (:710) / _unzip_iter destination (:740/:745)
- **p1-s-024** `nltk/downloader.py:287` (param/field attrib, conf 0.85) - xml.attrib values come from the data-server index XML (ElementTree.parse(urlopen(self._url)) downloader.py:962) and are passed as **xml.attrib into Package/Collection, whose fields become path components: Package.filename = os.path.join(subdir, id + ext) (:270) -> filepath = os.path.join(download_dir, info.filename) (:700) -> open (:718) / os.mkdir (:710) / _unzip_iter destination (:740/:745)
- **p1-s-025** `nltk/downloader.py:288` (param/field attrib, conf 0.85) - xml.attrib values come from the data-server index XML (ElementTree.parse(urlopen(self._url)) downloader.py:962) and are passed as **xml.attrib into Package/Collection, whose fields become path components: Package.filename = os.path.join(subdir, id + ext) (:270) -> filepath = os.path.join(download_dir, info.filename) (:700) -> open (:718) / os.mkdir (:710) / _unzip_iter destination (:740/:745)
- **p1-s-026** `nltk/downloader.py:327` (param/field attrib, conf 0.85) - xml.attrib values come from the data-server index XML (ElementTree.parse(urlopen(self._url)) downloader.py:962) and are passed as **xml.attrib into Package/Collection, whose fields become path components: Package.filename = os.path.join(subdir, id + ext) (:270) -> filepath = os.path.join(download_dir, info.filename) (:700) -> open (:718) / os.mkdir (:710) / _unzip_iter destination (:740/:745)
- **p1-s-027** `nltk/downloader.py:328` (param/field attrib, conf 0.85) - xml.attrib values come from the data-server index XML (ElementTree.parse(urlopen(self._url)) downloader.py:962) and are passed as **xml.attrib into Package/Collection, whose fields become path components: Package.filename = os.path.join(subdir, id + ext) (:270) -> filepath = os.path.join(download_dir, info.filename) (:700) -> open (:718) / os.mkdir (:710) / _unzip_iter destination (:740/:745)
- **p1-s-028** `nltk/downloader.py:330` (param/field attrib, conf 0.85) - xml.attrib values come from the data-server index XML (ElementTree.parse(urlopen(self._url)) downloader.py:962) and are passed as **xml.attrib into Package/Collection, whose fields become path components: Package.filename = os.path.join(subdir, id + ext) (:270) -> filepath = os.path.join(download_dir, info.filename) (:700) -> open (:718) / os.mkdir (:710) / _unzip_iter destination (:740/:745)
- **p1-s-042** `nltk/downloader.py:2239` (param/field unzip, conf 0.80) - unzip(filename, root): filename is the zip to open (zipfile.ZipFile(filename) :2255 via _unzip_iter) - a caller-controlled path with real file access
- **p1-s-043** `nltk/downloader.py:2239` (param/field unzip, conf 0.80) - unzip(filename, root): root is the extraction destination base; the zip's network-controlled entry names are joined onto it with NO containment (:2281/:2287) - the declared root that entry names can escape (CWE-22).
- **p1-s-044** `nltk/downloader.py:2249` (param/field _unzip_iter, conf 0.80) - _unzip_iter(filename, root): filename path of the archive to open (ZipFile :2255); caller/downstream-controlled (the downloaded package path join(download_dir, info.filename) :700).
- **p1-s-045** `nltk/downloader.py:2249` (param/field _unzip_iter, conf 0.80) - _unzip_iter(filename, root): root is the extraction base; entry names escape it via the unfiltered joins (:2281/:2287) -> mkdir (:2283) / open (:2290).
- **p1-s-046** `nltk/downloader.py:2264` (param/field namelist, conf 0.90) - Entry names of the DOWNLOADED package zip: namelist = zf.namelist() (:2264) -> dirlist/filelist (:2266-:2271) -> dirpath = os.path.join(root, *pieces[:i+1]) (:2281) -> os.mkdir (:2283) and filepath = os.path.join(root, *filename.split('/')) (:2287) -> open(filepath,'wb') (:2290)
- **p1-s-068** `nltk/app/wordnet_app.py:98` (param/field path, conf 0.95) - self.path read inside MyServerHandler.do_GET (BaseHTTPRequestHandler)

## 4. Sanitizer list

Empty - see label_stats.md. MySanitizers resolves to none().

## 5. Unresolved / candidate items (manual review points, classification=candidate)

- **p1-s-030** `nltk/downloader.py:622` role=source cls=candidate conf=0.55 - incr_download(..., download_dir): the base directory of the download channel
- **p1-s-031** `nltk/downloader.py:684` role=source cls=candidate conf=0.55 - _download_package(info, download_dir, force): same base-directory role as incr_download; the untrusted path components come from info (XML index).
- **p1-s-033** `nltk/downloader.py:756` role=source cls=candidate conf=0.55 - Downloader.download(..., download_dir): public download API; download_dir is the destination base, the XML-index components are what can escape it.
- **p1-s-040** `nltk/downloader.py:1276` role=none cls=candidate conf=0.55 - Interactive 'New Directory>' input feeding the download_dir base (extraction root)
- **p1-s-041** `nltk/downloader.py:1284` role=none cls=candidate conf=0.55 - Interactive 'New URL>' input feeding the data-server URL (trust anchor of the index/zip channel)
- **p1-s-054** `nltk/tag/stanford.py:50` role=source cls=candidate conf=0.50 - StanfordTagger(model_filename): explicit tool location handed to the find_jar/find_binary machinery (internals.py isfile checks, e.g
- **p1-s-055** `nltk/tag/stanford.py:51` role=source cls=candidate conf=0.50 - StanfordTagger(path_to_jar): same shape as model_filename - flows into find_jar path checks (internals.py:735) and command construction
- **p1-s-064** `nltk/corpus/util.py:53` role=source cls=candidate conf=0.55 - LazyCorpusLoader(name): the corpus name propagates into corpus resolution (root = data.find('corpora/...') through the lazy __load__); find's normalization keeps a leading '..' so a crafted name could escape, but the path is indirect and dynamic (nltk.corpus __getattr__ indirection) - kept as candidate.
- **p1-k-093** `nltk/corpus/reader/crubadan.py:83` role=sink cls=candidate conf=0.55 - open(mapper_file) where mapper_file = join(self.root, _LANG_MAPPER_FILE) - corpus-root read; root is the API base, the component is a class constant
- **p1-k-094** `nltk/corpus/reader/crubadan.py:85` role=sink cls=candidate conf=0.55 - open(mapper_file) where mapper_file = join(self.root, _LANG_MAPPER_FILE) - corpus-root read; root is the API base, the component is a class constant
- **p1-k-097** `nltk/corpus/reader/crubadan.py:104` role=sink cls=candidate conf=0.55 - open(ngram_file) with ngram_file = join(self.root, crubadan_code + '-3grams.txt') (:97) - the filename component is corpus-content-derived; kept candidate (content-origin, base is the API corpus root).
- **p1-k-098** `nltk/corpus/reader/crubadan.py:106` role=sink cls=candidate conf=0.55 - open(ngram_file) with ngram_file = join(self.root, crubadan_code + '-3grams.txt') (:97) - the filename component is corpus-content-derived; kept candidate (content-origin, base is the API corpus root).
- **p1-k-108** `nltk/data.py:135` role=sink cls=candidate conf=0.50 - BufferedGzipFile.__init__ GzipFile(filename, ...): internal gzip wrapper reached with pointer paths (e.g
- **p1-k-152** `nltk/downloader.py:708` role=sink cls=candidate conf=0.55 - os.mkdir(download_dir) - the base directory parameter only (library-API/CLI-supplied); the escaping components are XML-derived.
- **p1-k-168** `nltk/downloader.py:923` role=sink cls=candidate conf=0.60 - os.walk(unzipdir) - walks the extraction directory derived from the downloaded package path (filepath[:-4], XML-derived); enumeration of extraction output.
- **p1-k-173** `nltk/downloader.py:2221` role=sink cls=candidate conf=0.50 - md5 checksum helper: open(file, 'rb') of a caller-supplied filename (public helper used on downloaded packages).
- **p1-k-176** `nltk/downloader.py:2275` role=sink cls=candidate conf=0.65 - os.mkdir(root) - extraction base root parameter of _unzip_iter/unzip (library-API boundary); base only.
- **p1-k-193** `nltk/internals.py:540` role=summary cls=candidate conf=0.50 - find_binary/find_jar search-path propagation: base is the API parameter (filename/searchpath/path_to_jar) joined with fixed alternatives; operator-env and param trust - kept as candidate propagation for recall.
- **p1-k-196** `nltk/internals.py:553` role=summary cls=candidate conf=0.50 - find_binary/find_jar search-path propagation: base is the API parameter (filename/searchpath/path_to_jar) joined with fixed alternatives; operator-env and param trust - kept as candidate propagation for recall.
- **p1-k-203** `nltk/internals.py:597` role=summary cls=candidate conf=0.50 - join over the searchpath parameter of find_binary/find_jar (caller-supplied search list) with fixed name components - candidate propagation.
- **p1-k-212** `nltk/internals.py:770` role=sink cls=candidate conf=0.50 - os.listdir over an env-var or searchpath directory in the find_binary/find_jar machinery (operator trust; enumeration of configured tool dirs).
- **p1-k-217** `nltk/internals.py:788` role=sink cls=candidate conf=0.50 - os.listdir over an env-var or searchpath directory in the find_binary/find_jar machinery (operator trust; enumeration of configured tool dirs).
- **p1-k-219** `nltk/internals.py:809` role=sink cls=candidate conf=0.50 - os.listdir over an env-var or searchpath directory in the find_binary/find_jar machinery (operator trust; enumeration of configured tool dirs).
- **p1-k-220** `nltk/internals.py:810` role=summary cls=candidate conf=0.50 - join over the searchpath parameter of find_binary/find_jar (caller-supplied search list) with fixed name components - candidate propagation.
- **p1-k-222** `nltk/internals.py:818` role=summary cls=candidate conf=0.50 - join over the searchpath parameter of find_binary/find_jar (caller-supplied search list) with fixed name components - candidate propagation.
- **p1-k-224** `nltk/internals.py:861` role=summary cls=candidate conf=0.50 - join over the searchpath parameter of find_binary/find_jar (caller-supplied search list) with fixed name components - candidate propagation.
- **p1-k-225** `nltk/internals.py:862` role=sink cls=candidate conf=0.50 - os.walk(path_to_jars) in find_jars_within_path - walks a caller-supplied directory parameter (jar discovery helper).
- **p1-k-250** `nltk/chunk/named_entity.py:215` role=sink cls=candidate conf=0.50 - os.walk(root) in load_ace_data - the roots parameter of the demo corpus loader (caller-supplied corpus dirs).
- **p1-k-251** `nltk/chunk/named_entity.py:230` role=sink cls=candidate conf=0.50 - open(annfile) - textfile+'.tmx.rdc.xml' derived from the roots parameter of the demo loader.
- **p1-k-252** `nltk/chunk/named_entity.py:242` role=sink cls=candidate conf=0.50 - open(textfile) - derived from the roots parameter of the demo loader.
- **p1-k-270** `nltk/classify/senna.py:91` role=summary cls=candidate conf=0.55 - path.join(base_path, fixed-executable-name) - base_path is self._path (Senna constructor parameter or SENNA env) joined with fixed binary names; propagation of the API param, candidate.
- **p1-k-271** `nltk/classify/senna.py:92` role=summary cls=candidate conf=0.55 - path.join(base_path, fixed-executable-name) - base_path is self._path (Senna constructor parameter or SENNA env) joined with fixed binary names; propagation of the API param, candidate.
- **p1-k-272** `nltk/classify/senna.py:94` role=summary cls=candidate conf=0.55 - path.join(base_path, fixed-executable-name) - base_path is self._path (Senna constructor parameter or SENNA env) joined with fixed binary names; propagation of the API param, candidate.
- **p1-k-273** `nltk/classify/senna.py:96` role=summary cls=candidate conf=0.55 - path.join(base_path, fixed-executable-name) - base_path is self._path (Senna constructor parameter or SENNA env) joined with fixed binary names; propagation of the API param, candidate.
- **p1-k-274** `nltk/classify/senna.py:97` role=summary cls=candidate conf=0.55 - path.join(base_path, fixed-executable-name) - base_path is self._path (Senna constructor parameter or SENNA env) joined with fixed binary names; propagation of the API param, candidate.
- **p1-k-280** `nltk/tokenize/stanford_segmenter.py:181` role=summary cls=candidate conf=0.50 - join(path_to_sihan_dir, sihan_dir) - find_dir result (env-driven) joined with a fixed name; candidate propagation.
- **p1-k-306** `nltk/corpus/reader/util.py:821` role=sink cls=candidate conf=0.55 - find_corpus_fileids: os.walk(root.path, followlinks=True) - walks the corpus root parameter FOLLOWING SYMLINKS (CWE-59-adjacent evidence); enumeration sink of the corpus-root boundary, no canonicalization anywhere in the corpus layer.
- **p1-k-320** `nltk/classify/weka.py:74` role=sink cls=candidate conf=0.50 - zipfile.ZipFile(jar) - jar is the WEKAHOME-derived classpath (operator env); version probe of a configured jar.

## 6. Analyst notes (10 review criteria from the task brief)

1. **Source trust**: only wordnet_app.py:98 `self.path` is remotely reachable (HTTPServer binds all interfaces, :247). Downloader XML attribs (:286-:330) and package zip namelist (:2264) are network-controlled via the data server. Library API params are the application-facing boundary of a library. env/input()/optparse/tkinter rows are operator trust -> none/fp.
2. **Decode/normalize/join chains**: find() percent-decodes via url2pathname (:650/:657) AFTER normpath (:257) kept a leading '..'; the wordnet request path is unquote_plus-decoded (:99/:118) - both traced step by step in rationales; all decode/join steps labeled 'summary'.
3. **Sinks are real file access only**: open/gzip/ZipFile/sqlite3.connect/mkdir/remove/listdir/walk rows keep role 'sink'; join/stat/normpath/decode rows do not (summary/none).
4. **Escape capability**: '..' survives os.path.join lexically and an ABSOLUTE component (e.g. 'C:/x') replaces the base - applies to _unzip_iter (:2281/:2287), _download_package (:700/:710), find (:650/:657), pointer join (:354), load_creds (:84-:86). No prefix check anywhere.
5. **No containment**: verified absence of startswith(base), realpath, relative_to, fixed-name mapping (except wordnet:119 exact literal) across data.py/downloader.py/corpus readers/twitter.
6. **normpath/abspath/basename are NOT sanitizers here**: normpath (:257) preserves leading '..'; abspath (:331) resolves without confining; expanduser adds nothing. Labeled summary (propagation), never sanitizer.
7. **Symlinks**: os.walk(root.path, followlinks=True) at corpus/reader/util.py:821 (candidate, CWE-59-adjacent); no realpath canonicalization in the corpus layer; no symlink creation in the tree. TOCTOU shape noted at wordnet :121/:122 and data.py :648-:658 vs :345 (dominated by other factors).
8. **Authorized file serving**: wordnet_app open (:122) is guarded by exact literal equality -> fp (fixed-filename whitelist); get_static_page_by_path is an exact-literal dispatch that never touches the filesystem.
9. **Tests/fixtures/generated code**: excluded at extraction time (%/nltk/test/ pruned; nltk-db excluded by scope); demo mains (tbl/demo.py, chartparser/chunkparser dialogs) remain as fp sink rows with rationale.
10. **Complete flows**: three complete untrusted-source -> dangerous-path flows exist: (a) XML index attribs -> filename/subdir -> join -> open/mkdir/remove (downloader); (b) zip entry names -> join(root, *pieces) -> mkdir/open (zip-slip); (c) HTTP request path -> unquote_plus -> open (guarded). Library-param flows (find/pointer join/corpus root+fileid/load_creds/TweetWriter/model files) are boundary-to-sink flows whose exploitability depends on the embedding application passing untrusted values - expected for a library CVE pattern.

## 7. Review decision

- [ ] Approved to proceed to Phase 2 (Step 4 library generation)
- [ ] Changes requested (list entry ids)

Reviewers should focus on: the candidate rows in section 5, the operator-trust judgments (env/cli input), and whether the in-archive ZipFilePathPointer exclusions match the intended threat model.
