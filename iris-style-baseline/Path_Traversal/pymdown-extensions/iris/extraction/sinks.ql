/**
 * @name pymdown-extensions CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the
 *   pymdown-extensions CodeQL database (snapshot a8fb9666,
 *   pymdown-extensions 9.11.0 final - the Markdown extension library
 *   itself is the audit target): real file reads/writes (codecs.open(
 *   snippet, 'r', ...) at snippets.py:311 - THE markdown-include read
 *   fed by the unguarded os.path.join(base, path) resolution at :162/
 *   :170; open(file_name, 'rb') at b64.py:86 - THE rendered-output img
 *   src read fed by util.parse_url/html.unescape + util.url2path/
 *   url2pathname decoding and os.path.normpath(os.path.join(base_path,
 *   path)) at :80, with the absolute-path branch at :78; open(
 *   file_location, 'wb') at gen_emoji.py:73 and zipfile.ZipFile(
 *   file_location, 'r') + z.extractall(...) at :44/:45 - the
 *   externally-downloaded archive write/extract channel with no member
 *   validation; plus the dev-script opens in gen_emoji1/gen_gemoji/
 *   gen_joypixels/gen_twemoji and hatch_build.py:36); the include/attr
 *   resolution pipeline (os.path.join at snippets.py:162/:170,
 *   b64.py:80, pathconverter.py:81/:106 with the attacker-controlled
 *   path at argument 1, and gen_emoji.py:66 with the external-derived
 *   basename in argument 0; os.path.normpath at b64.py:78/:80 and
 *   pathconverter.py:81/:106, os.path.relpath at pathconverter.py:80,
 *   os.path.splitext at b64.py:83, os.path.basename at snippets.py:167
 *   and gen_emoji.py:66, os.path.dirname at snippets.py:168,
 *   os.path.abspath at run_tests.py:28; the decode helpers
 *   util.parse_url(...) at b64.py:73/pathconverter.py:72/:102,
 *   util.url2path(...) at b64.py:75/pathconverter.py:77/:105,
 *   url2pathname(path) at util.py:56 and html.unescape(url) at
 *   util.py:119 - HTML-entity and percent decoding BEFORE the join; the
 *   custom resolution wrapper self.get_snippet_path(path) at
 *   snippets.py:301); the existence/metadata gates (os.path.exists at
 *   snippets.py:160/:163/:171, b64.py:82, gen_emoji.py:60; os.path.
 *   isdir at snippets.py:161 and gen_emoji.py:50; os.path.isfile at
 *   gen_twemoji.py:201 - check-then-open TOCTOU-shaped gates); the
 *   directory operations (os.listdir at gen_emoji.py:48 and
 *   gen_twemoji.py:200, os.makedirs at gen_emoji.py:61/:65,
 *   shutil.rmtree at :64, os.rename at :54); and definition rows for
 *   the path-consuming internal APIs (SnippetPreprocessor.get_snippet_
 *   path path, util.url2path path, util.parse_url url) with the true
 *   parameter positions. pathconverter.py is VERIFIED string-only (no
 *   exists/open/stat anywhere in the module) - its wrapper rows are
 *   propagation-chain evidence for the labeling step. Raw BQRS
 *   extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/pymdown-extensions/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member name ("open" for file_open rows,
 *                   "ZipFile"/"extractall" for archive rows, "join" for
 *                   path_join rows, "parse_url"/"url2path"/"url2pathname"/
 *                   "unescape"/"normpath"/"relpath"/"splitext"/"basename"/
 *                   "dirname"/"abspath"/"get_snippet_path" for wrapper
 *                   rows, "exists"/"isdir"/"isfile" for stat rows,
 *                   "listdir"/"makedirs"/"rmtree"/"rename" for directory
 *                   rows, the function name for file_api_def rows)
 *   4. flow_kind  - "file_open" (builtin open / codecs.open - the path
 *                   argument), "archive_open" (zipfile.ZipFile argument
 *                   0), "archive_extract" (z.extractall argument 0 - the
 *                   extraction destination), "path_join" (os.path.join
 *                   with the attacker-controlled argument index), "path_
 *                   wrapper" (decode helpers, pure os.path ops and the
 *                   custom resolution wrapper - intermediate propagation
 *                   /validation nodes), "file_stat" (os.path.exists/
 *                   isdir/isfile existence gates), "file_read" (os.
 *                   listdir), "file_mkdir" (os.makedirs), "file_remove"
 *                   (shutil.rmtree), "file_rename" (os.rename), "file_
 *                   api_def" (definition row of a path-consuming internal
 *                   API, carrying the path parameter position)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "m"/"self"/"z"/"os.path"/"os"/"codecs"/
 *                   "shutil"/"zipfile"/"util"/"html" etc., "" if none;
 *                   enclosing class name for file_api_def rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "builtins"/"codecs"/"os.path"/"os"/"shutil"/
 *                   "zipfile"/"urllib.request" for the stdlib channels
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for open/ZipFile/extractall/stat-family/
 *                   decode-wrapper rows; argument 1 for the os.path.join
 *                   rows in pymdownx where the include/src path is joined
 *                   onto the operator-configured base at argument 0 -
 *                   argument 0 for the gen_emoji.py:66 join whose
 *                   external-derived basename is embedded in argument 0;
 *                   the parameter position for file_api_def rows,
 *                   including the self slot)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): the sink core is the
 * FILE PATH PARAMETER of actual filesystem operations and the
 * resolution/decode pipeline nodes that directly determine the accessed
 * file - the codecs.open/builtin open reads in snippets.py/b64.py, the
 * download/extract channel in gen_emoji.py, the os.path.join resolution
 * feeding the existence gates and opens, and the decode helpers that
 * transform the attacker string before the join - NOT every path string
 * construction node (util.path2url/urlunparse output rewrites, str
 * coercions, os.path.join calls with only operator/literal operands in
 * hatch_build.py:23/:36 and the gen_* scripts, os.chdir, the tools'
 * current_dir __file__ derivations and f.write()/f.read() calls on
 * already-open handles are pure and are documented in detection.json
 * uncoveredCases instead).
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no sink row is expected to resolve at API level:
 * the file-access channels flow through os.path/os/codecs/shutil/zipfile
 * module-attribute calls (those stdlib modules are not part of the database
 * - only the pymdown-extensions tree is) and local-variable member calls
 * (z.extractall, self.get_snippet_path, m.group). Receiver-name matching is
 * constrained to stable names (z for the ZipFile, self for the preprocessor,
 * os/codecs/shutil/zipfile/util/html module names) and audited for
 * collisions: keys.py:158 also calls html.unescape() but is excluded by the
 * util.py-only file scope of that family; the tools/ builtin open matches
 * are all genuine path opens.
 *
 * Excluded paths (applied to every row): /tests/ (32 files of the database
 * snapshot), /pymdown-extensions-db/ (the CodeQL database directory nested
 * inside the source tree), /docs/. tools/ and the root scripts
 * (hatch_build.py, run_tests.py) are kept in scope (maintainer tooling;
 * their rows are expected to be labeled none/FP - kept for auditability,
 * consistent with prior projects in this series).
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
  path.replaceAll("\\", "/").matches("%/tests/%")
  or
  path.replaceAll("\\", "/").matches("%/pymdown-extensions-db/%")
  or
  path.replaceAll("\\", "/").matches("%/docs/%")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* -------------------------------------------------------------- */
  /* family 1: file_open - builtin open(...) calls. Key sites:
     b64.py:86 open(file_name, "rb") - THE rendered-output img-src read
     (file_name is normpath(join(base_path, path)) of the decoded src
     attribute; content is embedded as a data URI); hatch_build.py:36
     open(os.path.join(root, "requirements/project.txt")) - build hook
     (operator input, FP-expected); gen_emoji.py:73 open(file_location,
     'wb') - the downloaded-zip write (file_location embeds
     os.path.basename(url) of the GitHub API zipball_url); the dev-db
     generator opens gen_emoji1.py:21/:43/:53, gen_gemoji.py:115/:124/
     :128, gen_joypixels.py:21, gen_twemoji.py:264/:274 (operator
     paths, FP-expected). Every builtin open in these files is a
     genuine path open (grep-verified - no io.open/aliasing). */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    (normalizedPathOf(c).matches("%/pymdownx/b64.py") or
     normalizedPathOf(c).matches("%/hatch_build.py") or
     normalizedPathOf(c).matches("%/tools/gen_emoji.py") or
     normalizedPathOf(c).matches("%/tools/gen_emoji1.py") or
     normalizedPathOf(c).matches("%/tools/gen_gemoji.py") or
     normalizedPathOf(c).matches("%/tools/gen_joypixels.py") or
     normalizedPathOf(c).matches("%/tools/gen_twemoji.py")) and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* family 2: file_open - codecs.open(...) calls: snippets.py:311
     codecs.open(snippet, 'r', encoding=self.encoding) - THE markdown-
     include read (snippet is the os.path.join(base, path) resolution of
     the extracted include path, gated only by os.path.exists); tools/
     gen_gemoji.py:87 codecs.open(os.path.join(current_dir, ...), 'r',
     encoding='utf-8') - dev-db generator read (operator input,
     FP-expected) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "codecs" and
    (normalizedPathOf(c).matches("%/pymdownx/snippets.py") or
     normalizedPathOf(c).matches("%/tools/gen_gemoji.py")) and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "codecs" and
    moduleHint = "codecs" and
    matchKind = "ast"
  )
  or
  /* family 3: archive_open - zipfile.ZipFile(file_location, "r") at
     gen_emoji.py:44 - opens the archive downloaded from the GitHub API
     zipball_url; argument 0 is the archive path (the 'wb'-written
     file_location of family 1) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "ZipFile" and
    func.getObject().(Name).getId() = "zipfile" and
    normalizedPathOf(c).matches("%/tools/gen_emoji.py") and
    node = c and
    flowKind = "archive_open" and
    callableName = "ZipFile" and
    argIndex = 0 and
    receiver = "zipfile" and
    moduleHint = "zipfile" and
    matchKind = "ast"
  )
  or
  /* family 4: archive_extract - z.extractall(os.path.dirname(
     file_location)) at gen_emoji.py:45 - extracts the externally
     downloaded archive into the zip's own directory with NO member-name
     validation (zip-slip shape: entry names with ../ or absolute
     components write outside the destination); argument 0 is the
     extraction destination */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "extractall" and
    func.getObject().(Name).getId() = "z" and
    normalizedPathOf(c).matches("%/tools/gen_emoji.py") and
    node = c and
    flowKind = "archive_extract" and
    callableName = "extractall" and
    argIndex = 0 and
    receiver = "z" and
    moduleHint = "zipfile" and
    matchKind = "ast"
  )
  or
  /* family 5: path_join - os.path.join(...) resolution joins.
     pymdownx sites carry the attacker-controlled path at argument 1
     (argument 0 is the operator-configured base): snippets.py:162
     os.path.join(base, path) and :170 os.path.join(dirname, path) - THE
     include-path resolution inside get_snippet_path, with NO '..'/
     absolute/containment validation before the exists gate and
     codecs.open; b64.py:80 os.path.join(base_path, path) - THE img-src
     resolution (nested inside os.path.normpath); pathconverter.py:81/
     :106 os.path.join(base_path, path) - the link-rewrite join (string-
     only module, propagation evidence). gen_emoji.py:66
     os.path.join(destination, os.path.basename(url) + '.zip') carries
     the external-derived basename inside argument 0 (the row for line
     66 is selected by line, excluding the operator-only joins at
     :49/:54/:59). */
  exists(Call c, Attribute func, Attribute funcObj |
    func = c.getFunc().(Attribute) and
    func.getName() = "join" and
    funcObj = func.getObject().(Attribute) and
    funcObj.getName() = "path" and
    funcObj.getObject().(Name).getId() = "os" and
    (
      /* pymdownx resolution joins: attacker-controlled argument 1 */
      (normalizedPathOf(c).matches("%/pymdownx/snippets.py") or
       normalizedPathOf(c).matches("%/pymdownx/b64.py") or
       normalizedPathOf(c).matches("%/pymdownx/pathconverter.py"))
      and argIndex = 1
      or
      /* the external-derived gen_emoji.py:66 join: argument 0 */
      normalizedPathOf(c).matches("%/tools/gen_emoji.py") and
      c.getLocation().getStartLine() = 66 and
      argIndex = 0
    ) and
    node = c and
    flowKind = "path_join" and
    callableName = "join" and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 6a: path_wrapper - os.path.normpath(...) calls: b64.py:78
     normpath(path) - the ABSOLUTE-path branch (values parse_url marked
     is_absolute: file://, c:/, UNC //, leading / or \ - read outside
     base_path by construction); b64.py:80 normpath(join(base_path,
     path)) - the joined branch; pathconverter.py:81/:106 normpath(join
     (base_path, path)) - the link-rewrite normalization. normpath
     collapses '..' but does NOT contain the result to any base. */
  exists(Call c, Attribute func, Attribute funcObj |
    func = c.getFunc().(Attribute) and
    func.getName() = "normpath" and
    funcObj = func.getObject().(Attribute) and
    funcObj.getName() = "path" and
    funcObj.getObject().(Name).getId() = "os" and
    (normalizedPathOf(c).matches("%/pymdownx/b64.py") or
     normalizedPathOf(c).matches("%/pymdownx/pathconverter.py")) and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "normpath" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 6b: path_wrapper - os.path.relpath(...) at pathconverter.py:80
     (relpath(normpath(join(base_path, path)), normpath(relative_path))
     - the link-rewrite relative conversion; string-only module,
     propagation evidence) */
  exists(Call c, Attribute func, Attribute funcObj |
    func = c.getFunc().(Attribute) and
    func.getName() = "relpath" and
    funcObj = func.getObject().(Attribute) and
    funcObj.getName() = "path" and
    funcObj.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/pymdownx/pathconverter.py") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "relpath" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 6c: path_wrapper - os.path.splitext(file_name)[1] at b64.py:83
     (extension check that gates which files get read and embedded) */
  exists(Call c, Attribute func, Attribute funcObj |
    func = c.getFunc().(Attribute) and
    func.getName() = "splitext" and
    funcObj = func.getObject().(Attribute) and
    funcObj.getName() = "path" and
    funcObj.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/pymdownx/b64.py") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "splitext" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 6d: path_wrapper - os.path.basename(...): snippets.py:167
     basename(base) - the base_path entry dissection inside
     get_snippet_path (compared case-insensitively to the include path
     at :169 before the :170 join); gen_emoji.py:66 basename(url) - the
     external zipball_url filename embedded into the zip path */
  exists(Call c, Attribute func, Attribute funcObj |
    func = c.getFunc().(Attribute) and
    func.getName() = "basename" and
    funcObj = func.getObject().(Attribute) and
    funcObj.getName() = "path" and
    funcObj.getObject().(Name).getId() = "os" and
    (normalizedPathOf(c).matches("%/pymdownx/snippets.py") or
     (normalizedPathOf(c).matches("%/tools/gen_emoji.py") and
      c.getLocation().getStartLine() = 66)) and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "basename" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 6e: path_wrapper - os.path.dirname(base) at snippets.py:168
     (the base_path entry dissection feeding the :170 join) */
  exists(Call c, Attribute func, Attribute funcObj |
    func = c.getFunc().(Attribute) and
    func.getName() = "dirname" and
    funcObj = func.getObject().(Attribute) and
    funcObj.getName() = "path" and
    funcObj.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/pymdownx/snippets.py") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "dirname" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 6f: path_wrapper - os.path.abspath(args.file[0]) at
     run_tests.py:28 - the CLI --file value canonicalized before the
     exists gate and set_target_file (operator input, FP-expected) */
  exists(Call c, Attribute func, Attribute funcObj |
    func = c.getFunc().(Attribute) and
    func.getName() = "abspath" and
    funcObj = func.getObject().(Attribute) and
    funcObj.getName() = "path" and
    funcObj.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/run_tests.py") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "abspath" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 6g: path_wrapper - util.parse_url(...) calls at b64.py:73,
     pathconverter.py:72/:102; the shared decoder (util.py:103-159)
     applies html.unescape (HTML-entity decoding) + urlparse and
     classifies absolute forms (file://, file://c:/, file://\\..., c:/,
     // UNC, leading / or \) - mixed-separator and absolute-path
     acceptance evidence decoded BEFORE the join */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "parse_url" and
    func.getObject().(Name).getId() = "util" and
    (normalizedPathOf(c).matches("%/pymdownx/b64.py") or
     normalizedPathOf(c).matches("%/pymdownx/pathconverter.py")) and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "parse_url" and
    argIndex = 0 and
    receiver = "util" and
    moduleHint = "pymdownx.util" and
    matchKind = "ast"
  )
  or
  /* family 6h: path_wrapper - util.url2path(...) calls at b64.py:75,
     pathconverter.py:77/:105; the shared percent-decoder (util.py:53-56
     wraps url2pathname) - encoded traversals (%2e%2e%2f) decode to
     plain ../ BEFORE the join */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "url2path" and
    func.getObject().(Name).getId() = "util" and
    (normalizedPathOf(c).matches("%/pymdownx/b64.py") or
     normalizedPathOf(c).matches("%/pymdownx/pathconverter.py")) and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "url2path" and
    argIndex = 0 and
    receiver = "util" and
    moduleHint = "pymdownx.util" and
    matchKind = "ast"
  )
  or
  /* family 6i: path_wrapper - url2pathname(path) at util.py:56 (the
     percent-decoding call inside util.url2path; imported directly via
     'from urllib.request import url2pathname', so the callee is a bare
     Name) */
  exists(Call c |
    c.getFunc().(Name).getId() = "url2pathname" and
    normalizedPathOf(c).matches("%/pymdownx/util.py") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "url2pathname" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "urllib.request" and
    matchKind = "ast"
  )
  or
  /* family 6j: path_wrapper - html.unescape(url) at util.py:119 (the
     HTML-entity decoding call inside util.parse_url, applied to the raw
     attribute value BEFORE urlparse; scoped to util.py - keys.py:158
     also calls html.unescape() but operates on keyboard-key tokens, not
     paths) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "unescape" and
    func.getObject().(Name).getId() = "html" and
    normalizedPathOf(c).matches("%/pymdownx/util.py") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "unescape" and
    argIndex = 0 and
    receiver = "html" and
    moduleHint = "html" and
    matchKind = "ast"
  )
  or
  /* family 6k: path_wrapper - self.get_snippet_path(path) call at
     snippets.py:301 - THE custom resolution wrapper invocation that
     carries the extracted include path into the os.path.join pipeline
     (the wrapper definition itself is emitted as family 11's
     file_api_def row); conditional expression
     `self.get_snippet_path(path) if not url else path` */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get_snippet_path" and
    func.getObject().(Name).getId() = "self" and
    normalizedPathOf(c).matches("%/pymdownx/snippets.py") and
    node = c and
    flowKind = "path_wrapper" and
    callableName = "get_snippet_path" and
    argIndex = 0 and
    receiver = "self" and
    moduleHint = "pymdownx.snippets" and
    matchKind = "ast"
  )
  or
  /* family 7: file_stat - os.path.exists(...) existence gates:
     snippets.py:160 (base_path entry), :163/:171 (the joined include
     filename - THE check-then-codecs.open TOCTOU-shaped gate; also the
     only thing standing between the join and the read, and it is an
     existence check, not a traversal guard), b64.py:82 (the resolved
     img-src filename before open), gen_emoji.py:60 (destination tag
     dir, operator); os.path.isdir(...): snippets.py:161 (base_path
     entry branch), gen_emoji.py:50 (extracted repo dir); os.path.
     isfile(...): gen_twemoji.py:201 (svg asset filter, operator) */
  exists(Call c, Attribute func, Attribute funcObj |
    func = c.getFunc().(Attribute) and
    (func.getName() = "exists" or func.getName() = "isdir" or func.getName() = "isfile") and
    funcObj = func.getObject().(Attribute) and
    funcObj.getName() = "path" and
    funcObj.getObject().(Name).getId() = "os" and
    (normalizedPathOf(c).matches("%/pymdownx/snippets.py") or
     normalizedPathOf(c).matches("%/pymdownx/b64.py") or
     normalizedPathOf(c).matches("%/tools/gen_emoji.py") or
     normalizedPathOf(c).matches("%/tools/gen_twemoji.py")) and
    node = c and
    flowKind = "file_stat" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 8: file_read - os.listdir(...) directory reads:
     gen_emoji.py:48 (scan of the extraction dir for the extracted repo
     folder), gen_twemoji.py:200 (svg asset dir listing, operator) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "listdir" and
    func.getObject().(Name).getId() = "os" and
    (normalizedPathOf(c).matches("%/tools/gen_emoji.py") or
     normalizedPathOf(c).matches("%/tools/gen_twemoji.py")) and
    node = c and
    flowKind = "file_read" and
    callableName = "listdir" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 9: file_mkdir - os.makedirs(destination) at gen_emoji.py:61
     and :65 (the tag destination dir created before download/extract;
     operator input) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "makedirs" and
    func.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/tools/gen_emoji.py") and
    node = c and
    flowKind = "file_mkdir" and
    callableName = "makedirs" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 10: file_remove - shutil.rmtree(destination) at
     gen_emoji.py:64 (removal of the old tag dir before re-download;
     operator input) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "rmtree" and
    func.getObject().(Name).getId() = "shutil" and
    normalizedPathOf(c).matches("%/tools/gen_emoji.py") and
    node = c and
    flowKind = "file_remove" and
    callableName = "rmtree" and
    argIndex = 0 and
    receiver = "shutil" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  /* family 11: file_rename - os.rename(repo_dir, os.path.join(base,
     ...)) at gen_emoji.py:54 (renaming the extracted repo folder to the
     canonical name; the source argument 0 is a listing-derived path) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "rename" and
    func.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/tools/gen_emoji.py") and
    node = c and
    flowKind = "file_rename" and
    callableName = "rename" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 12: file_api_def - definition rows of the path-consuming
     internal APIs (for labeling as summary/boundary), carrying the true
     parameter positions. */

  /* SnippetPreprocessor.get_snippet_path(self, path) - path at position
     1; THE resolution wrapper: os.path.join(base, path) at :162/:170
     with NO traversal validation, existence-gated at :163/:171, its
     return value feeds codecs.open at :311 */
  exists(Function fn, Parameter p |
    fn.getName() = "get_snippet_path" and
    fn.getEnclosingScope().(Class).getName() = "SnippetPreprocessor" and
    normalizedPathOf(fn).matches("%/pymdownx/snippets.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "get_snippet_path" and
    argIndex = p.getPosition() and
    receiver = "SnippetPreprocessor" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* util.url2path(path) - module-level function at util.py:53; the
     percent-decoding wrapper around url2pathname consumed by b64.py:75
     and pathconverter.py:77/:105 */
  exists(Function fn, Parameter p |
    fn.getName() = "url2path" and
    normalizedPathOf(fn).matches("%/pymdownx/util.py") and
    p = fn.getArgByName("path") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "url2path" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* util.parse_url(url) - module-level function at util.py:103; the
     HTML-entity + URL parse/decoder (absolute-form classifier consumed
     by b64.py:73 and pathconverter.py:72/:102) */
  exists(Function fn, Parameter p |
    fn.getName() = "parse_url" and
    normalizedPathOf(fn).matches("%/pymdownx/util.py") and
    p = fn.getArgByName("url") and
    node = p and
    flowKind = "file_api_def" and
    callableName = "parse_url" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
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
