/**
 * @name pymdown-extensions CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   pymdown-extensions CodeQL database (snapshot a8fb9666, pymdown-extensions
 *   9.11.0 final - the Markdown extension library itself is the audit
 *   target; there is no web surface and no console entry point, the
 *   untrusted boundary is the MARKDOWN SOURCE TEXT / rendered HTML output
 *   fed by the host Python-Markdown core through the extension run()
 *   boundaries): the snippet include-path extraction family
 *   (m.group('snippet') call nodes at snippets.py:258 - both branches of
 *   the inline conditional - whose return value is the quoted include path
 *   straight out of the markdown line, and m.group(1) at :276, the bare
 *   path after RE_SNIPPET_FILE ':lines'/':section' suffix stripping; these
 *   feed get_snippet_path -> os.path.join(base, path) -> codecs.open at
 *   snippets.py:311 with NO traversal validation); the img/link attribute
 *   extraction family (m.group('path') at b64.py:73, pathconverter.py:72/
 *   :102 - src attribute values out of the rendered output, decoded by
 *   util.parse_url/html.unescape + util.url2path/url2pathname and resolved
 *   by os.path.normpath(os.path.join(base_path, path)) before the
 *   open(file_name, 'rb') read at b64.py:86); the processor boundary
 *   parameters (SnippetPreprocessor.run lines, SnippetPreprocessor.
 *   parse_snippets lines - the recursive nested-include entry,
 *   SnippetPreprocessor.download url - the markdown-controlled URL fetched
 *   by urlopen when url_download is enabled, network/Pass-3-adjacent,
 *   emitted for labeling, B64Postprocessor.run text,
 *   PathConverterPostprocessor.run text) with true parameter positions;
 *   the argparse CLI boundary of the dev/test scripts (parser.parse_args()
 *   at run_tests.py:25 and tools/gen_emoji.py:126, and the args.file[0]
 *   subscript read at run_tests.py:28 reaching os.path.abspath/:exists);
 *   and the external-content boundary of the maintainer emoji tool
 *   (tags[user_input]['zipball_url'] at gen_emoji.py:112 - the GitHub API
 *   JSON response value whose basename lands in the downloaded-zip path).
 *   Operator-configured values that are NOT attacker input (base_path /
 *   relative_path / encoding / check_paths / auto_append / url_* configs,
 *   current_dir script-location derivatives, hardcoded repo names) are NOT
 *   emitted - documented in detection.json instead. Raw BQRS extraction
 *   query: run with `codeql query run` and decode with `codeql bqrs
 *   decode` (not database analyze). This is a plain multi-column select
 *   query on purpose: @kind problem is the wrong shape for candidate
 *   tables and @kind table is not assumed to exist.
 * @id iris/pymdown-extensions/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (e.g. "group", "parse_args",
 *                   "zipball_url", or the function name for parameter rows)
 *   4. flow_kind  - "markdown_snippet_path" (regex-group extraction of
 *                   snippet include paths from markdown lines),
 *                   "markdown_attr_path" (regex-group extraction of img
 *                   src / link href values from the rendered output),
 *                   "param" (Markdown preprocessor/postprocessor boundary
 *                   parameters receiving the document source or rendered
 *                   output), "cli" (argparse Namespace / parse boundary of
 *                   the dev/test scripts), "external_content" (GitHub API
 *                   JSON response reads in the maintainer tool)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "m"/"parser"/"args"/"tags" etc., "" when
 *                   none, enclosing class name for parameter rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index when a call argument
 *                   carries the value; subscript index for subscript-read
 *                   rows; -1 when the return value carries it; for "param"
 *                   rows the true parameter position in the function
 *                   definition, including the self slot for methods
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no source row is expected to resolve at API level:
 * the extracted values come from regex match objects (m.group(...)), argparse
 * Namespace fields, dict subscript reads and processor parameters - none of
 * which API graphs can bind to stdlib members (markdown/argparse/urllib are
 * not part of the database - only the pymdown-extensions tree is). The
 * match_kind column is kept "ast" for all families for cross-project
 * contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (32 files of the database
 * snapshot), /pymdown-extensions-db/ (the CodeQL database directory sits
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

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: snippet include-path extraction - m.group('snippet') call
     nodes at snippets.py:258 (both branches of the conditional expression
     `m.group('snippet')[1:-1].strip() if inline else m.group('snippet').
     strip()`); the return value is the quoted include path taken straight
     out of the markdown source line ('--8<-- "path"' inline form). These
     two call nodes are the origin of the dominant attacker-controlled
     file-location input: it flows through m.group(1) (family 2),
     get_snippet_path, os.path.join(base, path) (snippets.py:162/:170 - no
     traversal validation) and codecs.open (snippets.py:311). */
  exists(Call c, Attribute func, StringLiteral arg0 |
    func = c.getFunc().(Attribute) and
    func.getName() = "group" and
    func.getObject().(Name).getId() = "m" and
    arg0 = c.getPositionalArg(0).(StringLiteral) and
    arg0.getText() = "snippet" and
    normalizedPathOf(c).matches("%/pymdownx/snippets.py") and
    node = c and
    flowKind = "markdown_snippet_path" and
    callableName = "group" and
    argIndex = -1 and
    receiver = "m" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 2: bare include-path re-extraction - m.group(1) at
     snippets.py:276; RE_SNIPPET_FILE (:77) splits trailing ':N:N' line
     ranges and ':name' section selectors off the raw include path and
     group(1) is the bare path that reaches get_snippet_path (:301).
     The getValue() = 1 constraint distinguishes group(1) from the
     line-range/section group indices read at :283/:286/:289
     (m.group(2)/m.group(3)/m.group(4) are line numbers and section
     names, not paths). */
  exists(Call c, Attribute func, IntegerLiteral arg0 |
    func = c.getFunc().(Attribute) and
    func.getName() = "group" and
    func.getObject().(Name).getId() = "m" and
    arg0 = c.getPositionalArg(0).(IntegerLiteral) and
    arg0.getValue() = 1 and
    normalizedPathOf(c).matches("%/pymdownx/snippets.py") and
    node = c and
    flowKind = "markdown_snippet_path" and
    callableName = "group" and
    argIndex = -1 and
    receiver = "m" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: img/link attribute extraction - m.group('path') call nodes
     at b64.py:73 (inside repl_path: the src attribute value of <img> tags
     in the rendered output, quoted text stripped by the [1:-1] slice; it
     feeds util.parse_url -> util.url2path -> os.path.normpath(os.path.join
     (base_path, path)) at b64.py:80 and open(file_name, 'rb') at :86) and
     pathconverter.py:72/:102 (repl_relative/repl_absolute: the same
     extraction shape over src/href attributes; VERIFIED pure string
     rewriting - no filesystem access in pathconverter.py, rows emitted as
     propagation-chain evidence for the labeling step) */
  exists(Call c, Attribute func, StringLiteral arg0 |
    func = c.getFunc().(Attribute) and
    func.getName() = "group" and
    func.getObject().(Name).getId() = "m" and
    arg0 = c.getPositionalArg(0).(StringLiteral) and
    arg0.getText() = "path" and
    (normalizedPathOf(c).matches("%/pymdownx/b64.py") or
     normalizedPathOf(c).matches("%/pymdownx/pathconverter.py")) and
    node = c and
    flowKind = "markdown_attr_path" and
    callableName = "group" and
    argIndex = -1 and
    receiver = "m" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 4: Markdown processor boundary parameters - the host
     Python-Markdown core (outside the database) invokes these run()
     methods with the untrusted document source lines / rendered HTML
     output. Positions include the self slot for methods. */

  /* SnippetPreprocessor.run(self, lines) - lines at position 1; the
     preprocessor entry (registered as 'snippet', snippets.py:392);
     parse_snippets is called on these lines at :359 */
  exists(Function fn, Parameter p |
    fn.getName() = "run" and
    fn.getEnclosingScope().(Class).getName() = "SnippetPreprocessor" and
    normalizedPathOf(fn).matches("%/pymdownx/snippets.py") and
    p = fn.getArgByName("lines") and
    node = p and
    flowKind = "param" and
    callableName = "run" and
    argIndex = p.getPosition() and
    receiver = "SnippetPreprocessor" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* SnippetPreprocessor.parse_snippets(self, lines, file_name, is_url) -
     lines at position 1; the recursive entry that re-parses the lines of
     every included snippet file (snippets.py:333-341), so nested include
     content (which itself comes from files resolved by unguarded
     os.path.join) re-enters here; also the direct path from run() */
  exists(Function fn, Parameter p |
    fn.getName() = "parse_snippets" and
    fn.getEnclosingScope().(Class).getName() = "SnippetPreprocessor" and
    normalizedPathOf(fn).matches("%/pymdownx/snippets.py") and
    p = fn.getArgByName("lines") and
    node = p and
    flowKind = "param" and
    callableName = "parse_snippets" and
    argIndex = p.getPosition() and
    receiver = "SnippetPreprocessor" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* SnippetPreprocessor.download(self, url) - url at position 1; the
     markdown-controlled http(s) include URL (path.lower().startswith(
     ('https://', 'http://')) gate at snippets.py:294, url_download config
     at :300); fetched via urllib.request.urlopen (:186) when enabled - a
     network fetch of attacker-chosen content (Pass 3 / SSRF adjacent);
     emitted for labeling, which may legitimately mark it none for Pass 1 */
  exists(Function fn, Parameter p |
    fn.getName() = "download" and
    fn.getEnclosingScope().(Class).getName() = "SnippetPreprocessor" and
    normalizedPathOf(fn).matches("%/pymdownx/snippets.py") and
    p = fn.getArgByName("url") and
    node = p and
    flowKind = "param" and
    callableName = "download" and
    argIndex = p.getPosition() and
    receiver = "SnippetPreprocessor" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* B64Postprocessor.run(self, text) - text at position 1; the
     postprocessor entry (registered as 'b64', b64.py:139) receiving the
     rendered HTML output; img src paths are extracted from it by
     RE_TAG_HTML/RE_TAG_LINK_ATTR (b64.py:42-65) */
  exists(Function fn, Parameter p |
    fn.getName() = "run" and
    fn.getEnclosingScope().(Class).getName() = "B64Postprocessor" and
    normalizedPathOf(fn).matches("%/pymdownx/b64.py") and
    p = fn.getArgByName("text") and
    node = p and
    flowKind = "param" and
    callableName = "run" and
    argIndex = p.getPosition() and
    receiver = "B64Postprocessor" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* PathConverterPostprocessor.run(self, text) - text at position 1; the
     postprocessor entry (registered as 'path-converter',
     pathconverter.py:181) receiving the rendered HTML output whose
     src/href attributes get rewritten */
  exists(Function fn, Parameter p |
    fn.getName() = "run" and
    fn.getEnclosingScope().(Class).getName() = "PathConverterPostprocessor" and
    normalizedPathOf(fn).matches("%/pymdownx/pathconverter.py") and
    p = fn.getArgByName("text") and
    node = p and
    flowKind = "param" and
    callableName = "run" and
    argIndex = p.getPosition() and
    receiver = "PathConverterPostprocessor" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* family 5: CLI boundaries of the dev/test scripts (operator trust
     level, real process-input boundaries, emitted for labeling per the
     series convention) */

  /* parser.parse_args() boundary calls - run_tests.py:25 (ArgumentParser
     with --update/--test-target/--file; parse_args() without arguments
     reads sys.argv) and tools/gen_emoji.py:126 (ArgumentParser with
     --tag/--gemoji/--emojione/--twemoji/...; the tag values are version
     strings, not paths - only the parse boundary is emitted here) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "parse_args" and
    func.getObject().(Name).getId() = "parser" and
    (normalizedPathOf(c).matches("%/run_tests.py") or
     normalizedPathOf(c).matches("%/tools/gen_emoji.py")) and
    node = c and
    flowKind = "cli" and
    callableName = "parse_args" and
    argIndex = -1 and
    receiver = "parser" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* args.file[0] subscript read at run_tests.py:28 - the --file CLI value
     (a test-file path) read out of the argparse Namespace; it flows into
     os.path.abspath (:28), os.path.exists (:29) and
     test_syntax.set_target_file (:30). argIndex 0 is the subscript index.
     The non-path fields (args.update, args.test_target) are not matched. */
  exists(Subscript s, Attribute obj |
    obj = s.getObject().(Attribute) and
    obj.getName() = "file" and
    obj.getObject().(Name).getId() = "args" and
    normalizedPathOf(s).matches("%/run_tests.py") and
    node = s and
    flowKind = "cli" and
    callableName = "file" and
    argIndex = 0 and
    receiver = "args" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 6: external-content boundary of the maintainer emoji tool -
     tags[user_input]['zipball_url'] subscript read at gen_emoji.py:112;
     tags is json.loads(requests.get(GITHUB_API ...).text) (:83-90), i.e.
     external GitHub API JSON; the zipball_url value flows into
     download_tag -> os.path.basename(url) + '.zip' (join at :66) ->
     open(file_location, 'wb') (:73) and zipfile.ZipFile +
     z.extractall (:44-45) with no member validation. argIndex 0 is the
     subscript index; the outer subscript node is the row node, receiver
     'tags' is the inner subscript's base. */
  exists(Subscript s, Subscript inner, StringLiteral idx |
    inner = s.getObject().(Subscript) and
    inner.getObject().(Name).getId() = "tags" and
    idx = s.getIndex().(StringLiteral) and
    idx.getText() = "zipball_url" and
    normalizedPathOf(s).matches("%/tools/gen_emoji.py") and
    node = s and
    flowKind = "external_content" and
    callableName = "zipball_url" and
    argIndex = 0 and
    receiver = "tags" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
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
