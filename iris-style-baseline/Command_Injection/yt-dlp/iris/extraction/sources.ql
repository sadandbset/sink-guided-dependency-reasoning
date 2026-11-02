/**
 * @name yt-dlp CWE-78 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the yt-dlp
 *   CodeQL database (snapshot 61bdf15): JSON decoding of remote payloads (json.loads,
 *   the InfoExtractor._parse_json boundary at yt_dlp/extractor/common.py:1013 and the
 *   47+ direct json.loads sites across extractors, the updater GitHub-API decode, the
 *   postprocessor _download_json decode), raw network response reads (.read()/.recv()
 *   on response handles, websocket frames, the SOCKS proxy socket), the network fetch
 *   funnel (YoutubeDL.urlopen / RequestDirector.send / opener.open), the
 *   extractor-facing download-and-parse method calls (_download_json,
 *   _download_webpage, _parse_json, ... - factory-generated via
 *   __create_download_methods, matched at call sites), handler entry-point parameters
 *   (_real_extract, real_download, PostProcessor.run, parse_cmd, CLI/config readers),
 *   CLI/config/parameter reads (opts.<name>, get_param, _configuration_args, sys.argv,
 *   optparse), environment reads (os.environ/os.getenv/expandvars), and built-in
 *   open() file input. Raw BQRS extraction query: run with `codeql query run` and
 *   decode with `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong shape for
 *   candidate tables and @kind table is not assumed to exist.
 * @id iris/yt-dlp/extraction/sources
 * @tags command-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or attribute name)
 *   4. flow_kind  - "return" (tainted return value), "read" (response/stream/file read),
 *                   "socket_recv" (websocket/proxy socket receive), "net_fetch"
 *                   (network request dispatch), "extractor_boundary" (download/parse
 *                   method call returning remote content), "parse" (string parsed into
 *                   structured data), "param" (handler entry-point parameter),
 *                   "config" (ydl parameter / configured args), "env", "cli", "file"
 *   5. receiver   - syntactic receiver hint (base name of the object expression, ""
 *                   if none, enclosing class name for function-definition rows)
 *   6. moduleHint - module hint: external module name, "yt_dlp.utils" for internal
 *                   utils helpers, or the dotted python module path of the candidate
 *                   (variable intentionally named moduleHint; `module` is not a valid
 *                   QL variable name here)
 *   7. arg_index  - 0-based positional argument index (parameter position in the
 *                   function definition for "param" rows), -1 if N/A
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath(); AstNode.getFile()
 *                    does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast" (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), avoids assigning API::Node
 * values to DataFlow::Node variables, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced a row).
 * The _download_json family of InfoExtractor is generated at runtime by the
 * __create_download_methods factory (extractor/common.py:1021-1091) and dispatched
 * through getattr, so those boundaries resolve only at AST level.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for internal
 *  candidates). Files that are not on an import path (top-level scripts like
 *  pyinst.py, devscripts/*.py, test/*.py) have no dotted module name; their file
 *  base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
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

/** Receiver hint for the callee expression of a call ("" when there is no attribute receiver). */
string receiverHintOfCall(Call c) {
  exists(Attribute a |
    a = c.getFunc() and
    result = receiverHint(a)
  )
  or
  not c.getFunc() instanceof Attribute and result = ""
}

/** Syntactic name of the callee of a call ("<expr>" if it is neither Name nor Attribute). */
string calledNameOf(Call c) {
  result = c.getFunc().(Name).getId()
  or
  result = c.getFunc().(Attribute).getName()
  or
  not c.getFunc() instanceof Name and
  not c.getFunc() instanceof Attribute and
  result = "<expr>"
}

/* ------------------------------------------------------------------ */
/* Source family 1: resolved decode APIs (API graphs)                  */
/* ------------------------------------------------------------------ */

/**
 * External decoding/lookup APIs whose return value may carry attacker-controlled data:
 * json.loads decodes JSON payloads (the dominant remote-data decode in this tree),
 * os.getenv reads the process environment, urllib parse_* / unquote* decode request
 * strings, urllib.request.urlopen returns a remote response. yt-dlp imports json in
 * 158 modules, so json.loads resolves broadly through API graphs.
 */
private predicate resolvedDecodeCall(API::CallNode cn, string moduleHint, string member, int argIndex) {
  (
    moduleHint = "json" and member in ["loads", "load"] and argIndex = 0
    or
    moduleHint = "os" and member = "getenv" and argIndex = 0
    or
    moduleHint = "urllib.parse" and member in ["parse_qs", "parse_qsl", "unquote_plus", "unquote"] and argIndex = 0
    or
    moduleHint = "urllib.request" and member = "urlopen" and argIndex = 0
  ) and
  (
    moduleHint != "urllib.parse" and cn = API::moduleImport(moduleHint).getMember(member).getACall()
    or
    moduleHint = "urllib.parse" and
    cn = API::moduleImport("urllib").getMember("parse").getMember(member).getACall()
  )
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Source family 2: decode/input calls matched by AST shape            */
/* ------------------------------------------------------------------ */

/**
 * Internal/protocol input calls matched by AST shape: JSON decode (qualified
 * json.loads/json.load and bare from-imported loads), urllib parse/decode through
 * any `<mod>.parse.*` alias or bare from-imported names, urllib request fetch,
 * os.getenv fallback, base64 decoders of remote payloads, zlib decompression of
 * remote manifests, and the internal yt_dlp.utils JS/JSON decoders
 * (js_to_json, jwt_decode_hs256) bound by from-import.
 */
private predicate decodeSourceCall(Call c, string moduleHint, string callableName, int argIndex) {
  /* json decode: json.loads(...)/json.load(...) / bare loads(...)
     (bare "load" is too collision-prone for a syntax-level match) */
  moduleHint = "json" and
  argIndex = 0 and
  (
    c.getFunc().(Attribute).getName() = callableName and
    c.getFunc().(Attribute).getObject().(Name).getId() = "json" and
    callableName in ["loads", "load"]
    or
    callableName = "loads" and
    c.getFunc().(Name).getId() = "loads"
  )
  or
  /* os.getenv syntax-level fallback */
  moduleHint = "os" and
  callableName = "getenv" and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = "getenv" and
  c.getFunc().(Attribute).getObject().(Name).getId() = "os"
  or
  /* urllib parse decode: <mod>.parse.<member>(...) (any base name before ".parse."
     is accepted - import aliases make the module prefix syntactically variable),
     or bare from-imported member names */
  moduleHint = "urllib.parse" and
  callableName in ["parse_qs", "parse_qsl", "unquote_plus", "unquote"] and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = callableName and
  c.getFunc().(Attribute).getObject().(Attribute).getName() = "parse"
  or
  moduleHint = "urllib.parse" and
  callableName in ["parse_qs", "parse_qsl", "unquote_plus", "unquote"] and
  argIndex = 0 and
  c.getFunc().(Name).getId() = callableName
  or
  /* urllib request fetch: <mod>.request.urlopen(...) / bare urlopen */
  moduleHint = "urllib.request" and
  callableName = "urlopen" and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = "urlopen" and
  c.getFunc().(Attribute).getObject().(Attribute).getName() = "request"
  or
  moduleHint = "urllib.request" and
  callableName = "urlopen" and
  argIndex = 0 and
  c.getFunc().(Name).getId() = "urlopen"
  or
  /* base64 decode of remote payloads: base64.b64decode / urlsafe_b64decode,
     or bare from-imported names */
  moduleHint = "base64" and
  callableName in ["b64decode", "urlsafe_b64decode", "decodebytes"] and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = callableName and
  c.getFunc().(Attribute).getObject().(Name).getId() = "base64"
  or
  moduleHint = "base64" and
  callableName in ["b64decode", "urlsafe_b64decode", "decodebytes"] and
  argIndex = 0 and
  c.getFunc().(Name).getId() = callableName
  or
  /* zlib.decompress of remote manifests (downloader/f4m.py) */
  moduleHint = "zlib" and
  callableName = "decompress" and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = "decompress" and
  c.getFunc().(Attribute).getObject().(Name).getId() = "zlib"
  or
  /* internal yt_dlp.utils decoders bound by from-import:
     js_to_json (remote JS -> JSON), jwt_decode_hs256 (remote JWT payload) */
  moduleHint = "yt_dlp.utils" and
  callableName in ["js_to_json", "jwt_decode_hs256"] and
  argIndex = 0 and
  c.getFunc().(Name).getId() = callableName
}

/* ------------------------------------------------------------------ */
/* Source family 3: response / stream / socket reads                   */
/* ------------------------------------------------------------------ */

/**
 * Raw byte/text input calls matched by member name: `.read()` on response handles,
 * files and streams (extractor/common.py:979 `urlh.read()`, downloader/hls.py:79,
 * update.py:218/258, networking Response.read at networking/common.py:513, file
 * re-reads of remote-derived artifacts), and `.recv()` websocket/proxy socket
 * receives (downloader/niconico.py:107, extractor/fc2.py:213/225,
 * extractor/niconico.py:984, downloader/websocket.py:50, socks.py:118/247).
 */
private predicate readSourceCall(Call c, string callableName, string flowKind) {
  callableName = "read" and
  flowKind = "read" and
  c.getFunc().(Attribute).getName() = "read"
  or
  callableName = "recv" and
  flowKind = "socket_recv" and
  c.getFunc().(Attribute).getName() = "recv"
}

/* ------------------------------------------------------------------ */
/* Source family 4: network fetch funnel                               */
/* ------------------------------------------------------------------ */

/**
 * Network request dispatch calls: any `.urlopen(...)` call (YoutubeDL.urlopen and
 * every self.ydl/self._downloader/ydl.urlopen caller - the single funnel for all
 * remote fetches), `.send(...)` on a receiver named `_request_director`
 * (RequestDirector.send at YoutubeDL.py:4051), and `.open(...)` on a receiver named
 * `opener` (the raw urllib opener at networking/_urllib.py:410). Argument 0 is the
 * URL / Request in each case.
 */
private predicate netFetchCall(Call c, string callableName) {
  callableName = "urlopen" and
  c.getFunc().(Attribute).getName() = "urlopen"
  or
  callableName = "send" and
  c.getFunc().(Attribute).getName() = "send" and
  receiverHintOfCall(c) = "_request_director"
  or
  callableName = "open" and
  c.getFunc().(Attribute).getName() = "open" and
  receiverHintOfCall(c) = "opener"
}

/* ------------------------------------------------------------------ */
/* Source family 5: extractor download/parse boundary calls            */
/* ------------------------------------------------------------------ */

/**
 * InfoExtractor / PostProcessor download-and-parse method calls with the 0-based
 * positional argument index that carries the remote content or its URL. The fetch
 * methods take the URL at index 0; _search_json takes the input string at index 1
 * (start_pattern, string, name, video_id); the _parse_* methods take the content
 * string at index 0. These methods are generated by the
 * __create_download_methods factory and dispatched through getattr, so they are
 * matched purely syntactically on the member name.
 */
private predicate extractorBoundaryCall(Call c, string callableName, string flowKind, int argIndex) {
  callableName in ["_download_json", "_download_json_handle", "_download_webpage",
                   "_download_webpage_handle", "_download_xml", "_download_xml_handle",
                   "_download_socket_json", "_download_socket_json_handle",
                   "_request_webpage"] and
  flowKind = "extractor_boundary" and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = callableName
  or
  callableName in ["_parse_json", "_parse_xml", "_parse_socket_response_as_json",
                   "_search_json_ld"] and
  flowKind = "parse" and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = callableName
  or
  callableName = "_search_json" and
  flowKind = "parse" and
  argIndex = 1 and
  c.getFunc().(Attribute).getName() = callableName
}

/* ------------------------------------------------------------------ */
/* Source family 6: handler entry-point functions                      */
/* ------------------------------------------------------------------ */

/**
 * Functions that sit at an external-data boundary: the per-URL extractor entry
 * point (_real_extract, ~1000 implementations), downloader entry points
 * (real_download), postprocessor entry points (run on *PP / *PostProcessor classes),
 * the ExecPP command template parser (parse_cmd), the CLI/config readers
 * (parseOpts / parse_options / _real_main / main / read_config / load_configs /
 * read_file / read_stdin), the credentials boundaries (_get_netrc_login_info,
 * load_cookies, extract_cookies_from_browser, _perform_login), the network funnel
 * definitions (urlopen, _request_webpage, _webpage_read_content,
 * _download_webpage_handle), the remote-content parser definitions
 * (_parse_json/_download_json/_parse_xml/_search_json/_search_regex/
 * _html_search_regex), and the live-chat fragment parser
 * (download_and_parse_fragment). Dunders and pure logging/reporting helpers are
 * not included.
 */
private predicate isHandlerFunction(Function f) {
  f.getName() in ["_real_extract", "_perform_login", "_real_initialize", "real_download",
                  "parse_cmd", "main", "_real_main", "parse_options", "parseOpts",
                  "read_config", "load_configs", "_load_from_config_dirs", "read_file",
                  "read_stdin", "load_cookies", "extract_cookies_from_browser",
                  "_get_netrc_login_info", "download_and_parse_fragment", "urlopen",
                  "_request_webpage", "_webpage_read_content", "_download_webpage_handle",
                  "_parse_json", "_download_json", "_parse_xml", "_search_json",
                  "_search_json_ld", "_search_regex", "_html_search_regex"]
  or
  /* postprocessor run() entry points (information dict is remote-derived) */
  f.getName() = "run" and
  f.getEnclosingScope() instanceof Class and
  (
    f.getEnclosingScope().(Class).getName().matches("%PP")
    or
    f.getEnclosingScope().(Class).getName().matches("%PostProcessor")
  )
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                         */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: resolved decode API calls (API graphs, alias-aware) */
  exists(API::CallNode cn |
    resolvedDecodeCall(cn, moduleHint, callableName, argIndex) and
    node = astCallOf(cn) and
    flowKind = "return" and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 2: decode/input calls matched by AST shape */
  exists(Call c |
    decodeSourceCall(c, moduleHint, callableName, argIndex) and
    node = c and
    flowKind = "return" and
    receiver = receiverHintOfCall(c) and
    matchKind = "ast"
  )
  or
  /* family 3: response / stream / socket reads */
  exists(Call c |
    readSourceCall(c, callableName, flowKind) and
    node = c and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    argIndex = -1 and
    matchKind = "ast"
  )
  or
  /* family 4: network fetch funnel (urlopen / director.send / opener.open) */
  exists(Call c |
    netFetchCall(c, callableName) and
    node = c and
    flowKind = "net_fetch" and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    argIndex = 0 and
    matchKind = "ast"
  )
  or
  /* family 5: extractor download/parse boundary method calls */
  exists(Call c |
    extractorBoundaryCall(c, callableName, flowKind, argIndex) and
    node = c and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6a: parameters of handler entry-point functions
     (arg_index is the 0-based position in the function definition; self is excluded) */
  exists(Function f, Parameter p |
    isHandlerFunction(f) and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "param" and
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
  /* family 7a: ydl parameter reads: self.get_param(...) - every CLI/config option
     reaches consumers through this accessor (e.g. get_param('netrc_cmd'),
     get_param('exec_cmd')) */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "get_param" and
    node = c and
    flowKind = "config" and
    callableName = "get_param" and
    argIndex = 0 and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 7b: configured per-tool arguments: self._configuration_args(...)
     (merges user --ffmpeg-args / external downloader args into process argv) */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "_configuration_args" and
    node = c and
    flowKind = "config" and
    callableName = "_configuration_args" and
    argIndex = 0 and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 7c: CLI option loads: opts.<name> / options.<name>
     (parseOpts result namespace consumed across yt_dlp/__init__.py) */
  exists(Attribute a |
    a.getObject().(Name).getId() in ["opts", "options"] and
    node = a and
    flowKind = "cli" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = a.getObject().(Name).getId() and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 8a: os.environ read */
  exists(Attribute a |
    a.getName() = "environ" and
    a.getObject().(Name).getId() = "os" and
    node = a and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 8b: os.environ.get(...) read */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Attribute).getName() = "environ" and
    func.getObject().(Attribute).getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 8c: os.path.expandvars(...) env-var expansion of user/config paths */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "expandvars" and
    c.getFunc().(Attribute).getObject().(Attribute).getName() = "path" and
    node = c and
    flowKind = "env" and
    callableName = "expandvars" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 8d: expand_path(...) internal wrapper (os.path.expandvars +
     expanduser on user/config-supplied paths, bound by from-import) */
  exists(Call c |
    c.getFunc().(Name).getId() = "expand_path" and
    node = c and
    flowKind = "env" and
    callableName = "expand_path" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "yt_dlp.utils" and
    matchKind = "ast"
  )
  or
  /* family 9a: sys.argv / sys.orig_argv reads (CLI; orig_argv drives the
     updater restart command) */
  exists(Attribute a |
    a.getName() in ["argv", "orig_argv"] and
    a.getObject().(Name).getId() = "sys" and
    node = a and
    flowKind = "cli" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "sys" and
    moduleHint = "sys" and
    matchKind = "ast"
  )
  or
  /* family 9b: optparse registration and parsing (options.py uses optparse,
     not argparse: _YoutubeDLOptionParser(optparse.OptionParser)) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["add_option", "parse_args", "parse_known_args"] and
    node = c and
    flowKind = "cli" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "optparse" and
    matchKind = "ast"
  )
  or
  /* family 10: built-in open(): file input (path is argument 0) - config files,
     cookie jars, info.json, batch files, remote-derived disk artifacts */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    node = c and
    flowKind = "file" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind)
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
  matchKind as match_kind
