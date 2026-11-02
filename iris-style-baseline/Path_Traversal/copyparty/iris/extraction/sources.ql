/**
 * @name copyparty CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   copyparty CodeQL database (copyparty 1.8.1 "argon", snapshot sha 8f59afb,
 *   a framework-less multi-protocol file server): the decoded HTTP request
 *   URL path self.vpath (percent-decoded from the raw request line at
 *   httpcli.py:375 after the FIRST undot at :333/:337 - encoded traversal
 *   survives that first undot and is only neutralized by the second undot
 *   inside VFS.get at authsrv.py:473); the raw request line self.req
 *   (httpcli.py:241); the percent-decoder boundary itself (unquotep/unquote
 *   call sites at httpcli.py:341/:375/:1199/:1327/:1726/:3337/:3871 covering
 *   query values, the WebDAV Destination move target, zip item lists and the
 *   ?doc= filename); the percent-decoded query dict self.uparam (.get calls
 *   and [...] subscripts - th/doc/move/k/gz/xz carry path-bearing values);
 *   HTTP header reads self.headers (.get and [...] - including the WebDAV
 *   Destination header at :1197); cookie reads self.cookies; the up2k upload
 *   handshake JSON body (json.loads at httpcli.py:1752, api+ast rows) whose
 *   client fields name/hash/size/lmod plus the delete/srch item arrays
 *   control upload/delete destinations; multipart form fields
 *   (self.parser.require) and the multipart body generator
 *   (self.parser.gen, whose p_file filename reaches ren_open/sanitize_fn);
 *   the FTP boundary (the vpath parameters of FtpFs.v2a/rv2a and the
 *   client-controlled CWD state self.cwd in ftpd.py); the SMB boundary (the
 *   vpath parameters of smbd.py _v2a/_listdir/_open); and the boot-time
 *   environment reads os.environ.get in __main__.py (deployer trust level,
 *   kept for the labeling step to judge). Raw BQRS extraction query: run
 *   with `codeql query run` and decode with `codeql bqrs decode` (not
 *   database analyze). This is a plain multi-column select query on
 *   purpose: the problem query kind is the wrong shape for candidate
 *   tables and no table kind is assumed to exist.
 * @id iris/copyparty/extraction/sources
 * @tags path-traversal
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql and to the prior IRIS manual
 * projects aiohttp/airflow/ansible/coderedcms):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (e.g. "vpath", "unquotep",
 *                   "get", "loads", "require", "gen", "v2a", "environ")
 *   4. flow_kind  - "http_path" (decoded URL path), "http_req" (raw request
 *                   line), "http_url_decode" (percent-decode call),
 *                   "http_query" (self.uparam read), "http_header"
 *                   (self.headers read), "http_cookie" (self.cookies read),
 *                   "json_body" (json.loads of the POST body),
 *                   "form_field" (multipart form field), "multipart_gen"
 *                   (multipart body/filename generator), "ftp_param" (FTP
 *                   vpath parameter), "ftp_cwd" (FTP working-directory
 *                   state), "smb_param" (SMB vpath parameter), "env"
 *                   (os.environ.get boot-time read)
 *   5. receiver   - syntactic receiver hint ("self", "self.uparam",
 *                   "self.headers", "self.cookies", "self.parser",
 *                   "self.cwd", "FtpFs", the smbd function name for
 *                   parameter rows, "" / "json" / "os" for module-level
 *                   families)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "copyparty.util" for the unquotep family
 *                   (imported from .util at httpcli.py:78-:79) and "json"/
 *                   "os" for the stdlib families
 *   7. arg_index  - 0-based positional argument index carrying the
 *                   controlled key/value (index 0 for keyed reads and the
 *                   decode/loads argument; the 0-based parameter position
 *                   including self for parameter rows), -1 if N/A
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates/functions), does not
 * assign API::Node values to DataFlow::Node variables, keeps every variable
 * bound through a positive body, and keeps resolved-API matching strictly
 * separate from AST syntax matching (the match_kind column records which one
 * produced a row). Only the json.loads family and the os.environ.get family
 * resolve at API level here (API::moduleImport(...).getMember(...).getACall());
 * every other source family is an attribute of the first-party HttpCli/FtpFs
 * request state or a bare-name call to a first-party util function, matched
 * at AST level (copyparty has no framework, so there are no framework-injected
 * route parameters - the URL path itself is the route).
 *
 * Scope (applied to every row): %/copyparty_vuln/copyparty/% (the shipped
 * copyparty package), EXCLUDING the nested %/copyparty-db/% database
 * directory (also outside the positive scope by construction - copyparty-db
 * does not match %/copyparty/%) and %/copyparty/stolen/% (vendored
 * third-party code). Root setup.py, tests/, scripts/, bin/, contrib/, docs/
 * and srv/ are outside the positive scope.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/* Note: every source family hardcodes its moduleHint constant
   ("copyparty.httpcli", "copyparty.util", "copyparty.ftpd",
   "copyparty.smbd", "json", "os") because the families are already
   restricted to their containing module by the normalizedPathOf file
   filter, so no moduleHintOf helper is needed here. */

/** Forward-slash-normalized absolute path of the file containing n, so path
 *  matching works with both CodeQL path styles on Windows. */
string normalizedPathOf(AstNode n) {
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
}

/** True iff the candidate's file path is inside the audited copyparty
 *  package (%/copyparty_vuln/copyparty/% but not the vendored stolen/ tree
 *  and not the nested %/copyparty-db/% database directory). bindingset[path]
 *  declares that the caller passes a bound path (the path only appears in
 *  checked positions such as the receiver of replaceAll/matches inside this
 *  predicate). */
bindingset[path]
predicate copypartySourcePath(string path) {
  path.replaceAll("\\", "/").matches("%/copyparty_vuln/copyparty/%") and
  not path.replaceAll("\\", "/").matches("%/copyparty-db/%") and
  not path.replaceAll("\\", "/").matches("%/copyparty/stolen/%")
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: the decoded HTTP request URL path: every self.vpath attribute
     read in httpcli.py. Assigned once at :375 (self.vpath = unquotep(vpath),
     after undot of the still-encoded path at :333/:337) and read ~116 times;
     the value reaches vfs.get at :423, the .cpr static-resource join at
     :782 (os.path.join(self.E.mod, "web/", self.vpath[5:])), the thumbnail
     channel at :3506 and every handler. The two assignment rows (:142
     placeholder, :375 boundary) are included deliberately - :375 IS the
     decode boundary node. */
  exists(Attribute a |
    a.getName() = "vpath" and
    a.getObject().(Name).getId() = "self" and
    normalizedPathOf(a).matches("%/copyparty/httpcli.py") and
    node = a and
    flowKind = "http_path" and
    callableName = "vpath" and
    argIndex = -1 and
    receiver = "self" and
    moduleHint = "copyparty.httpcli" and
    matchKind = "ast"
  )
  or
  /* family 2: the raw HTTP request line: every self.req attribute read in
     httpcli.py (assigned from the socket header split at :241; the origin
     of vpath/uparam before any splitting or decoding). */
  exists(Attribute a |
    a.getName() = "req" and
    a.getObject().(Name).getId() = "self" and
    normalizedPathOf(a).matches("%/copyparty/httpcli.py") and
    node = a and
    flowKind = "http_req" and
    callableName = "req" and
    argIndex = -1 and
    receiver = "self" and
    moduleHint = "copyparty.httpcli" and
    matchKind = "ast"
  )
  or
  /* family 3: the percent-decode boundary: bare-name unquotep(...)/
     unquote(...) calls in httpcli.py (imported from .util at :78-:79).
     Sites: :341 (query values), :375 (the URL path), :1199 (WebDAV
     Destination), :1327 (basic-auth payload - password, kept for labeling
     to judge), :1726 (zip item lists), :3337 (move= query target), :3871
     (?doc= filename). Argument 0 is the encoded attacker value. */
  exists(Call c |
    c.getFunc().(Name).getId() in ["unquotep", "unquote"] and
    normalizedPathOf(c).matches("%/copyparty/httpcli.py") and
    node = c and
    flowKind = "http_url_decode" and
    callableName = c.getFunc().(Name).getId() and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "copyparty.util" and
    matchKind = "ast"
  )
  or
  /* family 4a: query-string reads: self.uparam.get(key) - argument 0
     carries the key whose percent-decoded value is returned. Path-bearing
     keys at the observed sites include th (thumbnail format), doc (file
     read), move (move destination), k (filekey), gz/xz (compression). */
  exists(Call c, Attribute func, Attribute upar |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    upar = func.getObject().(Attribute) and
    upar.getName() = "uparam" and
    upar.getObject().(Name).getId() = "self" and
    normalizedPathOf(c).matches("%/copyparty/httpcli.py") and
    node = c and
    flowKind = "http_query" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "self.uparam" and
    moduleHint = "copyparty.httpcli" and
    matchKind = "ast"
  )
  or
  /* family 4b: query-string item reads: self.uparam[key] - the index
     carries the key. */
  exists(Subscript s, Attribute upar |
    upar = s.getObject().(Attribute) and
    upar.getName() = "uparam" and
    upar.getObject().(Name).getId() = "self" and
    normalizedPathOf(s).matches("%/copyparty/httpcli.py") and
    node = s and
    flowKind = "http_query" and
    callableName = "uparam" and
    argIndex = 0 and
    receiver = "self.uparam" and
    moduleHint = "copyparty.httpcli" and
    matchKind = "ast"
  )
  or
  /* family 5a: header reads: self.headers.get(key) - argument 0 carries
     the key. Header values are raw (no percent-decode); the path-bearing
     site is the WebDAV Destination header at :1197. */
  exists(Call c, Attribute func, Attribute hdr |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    hdr = func.getObject().(Attribute) and
    hdr.getName() = "headers" and
    hdr.getObject().(Name).getId() = "self" and
    normalizedPathOf(c).matches("%/copyparty/httpcli.py") and
    node = c and
    flowKind = "http_header" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "self.headers" and
    moduleHint = "copyparty.httpcli" and
    matchKind = "ast"
  )
  or
  /* family 5b: header item reads: self.headers[key] - the index carries
     the key. Sites include :1197 (destination), :1733/:2417
     (content-length). */
  exists(Subscript s, Attribute hdr |
    hdr = s.getObject().(Attribute) and
    hdr.getName() = "headers" and
    hdr.getObject().(Name).getId() = "self" and
    normalizedPathOf(s).matches("%/copyparty/httpcli.py") and
    node = s and
    flowKind = "http_header" and
    callableName = "headers" and
    argIndex = 0 and
    receiver = "self.headers" and
    moduleHint = "copyparty.httpcli" and
    matchKind = "ast"
  )
  or
  /* family 6: cookie reads: self.cookies.get(key) - cookies parsed from
     the cookie header at :359-:368 (values unescape_cookie-decoded). */
  exists(Call c, Attribute func, Attribute ck |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    ck = func.getObject().(Attribute) and
    ck.getName() = "cookies" and
    ck.getObject().(Name).getId() = "self" and
    normalizedPathOf(c).matches("%/copyparty/httpcli.py") and
    node = c and
    flowKind = "http_cookie" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "self.cookies" and
    moduleHint = "copyparty.httpcli" and
    matchKind = "ast"
  )
  or
  /* family 7a: the up2k handshake JSON body, resolved via API graphs:
     json.loads(...) - the POST body of handle_post_json (httpcli.py:1752,
     up to 1 MB of client JSON: name/hash/size/lmod/rand fields plus the
     delete/srch item arrays). The other in-package json.loads sites
     (:3006 broker IPC reply, cert.py:66, mtag.py:587, up2k.py:799
     registry file) are internal/file-derived and are included as rows for
     the labeling step to judge. Argument 0 is the JSON text. */
  exists(API::CallNode cn |
    cn = API::moduleImport("json").getMember("loads").getACall() and
    node = astCallOf(cn) and
    flowKind = "json_body" and
    callableName = "loads" and
    argIndex = 0 and
    receiver = "json" and
    moduleHint = "json" and
    matchKind = "api"
  )
  or
  /* family 7b: syntax-level fallback of the same json.loads family
     (module-qualified attribute calls; every use in this codebase is
     qualified `json.loads`). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "loads" and
    func.getObject().(Name).getId() = "json" and
    node = c and
    flowKind = "json_body" and
    callableName = "loads" and
    argIndex = 0 and
    receiver = "json" and
    moduleHint = "json" and
    matchKind = "ast"
  )
  or
  /* family 8: multipart form fields: self.parser.require(field_name,
     max_len) - argument 0 names the field whose raw string value is
     returned by the first-party MultipartParser (util.py:1268+).
     Path-bearing sites: mkdir 'name' (:2049), new-md 'name' (:2091),
     text-upload 'lastmod' (:2409). */
  exists(Call c, Attribute func, Attribute par |
    func = c.getFunc().(Attribute) and
    func.getName() = "require" and
    par = func.getObject().(Attribute) and
    par.getName() = "parser" and
    par.getObject().(Name).getId() = "self" and
    normalizedPathOf(c).matches("%/copyparty/httpcli.py") and
    node = c and
    flowKind = "form_field" and
    callableName = "require" and
    argIndex = 0 and
    receiver = "self.parser" and
    moduleHint = "copyparty.httpcli" and
    matchKind = "ast"
  )
  or
  /* family 9: the multipart body generator: self.parser.gen attribute
     reads - the generator yielding (field, filename, datafile) tuples;
     the client-supplied p_file filename is consumed at :2170-:2197
     (sanitize_fn basename-only, then ren_open(fname, "wb", fdir=fdir)
     at :2190 and os.path.join(fdir, fname) at :2197). */
  exists(Attribute a |
    a.getName() = "gen" and
    a.getObject().(Attribute).getName() = "parser" and
    a.getObject().(Attribute).getObject().(Name).getId() = "self" and
    normalizedPathOf(a).matches("%/copyparty/httpcli.py") and
    node = a and
    flowKind = "multipart_gen" and
    callableName = "gen" and
    argIndex = -1 and
    receiver = "self.parser" and
    moduleHint = "copyparty.httpcli" and
    matchKind = "ast"
  )
  or
  /* family 10: the FTP path boundary: the `vpath` parameter of FtpFs.v2a
     and FtpFs.rv2a (ftpd.py:142/:189) - the client-supplied FTP path
     string dispatched by pyftpdlib (external) into the filesystem layer.
     v2a backslash-normalizes, sanitize_fn-basenames the final component
     (:157), vfs.get-resolves (:160) and canonical-joins (:166/:176). */
  exists(Function f, Parameter p |
    normalizedPathOf(f).matches("%/copyparty/ftpd.py") and
    f.getName() in ["v2a", "rv2a"] and
    p = f.getAnArg() and
    p.getName() = "vpath" and
    node = p and
    flowKind = "ftp_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = "FtpFs" and
    moduleHint = "copyparty.ftpd" and
    matchKind = "ast"
  )
  or
  /* family 11: the FTP working-directory state: self.cwd attribute reads
     in ftpd.py - the CWD command target set by the FTP client, joined in
     rv2a via os.path.join(self.cwd, vpath) at :188. */
  exists(Attribute a |
    a.getName() = "cwd" and
    a.getObject().(Name).getId() = "self" and
    normalizedPathOf(a).matches("%/copyparty/ftpd.py") and
    node = a and
    flowKind = "ftp_cwd" and
    callableName = "cwd" and
    argIndex = -1 and
    receiver = "self" and
    moduleHint = "copyparty.ftpd" and
    matchKind = "ast"
  )
  or
  /* family 12: the SMB path boundary: the `vpath` parameter of any smbd.py
     function (_v2a :122, _listdir :133, _open :163) - the client-supplied
     SMB path string. _v2a resolves vfs.get(vpath, LEELOO_DALLAS, True,
     True) + canonical(rem); _open calls bos.open(ap, flags) at :185. */
  exists(Function f, Parameter p |
    normalizedPathOf(f).matches("%/copyparty/smbd.py") and
    p = f.getAnArg() and
    p.getName() = "vpath" and
    node = p and
    flowKind = "smb_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = f.getName() and
    moduleHint = "copyparty.smbd" and
    matchKind = "ast"
  )
  or
  /* family 13a: boot-time environment reads, resolved via API graphs:
     os.environ.get(...) - config/temp directory discovery in __main__.py
     (:148/:150/:151/:152/:202/:1148). Deployer trust level, NOT attacker
     input - kept for the labeling step to judge per the boundary rule.
     Argument 0 is the variable name. */
  exists(API::CallNode cn |
    cn = API::moduleImport("os").getMember("environ").getMember("get").getACall() and
    node = astCallOf(cn) and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "api"
  )
  or
  /* family 13b: syntax-level fallback of the same os.environ.get family
     (qualified os.environ.get(...) calls; all uses in this codebase are
     qualified). */
  exists(Call c, Attribute func, Attribute env |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    env = func.getObject().(Attribute) and
    env.getName() = "environ" and
    env.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  copypartySourcePath(normalizedPathOf(node))
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
