/**
 * @name copyparty CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the copyparty
 *   CodeQL database (copyparty 1.8.1 "argon", snapshot sha 8f59afb, a
 *   framework-less multi-protocol file server): the real file operations -
 *   builtin open() (httpcli.py:1159 WebDAV LOCK create, :2110 new-md,
 *   :2518 text-upload write, :3604 README read, :3874 ?doc= read, ftpd.py:221
 *   FtpFs.open, th_srv.py:210/:302, up2k.py:3493, util.py:1221 ren_open
 *   internal, :2121 yieldfile - the zip-download read), the first-party bos
 *   fs API (bos.open at httpcli.py:2615/smbd.py:185, bos.stat ~30 sites,
 *   bos.unlink ~15 (up2k.py:2925 delete channel), bos.rename, bos.mkdir/
 *   bos.makedirs), the os-level syscalls (os.sendfile util.py:2200 - the
 *   file-data-to-socket syscall of tx_file, os.scandir util.py:2237 in
 *   statdir behind VFS.ls/walk/zipgen, os.unlink), and PIL Image.open
 *   (th_srv.py:355, fed by os.path.join(ptop, rem) at :197 with no
 *   undot/relchk/assert_safe_rem on that join); the internal wrappers that
 *   actually touch files (ren_open util.py:1173 atomic create with
 *   os.path.join(fdir, fname) at :1207, yieldfile util.py:2120 streaming
 *   read, tx_file/tx_md httpcli.py:2597/:2889 - the HTTP file-serving
 *   response wrappers); the VFS path-resolution core (vfs.get - 31 sites,
 *   canonical/dcanonical - the realpath+'/'+rem construction at
 *   authsrv.py:498-:513 with absreal abspath+realpath symlink resolution,
 *   chk_ap - the opt-in xdev/xvol prefix containment at authsrv.py:705);
 *   the os.path propagation/validation pipeline (join - api+ast rows over
 *   ~38 sites incl. httpcli.py:782 static resources and th_srv.py:197,
 *   isfile/isdir/exists/getsize existence checks, abspath/realpath/dirname/
 *   split resolution); the undot/sanitize_fn sanitizers as path_sanitize
 *   rows; and internal wrapper functions whose body directly performs a
 *   filesystem operation (tx_file, dump_to_file, handle_plain_upload,
 *   handle_text_upload, handle_new_md, _mkdir, FtpFs.open/mkdir/rmdir/
 *   remove/rename/stat, smbd _v2a/_open/_listdir, th_srv get/worker/
 *   conv_pil, VFS.ls/walk/zipgen, util ren_open/yieldfile/statdir/
 *   sendfile_kern/sendfile_py, the up2k bos.* cluster, szip ser/gen).
 *   flow_kind marks each row as a real file operation (file_open, bos_open,
 *   fs_stat, fs_unlink, fs_rename, fs_mkdir, fs_sendfile, fs_scandir,
 *   image_open, fs_open_wrapper, fs_read_wrapper, file_serve), a path
 *   resolution/validation node (vfs_canonical, vfs_get, vfs_chk_ap,
 *   path_join, path_check, path_resolve, path_sanitize) or an internal
 *   wrapper definition (internal_file_wrapper); only the rows that actually
 *   access the filesystem with a controlled path argument are expected to
 *   label as sinks - the propagation rows are candidates for summary/
 *   sanitizer labels. Raw BQRS extraction query: run with `codeql query
 *   run` and decode with `codeql bqrs decode` (not database analyze). This
 *   is a plain multi-column select query on purpose: the problem query
 *   kind is the wrong shape for candidate tables and no table kind is
 *   assumed to exist.
 * @id iris/copyparty/extraction/sinks
 * @tags path-traversal
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql and to the prior IRIS manual
 * projects aiohttp/airflow/ansible/coderedcms):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or attribute name)
 *   4. flow_kind  - see the @description: real fs operations (file_open,
 *                   bos_open, fs_stat, fs_unlink, fs_rename, fs_mkdir,
 *                   fs_sendfile, fs_scandir, image_open, fs_open_wrapper,
 *                   fs_read_wrapper, file_serve), VFS/os.path propagation
 *                   and validation nodes (vfs_canonical, vfs_get,
 *                   vfs_chk_ap, path_join, path_check, path_resolve,
 *                   path_sanitize), internal wrapper definitions
 *                   (internal_file_wrapper)
 *   5. receiver   - syntactic receiver hint ("os", "os.path", "bos",
 *                   "bos.path", "Image", "vfs", the receiver base name for
 *                   method calls, "" when none; the enclosing function name
 *                   for parameterless wrapper rows)
 *   6. moduleHint - module hint: external module name (os.path, os, PIL,
 *                   builtin), the first-party module providing the wrapper
 *                   ("copyparty.bos" for bos.*, "copyparty.util" for
 *                   ren_open/yieldfile), or the dotted python module path of
 *                   the containing module (variable intentionally named
 *                   moduleHint; `module` is not a valid QL variable name
 *                   here)
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (1 for fs_rename dst - src sits at 0; 1 for
 *                   fs_sendfile in_fd; -1 when the path is the receiver or
 *                   for wrapper rows)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Scope: real filesystem operations (open/create/read/write/remove/rename/
 * directory ops, file-serving) plus the VFS/os.path propagation and
 * validation nodes that carry the controlled path values toward them. Every
 * row points at a call/attribute/function actually present in the code - the
 * propagation families exist so the labeling step can mark summary steps and
 * sanitizers, not to inflate sink counts. The os.path.join family resolves
 * both via API graphs (alias-aware, API::moduleImport("os").getMember("path")
 * .getMember("join").getACall() - this also covers the os.path.join inside
 * the first-party djoin wrapper at util.py:1658) and via the qualified
 * os.path.join syntax shape (all uses in this codebase are qualified; `from
 * os import path` does not occur); the same call site can legitimately yield
 * one api and one ast row (identical to the airflow/coderedcms projects of
 * this series).
 *
 * Note on bos: copyparty/bos/ is FIRST-PARTY code (the project's own
 * windows-safe filesystem abstraction over os/os.path), so bos.* calls are
 * matched at AST level as real fs operations, not as an external API graph.
 *
 * Note: this file defines no QL classes (only predicates/functions), does not
 * assign API::Node values to DataFlow::Node variables, and keeps resolved-API
 * matching strictly separate from AST syntax matching (the match_kind column
 * records which one produced a row).
 *
 * Scope (applied to every row): %/copyparty_vuln/copyparty/% (the shipped
 * copyparty package), EXCLUDING the nested %/copyparty-db/% database
 * directory (also outside the positive scope by construction) and
 * %/copyparty/stolen/% (vendored third-party code). Root setup.py, tests/,
 * scripts/, bin/, contrib/, docs/ and srv/ are outside the positive scope.
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
/* Sink family tables                                                  */
/* ------------------------------------------------------------------ */

/**
 * os.path members observed in this codebase, classified as propagation
 * (join), validation/check (isfile/isdir/exists/lexists/getsize/getmtime/
 * splitext/basename) or resolution (abspath/realpath/dirname/split/
 * normpath) nodes. None of them is a file access by itself; they carry and
 * transform the controlled path values (httpcli.py:782 joins the request
 * path onto the web-asset root; :2105/:2197/:2428 join upload destinations;
 * th_srv.py:197 joins the thumbnail remainder onto the volume realpath;
 * ftpd.py:152/:176/:188 join FTP paths). The bos.path.<member> forms
 * (first-party wrapper, ~69 sites) and os.path.<member> forms (~250 sites)
 * are both matched at AST level.
 */
private predicate osPathMemberKind(string member, string flowKind) {
  member = "join" and flowKind = "path_join"
  or
  member in ["isfile", "isdir", "exists", "lexists", "getsize", "getmtime", "splitext", "basename"] and
  flowKind = "path_check"
  or
  member in ["abspath", "realpath", "dirname", "split", "normpath"] and
  flowKind = "path_resolve"
}

/**
 * Holds if func is the callee attribute of a call whose receiver is the
 * os.path module prefix (os.path.<member>(...)) - the qualified syntax
 * shape used everywhere in this codebase.
 */
private predicate osPathCallFunc(Attribute func, Attribute pathmod) {
  pathmod = func.getObject().(Attribute) and
  pathmod.getName() = "path" and
  pathmod.getObject().(Name).getId() = "os"
}

/**
 * Holds if func is the callee attribute of a call whose receiver is the
 * bos.path module prefix (bos.path.<member>(...) - the first-party
 * windows-safe wrapper, httpcli, up2k, mtag, th_srv, th_cli, ftpd, smbd,
 * u2idx).
 */
private predicate bosPathCallFunc(Attribute func, Attribute pathmod) {
  pathmod = func.getObject().(Attribute) and
  pathmod.getName() = "path" and
  pathmod.getObject().(Name).getId() = "bos"
}

/**
 * bos module members that directly perform a filesystem operation on their
 * path argument (index 0; rename: src 0 / dst 1). The bos module is
 * first-party (copyparty/bos/bos.py:19-:70: chmod/listdir/makedirs/mkdir/
 * open/rename/replace/rmdir/stat/unlink/utime wrapping os with long-path
 * handling), so these are real fs operation rows, not an external API.
 */
private predicate bosMemberKind(string member, string flowKind) {
  member = "open" and flowKind = "bos_open"
  or
  member = "stat" and flowKind = "fs_stat"
  or
  member in ["unlink", "rmdir", "replace"] and flowKind = "fs_unlink"
  or
  member = "rename" and flowKind = "fs_rename"
  or
  member in ["mkdir", "makedirs"] and flowKind = "fs_mkdir"
}

/**
 * Holds if c is a call site that directly performs a filesystem operation
 * (used for the internal_file_wrapper family): builtin open, the bos
 * fs-op members, the bos.path/os.path existence checks, the os-level
 * syscalls (os.scandir/os.sendfile/os.unlink), PIL Image.open, the
 * first-party ren_open/yieldfile/statdir wrappers and the tx_file/tx_md
 * file-serving wrappers. Pure string operations (os.path join/splitext/
 * dirname/abspath/basename, djoin, undot, sanitize_fn, canonical) and the
 * permission-only vfs.get deliberately do NOT count - a wrapper row
 * requires a direct file access in the body.
 */
private predicate fileOpCallSite(Call c) {
  c.getFunc().(Name).getId() = "open"
  or
  c.getFunc().(Name).getId() in ["ren_open", "yieldfile", "statdir", "tx_file", "tx_md"]
  or
  exists(Attribute func, string boskind |
    func = c.getFunc().(Attribute) and
    bosMemberKind(func.getName(), boskind) and
    func.getObject().(Name).getId() = "bos"
  )
  or
  exists(Attribute func, Attribute pathmod |
    func = c.getFunc().(Attribute) and
    func.getName() in ["isfile", "isdir", "exists", "lexists"] and
    (osPathCallFunc(func, pathmod) or bosPathCallFunc(func, pathmod))
  )
  or
  exists(Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["scandir", "sendfile", "unlink"] and
    func.getObject().(Name).getId() = "os"
  )
  or
  exists(Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "Image"
  )
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 0: builtin open() - bare-name calls across the package. Key
     sites: httpcli.py:1159 (WebDAV LOCK create, dcanonical-fed), :1661,
     :2110 (new-md create, canonical+join-fed), :2374, :2518 (text-upload
     write, canonical+join-fed), :3604 (README read), :3874 (?doc= read,
     os.path.join(abspath, doc) with the unquotep-decoded query value),
     ftpd.py:221 (FtpFs.open, v2a-fed), th_srv.py:210/:302, up2k.py:3493,
     util.py:1221 (ren_open internal), :2121 (yieldfile - the zip download
     content read). The path is argument 0. Note: tx_file's open at
     httpcli.py:2772 is a DYNAMIC call (open_func = open at :2733) and is
     deliberately not matched here - see the file_serve family and the
     wrapper rows. */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtin" and
    matchKind = "ast"
  )
  or
  /* family 1: the first-party bos fs API: bos.<member>(...) - bos.open
     (httpcli.py:2615 O_RDONLY block-device probe, smbd.py:185 the SMB
     file open), bos.stat (~30 sites: tx_file :2610, up2k dupe checks,
     th_srv :235), bos.unlink (~15 sites: upload rollback httpcli :2254/
     :2255, up2k.py:2925 the delete channel), bos.rename (httpcli :2489
     .hist archival), bos.mkdir/bos.makedirs (:1403/:2071/:2159, th_srv
     :206). The path is argument 0 (rename: dst at 1, src at 0). */
  exists(Call c, Attribute func, string member |
    func = c.getFunc().(Attribute) and
    func.getObject().(Name).getId() = "bos" and
    bosMemberKind(func.getName(), flowKind) and
    member = func.getName() and
    node = c and
    callableName = member and
    (
      member = "rename" and argIndex = 1
      or
      member != "rename" and argIndex = 0
    ) and
    receiver = "bos" and
    moduleHint = "copyparty.bos" and
    matchKind = "ast"
  )
  or
  /* family 2: os-level fs syscalls: os.scandir (util.py:2237 inside
     statdir - the directory-listing read behind VFS.ls/walk/zipgen;
     httpsrv.py:475 web assets), os.sendfile (util.py:2200 inside
     sendfile_kern - the file-data-to-socket syscall of tx_file; in_fd is
     argument 1), os.unlink (th_srv.py:307). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getObject().(Name).getId() = "os" and
    func.getName() in ["scandir", "sendfile", "unlink"] and
    node = c and
    callableName = func.getName() and
    (
      func.getName() = "sendfile" and flowKind = "fs_sendfile" and argIndex = 1
      or
      func.getName() = "scandir" and flowKind = "fs_scandir" and argIndex = 0
      or
      func.getName() = "unlink" and flowKind = "fs_unlink" and argIndex = 0
    ) and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 3: PIL image file access: Image.open(fsenc(abspath)) at
     th_srv.py:355 - reads the thumbnail source whose abspath was built at
     :197 as os.path.join(ptop, rem) with rem = the thumbnail-request
     vrem from httpcli.py:3506 (no undot/relchk/_assert_safe_rem on that
     join). The path is argument 0. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "Image" and
    node = c and
    flowKind = "image_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "Image" and
    moduleHint = "PIL" and
    matchKind = "ast"
  )
  or
  /* family 4a: os.path.join resolved via API graphs (alias-aware) - also
     covers the join inside the first-party djoin wrapper (util.py:1658).
     Sites: httpcli.py:782 (static resources from the request path),
     :2105, :2197, :2224-:2235, :2428, :3487/:3495, :3587, :3602,
     th_srv.py:197/:208/:285, ftpd.py:152/:176/:188, up2k.py (36 sites),
     util.py (17 sites). Argument 0 carries the base; the controlled
     component may sit at any index - labeling must treat join as
     taint-preserving for ALL arguments. */
  exists(API::CallNode cn |
    cn = API::moduleImport("os").getMember("path").getMember("join").getACall() and
    node = astCallOf(cn) and
    flowKind = "path_join" and
    callableName = "join" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "api"
  )
  or
  /* family 4b: os.path member calls, qualified syntax shape
     (os.path.<member>(...)). join rows share the api rows' sites; the
     check/resolve members (isfile/isdir/exists/lexists/getsize/getmtime/
     splitext/basename; abspath/realpath/dirname/split/normpath) are
     ast-only rows - the existence checks are the TOCTOU-relevant stat
     probes (tx_file :2607-:2610 stat before the :2772 open). */
  exists(Call c, Attribute func, Attribute pathmod |
    func = c.getFunc().(Attribute) and
    osPathMemberKind(func.getName(), flowKind) and
    osPathCallFunc(func, pathmod) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 4c: bos.path member calls (bos.path.<member>(...) - the
     first-party windows-safe wrapper over os.path; ~69 sites across
     httpcli, up2k, mtag, th_srv, th_cli, ftpd, smbd, u2idx). Same
     member classification; argument 0. */
  exists(Call c, Attribute func, Attribute pathmod |
    func = c.getFunc().(Attribute) and
    osPathMemberKind(func.getName(), flowKind) and
    bosPathCallFunc(func, pathmod) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "bos.path" and
    moduleHint = "copyparty.bos" and
    matchKind = "ast"
  )
  or
  /* family 5: the VFS path-resolution core: <vfs>.canonical(rem) /
     dcanonical(rem) method calls - THE path construction node
     (authsrv.py:498-:513: ap = self.realpath + "/" + rem, then absreal
     abspath+realpath for canonical / parent-only resolution for
     dcanonical - TOCTOU-shaped). Sites: httpcli.py:425 (the central
     request resolution), :609, :874, :1117, :1336, :1392, :1784, :2017,
     :2059, :2104, :2152, :2422, :3264, :3431, ftpd.py:166/:226/:427,
     smbd.py:131, authsrv.py:525 (VFS.ls). Argument 0 is the attacker
     path remainder. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["canonical", "dcanonical"] and
    node = c and
    flowKind = "vfs_canonical" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "vfs" and
    moduleHint = "copyparty.authsrv" and
    matchKind = "ast"
  )
  or
  /* family 6: the VFS vpath resolution: <vfs>.get(vpath, ...) method
     calls - resolves the decoded URL path into a volume node + fs
     remainder (authsrv.py:454-:487: relchk under ANYWIN, undot at :473 -
     the SECOND dot-filter that neutralizes decoded '..' - then per-user
     permission checks). 31 sites: httpcli.py:423 plus 13 more (:873,
     :1200, :1389, :1769, :2057, :2095, :2147, :2414, :3812...),
     up2k.py:7, ftpd.py:3, smbd.py:4, authsrv.py:3. Argument 0 is the
     vpath. */
  exists(Call c, Attribute func, Attribute vobj |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    vobj = func.getObject().(Attribute) and
    vobj.getName() = "vfs" and
    node = c and
    flowKind = "vfs_get" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "vfs" and
    moduleHint = "copyparty.authsrv" and
    matchKind = "ast"
  )
  or
  /* family 7: the opt-in containment check: chk_ap(ap) method calls
     (authsrv.py:705-:734: prefix-match aps.startswith(vap) + device-id
     equality, ONLY for volumes with the xdev/xvol flags). Sites:
     httpcli.py:426, ftpd.py:168, authsrv internal. Argument 0 is the
     absolute path to validate. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "chk_ap" and
    node = c and
    flowKind = "vfs_chk_ap" and
    callableName = "chk_ap" and
    argIndex = 0 and
    receiver = "vfs" and
    moduleHint = "copyparty.authsrv" and
    matchKind = "ast"
  )
  or
  /* family 8: the sanitizer family as candidate rows for labeling:
     undot(...) bare-name calls (util.py:1673 - the '..'/'.'/''
     segment filter; httpcli.py:333/:337 BEFORE percent-decode, :1765,
     :3167, authsrv.py:473 inside vfs.get - AFTER decode) and
     sanitize_fn(...) bare-name calls (util.py:1689 - basename-only when
     ok='' plus windows remapping; httpcli.py:2177/:2052/:2101,
     up2k.py:2235, ftpd.py:157). Argument 0 is the filtered value. */
  exists(Call c |
    c.getFunc().(Name).getId() in ["undot", "sanitize_fn"] and
    node = c and
    flowKind = "path_sanitize" and
    callableName = c.getFunc().(Name).getId() and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "copyparty.util" and
    matchKind = "ast"
  )
  or
  /* family 9: the atomic-create wrapper: ren_open(fname, ...) bare-name
     calls (util.py:1173 - resolves os.path.join(fdir, fname) at :1207
     and opens via the dynamic fun=open at :1216). Sites:
     httpcli.py:1519/:1561 (PUT dump_to_file), :2190 (plain-upload
     destination reservation with the multipart filename), :2233 (chunk
     write). Argument 0 is the filename. */
  exists(Call c |
    c.getFunc().(Name).getId() = "ren_open" and
    node = c and
    flowKind = "fs_open_wrapper" and
    callableName = "ren_open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "copyparty.util" and
    matchKind = "ast"
  )
  or
  /* family 10: the streaming-read wrapper: yieldfile(fn) bare-name
     calls (util.py:2120-:2127: open(fsenc(fn), "rb")). Site: szip.py:259
     - the zip-download content read of the f["ap"] paths produced by
     VFS.zipgen. Argument 0 is the path. */
  exists(Call c |
    c.getFunc().(Name).getId() = "yieldfile" and
    node = c and
    flowKind = "fs_read_wrapper" and
    callableName = "yieldfile" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "copyparty.util" and
    matchKind = "ast"
  )
  or
  /* family 11: the HTTP file-serving response wrappers: tx_file(...) /
     tx_md(...) method calls - the read side of the server (tx_file body:
     bos.stat at :2610, bos.open at :2615, the req_path+'.gz'/'.br'
     edition concat at :2607-:2610, the DYNAMIC open_func(*open_args) at
     :2772, sendfile_kern/sendfile_py at :2773-:2775). Sites:
     httpcli.py:783 (static resources, request-path-fed), :3509
     (thumbnail artifact), :3535 (tx_md markdown viewer), :3537
     (tx_file(abspath) - THE file download), :3814 (index.html resolve).
     Argument 0 is the path to serve. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["tx_file", "tx_md"] and
    node = c and
    flowKind = "file_serve" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "self" and
    moduleHint = "copyparty.httpcli" and
    matchKind = "ast"
  )
  or
  /* family 12: internal functions that directly perform a filesystem
     operation: expected members include HttpCli.tx_file (:2597),
     dump_to_file (:1386), handle_plain_upload (:2144),
     handle_text_upload (:2406), handle_new_md (:2089), _mkdir (:2055),
     the lock handler, FtpFs.open/mkdir/rmdir/remove/rename/stat/v2a
     (ftpd.py), smbd _v2a/_open/_listdir, th_srv get/worker/conv_pil,
     VFS.ls/walk/zipgen (authsrv.py, via statdir), util
     ren_open/yieldfile/statdir/sendfile_kern/sendfile_py, the up2k
     bos.* cluster and szip StreamZip.ser/gen (via yieldfile). Module-
     level code has no enclosing Function and yields no row. */
  exists(Function f |
    exists(Call c |
      fileOpCallSite(c) and
      c.getScope().(Function) = f
    ) and
    node = f and
    flowKind = "internal_file_wrapper" and
    callableName = f.getName() and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    receiver = f.getName()
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  copypartySourcePath(normalizedPathOf(node))
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
