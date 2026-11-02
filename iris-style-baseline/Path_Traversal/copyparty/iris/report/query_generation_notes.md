# Pass 1 Query Generation Notes — copyparty (Path Traversal, CWE-22/23/36/73)

Augur Phase 2, Step 4–5. Records how the approved pass-1 labels
(`labels/labels.json`, 769 entries) were compiled into the CodeQL taint model
(`libraries/MySources.qll`, `MySinks.qll`, `MySanitizers.qll`, `MySummaries.qll`)
and the path query (`queries/Pass1_PathTraversal.ql`). Per the task contract,
**no compilation and no analysis were run** in this step.

## 0. Inputs, toolchain pinning, and process

- Labels basis: `labels/labels.json` (pass 1, reviewed in `labels/phase1_review.md`).
  `labels/review_decision.json` does **not exist** in the workspace (it was not
  created in Phase 1; the review record is `phase1_review.md`). The labels are
  treated as approved per the task statement; no label was modified.
- Template: `augur-0.3.0/assets/taint_query.ql.tmpl`, rendered with
  `{{QUERY_NAME}}`, `{{QUERY_ID}}` = `py/augur/copyparty/pass1-path-traversal`,
  `{{PRECISION}}` = medium, all four CWE tags, `{{PASS_KEY}}` = `path_traversal`,
  `{{CONFIG_NAME}}` = `Pass1Config`, `{{FLOW_MODULE}}` = `Pass1Flow`, and the
  Python import block from WORKFLOW.md 5.2.1a. The template's
  `import {{FLOW_MODULE}}::PathGraph` shape was kept verbatim.
- API surface pinned against the local pack cache (`codeql/python-all` 7.1.1 and
  7.1.2 under `~/.codeql/packages`, the same family the DB and sibling projects
  used): `DataFlow::Node.asExpr()` (member cast, `dataflow/new/internal/DataFlowPublic.qll:200/299`),
  `DataFlow::parameterNode(Parameter)` (`DataFlowPublic.qll:350`, re-exported
  through `module Public` in `DataFlowImplSpecific.qll` into `DataFlow`),
  `TaintTracking::Global<Config>` + `PathGraph`/`PathNode`/`flowPath`
  (`codeql/dataflow` shared framework, `DataFlow.qll:401` ConfigSig,
  `:792/:853` PathGraph modules). Python AST predicates used:
  `Call.getFunc()/getArg(int)`, `Attribute.getName()/getObject()`,
  `Subscript.getObject()`, `Name.getId()`, `Function.getName()/getAnArg()`,
  `Parameter.asName()`, `AstNode.getLocation().getFile().getShortName()`,
  `AstNode.getScope().(Function)` (Function extends Scope, `semmle/python/Function.qll:10`).
  No `API::Node` value is ever assigned to a `DataFlow::Node` variable; no
  `module` used as a variable name; no deprecated AST classes.
- Modeling policy: sources/sinks/barriers are anchored by
  **file + (function or receiver/attribute shape)** constraints derived from the
  verified source, never by line numbers, so the model survives harmless
  reformatting while staying inside the reviewed label set.
- Deviations from label roles (all conservative, none modify labels.json) are
  listed in §6 with reasons; none requires returning labels to Step 5 re-review
  — the labels themselves were not found to contain omissions that block
  modeling (see §6.7 for the one borderline case, the `vfs_get` summary family).

## 1. Label-ID → QLL predicate mapping

### MySources::isSource (label role=source, 195 tp entries → 5 rules)

| rule | labels | count | source-code evidence |
| --- | --- | --- | --- |
| `httpRequestLineOrPath` | http_path P1-S-0002..P1-S-0102; http_req P1-S-0001..P1-S-0088 | 72 + 23 | `self.req` split from the socket request line at httpcli.py:241; `self.vpath = unquotep(vpath)` at :375 (decode AFTER the pre-decode undot at :333/:337); boundary attributes of the HttpCli request state |
| `httpQueryHeaderCookieValue` | http_query P1-S-0116..; http_header P1-S-0104.. (incl. Destination @1197); http_cookie | 27 + 40 + 4 | query dict built at :330–:343 (per-key unquotep), raw headers at :243–:247, cookies at :359–:368; matched as `.get(...)` calls and `[...]` subscripts on `self.uparam/self.headers/self.cookies` |
| `httpFormOrMultipart` | form_field P1-S-0176..P1-S-0184; multipart_gen P1-S-0182..P1-S-0186 | 6 + 4 | `self.parser.require(...)` (mkdir/new-md `name`, `lastmod`) and `self.parser.gen` (client multipart filenames), MultipartParser at util.py:1268 |
| `up2kHandshakeJson` | json_body tp P1-S-0178 (httpcli.py:1752) | 1 | `json.loads(json_buf...)` of the ≤1 MB POST body in `handle_post_json` (:1745–:1754); restricted to that function — the other 4 json_body labels are none/fp (broker IPC :3006, cert.py:66, mtag.py:587, up2k.py:799) |
| `ftpBoundary` | ftp_param P1-S-0194/P1-S-0195 (v2a:144, rv2a:182); ftp_cwd source P1-S-0196..P1-S-0202 | 2 + 6 | pyftpdlib dispatches FTP command args into `FtpFs.v2a/rv2a`; `self.cwd` stored from raw CWD args at ftpd.py:239 and consumed at :188/:224/:255/:300/:313/:314 |
| `smbBoundary` | smb_param P1-S-0203..P1-S-0212 | 10 | SMB server callbacks `_v2a/_listdir/_open/_mkdir/_stat/_unlink/_utime/_p_exists/_p_getsize/_p_isdir` take the client path as `vpath` |

External input boundary and access conditions per source family (from the
labels' rationales): HTTP sources are reachable by **any unauthenticated
client** (per-volume read/write permissions are checked later, in `VFS.get`,
authsrv.py:476–486 — authorization limits *who*, not *what path*); the
up2k JSON/multipart/require sources additionally require write access to the
target volume (enforced inside the write handlers); FTP sources require an FTP
login with the corresponding per-volume r/w/m/d permissions via
`v2a(..., r/w/m/d)`; SMB sources are resolved **as the LEELOO_DALLAS
full-access builtin** (smbd.py:130) — per-user permissions are bypassed by
design on the SMB channel (CWE-073 context). The 3 `env` (none/fp) and 4
file-derived `json_body` (none/fp) labels are not modeled as sources.

### MySinks::isSink (label role=sink classification=tp, 159 entries → 10 rules)

| rule | labels | count | operation / dangerous arg / access type |
| --- | --- | --- | --- |
| `builtinOpen` | file_open tp: P1-K-0017 ftpd:221, K-0019 httpcli:1159, K-0024 :2110, K-0028 :2518, K-0035/:0036/:0038 :3595/:3603/:3878, K-0040 star:94, K-0054 util:1221, K-0057 util:2759 | 10 | `open()` arg 0 — file read (README/doc/tar-content/gzip-editions), write/create (LOCK create, new-md, text upload, fn-trunc). Callers: FtpFs.open, handle_lock, handle_new_md, handle_text_upload, tx_browser, StreamTar.ser, ren_open/gzip_orig_sz |
| `bosOpen` | bos_open tp: K-0029 httpcli:2615, K-0039 smbd:185 | 2 | `bos.open()` arg 0 — read (block-device size probe in tx_file; SMB file open via `_v2a`) |
| `fileServe` | file_serve tp: K-0018 :783, K-0032 :3509, K-0033 :3535 (tx_md), K-0034 :3537, K-0037 :3814 | 5 | `self.tx_file(p)/self.tx_md(p)` arg 0 — **file response**: tx_file stats (:2610), opens via dynamic `open_func = open` (:2772) and transfers with os.sendfile (:2773–:2775); tx_md streams via yieldfile (:2907/:2954) |
| `renOpen` | fs_open_wrapper tp: K-0020/:0021 httpcli:1519/:1561, K-0025/:0026 :2190/:2233, K-0048 up2k:2567, K-0050 up2k:3571 | 6 | `ren_open(fname)` arg 0 — **file create/write**: `os.path.join(fdir, fname)` + `fun(fsenc(fpath))` with `fun = open` (util.py:1204–:1216) |
| `yieldfileRead` | fs_read_wrapper tp: K-0030/:0031 httpcli:2907/:2954, K-0042/:0043 szip:250/:259 | 4 | `yieldfile(fn)` arg 0 — **content read** (markdown viewer; zip-download entries) via `open(fsenc(fn),"rb")` (util.py:2121) |
| `imageOpen` | image_open tp: K-0047 th_srv:355 | 1 | `Image.open()` arg 0 — read/decode of the thumbnail source (`abspath = os.path.join(ptop, rem)`, th_srv.py:197) |
| `kernSendfile` | fs_sendfile tp: K-0247 util:2200 | 1 | `os.sendfile()` arg 1 (in_fd) — content transfer; the fd is opened from the request path at httpcli.py:2772 |
| `statdirScandir` | fs_scandir tp: K-0248 util:2237 | 1 | `os.scandir()` arg 0 — directory listing read behind VFS.ls/walk/zipgen |
| `fsOperation` | fs_stat tp (34), fs_unlink tp (25), fs_rename tp (2: K-0124 httpcli:2489, K-0229 up2k:3437), fs_mkdir tp (16) | 77 | `bos./os.` `stat/lstat/unlink/rmdir/mkdir/makedirs` arg 0, `rename` arg **1** (destination) — metadata / delete / create / move. Files httpcli/ftpd/smbd/up2k (all tp-labeled there) + util restricted to `atomic_move` (K-0246 os.unlink, util.py:1963) |
| `pathMetadataProbe` | path_check tp (52) | 52 | `bos.path./os.path.` `exists/isfile/isdir/getsize/getmtime/lexists/islink` arg 0 — **weak sink** (existence/size oracle, no content); kept because the approved labels classify them role=sink (conf 0.55–0.6); files httpcli/ftpd/up2k + util upload-path helpers |

All sink anchors are the **path text** at the call argument (arg 0; rename dst
arg 1; sendfile in_fd arg 1); no already-opened file object is used as a sink
anchor. The 24 `candidate` sink labels (thumbnail/media pipeline metadata ops
in th_srv/th_cli/mtag/sutil, broker-IPC-fed opens at httpcli:1661/:1914, the
untraced `_hashlist_from_file` open) are **not** modeled — they were the §7
manual-review points of the Phase 1 review; the thumbnail channel remains
covered through the tp sinks `imageOpen` (th_srv:355) and the join/canonical
steps.

### MySanitizers::isBarrier (label role=sanitizer; 9 of 19 entries modeled as barriers)

| barrier | labels | why it provably blocks this traversal mechanism |
| --- | --- | --- |
| `soundUndotBarrier` | P1-K-0270 (authsrv:430, VFS._find recursion), P1-K-0271 (:439, can_access), P1-K-0272 (:473, **VFS.get** — the load-bearing guard), P1-K-0337 (httpcli:1765, undot on the JSON handshake name, '/' rejected at :1766), P1-K-0364 (httpcli:3167, tx_tree on decoded vpath) | `undot` (util.py:1673–:1686) splits on '/' and drops `''`, `'.'` and `'..'` segments (popping the parent). Applied to **decoded** (or never-encoded) values it provably removes literal dot-traversal; the barrier sits on the call result, so taint passing through undot's output is cut. Verified consequences: guarded channels (main download :3537, PUT/uploads, FTP v2a, SMB _v2a) resolve `rem` from `undot(vpath)` inside VFS.get, so no traversal survives into `canonical(rem)` on those channels. Caveat (does NOT block): backslash traversal on POSIX — undot splits on '/' only; that is stopped solely by the Windows-only `relchk` (httpcli.py:377–:383, authsrv.py:466–:471) |
| `sanitizeFnBarrier` | P1-K-0301 (ftpd:158), P1-K-0330 (httpcli:1473), P1-K-0343 (:2052), P1-K-0348 (:2101), P1-K-0353 (:2176), P1-K-0413 (up2k:2235) | `sanitize_fn(fn, '', bad)` with `ok=''` takes `fn.replace("\\","/").split("/")[-1]` (util.py:1691) — basename-only, **every** directory component removed, plus Windows devname/charset remap. Blocks both `../` and absolute-path injection in the filename channel |

Not emitted as barriers (label role sanitizer, but not provable as blanket
blocking — see §6): `chk_ap` (P1-K-0277/0304/0309/0319/0457), the pre-decode
`undot` at httpcli:333/:337 (P1-K-0315/0316, classification candidate), and
szip.py:109 `sanitize_fn` (P1-K-0392, ok='/' keeps separators).

### MySummaries::isAdditionalTaintStep (label role=summary; 4 step families)

| step | labels | evidence |
| --- | --- | --- |
| `urlDecodeStep` | http_url_decode 8× tp (P1-S-0011/0012/0049/0057/0064/0093/0095/0103) | `unquotep/unquote` at httpcli :341/:375/:1199/:1327/:1726/:3237/:3337/:3871 — percent-decode is taint-preserving |
| `pathJoinStep` | path_join 49 tp | `os.path.join` / `djoin` (util.py:1658) / `vjoin` — joins are two-sided (controlled component at any position: `join(E.mod,'web/',vpath[5:])` :782, `join(ptop, rem)` th_srv:197, `join(abspath, doc)` :3875, `join(fdir, fname)` util:1207), so taint flows from **every** argument to the result |
| `pathResolveStep` | path_resolve 23 tp | `os.path.split/dirname/normpath/abspath/realpath` — pure transforms (e.g. `fdir, fn = os.path.split(fdir)` httpcli:1400, `absreal` abspath+realpath util:1735/1743) with no Python body for default interprocedural flow, yet taint-preserving in reality |
| `vfsCanonicalStep` | vfs_canonical 25 tp | `VFS.canonical/dcanonical` (authsrv.py:498–:513): `realpath + '/' + rem` then `absreal`; without the step, taint dies inside `absreal`'s `os.path.realpath` and no guarded-channel flow could ever be explained |
| (not modeled) | vfs_get 29 tp | see §6.1 — the default interprocedural flow through `VFS.get`'s body **is** the propagation, and it is exactly where the undot barrier lives |

## 2. Root-directory / symlink / normalization-order evidence (encoded in the model)

- **Allowed root**: each volume's `realpath`; `canonical` is plain
  concatenation `realpath + '/' + rem` (authsrv.py:498–:504) — there is **no
  default containment** after canonicalization. Containment exists only as the
  opt-in `chk_ap` prefix+device check for `xdev`/`xvol` volumes
  (httpcli.py:424–:428, authsrv.py:705–:734) — this is why chk_ap is not a
  blanket barrier (§6.2).
- **Normalization order** (the core CWE-22 fact the model encodes): undot runs
  on the **raw encoded** path at httpcli:333/:337, percent-decode at :375, and
  the **second** undot on the decoded path only inside `VFS.get`
  (authsrv:473). Channels that resolve through `VFS.get` are therefore modeled
  as guarded (barrier cuts the flow); the `.cpr` static branch
  (httpcli.py:766–:783) slices `self.vpath[5:]` without the second undot and
  joins it onto `E.mod/web/` — the model intentionally leaves this channel
  unguarded (the pre-decode undot is not a barrier), so
  `source(self.vpath) → vpath[5:] → pathJoinStep(:782) → fileServe(:783)` is
  the **primary expected alert** of this query.
- **Symlinks / CWE-36**: `canonical` resolves symlinks at request time
  (`absreal` = abspath+realpath), `dcanonical` resolves only the parent
  directory leaving the final component unresolved at open time
  (authsrv.py:506–:513; used by LOCK :1117 and tx_browser :3431) — TOCTOU-shaped
  and recorded in the labels; no barrier models it (nothing provably blocks it
  out of band).
- **Write-side extra guard**: `_assert_safe_rem` (httpcli.py:197–:200) rejects
  `rem` starting with `/`, `../` or containing `/../` on the write paths only
  (:2058/:2096/:2148/:2415); it has no label row (not extracted) and no
  barrier is emitted for it — noted for Step 6 triage.

## 3. Expected alert behavior (pre-registered before any execution)

- **Expected TP candidate**: the `.cpr` static-resource read
  (httpcli.py:782/:783) as described above; the same channel may also surface
  on the weak `pathMetadataProbe`/`fs_stat` sinks inside `tx_file` (:2610).
- **Expected guard-limited alerts (triage as likely-FP in Step 6)**: `?doc=`
  viewer (:3875 join → :3878 open) — the listing-membership check at :3874
  whitelists `doc` to an existing basename, which taint tracking cannot see;
  and tx_md/tx_file flows whose `abspath` derives from `dcanonical(rem)` where
  `rem` is only reachable through barrier-cut paths.
- **Expected silent (guarded)**: main download :3537, PUT dump_to_file,
  MKCOL/new-md/plain/text uploads, up2k handshake destinations, FTP
  v2a/rv2a/`open`, SMB `_v2a/_open` — all resolve through `VFS.get`'s undot
  barrier plus `sanitize_fn`.

## 4. Dynamic dispatch / alias / CodeQL limitations

1. **Dynamic open dispatch**: `tx_file`'s `open_func(*open_args)`
   (httpcli.py:2772, `open_func = open`/`gzip.open` at :2728–:2733),
   `ren_open`'s `fun` kwarg (util.py:1176/1216) and `dump_to_file`'s
   `open_ka` overrides (:1447–:1451) are Name-variable calls no AST sink rule
   can match. The model compensates by anchoring sinks at the *call sites*
   (`fileServe`, `renOpen`) and, for the sendfile syscall, at
   `os.sendfile`'s fd argument.
2. **Broker IPC boundary**: `handle_rm`/`handle_mv`/`handle_chunk` cross into
   the up2k broker process (httpcli.py:3319/:3347/:1890) — no fabricated
   cross-process taint edges; up2k-side `_handle_rm`/`handle_mv`/`handle_json`
   entry params are therefore unreachable from the HTTP sources in this DB
   (their labels are summaries/candidates and were not promoted to sources —
   correctly, per the "internal param is not a Source" rule).
3. **Method-call resolution**: `self.asrv.vfs.get(...)`,
   `self.hub.asrv.vfs.get(...)` interprocedural dispatch depends on the
   library's receiver-type inference. If dispatch fails, guarded channels stay
   silent (correct outcome) and the `.cpr` channel is unaffected (it never
   calls vfs.get) — the model degrades safely either way.
4. **fsenc/encode wrappers**: sinks wrapped as `open(fsenc(ap), ...)` rely on
   the default taint step through `fsenc`'s body (str encode). The primary
   channels (`.cpr`, tx_file call sites, yieldfile call sites, ren_open call
   sites) do not depend on this.
5. **Attribute store→load flow** (`self.vpath = ...` then reads): if the
   library does not model attribute store-to-load flow intraprocedurally, the
   read-side sources (`self.vpath` loads) still anchor the taint directly, so
   recall does not depend on it.

## 5. Diagnostics (not part of the formal Pass 1 results)

If wrapper wiring needs debugging before Step 5, write separate
non-`path-problem` diagnostics queries (e.g. `@kind table` selects counting
`MySources::isSource`/`MySinks::isSink`/barrier matches per file, and a
`DataFlow::Global<Pass1Config>` local-flow probe for `vfs.get` dispatch).
These must not be counted as Pass 1 alerts. Candidate-classified sink sites
(§1 sink table) can also be attached to a diagnostics-only sink predicate to
check whether the thumbnail/pipeline channels ever see taint.

## 6. Documented deviations from label roles (no label was modified)

1. **`vfs_get` (29 summary tp) — no additional step emitted.** An explicit
   `arg → result` edge for `vfs.get` would bypass `VFS.get`'s body, where the
   load-bearing undot barrier (authsrv:473) lives, and would flag **every**
   legitimate file download (the download path is always
   attacker-chosen-but-guarded). The default interprocedural flow provides the
   label's intended propagation while respecting the barrier. Modeled
   semantics match the label rationale ("rem is the attacker-chosen
   post-undot relative path"); the mechanism differs (default flow instead of
   an additional edge).
2. **`vfs_chk_ap` (4 tp + def row) — no barrier.** Prefix containment
   (`aps.startswith(vap)`) + device check only runs for volumes with
   `xdev`/`xvol` flags; default volumes have no post-canonical containment,
   so a blanket barrier cannot be proven to block traversal. Sanitizer role
   acknowledged in the notes; barrier intentionally omitted per the
   "sanitizers need concrete proof" contract.
3. **Pre-decode undot at httpcli:333/:337 (2 sanitizer candidate labels) — no
   barrier**, matching their `candidate` classification: unsound against
   percent-encoded traversal (decode at :375 happens after).
4. **szip.py:109 `sanitize_fn` (tp 0.6) — no barrier**: called with `ok='/'`
   which keeps separators; it sanitizes archive entry names, not fs paths.
5. **ftp_cwd:239 store (summary label)**: the `self.cwd` attribute rule
   matches loads; if store-target Attribute nodes bind via `asExpr()`, the
   :239 store in `chdir` may co-match. Same attacker data (raw CWD path),
   harmless direction; the :132 `__init__` constant store is excluded by the
   `!= "__init__"` guard.
6. **24 candidate-classified sink labels deferred** to diagnostics (§1, §5) —
   they were Phase 1 manual-review points with unresolved provenance (IPC
   hops, untraced params, pipeline paths).
7. **No label omissions found requiring Step 5 re-review**: every modeled rule
   maps onto reviewed tp entries; the only families whose *mechanism* had to
   be re-interpreted rather than dropped are `vfs_get` (§6.1) and `chk_ap`
   (§6.2), both documented above.

## 7. Experimental independence

No PyVul ground truth (VULNERABILITY_AUDIT_REPORT.md, enhanced_path_sinks.csv,
path_traversal_sinks.csv, tests/), no CVE data and no fix patches were read.
The source tree, CodeQL database, Augur installation and the Phase 1 label
artifacts were not modified; the only files written are the six Phase 2
artifacts listed in the task. All evidence cited in this report comes from
first-hand reading of the copyparty package during Phase 1/2 of this
experiment.

## 8. Files produced (this step)

1. `iris/libraries/MySources.qll`
2. `iris/libraries/MySinks.qll`
3. `iris/libraries/MySanitizers.qll`
4. `iris/libraries/MySummaries.qll`
5. `iris/queries/Pass1_PathTraversal.ql`
6. `iris/report/query_generation_notes.md`

## 9. Post-generation compile record (added after the user ran the check)

The generation contract for this step was "generate only, do not compile";
the user then ran `codeql query compile --check-only`, which exposed one
defect that has been fixed in place:

- **Root cause**: `MySummaries.qll` used `from`/`to` as parameter names
  (`isAdditionalTaintStep(DataFlow::Node from, DataFlow::Node to, ...)`).
  `from` is a reserved QL keyword (query-clause head), so the parser failed at
  MySummaries.qll:57 and every subsequent "library modules cannot contain
  query clauses / select clause conflicts / predicate to() conflicts" message
  was cascade noise from that single token. The template itself uses
  `nodeFrom`/`nodeTo`; the deviation from the template naming was the bug.
- **Fix**: renamed the parameters and all call sites to
  `nodeFrom`/`nodeTo` in `MySummaries.qll` (no semantic change), and removed
  the (then-flagged) unused private helper `funcIs` from
  `MySanitizers.qll`.
- **Result**: `codeql query compile --check-only queries/Pass1_PathTraversal.ql`
  now completes with **zero errors and zero warnings** against the local
  toolchain (CodeQL CLI on this machine + `codeql/python-all` resolved from
  the pack cache). The API surface pinned in section 0
  (`DataFlow::Node.asExpr()`, `DataFlow::parameterNode()`, `Function.getAnArg()`,
  `AstNode.getScope().(Function)` casts, the `import Pass1Flow::PathGraph`
  shape and the `ConfigSig` signatures) all type-checked as predicted.

No model semantics changed: sources, sinks, barriers and summary steps are
exactly as documented in sections 1-6. The next step remains
`codeql database analyze` (Step 5 execution) against `copyparty-db`.
