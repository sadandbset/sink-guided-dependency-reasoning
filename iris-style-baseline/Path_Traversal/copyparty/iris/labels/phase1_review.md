# Phase 1 Review — copyparty, Pass 1 (Path Traversal, CWE-22/23/36/73)

Human review gate for Augur Step 3 (LLM candidate labeling). This document summarizes
`labels/labels.json` for approval before Phase 2. No Phase 2 work (library generation,
taint queries, analysis) has been performed.

## 1. Scope and method

- Target: copyparty 1.8.1 "argon" (source tree `copyparty_vuln/copyparty/`, 22079 LOC), CodeQL DB `copyparty-db` (CLI 2.25.1, sha 8f59afb).
- Pass 1 focus: Path Traversal (CWE-022/023/0036/0073).
- Candidates: `extraction/sources.csv` (225 rows) + `extraction/sinks.csv` (646 rows) = 871 rows.
- LLM labeling was performed **by the in-session model itself** (glm-5.3, via Claude Code CLI — no external LLM API calls), in **8 batches** (s1–s4 source families, k1–k4 sink families), after first-hand source reading of httpcli.py, authsrv.py, util.py, up2k.py, ftpd.py, smbd.py, th_srv.py, star.py, szip.py, __main__.py and bos/.
- Dedup: key `(file, line, callable, flowKind, argIndex, receiver)` → **769 unique entries**; 95 api/ast double rows merged, 7 exact duplicate rows dropped. Every one of the 871 input rows has exactly one disposition recorded in `labels_raw_pass1.json` (labeled / merged_into / duplicate).
- `labels.json` validates against `augur-0.3.0/assets/labels_schema.json` (jsonschema 4.26.0, draft 2020-12): **SCHEMA OK**.
- Independence: no ground truth (VULNERABILITY_AUDIT_REPORT.md, enhanced_path_sinks.csv, path_traversal_sinks.csv, tests/), no patch diffs, no CVE data were consulted; only the copyparty package sources. No source, DB, Augur or Phase 1 CSV files were modified.

## 2. Label counts (769 entries)

| role | tp | candidate | fp | total |
| --- | --- | --- | --- | --- |
| source | 195 | 0 | 0 | 195 |
| sink | 159 | 24 | 0 | 183 |
| sanitizer | 17 | 2 | 0 | 19 |
| summary | 196 | 13 | 0 | 209 |
| none | 0 | 0 | 163 | 163 |
| **total** | **567** | **39** | **163** | **769** |

- 37 entries below the 0.55 confidence threshold (see `label_stats.md`); all are retained as `candidate` with manual-review notes rather than re-asked, because the residual uncertainty is structural (cross-process broker IPC hops, pipeline second-order paths) rather than something a re-ask would resolve.

## 3. Top high-risk sink APIs (confidence ≥ 0.8)

| site | callable | conf | note |
| --- | --- | --- | --- |
| httpcli.py:783 | `tx_file` (file_serve) | 0.95 | **.cpr static-resource read — the unguarded channel** (see §6) |
| httpcli.py:3537 | `tx_file` (file_serve) | 0.90 | main file download (abspath from canonical of post-undot rem) |
| httpcli.py:2615 | `open` (bos_open) | 0.85 | tx_file block-device probe on request path |
| ftpd.py:221 | `open` (FtpFs.open) | 0.85 | FTP file open funnel via v2a |
| smbd.py:185 | `open` (bos.open) | 0.85 | SMB file open via _v2a |
| httpcli.py:1519/1561/2190/2233, up2k.py:2567/3571 | `ren_open` | 0.80 | atomic file-create (upload write channels) |
| httpcli.py:2907/2954, szip.py:250/259 | `yieldfile` | 0.80 | streaming content read (tx_md, zip download) |
| httpcli.py:3535 | `tx_md` | 0.80 | markdown viewer content stream |
| star.py:94 | `open` | 0.80 | tar-download content read (zipgen `ap` paths) |
| th_srv.py:355 | `Image.open` | 0.80 | thumbnail source read (`join(ptop, rem)` at th_srv.py:197) |
| httpcli.py:1159 | `open` | 0.80 | WebDAV LOCK file create (dcanonical-fed) |
| ftpd.py:252/291, smbd.py:237/249 | `makedirs`/`rmdir`/`mkdir` | 0.80 | FTP/SMB dir create/delete funnels |
| util.py:2200 | `os.sendfile` | 0.80 | file-content-to-socket syscall of tx_file |

## 4. Top broad source APIs

- `self.vpath` reads (http_path, 72 entries, conf 0.90/0.95) — the percent-decoded URL path; the single most load-bearing attacker value (116 references in httpcli.py).
- `self.headers` / `self.uparam` / `self.cookies` reads (40/27/4 entries, conf 0.70–0.90) — raw headers (Destination at :1197 is path-bearing), decoded query params (move/doc/th are path-bearing), cookies.
- `self.req` reads (23 entries, conf 0.85) — raw request line; origin of vpath/uparam.
- `json.loads` of the up2k handshake body (httpcli.py:1752, conf 0.95) — client `name`/`delete`/`srch` arrays.
- `self.parser.require` / `self.parser.gen` (6/4 entries, conf 0.90/0.85) — multipart form fields and filenames.
- FTP `vpath` params of `v2a`/`rv2a` (2 entries, 0.85) + `self.cwd` state reads (8 entries, 0.65); SMB `vpath` params (10 entries, 0.80) — protocol network boundaries (dispatch outside DB, noted as evidence gap).
- `unquotep`/`unquote` call sites (8 entries) are labeled **summary** (taint-preserving decode steps), not sources — the raw inputs they decode are already covered by http_req/http_path/uparam/headers sources.

## 5. Sanitizer list (19 entries)

| site | callable | class | conf | note |
| --- | --- | --- | --- | --- |
| authsrv.py:473 | `undot` | tp | 0.75 | **the load-bearing guard**: VFS.get applies undot to the DECODED request path; sound for dot-segments; splits on '/' only (backslash traversal stopped only by Windows relchk) |
| authsrv.py:430/439 | `undot` | tp | 0.70 | undot inside VFS._find/can_access volume-tree walk |
| httpcli.py:1765 | `undot` | tp | 0.70 | JSON body 'name' (not percent-encoded) + '/' rejection at :1766 |
| httpcli.py:3167 | `undot` | tp | 0.70 | tx_tree: undot on the already-decoded vpath |
| httpcli.py:333/337 | `undot` | **candidate** | 0.50 | PRE-decode application: neutralizes literal '..' but **not %2e%2e** (decode happens after, at :375) — barrier unsound against encoded traversal; flagged for manual review |
| ftpd.py:158, httpcli.py:1473/2052/2101/2176, up2k.py:2235 | `sanitize_fn` | tp | 0.85 | basename-only (ok='') — removes all directory components; FTP final component, PUT/multipart filenames, mkdir/new-md names, up2k handshake name |
| szip.py:109 | `sanitize_fn` | tp | 0.60 | ok='/' keeps separators — sanitizes archive entry NAMES, not fs paths |
| authsrv.py:705 (+ call sites :602, ftpd.py:167/235, httpcli.py:426) | `chk_ap` | tp | 0.60 | prefix containment (aps.startswith(vap)) + device check — **opt-in only** (xdev/xvol volume flags); default volumes have no post-canonical containment |

Not in the candidate CSV and therefore not labeled as entries: `_assert_safe_rem` (httpcli.py:197-200, write-side-only rejection of leading `/`, `../`, `/../`) and the Windows-only `relchk`/null-byte checks (:377-383). Both are documented here for the Phase 2 reviewer; `_assert_safe_rem` covers only the write paths (:2058/:2096/:2148/:2415), never the read paths.

## 6. Key finding candidates carried into the labels

1. **`.cpr` static-resource read channel (highest priority).** httpcli.py:766-783: `self.vpath` is dot-filtered only BEFORE percent-decode (undot at :333/:337 on the raw path), decoded at :375, and the static branch slices `self.vpath[5:]` directly into `os.path.join(self.E.mod, "web/", ...)` → `tx_file` (:783) — this branch never reaches the second undot inside VFS.get. Encoded traversal (`%2e%2e%2f`) therefore survives into the join, which escapes `E.mod/web/`; tx_file then stats/opens/serves any reachable file (bos.stat :2610, dynamic `open_func = open` :2772, sendfile :2773-2775). Labeled: source P1-S-0030 (:782, 0.95), summary P1-K-0321 (join :782, 0.95), sink P1-K-0018 (tx_file :783, 0.95).
2. **Read/write guard asymmetry.** All write channels (PUT dump_to_file, MKCOL, new-md, plain/text upload, up2k) pass vfs.get(undot) + `_assert_safe_rem` + `sanitize_fn`; the read channels (tx_file :3537, tx_browser :3431, thumbnails, ?doc=, zipgen) rely solely on the vfs.get double-undot — sound for the decoded vpath, but with no defense-in-depth.
3. **Thumbnail channel has a local join with no guard** (th_srv.py:197 `os.path.join(ptop, rem)` → `Image.open` :355); the defense is entirely the upstream undot of rem (rem comes from vfs.get via httpcli.py:3506). Modeled as summary (0.85) + sink (0.80) so a Phase 2 query will still trace it.
4. **chk_ap containment is opt-in** (xdev/xvol flags, httpcli.py:424-428): default volumes have no post-canonical containment; canonical is plain `realpath + '/' + rem` concatenation (authsrv.py:498-504). CWE-073 context.
5. **dcanonical leaves the final component unresolved** (authsrv.py:506-513; LOCK :1117, browser :3431) — TOCTOU-shaped (CWE-36); symlinks inside a volume resolve at canonical time, but the final component is opened later.
6. **SMB resolves all paths as LEELOO_DALLAS** (full-access builtin, smbd.py:130) — per-user volume permissions are bypassed by design on the SMB channel (CWE-073 context).
7. **`?doc=` viewer is guarded by listing membership** (httpcli.py:3874: doc must equal an actual entry name from statdir of abspath → basename-only in practice).

## 7. Unresolved / low-confidence items (manual review points)

- 24 sink + 13 summary + 2 sanitizer entries at `candidate`, mostly in the thumbnail pipeline (th_srv/th_cli), media-tagging pipeline (mtag), search index (u2idx), up2k registry maintenance — server-built or second-order paths where request influence is indirect.
- Broker IPC boundary: `handle_post_binary`/`bakflip` open paths returned by `up2k.handle_chunk` (httpcli.py:1890-1918, :1644-1661) cross a process boundary that CodeQL cannot see; components were validated at handshake time. Needs a MySummaries step in Phase 2 if these flows are to be tracked end-to-end.
- `up2k.py:3006` json.loads (broker reply) labeled none/fp — second-order client data; revisit if Phase 2 misses delete/mv flows.
- `up2k._hashlist_from_file` path param origin (CLI hashlist feature) not fully traced.
- pyftpdlib/impacket dispatch is outside this DB — the FTP/SMB source labels rely on the documented dispatch semantics (evidence gap, noted in each rationale).
- Dynamic open dispatch: tx_file's `open_func(*open_args)` (:2772), ren_open's `fun` kwarg and dump_to_file's `open_ka` overrides are Name-variable calls the file_open family cannot match; the tx_file/ren_open sink entries and the internal_file_wrapper summaries bracket them, but Phase 2 may need an explicit MySummaries edge for `open_func`/`fun`.

## 8. Exclusion record (role `none`, 163 entries — all classification fp)

- `os.environ.get` boot/config lookups in `__main__.py` (env family) — operator trust level, not request-reachable.
- `json.loads` of internal/file-derived documents: cert.py:66, mtag.py:587, up2k.py:799 (registry snapshot), httpcli.py:3006 (broker IPC).
- All `open`/`join`/`stat`-family sites in boot/config modules: `__main__.py` (config dir, salts, srvname, license, webdeps, boot tarball unpack), cert.py (TLS store), httpsrv.py (jinja loader over fixed web dir, cachebuster), svchub.py (logfile, restart), tcpsrv.py (/proc read), httpconn.py (fixed web resource paths), authsrv config regions (volume setup dive/hist, powner, expand_config_file).
- `os.path.join` and `os.path` resolve/check rows were **not** labeled as sinks (join/concat/Path are propagation, not file access) — request-channel ones are `summary` (taint-preserving through all arguments), config ones are `none`.
- WebDAV XML bodies, `self.pw`/auth values, MembershipTest guards and `self.ouparam` were never extracted as candidates (per detection.json) — nothing to exclude here.

## 9. Verification of the ten labeling criteria

1. *Sources at true boundaries only*: yes — HTTP socket parser attributes, json/form/multipart bodies, FTP/SMB protocol params; env vars and internal params → none/fp.
2. *Decode/normalize/join/object-conversion steps traceable*: yes — every step verified against real code (request-line split :241, undot :333/:337, unquotep :375, vfs.get :423 → authsrv.py:473, canonical :498-513, tx_file :2597-2786).
3. *Sinks are real file accesses*: yes — content read/write/delete/create/serve; `os.path.join`/`dirname`/`normpath` labeled summary, not sink; `stat`-family kept as weak sinks (0.55–0.75) with explicit "metadata-only" rationale.
4. *Traversal variants considered*: `../` literal (blocked by second undot), percent-encoded (survives first undot — the .cpr channel), absolute paths (undot strips leading '/' → relative), backslashes (POS: undot splits on '/' only; Windows relchk), double decode (query values decoded once at :341; vpath once at :375 — no re-decode found).
5. *Root-containment checks*: only opt-in chk_ap (xdev/xvol); no relative_to/startswith-based default containment anywhere on the read path — verified.
6. *Sanitizers need concrete evidence*: undot/sanitize_fn/chk_ap verified line-by-line incl. their caveats; the pre-decode undot explicitly downgraded to `candidate` for its encoded-traversal unsoundness.
7. *Symlinks/TOCTOU*: canonical resolves at request time, dcanonical leaves final component unresolved (noted, CWE-36); no symlink creation on request paths except up2k dedup `_symlink` (server-controlled target).
8. *Authorized file access ≠ vuln*: the main tx_file download (:3537) is the intended service — labeled sink/tp for taint tracking with the guard chain documented; exploitation requires bypassing the double-undot, which only the .cpr branch achieves.
9. *Tests/fixed constants/generated code*: DB directory and vendored `copyparty/stolen/` were excluded at extraction; boot/config fixed paths → none/fp.
10. *Complete flows vs local wrappers*: source→sink completeness was established per channel (see §6); wrapper-only rows (internal_file_wrapper) are `summary` steps so Phase 2 can connect both ends.

## 10. Decision requested

Approve `labels/labels.json` for Phase 2 (Step 4 library generation), or adjust labels first.
Suggested Phase 2 attention: (a) emit the .cpr static path as a priority flow, (b) add MySummaries
edges for vfs.get / canonical / djoin / unquotep / the dynamic `open_func`/`fun` dispatches and the
broker IPC hops, (c) treat the pre-decode undot sites as non-barriers (candidate labels) unless the
reviewer decides otherwise.
