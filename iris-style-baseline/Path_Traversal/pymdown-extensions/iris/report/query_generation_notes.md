# Augur Phase 2 Step 4 — Query Generation Notes (Pass 1: Path Traversal)

- **Project:** pymdown-extensions (vuln snapshot, `pymdownx` 9.11.0)
- **DB / source tree:** `.../path_traversal_dbs/pymdown-extensions_vuln` (+ nested `pymdown-extensions-db`)
- **Generated:** 2026-10-23 · **Pack:** `iris/qlpack.yml` (`iris/pymdown-extensions-cwe22`, dependency `codeql/python-all: "*"`, pre-existing, unchanged)
- **Generated files:** `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass1_PathTraversal.ql`, this note
- **Per the task contract:** no query execution, no analysis run; source tree, database, Augur installation and Phase 1 labels were not modified. (A `codeql query compile --check-only` of `queries/Pass1_PathTraversal.ql` was subsequently run and passes — see the compile note at the end of §6; no taint query was executed and no SARIF/analysis output was produced.)
- **Input label set:** `iris/labels/labels.json` (pass 1, 73 entries, schema-valid). `iris/labels/labels_raw_pass1.json` and `iris/labels/phase1_review.md` (review payload) were consulted for the candidate/uncertainty context of each entry.
- **Note on `labels/review_decision.json`:** the file does **not exist** in the workspace. WORKFLOW.md §4.5 declares the human review gate advisory and permits automated continuation with a logged summary; the Phase 1 review payload (`labels/phase1_review.md`, with an explicit 5-item human-review queue) is treated as the reviewed state of the labels, and the queue items are carried into this note rather than resolved silently. No `review_decision.json` was fabricated.

## 1. Label → QLL predicate mapping

All four libraries expose the pass-keyed interface used by the query template
(`isSource`/`isSink`/`isBarrier(node, passKey)`, `isAdditionalTaintStep(from, to, passKey)`,
uniform pass key `"path_traversal"`), imported from the query via
`import libraries.MySources` etc. Matching is purely AST-based
(callee name / receiver name / `os.path` attribute chain + file base name + line),
mirroring the Phase 1 extraction contract — no API-graph resolution is required.

### MySources.qll (6 of 7 source-labeled entries rendered)

| Label | Location | Rendered as | External input boundary & access conditions |
| --- | --- | --- | --- |
| `p1-s01` (tp, 0.95) | b64.py:73 | `markdownAttrPathSource` — node of the `m.group('path')` call | `<img>` src attribute value extracted by `RE_TAG_LINK_ATTR` from the rendered HTML of untrusted Markdown (host feeds `run(text)`); value fully attacker-chosen, quotes stripped `[1:-1]` on the same line. No privilege boundary: the extension runs with the host process' filesystem privileges. |
| `p1-s02` (tp, 0.9) | b64.py:114 | `processorRunParamSource` — `DataFlow::parameterNode(text)` | Host-library boundary: `B64Postprocessor.run(text)` invoked by the Python-Markdown core (site-packages, outside the DB) with untrusted rendered output. See §5 (callback limitation) — this row is a boundary declaration; the actual path connectivity is carried by `p1-s01`. |
| `p1-s03` (candidate, 0.55) | gen_emoji.py:112 | `externalContentSource` — node of the `tags[user_input]['zipball_url']` subscript (pinned by the `'zipball_url'` string-literal index) | GitHub API JSON (`json.loads(requests.get(api.github.com/.../releases).text)`); HTTPS, semi-trusted; `user_input` is an operator-selected list index. Maintainer-run dev tool, not shipped package code. Kept because its sink pair (`p1-k09`/`p1-k10`) is also candidate and the barrier `p1-k19` models the review-questioned guard. |
| `p1-s12` (tp, 0.95) | snippets.py:258 | `snippetPathSource` — node(s) of the `m.group('snippet')` call(s) | Inline `--8<-- "path"` include path straight out of an untrusted Markdown line (the two calls of the inline conditional share line 258; the location-scoped rule matches both — the label set already deduplicated them into one entry). |
| `p1-s13` (tp, 0.9) | snippets.py:276 | `snippetPathSource` — node of the `m.group(1)` call | Block-form include path re-extracted after `RE_SNIPPET_FILE` strips `:lines`/`:section` suffixes. |
| `p1-s14` (tp, 0.9) | snippets.py:352 | `processorRunParamSource` — `DataFlow::parameterNode(lines)` | Host-library boundary: `SnippetPreprocessor.run(lines)` receives the untrusted document source. Same callback limitation note as `p1-s02`. |

**Not rendered:** `p1-s11` (`parse_snippets` `lines` parameter, classification **candidate**) — an internal recursion parameter, not an external input boundary; per the Step-4 contract ("Source 只能是实际可控的外部输入节点") it is not emitted as a source rule. Recall is preserved: the same data enters the DB-internal flow through `p1-s14` (run) and the `run()` → `parse_snippets()` call edge, and the origin rows `p1-s12`/`p1-s13` sit inside `parse_snippets` anyway. This is a **rendering decision recorded here, not a modification of labels.json**; if the reviewer wants `p1-s11` active, it maps to `DataFlow::parameterNode(p)` with `p.getName() = "lines"`, `p.getPosition() = 1`, snippets.py:210 — one additional clause in `processorRunParamSource`. No label re-review was triggered: no reviewed label was found to be missing or wrong for query generation (the only near-miss is this candidate row, handled as above).

### MySinks.qll (4 sink-labeled entries, all rendered)

| Label | Location | Predicate | Real file operation / dangerous arg / access type / call relationship |
| --- | --- | --- | --- |
| `p1-k08` (tp, 0.95) | b64.py:86 | `b64FileReadSink` — `DataFlow::exprNode(open-call.getPositionalArg(0))` | builtin `open(file_name, "rb")`, **arg 0** = resolved path. **Read**; bytes are base64-embedded as a `data:` URI into the rendered output (read + exfiltration channel). Reached from `repl_path` via `parse_url`/`url2path`/`join`/`normpath` (b64.py:73–:82); gated only by `os.path.exists` and the image-extension whitelist (which restricts *what* is read, not *where*). |
| `p1-k55` (tp, 0.95) | snippets.py:311 | `snippetFileReadSink` — arg-0 node of the `codecs.open` call | `codecs.open(snippet, "r", encoding)`, **arg 0** = `get_snippet_path` result. **Read** (text); lines recursively re-parsed at snippets.py:333–341 so nested includes compound the traversal. Reached from `parse_snippets` after `m.group('snippet')`/`m.group(1)` extraction. |
| `p1-k09` (candidate, 0.55) | gen_emoji.py:44 | `archiveOpenSink` — arg-0 node of `zipfile.ZipFile(file_location, "r")` | Archive **open** of externally downloaded content; arg 0 is the basename-guarded download path (see barrier §4). Feeds `extractall` at :45. Semi-trusted source / maintainer tool → held at candidate. |
| `p1-k10` (candidate, 0.6) | gen_emoji.py:45 | `archiveExtractSink` — arg-0 node of `z.extractall(os.path.dirname(file_location))` | Archive **extract to disk** with no member-name validation (zip-slip shape: member names with `../` or absolute components write outside the extraction dir). Note the *dangerous* component is the member-name set, which is archive **content** — not reachable as a string data flow from `p1-s03`; see §5 for the modeling consequence. |

Path text producers are deliberately **not** sinks: `os.path.join`, `normpath`, `relpath`, `Path`-style wrappers etc. never touch the filesystem in this project, and `pathconverter.py`'s join/normpath chain is verified pure string rewriting (all 13 of its label entries are `none`).

### MySanitizers.qll (1 sanitizer-labeled entry, rendered)

See §4.

### MySummaries.qll (13 summary-labeled entries, rendered as argument→result edges)

| Label | Call site | Edge | Source evidence |
| --- | --- | --- | --- |
| `p1-k01` | b64.py:73 `util.parse_url(...)` | arg 0 → result | `util.parse_url` = `html.unescape` + `urlparse` (util.py:119) + absolute-form classification (util.py:127–157); returns the path component consumed by the join. Not stdlib-modeled by CodeQL — this edge is the only connectivity through the decode helper. |
| `p1-k02` | b64.py:75 `util.url2path(path)` | arg 0 → result | percent-decode wrapper (`url2pathname`, util.py:53–56): `%2e%2e%2f` → `../` **before** the join. |
| `p1-k03` | b64.py:78 `os.path.normpath(path)` | arg 0 → result | absolute branch: `is_absolute` src forms (file://, `c:/`, UNC `//`, leading `/`) normpathed without joining `base_path`. |
| `p1-k04` | b64.py:80 `os.path.normpath(join(...))` | arg 0 → result | lexical collapse only; no containment downstream. |
| `p1-k05` | b64.py:80 `os.path.join(base_path, path)` | **arg 1** → result | attacker path at arg 1; join semantics also let an absolute argument discard the base. |
| `p1-k48` | snippets.py:162 `os.path.join(base, path)` | **arg 1** → result | directory-style base branch of `get_snippet_path`. |
| `p1-k52` | snippets.py:170 `os.path.join(dirname, path)` | **arg 1** → result | file-style base branch (after the case-insensitive basename comparison at :169). |
| `p1-k45` + `p1-k54` | snippets.py:301 `self.get_snippet_path(path)` (def at :155) | arg 0 → result | internal resolution wrapper: param → first existing join result across `base_path`, **no validation inside the function**. The def-row (`p1-k45`) and the call-site row (`p1-k54`) are realized as the single edge at the sole call site. |
| `p1-k56` | def util.py:53 `url2path` | realized by the `p1-k02` edge at b64.py:75 | the only summary-labeled call site of `url2path`; the pathconverter.py call sites (util at :77/:105) are label `none` and intentionally receive **no** edge. |
| `p1-k57` | util.py:56 `url2pathname(path)` | arg 0 → result | the percent-decoding primitive inside `url2path`. |
| `p1-k58` | def util.py:103 `parse_url` | realized by the `p1-k01` edge at b64.py:73 | same def-row reasoning as `p1-k56`; pathconverter call sites labeled none, no edges. |
| `p1-k59` | util.py:119 `html.unescape(url)` | arg 0 → result | entity decode (`&#46;`) before parse/join. |

No arbitrary node-to-node propagation exists: every edge is bound to a call site that exists in the source, pinned by callee+receiver+file+line, and only the reviewed argument index flows to the call result.

## 2. Evidence on path composition, decoding, normalization, allowed roots, symlinks

Verified against the real source (line numbers from the audited snapshot):

- **Decode-before-join chain (b64):** quotes strip (`[1:-1]`, b64.py:73) → `html.unescape` (util.py:119, HTML entities) → `urlparse` → `url2pathname` (util.py:56, percent) → `os.path.join(base_path, path)` (b64.py:80) → `os.path.normpath` → `open`. Encoded traversals (`%2e%2e%2f`, `&#46;`) decode **into plain `../` before the join**; mixed separators are additionally normalized to `/` inside `parse_url`'s file-branches (util.py:129/:134/:142).
- **Absolute-path acceptance (b64):** `parse_url` sets `is_absolute` for `file:///`, `file://c:/`, `file://\\…`, `c:` drive schemes, UNC `//`, and leading `/`/`\` (util.py:127–157); b64.py:77–78 then normpaths the path **without joining base_path** — reads outside the declared root by construction. Relative `../` chains also survive (normpath only collapses lexically).
- **Include-path composition (snippets):** `path = m.group('snippet')[1:-1].strip()` / `m.group(1)` → `get_snippet_path` → `os.path.join(base, path)` (:162) or `join(dirname, path)` (:170). `os.path.join` semantics accept an absolute include path (discarding base) and pass `..` segments through; the result is returned and opened at :311.
- **Allowed-root checks:** **none exist.** No `relative_to`, no `abspath`+prefix, no `startswith(base)`, no fixed-filename map, no location allowlist anywhere between the Markdown-born path and the file read in either pipeline. `check_paths` (snippets.py:280/:327–330/:343–344) only converts *missing* snippets into `SnippetMissingError`; the `seen` set (:306) is cycle prevention; the `;`-escape (:268) is a content convenience; `is_url` content rule (:293–296) only constrains includes *inside downloaded URL content*.
- **Existence gates:** `os.path.exists` at snippets.py:163/:171 and b64.py:82 — check-then-read TOCTOU-shaped oracles; they are not modeled as barriers (a missing file falls through to the next base / raises the missing-snippet error).
- **Symlinks:** no symlink-handling code (`islink`, `realpath` resolution policy) exists anywhere in the two pipelines — recorded as **not applicable**. A symlink placed inside a reachable directory would therefore be followed transparently at the `open`/`codecs.open` call; no canonicalization-vs-validation ordering issue arises because there is no validation at all.
- **Case-insensitive comparison:** `basename(base).lower() == path.lower()` (snippets.py:169) — Windows-relevant name matching in the file-style base branch; not a traversal guard.

## 3. Flow connectivity review (why the two confirmed flows will be found)

`TaintTracking::Global<Pass1Config>` with the rendered libraries gives, for the
**snippets pipeline**: source `p1-s12`/`p1-s13` (group call nodes) — default taint
steps cover the `[1:-1]` slice (`subscriptStep`) and `.strip()`
(`stringManipulation`) — `path` variable → `self.get_snippet_path(path)` argument
→ `p1-k45/k54` edge → call result → `snippet` → `codecs.open` arg 0 (`p1-k55`).
The join edges `p1-k48`/`p1-k52` additionally let global taint traverse the
*inside* of `get_snippet_path` (param → join → return). For the **b64
pipeline**: source `p1-s01` → `parse_url` arg (`p1-k01` edge) → call result →
tuple unpacking (default unpacking store steps) → `path` → `url2path`
(`p1-k02`) → join (`p1-k05`) → normpath (`p1-k04`) → `file_name` → `open`
arg 0 (`p1-k08`). The absolute branch is covered by `p1-k03`.

**Overlap with CodeQL defaults (verified in the cached pack, python-all 7.1.2):**
`semmle/python/frameworks/Stdlib.qll` registers `os.path.join` (any argument)
and the path computations `abspath, basename, dirname, expanduser, expandvars,
join, normcase, normpath, realpath, relpath, split, splitdrive, splitext`
(argument 0) as default `TaintTracking::AdditionalTaintStep`s for every global
config. The rendered `os.path.*` edges (`p1-k03/k04/k05/k48/k52`) therefore
re-state default semantics at the labeled locations — strictly narrower (one
argument, one call site), so they cannot widen any flow; they are kept because
the reviewed labels mandate them. The non-stdlib wrappers (`parse_url`,
`url2path`, `url2pathname`, `html.unescape`, `get_snippet_path`) have no
default model and rely entirely on the rendered edges.

## 4. Barrier analysis

**`p1-k19` — `os.path.basename(url)` at gen_emoji.py:66 (the only sanitizer label).**
Barrier node: the basename call node itself. Proof of blocking for the
download-write path: `basename` strips all separator components from the
external `zipball_url`, the literal `'.zip'` suffix is appended, and the result
is joined into the fixed operator-configured `tools/tags/<repo>` directory —
the external URL cannot influence any directory component of `file_location`.
Every route from `p1-s03` toward `file_location` and its derivatives
(`open(file_location,'wb')` :73, `ZipFile` :44, `dirname(file_location)` for
`extractall` :45) passes through this node, which is also where the *default*
`OsPathComputation` taint step would deliver taint — the barrier cuts exactly
there. Scope limits (kept open per the label): it does **not** validate
archive member names (zip-slip through `extractall` content is not a string
flow from the URL and is unreachable anyway — see §5), and on POSIX a
backslash-containing basename stays a flat filename.

**No barrier is emitted for the snippets/b64 pipelines** — §2 documents that
no code restricts the resolved path to the declared root; `normpath`, decode
helpers and existence gates were each examined and are propagation/oracles,
not sanitizers.

## 5. Known modeling gaps, CodeQL limitations, diagnostics (not formal alerts)

1. **Callback boundary (run → regex match object):** taint from the `run(text)`/`run(lines)` parameters into the `re.sub`/`RE.match` machinery and out through `m.group(...)` is **not** modeled (no default step for regex match results; the match object's provenance is opaque). Consequence: `p1-s02`/`p1-s14` are boundary declarations that may yield no path on their own; the actual connectivity is carried by the origin rows `p1-s01`/`p1-s12`/`p1-s13`, which is exactly why the reviewed label set contains both families.
2. **`urlparse` internals:** taint through `urlparse(...)` (util.py:119) is not modeled; the `p1-k01` call-site edge (arg → result of `parse_url`) provides the connectivity around it. If `parse_url` is ever called with an already-tainted argument at a *new* call site, that site needs its own reviewed edge.
3. **Dynamic dispatch / receiver aliases:** source/sink/summary matching relies on the stable receiver names of the extraction contract (`m`, `self`, `z`, `os`, `codecs`, `zipfile`, `util`, `html`) plus file+line pinning. A refactored receiver name would silently de-match — a `diagnostics` query (suggested below) would catch count drift.
4. **Zip member content:** zip-slip through `extractall` member names is not a data flow from the URL string; it would require modeling `ZipFile` iteration/`getnames` as a source. This is out of scope of the reviewed labels (no such source row exists) — recorded, not modeled, per the "no unevidenced source" rule.
5. **Host library:** the Python-Markdown core (site-packages) is outside the database; anything it does with files is invisible. The `run()` parameter rows are the visible boundary proxy.
6. **Suggested diagnostics (NOT written, NOT formal Pass 1 alerts):** a non-`path-problem` query selecting `MySources::isSource(n, "path_traversal")` and one selecting `MySinks::isSink(n, "path_traversal")` would verify that exactly 6 source nodes and 4 sink nodes match (compare with labels: 6 rendered sources + 4 sinks) before the Step 5 execution round; a third could assert the barrier matches exactly 1 node. Any drift indicates a refactor or an AST-matching regression to fix **before** the formal run. Per the task contract only the six files above were written; these queries remain suggestions for the execution round.
7. **Label deviations:** none requiring re-review (see §1 for the `p1-s11` rendering decision and the def-row realization of `p1-k45/k56/k58` via their call sites; `labels.json` untouched).

## 6. Experiment independence

No PyVul ground truth was consulted at any point: `CVE_VULNERABILITY_REPORT.md`,
`VULNERABILITY_AUDIT_REPORT.md` and `path_traversal_sinks.csv` at the repo root
were never opened; no patch diffs or known-CVE line numbers were used. All
label-to-code evidence in this note was re-derived by reading the actual source
files (`pymdownx/snippets.py`, `pymdownx/b64.py`, `pymdownx/pathconverter.py`,
`pymdownx/util.py`, `tools/gen_emoji.py`, `run_tests.py`, `hatch_build.py`) and
the locally cached `codeql/python-all 7.1.2` / `codeql/dataflow 2.1.3` library
sources (read-only, to verify the CodeQL APIs used: `DataFlow::ConfigSig`
defaults, `TaintTracking::Global`, `DataFlow::exprNode`/`parameterNode`,
`Node.asExpr()`, `Call.getPositionalArg(int)`, `Call.getFunc()`,
`Attribute.getName()/getObject()`, `Name.getId()`, `Subscript.getIndex()`,
`StringLiteral.getText()`, `Parameter.getName()/getPosition()`,
`Function.getArg(int)`, `Location.getFile()`, `File.getBaseName()`,
`Location.getStartLine()`, and
the default taint-step inventory). One API mistake was caught and fixed by the
user-initiated check-only compile: `AstNode.getFile()` does **not** exist in
this library (Phase 1's detection.json had already documented this); the
correct chain is `node.getLocation().getFile()` — exactly what the first
version of the four libraries got wrong on all nine `getFile()` uses. After
replacing every `X.getFile().getBaseName()` with
`X.getLocation().getFile().getBaseName()` (9 occurrences across the four
libraries), `codeql query compile --check-only queries/Pass1_PathTraversal.ql`
run from the `iris/` pack root compiles **clean** (Done [1/1], no errors,
no warnings surfaced). The source tree, database, Augur installation, Phase 1
CSVs and `labels.json` are
unmodified. Taint-query execution (Step 5 run, SARIF decode, filtering) is
deferred to the next round per the task contract.
