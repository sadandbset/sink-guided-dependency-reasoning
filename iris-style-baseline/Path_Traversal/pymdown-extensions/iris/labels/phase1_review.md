# Phase 1 Step 3 — LLM Candidate Labeling Review (Pass 1: Path Traversal)

Project: **pymdown-extensions** (vuln snapshot) · Model: **glm-5.3** · Generated: 2026-10-23
Scope: Pass 1 (CWE-022/023/036/073) · Candidates: 74 CSV rows → **73 labeled entries** (1 dedup)
Ground-truth access: **none** (PyVul CVE/audit reports, patch diffs, `path_traversal_sinks.csv`
were not opened; labeling derives only from reading the real source tree and the Augur
references).

The audit target is a pure **library** (extension pack for Python-Markdown). There is no HTTP
surface, no routing, no request/upload/static-file code. The untrusted boundary is the
**Markdown source text / rendered output** that the host application pushes through the extension
`run()` methods; the host (site-packages `markdown` package) is outside the CodeQL database, so
`run()` parameter rows and regex-group origin rows are the visible boundary proxies.

---

## The two confirmed attacker-to-file flows (tp)

### Flow 1 — Snippets include path traversal

```
Markdown document (untrusted)
  -> SnippetPreprocessor.run(lines)                 snippets.py:352   [source, p1-s14]
  -> parse_snippets: m.group('snippet')             snippets.py:258   [source, p1-s12]
     / m.group(1) after suffix strip                snippets.py:276   [source, p1-s13]
  -> self.get_snippet_path(path)                    snippets.py:301   [summary, p1-k54]
  -> os.path.join(base, path)                       snippets.py:162/:170 [summary, p1-k48/p1-k52]
  -> codecs.open(snippet, 'r', encoding)            snippets.py:311   [SINK, p1-k55, conf 0.95]
  -> lines recursively re-parsed                    snippets.py:333-341  (nested includes compound)
```

- `--8<-- "../../etc/passwd"` (inline or block form) survives every step: no `..` rejection, no
  absolute-path rejection, no base containment. `os.path.join` semantics additionally discard
  `base` when the include path is absolute.
- Only gates: `os.path.exists` (`:163`/`:171`) — existence oracles, TOCTOU-shaped but not guards;
  `check_paths` config only turns *missing* files into an error; the `seen` set (`:306`) is cycle
  prevention, not traversal prevention.
- Read content is injected into the rendered document → information disclosure of any file
  readable by the process (default `base_path` is `["."]`).

### Flow 2 — B64 img-src traversal

```
rendered HTML of untrusted Markdown
  -> B64Postprocessor.run(text)                     b64.py:114        [source, p1-s02]
  -> m.group('path') (img src value)                b64.py:73         [source, p1-s01]
  -> util.parse_url: html.unescape + urlparse       util.py:103/:119  [summary, p1-k58/p1-k59]
  -> util.url2path: url2pathname (percent decode)   b64.py:75, util.py:53/:56 [summary]
  -> is_absolute: os.path.normpath(path)            b64.py:78         [summary, p1-k03]
     else: normpath(join(base_path, path))          b64.py:80         [summary, p1-k04/p1-k05]
  -> os.path.exists (oracle only)                   b64.py:82         [none]
  -> open(file_name, 'rb')                          b64.py:86         [SINK, p1-k08, conf 0.95]
  -> content embedded as data: URI in output        b64.py:87-90      (exfiltration channel)
```

- `parse_url` (util.py:127-157) accepts `file:///…`, `file://c:/…`, UNC `//…`, `c:/…` and
  leading `/`/`\` forms as **absolute**, which take the direct `normpath` branch at b64.py:78 and
  read **outside `base_path` by construction** (reads any `.png/.jpg/.gif/.svg` on the host).
- Relative traversal works too: entity (`&#46;`) decodes at util.py:119 and percent (`%2e%2e%2f`)
  decodes at util.py:56 **before** the join; `normpath` collapses `..` lexically but contains
  nothing.
- The extension whitelist at b64.py:84-85 restricts *which* files are readable (image types), not
  *where* they may live.

### Candidate flow — gen_emoji zip handling (human review)

`tags[user_input]['zipball_url']` (gen_emoji.py:112, GitHub API JSON) → `basename(url)+'.zip'`
join (`:66`) → `open('wb')` (`:73`) → `ZipFile`/`extractall` (`:44`/`:45`) with **no member
validation** — a real zip-slip shape. Held at `candidate` because the source is a semi-trusted
HTTPS GitHub API response and the tool is maintainer-run (`tools/`, not shipped package code).
The `basename`+literal `'.zip'` composition at `:66` is labeled a *conditional sanitizer* for the
download-write path (flat filename, no directory influence) but does not validate archive
members, so `extractall` remains the exposed surface.

---

## Review against the 10-point checklist

1. **Source = real untrusted boundary?** Yes for the Markdown text boundaries: `run(lines)`
   (snippets.py:352), `run(text)` (b64.py:114), and the regex-group extractions `m.group('snippet')`
   (:258/:276) and `m.group('path')` (b64.py:73) — values born from untrusted document content, not
   internal wrapper artifacts. `parse_snippets(lines)` (:210) is an *internal* parameter — kept as
   low-confidence source (`candidate`) only for recall of the recursion. CLI rows (run_tests.py:22/:26,
   gen_emoji.py:126) are trusted operator input → `none`. `zipball_url` is external but semi-trusted
   → `candidate`.
2. **Decode/normalize/join chain traceable?** Yes, every step read in real code: quotes strip
   (`[1:-1]`) → `html.unescape` (util.py:119) → `urlparse` (util.py:119) → `url2pathname`
   (util.py:56) → `os.path.join` (b64.py:80 / snippets.py:162/:170) → `normpath` → exists →
   open/codecs.open. Each decode is *before* the join (traversal-enabling, not neutralizing).
3. **Sink = actual file read/write/delete/extract/response?** Yes for the two tp sinks
   (`codecs.open` snippets.py:311, `open` b64.py:86) and the candidate `extractall`
   (gen_emoji.py:45). `Path()`/`join()`/string building alone are **not** sinks here — they are
   labeled `summary` (propagation steps). `pathconverter.py`'s entire join/normpath/relpath chain
   is string rewriting with no file access → `none`.
4. **Traversal variants possible (`../`, absolute, drive/UNC, multi-decode)?** Yes for both tp
   flows: plain `../`; absolute paths via `os.path.join` argument semantics (snippets) and via the
   `is_absolute` branch (b64:78); `c:`/`file://`/`//` UNC and leading-slash forms accepted by
   `parse_url`; `%2e%2e%2f` and `&#46;` decode before the join. All escape the declared
   `base_path`.
5. **Real restricted-root check before file access?** **None exists.** No `relative_to`, no
   `abspath`+prefix containment, no `startswith(base)`, no fixed-filename map, no allowlist on
   path location anywhere in `get_snippet_path` or `repl_path`.
6. **Do normpath/resolve/basename/startswith/blacklists block it here?** No. `normpath` only
   collapses lexically (no containment); `url2path`/`parse_url`/`unescape` decode (widen). The only
   `basename` near a tainted value is gen_emoji.py:66 (conditional sanitizer, download path only);
   snippets.py:167's `basename` touches the operator base, never the attacker path.
7. **Symlinks / TOCTOU / time-of-check?** No symlink handling code exists anywhere in the
   pipelines (recorded as **not applicable**). TOCTOU windows exist (`exists` at b64.py:82 and
   snippets.py:163/:171 immediately before the opens) but are check-then-read, not guards.
8. **Authorized file access?** Normal snippet includes and local image embedding *within*
   `base_path` are intended features; the flows escape the declared root, which is not authorized.
   Operator CLI/build paths (run_tests, hatch_build) are deliberate authorized access → `none`.
9. **Test constants / generated files / unreachable code?** tests/ and the CodeQL DB directory were
   excluded at extraction; all dev-tool fixed-literal or `__file__`-derived paths
   (gen_emoji1/gen_gemoji/gen_joypixels/gen_twemoji/hatch_build) are labeled `none`. Generated
   `*_db.py` outputs are fixed literal paths.
10. **Full untrusted-source → dangerous-path flow, or local wrapper only?** Both tp flows are
    complete untrusted-source → file-read flows. `pathconverter.py` is a local
    wrapper-to-string-rewrite chain with no file API → `none` for Pass 1. The `download(url)`
    boundary (snippets.py:177) is a network fetch (SSRF/Pass 3), labeled `none` for Pass 1 and
    recorded for the later pass.

## Role/summary decisions for query generation

- **Summaries (13):** decode + resolution steps that taint must traverse: `parse_url`,
  `url2path`/`url2pathname`, `html.unescape`, `normpath`/`join` at the b64/snippets pipeline rows,
  and the `get_snippet_path` wrapper (definition row `:155` + call-site row `:301`).
  These feed `MySummaries.qll` as `isAdditionalTaintStep` edges.
- **Sanitizers (1, candidate):** gen_emoji.py:66 `basename` — barrier only for the dev-tool
  download-write path; `MySanitizers.qll` may include it or resolve to `none()` per review.
- **Sources (7):** the Markdown boundary rows; **Sinks (4):** the two reads + two archive rows.
- **No sanitizer label exists for the snippets/b64 pipelines** — this is the central finding; the
  barrier predicate for the Pass 1 query will legitimately be empty for those flows.

## Human review points

1. `p1-k10` (extractall zip-slip): confirm or refute reachability given the semi-trusted GitHub
   source and the maintainer-only execution context.
2. `p1-k19` (basename sanitizer): accept as barrier for the download-write path, or drop to `none`
   and re-evaluate `p1-k18`/`p1-k20` jointly.
3. `p1-s03` / `p1-k09`: whether the GitHub API `zipball_url` should count as an untrusted source
   at all in this maintainer tool.
4. `p1-s11` (parse_snippets param): keep as recall source or rely on `run()` alone.
5. None of the 73 entries was left `unknown`; all uncertain items carry `candidate` with
   confidence 0.55–0.6 and explicit open questions above.

## Integrity statements

- All 15 source rows and 59 sink rows were processed (74 rows → 73 entries, 1 documented dedup);
  no candidate was skipped or invented.
- Labeling used only: the real source tree, `iris/exploration/detection.json`,
  `references/python.md`, `references/patterns.md`, `WORKFLOW.md`, and
  `assets/labels_schema.json` (no framework reference matched this tree — none was loaded).
- No source file, CodeQL database, Augur installation file, or Phase 1 CSV was modified.
- `labels.json` passed local validation against `assets/labels_schema.json` (Draft 2020-12,
  format checker on).
- Per the task contract, execution **stops here** — no Phase 2 (no `MySinks.qll`/pass-query
  generation, no taint tracking, no report).
