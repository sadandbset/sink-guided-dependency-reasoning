# Phase 1 Step 3 Review - CairoSVG Pass 3 (CWE-918 SSRF)

Checkpoint review payload (Augur WORKFLOW.md 4.5, interactive mode: stop here, await human approval before Phase 2).

- Run: `cairosvg-pass3-cwe918-labeling-20261019` (2026-10-19T09:59:57Z)
- Model: glm-5.3 (Claude Code CLI agent, deterministic labeling, no sampling)
- Scope: Pass 3 / CWE-918 only; 79 candidates (62 source + 17 sink) in 6 batches; 0 dropped.

## Label counts (pass 3)

| role | count | tp | candidate | fp |
| --- | --- | --- | --- | --- |
| source | 32 | 0 | 32 | 0 |
| sink | 2 | 1 | 1 | 0 |
| sanitizer | 0 | 0 | 0 | 0 |
| summary | 24 | 23 | 1 | 0 |
| none | 21 | 0 | 0 | 21 |

### Top high-risk sinks

- `P3-K-013` **urlopen** (tp, conf 0.95) @ `cairosvg/url.py:84` arg_index=0 - urlopen(Request(url, headers=HTTP_HEADERS))(url.py:84):全代码库唯一网络出口(已 grep 核实 cairosvg/ 内无 requests/httpx/socket/urlretrieve,无固定主机 URL)
- `P3-K-017` **url_fetcher** (candidate, conf 0.80) @ `cairosvg/url.py:143` arg_index=0 - return url_fetcher(url, resource_type)(url.py:143):动态分发调用(目标为 self.url_fetcher,默认 fetch,parser.py:354;CodeQL 无法静态解析)

### Top broad sources (entry boundary)

- `P3-S-001` cairosvg.__init__.svg2svg param (candidate, conf 0.75) @ `cairosvg/__init__.py:38`
- `P3-S-002` cairosvg.__init__.svg2svg param (candidate, conf 0.70) @ `cairosvg/__init__.py:38`
- `P3-S-003` cairosvg.__init__.svg2svg param (candidate, conf 0.70) @ `cairosvg/__init__.py:38`
- `P3-S-004` cairosvg.__init__.svg2png param (candidate, conf 0.75) @ `cairosvg/__init__.py:51`
- `P3-S-005` cairosvg.__init__.svg2png param (candidate, conf 0.70) @ `cairosvg/__init__.py:51`
- `P3-S-006` cairosvg.__init__.svg2png param (candidate, conf 0.70) @ `cairosvg/__init__.py:51`
- `P3-S-007` cairosvg.__init__.svg2pdf param (candidate, conf 0.75) @ `cairosvg/__init__.py:63`
- `P3-S-008` cairosvg.__init__.svg2pdf param (candidate, conf 0.70) @ `cairosvg/__init__.py:63`
- `P3-S-009` cairosvg.__init__.svg2pdf param (candidate, conf 0.70) @ `cairosvg/__init__.py:63`
- `P3-S-010` cairosvg.__init__.svg2ps param (candidate, conf 0.75) @ `cairosvg/__init__.py:75`
- `P3-S-011` cairosvg.__init__.svg2ps param (candidate, conf 0.70) @ `cairosvg/__init__.py:75`
- `P3-S-012` cairosvg.__init__.svg2ps param (candidate, conf 0.70) @ `cairosvg/__init__.py:75`
- `P3-S-013` cairosvg.__init__.svg2eps param (candidate, conf 0.75) @ `cairosvg/__init__.py:87`
- `P3-S-014` cairosvg.__init__.svg2eps param (candidate, conf 0.70) @ `cairosvg/__init__.py:87`
- `P3-S-015` cairosvg.__init__.svg2eps param (candidate, conf 0.70) @ `cairosvg/__init__.py:87`
- `P3-S-017` cairosvg.__main__.main param (candidate, conf 0.55) @ `cairosvg/__main__.py:13`
- `P3-S-054` cairosvg.surface.convert param (candidate, conf 0.75) @ `cairosvg/surface.py:97`
- `P3-S-055` cairosvg.surface.convert param (candidate, conf 0.70) @ `cairosvg/surface.py:97`
- `P3-S-056` cairosvg.surface.convert param (candidate, conf 0.70) @ `cairosvg/surface.py:97`

### Document-derived sources (canonical SSRF drivers)

- `P3-S-019` sys.stdin @ `cairosvg/__main__.py:65` (conf 0.55)
- `P3-S-021` stdin.buffer @ `cairosvg/__main__.py:70` (conf 0.60)
- `P3-S-024` get_href @ `cairosvg/bounding_box.py:344` (conf 0.70)
- `P3-S-028` url_token.value @ `cairosvg/css.py:37` (conf 0.80)
- `P3-S-035` get_href @ `cairosvg/defs.py:348` (conf 0.75)
- `P3-S-037` {http://www.w3.org/XML/1998/namespace}base @ `cairosvg/image.py:24` (conf 0.75)
- `P3-S-039` get_href @ `cairosvg/image.py:27` (conf 0.80)
- `P3-S-042` {http://www.w3.org/1999/xlink}href @ `cairosvg/parser.py:262` (conf 0.70)
- `P3-S-043` href @ `cairosvg/parser.py:263` (conf 0.70)
- `P3-S-045` {http://www.w3.org/1999/xlink}href @ `cairosvg/parser.py:313` (conf 0.65)
- `P3-S-046` href @ `cairosvg/parser.py:313` (conf 0.65)

## Sanitizers

None labeled (concrete-evidence rule). No scheme/host allowlist, private-IP blocking or redirect control exists in cairosvg/; the default fetcher is explicitly unlimited (cairosvg/url.py:133-135). defusedxml flags (parser.py:390-392) are XXE-only protections, caller-disableable via `unsafe=True`, and do not block external URL fetch - not a CWE-918 sanitizer (user review point 6).

## Unresolved / low-confidence items

- `P3-S-017` (source, candidate, conf 0.55) @ `cairosvg/__main__.py:13`
- `P3-S-019` (source, candidate, conf 0.55) @ `cairosvg/__main__.py:65`
- `P3-S-021` (source, candidate, conf 0.60) @ `cairosvg/__main__.py:70`
- `P3-S-026` (summary, tp, conf 0.60) @ `cairosvg/css.py:34`
- `P3-S-029` (summary, tp, conf 0.60) @ `cairosvg/css.py:38`
- `P3-S-030` (none, fp, conf 0.60) @ `cairosvg/css.py:54`
- `P3-S-031` (none, fp, conf 0.60) @ `cairosvg/css.py:96`
- `P3-S-040` (none, fp, conf 0.60) @ `cairosvg/parser.py:193`
- `P3-S-041` (none, fp, conf 0.60) @ `cairosvg/parser.py:195`
- `P3-S-047` (summary, candidate, conf 0.55) @ `cairosvg/parser.py:321`
- `P3-S-061` (none, fp, conf 0.60) @ `cairosvg/text.py:71`
- `P3-S-062` (none, fp, conf 0.60) @ `cairosvg/text.py:71`

All entries >= 0.55; no re-ask needed (threshold 0.55). The list above is the human-review queue.

## Review-point responses (per task instructions)

1. **Input boundary**: CairoSVG is a pure library. The svg2*/convert bytestring/file_obj/url parameters and CLI streams are labeled `source` with classification `candidate` - untrusted only when a host application converts attacker-supplied SVG/URLs; parameters are NOT auto-trusted (concerns 1 and 9 honored; internal wrapper form params fetch/read_url/Node.fetch_url are `summary`, not `source`).
2. **Document references that drive real requests**: verified real - `<image>` href + xml:base (cairosvg/image.py:24-28), CSS @import URL (cairosvg/css.py:34-39), `<tref>` href (parser.py:262-267), `<use>` href (defs.py:348-352, bounding_box.py:344-347), external SVG via Tree(url=...) (parser.py:386). CSS declaration url() values are fragment-only consumers (helpers.py:47, surface.py:317/318/372) - labeled none/fp.
3. **Propagation and reachability**: verified end-to-end chain Node.fetch_url (parser.py:242) -> read_url (url.py:132) -> url_fetcher dynamic dispatch (url.py:143, default fetch) -> urlopen (url.py:84). No scheme/host validation anywhere between href read and network call.
4. **Dangerous argument position**: urlopen arg 0 (the Request object carrying the URL) at url.py:84 is accurate; Request ctor arg 0 labeled `summary` (object construction, not I/O); parse_url/urljoin are pure processing - labeled `summary` (propagation), never `sink`.
5. **Blocking controls**: none exist (see Sanitizers). No fixed-URL fetches either - all fetch URLs are caller/derived (grep: no requests/httpx/socket/urlretrieve, no http(s) literal URLs outside comments).
6. **defusedxml**: XXE-only, not an SSRF sanitizer; disableable via caller-controlled unsafe=True (recorded in S-051 rationale and metadata notes).
7. **Fixed vs attacker-controlled targets**: no admin-config/fixed-host requests exist in the library. CLI argv/options.input are operator-typed - labeled none/fp (S-016/S-018/S-020/S-022) with deployment caveat; document-embedded references are the attacker-controlled class.
8. **file:/data:**: url.py:140 file:// rewrite and data: pass-through (url.py:33) are NOT network SSRF; labeled none/fp with cross-CWE note (arbitrary local file read via urlopen(file://...), CWE-22-adjacent; XXE path covered by Pass 8, not evaluated here).
9. **Internal wrapper formals**: fetch (url.py:77), read_url (url.py:132), Node.fetch_url (parser.py:242) params labeled `summary`; no internal diagnostic wrapper was promoted to a formal Source.

## Findings posture

No SSRF vulnerability is confirmed at this stage. The labeling establishes: a verified single network egress (urlopen, arg position confirmed), a verified attacker-controllable URL-composition chain from document references to that egress with zero validation, and deployment-conditional sources. Whether this constitutes a vulnerability in a given deployment depends on the host's trust model and any injected `url_fetcher` - to be resolved by Phase 2 taint analysis and human triage, not by labeling.

## Coverage / dedup record

- 79/79 CSV rows labeled; no row dropped; exclusions from extraction (tests, nested DB dir) were already applied at Step 2 and are documented in exploration/detection.json.
- K-008 duplicates the K-007/K-015 wrapper edge (kept per call site; dedupe at Step 4). S-045/S-046 overlap the per-consumer get_href rows (kept: dict .get() flows are untracked at extraction level).
- Ground-truth files in the source tree (CVE-Report-*.md, ssrf_sinks.*, ssrf_vulnerability_report.md) were NOT opened; labels derive from source reading only. Project source, the CodeQL database, the original CSVs and Augur files were not modified.

## Approval

Interactive mode: awaiting human review of this document and `labels/labels.json` before Phase 2 (Step 4 library generation).
