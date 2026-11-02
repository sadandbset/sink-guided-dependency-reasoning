# Pass 3 (CWE-918 SSRF) Label Statistics - CairoSVG

- Run ID: `cairosvg-pass3-cwe918-labeling-20261019`
- Generated: 2026-10-19T09:59:57Z
- LLM model: glm-5.3 (Claude Code CLI agent, deterministic labeling, no sampling)
- Batch policy: 6 batches (B1 22, B2 14, B3 15, B4 11, B5 9, B6 8); deterministic labeling, no sampling; re-ask threshold 0.55 (0 entries re-asked); human-review flag threshold 0.65.

## Coverage

| metric | count |
| --- | --- |
| candidates in CSVs (62 source + 17 sink) | 79 |
| labeled entries in labels.json (pass 3) | 79 |
| dropped / excluded | 0 |
| pass 1 placeholder (schema `contains pass_id 1`) | 0 entries |

## Label distribution (pass 3, 79 entries)

| role | count |
| --- | --- |
| source | 32 |
| sink | 2 |
| sanitizer | 0 |
| summary | 24 |
| none | 21 |

| role / classification | count |
| --- | --- |
| none / fp | 21 |
| sink / candidate | 1 |
| sink / tp | 1 |
| source / candidate | 32 |
| summary / candidate | 1 |
| summary / tp | 23 |

## Confidence distribution

| bucket | count |
| --- | --- |
| >=0.8 | 17 |
| 0.7-0.79 | 44 |
| 0.65-0.69 | 6 |
| <0.65 | 12 |

## Candidates by module

| module | candidates |
| --- | --- |
| cairosvg.parser | 16 |
| cairosvg.__init__ | 15 |
| cairosvg.css | 8 |
| cairosvg.__main__ | 7 |
| cairosvg.surface | 7 |
| cairosvg.defs | 6 |
| cairosvg.image | 5 |
| cairosvg.url | 4 |
| cairosvg.bounding_box | 3 |
| cairosvg.text | 3 |
| cairosvg.path | 2 |
| urllib.request | 2 |
| cairosvg.helpers | 1 |

## Entries flagged for human review (confidence < 0.65)

- `P3-S-017` source candidate main @ cairosvg/__main__.py:13 (conf 0.55): stdin(位置参数 2)承载管道输入的 SVG 文档内容(__main__.py:69-70:options.input=='-' 时 kwargs['fil
- `P3-S-019` source candidate sys.stdin @ cairosvg/__main__.py:65 (conf 0.55): stdin = stdin or sys.stdin(__main__.py:65):sys.stdin 是外部输入流(管道字节),宿主以管道喂入不可信文档时是
- `P3-S-021` source candidate stdin.buffer @ cairosvg/__main__.py:70 (conf 0.60): kwargs['file_obj'] = stdin.buffer(__main__.py:70):管道输入的文档内容字节进入 Tree -> ElementT
- `P3-S-026` summary tp parse_one_component_value @ cairosvg/css.py:34 (conf 0.60): url_token = tinycss2.parse_one_component_value(rule.prelude)(css.py:34):@import 
- `P3-S-029` summary tp parse_stylesheet @ cairosvg/css.py:38 (conf 0.60): tinycss2.parse_stylesheet(tree.fetch_url(...).decode())(css.py:38):对已取回 CSS 的解析,
- `P3-S-030` none fp parse_declaration_list @ cairosvg/css.py:54 (conf 0.60): tinycss2.parse_declaration_list(...)(css.py:54/96 与 parser.py:195 parse_declarat
- `P3-S-031` none fp parse_declaration_list @ cairosvg/css.py:96 (conf 0.60): tinycss2.parse_declaration_list(...)(css.py:54/96 与 parser.py:195 parse_declarat
- `P3-S-040` none fp style @ cairosvg/parser.py:193 (conf 0.60): style_attr = node.get('style')(parser.py:193):内联 style 声明内容;其 url() 值仅被 fragment
- `P3-S-041` none fp parse_declarations @ cairosvg/parser.py:195 (conf 0.60): css.parse_declarations(style_attr)(parser.py:195):声明解析,同 S-030/S-031 的 fragment-
- `P3-S-047` summary candidate parse_url @ cairosvg/parser.py:321 (conf 0.55): Tree.__new__ 中 parsed_url = parse_url(kwargs['url'])(parser.py:321)用于 tree_cache
- `P3-S-061` none fp get_href @ cairosvg/text.py:71 (conf 0.60): text.py:71 node.get_href() 的取值仅被 fragment 消费(同 S-060),不驱动网络请求
- `P3-S-062` none fp get_href @ cairosvg/text.py:71 (conf 0.60): text.py:71 parent.get_href() 的取值仅被 fragment 消费(同 S-060),不驱动网络请求

## Sanitizers

0 sanitizer labels. Verified absent in source: no URL scheme allowlist, no host allowlist, no private-IP/loopback blocking, no redirect policy anywhere in cairosvg/; `read_url`'s docstring states the default fetcher has "no limitations" (cairosvg/url.py:133-135). defusedxml forbid_entities/forbid_external (cairosvg/parser.py:390-392) is XXE containment only and is disabled by caller-controlled `unsafe=True` - it does not intercept the SSRF fetch path, so it is not labeled as a CWE-918 sanitizer. The only structural mitigation available to integrators is injecting a restrictive `url_fetcher` (cairosvg/parser.py:354); the library performs no URL validation.

## Key sink / source inventory

Sinks (2): `urllib.request.urlopen` arg 0 @ cairosvg/url.py:84 (tp, 0.95) - the only network egress; `url_fetcher` dynamic dispatch arg 0 @ cairosvg/url.py:143 (candidate, 0.80) - unresolved dispatch boundary.

Broadest sources: 19 public-entry parameter labels (svg2* x5, Surface.convert, CLI stdin) - all classification `candidate` because CairoSVG is a library and untrusted-ness depends on the host application; 11 document-derived reference reads (href/xlink:href/xml:base/@import url_token.value) - the canonical SSRF drivers when an untrusted document is converted.

Summary steps (24): the fetch wrapper chain Node.fetch_url -> read_url -> url_fetcher -> fetch -> urlopen and parse_url/Tree(url=...) composition sites.
