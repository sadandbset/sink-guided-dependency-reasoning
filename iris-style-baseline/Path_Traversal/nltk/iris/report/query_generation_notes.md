# Query Generation Notes - Augur Phase 2 Step 4-5 (nltk, Pass 1 Path Traversal)

- run_id: nltk-iris-pass1-step3-20261022  |  pass key: `path_traversal`  |  query id: `py/augur/nltk/pass1-path-traversal`
- generated: 2026-10-22 (same session as Phase 1 Step 3)  |  model: glm-5.3 via Claude Code CLI
- inputs: `labels/labels.json` (337 unique entries: 46 source / 128 sink / 0 sanitizer / 92 summary / 71 none), `labels/review_decision.json` (**not present** - see 0.3), `extraction/sources.csv` + `sinks.csv` (provenance of label locations), WORKFLOW.md Phase 2, references/python.md, references/patterns.md, assets/taint_query.ql.tmpl, and first-hand re-reading of the cited source lines.
- outputs: `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass1_PathTraversal.ql`, this report. Regeneration: `python -I report/gen2a.py && python -I report/gen2b.py && python -I report/gen2c.py`.
- **No compilation or analysis was executed** (per task contract: generation only). All QL API shapes used are either (a) proven by the Phase-1 extraction queries that RAN on this toolchain (CLI 2.25.1), or (b) verified by direct inspection of the local pack `codeql/python-all 7.1.2` (`DataFlow::Node.asExpr()`, `DataFlow::ParameterNode` + `getParameter()`, `DataFlow::ConfigSig` with `isSource/isSink/isBarrier/isAdditionalFlowStep`, `TaintTracking::Global<Config>`, `PathGraph`/`flowPath`).

## 0. Contract compliance

0.1 **Query metadata**: `@kind path-problem`, `@problem.severity error`, `@precision medium`, `@tags security external/cwe/cwe-022 external/cwe/cwe-023 external/cwe/cwe-036 external/cwe/cwe-073`, id `py/augur/nltk/pass1-path-traversal` - rendered from `assets/taint_query.ql.tmpl` with the Python import block required by WORKFLOW.md 5.2.1a.
0.2 **Layout**: qlpack.yml (`name: iris/nltk-cwe22`, dependency `codeql/python-all: "*"`) sits at the iris root; the four libraries live in `iris/libraries/`, the query in `iris/queries/`; the query imports them with dotted syntax (`import libraries.MySources` etc.) and every predicate interface referenced by the template exists: `MySources::isSource(DataFlow::Node, string)`, `MySinks::isSink(DataFlow::Node, string)`, `MySanitizers::isBarrier(DataFlow::Node, string)`, `MySummaries::isAdditionalTaintStep(DataFlow::Node, DataFlow::Node, string)`, all gated on the unified pass key `"path_traversal"`.
0.3 **Review gate status**: `labels/review_decision.json` does not exist in the workspace (the Phase-1 checkpoint produced `labels/phase1_review.md` only; WORKFLOW.md 4.5 declares review_decision.json an optional audit artifact). Per the task instruction that the Step-5 review has been performed, `labels/labels.json` as generated is treated as the reviewed, frozen input. No entry of labels.json was modified; no rollback to Step 5 was needed for coverage reasons (two benign label artifacts are recorded in section 6.5 with a re-audit recommendation).

## 1. Label ID -> QLL predicate mapping

Every label entry maps 1:1 to one clause of one library predicate; the label id and classification/confidence are kept as QL comments at each clause for auditability.

| role | entries | rendered into | matching strategy |
| --- | --- | --- | --- |
| source | 46 | `MySources.qll` (`isSource` via 4 helper predicates + `AuditedSourceParameter` class) | field/return kinds: location-anchored AST (Attribute/Call + file + start line, same shapes as the proven extraction); param kind: Function/Class/Parameter name matching ported 1:1 from `extraction/sources.ql:fileApiParamShape` (labels' line = def line; name-based matching avoids multi-line-signature line drift, e.g. StanfordTagger :48-:55) |
| sink | 128 | `MySinks.qll` (`auditedSinkCall` + `isSink`) | location-anchored Call (callee Name/Attribute form from the label's receiver hint + file + start line); sink node = `c.getArg(0)` (all audited sink rows carry arg_index 0) |
| sanitizer | 0 | `MySanitizers.qll` | `none()` - no sanitizer-role labels exist (see section 5) |
| summary | 92 | `MySummaries.qll` (`auditedSummaryCall` + `propagationCallStep`) | location-anchored Call; step = any-argument -> call result (rendering decision, section 6.1) |
| none | 71 | (not rendered) | operator-trust env/input rows, guard reads, content-only returns, in-archive member names - excluded by the audited labels |

Label-by-label rendering (id, classification, location, QL clause anchor):

### MySources.qll (46)

| label id | cls | node | anchor |
| --- | --- | --- | --- |
| p1-s-001 | tp | lib_api_param (public API parameter) | nltk/corpus/reader/api.py:47 |
| p1-s-002 | tp | lib_api_param (public API parameter) | nltk/corpus/reader/api.py:47 |
| p1-s-003 | tp | lib_api_param (public API parameter) | nltk/corpus/reader/api.py:159 |
| p1-s-004 | tp | lib_api_param (public API parameter) | nltk/corpus/reader/api.py:204 |
| p1-s-005 | tp | lib_api_param (public API parameter) | nltk/sem/chat80.py:410 |
| p1-s-006 | tp | lib_api_param (public API parameter) | nltk/sem/chat80.py:450 |
| p1-s-007 | tp | lib_api_param (public API parameter) | nltk/twitter/common.py:93 |
| p1-s-008 | tp | lib_api_param (public API parameter) | nltk/twitter/common.py:137 |
| p1-s-009 | tp | lib_api_param (public API parameter) | nltk/twitter/common.py:158 |
| p1-s-012 | tp | lib_api_param (public API parameter) | nltk/data.py:324 |
| p1-s-013 | tp | lib_api_param (public API parameter) | nltk/data.py:353 |
| p1-s-014 | tp | lib_api_param (public API parameter) | nltk/data.py:497 |
| p1-s-018 | tp | lib_api_param (public API parameter) | nltk/data.py:589 |
| p1-s-019 | tp | lib_api_param (public API parameter) | nltk/data.py:704 |
| p1-s-020 | tp | lib_api_param (public API parameter) | nltk/data.py:704 |
| p1-s-021 | tp | lib_api_param (public API parameter) | nltk/data.py:781 |
| p1-s-023 | tp | http_request_path / net_xml_attr (attribute read) | nltk/downloader.py:286 |
| p1-s-024 | tp | http_request_path / net_xml_attr (attribute read) | nltk/downloader.py:287 |
| p1-s-025 | tp | http_request_path / net_xml_attr (attribute read) | nltk/downloader.py:288 |
| p1-s-026 | tp | http_request_path / net_xml_attr (attribute read) | nltk/downloader.py:327 |
| p1-s-027 | tp | http_request_path / net_xml_attr (attribute read) | nltk/downloader.py:328 |
| p1-s-028 | tp | http_request_path / net_xml_attr (attribute read) | nltk/downloader.py:330 |
| p1-s-030 | candidate | lib_api_param (public API parameter) | nltk/downloader.py:622 |
| p1-s-031 | candidate | lib_api_param (public API parameter) | nltk/downloader.py:684 |
| p1-s-033 | candidate | lib_api_param (public API parameter) | nltk/downloader.py:756 |
| p1-s-035 | tp | net_fetch / archive_entry (call return) | nltk/downloader.py:962 |
| p1-s-042 | tp | lib_api_param (public API parameter) | nltk/downloader.py:2239 |
| p1-s-043 | tp | lib_api_param (public API parameter) | nltk/downloader.py:2239 |
| p1-s-044 | tp | lib_api_param (public API parameter) | nltk/downloader.py:2249 |
| p1-s-045 | tp | lib_api_param (public API parameter) | nltk/downloader.py:2249 |
| p1-s-046 | tp | net_fetch / archive_entry (call return) | nltk/downloader.py:2264 |
| p1-s-051 | tp | lib_api_param (public API parameter) | nltk/tag/perceptron.py:109 |
| p1-s-052 | tp | lib_api_param (public API parameter) | nltk/tag/perceptron.py:114 |
| p1-s-053 | tp | lib_api_param (public API parameter) | nltk/tag/perceptron.py:239 |
| p1-s-054 | candidate | lib_api_param (public API parameter) | nltk/tag/stanford.py:50 |
| p1-s-055 | candidate | lib_api_param (public API parameter) | nltk/tag/stanford.py:51 |
| p1-s-058 | tp | lib_api_param (public API parameter) | nltk/parse/transitionparser.py:505 |
| p1-s-059 | tp | lib_api_param (public API parameter) | nltk/parse/transitionparser.py:546 |
| p1-s-060 | tp | lib_api_param (public API parameter) | nltk/twitter/twitterclient.py:447 |
| p1-s-061 | tp | lib_api_param (public API parameter) | nltk/twitter/twitterclient.py:448 |
| p1-s-062 | tp | lib_api_param (public API parameter) | nltk/corpus/reader/util.py:131 |
| p1-s-064 | candidate | lib_api_param (public API parameter) | nltk/corpus/util.py:53 |
| p1-s-065 | tp | lib_api_param (public API parameter) | nltk/twitter/util.py:47 |
| p1-s-066 | tp | lib_api_param (public API parameter) | nltk/twitter/util.py:47 |
| p1-s-067 | tp | lib_api_param (public API parameter) | nltk/twitter/util.py:123 |
| p1-s-068 | tp | http_request_path / net_xml_attr (attribute read) | nltk/app/wordnet_app.py:98 |

### MySinks.qll (128)

| label id | cls | callable | access type | location |
| --- | --- | --- | --- | --- |
| p1-k-069 | fp | open | file open (gzip/plain) | nltk/__init__.py:31 |
| p1-k-070 | fp | open | file open (gzip/plain) | nltk/metrics/agreement.py:468 |
| p1-k-071 | fp | remove | file/dir delete | nltk/sem/boxer.py:241 |
| p1-k-072 | fp | open | file open (gzip/plain) | nltk/app/chartparser_app.py:799 |
| p1-k-073 | fp | open | file open (gzip/plain) | nltk/app/chartparser_app.py:820 |
| p1-k-074 | fp | open | file open (gzip/plain) | nltk/app/chartparser_app.py:2278 |
| p1-k-075 | fp | open | file open (gzip/plain) | nltk/app/chartparser_app.py:2301 |
| p1-k-076 | fp | open | file open (gzip/plain) | nltk/app/chartparser_app.py:2316 |
| p1-k-077 | fp | open | file open (gzip/plain) | nltk/app/chartparser_app.py:2319 |
| p1-k-078 | fp | open | file open (gzip/plain) | nltk/app/chartparser_app.py:2333 |
| p1-k-079 | fp | open | file open (gzip/plain) | nltk/app/chartparser_app.py:2336 |
| p1-k-080 | tp | connect | sqlite db open | nltk/sem/chat80.py:431 |
| p1-k-081 | tp | connect | sqlite db open | nltk/sem/chat80.py:462 |
| p1-k-083 | fp | open | file open (gzip/plain) | nltk/sem/chat80.py:683 |
| p1-k-085 | fp | open | file open (gzip/plain) | nltk/app/chunkparser_app.py:1398 |
| p1-k-086 | fp | open | file open (gzip/plain) | nltk/app/chunkparser_app.py:1419 |
| p1-k-087 | fp | open | file open (gzip/plain) | nltk/app/chunkparser_app.py:1434 |
| p1-k-088 | tp | open | file open (gzip/plain) | nltk/twitter/common.py:143 |
| p1-k-089 | tp | open | file open (gzip/plain) | nltk/twitter/common.py:145 |
| p1-k-090 | tp | open | file open (gzip/plain) | nltk/twitter/common.py:149 |
| p1-k-091 | tp | open | file open (gzip/plain) | nltk/twitter/common.py:151 |
| p1-k-093 | candidate | open | file open (gzip/plain) | nltk/corpus/reader/crubadan.py:83 |
| p1-k-094 | candidate | open | file open (gzip/plain) | nltk/corpus/reader/crubadan.py:85 |
| p1-k-097 | candidate | open | file open (gzip/plain) | nltk/corpus/reader/crubadan.py:104 |
| p1-k-098 | candidate | open | file open (gzip/plain) | nltk/corpus/reader/crubadan.py:106 |
| p1-k-108 | candidate | GzipFile | file open (gzip/plain) | nltk/data.py:135 |
| p1-k-116 | tp | open | file open (gzip/plain) | nltk/data.py:345 |
| p1-k-119 | tp | BufferedGzipFile | file open (gzip/plain) | nltk/data.py:482 |
| p1-k-120 | tp | GzipFile | file open (gzip/plain) | nltk/data.py:484 |
| p1-k-121 | tp | OpenOnDemandZipFile | zip archive open | nltk/data.py:506 |
| p1-k-122 | tp | abspath | file open | nltk/data.py:506 |
| p1-k-123 | fp | BufferedGzipFile | file open (gzip/plain) | nltk/data.py:557 |
| p1-k-124 | fp | GzipFile | file open (gzip/plain) | nltk/data.py:559 |
| p1-k-137 | tp | open | file open (gzip/plain) | nltk/data.py:732 |
| p1-k-138 | tp | open | file open (gzip/plain) | nltk/data.py:1064 |
| p1-k-139 | fp | open | file open (gzip/plain) | nltk/tbl/demo.py:252 |
| p1-k-140 | fp | open | file open (gzip/plain) | nltk/tbl/demo.py:259 |
| p1-k-141 | fp | open | file open (gzip/plain) | nltk/tbl/demo.py:320 |
| p1-k-142 | fp | open | file open (gzip/plain) | nltk/tbl/demo.py:330 |
| p1-k-143 | fp | open | file open (gzip/plain) | nltk/tbl/demo.py:333 |
| p1-k-144 | tp | open | file open (gzip/plain) | nltk/corpus/reader/dependency.py:45 |
| p1-k-145 | tp | open | file open (gzip/plain) | nltk/parse/dependencygraph.py:247 |
| p1-k-146 | tp | open | file open (gzip/plain) | nltk/metrics/distance.py:265 |
| p1-k-150 | tp | remove | file/dir delete | nltk/downloader.py:704 |
| p1-k-152 | candidate | mkdir | directory create | nltk/downloader.py:708 |
| p1-k-155 | tp | mkdir | directory create | nltk/downloader.py:710 |
| p1-k-156 | tp | join | file open | nltk/downloader.py:710 |
| p1-k-157 | tp | open | file open (gzip/plain) | nltk/downloader.py:718 |
| p1-k-168 | candidate | walk | directory walk | nltk/downloader.py:923 |
| p1-k-173 | candidate | open | file open (gzip/plain) | nltk/downloader.py:2221 |
| p1-k-174 | tp | ZipFile | zip archive open | nltk/downloader.py:2255 |
| p1-k-176 | candidate | mkdir | directory create | nltk/downloader.py:2275 |
| p1-k-179 | tp | mkdir | directory create | nltk/downloader.py:2283 |
| p1-k-181 | tp | open | file open (gzip/plain) | nltk/downloader.py:2290 |
| p1-k-185 | fp | walk | directory walk | nltk/downloader.py:2443 |
| p1-k-187 | fp | walk | directory walk | nltk/downloader.py:2464 |
| p1-k-189 | fp | ZipFile | zip archive open | nltk/downloader.py:2471 |
| p1-k-212 | candidate | listdir | directory list | nltk/internals.py:770 |
| p1-k-217 | candidate | listdir | directory list | nltk/internals.py:788 |
| p1-k-219 | candidate | listdir | directory list | nltk/internals.py:809 |
| p1-k-225 | candidate | walk | directory walk | nltk/internals.py:862 |
| p1-k-228 | tp | open | file open (gzip/plain) | nltk/corpus/reader/ipipan.py:72 |
| p1-k-229 | tp | open | file open (gzip/plain) | nltk/corpus/reader/ipipan.py:203 |
| p1-k-230 | tp | open | file open (gzip/plain) | nltk/corpus/reader/lin.py:44 |
| p1-k-231 | fp | open | file open (gzip/plain) | nltk/parse/malt.py:213 |
| p1-k-232 | fp | remove | file/dir delete | nltk/parse/malt.py:225 |
| p1-k-233 | fp | remove | file/dir delete | nltk/parse/malt.py:226 |
| p1-k-234 | fp | remove | file/dir delete | nltk/parse/malt.py:299 |
| p1-k-236 | fp | open | file open (gzip/plain) | nltk/classify/maxent.py:1455 |
| p1-k-237 | fp | remove | file/dir delete | nltk/classify/maxent.py:1493 |
| p1-k-238 | fp | open | file open (gzip/plain) | nltk/classify/maxent.py:1557 |
| p1-k-239 | fp | remove | file/dir delete | nltk/classify/maxent.py:1560 |
| p1-k-240 | fp | remove | file/dir delete | nltk/classify/maxent.py:1561 |
| p1-k-250 | candidate | walk | directory walk | nltk/chunk/named_entity.py:215 |
| p1-k-251 | candidate | open | file open (gzip/plain) | nltk/chunk/named_entity.py:230 |
| p1-k-252 | candidate | open | file open (gzip/plain) | nltk/chunk/named_entity.py:242 |
| p1-k-253 | fp | open | file open (gzip/plain) | nltk/chunk/named_entity.py:343 |
| p1-k-256 | tp | open | file open (gzip/plain) | nltk/corpus/reader/nkjp.py:258 |
| p1-k-257 | fp | remove | file/dir delete | nltk/corpus/reader/nkjp.py:282 |
| p1-k-258 | tp | connect | sqlite db open | nltk/corpus/reader/panlex_lite.py:46 |
| p1-k-259 | tp | join | file open | nltk/corpus/reader/panlex_lite.py:46 |
| p1-k-260 | tp | open | file open (gzip/plain) | nltk/tag/perceptron.py:111 |
| p1-k-261 | tp | open | file open (gzip/plain) | nltk/tag/perceptron.py:235 |
| p1-k-262 | tp | open | file open (gzip/plain) | nltk/tag/perceptron.py:322 |
| p1-k-263 | tp | open | file open (gzip/plain) | nltk/corpus/reader/pl196x.py:114 |
| p1-k-264 | fp | open | file open (gzip/plain) | nltk/tokenize/punkt.py:1492 |
| p1-k-265 | fp | connect | sqlite db open | nltk/sem/relextract.py:329 |
| p1-k-276 | fp | unlink | file/dir delete | nltk/parse/stanford.py:273 |
| p1-k-277 | fp | unlink | file/dir delete | nltk/tag/stanford.py:121 |
| p1-k-278 | fp | unlink | file/dir delete | nltk/tokenize/stanford.py:117 |
| p1-k-281 | fp | unlink | file/dir delete | nltk/tokenize/stanford_segmenter.py:277 |
| p1-k-282 | tp | open | file open (gzip/plain) | nltk/toolbox.py:46 |
| p1-k-283 | tp | open | file open (gzip/plain) | nltk/parse/transitionparser.py:542 |
| p1-k-284 | tp | open | file open (gzip/plain) | nltk/parse/transitionparser.py:556 |
| p1-k-285 | fp | open | file open (gzip/plain) | nltk/tree.py:821 |
| p1-k-286 | fp | remove | file/dir delete | nltk/tree.py:823 |
| p1-k-287 | fp | remove | file/dir delete | nltk/tree.py:824 |
| p1-k-289 | tp | mkdir | directory create | nltk/twitter/twitterclient.py:497 |
| p1-k-291 | tp | open | file open (gzip/plain) | nltk/twitter/twitterclient.py:518 |
| p1-k-292 | tp | open | file open (gzip/plain) | nltk/twitter/twitterclient.py:520 |
| p1-k-293 | tp | open | file open (gzip/plain) | nltk/sem/util.py:147 |
| p1-k-294 | tp | open | file open (gzip/plain) | nltk/util.py:208 |
| p1-k-295 | tp | open | file open (gzip/plain) | nltk/sentiment/util.py:280 |
| p1-k-296 | tp | open | file open (gzip/plain) | nltk/sentiment/util.py:303 |
| p1-k-297 | tp | open | file open (gzip/plain) | nltk/sentiment/util.py:394 |
| p1-k-298 | tp | open | file open (gzip/plain) | nltk/sentiment/util.py:465 |
| p1-k-299 | tp | open | file open (gzip/plain) | nltk/sentiment/util.py:486 |
| p1-k-301 | tp | open | file open (gzip/plain) | nltk/corpus/reader/util.py:218 |
| p1-k-302 | tp | open | file open (gzip/plain) | nltk/corpus/reader/util.py:221 |
| p1-k-304 | tp | remove | file/dir delete | nltk/corpus/reader/util.py:540 |
| p1-k-305 | tp | open | file open (gzip/plain) | nltk/corpus/reader/util.py:548 |
| p1-k-306 | candidate | walk | directory walk | nltk/corpus/reader/util.py:821 |
| p1-k-310 | tp | open | file open (gzip/plain) | nltk/twitter/util.py:91 |
| p1-k-312 | tp | open | file open (gzip/plain) | nltk/twitter/util.py:138 |
| p1-k-316 | fp | open | file open (gzip/plain) | nltk/draw/util.py:1871 |
| p1-k-320 | candidate | ZipFile | zip archive open | nltk/classify/weka.py:74 |
| p1-k-322 | fp | listdir | directory list | nltk/classify/weka.py:139 |
| p1-k-323 | fp | remove | file/dir delete | nltk/classify/weka.py:140 |
| p1-k-324 | fp | join | file open | nltk/classify/weka.py:140 |
| p1-k-325 | fp | rmdir | file/dir delete | nltk/classify/weka.py:141 |
| p1-k-327 | fp | listdir | directory list | nltk/classify/weka.py:246 |
| p1-k-328 | fp | remove | file/dir delete | nltk/classify/weka.py:247 |
| p1-k-329 | fp | join | file open | nltk/classify/weka.py:247 |
| p1-k-330 | fp | rmdir | file/dir delete | nltk/classify/weka.py:248 |
| p1-k-331 | tp | open | file open (gzip/plain) | nltk/classify/weka.py:282 |
| p1-k-335 | fp | open | file open (gzip/plain) | nltk/app/wordnet_app.py:122 |
| p1-k-336 | fp | open | file open (gzip/plain) | nltk/app/wordnet_app.py:229 |
| p1-k-337 | tp | open | file open (gzip/plain) | nltk/corpus/reader/xmldocs.py:173 |

### MySummaries.qll (92 propagation sites + 6 handoff edge groups)

| label id | cls | callable | location |
| --- | --- | --- | --- |
| p1-k-092 | tp | join | nltk/corpus/reader/crubadan.py:78 |
| p1-k-095 | tp | join | nltk/corpus/reader/crubadan.py:97 |
| p1-k-099 | fp | expanduser | nltk/data.py:93 |
| p1-k-100 | fp | expanduser | nltk/data.py:94 |
| p1-k-101 | fp | join | nltk/data.py:99 |
| p1-k-102 | fp | join | nltk/data.py:100 |
| p1-k-103 | fp | join | nltk/data.py:101 |
| p1-k-104 | fp | join | nltk/data.py:102 |
| p1-k-105 | fp | join | nltk/data.py:110 |
| p1-k-106 | fp | join | nltk/data.py:111 |
| p1-k-107 | fp | join | nltk/data.py:112 |
| p1-k-110 | tp | normpath | nltk/data.py:257 |
| p1-k-111 | tp | abspath | nltk/data.py:261 |
| p1-k-112 | tp | join | nltk/data.py:261 |
| p1-k-114 | tp | abspath | nltk/data.py:331 |
| p1-k-118 | tp | join | nltk/data.py:354 |
| p1-k-125 | fp | normpath | nltk/data.py:575 |
| p1-k-126 | fp | join | nltk/data.py:575 |
| p1-k-129 | tp | join | nltk/data.py:650 |
| p1-k-130 | tp | url2pathname | nltk/data.py:650 |
| p1-k-132 | tp | join | nltk/data.py:657 |
| p1-k-133 | tp | url2pathname | nltk/data.py:657 |
| p1-k-136 | tp | abspath | nltk/data.py:722 |
| p1-k-147 | tp | join | nltk/downloader.py:270 |
| p1-k-148 | tp | join | nltk/downloader.py:700 |
| p1-k-153 | tp | exists | nltk/downloader.py:709 |
| p1-k-154 | tp | join | nltk/downloader.py:709 |
| p1-k-158 | tp | join | nltk/downloader.py:740 |
| p1-k-159 | tp | exists | nltk/downloader.py:743 |
| p1-k-160 | tp | join | nltk/downloader.py:743 |
| p1-k-161 | tp | join | nltk/downloader.py:888 |
| p1-k-166 | tp | stat | nltk/downloader.py:922 |
| p1-k-167 | tp | join | nltk/downloader.py:922 |
| p1-k-170 | fp | expanduser | nltk/downloader.py:1091 |
| p1-k-171 | fp | join | nltk/downloader.py:1096 |
| p1-k-177 | tp | join | nltk/downloader.py:2281 |
| p1-k-180 | tp | join | nltk/downloader.py:2287 |
| p1-k-182 | fp | join | nltk/downloader.py:2341 |
| p1-k-184 | fp | join | nltk/downloader.py:2359 |
| p1-k-186 | fp | join | nltk/downloader.py:2446 |
| p1-k-188 | fp | join | nltk/downloader.py:2468 |
| p1-k-190 | tp | join | nltk/corpus/reader/framenet.py:1403 |
| p1-k-191 | tp | join | nltk/corpus/reader/framenet.py:1488 |
| p1-k-192 | tp | join | nltk/corpus/reader/framenet.py:1832 |
| p1-k-193 | candidate | join | nltk/internals.py:540 |
| p1-k-196 | candidate | join | nltk/internals.py:553 |
| p1-k-199 | fp | join | nltk/internals.py:576 |
| p1-k-201 | fp | join | nltk/internals.py:586 |
| p1-k-203 | candidate | join | nltk/internals.py:597 |
| p1-k-209 | fp | isfile | nltk/internals.py:763 |
| p1-k-210 | fp | join | nltk/internals.py:763 |
| p1-k-211 | fp | join | nltk/internals.py:767 |
| p1-k-213 | fp | join | nltk/internals.py:777 |
| p1-k-214 | fp | join | nltk/internals.py:781 |
| p1-k-216 | fp | join | nltk/internals.py:787 |
| p1-k-220 | candidate | join | nltk/internals.py:810 |
| p1-k-222 | candidate | join | nltk/internals.py:818 |
| p1-k-224 | candidate | join | nltk/internals.py:861 |
| p1-k-235 | tp | join | nltk/tag/mapping.py:60 |
| p1-k-241 | tp | join | nltk/corpus/reader/mte.py:269 |
| p1-k-242 | tp | join | nltk/corpus/reader/mte.py:283 |
| p1-k-243 | tp | join | nltk/corpus/reader/mte.py:297 |
| p1-k-244 | tp | join | nltk/corpus/reader/mte.py:311 |
| p1-k-245 | tp | join | nltk/corpus/reader/mte.py:330 |
| p1-k-246 | tp | join | nltk/corpus/reader/mte.py:349 |
| p1-k-247 | tp | join | nltk/corpus/reader/mte.py:368 |
| p1-k-248 | tp | join | nltk/corpus/reader/mte.py:387 |
| p1-k-249 | tp | join | nltk/corpus/reader/mte.py:407 |
| p1-k-254 | tp | join | nltk/corpus/reader/nkjp.py:68 |
| p1-k-255 | tp | join | nltk/corpus/reader/nkjp.py:253 |
| p1-k-266 | tp | normpath | nltk/classify/senna.py:62 |
| p1-k-268 | fp | normpath | nltk/classify/senna.py:71 |
| p1-k-270 | candidate | join | nltk/classify/senna.py:91 |
| p1-k-271 | candidate | join | nltk/classify/senna.py:92 |
| p1-k-272 | candidate | join | nltk/classify/senna.py:94 |
| p1-k-273 | candidate | join | nltk/classify/senna.py:96 |
| p1-k-274 | candidate | join | nltk/classify/senna.py:97 |
| p1-k-279 | fp | join | nltk/tokenize/stanford_segmenter.py:139 |
| p1-k-280 | candidate | join | nltk/tokenize/stanford_segmenter.py:181 |
| p1-k-290 | tp | join | nltk/twitter/twitterclient.py:499 |
| p1-k-307 | tp | normpath | nltk/twitter/util.py:84 |
| p1-k-308 | tp | join | nltk/twitter/util.py:85 |
| p1-k-311 | fp | join | nltk/twitter/util.py:130 |
| p1-k-314 | tp | expanduser | nltk/twitter/util.py:152 |
| p1-k-315 | tp | join | nltk/twitter/util.py:152 |
| p1-k-317 | fp | exists | nltk/classify/weka.py:52 |
| p1-k-318 | fp | join | nltk/classify/weka.py:52 |
| p1-k-319 | fp | join | nltk/classify/weka.py:53 |
| p1-k-321 | fp | join | nltk/classify/weka.py:106 |
| p1-k-326 | fp | join | nltk/classify/weka.py:223 |
| p1-k-332 | tp | unquote_plus | nltk/app/wordnet_app.py:99 |
| p1-k-333 | tp | unquote_plus | nltk/app/wordnet_app.py:118 |

## 2. Source boundaries and access conditions

nltk is a library; the audited trust model distinguishes three genuinely untrusted input classes plus the operator class (excluded):

1. **HTTP request path** (`p1-s-068`, wordnet_app.py:98): `self.path` read in `MyServerHandler.do_GET`; the demo server `HTTPServer(('', port), MyServerHandler)` (:247) binds ALL interfaces, so any network peer that can reach the port controls this value. Percent-decoded by `unquote_plus` (:99/:118) before the only filesystem-reaching branch (`open(usp)` :122, exact-literal-guarded).
2. **Downloader network inputs** (`p1-s-023`..`p1-s-028`, `p1-s-035`, `p1-s-046`): (a) the XML index attributes read in `Package.fromxml`/`Collection.fromxml` - trust boundary = the data server (URL operator-configurable via DEFAULT_URL/NLTK_DOWNLOAD_URL/:1284); the attributes become `Package.filename = os.path.join(subdir, id + ext)` (:270) and reach `join(download_dir, ...)` (:700/:709/:740) -> `open`/`mkdir`/`remove`/`_unzip_iter`; (b) `urlopen(self._url)` (:962) - the index download entry; (c) `zf.namelist()` (:2264) - entry names of the downloaded package zip that drive the unfiltered `join(root, *pieces)` extraction (zip-slip).
3. **Public library API parameters** (37 entries): the application-facing boundary of a library - whoever calls `nltk.data.find/resource load`, the path-pointer constructors/joins, `CorpusReader(root, fileids)`/`.open`/`.abspath`, `StreamBackedCorpusView(fileid)`, `LazyCorpusLoader(name)` (candidate), `unzip/_unzip_iter(filename, root)`, `Downloader.download/incr_download/_download_package(download_dir)` (candidates - base dirs), the twitter writer/credentials params, model save/load paths and chat80 `dbname`. Access condition: the embedding application must pass attacker-influenced values (the standard library-CVE pattern); no authentication/authorization layer exists inside nltk.
4. **Excluded (role=none)**: `os.environ.get` (NLTK_DATA/APPDATA/NLTK_DOWNLOAD_URL/STANFORD_SEGMENTER - operator trust: env control implies host control), interactive `input()` rows (operator terminal; :1276/:1284 kept as classification=candidate review points), content-only `urlopen` returns (:717/:998), in-archive member scans (`data.py:522`, `corpus/reader/util.py:807`, index-builder namelists), `build_index` root (operator tooling).

## 3. Dangerous sinks: operation, argument, access type, call relationships

All 128 sink entries take the dangerous path as **positional argument 0** (verified per site against the source); the sink node is the path TEXT (an expression), never the resulting file object - e.g. for `data.py:557/:559` the labels note that `GzipFile(self._entry, fileobj=stream)` does not open a file through the entry name (fileobj provided), and those two entries are classification fp. Highlights by channel:
- **Central resource read**: `open(self._path, 'rb')` data.py:345 (`p1-k-116`, tp 0.95) fed by `find()` joins (:650/:657) and `FileSystemPathPointer.join` (:354); gzip variants :482/:484.
- **Zip-slip writes** (strongest CWE-22 channel): `open(filepath, 'wb')` downloader.py:2290 and `os.mkdir(dirpath)` :2283 (`p1-k-181`/`p1-k-179`, tp 0.9-0.95) - filepath/dirpath from `os.path.join(root, *filename.split('/'))` (:2287) / `join(root, *pieces[:i+1])` (:2281) with network-controlled entry names; `os.mkdir(os.path.join(download_dir, info.subdir))` :710 (XML subdir).
- **XML-index-driven writes/deletes**: `open(filepath, 'wb')` :718, `os.remove(filepath)` :704 (arbitrary-file delete via stale-package removal), `zipfile.ZipFile(filename)` :2255.
- **retrieve() write**: `open(filename, 'wb')` data.py:732 (explicit param or URL-derived name).
- **Pointer/corpus reads**: `codecs.open`/`open` in the corpus readers (ipipan, lin, pl196x, xmldocs, dependency, util.py:218/:221/:548), `sqlite3.connect` (chat80 :431/:462 via `find`, panlex_lite :46), twitter writes (common.py :143/:145/:149/:151, twitterclient :518/:520, util :91/:138), model files (perceptron :111/:235/:322, transitionparser :542/:556).
- **Fixed/tempfile/operator sites** (classification fp): tkinter dialog opens, optparse demo, tempfile mkstemp/mkdtemp cleanups, fixed literals (`/tmp/punkt.new`, `chat_pnames.cfg`, VERSION), GzipFile-with-fileobj sites.

## 4. Join/decode/normalize, allowed-root, symlink evidence

- **Joins** (47 summary sites): `os.path.join` keeps `..` lexically and an absolute component REPLACES the base - the escape primitive at data.py:650/:657 (find), :354 (pointer join), downloader.py:2281/:2287 (extraction), :700/:709/:740 (XML-index), mte/framenet/nkjp/crubadan reader joins. No site performs a post-join prefix check.
- **Decodes** (4 summary sites, CWE-36): `url2pathname(resource_name)` BEFORE the join at data.py:650/:657 (`%2e%2e%2f` -> `../`, bypassing any naive `..` check; note normpath at :257 runs BEFORE the decode, so decode happens on the already-normalized name - a mixed-decoder ordering hazard); `unquote_plus(sp)` wordnet_app.py:99/:118 on the HTTP request path.
- **Normalization** (13 summary sites): `normpath` data.py:257 resolves interior `..` but PRESERVES a leading `../..`; `abspath` :331/:506/:261 and `normpath` twitter/util.py:84 resolve lexically but confine to NOTHING; `expanduser` adds `~` expansion only. None is a containment check - all are propagation steps.
- **Allowed root**: the only "declared roots" are `download_dir`/`root` parameters and the `nltk.data.path` search dirs - none is enforced at any use site (no startswith/relative_to/realpath anywhere in the audited flows).
- **Symlinks**: `os.walk(root.path, followlinks=True)` corpus/reader/util.py:821 follows symlinked corpus subdirs during fileid discovery (sink candidate `p1-k-306`, CWE-59-adjacent); no realpath canonicalization exists in the corpus layer; TOCTOU shapes: wordnet :121 isfile vs :122 open (dominated by the exact-literal guard), data.py:648-:658 existence checks vs the :345 open. No symlink creation (`os.symlink`) anywhere in the tree.

## 5. Barrier analysis

`MySanitizers::isBarrier` returns `none()` because the audited labels contain ZERO sanitizer-role entries, and first-hand verification confirms no callable in the audited flows neutralizes traversal:
- `os.path.normpath` (data.py:257) - preserves leading `..`; labeled summary (propagation).
- `os.path.abspath` (data.py:331/:506/:261/:722) - resolves without confining; labeled summary.
- `os.path.exists/isfile/isdir` (54 sites) - existence probes only, no neutralization; labeled none.
- The ONE real neutralization in the target - the exact literal guard `usp == 'NLTK Wordnet Browser Database Info.html'` (wordnet_app.py:119) in front of `open(usp)` :122 - is a control-flow equality gate on a single site, not a data transformation and not a candidate row; the audited label for that sink is `p1-k-335` classification=fp with the guard as evidence. It is therefore NOT modeled as isBarrier (that would be an unevidenced generalization); the alert is expected to be filtered by the Step-6 fixed-filename-mapping heuristic.

## 6. Additional propagation edges, gaps, limitations, diagnostics

### 6.1 Rendering decision (documented, not a label change)
The labels record `arg_index 0` for summary rows, but at several audited sites the traversal-bearing operand is NOT argument 0 (e.g. `os.path.join(path_, url2pathname(resource_name))` data.py:650 - the tainted component is the second operand). Rendering arg0-only edges would miss the audited find() channel, so `propagationCallStep` uses **any-argument -> call-result** edges at the 92 anchored call sites. This widens propagation only at the audited pure path-construction call sites; it creates no cross-function or unconditional edges.
### 6.2 The six handoff edges (`auditedHandoffStep`)
Syntax-level extraction cannot span these; each edge is anchored to audited source parameters and audited consuming attribute loads (label evidence citations in the QL comments):
- **A**: `**xml.attrib` (:288/:330) -> Package/Collection constructor params (id/url/name/subdir/children) - default dataflow does not model `**kwargs` dict expansion into parameters (detection.json uncoveredCases).
- **B1/B2/B3**: Package params subdir/id -> the `info.filename` loads (:700/:888), `info.subdir` loads (:709/:710/:740), `info.id` load (:743) - the `self.filename = join(subdir, id+ext)` field handoff (:270) plus cross-object attribute reads that field-flow may not resolve (info is a different local than self).
- **E1**: `FileSystemPathPointer.__init__` `_path` param -> `self._path` loads (:345/:351/:354/:482/:484) - guarantees the pointer-join channel even where field-flow branching is limited.
- **E2**: `CorpusReader.__init__` root param -> `self._root` loads (api.py:168/:213) and `self.root`/`self._root` loads of the crubadan (:78/:97) and mte (:269) readers.
### 6.3 Dynamic dispatch / aliasing NOT modeled (documented gaps)
`nltk.corpus` `__getattr__` lazy-loading indirection; `LazyCorpusLoader.__load__` pass-through (its `name` source stays a candidate); the downloader generator message plumbing (coroutine yields); `find_corpus_fileids` regexp expansion of fileids; `Package.__dict__.update(kw)` dynamic attribute sink; `six.moves.urllib.request.urlopen` aliasing (Name-matched, as proven by extraction); `GzipFileSystemPathPointer` subclass field reads (covered by E1 anyway); receiver-tainted method calls (`self._root.join(file)` - the receiver taint of `root` is not required for the audited fileid channel).
### 6.4 CodeQL limitations
Location-anchored matching is exact for THIS database (sha 2554ff4) but re-bases poorly (deliberate trade-off: the labels carry file/line provenance and the audit forbids broader matching); no compilation was run in this step (per contract), so QL compile diagnostics are deferred to the execution round; `getArg(0)` assumes the audited positional shape (verified per site); Python CodeQL has no `Decorator`/`StrConst` usage (WORKFLOW section 9 respected); `module` is never used as a variable name (moduleHint convention kept).
### 6.5 Label artifacts found during rendering (recorded, NOT fixed - labels are frozen)
The Phase-1 decision table was keyed by (file, line, argIndex); where two different callables share a line, both CSV rows inherited the same decision:
- `join` at downloader.py:710, weka.py:140/:247, panlex_lite.py:46 inherited the same-line sink decision (mkdir/remove/connect) -> rendered as 4 extra sink clauses on JOIN calls. Impact: benign-to-minor - the join at :710 can alert via the `download_dir` candidate sources (duplicate of the correct mkdir-sink alert); the weka/panlex joins sit on tempfile/operator-env paths with no labeled source. Recommendation: re-audit these 4 rows in a Step-5 review round (change role to summary); NOT executed here because labels.json must not be modified in this step.
- `exists`/`stat` at weka.py:52, downloader.py:709/:743/:922 inherited summary decisions -> arg->bool-result edges; inert (boolean results do not reach path arguments).
- No coverage rollback is required: every audited tp/candidate channel (zip-slip, XML-index, wordnet HTTP, find/pointer/corpus API params) is fully rendered.
### 6.6 Diagnostics (NOT part of the official Pass 1 alert set)
Suggested wrapper-reachability diagnostic (to be written separately if needed, not delivered in this round): a plain `@kind table` query selecting `AuditedSourceParameter` nodes joined with their enclosing Function's call sites (`Call.getFunc().(Attribute)` name matches), to verify during the execution round that the parameter sources are actually exercised; plus a `Pass1Flow::flowPath` count-by-source diagnostic. None of these produce Pass 1 alerts.

## 7. Experimental independence

Ground-truth artifacts at the source root (CVE-Report-NLTK-PathTraversal.md, NLTK-*-Report*.md, SECURITY_DISCLOSURE_EMAIL.md, path_traversal_sinks.csv) and the nltk/test tree were NOT opened; no PyVul truth, CVE line numbers or patch diffs were consulted. All modeling evidence comes from first-hand reading of the nltk/ source tree, the frozen Phase-1 labels, and the Augur assets/references. No source file, CodeQL database, Augur installation file or Phase-1 artifact (labels.json, CSVs) was modified; the only writes were the six deliverables (plus the deterministic generator scripts report/gen2*.py kept for auditability).

## 8. Compile verification (post-fix, at the reviewer's request)

The first check-only compile (`codeql query compile --check-only`) of the delivered files reported 4 errors in MySummaries.qll: `p() cannot be resolved for type IndexCtorParam/PointerParamNode` + `unexpected input '.'`. Root cause: QL class FIELDS are class-local - the handoff-edge predicates referenced the field `p` of the parameter-node classes from OUTSIDE the class bodies (`pn.p.getName()`). Fix (applied in the generator and regenerated, labels untouched): the three classes `IndexCtorParam`/`PointerParamNode`/`CorpusRootParamNode` now expose `Parameter getParam() { result = p }` and the edges use `pn.getParam().getName()`. Verified clean: `codeql query compile --check-only --additional-packs=<13 exact pack dirs> -- queries/Pass1_PathTraversal.ql` with CLI 2.25.1 and the version-pinned closure codeql/python-all 7.1.2 + concepts 0.0.25 + dataflow 2.1.7 + mad/regex/threat-models/tutorial/xml/yaml 1.0.51 + util 2.0.38 + controlflow/typetracking 2.0.35 + ssa 2.0.27 -> `Done [1/1]`, zero errors/warnings. (The bare user pack cache holds multiple versions per pack, which makes un-pinned `"*"` resolution ambiguous; passing the exact closure directories or a lockfile is required. `codeql pack install` cannot pin on this machine: CLI 2.25.1 fails to parse the 7.2.8 manifest fetched from the network.) No database analysis was run.

## 9. Execution round contract (next step, not performed here)

Per WORKFLOW.md 5.2: run `codeql pack install` (already resolved for this pack), then sequentially `codeql database analyze <db> queries/Pass1_PathTraversal.ql --format=sarifv2.1.0 --output=results/pass1.sarif`; expected alert families: (1) `zf.namelist()` -> join -> open/mkdir (zip-slip); (2) xml.attrib -> Package fields -> join -> open/mkdir/remove; (3) `self.path` -> unquote_plus -> open(usp) (fp by the :119 guard - to filter in Step 6); (4) public-API parameter sources -> pointer join -> open (:345) and the twitter/model-file sinks, whose exploitability depends on the embedding application (library threat model).
