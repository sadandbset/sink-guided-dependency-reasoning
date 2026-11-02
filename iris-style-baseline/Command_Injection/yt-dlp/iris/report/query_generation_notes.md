# Query Generation Notes — Augur Phase 2 Step 4–5 (Pass 2 / CWE-78, yt-dlp)

Date: 2026-10-19 · Generator: `glm-5.3` (Claude Code CLI agent) · Augur 0.3.0
Labels input: `iris/labels/labels.json`, run `yt-dlp-pass2-cwe78-20261019` (human-reviewed, 180 pass-2 entries)
Source tree: `dataset/codeql_databases/yt-dlp_vuln` (sha 61bdf15) — same snapshot as database `yt-dlp-db`.

## 0. Generated files and verification

| File | Content |
| --- | --- |
| `libraries/MySources.qll` | `MySources::isSource/2` — formal + diagnostics pass-key dispatch, sharded into 4 family modules |
| `libraries/MySinks.qll` | `MySinks::isSink/2` — shell-string / Popen-wrapper / internal-wrapper sink modules |
| `libraries/MySanitizers.qll` | `MySanitizers::isBarrier/2` — resolves to `none()` (empty reviewed sanitizer set) |
| `libraries/MySummaries.qll` | `MySummaries::isAdditionalTaintStep/3` — 3 step families, all per-call-site |
| `queries/Pass2_CommandInjection.ql` | formal path query, id `py/augur/yt-dlp/pass2-command-injection` |
| `diagnostics/Pass2_WrapperPropagation.ql` | diagnostics-only path query, id `py/augur/yt-dlp/pass2-wrapper-diagnostics` |

Both queries **compile clean** with `codeql query compile` (CLI 2.25.1; `codeql/python-all` resolved
locally — APIs cross-checked against the pack sources 7.1.x). No analysis was executed (no
`database analyze` / `query run`), per instruction. The temporary API-probe query used to validate
idioms during generation was removed.

Template compliance (`assets/taint_query.ql.tmpl`): all placeholders rendered —
`{{QUERY_ID}}` `py/augur/yt-dlp/pass2-command-injection`; `@kind path-problem` +
`@problem.severity error` (WORKFLOW 3.5); `@tags security` + `external/cwe/cwe-078`;
`{{PRECISION}}` medium; `{{LANGUAGE_IMPORTS}}` = `import python` +
`semmle.python.dataflow.new.{DataFlow,TaintTracking}`; `{{CONFIG_NAME}}` `Pass2Config`;
`{{FLOW_MODULE}}` `Pass2Flow` with `import Pass2Flow::PathGraph` and `flowPath(source, sink)`;
`{{PASS_KEY}}` `command_injection`. `qlpack.yml` (iris root, `iris/yt-dlp-cwe78`, dependency
`codeql/python-all: "*"`) is unchanged; libraries are imported with the dotted syntax
`import libraries.MySources`.

QL style constraints honored: no `module` used as a variable name (only as the QL module
keyword); no deprecated AST classes (`CallNode`/`StrConst` avoided — the AST classes used are
`Call`, `Name`, `Attribute`, `Function`, and `Parameter` via `Function.getArg`); API::Node →
DataFlow::Node conversions are made only through the documented interop (`asSource()`,
`asSink()`, `getACall()`, `DataFlow::exprNode()`, `DataFlow::parameterNode()`); ConfigSig
implements `isSource/isSink/isBarrier/isAdditionalFlowStep` and flows use
`TaintTracking::Global<Config>` (taint-style tracking: container/subscript/string-formatting
steps included, required for dict-borne metadata).

## 1. Label-ID → predicate mapping

### 1.1 Sources — `MySources::isSource(node, passKey)`

Pass keys: `command_injection` (formal) = external boundaries only;
`command_injection_diagnostics` = external boundaries **plus** the wrapper-recall family
(same two-key convention as the maltrail experiment; diagnostics results are not formal findings).

| Label IDs | Family (module in MySources.qll) | Matcher | Controllability |
| --- | --- | --- | --- |
| P2-044, P2-043 | `RemoteFetchSources` — `json.loads`/`json.load` returns | `API::moduleImport("json").getMember("loads"/"load").getReturn().asSource()` | remote (extractor APIs, update feed, info.json) |
| P2-104..P2-110, P2-112 | `RemoteFetchSources` — `_download_json(_handle)`, `_download_webpage(_handle)`, `_download_xml(_handle)`, `_download_socket_json`, `_request_webpage` returns | attribute-call result by method name (factory-generated methods, no static defs for the generated variants) | remote (the fetch+decode funnel; call sites across ~all extractors) |
| P2-054 | `.urlopen(...)` results | attribute-call result | remote (response handles) |
| P2-040 | `.read()` results | attribute-call result | remote/local mixed (receiver-ambiguous; label conf 0.6; Step 6 filters tests) |
| P2-041 | `.recv()` results | attribute-call result | remote (websocket frames, SOCKS protocol) |
| P2-114 | `opener.open(...)` results | attribute call, receiver name `opener` (networking/_urllib.py:410, update.py:459) | remote |
| P2-115 | `self._request_director.send(...)` | attribute call, receiver name `_request_director` (YoutubeDL.py:4051) | remote |
| P2-118 | `jwt_decode_hs256(...)` returns | bare-name call result | remote (JWT payload) |
| P2-045..P2-048 | `CliEnvConfigSources` — `parse_args`/`parse_known_args` returns | attribute-call result | local CLI/config values |
| P2-049/050/051 | `os.environ` (attr), `os.environ.get(...)` (API), `os.getenv(...)` (API) | mixed | environment |
| P2-052/053 | `sys.argv` / `sys.orig_argv` attribute nodes | attribute read on `sys` | local CLI (orig_argv → Updater.restart cmd) |
| P2-056..P2-098 (+P2-061) | 42 command-relevant `opts.<attr>` reads | attribute read on name `opts` (yt_dlp/__init__.py) | local CLI/config templates (see §2) |
| P2-113 | `get_param(...)` returns | attribute-call result | local config values (incl. `netrc_cmd` at common.py:1307 — **the --netrc-cmd shell string**) |
| P2-103 | `_configuration_args(...)` returns | attribute-call result | local config (child-process argv args) |
| P2-042 | `open(...)` results | bare-name call result | file content (config, cookies, info.json — remote-derived) |
| P2-099/100 | `extract_cookies_from_browser`/`load_cookies` returns | bare-name call result | cookie values (server-influenced → downloader argv) |
| P2-119 | `Config.read_file(...)` returns | attribute-call result | config file content (shlex-split to argv level) |
| P2-120 | `read_stdin(...)` returns | bare-name call result | stdin config |
| P2-111, P2-101/102, P2-117, P2-055/073/080/116 | `WrapperBoundarySources` — **diagnostics key only** | parameter nodes (see §4) | internal recall boundaries (NOT formal sources) |

Not rendered (role `none`, documented in the QLL headers): P2-001..017 `add_option`
registrations, P2-026 `_perform_login` credentials, P2-018/023/024/027/028 request-target
plumbing params, P2-019..039 generic option/format/container rows, and the 361 non-command CLI
option reads (label_stats.md).

### 1.2 Sinks — `MySinks::isSink(node, passKey)`

Both pass keys select the same 12 candidate sink signatures. The 6 fp-classified wrapper
labels (P2-163/164/165 keyring helpers, P2-173 `current_git_head`, P2-175
`_get_exe_version_output`, P2-176 `check_executable`) are **not rendered as distinct nodes**:
the subprocess executions inside them are already matched by the Popen family (P2-174/P2-177);
their site-level benign judgment lives in `labels_raw_pass2.json` and is applied by the Step 6
filter.

| Label ID | Signature | Module (in MySinks.qll) | Matcher & argument index |
| --- | --- | --- | --- |
| P2-162 | `subprocess.call` arg 0 | `ShellStringSinks` | `API::moduleImport("subprocess").getMember("call").getParameter(0).asSink()` |
| P2-161 | `atexit.register` arg 1 | `ShellStringSinks` | `API::moduleImport("atexit").getMember("register").getParameter(1).asSink()` (arg 0 is the Popen callable) |
| P2-177 | `yt_dlp.utils.Popen.run` arg 0 | `PopenWrapperSinks` | AST: attribute call `Popen.run(...)` positional arg 0; **plus** API-graph `API::moduleImport("yt_dlp.utils").getMember("Popen").getMember("run").getACall().getArg(0)` (dual route, see §5) |
| P2-174 | `yt_dlp.utils.Popen` ctor arg 0 | `PopenWrapperSinks` | AST: bare-name call `Popen(...)` positional arg 0; **plus** API-graph `...getMember("Popen").getACall().getArg(0)` |
| P2-167/168 | `ExternalFD._call_process` / `Aria2cFD._call_process` param 0 (cmd) | `InternalWrapperSinks` | `parameterNode(f.getArg(1))`, function name + file `yt_dlp/downloader/external.py` (one matcher covers both label entries) |
| P2-166 | `FFmpegFD._call_downloader` param 1 (info_dict) | `InternalWrapperSinks` | `parameterNode(f.getArg(2))`, name + file + param-name `info_dict` |
| P2-172 | `FFmpegPostProcessor.real_run_ffmpeg` param 0 | `InternalWrapperSinks` | `parameterNode(f.getArg(1))`, name + file `yt_dlp/postprocessor/ffmpeg.py` |
| P2-170 | `get_audio_codec` param 0 (path) | `InternalWrapperSinks` | `parameterNode(f.getArg(1))`, ffmpeg.py |
| P2-171 | `get_metadata_object` param 0 (path) | `InternalWrapperSinks` | `parameterNode(f.getArg(1))`, ffmpeg.py |
| P2-169 | `run_rtmpdump` param 0 (args) | `InternalWrapperSinks` | `parameterNode(f.getArg(0))` — nested function (rtmp.py:23, no self) |
| P2-178 | `write_xattr` param 2 (value) | `InternalWrapperSinks` | `parameterNode(f.getArg(2))` — module function (_utils.py:4416, no self) |

### 1.3 Sanitizers — `MySanitizers::isBarrier(node, passKey)`

Resolves to `none()` for both keys: zero sanitizer labels exist (7204 raw rows, sanitizer = 0).
Evidence for the deliberate non-barriers is in §3.

### 1.4 Summaries — `MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, passKey)`

| Label IDs | Step family | Shape |
| --- | --- | --- |
| P2-124/125/126/127, P2-121/122, P2-137 | `externalDecoderStep` — `urllib.parse.parse_qs/parse_qsl/unquote/unquote_plus`, `base64.b64decode/urlsafe_b64decode`, `zlib.decompress` | arg 0 → call result, bound per call site via `API::CallNode` |
| (evidenced helper, no label ID) | `externalDecoderStep` — `shlex.split` | arg 0 → call result (see §3) |
| P2-123 | `externalDecoderStep` — `os.path.expandvars` | arg 0 → call result |
| P2-129/130/131/132 | `internalHelperStep` — `_parse_json/_parse_xml/_search_json/_search_json_ld` | arg 0 → call result |
| P2-133/128 | `internalHelperStep` — `_search_regex/_html_search_regex` | arg 1 (remote text) → call result |
| P2-136/135 | `internalHelperStep` — `js_to_json`, `expand_path` | arg 0 → call result (bare-name calls) |
| P2-134 | `internalHelperStep` — `ExecPP.parse_cmd(cmd, info)` | arg 0 (template) and arg 1 (info) → returned command string |
| P2-179, P2-180 | `commandReplaceStep` — `cmd.replace(...)` | receiver `cmd` and arg 1 → result; pinned to `extractor/common.py` + `postprocessor/exec.py` |

## 2. Source-code evidence and controllability (per the six review directives)

1. **Remote decode does not restrict command parameters.** `_webpage_read_content`
   (common.py:978-995) only decodes charset; `_parse_json` (common.py:1011-1016) parses;
   decoders (P2-121..137) are modeled as taint-PRESERVING steps, never barriers.
2. **External input → commands, the real edges.** (a) remote metadata → `info_dict` fields →
   ExecPP outtmpl `%`-format (exec.py:17/30) → `subprocess.call(cmd, shell=True)` (exec.py:31);
   (b) remote values → filenames/URLs/headers → ffmpeg/external-downloader/rtmpdump argv;
   (c) local config templates (`opts.exec_cmd` P2-065, `opts.netrc_cmd` P2-075,
   `opts.postprocessor_args`/`external_downloader_args`/`sponskrub_args`, P2-082/067/089) —
   locally trusted on a clear boundary; modeled as sources only for the config→command edge.
3. **Shell string vs argv list, modeled per the actually dangerous argument.** Only 3
   shell=True string commands exist: exec.py:31 (`subprocess.call` **arg 0**), common.py:1311
   (`Popen.run` **arg 0**, the --netrc-cmd string, unquoted `str.replace` at :1309) and
   update.py:376 (`atexit.register` **arg 1**, program-controlled path). All other exec sites
   pass argv LISTS — dangerous argument is the list at arg 0 (Popen ctor/run) or the
   command-building wrapper parameter (InternalWrapperSinks). No `os.system/os.popen/os.exec*`
   exists in the tree.
4. **Internal functions** are split exactly as reviewed: entry/recall params → diagnostics-only
   sources; argv-building wrappers → sinks; parse/decode helpers → summaries; plumbing
   (`_request_webpage` params, `_perform_login`) → not modeled.
5. **Trust boundary.** Command templates are local config; the attacker-controlled side is the
   substituted remote metadata. The weak seam common.py:1309 (netrc_machine inserted unquoted)
   is a summary step (P2-179), not a barrier.
6. **No data check blocks dangerous characters.** exec.py:24 shlex-quotes only the legacy `{}`
   placeholder; `--` separators (external.py:223, sponskrub.py:83) are not modeled as barriers;
   FFmpegFD passes `fmt['url']` **without** a `--` guard (external.py:578) — an
   argument-injection candidate the taint run should surface.

## 3. Sanitizer and summary modeling evidence

- **Sanitizers: none.** Every mitigation candidate was individually rejected with code
  evidence (phase1_review.md §4): exec.py:24 partial quoting; `--` separators (option-injection
  only); `shlex.split` (tokenization, content untouched); update.py:82 `re.fullmatch`
  validates the git command's OUTPUT. The barrier predicate therefore resolves to `none()`
  and never blocks unconditionally (WORKFLOW 5.2.3).
- **shlex.split step** (no label ID; family-1 member): evidence is the reviewed labels'
  partial-mitigation observations — sponskrub.py:81 splits user `--sponskrub-args` into the
  sponskrub argv, and `Config.read_file` (utils/_utils.py:4866) splits config content to argv
  level. Without this step the reviewed `opts.sponskrub_args` (P2-089) and `read_file`
  (P2-119) sources cannot reach their sinks. Strictly per-call-site, never unconditional.
- **Summary steps are load-bearing where the callee is external** (json.loads, ElementTree,
  urllib.parse, base64, zlib): python-all's interprocedural analysis cannot follow external
  call bodies, so `_parse_json`'s argument would not reach its return without P2-129. The
  `%`-formatting / f-string / `+` / container / subscript steps the ExecPP and argv paths rely
  on are provided by python-all's default taint steps (verified in the pack sources:
  `TaintTrackingPrivate.stringManipulation/concatStep/containerStep/subscriptStep`) and are
  deliberately NOT duplicated, except the label-mandated `cmd.replace` redundancy
  (P2-179/180), constrained to a receiver named `cmd` in the two reviewed files.

## 4. Internal wrapper parameters are not formal sources (diagnostics query)

`WrapperBoundarySources` (P2-111 `_real_extract` url; P2-101/102 `real_download`
filename/info_dict; P2-117 `PostProcessor.run` info; P2-055/073/080/116 CLI entry argv params)
is admitted **only** under `command_injection_diagnostics`.
`diagnostics/Pass2_WrapperPropagation.ql` uses that key to verify, with full paths, that these
wrapper parameters locally propagate into the reviewed sinks (e.g.
`ExecPP.run(info) → parse_cmd → subprocess.call(shell=True)`;
`FFmpegFD._call_downloader(info_dict) → Popen(args)`). Its results are marked
DIAGNOSTIC in the name/description/select message and are **not counted as formal findings**;
the formal query keeps these wrappers out so no alert fires merely because data "already looks
tainted" at a wrapper boundary. This mirrors the maltrail two-key design, with the keys'
semantics adapted: maltrail's diagnostics key admitted unreviewed candidates, ours admits
reviewed internal recall boundaries.

## 5. Uncovered APIs, dynamic calls, known limitations

- **Factory-generated boundary methods.** `_download_json/_webpage/_xml` (+`_handle`) are
  generated at runtime by `__create_download_methods` (common.py:1021-1091) and dispatched via
  `getattr`; the generated variants have no static definitions. Modeled by method name at call
  sites (ast-style), matching the extraction families. The five explicit overrides
  (crackle/eagleplatform/soundcloud/udemy/postprocessor.common) are covered by the same
  name match.
- **Popen from-import resolution.** `from ..utils import Popen` may not resolve through
  `API::moduleImport("yt_dlp.utils")`, so every Popen site is matched twice: API-graph route
  + AST name route (bare `Popen(` / `Popen.run(`). The two routes match the same nodes
  (mirrors the redundant api/ast extraction families).
- **Attribute reads from the parse_args return are not natively tracked** (python-all has no
  object-field taint step for arbitrary attribute reads). This is why each command-relevant
  `opts.<attr>` read is its own source node (42 matchers) rather than relying on the
  `parse_args`-return source P2-045..048 (kept, but weak).
- **`write_xattr`** models position 2 (value) per the label signature; the path (param 0) is
  equally argv-relevant per the label rationale but is not a separate sink — remote-derived
  paths reach the same `Popen.run` argv via P2-177.
- **`real_run_ffmpeg`** models position 1 (input_path_opts = label arg_index 0);
  output_path_opts (label arg_index 1) is documented in the label and reaches the same
  execution site.
- **Broad name matches** (`.read()`, `.recv()`, `open()`, `get_param`, `_configuration_args`,
  `parse_args`) intentionally reproduce the reviewed label families, including test-file sites;
  test/dev filtering is deferred to Step 6 (WORKFLOW 5.3.2), not to sink shaping.
- **`PhantomJSwrapper.execute`** (openload.py:223): remote-derived JS travels via a temp FILE
  with fixed argv — a pass-4 code-injection concern; not modeled here (label role `none`).
- **Positional-argument convention.** Labels' `arg_index` excludes `self`; `Function.getArg`
  counts `self` at position 0. Every parameter matcher therefore passes `label_index + 1` for
  methods and `label_index` for module-level/nested functions (`run_rtmpdump` 0,
  `write_xattr` 2, CLI entries 0). This is documented in all three QLLs.
- **`atexit.register` argument index.** The CSV row carried argIndex 0 (the `Popen` callable);
  the reviewed label corrected the dangerous position to argument 1 (the command string) —
  the query uses 1.
- **Compile-only validation.** Per instruction, only `codeql query compile` was run (CLI
  2.25.1; `codeql/python-all` resolved from the local toolchain). Runtime behavior
  (alert volume, path completeness) is a Step 5 execution concern and was not exercised.

## 6. Modeling principles shared with the other experiments

- Two pass keys (`command_injection` / `command_injection_diagnostics`) with diagnostics
  results excluded from formal findings — same convention as maltrail.
- Label-mandated redundancy for steps python-all already models (maltrail note: "kept as
  label-mandated redundancy so the propagation survives even if the built-in modeling
  changes"); genuinely load-bearing steps are the external-call bridges and parse_cmd.
- `isBarrier` always present and resolvable to `none()` when the confirmed sanitizer set is
  empty (WORKFLOW 5.2.3; maltrail/`dcnnt-py` policy).
- Location pinning (`getLocation().getFile().getRelativePath()`) for site-specific matchers
  (maltrail `functionParamAt` idiom); family-shape matching for extractor-wide boundaries.
- Internal wrapper parameters never become formal sources by default — they are diagnostics
  material (task directive; consistent with maltrail's candidate handling).
- No ground truth consulted; project source, database, and Phase 1 labels unmodified.
