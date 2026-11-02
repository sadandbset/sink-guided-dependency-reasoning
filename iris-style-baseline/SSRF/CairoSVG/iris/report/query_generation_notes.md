# Query Generation Notes — Pass 3 (CWE-918 SSRF) / Phase 2 Step 4–5

生成时间:2026-10-19 · 项目:CairoSVG(快照 58be378)· 工具链:CodeQL CLI 2.25.1 + codeql/python-all 7.1.x(自 `~/.codeql/packages` 缓存解析)
输入:`iris/labels/labels.json`(Pass 3,run_id `cairosvg-pass3-cwe918-labeling-20261019`,经人工审核门 `labels/phase1_review.md`)
产出:4 个 QLL(`libraries/`)、1 个正式路径查询(`queries/Pass3_SSRF.ql`)、1 个诊断查询(`diagnostics/WrapperChainDiagnostic.ql`,不计入正式结果)。
本步骤只生成并编译验证文件,**未执行** `codeql database analyze`(按实验指令,正式分析待后续指令)。

关于 `labels/review_decision.json`:该文件在本工作区不存在。Phase 1 审查以 `labels/phase1_review.md` 为载体并停在人工审查关口;本次进入 Phase 2 的依据是操作者指令本身(指令明确引用"经过人工审核的 labels/labels.json"并指示执行 Step 4–5)。此差异如实记录,未补造审查文件。

## 1. 产出文件与接口契约

| 文件 | 接口 |
| --- | --- |
| `libraries/MySources.qll` | `module MySources { predicate isSource(DataFlow::Node, string passKey) }`,渲染 32 条 source 标签(10 个私有 source 类) |
| `libraries/MySinks.qll` | `module MySinks { predicate isSink(DataFlow::Node, string passKey) }`,渲染 2 条 sink 标签 |
| `libraries/MySanitizers.qll` | `module MySanitizers { predicate isBarrier(DataFlow::Node, string passKey) }`,解析为 `none()` |
| `libraries/MySummaries.qll` | `module MySummaries { predicate isAdditionalTaintStep(DataFlow::Node, DataFlow::Node, string passKey) }`,渲染 4 条有源码依据的自定义传播边 |
| `queries/Pass3_SSRF.ql` | 正式路径查询(`@kind path-problem`、`@problem.severity error`、`@tags security` + `external/cwe/cwe-918`、id `py/augur/cairosvg/pass3-ssrf`) |
| `diagnostics/WrapperChainDiagnostic.ql` | 包装链可达性诊断(**不计入正式结果**) |

查询结构与 augur `assets/taint_query.ql.tmpl` 一致:`module Pass3Config implements DataFlow::ConfigSig` 四谓词分别委托 `MySources::isSource` / `MySinks::isSink` / `MySanitizers::isBarrier` / `MySummaries::isAdditionalTaintStep`(passKey 统一为 `"ssrf"`);`module Pass3Flow = TaintTracking::Global<Pass3Config>; import Pass3Flow::PathGraph;` 主体 `from Pass3Flow::PathNode source, sink where Pass3Flow::flowPath(source, sink) select sink.getNode(), source, sink, "…"`。导入采用点号语法 `import libraries.MySources` 等,库中模块名、谓词名与 arity 与调用点逐一匹配(qlpack `iris/cairosvg-cwe918` 位于 iris 根)。

**编译验证**:4 个 QLL(经 `queries/Pass3_SSRF.ql` 传递编译,其导入并调用全部四模块谓词)与 `diagnostics/WrapperChainDiagnostic.ql`(传递编译 MySinks/MySummaries)均通过 `codeql query compile`(仅编译,未运行任何分析)。验证过程中修正两处编译问题(可复现性记录):主查询 `@description` 注释中的 `svg2*/Surface.convert` 含 `*/` 提前终止了块注释(已改写措辞);诊断查询最初使用 `Parameter.getScope()`,python-all 7.1.x 的 Parameter 类无此谓词(已改用经验证的 `Function.getArg(i)` / `getKeywordOnlyArg(i)`)。另:`codeql pack install` 因 CLI 2.25.1 无法解析 registry 上最新 python-all 7.2.7 的 manifest 格式而失败(与本实验无关的工具链版本问题);依赖 `"*"` 从本地用户包缓存(python-all 7.1.2)解析成功,与 CWE-78 实验相同,未生成 lock 文件。

## 2. 标签 ID ↔ CodeQL 谓词对应关系

### Sources(MySources.qll,32 条 role=source 全部渲染)

| 标签 ID | source 类 | 匹配逻辑 |
| --- | --- | --- |
| P3-S-001..015 | `Svg2EntryParameterSource` + `svg2Function` | `__init__.py` 模块级 svg2svg/svg2png/svg2pdf/svg2ps/svg2eps:bytestring 取 `f.getArg(0)`(位置参数),file_obj/url 取 `f.getArgByName`(仅关键字参数,`getArgByName` 覆盖 keyword-only);节点 = `DataFlow::parameterNode(p)` |
| P3-S-054..056 | `SurfaceConvertParameterSource` + `surfaceConvertFunction` | `surface.py` `Surface.convert` 类方法:bytestring 取 `getArg(1)`(0 为 cls),file_obj/url 取 `getArgByName` |
| P3-S-017 | `MainStdinParameterSource` + `mainFunction` | `__main__.py` 模块级 `main(argv, stdout, stdin)` 的 `getArg(2)`(stdin) |
| P3-S-019 / P3-S-021 | `CliStdinFieldSource` | `__main__.py` 内 `sys.stdin`(65 行)与 `stdin.buffer`(70 行)属性表达式节点 |
| P3-S-039 / P3-S-035 / P3-S-024 | `GetHrefCallSource` + `labeledGetHrefSite` | `node.get_href()` 调用结果节点,**按标签位置钉定**:image.py:27、defs.py:348、bounding_box.py:344。其余 get_href 调用点(defs.py:35 → P3-S-033、text.py:71 → P3-S-061/062)标签为 none,钉定匹配确保它们不会成为 Source |
| P3-S-042 / 043 / 045 / 046 | `HrefDictGetCallSource` | parser.py 内 `.get('{http://www.w3.org/1999/xlink}href')` 与 `.get('href')` 调用结果节点(262/263 行 tref 读取 + 313 行 get_href 定义体读取,共 4 个调用表达式,与 4 条标签一一对应) |
| P3-S-037 | `XmlBaseDictGetSource` | image.py 内 `.get('{http://www.w3.org/XML/1998/namespace}base')` 调用结果(24 行,xml:base) |
| P3-S-028 | `CssImportUrlTokenSource` | css.py 内 `url_token.value` 属性节点(37 行,CSS @import URL) |
| P3-S-025 | `StyleElementTextSource` | css.py 内 `element.text` 属性节点(<style> 元素文本;形状匹配同时覆盖 20 行同一值的真值判断,见 §7 局限 2) |
| P3-S-051 | `XmlParseBoundarySource` | parser.py 内 `ElementTree.fromstring(...)` 第 0 位置实参(解析边界) |

21 条 role=none 的 source 候选(CLI argv/options.input、fragment-only 消费、file:// 构造)**不渲染**,与 pydash CWE-78 实验的"仅渲染有效标签"原则一致。

### Sinks(MySinks.qll,2 条 role=sink 全部渲染)

| 标签 ID | sink 类 | 匹配逻辑 | 危险参数位置 |
| --- | --- | --- | --- |
| P3-K-013(tp,0.95) | `UrlopenRequestUrlSink` | API 图解析:`API::moduleImport("urllib.request").getMember("urlopen").getACall().asExpr()`(与提取查询同一解析路径,url.py:10 的 from-import 已验证可解析);`API::CallNode` 经 `.asExpr()` 转为 Call,再取 `getPositionalArg(0)` 为 DataFlow::Node | 位置参数 0(承载目标 URL 的 Request 对象;urlopen 同一位置也接受裸 URL 字符串,模型对两种形态均正确) |
| P3-K-017(candidate,0.80) | `FetcherDispatchUrlSink` + `fetcherDispatchCall` | `url.py` 内裸名调用 `url_fetcher(url, resource_type)`(143 行,全库唯一)的 `getPositionalArg(0)` | 位置参数 0(动态分发前的最终 URL) |

### Sanitizers / Summaries

| 类别 | 标签数 | 谓词行为 |
| --- | --- | --- |
| sanitizer | 0 | `isBarrier` → `none()`(WORKFLOW 硬约束:barrier 挂钩必须存在,可为空;无证据不臆造) |
| summary | 24(13 sink 侧 + 11 source 侧) | 13 条 sink 侧 + 4 条关键 source 侧传播语义渲染为 §5 的 4 条自定义边;其余 7 条 parse_url 返回传播(S-023/027/034/038/044/049/050)由标准过程间数据流覆盖(parse_url 定义于数据库内),1 条 file_obj.read(S-048)由局部流覆盖,2 条 tinycss2 解析(S-026/029)由 S-028 读取点 source 补偿,1 条 Tree.__new__ 缓存(S-047)不建边——均逐条记录于 MySummaries.qll 头注,不暗中丢弃 |

## 3. Source 输入的可信度边界与传播依据

CairoSVG 是纯库:**全部 32 条 source 标签均为 classification `candidate`**——不可信性由宿主应用决定(典型场景:转换用户上传/提交的 SVG)。按可控范围分级(用户要求:不同可控范围不得混作相同严重程度):

| 可控范围 | 触达路径 | 说明 |
| --- | --- | --- |
| **完整 URL(scheme+host+port+path)直接控制** | 入口 `url` 参数(S-003/006/009/012/015、S-056:宿主传入攻击者 URL 且无 bytestring 时,`Tree.__init__` → parser.py:386 直接取回该 URL) | 请求目标整体由攻击者选择;前提是宿主把攻击者可控值当 url 传入 |
| **完整 URL 间接控制(文档内引用)** | `<image>` href(S-039)+ xml:base(S-037)、CSS @import 绝对 URL(S-028)、`<tref>`/`<use>` 绝对 URL(S-042/043/035/024) | 不可信文档被转换时,引用值本身即为完整 URL;攻击者也可用 xml:base 重定向相对引用解析出的 host/scheme |
| **名义上仅路径(相对引用 + 固定基 URL)** | 相对 href 拼接固定基(parse_url urljoin 分支) | **实际仍可升级为完整控制**:href 字符串本身无任何校验,攻击者随时可改写为绝对 URL 或 scheme-relative(`//host/`)形式;仅当宿主外部强制改写 href 时才真正限于路径——库内不存在这种强制 |
| **无请求(fragment-only)** | defs.py:35(S-033)、helpers.py:47、surface.py:317/318/372、path.py:21/25、text.py:71、`Tree(url='#…')`(K-003) | 仅文档内查找,标签已判 none,不渲染 |

SVG 属性读取的传播依据:`parser.py:190 self.update(self.xml_tree.attrib)` 把输入文档属性拷入 dict,`parser.py:312-313` 的 `.get('xlink:href'/'href')` 与各消费点 `get_href()` 读回——**dict update/get 传递不被标准数据流跟踪**,因此标签把 Source 钉在读取点(HrefDictGetCallSource / GetHrefCallSource),读取值随后经 `parse_url`(数据库内函数,标准过程间流覆盖:实参→形参→函数体局部污点→返回→调用结果)传入 `X.fetch_url(...)` 实参 0。CLI 侧 `stdin`(S-017/019/021)按标签保守渲染,但 `__main__.py:78 convert(**kwargs)` 的字典分发不可跟踪,当前模型下无告警路径(见 §7 局限 3)。

## 4. Sink 的真实网络 API、危险参数索引与调用位置

- **真实网络 API**:`urllib.request.urlopen`,调用位置 `cairosvg/url.py:84`(`fetch()` 内,`return urlopen(Request(url, headers=HTTP_HEADERS)).read()`)。grep 全库核实:这是唯一网络出口(无 requests/httpx/socket/urlretrieve,无固定主机 URL)。
- **危险参数索引**:urlopen 位置参数 0——即承载目标 URL 的 `Request` 对象;URL 字符串经 `Request(url, ...)` 位置参数 0 进入(K-014,渲染为 requestUrlStep 传播边,而非 sink:构造本身不是网络 I/O)。url_fetcher 分发(url.py:143)位置参数 0 为动态分发前的最终 URL(K-017)。
- **包装器 sink 依据**:url_fetcher 分发被标为 candidate 级 sink 的唯一理由是有真实代码证据表明其默认目标执行网络 I/O:`parser.py:354 self.url_fetcher = kwargs.get('url_fetcher', fetch)`(默认 `fetch`)→ `url.py:84 urlopen`。其余资源处理函数(`Node.fetch_url`、`read_url`、`Tree(url=…)`)一律不是 sink,只作为传播边(§5)。`parse_url`/`urljoin`/`urlparse` 为纯处理 API,既非 sink 亦无条件传播。

## 5. 自定义传播边的源码依据(MySummaries.qll,4 条)

| 边 | 标签 | 源码依据 |
| --- | --- | --- |
| **E1 fetchUrlWrapperStep**:`X.fetch_url(arg0)` 实参 0 → `read_url` 形参 `url`(DataFlow::parameterNode) | K-002/K-005/K-010(调用点)+ K-007/K-008/K-015(定义) | `parser.py:242-243 def fetch_url(self, url, resource_type): return read_url(url, self.url_fetcher, resource_type)`——直接透传;真实调用点恰为 image.py:28、css.py:39、parser.py:386 三处。该边补偿两处 CodeQL 解析缺口:`node.fetch_url`/`tree.fetch_url` 属性调用在不带注解的形参上无法静态解析;补偿是条件性的(仅匹配 callee 属性名为 `fetch_url` 的调用) |
| **E2 treeUrlStep**:`Tree(...)` 的 `url` 关键字实参值 → parser.py:386 `self.fetch_url(parse_url(self.url), …)` 的实参 0(即 parse_url 调用节点) | K-001/K-004/K-009/K-011 + K-010(目标) | `parser.py:343-387 Tree.__init__`:url 经 kwargs 字典进入(`kwargs.get('url')`,347 行,标准数据流不可跟踪),无 bytestring 时于 386 行取回。按标签排除两处:image.py:46(K-006:bytestring 恒有值,该 url 永不被取回)与 `Tree(url='#…')`(K-003:fragment 复用父树,parser.py:376-383) |
| **E3 fetcherDispatchStep**:`url_fetcher` 分发调用实参 0 → `fetch` 形参 `url` | K-012(fetch 形参)+ K-017 记录的包装证据 | `url.py:143 return url_fetcher(url, resource_type)` + `parser.py:354` 默认 `fetch`(→ urlopen)。动态分发不可静态解析;默认目标唯一且在数据库内。保守近似说明:注入的自定义 fetcher 收到的是同一污点实参,故该边是文档化默认路径的保守近似,而非无条件传播 |
| **E4 requestUrlStep**:`Request(...)` 实参 0 → Request 调用结果节点 | K-014 | `url.py:84 urlopen(Request(url, headers=…))`:urlopen 实参 0 恰为 Request 调用表达式,URL 污点需经此边到达 sink 节点;API 图匹配真实 urllib.request.Request(提取阶段已验证解析) |

完整污点链(以 `<image>` href 为例):S-039 `node.get_href()`(image.py:27)→ 局部流 → `parse_url(...)` 实参(标准过程间)→ `node.fetch_url(url, 'image/*')` 实参 0(image.py:28)→ **E1** → `read_url` 形参 → 局部流 → `url_fetcher` 分发实参 0(url.py:143,**K-017 sink**)→ **E3** → `fetch` 形参 → 局部流 → `Request(url)` 实参 0 → **E4** → Request 调用节点 = urlopen 实参 0(url.py:84,**K-013 sink**)。

## 6. URL scheme、固定目标、重定向、私有地址与 sanitizer 处理情况

- **scheme 限制**:不存在。任何 scheme 均原样到达 urlopen(含 `file://` 与 `ftp://`;`data:` 在 `normalize_url` 直接放行,url.py:33,由 urllib DataHandler 处理,不构成网络请求)。read_url 对无 scheme 引用补 `file://`(url.py:140)——本地文件读取,Phase 1 已按用户提示第 8 条记为跨 CWE(CWE-22 相关)备注,K-016 标签 role=none,不渲染。
- **固定目标请求**:库内不存在任何固定主机/管理员配置 URL(grep 核实,http(s) 字面量均为注释);所有取回 URL 都是调用方传入或文档派生,故无需也不存在"固定端点 → FP"的降级规则。
- **重定向**:无任何控制;urllib 默认跟随 HTTP 重定向(`HTTPRedirectHandler` 默认启用)——即便攻击者只控制路径,一次 302 也可把请求重定向到任意主机。此为报告级事实,不影响 sink 匹配。
- **私有地址**:无 loopback/私网 IP 拦截、无 DNS 解析后校验。
- **有效 sanitizer**:`MySanitizers::isBarrier` → `none()`。经 Phase 1 审查确认(见 labels/phase1_review.md §Sanitizers):全库无 scheme/host 白名单、无私网拦截、无重定向策略;`read_url` 文档字符串自述默认取回器 "no limitations"(url.py:133-135);defusedxml `forbid_entities/forbid_external`(parser.py:390-392)是 XXE 防护且可被调用方 `unsafe=True` 关闭,不拦截外部资源取回,**不构成 CWE-918 sanitizer**;唯一结构性缓解是宿主注入受限 `url_fetcher`(parser.py:354),属部署级措施,非库内 barrier。

## 7. 未覆盖的 API、动态调用与 CodeQL 分析限制

1. **PIL/tinycss2/cssselect2/defusedxml 源码不在数据库内**:成员调用(`Image.open`、`tinycss2.parse_*`、`ElementTree.fromstring`)只能按 AST 形态匹配;`fromstring` 匹配限定 parser.py、`parse_stylesheet` 相关读取钉在 css.py,均与标签位置一致。
2. **`StyleElementTextSource` 形状宽度**:css.py 的 `element.text` 匹配同时覆盖 20 行(真值判断)与 25 行(parse_stylesheet 实参)——同一值的两处表达式;20 行处污点无下游(tinycss2 对象属性流不可跟踪),不产生额外告警。已记录,不视为标签偏差。
3. **kwargs 字典分发缺口**:入口 `bytestring`/`file_obj` 参数 → `Surface.convert(**kwargs)`(CLI 路径)与 `Tree(**kwargs)`(bytestring/file_obj 分支)的字典传递不可跟踪,因此 bytestring/file_obj/CLI 类 Source 在当前模型下没有到 sink 的路径(告警路径由文档派生读取点 Source 承载——这正是 Phase 1 把读取点标为 Source 的设计原因)。XML 属性 dict 流同理(fromstring → `.get('href')`),以读取点 Source 补偿。**未**为连通路径而把 dict 边建为无条件传播,亦未把内部包装形参升为 Source。
4. **`node.fetch_url` / `tree.fetch_url` 属性调用解析**:不带注解形参上的属性调用目标无法可靠静态解析,由 E1 条件边补偿;若 CodeQL 某些调用点可解析,则标准流与 E1 并存(冗余无害)。
5. **`url_fetcher` 动态分发**:E3 按默认目标 `fetch` 建边(保守近似);注入自定义 fetcher 的部署中,urlopen sink(K-013)实际收到的 URL 取决于该 fetcher,K-017(dispatch 边界)仍如实告警。
6. **`Call.getArg(int)` 语义**:`*args` 前置的参数不计入位置索引;本库全部相关调用均为简单位置/关键字形态,不受影响。
7. **行号钉定的脆弱性**:`GetHrefCallSource` 按(文件,行)钉定 3 个标签位置,`treeCallWithoutFetch` 钉定 image.py:46——对当前 DB 快照(58be378)精确;代码移动后需随标签重新渲染(可复现原则的一部分:库文件由标签表机械生成)。
8. **诊断查询**:`diagnostics/WrapperChainDiagnostic.ql` 以 cairosvg 全部函数形参为 Source(仅诊断用,正式 MySources 不含)检查到网络 sink 的可达性,用于验证"内部包装器参数不自动等于 Source"与包装链局部可达性;其结果**不计入**正式 CWE-918 告警(独立目录、无 path-problem 元数据)。预期仅 fetch/read_url/Node.fetch_url 的 url 形参及 Tree.__init__ 相关输入可达;出现其他形参即为建模缺口信号。
9. **Pass 1 占位块**:labels.json 中 pass_id=1 为 schema contains 约束所需的空占位,未渲染任何 Pass 1 内容;所有谓词 passKey 分发目前仅有 `"ssrf"` 一个键(无 command_injection 等残留)。
10. **标签缺口评估**:未发现需要退回重审的标注错误。两处软性记录:(a) bytestring/file_obj/CLI 类 Source 属边界标签,当前模型无路径(设计使然,见局限 3);(b) K-006(image.py:46)按标签语义排除出 E2——若人工复核认为应保守包含,属标签层决策,不应在模型中暗中放宽。

## 8. 建模原则(与此前 CWE-78 实验一致的可复现/独立评估原则)

1. **仅渲染有效标签**:21 条 role=none 候选一律不进库;内部网络包装形参(fetch/read_url/Node.fetch_url)按标签为 summary,渲染为传播边,绝不升为 Source。
2. **签名优先、位置忠实**:Source 按标签签名(函数+文件+参数索引/名称、读取点位置)匹配;读取点按(文件,行)钉定;Sink 按真实 API + 危险实参索引匹配。
3. **无证据即 none()**:barrier 与无条件传播一律不引入;每条自定义边都附源码依据与排除项(K-006/K-003)。
4. **API::Node → DataFlow::Node 转换**:`API::moduleImport(...).getMember(...).getACall().asExpr()` 得到 Call 表达式,再以 `getPositionalArg(0)` / 调用节点本身取 DataFlow::Node(urlopen/Request 两处)。
5. **不修改已审核标签**:本次未改 labels.json;发现的两处软性点记录于 §7.10,留待人工决策。
6. **确定性渲染与可审计**:4 个 QLL 由标签表机械生成、头注逐条列出标签 ID 映射;编译验证仅用 `codeql query compile`,未执行数据库分析;未读取 PyVul 真值/修复提交/CVE 描述,未修改项目源码、数据库、Phase 1 标签与 Augur 工具文件。
7. **独立评估**:诊断查询与正式查询分离,诊断结果不进正式报告;正式查询的告警语义完全由已审核标签驱动。

## 9. 状态

Step 4(库生成)与 Step 5 的查询生成已完成:4 个 QLL + `queries/Pass3_SSRF.ql` + `diagnostics/WrapperChainDiagnostic.ql` 全部通过 `codeql query compile` 编译验证(仅编译,未运行任何分析)。**未执行** `codeql database analyze`(按指令:仅生成文件)。后续 Step 5 执行(`codeql database analyze "$DB" iris/queries/Pass3_SSRF.ql --format=sarifv2.1.0 --output=iris/results/pass3.sarif`,顺序执行;可选先运行诊断查询 `codeql query run` 验证包装链可达性,其结果不计入正式告警)与 Step 6 过滤报告待指令。
