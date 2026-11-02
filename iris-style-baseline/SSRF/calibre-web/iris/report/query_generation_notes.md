# Query Generation Notes — Pass 3 (CWE-918 SSRF) / Phase 2 Step 4–5

生成时间:2026-10-19 · 项目:calibre-web · 生成模型:glm-5.3(Z.ai GLM,会话内直接生成)· 工具链:CodeQL CLI 2.25.1(E:\codeql)
输入:`iris/labels/labels.json`(Pass 3,run_id `calibre-web-iris-pass3-step3-20261019`,199 条条目:11 source / 13 sink / 0 sanitizer / 4 summary / 171 none;与 Phase 1 Step 3 产出逐字节一致,未被修改)
产出:4 个 QLL(`libraries/`)、1 个正式路径查询(`queries/Pass3_SSRF.ql`)、1 个诊断查询(`diagnostics/WrapperChainDiagnostic.ql`,不计入正式结果)。
本步骤只生成并编译验证文件,**未执行** `codeql database analyze`(按实验指令,正式分析待后续指令)。

关于 `labels/review_decision.json`:该文件在本工作区不存在。Phase 1 审查以 `labels/phase1_review.md` 为载体并停在人工审查关口;本次进入 Phase 2 的依据是操作者指令本身(指令明确引用"经过人工审核的 labels/labels.json"并指示执行 Step 4–5)。此差异如实记录,未补造审查文件。

## 1. 产出文件与接口契约

| 文件 | 接口 |
| --- | --- |
| `libraries/MySources.qll` | `module MySources { predicate isSource(DataFlow::Node, string passKey) }`,渲染 11 条 source 标签(8 个私有 source 类) |
| `libraries/MySinks.qll` | `module MySinks { predicate isSink(DataFlow::Node, string passKey) }`,渲染 13 条 sink 标签(6 个私有 sink 类) |
| `libraries/MySanitizers.qll` | `module MySanitizers { predicate isBarrier(DataFlow::Node, string passKey) }`,解析为 `none()` |
| `libraries/MySummaries.qll` | `module MySummaries { predicate isAdditionalTaintStep(DataFlow::Node, DataFlow::Node, string passKey) }`,渲染 3 条有源码依据的自定义传播边 |
| `queries/Pass3_SSRF.ql` | 正式路径查询(`@kind path-problem`、`@problem.severity error`、`@tags security` + `external/cwe/cwe-918`、id `py/augur/calibre-web/pass3-ssrf`、`@precision medium`) |
| `diagnostics/WrapperChainDiagnostic.ql` | 包装链可达性诊断(**不计入正式结果**) |

查询结构与 augur `assets/taint_query.ql.tmpl` 一致:`module Pass3Config implements DataFlow::ConfigSig` 四谓词分别委托 `MySources::isSource` / `MySinks::isSink` / `MySanitizers::isBarrier` / `MySummaries::isAdditionalTaintStep`(passKey 统一为 `"ssrf"`);`module Pass3Flow = TaintTracking::Global<Pass3Config>; import Pass3Flow::PathGraph;` 主体 `from Pass3Flow::PathNode source, sink, string msg where Pass3Flow::flowPath(source, sink) and ssrfMessage(sink.getNode(), msg) select sink.getNode(), source, sink, msg`。导入采用点号语法 `import libraries.MySources` 等,库中模块名、谓词名与 arity 与调用点逐一匹配(qlpack `iris/calibre-web-cwe918` 位于 iris 根)。全部 passKey 仅有 `"ssrf"` 一个键,无 `command_injection` 等残留;未把 `module` 用作变量名。

**编译验证**:`queries/Pass3_SSRF.ql`(传递编译全部 4 个 QLL)与 `diagnostics/WrapperChainDiagnostic.ql`(传递编译 MySinks/MySummaries)均通过 `codeql query compile`(12.8s / 13.6s,一次通过,无错误无告警)。`codeql pack install` 按 WORKFLOW 硬约束执行但失败,原因与 CairoSVG 实验相同:CLI 2.25.1 无法解析 registry 上最新 python-all 7.2.7 的 OCI manifest 格式(`Unrecognized field "digest"`);依赖 `codeql/python-all: "*"` 随后由 `codeql query compile` 从 **CLI 内置包** `E:\codeql-codeql-cli-2.25.2\python\ql\lib`(codeql/python-all 7.0.4)成功解析——编译通过本身即为解析成功的证明(用户缓存 7.1.1/7.1.2 亦存在,但 resolve 优先命中内置包)。所用 API(DataFlow::ConfigSig、TaintTracking::Global、PathGraph/flowPath、parameterNode、asExpr、Call/Attribute/Subscript/Keyword/StringLiteral 谓词)在 7.0.4 下全部存在。

## 2. 标签 ID ↔ CodeQL 谓词对应关系

### Sources(MySources.qll,11 条 role=source 全部渲染)

| 标签 ID | source 类 | 匹配逻辑 |
| --- | --- | --- |
| src-063(tp,0.8) | `RequestFormToDictSource` + `requestFormToDictCall` + `labeledToDictSite` | `request.form.to_dict()` 调用结果节点,**按标签位置钉定** editbooks.py:778(POST /admin/book/<id> 的 to_save)。代码库另有 24 处 to_dict 调用(admin/shelf/web/editbooks:1152),标签均为 none,钉定确保它们不会成为 Source |
| src-064/065/066(tp,0.85) | `CoverUrlSubscriptSource` | `to_save["cover_url"]` 下标读取节点(索引为 "cover_url" 字符串字面量),钉定 editbooks.py:801/805/808。其余 to_save 键(book_title、tags 等)为本地图书元数据,标签 none,不渲染 |
| src-141(tp,0.8) | `MetadataSearchQuerySource` + `queryGetOnToDictCall` | 链式 `request.form.to_dict().get("query")` 调用结果节点(search_metadata.py:119;dict 成员读取不被标准数据流可靠跟踪,故锚定在 .get 调用本身) |
| src-142(tp,0.75) | `RequestFormToDictSource`(search_metadata.py:119 钉定) | 同一链条的内层 to_dict() 调用节点 |
| src-139(tp,0.75) | `MetadataProviderJsonSource` | `request.get_json()` 调用结果节点,钉定 search_metadata.py:92(POST /metadata/provider 的 JSON body) |
| src-087(tp,0.8) | `RequestFullPathSource` | `request.full_path` 属性读取节点,钉定 kobo.py:69(全库唯一出现;get_store_url_for_current_request 函数体内) |
| src-088(candidate,0.55) | `KoboProxyHeadersSource` | `request.headers` 属性读取,钉定 kobo.py:89(Headers(request.headers) 逐字转发)。**行钉定必须**:kobo.py:139 也读 request.headers(SyncToken.from_headers),标签为 none |
| src-090(candidate,0.55) | `KoboProxyBodySource` | `request.get_data()` 调用结果,钉定 kobo.py:98(转发为出站 body) |
| src-102(candidate,0.55) | `MatchUrlFieldSource` | `match.url` 属性读取,钉定 lubimyczytac.py:203(二阶:第 190 行 `BASE_URL + book_url`,book_url 来自搜索响应 HTML 的 @href) |

### Sinks(MySinks.qll,13 条 role=sink 全部渲染)

| 标签 ID | sink 类 | 匹配逻辑 | 危险参数位置 |
| --- | --- | --- | --- |
| snk-003/006/007/012/013 | `RequestsGetUrlSink` + `requestsGetCall` + `labeledRequestsGetSite` | `requests.get(...)` 调用,按标签钉定 (comicvine.py:49, google.py:48, helper.py:740, lubimyczytac.py:115/203)。**钉定必须**:cps/updater.py 有 4 处 requests.get(76/352/378/613),标签为 none(常量/GitHub 回显 URL) | 位置参数 0 |
| snk-004(tp,0.85) | `SaveCoverFromUrlSink` + `saveCoverFromUrlCall` | `helper.save_cover_from_url(to_save["cover_url"], book.path)`(editbooks.py:808,全库唯一调用点)。包装器依据:callee 定义于数据库内,首段即执行 `requests.get(url, ...)`(helper.py:740) | 位置参数 0 |
| snk-001/002(candidate,0.55) | `AmazonSessionGetUrlSink` + `amazonSessionGetCall` | amazon.py 内 `session.get(...)`(53 行:响应派生 href;110 行:原始 query 嵌入固定前缀后) | 位置参数 0 |
| snk-005(candidate,0.5) | `GdriveDownloadRequestUrlSink` + `gdriveDownloadRequestCall` | gdriveutils.py:626 `df.auth.Get_Http_Object().request(download_url, headers=...)`(callee 属性 `request` 挂在 Get_Http_Object() 调用结果上;downloadUrl 来自 Drive API 文件元数据,二阶) | 位置参数 0 |
| snk-008(candidate,0.6) | `KoboStoreRequestUrlSink` + `koboStoreRequestCall` | kobo.py 内唯一 `requests.request(...)`;sink 节点 = `url=` 关键字值表达式(kobo.py:96,即 get_store_url_for_current_request() 调用)。标签把 CSV 的 arg_index -1 归一为 1(requests.request(method, url, ...) 的 URL 位置参数索引;实际以 url= 关键字传入) | url= 关键字值(= 位置参数 1) |
| snk-009/010/011(candidate,0.5-0.55) | `KoboStoreWrapperInvocationSink` + `koboStoreWrapperCall` | `make_request_to_kobo_store(...)` 调用表达式本身,钉定 kobo.py:114/330/1059。包装器依据(按标签):每次调用触发 kobo.py:94 的出站请求(URL 请求派生)。**按构造不可达**:114/1059 无实参,330 只传 sync_token(标签审定为非 Source),污点无法终止于这些节点——同一流的告警在 snk-008 处浮现(见 §7.5) | 调用表达式(包装器触发点) |

### Sanitizers / Summaries

| 类别 | 标签数 | 谓词行为 |
| --- | --- | --- |
| sanitizer | 0 | `isBarrier` → `none()`(WORKFLOW 硬约束:barrier 挂钩必须存在,可为空;无证据不臆造) |
| summary | 4(2 处 store-URL 返回 + 2 处 provider-search 分发) | 全部 4 条渲染为 §5 的 3 条自定义边(src-089/091 共用 storeUrlStep);save_cover_from_url 实参→形参→requests.get 由标准过程间数据流覆盖,不建手工边(逐条记录于 MySummaries.qll 头注) |

## 3. Source 输入的可信度边界与传播依据

Flask 路由边界全部按 Phase 1 标注核实(登录/权限不自动视为可信,亦不把 admin 配置当攻击面):

| 边界 | 路由与鉴权 | 可信度判断 | 可控范围(分级,不混作同一严重程度) |
| --- | --- | --- | --- |
| 图书编辑封面 URL | POST `/admin/book/<int:book_id>`(editbooks.py:749-751 `@login_required_if_no_ano` + `@edit_required`;cover_url 分支另需 802-804 行 `current_user.role_upload()`) | **不可信的已认证用户**(任何具备编辑+上传角色的普通库用户,非运维管理员)。to_save 表单字典中的 cover_url 即完整请求 URL | **完整 URL(scheme+host+port+path)直接控制** |
| 元数据搜索 | POST `/metadata/search`(search_metadata.py:116-118 @login_required)与 POST `/metadata/provider`(:88-90 @login_required) | 任何已登录用户的搜索文本,经 quote() 编码后嵌入固定主机 URL | **仅查询/路径分量**(host/scheme 由常量钉定;amazon:110 未编码但仍在固定前缀后) |
| Kobo 代理 | blueprint `/kobo/<auth_token>/`(kobo.py:60);`@requires_kobo_auth` 仅覆盖带装饰器的路由——汇入 redirect_or_proxy_request 的路由中 `/v1/products/*`(kobo.py:1014)、`/v1/analytics/gettests`(990)等**无鉴权装饰器**;代理行为另需管理员开启 `config.config_kobo_proxy` | request.full_path 的路径后缀(剥去 /kobo/<token> 段后)拼接到固定主机后 | **主机钉定(storeapi.kobo.com)下的路径/查询控制 + 全部入站请求头/请求体逐字转发** |
| 二阶 URL | lubimyczytac/amazon 搜索响应 HTML 的 @href、Drive API 文件元数据 | 非直接 web 输入;只有被攻破/恶意的上游服务才能操纵 | **二阶路径控制**(主机由字符串拼接钉定) |

排除项(与标签一致,均不渲染):9 个环境变量与 19 个 CLI 参数(运维边界)、33 个 admin 表单(@admin_required,运维配置,经核实无一路径到达 18 个出站请求点)、opds/web/shelf 的本地分页与查询参数、文件上传对象、Kobo 设备同步 JSON、gdrive OAuth/webhook(令牌校验)、redirect.py/web.py:1606 开放重定向族(CWE-601,Pass 9,有 is_safe_url 同源防护)。

传播依据:flask/requests 为外部库,`request.form.to_dict()`、`request.get_json()` 等成员调用的接收者类型不可静态解析,故 Source 全部锚定在标签审定的**读取点表达式**(调用结果/属性/下标),不做 `API::Node` 全局建模;`to_save = request.form.to_dict()` → `to_save["cover_url"]` 的容器→元素污点由标准库覆盖,且下标读取点本身即 Source(src-064..066),双重保障。

## 4. Sink 的真实网络 API、危险参数索引与调用位置

| 标签 | 网络请求 API | 危险参数位置 | 调用位置 | 依据 |
| --- | --- | --- | --- | --- |
| snk-007 | `requests.get`(requests 库真实 HTTP 出口) | 位置参数 0(`url`) | cps/helper.py:740(`img = requests.get(url, timeout=(10, 200))`,save_cover_from_url 函数体内) | 唯一 caller 是 editbooks.py:808(全库 grep 核实) |
| snk-004 | `helper.save_cover_from_url`(包装器) | 位置参数 0 | cps/editbooks.py:808 | 包装器内 740 行即 requests.get(url);callee 在数据库内 |
| snk-008 | `requests.request` | url= 关键字值(requests.request(method, url, ...) 的位置参数 1) | cps/kobo.py:94-101(多行调用,url= 在 96 行) | kobo.py 全库唯一 requests.request;主机钉定 KOBO_STOREAPI_URL(kobo.py:55),allow_redirects=False |
| snk-009/010/011 | `make_request_to_kobo_store`(包装器) | 调用表达式(触发点;无 URL 实参) | kobo.py:114/330/1059 | 包装器内 94 行发出请求;按构造不可达(§7.5) |
| snk-003/006/012 | `requests.get` | 位置参数 0 | comicvine.py:49 / google.py:48 / lubimyczytac.py:115 | 固定主机常量 + quote() 编码 token 拼接 |
| snk-001/002 | `requests.Session().get` | 位置参数 0 | amazon.py:53 / 110 | 53:响应派生 href 未编码;110:原始 query 嵌入 `https://www.amazon.com/s?k=` 前缀后 |
| snk-013 | `requests.get` | 位置参数 0(`match.url`) | lubimyczytac.py:203 | match.url 来自 190 行 `BASE_URL + book_url`(响应 xpath @href) |
| snk-005 | pydrive `Get_Http_Object().request`(httplib2 传输) | 位置参数 0(`download_url`) | cps/gdriveutils.py:626 | downloadUrl 来自 df.metadata(管理员配置的 Drive 账号),二阶 |

不渲染的 sink 候选(标签 none):`scholarly.search_pubs`(实参 0 是编码后的搜索短语而非 URL,请求由 scholarly 库内部发出)与 cps/updater.py 4 处 requests.get(常量 `_REPOSITORY_API_URL` 或 GitHub API 回显的 zipball_url/parent url,由管理员触发的后台线程,无 web 输入影响)。urljoin/urlparse 类纯处理 API 不作为 sink(helper.py:736 的 urlparse 仅用于 localhost 检查)。

## 5. 自定义传播边的源码依据(MySummaries.qll,3 条)

| 边 | 标签 | 源码依据 |
| --- | --- | --- |
| **E1 storeUrlStep**:`request.full_path` 属性读取(kobo.py:69)→ `get_store_url_for_current_request()` 调用结果 | src-089(96 行调用点)+ src-091(110 行 307 重定向) | kobo.py:67-73:rpartition 剥前缀 → rstrip → partition → `KOBO_STOREAPI_URL + "/" + request_path` 拼接返回。元组解包→字符串拼接链可能部分被标准局部流覆盖;该边保证传播(条件于精确源形态,非无条件)。96 行调用结果即 snk-008 的 sink 节点 |
| **E2 providerSearchDispatchStep**:`.search(...)` 实参 0(search_metadata.py)→ 各 provider `search` 方法的 `query` 形参(getArg(1);self 占 getArg(0)) | src-140(109 行 `provider.search(new_state.get("query", ""))`) | 接收者 `provider` 来自 `next((c for c in cl ...))`(cl 为 import 时实例化的 Metadata 子类),动态分发不可静态解析;边为文档化默认的保守近似:cl 中每个 provider 都收到同一 query 实参 |
| **E3 executorSubmitSearchStep**:`executor.submit(c.search, query, ...)` 实参 1 → provider `search` 方法的 `query` 形参 | src-143(128 行,ThreadPoolExecutor 分发) | concurrent.futures 语义:submit(fn, *args) → fn(*args),即 `c.search(query, static_cover, locale)`;分发动态不可解析。仅桥接 query 实参(实参 0 是绑定的方法对象);static_cover/locale 不触达 URL,不建边 |

完整污点链:

1. **封面 URL 流(主链,完整目标控制)**:src-063(editbooks.py:778 to_dict)→ 标准容器/元素流 → src-064/065/066(801/805/808 下标)→ **snk-004**(808 实参 0)→ 标准过程间流(helper.py:732 形参 `url` → 函数体)→ **snk-007**(740 requests.get 实参 0)。
2. **元数据搜索流**(/metadata/search):src-141(119 行 `.get("query")` 结果)→ 局部流(119 行赋值 query → 128 行实参)→ **E3** → provider `query` 形参 → 函数体局部流 → provider fetch sinks(google:48/comicvine:49 内联拼接;lubimyczytac:115 经 `self._prepare_query(title=query)` 调用结果;amazon:110 经 f-string 插值)。
3. **Kobo 代理流**:src-087(kobo.py:69 full_path)→ **E1** → 96 行调用结果 = **snk-008**(url= 关键字值)。
4. **/metadata/provider 流**:src-139(92 行 get_json)→ new_state → 109 行 `new_state.get("query","")` → **E2** → provider 形参;**注意 §7.2 的 dict-get 缺口**——该链是否连通取决于标准库对 `.get()` 成员读取的建模。
5. **二阶锚点对**:src-102 与 snk-013 的实参为同一表达式(lubimyczytac.py:203 `match.url`),按标签如实渲染(见 §7.6)。

## 6. URL scheme、固定目标、重定向、私有地址与有效 sanitizer 处理

- **scheme 限制**:全库不存在任何 scheme 白/黑名单。封面流(完整 URL 控制)下攻击者可指定 requests 支持的任意 scheme——`requests` 库本身不接受 `file://`/`data:`(无对应 adapter,抛 InvalidSchema),故封面流实际限于 http(s)(+已安装的 transport adapter);源码中无任何构造 `file:`/`data:` URL 并发起请求的路径(Phase 1 grep 核实,urlopen/urlretrieve/httpx 全库未使用),按用户指令第 8 条,此类形态未混入 CWE-918。Kobo 代理的出站 URL 一定以 `https://storeapi.kobo.com/` 开头(kobo.py:55+73 字符串拼接;路径后缀无法逃逸出 scheme/host 段,拼接结果主机恒定)。
- **固定目标**:Kobo 代理(storeapi.kobo.com,kobo.py:55)、googleapis.com(google.py:35)、comicvine.gamespot.com(comicvine.py:33)、lubimyczytac.pl(lubimyczytac.py:79)、amazon.com(amazon.py f-string 前缀)、GitHub API(updater,已排除)。固定目标属性按 §2/§4 钉定在 sink 匹配与告警消息中,不作为 sanitizer。
- **重定向**:封面流 `requests.get(url, timeout=(10,200))` 未禁用 allow_redirects(默认 True)——公共 URL 一次 302 即可重定向到内网地址,**绕过 734-739 行的 localhost 检查**;此为报告级事实,不影响 sink 匹配。Kobo 代理请求显式 `allow_redirects=False`(kobo.py:99);110 行的 307 是把客户端重定向到商店,不是服务端取回。
- **私有地址**:唯一的 loopback 检查在 helper.py:734-739:受 `-l/--allow-localhost` 开关控制(cli.py:48,88)、只看首个 `getaddrinfo` 结果(DNS rebinding 可绕)、不覆盖重定向——**审定为不足,未建模为 barrier**。无私网段拦截、无解析后 IP 校验。
- **有效 sanitizer**:`MySanitizers::isBarrier` → `none()`。标签 sanitizer 数为 0;唯一 sanitizer 形态代码 redirect.py:36-39 `is_safe_url`(同源校验)属 CWE-601 防护,其保护的值在本 pass 不触达网络取回;provider 侧 quote() 编码是 sink 构造属性而非 barrier 节点。

## 7. 未覆盖的 API、动态调用与 CodeQL 分析限制

1. **flask/requests/flask-login 为外部库**:`request.*` 成员调用与 `requests.get/request` 均按 AST 形态 + 标签位置钉定匹配,不依赖 import 解析(Phase 1 已逐点 grep 核实 18 个出站请求点为全集);ApiGraphs 未用于本 pass(所有 sink 均可由源内形态唯一钉定)。
2. **dict 成员读取缺口**:`new_state.get("query", "")`(search_metadata.py:109)对 get_json() 结果的读取是否被标准污点跟踪取决于库版本对 dict 方法建模。**/metadata/provider 流(src-139)可能因此不连通**;/metadata/search 流不受影响(src-141 锚定在 .get 调用结果本身)。**未为连通而臆造未审定边**——该缺口应作为标签层重审项(见 §7.10)。
3. **f-string/JoinedStr 与方法解析**:amazon.py:110 依赖 f-string 插值污点步;lubimyczytac.py:115 依赖 `self._prepare_query` 的解析与返回值流(`_prepare_query` 定义于数据库内)。任一不成立则对应 provider 路径不产生告警,如实接受。
4. **`requests` 形参位置**:snk-008 按 requests.request(method, url, ...) 把 URL 记为位置参数 1(实际以 url= 关键字传入,与标签的归一化一致);其余 sink 均为位置参数 0。
5. **包装器调用 sink 按构造不可达**:snk-009/010/011(make_request_to_kobo_store @ kobo.py:114/330/1059)按标签渲染为调用表达式上的 sink,但 114/1059 无实参、330 只传 sync_token(标签审定不入 MySources),污点无实参通道可终止于这些节点——**同一流的告警在 snk-008(kobo.py:96,URL 实参真正承载请求派生值处)浮现**。这是数据流语义的如实结果,不是建模缺陷;若需让包装器触发点本身告警,须在标签层把出站 URL 汇聚点重新审定(属人工决策)。
6. **零长路径/同节点锚点对**:src-066 与 snk-004 实参(808 行同一表达式)、src-102 与 snk-013 实参(203 行同一表达式)为标签审定的同节点 source-sink 对;引擎是否为 source=sink 生成零长路径取决于 flowPath 语义,如实接受(封面流的主告警由 src-063→snk-004/007 承载;lubimyczytac 二阶流仅依赖该锚点对)。
7. **行号钉定的脆弱性**:Source/Sink 均按(文件基名,行)钉定标签位置,对当前 DB 快照精确;代码移动后需随标签重新渲染(可复现原则的一部分:库文件由标签表机械生成,头注逐条列出标签 ID 映射)。
8. **诊断查询**:`diagnostics/WrapperChainDiagnostic.ql` 以 cps/ 全部函数形参为 Source(仅诊断用,正式 MySources 不含)检查到网络 sink 的可达性,用于验证"内部包装器参数不自动等于 Source"与包装链局部可达性;预期行:helper.save_cover_from_url 的 url 形参(helper.py:732)与 5 个 provider search 的 query 形参(google.py:38 等);出现其他形参即为建模缺口信号。其结果**不计入**正式 CWE-918 告警(独立目录、无 path-problem 元数据)。
9. **Pass 1 占位块**:labels.json 中 pass_id=1 为 schema contains 约束所需的空占位,未渲染任何 Pass 1 内容;所有谓词 passKey 分发仅有 `"ssrf"` 一个键。
10. **标签缺口评估(要求重审而非暗改)**:(a) §7.2 的 dict-get 缺口——若希望 /metadata/provider 流(src-139)连通,需在标签层补一条 `new_state.get(...)` 的 summary 标签后重审;(b) snk-009/010/011 包装器触发点在纯数据流下不可达(§7.5)——若人工复核认为触发点本身应告警,属标签层决策。两处均未在模型中放宽或添加未审定边。

## 8. 建模原则(与此前 CWE-78 / CairoSVG 实验一致的可复现/独立评估原则)

1. **仅渲染有效标签**:171 条 role=none 候选(admin 配置、环境/CLI、本地查询参数等)一律不进库;内部包装返回点与 provider 分发按标签为 summary,渲染为传播边,绝不升为 Source;未为连通路径把任何内部形参设为外部 Source。
2. **签名优先、位置忠实**:Source 按标签读取点表达式(调用/属性/下标 + 文件 + 行)钉定;Sink 按真实网络 API + 危险实参位置 + 标签位置钉定;钉定的排斥效应(哪些 none 标签因此被挡在库外)逐条写入头注。
3. **无证据即 none()**:barrier 与无条件传播一律不引入;3 条自定义边均条件于具体语法形态并附源码依据;save_cover_from_url 的标准过程间流不建冗余手工边。
4. **可控范围分级**:告警消息按 4 级区分(完整 URL 控制 / 主机钉定+路径与头体转发 / 固定主机+编码查询 / 二阶 URL),由 `ssrfMessage` 按 sink 位置互斥分支生成,不混作同一严重程度。
5. **不修改已审核标签**:labels.json 与 Phase 1 产物逐字节未动;两处软性缺口记录于 §7.10,留待人工重审。
6. **确定性渲染与可审计**:4 个 QLL 由标签表机械生成、头注逐条列出标签 ID;编译验证仅用 `codeql query compile`(两个查询一次通过),未运行任何数据库分析;未读取 PyVul 真值/修复提交/CVE 描述,未修改项目源码、数据库、Phase 1 标签与 Augur 工具文件。
7. **独立评估**:诊断查询与正式查询分离(独立目录、无 path-problem 元数据),诊断结果不进正式报告;正式查询的告警语义完全由已审核标签驱动。

## 9. 状态

Step 4(库生成)与 Step 5 的查询生成已完成:4 个 QLL + `queries/Pass3_SSRF.ql` + `diagnostics/WrapperChainDiagnostic.ql` 全部通过 `codeql query compile` 编译验证(仅编译,未运行任何分析)。**未执行** `codeql database analyze`(按指令:仅生成文件)。后续正式分析(`codeql database analyze "C:\Users\lzh\Desktop\github\PyVul-main\dataset\codeql_databases\ssrf_dbs\calibre-web_vuln\calibre-web-db" queries/Pass3_SSRF.ql --format=sarifv2.1.0 --output=results/pass3.sarif`,顺序执行;可选先 `codeql query run` 诊断查询验证包装链可达性,其结果不计入正式告警)与 Step 6 过滤报告待指令。
