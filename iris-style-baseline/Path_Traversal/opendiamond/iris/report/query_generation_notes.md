# Augur Phase 2 Step 4–5 建模报告：Pass 1 Path Traversal（opendiamond）

- 生成日期：2026-10-22；工作区：`iris_manual/Path_Traversal/opendiamond/iris`
- 输入标签：`iris/labels/labels.json` pass 1（CWE-022/023/036/073，375 条已审核条目：source 137 / sink 38 / summary 70 / sanitizer 1 / none 129），run `opendiamond-pass1-labeling-20261022`，模型 glm-5.3
- 生成文件：`libraries/MySources.qll`、`libraries/MySinks.qll`、`libraries/MySanitizers.qll`、`libraries/MySummaries.qll`、`queries/Pass1_PathTraversal.ql`、本报告（共六个，未生成其他文件）
- 包结构：`qlpack.yml`（`iris/opendiamond-cwe22`，依赖 `codeql/python-all: "*"`，已存在于 iris 根）位于 iris 根；库文件经 `import libraries.MySources` 等点号路径导入；查询 ID `py/augur/opendiamond/pass1-path-traversal`，`@kind path-problem`、`@problem.severity error`、`@precision medium`、`@tags security + external/cwe/cwe-022/023/036/073`，统一 pass key `"path_traversal"`，模块化 API 采用 `DataFlow::ConfigSig` + `TaintTracking::Global<Pass1Config>` + `import Pass1Flow::PathGraph` + `flowPath`（按 `assets/taint_query.ql.tmpl` 渲染）
- 审核状态说明：Phase 1 审查门产物为 `iris/labels/phase1_review.md`；`labels/review_decision.json` 在本工作区不存在（Phase 1 Step 3 按指令仅输出四个标签文件，未写该可选审计文件；WORKFLOW.md 4.5 明确其为可选审计物而非门）。本次按用户指令将 labels.json 视为已审核输入，未对其做任何修改；本报告即 Step 4–5 的建模记录。
- 执行状态：按指令**只生成文件、不编译、不执行正式分析**。所有谓词接口先对照本地缓存 `codeql/python-all 7.1.2`（`C:\Users\lzh\.codeql\packages\codeql\python-all\7.1.2`）库源码核对了存在性：`DataFlow::ConfigSig`（含 `isBarrier`/`isAdditionalFlowStep`）、`TaintTracking::Global`、`DataFlow::parameterNode/exprNode`、`Function.getArgByName`（`semmle/python/Function.qll:65`）、`AstNode.getScope()`（`semmle/python/AstExtended.qll:17`，`Class/Function/Module` 均为 `Scope` 子类，见 `Class.qll:89`、`Function.qll:10`、`Module.qll:11`）、`Attribute.getName/getObject`、`Subscript.getObject`（`AstExtended.qll:98`，`getValue` 的别名）、`Call.getFunc/getArg`、`Name.getId`、`Location.getFile().getAbsolutePath()`。QL 注释中避免了 glob 简写（如 `scopeserver/` 目录通配）以防 `*/` 提前闭合注释；未用 `module` 作变量名；未混用 `API::Node` 与 `DataFlow::Node`。

## 0. 实验独立性

与前序各项目（aiohttp/airflow/ansible/coderedcms/copyparty 等）一致：未读取 PyVul 真值、已知 CVE 行号或修复补丁；未读取仓库根部的 `VULNERABILITY_AUDIT_REPORT.md` 与 `path_traversal_sinks.csv`（Phase 1 起即排除）；未修改源码、CodeQL 数据库、Augur 安装及 Phase 1 标签（`labels.json` 及原始 CSV 均只读）。所有结构匹配规则均对照 `opendiamond_vuln` 真实源码逐站点验证（"验证：……"各条）。

## 1. 标签 → QLL 谓词对应关系

### 1.1 MySources.qll（54 条建模的 source 标签 → 8 个家族谓词）

共 137 条 source 角色标签中，建模 tp 与 candidate 的 54 条；fp/none 的 83 条全部有结构性排除依据（见文件头注释逐类列举）。

| 家族谓词 | 标签条目（ID 摘要 → 分类/置信度） | 结构匹配规则（已对照源码验证匹配站点集合） |
| --- | --- | --- |
| `isFlaskRouteParamSource` | 15 条 tp：4 个 store 的 `get_object_id(object_path)`、`get_object_src_http(obj_path)`（augment 121/159、diamond 79/131、mixer 209/260、test 239/290，0.85–0.98）；3 个 store 的 `get_object_meta(object_path)`（diamond 87、mixer 217、test 247，0.80–0.95）；augment `get_scope(rootdir)`（64/a0，0.85）；yfcc100m_mysql `get_object_src_http(rel_path)`（126/a1，0.98）；video `get_object(video)`、`get_object_id(video)`（84/a2、76/a2，0.95/0.85） | (handler, 形参名, store 文件) 三元组表 `reviewedRouteParam` + `DataFlow::parameterNode(f.getArgByName(pname))`；形参名在每个 handler 内唯一，(函数,文件) 对固定审核站点。augment 的 `get_object_meta(present)` 为 fp 不匹配（其参数名不同，自动排除） |
| `isCandidateClassesParamSource` | `S-dataretriever_mixer_store-63-get_mixer_classes-a5`、`S-dataretriever_test_store-65-get_mixer_classes-a5`（candidate/0.55） | `get_mixer_classes` 的 `classes` 形参，限 mixer/test 两个 store 文件 |
| `isXdrRpcSource` | `S-server_search-130-setup-a1`（tp/0.80）、`S-server_search-248-reexecute_filters-a1`（tp/0.75）、`S-proxy_search-139-setup-a1`（candidate/0.60） | `setup`/`reexecute_filters` 的 `params` 形参，分别限定 server/search.py 与 proxy/search.py；两文件中同名函数各仅一处 |
| `isBlasterBodySource` | `S-blaster_handlers-313-body`、`S-blaster_handlers-360-body`（tp/0.85） | `self.request.body` 属性读（body←request←self 三层属性链），限定 handlers.py 且外层函数所属类为 `SearchHandler`/`EvaluateHandler`——据此排除同为 `post` 方法的 `PostBlobHandler`（335 行，fp：请求体被 `BlobCache.add` 哈希后才使用） |
| `isBlasterJsonLoadsSource` | `S-blaster_handlers-245-loads`、`-360-loads`、`-507-loads`（tp/0.75–0.85） | `json.loads(...)` 调用结果节点（func 为 `json` 模块的 `loads` 属性），限定 handlers.py；验证该文件恰好 3 处 `json.loads` |
| `isSockjsEventSource` | `S-blaster_handlers-505-on_message-a1`（tp/0.75）、`S-blaster_handlers-553-start-a1`（tp/0.88） | `on_message(data)` 与 `start(search_key)` 形参，限定 handlers.py；`start` 同名存在于 server/proxy search.py，但文件约束保证唯一 |
| `isScopeCookieParseSource` | `S-blaster_handlers-253-parse`（candidate/0.60） | `ScopeCookie.parse(...)` 调用结果（对象为 `ScopeCookie` 名），限定 handlers.py:253 一处 |
| `isDjangoViewSource` | 26 条 tp（0.8）：11 条 `request` 视图形参（gigapan 72/83/114、flickr 24、core 18、cocktail 30/82、metadata 30/69、mirage 25、gatekeeper 26/52）+ 15 条 `request.POST/GET` 属性读 | `generate/browse/index/manage` 四类视图函数的 `request` 形参 + 对象为 `request` 名的 POST/GET 属性读，均限定 7 个 scopeserver 应用的 views.py；函数名白名单排除 `generate_cookie(scopeurls,...)` 等无 request 的私有辅助函数 |

被审核为 fp/none 的 source 家族一律不进入 Source（详见 MySources.qll 文件头）：int 转换器路由参数、blaster `[0-9a-f]{64}` 路由正则约束参数、`get_argument`/`request.args` 查询参数、`self.request.headers`、PostBlobHandler 请求体、TMPDIR/DIAMOND_CONFIG/HOME 环境读、`server/child.py:62` 的 environ 写、内部 `mixer_list` 形参、代理端 RPC 的 start/retrain/reexecute/send_blobs/session_variables_set。**没有任何"为了出路径而把内部函数形参当 Source"的情况**——全部 54 个 Source 均为标签审核过的外部输入边界。

### 1.2 MySinks.qll（38 条 sink 标签 → 9 个谓词）

| 谓词 | 标签（站点 → 分类） | 匹配规则与危险参数 |
| --- | --- | --- |
| `isSendFileSink` | augment 165（fp）、diamond 137、mixer 266、test 296（tp/0.98）、yfcc100m_mysql 128（tp/0.97） | `send_file`（直接导入名）调用第 0 参（文件响应路径）；限定 5 个 store 文件，每文件恰一处 send_file；gigapan 108（参数为流对象，none）不在文件集合内 |
| `isBuiltinOpenSink` | 19 处：diamond 48/54、augment 184、mixer 83/182/203、test 106/211/233、video 52（fp）、blobcache 99、blaster/cache 126、server/filter 685/702（candidate）、server/object_ 293/314（tp）、dataretriever/util 48（tp）/82/94（fp） | 内建 `open(x,...)` 第 0 参；文件级限定上述文件（已验证无其他内建 open）；blaster/cache.py 额外限定外层函数 `get_search`——排除 prune() 的 :161（none：listdir 派生路径） |
| `isPopenSink` | video 136（tp/0.88）、162（tp/0.90） | `subprocess.Popen(cmd_l)` 第 0 参（命令列表，路径在列表元素 `-i video_path` / `-show_format video_path` 中）；限定 video_store.py，恰两处 |
| `isOsStatSink` | video 104（candidate/0.65） | `os.stat(video_path)` 第 0 参；该文件唯一一处 |
| `isOsUtimeSink` | blobcache 83（candidate/0.60） | `os.utime(_path(sig))` 第 0 参（mtime 存在性预言机）；该文件唯一一处 |
| `isOsRenameSink` | blobcache 71、197（candidate/0.55–0.60）、blaster/cache 117/118/142（fp/0.75） | `os.rename` 第 0 与第 1 参（源/目的均为缓存路径操作数；标签逐条记录的危险下标 0 或 1）；blobcache 限定外层函数 `_try_with_rescue`/`make_dest`，排除 prune GC 的 :134（none）；blaster/cache 无其他 rename |
| `isOsLinkSink` | blobcache 115（fp）、189（candidate/0.60）、dataretriever/util 55（candidate/0.65） | `os.link` 第 0 与第 1 参（blobcache 189 危险下标 0 = `_path(sig)` 源、115 危险下标 1 = 目的；util 55 危险下标 1 = `self.path` 目的）；blobcache 限定 `add`/`make_dest`，util 限定 `__exit__` |
| `isCopyfileSink` | blobcache 195（candidate/0.60） | `shutil.copyfile(src, dest_tmp)` 第 0 参（`_path(sig)` 源）；该文件唯一一处 |
| `isZipFileSink` | blaster/cache 50（fp/0.70） | `zipfile.ZipFile(path,'r')` 第 0 参；限定外层函数 `__init__`（_CachedSearchResult），排除 put_search_result 的 :136（none：NamedTemporaryFile 句柄）；内存态 ZipFile（filter/__init__ 121/126、proxy/search 214、client/util 33）与 CLI bundle 输出（bundle.py 107）均不匹配 |

路径构造/解析类调用一律不是 Sink（与标签一致）：`os.path.join`/`dirname`/`basename`/`split`/`split_scheme`/`isfile`/`exists`/`isdir`/`glob` 为 summary/none；`send_file` 收到流对象（gigapan 108）与 `ZipFile(BytesIO(...))` 为 none——满足"区分路径文本与实际文件访问 / 文件对象"。

### 1.3 MySanitizers.qll（1 条标签 → 1 个谓词）

`K-dataretriever_augment_store-156-safe_join`（sanitizer/tp/0.9）→ `isSafeJoinBarrier`：augment_store.py:156 的 `safe_join` 调用结果节点（augment_store.py:27 直接 `from werkzeug.utils import safe_join`，故 callee 为裸 `Name`；该文件唯一一处调用）。逐条证据见第 4 节。

### 1.4 MySummaries.qll（3 个新增步骤 + 标准库已覆盖项 + 明确不建模项）

| 传播边 | 对应标签/依据 | 作用域 |
| --- | --- | --- |
| `str(x)` arg0→结果 | video 通道的组成部分（标签链 video_store 55/87：`video_path = str(_get_obj_absolute_path(video))`） | 审计范围全域（其余 str 调用对已审流惰性无害） |
| `split_scheme(url)` arg0→结果 | `K-server_object_-235/251/259/334-split_scheme`、`K-server_filter-647/662/789-split_scheme`（summary/tp 0.75–0.85）：helpers.py:120-127 一方包装器，函数体止于外部 `urlparse`，其返回默认不带污点 | server/object_.py 与 server/filter.py（全部已审调用点所在文件） |
| blaster 字典下标读 接收者→结果 | 支撑 3 条 `json_body` source 标签（245/360/507）的容器出口：`config['cookies']`、`f['code']`、`request['object']`、`req_obj['uri']` | 仅 blaster/handlers.py（避免无条件跨函数容器污染） |

**未重复建模（逐一核对过标准库源码）**：`os.path.join`（任意参数→结果）等路径计算由 `Stdlib.qll` 的 `OsPathComputationAdditionalTaintStep` 覆盖（对应 diamond 123、mixer 252、test 282、video 125、yfcc_mysql 137、blaster/cache 75/78/81/84、blobcache 60/177、util 44 等全部 join 标签）；字符串拼接（`path + ATTR_SUFFIX`、`dataset_path + '/' + c`）与列表元素→容器（video Popen 命令列表）为标准污点步骤；**一方包装函数不需要 param→return 边**——`TaintTracking::Global` 对库内函数是过程间的（实参→形参→函数体→返回表达式），`_get_obj_absolute_path`/`_get_index_absolute_path`/`_get_obj_abosolute_path`/`BlobCache._path`/`SearchCache._search_*`/`ObjectLoader.load`/`_load_localfile` 等包装器函数体只含标准库已建模操作。特别是 **augment 的 `_get_obj_absolute_path` 刻意不加边**：其函数体即外部 `safe_join`，默认返回值不带污点，受控 store 因此保持静默（`MySanitizers` 的 barrier 作为纵深防御）。

**明确不建模（见第 6 节局限）**：`urlparse` 结果→`parts.scheme/path`（外部 urllib）；`blob_cache[sig]` 的 dunder `__getitem__` 派发；XDR 参数对象属性内容（`params.filters[].code`、`params.object_id`）；`sig.lower()` 大小写折叠。均为"无证据不建立任意节点到任意节点传播"原则的直接应用。

## 2. 每个 Source 的外部输入边界与权限/访问条件

| Source 家族 | 外部输入边界 | 可控范围 | 权限/访问条件 |
| --- | --- | --- | --- |
| Flask 路由参数（17 条：15 tp + 2 candidate） | Werkzeug 路由注入，**百分号解码发生在路由匹配之前**：`<path:object_path>`/`<path:obj_path>`/`<path:rel_path>`/`<path:video>` 接受 `/`，`..`、绝对形式、重复分隔符均可注入；`rootdir`/`classes` 为默认 string 转换器（无 `/`，单段） | path 转换器参数完全可控（`os.path.join` 语义允许绝对/前导 `..` 参数整体替换基目录）；rootdir/classes 单段（`classes` 可为 `..` 单段） | dataretriever 监听 `DRHOST:DRPORT`（默认 127.0.0.1:5873，config.py:156-158），按部署可对外；objectlist/obj 端点无认证——设计上即对持有有效 scope cookie 的 diamond 服务器开放，但端点本身不校验 cookie（`/obj/<path:...>` 任意可达） |
| XDR RPC 参数（3 条） | 原始 TCP socket RPC（server 端口 5874 控制通道 / proxy 端口 5904），`@RPCHandlers.handler(25/30)` 分发的 XDR 解码结果 | `params.filters[].code/blob`（'sha256:\<sig\>' URI 字符串）、`params.object_id`（任意 URI） | **无认证**：ConnListener 直接 accept（server/server.py:181，proxy.py:112-119）；TCP Wrappers 为主机级限制而非输入过滤 |
| blaster 请求体/JSON（5 条） | Tornado HTTP 边界：POST /search、POST /result/\<hex64\> 的 `self.request.body` 及其 `json.loads`；sockjs WebSocket /search 的 `on_message(data)`/`start(search_key)` | JSON 任意字段（含 blob URI 字符串）；**websocket search_key 无 `[0-9a-f]{64}` 约束**（HTTP 路由有，blaster/__init__.py:51-58） | 监听 :8080；`@_restricted` 装饰器为可选 IP 白名单——人群限制而非内容过滤 |
| ScopeCookie.parse（1 candidate） | POST /search JSON `config['cookies']` 中的 cookie 字符串 | 内容受 scope.py:96-136 签名验证约束：cookie 发行者（scopeserver 管理员）控制 scopeurls；候选待复核跨服务链 | 同上；签名验证是授权而非路径净化 |
| Django 视图（26 条） | 7 个 scopeserver 应用的 `request` 形参与 `request.POST/GET` | 表单字段值完全客户端可控 | 全部 `@permission_required`（如 gigapan.search）——认证人群限制；视图内无文件访问 |

## 3. 每个危险 Sink 的真实文件操作、危险参数下标、访问类型与调用关系

（危险参数下标与标签逐条一致；调用关系均已对照源码）

| Sink 站点 | 真实文件操作 | 危险下标 | 访问类型 | 调用关系（谁把什么路径传进来） |
| --- | --- | --- | --- | --- |
| diamond_store.py:137 `send_file` | Werkzeug/Flask 文件响应（读取文件内容并写入 HTTP 响应） | 0 | 读+响应 | `get_object_src_http`：`_get_obj_absolute_path(obj_path)`=`os.path.join(DATAROOT, obj_path)`（:122-123），路由 `/obj/<path:obj_path>`，无包含检查 |
| mixer_store.py:266 / test_store.py:296 `send_file` | 同上 | 0 | 读+响应 | 同构（mixer :251-252、test :281-282），test_store 为生产 store（DATASTORE 注册） |
| yfcc100m_mysql_store.py:128 `send_file` | 同上 | 0 | 读+响应 | `get_object_src_http(dataset, rel_path)`→`_get_obj_abosolute_path`=`join(DATAROOT, dataset, rel_path)`（:136-137），`/obj/<dataset>/<path:rel_path>` |
| augment_store.py:165 `send_file` | 同上（受控） | 0 | 读+响应 | `_get_obj_absolute_path`=`safe_join(DATAROOT, obj_path)`（:155-156）——**safe_join barrier 在此之前执行** |
| dataretriever/util.py:48 `open` | 打开属性文件 | 0 | 读 | `DiamondTextAttr.__enter__`；构造方 diamond_store.get_object_meta（`/meta/<path:object_path>`→join）传 `path`，`__init__` 存 `self.path = path + '.text_attr'`（:36-37） |
| server/object_.py:293/314 `open` | 打开对象内容/元数据文件 | 0 | 读 | `ObjectLoader.load`→`_load_localfile/_load_attrbutes_localfile`；路径来自 scope list objectlist 的 `file:` URI（`split_scheme` 解出）与 XDR reexecute 的 object id（server/search.py:273-277） |
| server/filter.py:685/702 `open` | 读过滤器代码头/ docker yaml 配置 | 0 | 读 | `Filter._resolve_mode`；`self.code_path`=`ExecutableBlobCache.executable_path(sig)`，sig 来自 XDR setup 的 'sha256:' 过滤器 URI（server/filter.py:645-656） |
| blobcache.py:99 `open` | 读 blob 缓存文件 | 0 | 读 | `BlobCache.__getitem__`；`_path(sig)`=`join(basedir, sig.lower())`（:59-60），sig 来自 blaster `blob:` URI 的 `parts.path`（handlers.py:207）或 RPC 'sha256:' URI |
| blaster/cache.py:126 `open`+`pickle.load` | 读搜索缓存（并反序列化） | 0 | 读+反序列化 | `SearchCache.get_search(search_key)`；`_search_path`=`join(join(basedir, search_key), 'search')`（:77-78），search_key 来自 HTTP（hex 约束）或**无约束的 sockjs `start` 事件**（handlers.py:553） |
| video_store.py:136 `Popen`（ffprobe） | 子进程读取视频文件元数据 | 0（命令列表内 `-show_format` video_path） | 读 | `_ffprobe(video_path)`；video_store.py:55 `str(_get_obj_absolute_path(video))`，`/scope/.../<gididx>` 索引行与 `/obj/.../<path:video>` |
| video_store.py:162 `Popen`（ffmpeg） | 子进程读取视频文件并**将内容流式写入 HTTP 响应** | 0（命令列表内 `-i` video_path） | 读+响应 | `get_object`→`_create_ffmpeg_segment_proc(video_path, ...)`（:83-90） |
| video_store.py:104 `os.stat` | 文件元数据（mtime/size 泄露 + 缓存头） | 0 | 元数据 | `get_object` 的 video_path（join 无守卫） |
| blobcache.py:83 `os.utime`、:71 `os.rename`、:189 `os.link`、:195 `shutil.copyfile`、:197 `os.rename` | mtime 刷新/救援改名/硬链接入可执行目录/复制/落名 | 0/1（见 1.2） | 元数据/移动/链接/复制 | 均为 `_path(sig)` 或 `join(_executable_dir, sig)` 派生路径；blaster/cache 117/118/142 的键为服务端生成的哈希（fp） |
| dataretriever/util.py:55 `os.link`、:82/:94 `open`、augment 184 `open` | 属性写通道/列表读/索引写 | 1/0/0 | 写/读/写 | DiamondTextAttr 'w' 模式（当前调用方只用 'r'）；augment 链上游 safe_join 受控 |

## 4. Barrier 是否真能阻断特定穿越机制（逐机制核对）

**唯一 barrier：augment_store.py:156 `safe_join(DATAROOT, obj_path)`（调用结果节点）**

| 穿越机制 | safe_join 能否阻断 | 证据 |
| --- | --- | --- |
| 绝对路径替换（`obj_path = '/etc/passwd'` 使 `join` 整体替换基目录） | **能**：werkzeug safe_join 拒绝绝对文件名 | augment_store.py:155-156 是该 store 全部三个通道（`/obj`、`/id`、`/root` rootdir）的唯一路径出口；对照其余 store 的裸 `join` 行为（diamond :123 无任何检查即被 send_file 使用） |
| `..` 段爬出基目录 | **能**：posixpath 规范化后包含检查，逃逸即拒绝（路由上下文抛 NotFound） | 同上；这也是 4 个未受控 store 的确认 CWE-22 机制（标签 tp 0.97–0.98） |
| 符号链接 | **不能**（记录于标签 caveat）：safe_join 不解析符号链接，DATAROOT 内指向外部的符号链接仍可穿越 | 全库无 `realpath`/`lstat`/`resolve-then-compare`（标签审核阶段已确认）；此 caveat 已写入 MySanitizers.qll 头注与 labels.json |
| 双重解码 | 不适用：本库无 `unquote` 调用，`split_scheme` 为纯 urlparse 拆分（helpers.py:122-127） | MySummaries 的 split_scheme 步骤因此不引入双解码风险 |

**其余候选全部论证为非 barrier**（写入 MySanitizers.qll 头注）：`'GIDIDX'+x.upper()` 前缀 + string 转换器（仅对索引文件名单段生效，且这些参数非 Source）；Tornado 路由正则、`@permission_required`/`@_restricted`（人群限制）；`ScopeCookie.verify`（签名授权）；`isfile/exists/isdir`（存在性门 + TOCTOU 窗口）；`split_scheme`（无过滤）；`sig.lower()`（大小写折叠）；`classes.replace('%2C',...)`（结果被丢弃的 no-op bug，mixer_store.py:177/206）；`normpath/realpath/basename/startswith` 在审计范围内根本不作为守卫出现——无一被机械视为安全过滤。

## 5. 路径连接、解码、规范化、允许根目录与符号链接的证据

- **允许根目录**：`DATAROOT`/`INDEXDIR` 来自 DiamondConfig（config.py:162-164，默认 `/srv/diamond` 与 `/src/diamond/INDEXES`，操作员级配置）。全部 store 以 `os.path.join(DATAROOT, 用户路径)` 构建——除 augment 的 safe_join 外无一处包含检查（5.1 节各表为证）。
- **连接**：`os.path.join`（标准库污点步骤，参数→结果）；`+` 拼接（`path + ATTR_SUFFIX`、`'GIDIDX'+gididx.upper()`、`dataset_path + '/' + c`）；`'/'.join(path.split('/')[:-2])` 段手术（mixer/test 的 class_text，仅 isfile 预言机）。
- **解码**：Werkzeug/Django 在路由前完成百分号解码（`<path:...>` 参数所见即解码后文本）；库内无 `unquote`；`urlparse` 仅拆分不解码——不存在重复/多次解码通道。
- **规范化**：无任何 `normpath/realpath/canonicalize` 使用于校验；safe_join 内部规范化包含检查是唯一一处规范化语义。
- **符号链接/TOCTOU**：无符号链接感知校验（见第 4 节）；BlobCache 两遍 GC 的 stat/rename/unlink 竞态与 `mktemp()`（blobcache.py:188）为设计内 TOCTOU，已在标签 rationale 记录，不影响 barrier 判定。
- **文件访问时机**：所有已确认读通道中，文件访问（send_file/open/Popen/stat）均发生在唯一的路径构建（join）之后、无中间校验；augment 的 safe_join 在文件访问**之前**执行（构建时即拒绝）。

## 6. 额外传播边、动态调用/别名遗漏、CodeQL 局限与诊断路径（不计入正式告警）

**预期正式告警通道（模型内完整可解析）**：
1. diamond/mixer/test/yfcc100m_mysql 的 `/obj/<path:...>` → `send_file`（4 条完整流：路由参数 Source → 过程间调用 → join 标准步骤 → send_file Sink）；
2. diamond `/meta/<path:object_path>` → `DiamondTextAttr` → util.py:48 `open`（属性存取 `self.path` 由标准属性分析连接，`with` 语句体内的 open 无需 dunder 派发建模）；
3. video `/obj/.../<path:video>` → `str()` 步骤 → `os.stat`:104 与 `Popen`:136/:162（命令列表经标准容器步骤）；
4. blaster sockjs `start(search_key)` → `get_search` → `_search_path` → blaster/cache.py:126 `open`（过程间 + join 标准步骤；pickle 反序列化同点，Pass 6 相关）。
5. augment 全部通道预期**静默**：`_get_obj_absolute_path` 函数体止于外部 `safe_join`（默认参数污点不达返回值）+ barrier 纵深防御——与标签"该 store 受控"一致。

**已知局限（预期不触发正式告警，均不添加无证据边）**：
- **XDR RPC 参数属性内容**：`params`（Source）→ `params.filters[].code` / `params.object_id` 属性读取默认不携带污点，XDR 解码层亦在库外。setup/reexecute 两条 tp Source 已按标签建模，但到 object_.py:293/314、server/filter.py:685/702、blobcache 系 Sink 的链路预期断裂于属性读取处。`split_scheme` 步骤（已建）服务于此链的 URI 拆分段。
- **blaster `blob:` URI 链**：json.loads/请求体 Source →（新增的下标步骤）→ `f['code']`/`req_obj['uri']` → `_BlasterBlob.fetch` 内 `urlparse(self.uri)`（外部）→ 断裂；`parts.path` 属性与 dunder `blob_cache[...]`→`__getitem__` 形参派发均未建模——blobcache.py:99/189/195/197/83/71 等 Sink 保持可达性待诊断。
- **`sig.lower()`**：即便上游可达，大小写折叠方法若未建模亦会截断 `_path` 内的 join 参数。
- **动态派发遗漏**：sockjs 事件经 `getattr(self, event)` 动态派发（handlers.py:514）——`start` 形参 Source 是对审核过的事件处理器的直接形参匹配，不依赖 CodeQL 解析动态派发；Django 表单 cleaned_data→`generate_cookie` 的跨服务链（Django 视图 Source 已建、scope.py:253 summary/candidate 标签存在）超出单库污点范围，属 Phase 2 MySummaries 跨服务边的既有记录（detection.json coverage gap），本轮不建立。
- **诊断建议（不构成正式 Pass 1 告警）**：可在 `iris/diagnostics/` 另写调试查询验证（a）blobcache `__getitem__` 形参在 `blob:` URI 调用点是否可达、（b）XDR `params` 属性读取的污点可达性、（c）`start(search_key)` 到 cache.py:126 的完整路径。本轮按指令未生成诊断文件。

**标签遗漏核查**：38 条 sink 角色标签全部建模；137 条 source 角色中 54 条 tp/candidate 全部建模、83 条 fp/none 均有结构性排除；70 条 summary 标签中标准库覆盖项与 3 个新增步骤的对应关系见 1.4 节，其余（包装器 param→return 不需要、外部 urlparse/dunder 不建）有明确论证。**未发现需要退回第五步重新审核的标签遗漏**，labels.json 未做任何修改。

## 7. 与后续步骤的衔接

`MySanitizers.qll` 含 1 条 barrier（safe_join），查询的 `isBarrier` 钩子经其接线（非空但单一）；`isAdditionalFlowStep` 仅 3 个有证据步骤。Step 6 运行 `codeql database analyze` 时（本次未执行），预期结果分布见第 6 节；过滤启发式（WORKFLOW 5.3.2 的 Path Traversal FP 规则：startswith 基目录守卫、basename 提取、显式 `..` 拒绝）在本项目仅 safe_join 一处命中，与 barrier 一致，不会误杀其余通道。

## 8. 编译验证与修复记录（2026-10-22 追加）

初次 `codeql query compile --check-only`（CodeQL CLI，包 `codeql/python-all 7.1.2`）报出 3 个 error / 2 个 warning，已全部修复并复验通过：

- **根因**：QL 语言没有字符串 `+` 拼接（`+` 仅为算术运算符）。三个库文件中的辅助谓词写了
  `matches("%/opendiamond/" + subpath)` / `matches("%/opendiamond/dataretriever/" + base)`
  这类动态拼接模式，编译器报 `'subpath' is not bound to a value`（MySummaries.qll:109、MySinks.qll:91）
  与 `'base' is not bound to a value`（MySources.qll:87）。
- **修复**：改为字面量映射表——`MySources.storeFilePattern`（6 行）、`MySinks.filePattern`（11 行）、
  `MySummaries.filePattern`（3 行），把短文件名映射为完整 `matches` 模式串；所有模式串均为字符串字面量，
  语义与原设计完全一致（文件级作用域约束不变）。
- **warning 清理**：删除 `MySinks.qll` 与 `MySources.qll` 中未被调用的 `inAuditScopeAst`
  （MySummaries 中的同名谓词被 `strConversionStep` 实际使用，保留）。
- **复验**：`codeql query compile --check-only -- queries/Pass1_PathTraversal.ql` → `Done [1/1]`，
  无 error 无 warning。修复未触碰 `labels.json`、Phase 1 产物、源码与数据库；谓词逻辑
  （Source/Sink/Barrier/Summary 匹配规则）零变更，仅文件作用域辅助实现由拼接改为字面量表。
