# Augur Phase 2 Step 4–5 — pyramid Pass 1 (Path Traversal) 污点模型与路径查询生成说明

- Run ID：`pyramid-pass1-pathtraversal-20261023`（与 Phase 1 标签一致）
- 生成时间：2026-10-23
- 输入：`labels/labels.json`（315 entries，schema 校验通过）、`labels/labels_raw_pass1.json`、`labels/label_stats.md`、`labels/phase1_review.md`、`extraction/{sources,sinks}.ql`（scope guard 镜像来源）、`assets/taint_query.ql.tmpl`、`references/{python.md,patterns.md}`、`WORKFLOW.md` §5（Phase 2），以及 `pyramid_vuln` 源码树中被引用的全部位置（逐行核对：static.py、i18n.py、traversal.py、path.py、response.py、request.py、router.py、view.py、config/assets.py、asset.py、urldispatch.py、authentication.py、events.py、predicates.py、viewderivers.py、config/views.py、session.py、threadlocal.py、wsgi.py、httpexceptions.py、scripts/*）
- 产物：`libraries/MySources.qll`、`libraries/MySinks.qll`、`libraries/MySanitizers.qll`、`libraries/MySummaries.qll`、`queries/Pass1_PathTraversal.ql`（本报告为第六件）
- 工具链事实：CodeQL CLI 2.25.1；本地用户级包缓存 `codeql/python-all 7.1.1/7.1.2` + `codeql/dataflow 2.1.3/2.1.6/2.1.7`；iris 根目录 `qlpack.yml`（`iris/pyramid-cwe22`，依赖 `codeql/python-all: "*"`，Step 0 产物，未修改）。本步只生成文件，**不编译、不执行分析**（按指令）。所有被使用的 CodeQL API 均在 python-all 7.1.2 包源码中逐项核实存在：`DataFlow::Node.asExpr()`、`DataFlow::parameterNode(Parameter)`（DataFlowPublic.qll:350）、`DataFlow::ConfigSig` 的 `isBarrier`/`isAdditionalFlowStep`（codeql/dataflow DataFlow.qll:401-427，默认 `none()`）、`TaintTracking::Global` + `PathGraph`、AST 类 `Attribute`/`Call`/`Subscript`/`Name`/`StringLiteral`/`Function`/`Parameter`（`getName`/`getObject`/`getFunc`/`getArg(int)`/`getAnArg`/`getValue`/`getIndex`/`getS`/`getPosition`）以及内置污点步骤（concatStep、subscriptStep、stringManipulation 的 `%`/`join`/format、containerStep 字面量、forReadStep，见 TaintTrackingPrivate.qll）。
- 独立性声明：未读取 PyVul 真值、已知 CVE 行号或修复补丁；未修改源码、数据库、Augur 目录与 Phase 1 标签（`labels/` 目录内容保持 2026-10-23 Step 3 状态，md5 校验 sources.csv/sinks.csv 未变）。

## 0. 审核状态说明（review_decision.json）

`labels/review_decision.json` 不存在：Step 3 的 CHECKPOINT 以 advisory 模式执行（WORKFLOW §4.5 允许，review_decision.json 是可选审计文件），`labels/phase1_review.md` 是审核 payload 但未写决策文件。本次用户指令"执行 Phase 2 Step 4–5"即视为进入 Phase 2 的批准。据此采取的渲染策略（与 pretalx 项目一致）：

- role=source 的 153 条（全部 classification=tp）→ 全部生成 Source 规则（6 条规则，按标签 ID 注释）。
- role=sink 且 classification ∈ {tp, candidate} 的 47 条（46 tp + 1 candidate）→ 全部生成 Sink 规则（9 条规则）。
- role=sink 且 classification=fp 的 4 条（K020/K024/K032/K041：pshell PYTHONSTARTUP、override_asset 配置期校验）→ 不进入 Sink 模型（操作员/配置边界，无可信源到达）。
- role=none 的 102 条（98 source 行 + 4 sink 行）→ 不进入任何模型（CLI argv/argparse、ini 设置、os.environ、配置期 asset spec、environ 写目标、服务器 WSGI 键、字面量参数、realpath 规范化、pviews/prequest CLI 模拟请求等，逐条排除理由见 labels.json 的 rationale）。
- role=sanitizer 的 2 条（A001/A002）→ 生成 Barrier 规则。
- role=summary 的 7 条（A003–A008 + S027）→ 处理见 §1.4（3 个渲染为污点步骤，4 个有据不渲染）。

## 1. 标签 → QLL 谓词对应总表

### 1.1 MySources::isSource(n, "path_traversal")（153 条，6 条规则）

| 规则 | 标签（编号） | 外部输入边界 | 权限/访问条件 | 源码证据 |
| --- | --- | --- | --- | --- |
| `requestFieldRead` | S003-S026, S028-S034, S036-S053（49 条，tp，conf 0.7–0.98） | webob/pyramid Request 字段属性读：path_info(7)/subpath(1)/path(1)/url(5)/path_url(3)/query_string(2)/accept_encoding(2)/environ(11)/cookies(4)/headers(5)/POST(1)/params(2)/GET(1)/matchdict(3)/locale_name(1)。接收者限定 `request`/`self.request`（locale_name 额外允许 `self`，因 Request 混入 LocalizerRequestMixin，request.py:144-149；reified locale_name 属性在 i18n.py:377-380，self 形式读点 i18n.py:363） | 静态视图与路由任何 HTTP 客户端可达；environ/cookies/headers 的认证数据无权限前置；locale_name 经 `_LOCALE_` param/cookie 由任何请求方可设置 | static.py:131/133（Chain A 入口）；i18n.py:135/137/166 与 i18n.py:363（Chain B 入口）；traversal.py:596-620；urldispatch.py:75；authentication.py:211-1143 |
| `requestFieldSubscript` | S109, S114, S118, S119（4 条，tp） | `request.cookies[...]`（csrf.py:139）与局部 `environ[...]` 读：traversal.py:631 `environ[HTTP_X_VHM_ROOT]`（X-Vhm-Root 请求头）、authentication.py:1058/1146 `environ['REMOTE_ADDR']`（行号限定，避开 1105-1107 的赋值目标） | X-Vhm-Root 任何客户端可发送（影响 virtual root 计算，非文件路径）；REMOTE_ADDR 用于 auth_tkt IP 绑定 | traversal.py:629-640；authentication.py:1055-1059/1140-1148；csrf.py:139 |
| `requestFieldLookup` | S144-S158（15 条，tp） | `request.<field>.get(...)` 值查找（environ/cookies/headers/POST/params/matchdict/GET） | 同字段族；i18n.py:135/137 的 `_LOCALE_` 为 Chain B 的参数/cookie 入口 | i18n.py:135/137；csrf.py:230/238/311；predicates.py:91/131/201；authentication.py:211/214/415/1052/1376；renderers.py:381；session.py:218 |
| `localDictGet` | S159-S164（6 条，tp） | 局部 `environ.get`/`matchdict.get`（行号限定到审核过的 6 个读点；局部名约定在 extraction 阶段已人工核验，见 detection.json request_field_lookup 家族） | SCRIPT_NAME/PATH_INFO 为服务器填充的原始 WSGI 边界值；traverse/subpath 为路由 URL 解码后的 star-arg 段 | traversal.py:729（VH root）、traversal.py:601/608（`matchdict.get('traverse'/'subpath')`）、request.py:274/275、httpexceptions.py:257 |
| `getattrRequestRead` | S121-S137（17 条，tp） | `getattr(request, ...)` 动态属性读（arg0 限定 `request`） | i18n.py:133 `getattr(request, '_LOCALE_', None)` 为 Chain B 属性入口；request.py:276 读 subpath 重建 PATH_INFO；其余 15 处为框架属性管道（保守二阶边界） | i18n.py:132-138；request.py:276-291；view.py/scripting.py/predicates.py/viewderivers.py/renderers.py/config/views.py |
| `entryParamSource` | S176-S239（62 条，tp，conf 0.75–0.98） | WSGI environ 形参（S202-S204：Router.__call__ router.py:262、Router.request_context :193、HTTPException.__call__ httpexceptions.py:336——最外层不可信边界）与 request 形参（请求入口方法 S226-S239：static_view.__call__ static.py:104、ResourceTreeTraverser :595、RoutesMapper urldispatch.py:72、Router handle/invoke ×3、事件 ×4、谓词 ×15、视图包装器 ×26、cache buster ×2 等）。按（函数名, 形参名, 位置, 文件, 形参行号）精确匹配，未标注的同名项（config/views.py:508 的未标注 `wrapper`、pviews.py:107 RoutesMultiView、response.py:43 FileResponse 的 request 形参——均为 role=none）不会被提升为 Source | request 对象本身承载全部 HTTP 可控数据；字段级读取才是精确源（见上），参数源仅为保守召回（对象污点不会自动流向属性读，无属性读步骤，故不会产生虚假路径） | 标签 location 字段逐条对应 |

未成为 Source 的角色（"内部形参不自动是 Source"）：98 条 role=none（CLI/配置/environ 写目标/服务器键/字面量/realpath/CLI 模拟请求）全部排除，理由逐条记录在 labels.json rationale。

### 1.2 MySinks::isSink(n, "path_traversal")（47 条，9 条规则）

谓词匹配的是**危险路径参数（路径文本）**；被 `open()` 返回的文件对象不在匹配范围（pyramid 的 FileResponse 实参 static.py:112 传的是 filepath 路径文本，不是文件对象）。全部按（调用形态, 文件, 行号）限定到审核过的调用点。

| 规则 | 标签 | 真实文件操作 / 访问类型 | 危险路径参数 | 调用关系（谁到达此处） |
| --- | --- | --- | --- | --- |
| `openPathArg` | K022(i18n.py:203), K023(:272, candidate), K025(response.py:57), K026(config/assets.py:281), K027(path.py:436), K028(static.py:394) | 文件读（全部 `open(...,'rb')`） | arg 0 | K022 ← make_localizer（**Chain B 落点**，locale 名未经任何 `..` 过滤）；K025 ← FileResponse.__init__ ← static_view（Chain A，_secure_path 之后）；K026 ← FSAssetSource.get_stream ← 资产覆盖机制；K027 ← FSAssetDescriptor.stream ← AssetResolver.resolve（配置侧 spec）；K028 ← ManifestCacheBuster（配置期 manifest_spec）；K023 ← Translations.load（公开 API，库内无请求派生调用方，candidate 人工复核） |
| `osListdirArg` | K034(i18n.py:200), K035(assets.py:302), K036(path.py:442) | 目录枚举 | arg 0 | K034 ← make_localizer（**Chain B**，locale 派生目录）；K035/K036 ← 资产覆盖/描述符机制（配置侧） |
| `osPathMetadataArg` | K029/K030/K040(i18n.py:193/198/202), K019/K031(assets.py:275/297), K021/K033(path.py:445/439) | 存在性探测（isdir/isfile/exists——信息泄露 oracle 与 TOCTOU 前置） | arg 0 | K029/K030/K040 ← make_localizer（Chain B 的门与探针）；其余 ← FSAssetSource/FSAssetDescriptor（配置侧） |
| `aliasMetadataArg` | K047/K048(response.py:55/56), K052(static.py:153), K055(:170), K049(:201) | 元数据读（`from os.path import getmtime, getsize, isdir, exists` 裸别名） | arg 0 | K047/K048 ← FileResponse（HTTP 文件服务伴随读）；K052/K055/K049 ← static_view（Chain A，受 `_secure_path` 保护后的路径；K049 为 size 排序，与后续 open 间存在 TOCTOU 窗口） |
| `pkgResourcesArg` | K001(asset.py:43), K002(assets.py:229), K010-K018(assets.py:228-254) | setuptools 外部 API 的真实文件访问（resource_filename 解析+可能解包、resource_stream 打开读、resource_exists/isdir/listdir 元数据） | arg 1（包相对资源路径） | K001 ← abspath_from_asset_spec（配置期 spec：manifest_spec/翻译目录/static root）；K002/K010-K018 ← PackageAssetSource 覆盖机制（配置前缀 + resource_name） |
| `selfPkgResourcesArg` | K042-K046(path.py:408-421) | 同上（PkgResourcesAssetDescriptor 方法内的 `self.pkg_resources.resource_*`） | arg 1（self.path，配置期 spec 的包相对路径） | ← AssetResolver.resolve 的描述符方法（pserve watch_files、翻译目录等操作员链） |
| `defaultProviderArg` | K004-K009(assets.py:32-82) | OverrideProvider 对 `pkg_resources.DefaultProvider.*` 的 super 委托——resource_name 进入 setuptools provider 的真实文件访问 | get_resource_filename/stream/string 为 arg 2（self/manager 之后）；has_resource/resource_isdir/resource_listdir 为 arg 1 | ← pkg_resources provider 机制（被覆盖包的资产加载；请求侧 resource_name 仅经 static view 包模式且已被 `_secure_path` 过滤） |
| `staticAliasArg` | K051(static.py:142), K053(:167), K054(:168) | resource_isdir/exists/filename（static.py:6 `from pkg_resources import ...` 裸别名） | arg 1（请求派生、`_secure_path` 之后的资源名） | ← static_view 包模式（Chain A）；K054 结果 → find_best_match → FileResponse |
| `fileResponseArg` | K050(static.py:112) | 文件响应（FileResponse；实际 open/getmtime/getsize 在 response.py:55-57 = K025/K047/K048） | arg 0（filepath 路径文本） | ← static_view.__call__（Chain A 的框架级落点） |

排除的 sink（policy，详见 §0）：K020/K032（override_asset 配置期 exists/isdir）、K024/K041（pshell PYTHONSTARTUP）、K003（字面量 `''`）、K037-K039（realpath，仅规范化）。

### 1.3 MySanitizers::isBarrier(n, "path_traversal")（2 条标签，2 条 barrier）

| 标签 | 谓词规则 | barrier 节点 | 阻断机制论证 |
| --- | --- | --- | --- |
| A001（sanitizer, tp, 0.95） | `_securePathCall`：static.py:134 的 `_secure_path(path_tuple)` 调用结果 | 调用表达式（其后所有下游用值都读自该调用） | 见 §5.1：拒绝 `..`/`.`/空段与含 `/`、`os.sep` 的段；先于 docroot join（:141/:152）与 find_resource_path（:167-168）执行；None → HTTPNotFound（:136-137）；lru_cache 输入为不可变元组、函数纯 |
| A002（sanitizer, tp, 0.9） | `splitPathInfoCall`：extraction scope 内全部 `split_path_info` 调用结果（traversal.py:506/613/632/655、urldispatch.py:192） | 调用表达式 | 见 §5.2：词法消解 `..`（弹出前一段，空前导 `..` 亦被丢弃）、丢弃 `''`/`.`、段内不可能含 `/`；局限（Windows `\` 段存活）对本 pass 无害：文件访问用途全部再过 A001 |

### 1.4 MySummaries::isAdditionalTaintStep(from, to, "path_traversal")（7 条 summary 标签的处理）

| 标签 | 处理 | 依据 |
| --- | --- | --- |
| A003 traversal_path_info | **不渲染**（默认过程间数据流已覆盖） | 函数体在库内、模块级名字可解析；其污点相关边界是 A002 barrier |
| A004 static_view.get_resource_name | **不渲染**（同上） | 类内 `self.get_resource_name(request)` 方法调用默认过程间解析；入口已是源（S037/S045），输出受 A001 保护 |
| A005 default_locale_negotiator / A007 LocalizerRequestMixin.localizer / S027 request.localizer | **不渲染**（被 S026 源规则取代） | reify + registry.queryUtility 间接调用不可静态解析，正是这些 summary 描述的缺口；S026 把 `request.locale_name`/`self.locale_name` 属性读本身定为审核过的源（request.py:144-149 混入关系核实），从另一侧闭合该链。再渲染返回值→属性读边会与该源重复，违反"避免无条件跨函数传播" |
| A006 make_localizer | **渲染**为 3 个步骤：`osPathJoinStep`（join 半边）+ `osPathRealpathStep`（规范化半边）+ `listAppendStep`（容器半边） | i18n.py:189-203 真实代码：join(tdir, lname) → realpath → isdir → append → 迭代 → join → listdir/isfile → realpath → open。join/realpath/append 均为默认污点模型不覆盖的调用形态（详见 §6.1） |
| A008 call_app_with_subpath_as_path_info | **不渲染**（environ 写→读间接层无库内文件 sink） | request.py:276-291 把 subpath 重建为子请求 PATH_INFO；库内静态视图直接读 request.subpath（S045），不经该路径；无条件 dict-store→load 边会造成任意传播。记为诊断缺口（§6.3） |

## 2. 每个 Source 的外部输入边界与权限/访问条件

见 §1.1 表第 3-4 列。要点：

- **真正不可信边界**：WSGI environ（PEP 3333，S202-S204 及 environ 字段/下标/get 读）；request 对象的字段（path_info/subpath 为原始 URL 路径或路由解码段；params/cookies/headers/POST/GET 为查询串/cookie/头/表单值；matchdict 为路由模式绑定的 URL 解码段；locale_name 为 `_LOCALE_` 协商结果）。HTTP 客户端任意可达（静态视图、路由匹配、locale 协商均无认证前置）；认证数据（repoze.who identity、auth_tkt、Authorization）为攻击者可影响但仅用于认证决策，非路径相关。
- **操作员/开发者边界（未成为源）**：CLI argv/argparse（scripts/*）、ini settings（watch_files/open_url）、os.environ（PYTHONSTARTUP）、配置期 asset spec/override 前缀/static root_dir/manifest_spec（它们是与请求路径拼接的 **base** 侧，请求侧才是污点侧）、pviews/prequest 的 Request.blank 模拟请求。逐条排除理由在 labels.json。
- `getattr(request, ...)` 17 条中仅 i18n.py:133 与 request.py:276 有路径相关性，其余为保守二阶边界（按标签保留，无属性读步骤故不会自行产生路径）。

## 3. 每个危险 Sink 的真实文件操作与调用关系

见 §1.2 表。要点：区分了路径文本参数（全部 47 个 sink 的匹配位）与文件对象（不匹配；K050 FileResponse 实参为 filepath 路径文本）；访问类型分文件读（open 6 处、resource_stream 2 处）、目录枚举（listdir 3 处 + resource_listdir 3 处）、元数据/存在性（isdir/isfile/exists/getmtime/getsize 16 处 + resource_exists/isdir 4 处）、路径解析（resource_filename 6 处）、文件响应（FileResponse 1 处）。两条完整调用链：Chain A（guarded，见 §4/§5）、Chain B（unguarded）。

## 4. 路径连接 / 解码 / 规范化、允许根目录与符号链接证据

- **URL 解码（一次性、入口规范化）**：PATH_INFO 按 PEP 3333 latin-1→UTF-8 解码（traversal.py:527-528 decode_path_info，无效 UTF-8 → URLDecodeError）；`traversal_path`（:420-435）经 unquote_bytes_to_wsgi 解百分号编码；路由 match 值在进入 matchdict 前由路由层解码。**无二次解码步骤**会重新引入 `%2e%2e`——即便以字面量段存活，也会被 `_secure_path`（A001）拒绝。
- **路径拼接**：static.py:152 `normcase(normpath(join(norm_docroot, path)))`（文件系统模式）与 :141 `'%s/%s' % (docroot, path)`（包模式）——`%` 格式化为 python-all 原生污点步骤（stringManipulation 的 Mod 规则）；`os.path.join` 为 MySummaries 的证据限定步骤（§6.1）。i18n.py:192/197/201 join —— 无包含检查（Chain B）。
- **允许根目录**：static 视图 docroot/norm_docroot（配置期，static.py:98/152）为 Chain A 的根；i18n translation_directories（配置期）为 Chain B 的名义根——但 join 的 lname 侧无任何检查，且 **join 语义在 lname 为绝对路径时直接丢弃 tdir**（Chain B 的绝对路径逃逸向量）。
- **符号链接**：Chain B 用 realpath（解析符号链接，非包含检查，i18n.py:192/198/201）；Chain A 无符号链接检查（仅存在性检查），存在 TOCTOU 窗口（static.py:201 getsize 与 response.py:55-57 open 之间；reload=False 时 filemap 缓存收窄窗口）。均为观察记录，未影响标签/屏障。
- **规范化顺序**：Chain A：解码 → split（词法 `..` 消解，A002）→ `_secure_path`（黑名单段过滤，A001）→ join/normpath → 存在性 → open。先规范化/过滤后使用，顺序正确。Chain B：locale 名 → join → realpath（解析后无包含复核）→ isdir → listdir → isfile → open——**规范化在检查之后且无包含验证**，即 Chain B 的缺陷。

## 5. Barrier 有效性分析（能否真正阻断特定穿越机制）

### 5.1 A001 `_secure_path`（static.py:263-285, 276）

- **`..` 段**：`_has_insecure_pathelement = {'..', '.', ''}.intersection`（:272）直接拒绝 → None → HTTPNotFound('Out of bounds')（:136-137）。对 traversal_path_info 输出（已词法消解）与 request.subpath（traversal_path 同族计算）双保险。
- **`.`/空段**：同上拒绝。
- **绝对路径/分隔符注入**：`_seps = {'/', os.sep}`（:263）+ `_contains_slash`（:266-270）拒绝任何含 `/` 或 os.sep 的段 → 无段可携带分隔符 → `join()`/`'%s/%s'` 恒在 docroot 前缀之下；绝对路径（以分隔符开头）不可能作为单段出现。Windows 上 `\` 显式被拒；POSIX 上段内 `\` 是字面文件名字符，非分隔符。
- **执行时机**：static.py:134 先于 :141/:152 拼接与 :160-171 find_resource_path（→ FileResponse :112 → open response.py:57）——真实的前置守卫。
- **barrier 建模**：阻断 `_secure_path` 调用结果节点 → 其后所有下游使用（path 变量 → join → resource_path → exists/isdir/filename → FileResponse → open）的污点全部截断。Chain A（S037/S045 → 静态文件 sink）不会告警，与 Phase 1 审核结论一致（受保护的正常文件服务 ≠ 漏洞）。

### 5.2 A002 `split_path_info`（traversal.py:510-523）

- 输出元组无 `..`/`.`/`''` 段、段内无 `/`（输入按 `/` 切分）；`..` 弹出前一段、空前导 `..` 丢弃。
- **局限**：Windows 上输入段内字面 `\`（os.sep）可存活（split 按 `/` 切分）；但该元组的全部**文件访问**用途都再经 A001（static.py:134），A001 拒绝含 os.sep 的段；traverser `__getitem__` 树遍历在本库无文件 sink。故对本 pass 无误杀。
- barrier 建模在 5 个调用点（traversal.py:506/613/632/655、urldispatch.py:192）的调用结果上；VH-root 链（S109 → decode → split :632/:655）同样被截断（其下游无文件 sink）。

### 5.3 明确不作为 barrier 的项（按具体实现逐个核查，非按函数名）

- `os.path.realpath`：解析符号链接、无包含、不拒 `..`（K037-K039 role=none；在 MySummaries 中作为传播步骤）。
- `os.path.normpath`/`normcase`（static.py:98/152）：纯词法规范化，单独不包含任何逃逸（是守卫的拼接侧，仅与 A001 组合后才安全）。
- `DirectoryOverride.startswith` 前缀匹配（config/assets.py:190）：配置期覆盖路由，非请求路径的前置守卫。
- `isdir`/`isfile` 存在性检查（i18n.py:193/198/202）：存在性门而非校验——建模为 sink（oracle）。

## 6. 额外传播边、动态调用/别名遗漏、CodeQL 局限与诊断路径

### 6.1 渲染的 3 条额外传播边（均证据限定，见 MySummaries.qll 头注）

1. `osPathJoinStep`：`os.path.join` 任意实参 → 调用结果，限定 src/pyramid scope。python-all 自带等价全局步骤（frameworks/Stdlib.qll `OsPathJoinCallAdditionalTaintStep`），但仅在 `import semmle.python.Concepts`（→ Frameworks → Stdlib）时注册，而 `import python` 不引入；本查询**有意不导入 Concepts**，使每条激活的传播边都是本文档记录的证据限定步骤（确定性、可审计）。此步镜像 Stdlib 规则并收窄到 src/pyramid。
2. `osPathRealpathStep`：`os.path.realpath` arg0 → 结果（i18n.py:192/198/201 为 scope 内仅有的 3 处，grep 核实）；realpath 是路径文本→规范化路径文本的包装器，污点穿透——它不是 sanitizer（§5.3）。
3. `listAppendStep`：`list.append(arg)` arg → 接收者，限定 i18n.py（:179 `locales_to_try.append(current_locale_name)`、:194 `locale_dirs.append(ldir)`）。python-all containerStep 只覆盖字面量构造 `[x, y]`，不覆盖 `.append()`；for 循环读取（forReadStep）为内置。无此步则 Chain B 在容器处截断。

原生已覆盖、无需建模：`%` 格式化与 f-string（stringManipulation）、`+` 拼接（concatStep）、下标读取（subscriptStep）、字面量容器构造（containerStep）、for 迭代（forReadStep）、`'/'.join` 的**接收者**→结果（stringManipulation join；`_secure_path` 内 `'/'.join(path_tuple)` 的实参侧不覆盖，但该处位于 A001 barrier 之后，无影响）。

### 6.2 动态调用 / 别名 / CodeQL 局限（可能漏报，非误报）

- `default_locale_negotiator` 经 `registry.queryUtility(ILocaleNegotiator, default=...)` 间接调用（i18n.py:148-151）——不可静态解析；已由 S026（locale_name 属性读为源）从另一侧闭合（§1.4）。若应用注册了自定义 negotiator 且其返回值直接进入路径，则超出本模型。
- `LocalizerRequestMixin.localizer`/`locale_name` 为 `@reify`（pyramid.decorator）属性——属性体无静态调用点，但污点路径在函数体内部即可成立（源在体内、sink 在下游被调用函数体内），不需要入口可达性。
- `request.localizer`/`request.locale_name` 的 webob/属性机制在外部依赖中，无法进一步下钻（同 Phase 1 结论）。
- pkg_resources 的真实文件访问在外部 setuptools 中（DB 外），按调用点形态匹配（含 static.py/path.py 的 from-import 裸别名与 `self.pkg_resources` 形态，与 extraction 同一覆盖面）；其他导入风格的同一 API 会漏。
- `str.split` 接收者→结果未建模（python-all 有意不含 split）：i18n.py:178 `current_locale_name.split('_')[0]` 分支（`xx_YY` 语言的短码回退）不传播；但 `locales_to_try.append(current_locale_name)`（:179）已把完整 locale 名放入列表，链路不依赖 split 分支。诊断建议见 §6.3。
- 装饰器（`@lru_cache` 的 traversal_path_info/split_path_info/_secure_path、`@reify`）：参数→过程间数据流按 AST 函数解析，不受装饰器绑定影响（标准行为；A001/A002 barrier 建模在调用结果节点，与内部解析无关）。
- 形参源按（函数名, 形参名, 位置, 文件, 形参行号）精确匹配；若数据库重建导致行号漂移会静默失配（召回风险，非误报风险）——主链（Chain A/B）不依赖形参源。

### 6.3 诊断路径（不计入正式 Pass 1 告警）

如需内部 wrapper 调试，可另写 diagnostics 查询（本步按指令未生成）：
1. 渲染 A005/A007/S027 的 reify 边（negotiator 返回值 → locale_name 属性读）以观察 S024/S014/S126 参数/cookie 源的端到端连接（当前由 S026 源替代闭合）；
2. `str.split` 接收者→结果步骤（i18n.py:178）以覆盖 `xx_YY` 短码回退分支；
3. A008 的 environ 写→读步骤（request.py:281-283 new_path_info → 包装 WSGI app 的 PATH_INFO）以探索子请求链；
4. `environ` 局部名约定的全库扫描（当前行号限定 6 处）。

### 6.4 预期告警形态（供 Step 5 执行后比对，本步不执行）

- **Chain B（locale，主 TP 候选）**：源 S026（i18n.py:363 `self.locale_name`）→ `current_locale_name` → make_localizer 过程间 → join（步骤 1）→ realpath（步骤 2）→ ldir → isdir K029 → append（步骤 3）→ for 迭代 → join → messages_dir → listdir K034 → join+realpath → mopath → open K022；K030/K040 在同链。S024/S155/S147/S126（`_LOCALE_` param/cookie/getattr 源）在 negotiator 返回处端点止步（§6.2 第 1 条），其告警预期来自 S026 侧。
- **Chain A（静态视图，guarded）**：S037/S045 → split/traversal_path_info（A002）→ `_secure_path` 调用（A001）→ 截断，预期无告警；若出现，说明 barrier 覆盖有缺口，回到本报告 §5 复核。
- **资产/配置侧 sink（K001/K002/K010-K018/K042-K046 等）**：库内无可信源到达（操作员边界），预期无告警。

## 7. 标签完整性检查（是否需要退回第五步复核）

逐项核对 315 条标签与六个产物后**未发现审核遗漏**：
- 153 条 source 全部渲染或按 family 归组（§1.1，六条规则 ID 并集 = 153）；
- 47 条 tp/candidate sink 全部渲染（§1.2，九条规则 ID 并集 = 47）；4 条 fp sink 与 4 条 none sink 有明确排除依据（§0）；
- 2 条 sanitizer、7 条 summary 的处理逐条有据（§1.3/§1.4）；
- 无"为凑路径而提升内部形参/包装器为源或 sink"的情况（S224/S225、config/views.py:508 wrapper、pviews 行等均被位置限定排除）。
结论：**无需退回第五步重新审核，labels.json 保持不变**。

## 8. 与各项目一致的实验独立性原则

未读取 PyVul 真值（PYRAMID-VULNERABILITY-REPORT.md、path_traversal_sinks.csv、漏洞审查报告.md、第一步筛选报告.md 等仓库根目录工件）、已知 CVE 行号或修复补丁；未修改 pyramid 源码、pyramid-db 数据库、augur-0.3.0 目录与 Phase 1 全部产物（labels/、extraction/ 仅读）。所有建模决策可回溯到：labels.json 条目 + 本报告引用的具体源码行。
