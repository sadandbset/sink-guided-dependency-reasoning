# Augur Phase 2 Step 4–5 — pretalx Pass 1 (Path Traversal) 污点模型与路径查询生成说明

- Run ID：`pretalx-pathtraversal-pass1-20261022`（与 Phase 1 标签一致）
- 生成时间：2026-10-23
- 输入：`labels/labels.json`（667 entries，schema 校验通过）、`labels/labels_raw_pass1.json`、`labels/label_stats.md`、`labels/phase1_review.md`、`extraction/{sources,sinks}.csv`、`assets/taint_query.ql.tmpl`、`references/{python.md,patterns.md,django.md}`、`WORKFLOW.md` §5（Phase 2），以及 `pretalx_vuln` 源码树中全部被引用位置（逐行核对）
- 产物：`libraries/MySources.qll`、`libraries/MySinks.qll`、`libraries/MySanitizers.qll`、`libraries/MySummaries.qll`、`queries/Pass1_PathTraversal.ql`（本报告为第六件）
- 工具链事实：CodeQL CLI 2.25.1；本地用户级包缓存含 `codeql/python-all 7.1.1/7.1.2` 与 `codeql/dataflow 2.1.3/2.1.6/2.1.7`；iris 根目录 `qlpack.yml`（`iris/pretalx-cwe22`，依赖 `codeql/python-all: "*"`，Step 0 产物，未修改，解析到 7.1.2）。本步只生成文件，不编译、不执行分析（按指令）。
- 独立性声明：未读取 PyVul 真值、已知 CVE 行号或修复补丁；未修改源码、数据库、Augur 目录与 Phase 1 标签（`labels/` 目录内容保持 2026-10-22 状态）。

## 0. 审核状态说明（review_decision.json）

`labels/review_decision.json` 不存在：Step 3 的 CHECKPOINT 以 advisory 模式执行（WORKFLOW §4.5 允许），`phase1_review.md` 是审核 payload 但未写决策文件。本次用户指令"执行 Phase 2 Step 4–5"即视为进入 Phase 2 的批准。据此采取的渲染策略：

- role=source 且 classification=tp 的 468 条 + candidate 的 7 条 → 全部生成 Source 规则（共 475 条，分 5 条规则）。
- role=source 且 classification=fp 的 87 条（`<int:…>`/`<slug:…>` 转换器路由参数）→ **不**进入 Source 模型：转换器正则不允许分隔符，穿越载荷在路由层即不可能（见 §1.1 与 §3）。
- role=none 的 80 条（env_config 41、resolver_match 8、内部形参/字面量 23、非文件 sink 8）→ 不进入任何模型。
- role=sink 且 classification=candidate 的 10 条 → 全部生成 Sink 规则（pretalx 无 tp sink）。
- role=sink 且 classification=fp 的 15 条 → 不进入 Sink 模型（见 §5 排除策略）。
- role=sanitizer / role=summary 各 0 条 → MySanitizers 返回 `none()`（§3），MySummaries 仅含两条**代码证据驱动**的必要传播边（§4.2，非标签渲染）。

## 1. 标签 → QLL 谓词对应总表

### 1.1 MySources::isSource(n, "path_traversal")（475 条，5 条规则）

| 规则 | 标签（P1-S 编号） | 外部输入边界 | 权限/访问条件 | 源码证据 |
| --- | --- | --- | --- | --- |
| `requestFieldRead` | P1-S-0077..0097, 0100..0269, 0276..0332, 0404..0411, 0472..0480, 0514..0553, 0557..0587（336 条，tp，conf 0.55–0.8） | Django `HttpRequest` 字段：GET(144)/POST(66)/FILES(12)/headers·META·COOKIES(35)/body(3)/path·path_info(29)/session(47)，含属性读、下标读、`.get()/.getlist()` 三种节点形态 | agenda 公开页（widget/schedule/exporter）任何人可达；cfp 提交链任何登录/匿名提交者可达；orga 视图需 orga 权限；session 为二阶（用户输入经服务端会话回读） | 例：cfp/views/user.py:69,78,283,337 与 orga/views/submission.py:368,385 `files=self.request.FILES`；agenda/views/schedule.py:123 headers；common/middleware/domains.py:32,34,37 headers/META |
| `formValueRead` | P1-S-0099, 0335..0381, 0412..0471（108 条，tp，conf 0.6–0.7） | 二阶再入：POST/FILES 经 Django 表单校验后的 `cleaned_data`/`files` 值（类型/长度受限，路径语义不受限） | cfp 向导（InfoForm/QuestionsForm 文件题）任何提交者；orga 评审导入（review.py import_file）与 Hierarkey 设置表单（custom_css 等）需 orga 权限（custom_css 非管理员需过 `validate_css`，orga/forms/event.py:191-198） | common/mixins/forms.py:439 `value = self.cleaned_data[name]`（→ K0030 链）；orga/forms/review.py:370 `uploaded_file = self.cleaned_data["import_file"]`；orga/forms/event.py:193-195 |
| `cfpSessionGetRead` | P1-S-0629..0634（6 条，candidate，conf 0.5） | `cfp_session.get(...)`（cfp 向导已存数据，含 initial/data/user 字段） | 提交向导用户；会话由 Django 会话后端完整性保护，值源自用户此前提交 → 人工复核项 | cfp/flow.py:191,192,411,436,519,534 |
| `routedHandlerParam` | P1-S-0056（candidate，conf 0.6）；P1-S-0064/0066/0068/0070（tp，conf 0.65） | S0056：get_static 的 `path` 形参（urlconfig 注入）；S0064 等：`schedule/v/<version>` str 转换器变量的 `version` 形参（widget.py 4 个处理函数 arg 2） | S0056：当前路由仅绑定字面量 `agenda/js/serviceworker.js`（agenda/urls.py:124-131），攻击者可控需恶意/插件 urlconfig —— 标签 candidate 的人工复核点；version：agenda 公开 URL | common/views.py:48-52（docstring 自认 traversal 潜在）；agenda/urls.py:65 get_schedule_urls("schedule/v/<version>")；agenda/views/widget.py:126,140,152,162 |
| `routeKwargRead` | P1-S-0098, 0382..0383, 0397..0401, 0488..0490, 0494..0496, 0500, 0502, 0511..0513, 0554（20 条，tp，conf 0.6–0.75） | URL 路由变量经 kwargs 映射读取，键限定 `version/tmpid/code/invitation/name` + DRF 动态 `lookup_field`（api/views/submission.py:93） | code/invitation/name/version 为公开或 cfp/orga 路由段；version 在 schedule.py:34 经 `unquote()` 二次解码（仅流向 DB 查询，无文件 API） | agenda/views/schedule.py:34,85；cfp/flow.py:64；orga/views/review.py:372；cfp/views/user.py:459-460；agenda/views/speaker.py:66,78,111 等 |

未成为 Source 的角色（符合"内部形参不自动是 Source"）：87 条 fp 路由参数（int/slug 转换器）、41 条 env_config（运维边界）、8 条 resolver_match（框架路由元数据）、23 条内部形参/字面量（`up`/`draft`/`response`/`view`/`obj` 等，调用方传常量或框架对象）。

### 1.2 MySinks::isSink(n, "path_traversal")（10 条 candidate，4 条规则）

| 标签 | 谓词规则 | 危险路径位置 | 真实文件操作 / 访问类型 | 调用关系（谁到达此处） |
| --- | --- | --- | --- | --- |
| K0010 | `openPathArg`（限 common/views.py:56） | arg 0（路径文本） | 文件读：`open(path,'rb')`，`path = settings.BASE_DIR / "pretalx/static" / <urlconfig path>`，无规范化、无包含检查、`..` 不拒；:53 `exists()` 为 check-then-use | get_static ← `sw.js` 路由（当前字面量绑定）；唯一完整 source→sink 链的落点 |
| K0012 | `openPathArg`（限 export…py:121） | arg 0 | 文件写：`dump_content` 将抓取内容写入 `Path(destination) / path.lstrip('/')`，仅去前导斜杠，`..` 存活 | export_event ← operator CLI/celery（ScheduleExportTriggerView）；URL 由应用生成（reverse()/storage URL） |
| K0013 | `openPathArg`（限 export…py:134） | arg 0 | 文件读：`get_mediastatic_content` 读 `STATIC_ROOT/MEDIA_ROOT / url[len(STATIC_URL):]`，原始拼接无包含检查 | 同上；URL 须以 STATIC_URL/MEDIA_URL 前缀开头 |
| K0008 | `mkdirReceiver`（限 export…py:119） | **receiver**（`path.parent`，路径文本） | 目录创建：`path.parent.mkdir(parents=True, exist_ok=True)`，URL 派生目录分量可越出导出临时目录 | `dump_content`（同 K0012 链） |
| K0020 | `fileResponseFileArg`（限 common/views.py:55） | arg 0（此处是被 `open()` 打开的**文件对象**，非路径文本） | 文件响应：FileResponse 把已打开文件流式回传，完成 get_static 读回链 | get_static；实际文件访问在 :56 的 open（K0010） |
| K0031 | `storageNameArg`(save)（cfp/flow.py:266） | arg 0（storage 相对名 = 客户端 multipart 文件名） | 文件写：`FileSystemStorage.save(field_file.name, field_file)`，根为 MEDIA_ROOT/cfp_uploads（flow.py:188） | `set_files(form.files)` ← FormFlowStep.post（cfp 向导）；**source 可达性受 §4.3-3 缺口限制** |
| K0030 | `storageNameArg`(save)（common/mixins/forms.py:450） | arg 0（`get_new_filename(value.name)`，原始文件名嵌为路径分量，forms.py:470-479） | 文件写：`default_storage.save(..., value)`（MEDIA_ROOT） | HierarkeyMixin.save ← orga 设置表单（custom_css 等）；source = forms.py:439 `self.cleaned_data[name]` |
| K0016 | `storageNameArg`(open)（cfp/flow.py:260） | arg 0（storage 相对名 = 会话 files 字典的 tmp_name） | 文件读：`FileSystemStorage.open(tmp_name)` | `get_files()` ← 向导回显（会话二阶；tmp_name 为 storage 生成） |
| K0032/K0033 | `storageNameArg`(delete)（forms.py:445/461） | arg 0（DB 存储的 storage 名） | 文件删除：`default_storage.delete(fname.name)`（旧设置文件） | HierarkeyMixin.save 换文件/删文件分支 |

谓词匹配的是**路径文本参数/接收者表达式**；被 `open()` 返回的文件对象不在匹配范围（K0020 例外保留，理由见 qll 头注——路径文本污点不会流到文件对象上，该 sink 只与路径文本实参同时告警）。

### 1.3 MySanitizers::isBarrier(n, "path_traversal")

无对应标签（role=sanitizer = 0），返回 `none()`。有效性与不可建模项论证见 §3。

### 1.4 MySummaries::isAdditionalTaintStep(from, to, "path_traversal")

无对应标签（role=summary = 0）；两条边为代码证据驱动的必要传播（指令允许的 Path()/join 包装器建模），见 §4.2。

## 2. 路径连接 / 解码 / 规范化与允许根目录、符号链接证据

- **URL 解码**：WSGI 服务器在路由前对 URL path 解码一次。pretalx 内 7 处 `urllib.parse.unquote()`（agenda/views/schedule.py:34 kwargs version、:85 GET exporter、agenda/views/widget.py:167 GET v、common/views.py:83 GET next、common/mixins/views.py:155 GET q、cfp/views/user.py:430 GET email、orga/views/person.py:69 GET next）构成**二次解码**放大点，但逐一核对：全部只流向 DB 查询或重定向目标，无一到达文件 API。get_static 链无解码环节（urlconfig 注入值已是解码后文本）。
- **路径连接**：全库路径拼接均为 pathlib `/`（无 `+` 拼接、除 path_with_hash 外无 os.path.join，grep 核对）。连接点清单：common/views.py:52、export_schedule_html.py:118/128/130/172/216、cfp/flow.py:188、common/tasks.py:91、settings.py:36/45/53/166/189。根均为 `Path(...)` 构造或 settings 路径常量（settings.py:31-53 全部为 `Path(...)`）。`url[len(STATIC_URL):]` 切片与 `path.lstrip("/")` 均保留 `..` 分量。
- **规范化顺序**：sink 路径上**不存在任何** normpath/abspath/resolve/basename（grep 核对；唯一 `.resolve()` 在 settings.py:348 静态 locale 路径）。因此无"规范化先后于包含检查"的问题——因为两者都不存在。get_static 的 `path.exists()`（:53）→ `open()`（:56）为 check-then-use；event/services.py:79 `zip_path.exists()` 先于导出重建再读（orga/schedule.py:124）。
- **允许根目录检查**：pretalx 自有代码零包含性检查（无 startswith/relative_to/白名单/固定文件名映射）。唯一根限制是 Django storage 内部的 safe_join（K0016/K0030-K0033 所依赖，库外不可验证）与 Django URL 转换器（在 source 层建模，见 §3）。HTML 导出链的"声明根目录"（HTMLEXPORT_ROOT/STATIC_ROOT/MEDIA_ROOT）仅靠前缀约定，`..` 可越出。
- **绝对路径/分隔符变体**：`lstrip("/")` 去前导 `/` 但不去 `..`；`Path(root) / "../../x"` 语义上等价逃逸；Windows 盘符形式在本代码库未见处理（跨平台部署下 normpath 语义差异不适用——无 normpath）。
- **符号链接**：全库无 `os.path.islink/realpath/lexists`（grep 核对）；pathlib `/` 与 `open` 对链接透明。与 Phase 1 判定一致：未发现链接相关利用路径，记录"不适用"，模型对链接透明（与真实行为一致）。
- **文件访问时机**：Django storage 的名称校验（若存在）发生在实际访问之前（save→_save→path(name)），时序上构成守卫，但位于库外无法验证——因此 K0016/K0030-K0033 保持 candidate 而非被 barrier 压制。

## 3. Barrier 有效性论证（MySanitizers = none()）

**不设任何 barrier 的三重理由**：

1. **自有代码零守卫**（grep 证据，detection.json `toctou_and_containment_evidence`）：无 safe_join/get_valid_filename/basename/abspath/normpath/realpath/relative_to。不存在可插入 barrier 节点的守卫。
2. **真实守卫均在库外**：Django URL 转换器（`<int:pk>` = `[0-9]+`、`<slug:event>` = `[-a-zA-Z0-9_]+`）确实阻断对应路由参数的穿越载荷——已按标签在 **source 层**实现（这些参数不成为 source，87 条 fp），而非 barrier（转换发生在路由层，DB 内无对应节点）。Django storage 校验（multipart 文件名 basename、`validate_file_name`、`safe_join`；Django `~=3.2.0`，src/setup.py:101）确实预期阻断 storage sink 越界——但库源码不在 DB、无法证明，故 K0016/K0030-K0033 保持 candidate 由人工复核，不冒充 barrier。
3. **按函数名不可机械认定**：`common/utils.py:132 safe_filename()`（NFD ASCII 折叠）与 `Storage().get_valid_name()`（speaker.py:129）仅用于 Content-Disposition 头，从不在文件访问之前；`url.lstrip("/")` 只去前导斜杠，已证明不阻 `..`。

## 4. 额外传播边、动态调用/别名遗漏、CodeQL 局限

### 4.1 依赖的库内建模型（本地 python-all 7.1.2 源码核实）

- **pathlib `/` 连接**：`Stdlib.qll:2795` `PathlibPathTaintStep`——`/`（Div）任一操作数污点 → 结果，**前提**是另一操作数被类型追踪为 pathlib Path（追踪起点是 DB 内 `Path(...)` 构造调用，Stdlib.qll:2668-2692）；`parent` 属性保持（Stdlib.qll:2616, 2647-2656）；joinpath/with_name/with_suffix 注入（:2628）。注意 Stdlib.qll:1254 的 TODO 注释"Handle pathlib (like we do for os.path.join)"——库自身确认 pathlib 覆盖不完整。
- **os.path.join**：`Stdlib.qll:1246` `OsPathJoinCallAdditionalTaintStep`（path_with_hash 链可用，本 pass 无依赖）。
- **字符串方法/格式化**：`TaintTrackingPrivate.qll:97-163` `stringManipulation`——`str.format` 的**任意实参** → 结果（:111-133）、`lstrip/replace/split/strip` 等方法对象污点 → 结果、`%`、f-string、`str()`；`concatStep`（:77-81）仅 `+`。
- **下标读**：`TaintTrackingPrivate.qll:86-89` `subscriptStep`——污点对象 → 其下标读结果（覆盖 `url[len(STATIC_URL):]` 切片）。
- **函数间流**：`TaintTracking::Global`（codeql/dataflow 2.1.7 TaintTracking.qll:313）默认含 DB 内函数的 call→形参 与 return→调用点 传播（覆盖 `get_new_filename` 的函数体流）。

### 4.2 已建模的必要传播边（MySummaries，均见 qll 注释，证据行号齐全）

1. `pathlibJoinStep`：`/` 操作数 → 结果，当连接链根为 `Path(...)` 构造或 `settings.{BASE_DIR,DATA_DIR,LOG_DIR,MEDIA_ROOT,STATIC_ROOT,HTMLEXPORT_ROOT}` 属性链（递归处理链式 `/`）。
   **必要性**：settings 常量经 `from django.conf import settings` 读取，django.conf 在 DB 外，类型追踪无法到达 settings.py:31-53 的 `Path(...)` 定义，故 python-all 的 Div 规则对 get_static 连接（common/views.py:52，唯一完整已审链）不生效。本步镜像该 Div 规则并放宽 settings 根，限定 pretalx 包内。
2. `uploadFileNameStep`：污点上传对象 → 其 `.name` 属性读，限 common/mixins/forms.py 与 cfp/flow.py。
   **必要性**：Python 污点模型只把整对象污点传给**下标**读（subscriptStep），无属性读等价物（TaintTrackingPrivate.qll 全文核对），`value.name`/`field_file.name` 会截断 cleaned_data → storage.save 链。Django `UploadedFile.name` 即客户端文件名（K0030/K0031 标签证据）。

### 4.3 已知局限 / 未建模（影响召回或精度，不影响标签正确性）

1. **settings.* 类型追踪缺口**（已由 4.2-1 补齐，记录为库局限根因）。
2. **整对象→属性读污点缺口**（已由 4.2-2 针对性补齐两文件；其余 `.name` 读不在上传链，未建模以免过近似）。
3. **Django 表单机制边界 —— 标签缺口（退回第五步项）**：`request.FILES` 传入表单构造器后经库外机制变成 `form.files`/`form.cleaned_data`；Phase 1 抽取族 `form_files/form_cleaned_data` 只提取了**下标/.get() 形态**，cfp/flow.py:227-228 的整对象读 `self.set_data(form.cleaned_data)` / `self.set_files(form.files)` 未被提取、因而无标签 → **K0031（flow.py:266 save）从已审 source 不可达**。这是抽取形态缺口而非标注错误；按指令记录原因并退回第五步复核（不改 labels.json，见 §7）。
4. **@cached_property getter**：`self.cfp_session`（django.utils.functional 装饰器，库外）——flow.py:62-66 的 request.session source 到 property 体内的流可能中断；会话 files 字典链（`self.cfp_session["files"]`，flow.py:254）同样未被抽取/标注 → **K0016 从已审 source 不可达**（同为 §7 复核项；其标签本就 candidate 0.45）。
5. **storage 动态分发按接收者点号名匹配**（`%file_storage`/`%default_storage`）：别名 storage（如 `storage = default_storage` 再转发）会漏；与 detection.json 已记录的接收者命名约束一致。
6. **FileField 保存链未入 sink**：`common/mixins/forms.py:370` `answer.answer_file.save(value.name, value)`（问答文件上传）——Django FileField.save 未被抽取为 sink 候选（detection.json coverage_gaps 已记录）；属抽取覆盖缺口，非标签遗漏。
7. **`urllib.parse.unquote` 不建模**：所有 unquote 链只到 DB 查询（§2），无 sink 依赖；外部 stdlib 亦无 DB 内实现。
8. **make_archive 关键字路径**（fp 标签，无 source 可达）：不建模。
9. **`Parameter.getPosition()`** 依赖函数签名与路由实参一致（get_static(request, path, content_type) 三参形态已核对 common/views.py:48；widget 四函数 (request, event, version[, locale]) 已核对）。

### 4.4 诊断路径（不计入正式 Pass 1 告警）

按指令未生成诊断文件（diagnostics/ 目录留空），建议 Step 5 调试时临时使用（用后删除或不作为正式产物）：

- **source/sink 自检**：`select n` where `MySources::isSource(n, "path_traversal")`（预期 ≈475 节点：336 request 字段 + 108 form 值 + 6 cfp 会话 + 5 形参 + 20 kwargs）/ `MySinks::isSink(n, "path_traversal")`（预期 10 节点：3 open + 1 mkdir receiver + 1 FileResponse + 5 storage arg0）。
- **summary 边自检**：select `MySummaries::isAdditionalTaintStep(f, t, "path_traversal")`——join 边预期覆盖 common/views.py:52、export_schedule_html.py:118/128/130/172、cfp/flow.py:188、common/tasks.py:91 及 settings.py 的链式 `/`；`.name` 边预期 forms.py:450/478、flow.py:266/269 及两文件内其余 `.name` 读。
- **主链可达性**：临时去掉 openPathArg 的行限制对比告警差异，验证 settings 根放宽是否生效。
- **barrier 自检**：select isBarrier（预期 0 节点）。

## 5. Sink 排除策略（fp/none 标签的实现决定）

- **15 条 fp sink 不进模型**（标签判定无不可信流可达，加入只稀释谓词、不增召回；与 mlflow 项目策略一致）：
  - common/tasks.py:37/64/108 save：字面量/校验和/event.slug（RegexValidator `^[a-zA-Z0-9.-]+$` 无分隔符）文件名；
  - common/tasks.py:54 open：finders.find(字面量 widget 文件)；
  - orga/views/schedule.py:124 open+FileResponse：HTMLEXPORT_ROOT/event.slug+'.zip'，orga 权限门；
  - common/forms/fields.py:135 open：Django 分配的上传临时路径（客户端控内容不控路径）；
  - common/settings/config.py:155 open：运维环境变量 PRETALX_CONFIG_FILE；
  - export_schedule_html.py:168/201/206/213 rmtree/mkdir/rename/make_archive：HTMLEXPORT_ROOT + event.slug 派生（残余"`..` 整体 slug"边缘已记入标签证据，运维权限）；
  - common/mixins/views.py:290/294/296 FileResponse(FieldFile)：storage 已验证名 + 权限门。
- **8 条 role=none 不进模型**：BytesIO FileResponse（speaker.py:168）、BytesIO Image.open（fields.py:146）、字面量后缀 NamedTemporaryFile（cards.py:122）、test_settings.py:23、makemessages.py:25/26/62 —— 调用点无文件路径实参或为测试/开发工具。
- **无 mlflow 式"fp sink 例外保留以激活 barrier"**：本 pass 无任何 barrier（§3），无需例外。

## 6. 预期告警面（预测，Step 5 验证，本轮不执行）

- **预期命中**：
  1. **S0056（get_static `path` 形参）→ [pathlibJoinStep, settings 根] → views.py:52 连接 → K0010（:56 open）**：唯一代码级完整的 source→sink 链；告警本身即标签 candidate 的人工复核项（可达性取决于 urlconfig/插件路由）。
  2. **forms.py:439 `self.cleaned_data[name]`（S 标签）→ [uploadFileNameStep] value.name → get_new_filename（内部 format 模型）→ K0030（:450 default_storage.save）**：HierarkeyMixin 设置表单上传链（orga 权限；custom_css 非管理员另有 validate_css 分支，不影响污点路径）。
- **预期无告警**（可达性缺口，非标签错误）：K0012/K0013/K0008（导出命令：URL 由应用生成，无已审 source 到达）；K0016/K0031（§4.3-3/4 的 form.files/cached_property 缺口）；K0032/K0033（fname 来自设置存储，无 source）；K0020（实参为文件对象，路径文本污点不流入）。
- **预期无噪声**：fp source（int/slug 参数）与 fp sink 均被排除，orga CRUD 视图的大量 GET/POST 读不会产生告警（无匹配 sink 路径）。

## 7. 标签遗漏检查（是否退回第五步）

逐链核对后结论：**发现 2 处抽取/标签形态缺口，均已记录、不修改 labels.json**：

1. `form.cleaned_data`/`form.files` **整对象读**（cfp/flow.py:227-228）未进入 `form_cleaned_data/form_files` 抽取族（该族只取下标/.get 形态）→ K0031 不可达。退回第五步的复核建议：把整对象读作为二阶 source 候选补充抽取并重新标注（预计 +2 条 candidate）。
2. `self.cfp_session` cached_property 及其 `["files"]` 下标链（flow.py:254）未被抽取 → K0016 不可达。复核建议：把该链作为 session_data 族的补充候选（预计 +1~2 条 candidate）。

两处缺口只影响 **candidate 级** sink 的召回（本 pass 无 tp sink），不改变已有任何标签的判定，故本轮按指令记录并继续；是否补抽取由第五步人工复核决定。另 `labels/review_decision.json` 缺失（§0）一并提请补记。若 Step 5 执行后发现某链不可达的根因在标签而非模型，再按指令退回第五步。

## 8. API 使用核对（防"调用不存在的 AST API"）

所有谓词/类均在本地包缓存核实（python-all 7.1.2 / codeql-dataflow 2.1.7）：`DataFlow::Node.asExpr`（DataFlowPublic.qll）、`DataFlow::parameterNode`（DataFlowPublic.qll:350）、AST `Attribute.getName/getObject`（Exprs.qll:74/77）、`Subscript.getObject`（Exprs.qll:98，getIndex 经 :93 用法核实）、`Call.getArg(int)`（Exprs.qll:156）、`Call.getAnArg`（Exprs.qll:167）、`BinaryExpr.getLeft/getOp/getRight`（AstGenerated.qll:117-123）、`Div`（Operations.qll:86-93）、`Name.getId`、`StringLiteral.getS`（AstGenerated.qll）、`Function.getName/getArg/isMethod`、`Parameter.getName/getPosition`（Function.qll）、`AstNode.getLocation`、`File.getRelativePath/getAbsolutePath`（Files.qll）——后三者已被本库 Phase 1 的 extraction 查询在本数据库上实际运行验证（sources.bqrs/sinks.bqrs 存在且成功解码）。核心机制：`DataFlow::ConfigSig`（DataFlow.qll:401-427，isBarrier/isAdditionalFlowStep 有默认实现）、`TaintTracking::Global<Config>`（TaintTracking.qll:313）、`import <FlowModule>::PathGraph` + `flowPath`（与 mlflow 项目 Pass1 查询同款模板渲染）。未使用 `module` 作为变量名；未使用 API::Node（无 API 图混用，MySummaries 仅以 AST 形态匹配）；`import libraries.MySources` 点号语法与 iris 根 qlpack.yml（`iris/pretalx-cwe22`）的包结构一致。
