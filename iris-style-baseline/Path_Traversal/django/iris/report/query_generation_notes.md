# Augur Phase 2 Step 4–5 建模报告 — Pass 1 Path Traversal (Django 2.2.26 alpha, django_vuln)

- 运行：`django-pathtraversal-pass1-step3-20261022`（沿用 Phase 1 run_id）；生成阶段为只生成、不执行。生成后用户以 `codeql query compile --check-only`（CLI 2.25.1，--additional-packs 指向本地 python ql/lib）做了编译校验，暴露两类解析错误并已修复（见 §8）；修复后**编译通过**（`Done [1/1]`，0 错误），未执行正式分析（`codeql database analyze` 仍未运行，属 Step 5 之后）。
- 输入：labels/labels.json（738 条 Pass 1 标签）、labels/phase1_review.md、iris/qlpack.yml（`iris/django-cwe22`，依赖 `codeql/python-all: "*"`，本地解析为 7.1.2，未修改）、Augur WORKFLOW.md §5.1/§5.2.1a、references/python.md、references/django.md、references/patterns.md、assets/taint_query.ql.tmpl，以及 django_vuln 真实源码。
- 生成文件：`libraries/MySources.qll`、`libraries/MySinks.qll`、`libraries/MySanitizers.qll`、`libraries/MySummaries.qll`、`queries/Pass1_PathTraversal.ql`（本报告为第六件）。
- API 事实核验（均来自本地安装包 codeql/python-all 7.1.2 与已成功编译运行的 Step 2 抽取查询）：`DataFlow::ConfigSig`（isSource/isSink/isBarrier/isAdditionalFlowStep，默认 none()）、`TaintTracking::Global<Config>` + `PathGraph` + `flowPath`（codeql/dataflow 2.1.7 共享库，经 `semmle.python.dataflow.new.TaintTracking` 导出）、`DataFlow::parameterNode`、`DataFlow::Node.asExpr()`、`AstNode.getLocation().getFile().getAbsolutePath()`（注意 `AstNode.getFile()` 不存在）、`Attribute.getName()/getObject()`、`Subscript.getObject()`、`Call.getFunc()/getArg()`、`Function.getAnArg()`、`Parameter.getName()/getPosition()`、`StringLiteral.getS()`、`AstNode.getScope().(Function).getName()`。未使用 `module` 作为变量名；未混用 API::Node 与 DataFlow::Node；未调用不存在的 AST API。

## 0. 审核状态说明（review_decision.json）

`labels/review_decision.json` 在本工作区不存在：Phase 1 的人审门以 WORKFLOW §4.5 的 advisory/automated 模式记录在 `labels/phase1_review.md`（38 条 candidate 复核点见其 §4）。本次 Step 4–5 以 phase1_review.md 为“已审核”状态：**只建模 classification=tp 的标签**；所有 candidate 级标签一律不进正式 Source/Sink/Barrier（除 §3.2 说明的一条“必要传播边”按标签 rationale 实现），并保留原样待第五步人工复核，未修改 labels.json。

## 1. Source 模型（MySources.qll）——标签 ID ↔ 谓词 ↔ 证据

统一 pass key `"path_traversal"`；只含 role=source 且 classification=tp 的 194 条标签。

| QL 谓词 | 标签 ID（数量） | 外部输入边界与权限/访问条件 | 源码证据 |
| --- | --- | --- | --- |
| `isStaticServePathParameter` | src-0180, src-0206 | URL resolver 经 `(?P<path>.*)$` 路由把完整请求路径注入 `serve(request, path)` 形参；任何 HTTP 客户端可达（DEBUG 静态服务/静态文件服务，无认证；staticfiles 变体受 DEBUG/insecure 门控但不影响内容可信度） | views/static.py:19（docstring 路由示例）、:35-:36 normpath→safe_join；contrib/staticfiles/views.py:15、:32-:39 |
| `isAdmindocsKwargsSubscript` | src-0197–src-0200 | resolver 注入的 URL kwargs（view/model_name/app_label/template），admin-docs 页面（staff 权限，但输入仍为远程 URL 内容） | contrib/admindocs/views.py:157/187/190/322；:332-:334 template→safe_join→open |
| `isRequestAttribute` | 140 条（http_path 35、http_meta 32、http_form 45、http_query 20、http_files 3、http_cookie 5；属性读） | `request.<attr>`：URL 路径/PATH_INFO、请求头、表单、查询串、multipart、Cookie —— 全客户端可控；admin 视图有认证门、CSRF 中间件不清洗内容 | http/request.py:52-:59 初始化；core/handlers/wsgi.py:69-:80 PATH_INFO→path |
| `isRequestDictGetCall` | 39 条（http_meta 19、http_form 9、http_query 9、http_cookie 2；`.get()` 结果节点） | 同上（取键值）；源节点取调用结果，避免依赖 MultiValueDict.get 的 receiver→result 建模 | sessions/middleware.py:19 `request.COOKIES.get(SESSION_COOKIE_NAME)`（session 键来源）；views/static.py:45 |
| `isWsgiEnvironExtraction` | src-0207–src-0211 | WSGI environ 最低层提取（PATH_INFO/SCRIPT_NAME/SCRIPT_URL/REDIRECT_URL/QUERY_STRING），原始远程输入 | core/handlers/wsgi.py:105/158/179/186/189（key 字面量约束与抽取查询一致） |
| `isMultipartFilename` | src-0116 | multipart Content-Disposition 的 `filename` 参数，完全客户端可控（RFC2231 filename* 经 :687 unquote 百分号解码，仅一次） | http/multipartparser.py:205；:207 force_text、:208 sanitize_file_name |
| `isSessionKeyParameter` | src-0077 | 不是普通内部形参：SessionMiddleware 用 cookie 值自动注入 `SessionStore(session_key)`；cookie 完全客户端可控 | sessions/middleware.py:19-:20；sessions/backends/file.py:20、:41-:55 _key_to_file |

**未建模的 source 标签**：src-0092/src-0093（views/i18n.py kwargs.get('domain'/'packages')，classification=candidate——domain 未验证流入 stdlib gettext .mo 文件名构造；按 phase1_review.md §4-2 待人工复核，未获批准故不进 MySources）。另 14 条 none/fp（9 env + 5 CLI）按标签不建模。

## 2. Sink 模型（MySinks.qll）——真实文件操作、危险参数索引、访问类型、调用关系

统一 pass key；只含 role=sink 且 classification=tp 的 26 个调用点（27 行标签；snk-0417/0418、snk-0342/0343、snk-0160/0161 为 ast/api 或双 flowKind 重复行，同一调用点）。**路径文本与文件对象区分**：receiver 型 sink（`fullpath.open('rb')`、`template_file.open()`）匹配的是承载路径的 receiver 表达式；参数型 sink 匹配危险参数表达式；FileResponse 的参数 0 是“被打开的文件对象”（见 §5 局限）。

| QL 谓词 | 标签 ID | 文件操作 / 危险参数 / 访问类型 | 调用关系（真实代码） |
| --- | --- | --- | --- |
| `isStaticServeFileSink` | snk-0381 | `fullpath.open('rb')`：receiver=路径对象；**读** | serve()：URL path→normpath→safe_join→Path→open；snk-0380 `FileResponse(...)` 参数 0=文件对象（文件响应，按标签保留） |
| | snk-0380 | FileResponse 文件响应（流式读文件内容） | 同上 ：50 |
| `isAdmindocsTemplateSink` | snk-0513 | `template_file.open()`：receiver；**读** | TemplateDetailView.get_context_data：kwargs['template']→safe_join→Path→exists→open |
| `isStorageFileSink` | snk-0409 | builtin `open(self.path(name), mode)`：参数 0=路径文本；**读** | FileSystemStorage._open（name 为外部存储名，经 path()=safe_join(location,name)） |
| | snk-0417/0418 | `os.open(full_path, O_CREAT\|O_EXCL)`：参数 0；**创建+写** | _save：get_available_name/generate_filename 校验链之后 |
| | snk-0413/0414 | `os.makedirs(directory)`：参数 0；**目录创建** | _save：dirname(full_path) |
| | snk-0416 | `file_move_safe(temp, full_path)`：参数 1=目标；**搬移** | _save：上传临时文件落位 |
| | snk-0423/0424 | `os.rmdir/os.remove(name)`：参数 0；**删除** | delete()：self.path(name) |
| `isFileMoveSink` | snk-0340 | `os.rename(old, new)`：参数 1=目标；**搬移** | file_move_safe：被 storage.py:268 与 cache filebased.py:55 调用 |
| | snk-0341 | builtin `open(old_file_name,'rb')`：参数 0；**读** | file_move_safe 跨文件系统回退 |
| | snk-0342/0343 | `os.open(new_file_name, O_WRONLY\|O_CREAT\|O_EXCL)`：参数 1；**创建+写** | 同上（allow_overwrite 时无 O_EXCL） |
| | snk-0345 | `os.remove(old_file_name)`：参数 0；**删除** | 搬移后清理源 |
| `isSessionFileSink` | snk-0158 | `open(self._key_to_file(), 'r')`：参数 0；**读**（函数域=load，避开其他 open） | load()：cookie 键→_key_to_file |
| | snk-0160/0161 | `os.open(session_file_name, O_WRONLY…)`：参数 0；**创建+写**（函数域=save） | save() |
| | snk-0163 | `shutil.move(tmp, session_file_name)`：参数 1；**搬移**（函数域=save） | save() 的原子改名 |
| | snk-0168 | `os.unlink(self._key_to_file(session_key))`：参数 0；**删除**（函数域=delete，与 save 内 :168 的 fp 级内部临时文件 unlink 区分） | delete() |
| `isFileCacheSink` | snk-0183/0189/0195 | `open(fname, 'rb'/'r+b')`：参数 0；**读 / 读+写**（函数域=get/touch/has_key，避开 set() 内 open(fd) :53） | 键经 _key_to_file 的 md5 |
| | snk-0186 | `file_move_safe(tmp_path, fname, allow_overwrite=True)`：参数 1；**搬移**（函数域=set） | set() |
| | snk-0192 | `os.remove(fname)`：参数 0；**删除**（函数域=_delete，避开 set() 内 :59 的 fp 级 tmp 清理） | _delete()（startswith(self._dir) 前缀检查为控制流） |

**未建模的 sink 标签（17 个 candidate 调用点）**：archive 解压写（snk-0042/0052 等，utils/archive.py）、CLI --template 解压（snk-0475）、模板 loader/dummy 读取（snk-0219/0140）、mail attach_file（snk-0331）、gis fromfile（snk-0144）、File/Image 重开（snk-0064/0237）、ManifestStaticFilesStorage open（snk-0386）等——均为 classification=candidate（应用误用形态或 CLI-only），按 §0 原则不进正式 Sink，**退回第五步人工复核**（若批准可再加入 MySinks，无需改动本查询骨架）。

## 3. 传播边（MySummaries.qll）与路径连接/解码/规范化证据

### 3.1 依赖标准库建模（已核验本地 7.1.2 包，不重复建边）

- `os.path.join`/`posixpath.join`：参数→结果（Stdlib.qll `OsPathJoinCallAdditionalTaintStep`，含 posixpath/ntpath 导入形式）。证据：static serve safe_join 内 join、sessions _key_to_file:55 join、storage path():330 join。
- `urllib.parse.unquote`：参数→结果（Stdlib.model.yml :156）。证据：multipartparser.py:687（src-0117 summary 标签）、staticfiles handlers 的 url2pathname（nturl2path 亦在 model.yml :92-:94）。URL 路径在 WSGI 层一次解码；multipart filename* 在 parse_header 一次解码——无二次解码叠加点（staticfiles handlers 的 url2pathname 是对已解码 path 的规范化，结果仍进 safe_join）。
- `str + str`、普通函数参数/返回：TaintTracking::Global 原生跨函数流（finders.find/find_location/storage.path/serve 委托等 5 条 summary 标签 snk-0222/0230/0373/0516 + src-0117 属此类，不需显式边）。

### 3.2 显式额外边（仅 3 条，全部窄域）

1. **`pathlibConstructorStep`**（views/static.py、contrib/admindocs/views.py 内 `Path(x)` 参数 0→构造结果）：安装包 Stdlib.qll:1246 对 pathlib 构造器留有显式 "TODO: Handle pathlib"；而两个 tp 级 receiver sink（snk-0381/0513）的危险操作数是 Path 对象，无此边则标签 sink 不可达。属“必要的路径包装器传播”，范围限于这两个文件。
2. **`sessionKeyFieldStep`**（sessions backends 包内 `__init__` 的 session_key 形参 → `self._session_key`/`self.session_key` 读取）：跨方法属性流不被自动追踪；该边把已批准的 source（src-0077 及 COOKIES.get 行）连到已批准的 session sinks（snk-0158/0160/0161/0163/0168）。依据为标签 snk-0154（summary/tp：“cookie 派生键→文件路径”的 arg→return 描述）及 snk-0157/0159/0167（candidate，rationale 明言"needs field-flow summary edge"——本边即其实现，连通关系而非新增角色）。证据：base.py:44-:45 存储、file.py:55/:180 读取。
3. **`uploadFileNameFieldStep`**（core/files/uploadhandler.py 内 `new_file` 的 file_name 形参 → `self.file_name` 读取）：直接对应已批准 summary 标签 src-0193（summary/tp）。证据：uploadhandler.py:101 存储、:140 读取进 `TemporaryUploadedFile(self.file_name, ...)`。

### 3.3 允许根目录、绝对路径、`..`、分隔符与符号链接检查的证据

- 根目录检查唯一实现为 `safe_join`（utils/_os.py:24-:47）：`abspath(join(base,*paths))` 与 `abspath(base)` 的 normcase 前缀（含 `base + sep`）、相等、最根路径三例外，越界即抛 SuspiciousFileOperation——先于任何文件访问（static.py:36→:41/:44→:50 的顺序、storage.path():330→:231、finders.py:121→:122、loaders/filesystem.py:36→:23、backends/base.py:77、admindocs:332→:334）。
- 绝对路径：join 遇绝对第二参即丢弃 base，随后前缀检查失败 → 拒绝（safe_join 文档注释 "/dir"、"/../d" 之例）。
- `..`：前缀检查在规范化后执行；上传名另有显式 '..' 部件拒绝（storage.py:71/:106 的 PurePath parts 检查、files/utils.py:17-:20）。
- 分隔符变体：normcase 处理 Windows 大小写；multipart `sanitize_file_name` 对 `/` 与 `\` 双 basename；`get_valid_filename` 字符白名单同时去除两种分隔符。
- 符号链接：**未发现**会抵消根目录限制的规范/校验时序问题可被远程利用——safe_join 是前缀式（不 resolve 链接），需先在 document_root 内植入链接（需另行入侵）；static.py:41/:44 exists/stat 先于 :50 open 为 TOCTOU 形态，已记录于标签 rationale，不构成 Barrier 缺陷。collectstatic 的 symlink/unlink 为 CLI 工具路径（fp）。

## 4. Barrier 模型（MySanitizers.qll）——能否真正阻断特定机制

Barrier 节点 = 被守卫调用的调用表达式节点（isBarrier 将该节点从流图中移除，使参数污点无法再经其结果继续传播）。

| Barrier | 标签 ID | 阻断机制（真实源码证明） | 有效性结论 |
| --- | --- | --- | --- |
| `isSafeJoinBarrier`（6 处 Name 调用，grep 验证全树仅此 6 处） | snk-0376/0223/0429/0220/0059/0511 | utils/_os.py:32-:47：规范化后前缀包含 + 抛异常，先于文件访问 | 对直连 `../`、绝对路径、大小写变体**有效**；对 base 内符号链接**无效**（无 realpath，标签已注明残余） |
| `isValidateFileNameBarrier`（3 处） | snk-0399/0492/0217 | files/utils.py:9-:22 拒绝 `''`/`.`/`..` 及含路径成分的名字 | 对名字携带目录成分**有效**（_set_name :51 为结果赋值形式，边被切断）；storage.py:73 与 files.py:308 为 validation-only 调用（结果弃用），守卫靠控制流（raise）——结果节点 barrier 不能切断原变量流，见 §5 局限 |
| `isSanitizeFileNameBarrier` | snk-0346 | multipartparser.py:309-:315 unescape+双 basename+危险名拒绝 | 对分隔符穿越**有效**；残余：Windows 盘符相对名（docstring 自认），交由存储层 barrier 兜底 |
| `isBasenameGuardBarrier`（uploadedfile:43；files/utils:9/:21） | snk-0490/0500/0502 | `os.path.basename` 使结果不含目录成分 | 对目录成分**有效**（盘符相对残余同上） |
| `isPurePathGuardBarrier`（storage:71/:106；files/utils:16） | snk-0398/0404/0501 | `if '..' in PurePath(x).parts: raise` | 语义上对 '..' **有效**，但属控制流守卫（检查值与 sink 值是不同表达式），构造调用节点 barrier 在数据流路径上基本 inert——如实记录，不夸大为可阻断 |
| `isValidFilenameBarrier`（storage:63 内 get_valid_filename 调用 + :108 self.get_valid_name 包装调用） | snk-0396 | utils/text.py:220 字符白名单 `[-\w.]` 去除 `/`、`\` | 对分隔符**有效** |

**明确不作 Barrier 的**（标签判 none/fp，符合“不能机械视为过滤”）：`posixpath.normpath`（仅规范化，`a/../../b`→`../b` 仍可穿越）、`abspath/realpath/normcase`（safe_join 之外无 containment 语义）、`startswith` 前缀检查（cache `_delete` filebased.py:82、archive target_filename:141——无尾分隔符，同前缀兄弟目录可绕过；后者本就是 candidate 级）、`dirname/split/splitext`。**未发现** `relative_to()` 用法。

## 5. 预期行为、CodeQL 局限与诊断路径（不计入正式告警）

**预期告警面（供 Step 5 执行后核对，非本次执行结果）**：按标签预测，唯一未被数据流 Barrier 截断的已批准 source→sink 连通是 **session 文件后端**（cookie 键→字段边→_key_to_file join→open/os.open/shutil.move/unlink，VALID_KEY_CHARS 为控制流守卫，数据流不可见）——对应标签"expected triage FP"；static/admindocs 链被 safe_join barrier 切断、上传名链被 sanitize_file_name barrier 切断，预期无告警。

局限与遗漏（如实记录）：
1. **FileResponse 参数 0 为文件对象**：其污点前提（Path.open receiver→结果）未建模，该 sink 行（snk-0380）预计 inert；配套的 receiver 型 open sink（snk-0381）为实际检测点。
2. **控制流守卫不可数据流化**：VALID_KEY_CHARS（file.py:51，行内 `set().issubset`）、缓存键 md5（filebased.py:127-:135，hashlib 仅 `hashlib.new` 有概念建模、无 arg→hexdigest 污点边——缓存链因此自然断开）、validate_file_name 的 validation-only 调用、PurePath 检查。这些由 Phase 2 Step 6 过滤/人工 triage 处理，标签 rationale 已逐条预告 triage FP。
3. **os.path 次级函数未建模**：dirname/normpath 无 arg→结果污点边（安装包仅 join 有）——影响 makedirs 等二级 sink 的可达性，不影响主链判定。
4. **属性流缺口**：`File.__init__` 的 `self.name = name`（base.py:14-:19）之后 UploadedFile 的 `_set_name` property setter（uploadedfile.py:36-:55）不被 CodeQL 调用（property setter 不建摸），故 `_set_name` 内的 basename/validate barrier 在上传主链上位于 sanitize_file_name 之后、属纵深防御；FieldFile 的 `self.name`（DB 字段值）无字段边——对应 candidate 标签 snk-0205..0215 未建边（无已批准 source 抵达）。
5. **动态调用/别名**：未发现动态 `open` 派发（检测自 Phase 1）；`IE_sanitize = sanitize_file_name` 类别名（multipartparser.py:317）未匹配（仅 :208 主调用，grep 验证别名无其他调用点）；`from os import path` 别名形式（templates.py）与 `from os.path import ...` 裸名形式（utils/_os.py）——sink/barrier 匹配基于 os.path. 限定形与 multipart/storage 实际调用形核对，CLI 文件不在正式模型内故无影响。
6. **诊断建议（不生成文件、不计入正式结果）**：如需在 Step 5 编译期调试 wrapper 连通性，可另写 `@kind problem` 的诊断查询（例如枚举 `isSource`/`isSink`/`isBarrier` 命中行、或仅含 session 家族的局部配置），按用户要求本次只交付六个文件，未创建。

## 6. 标签遗漏检查（是否需退回第五步）

未发现已批准（tp）标签在建模中被遗漏：194 source/tp 全部落入 §1 七条谓词；27 行 sink/tp 全部落入 §2 六条谓词（26 调用点）；17 sanitizer/tp 全部落入 §4 六条 barrier。三条显式传播边中两条直接对应 tp 级 summary 标签（src-0193、snk-0154 的连通描述），一条（Path 构造）为无标签的必要包装器边（§3.2-1，证据=tp 级 receiver sink + 安装包 TODO）。**不需退回第五步重审**；但 38 条 candidate 标签（2 source、17 sink、2 sanitizer、17 summary/candidate）仍处待审状态，若人工批准其中任一条，应回到第五步更新 labels.json 后再增量修改对应 QLL（本查询骨架无需变动）。

## 7. 实验独立性

与此前各步一致：未读取 PyVul 真值（含 django_vuln 根部的 path_traversal_sinks.csv）、已知 CVE 行号或修复补丁；未修改 django_vuln 源码、django-db 数据库、Augur 安装、Phase 1 标签（labels.json 等）与 extraction 原始 CSV；qlpack.yml 保持 Step 0 原样。本步仅新增六个文件，未执行编译或 `codeql database analyze`（按要求停止于生成）。

## 8. 编译校验与修复记录（本步生成后补充）

用户执行 `codeql query compile --check-only --additional-packs=<python ql/lib> queries/Pass1_PathTraversal.ql`（CLI 2.25.1）暴露两类解析错误，均已修复并复验通过：

1. `could not resolve module MySources/MySinks/MySanitizers/MySummaries`（查询 :32/:36/:40/:44 的 `My<Library>::isXxx(...)` 引用处）：`import libraries.MySources` 能解析到文件，但 QL 文件导入不把文件名绑定为可引用模块名。修复：在每个 .qll 内**显式声明与文件同名的 `module My<Name> { ... }`**（与标准库 `semmle/python/dataflow/new/DataFlow.qll` 内含 `module DataFlow` 的模式一致），`My<Name>::谓词` 引用随之解析。
2. `could not resolve predicate parameterNode/1`（MySources :73/:211、MySummaries :104/:133）：`parameterNode` 是 DataFlow 模块内部成员，不能裸调用。修复：改为限定形式 **`DataFlow::parameterNode(p)`**（与标准库 frameworks/Websockets.qll 的用法一致），共 4 处（MySources 2 处、MySummaries 2 处；MySinks/MySanitizers 未使用）。

修复后同一命令复验：`Compiling query plan ... Done [1/1]`，无错误无警告。语义未变：Source/Sink/Barrier/Summary 规则、标签映射、传播边与 §1–§7 的全部结论保持原样；四个库文件仅为包裹 module 与谓词限定名的机械变换（结构性检查：括号平衡不变）。`--check-only` 仅做解析/类型检查，查询计划编译不产生告警结果。
