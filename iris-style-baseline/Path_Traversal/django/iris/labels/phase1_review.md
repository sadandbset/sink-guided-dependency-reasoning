# Phase 1 Step 3 人工审查文档 — Pass 1 Path Traversal (Django 2.2.26 alpha)

- 运行：`django-pathtraversal-pass1-step3-20261022`，模型 glm-5.3（Claude Code CLI 会话，确定性分批标注，无采样随机性）
- 标注对象：extraction/sources.csv（225 行 → 211 唯一候选）+ extraction/sinks.csv（588 行 → 527 唯一候选）= **738 条全部处理**，去重规则为“仅 matchKind (ast/api) 不同的重复行合并、逐 CSV 5 条完全重复行折叠”；无任何候选被静默丢弃，排除均以 `role=none / classification=fp` + rationale 落盘。
- 判定依据：逐条读取 django_vuln 真实源码（每个候选的 file:line）；**未读取** PyVul 真值、补丁差异、CVE 公告；未修改源码/CodeQL 数据库/Augur 文件/Phase 1 原始 CSV。
- 分批：10 批（4 个 source 批、6 个 sink 批），批大小 19–154；原始逐条判定见 labels_raw_pass1.json。
- classification 语义：`tp` = 角色成立且路径参数/输入边界在真实攻击面上可达；`fp` = 候选被否（常量/配置/CLI 路径，或非文件访问）；`candidate` = 需人工复核。

## 1. 标签汇总（WORKFLOW 4.5 审查载荷）

| role | source 候选 | sink 候选 | 合计 |
| --- | --- | --- | --- |
| source | 194 | 0 | 194 |
| sink | 0 | 98 | 98 |
| sanitizer | 0 | 19 | 19 |
| summary | 3 | 24 | 27 |
| none | 14 | 386 | 400 |

classification：tp 243 / candidate 39 / fp 456 / unknown 0；置信度全部 ≥0.55，无需 re-ask 批（0.55–0.69 的 38 条全部为 candidate 级人工复核项）。

**Top 高危 sink（tp，请求可达的真实文件访问）**：views/static.py:50 `fullpath.open('rb')` + `FileResponse`（dev 静态服务）；contrib/admindocs/views.py:334 `template_file.open()`（URL kwargs 'template'）；core/files/storage.py:231/273/310/308/245/249/268（存储层读/写/删）；core/files/move.py:48/56/58/80（落盘搬运）；contrib/sessions/backends/file.py:78/126/164/181（cookie 键派生路径）；core/cache/backends/filebased.py:34/55/63/85/93（缓存键派生路径）。

**Top 宽 source 族**：request.path/path_info（39 条，全部请求处理代码）；request.META（51）、request.POST（54）、request.GET（29）、request.FILES（3）、request.COOKIES（7）；WSGI environ 提取（wsgi.py:105/158/179/186/189）；路由参数（static/staticfiles serve 的 `path`、admindocs `kwargs`）。

**Sanitizer 清单（19）**：`safe_join`×6（utils/_os.py，分别用于 static serve、staticfiles finders、storage.path、模板 loader、模板后端、admindocs）；`validate_file_name`×3；`PurePath/PurePosixPath` '..' 拒绝×3；`os.path.basename` 守卫×3；`get_valid_filename`；`MultiPartParser.sanitize_file_name`；archive `target_filename`×2（candidate，见 §4）。

## 2. 逐项审查结论（对应用户十条审查要求）

1. **Source 是否真正不可信**：是。194 条 source/tp 全部落在 URL 路径（WSGI PATH_INFO→request.path/path_info）、路由注入参数（`(?P<path>.*)$` 捕获的 serve path、admindocs kwargs）、请求参数/表单/头/Cookie、multipart Content-Disposition filename、以及 SessionStore.__init__ 的 session_key 形参（由 SessionMiddleware 用 cookie 值自动注入——形参本身即是边界，非“内部函数形参当 source”）。9 条 `os.environ.get`（部署者/操作者环境）与 5 条 CLI 形参（TemplateCommand handle/handle_template/download）判 none/fp：无远程攻击面。
2. **解码/规范化/拼接链路可跟踪**：三条主链均可逐步落到真实代码——
   - 静态服务：URL → `serve(request, path)` 形参 → `posixpath.normpath(path).lstrip('/')`（views/static.py:35，仅规范化，非屏障）→ `safe_join(document_root, path)`（:36，屏障）→ `Path(...)`（:36，构造非 sink）→ `is_dir/exists/stat`（:37/:41/:44，元数据）→ `fullpath.open('rb')`+`FileResponse`（:50，真实 sink）。staticfiles 变体经 `normpath` → `finders.find`（arg→return 需 summary）→ `safe_join`（finders.py:121）→ 回落 `static.serve` 二次 safe_join。
   - 上传名：Content-Disposition filename（multipartparser.py:205 source；RFC2231 `unquote` :687 summary，单次解码）→ `sanitize_file_name`（:208 sanitizer，html.unescape + rsplit basename）→ `handler.new_file`（uploadhandler.py:93 summary）→ `UploadedFile._set_name`（:39 summary + `os.path.basename` :43 + `validate_file_name` :51 sanitizer）→ 存储链 `get_available_name`/`generate_filename`（'..' 检查 + `get_valid_filename`）→ `storage.path`（safe_join）→ `os.open`/`file_move_safe`（真实 sink）。
   - admindocs：URL kwargs 'template' → `safe_join(directory, template)`（views.py:332）→ `Path.exists/open`（:333/:334）。
3. **Sink 为真实文件访问**：只有 open/os.open/makedirs/rename/remove/rmdir/unlink/move/symlink、解压落盘写、`FileResponse` 被标 sink。`Path()`、`os.path.join/normpath/abspath/split/splitext/basename`、`exists/isdir/stat/scandir/walk/listdir`、`chmod/utime/copystat` 一律 none/fp（386 条）。
4. **能否越过声明根目录**：直连 `../`、绝对路径在主链上均被 `safe_join`（abspath+normcase 前缀 + 分隔符/相等/根目录三例外）拦截；URL 侧仅单次解码（WSGI 层一次；staticfiles handlers 的 `url2pathname` 是第二处解码点，但解码结果仍进 safe_join）。`safe_join` 的两个已记录残余：前缀式（不 resolve 符号链接）与 check-then-open TOCTOU（:41/:44 在 :50 之前）——文档_root 内被植入符号链接时可越界，但植入前提本身需要其他入侵途径（详见 §4/§5）。
5. **受限根目录检查真实且先于文件访问**：`safe_join`（抛 SuspiciousFileOperation，发生在 open 之前）、session `VALID_KEY_CHARS`（`set(session_key).issubset`，file.py:51，仅 a-z0-9，行内检查非候选行、已写入 rationale）、缓存键 md5 hexdigest（filebased.py:132-135）、`validate_file_name` 系列、JavaScriptCatalog 包名白名单（i18n.py:206-212）。无 `relative_to()` 用法；固定文件名映射见 debug.py 技术页模板（常量字面量，判 fp）。
6. **函数名不当作 sanitizer**：`normpath`（static.py:35 等）全部判 none 并写明“仅规范化、输出仍可含穿越文本”；`basename` 仅在 `_set_name`/`validate_file_name` 内作为守卫实现的位置判 sanitizer（uploadedfile.py:43、files/utils.py:9/21），并注明 Windows 盘符相对名（"C:file"）残余——该残余由存储层 `validate_file_name`+`safe_join` 兜底。`startswith` 型守卫两处：cache `_delete`（filebased.py:82，无尾分隔符、理论可被同前缀兄弟目录绕过，但路径本身 md5 派生）与 archive `target_filename`（见 §4）。
7. **符号链接/TOCTOU**：框架内未发现“规范化/校验/使用”时序直接导致根目录失效的可远程利用点；已记录的时序风险：static serve `exists()/stat()` 先于 `open()`（TOCTOU 形态）、storage.py:238 exists→makedirs 竞态（注释自认，O_EXCL 兜底）、move.py:45 access→rename、session 校验与使用分离。collectstatic 的 symlink 操作为 CLI 工具（fp）。均写入对应 entry 的 rationale/evidence。
8. **授权访问≠漏洞**：static serve / staticfiles serve / admindocs 模板页属开发者/管理员文档功能，用户“被授权访问所选文件”——这些 sink 标 tp 是出于保守召回（sink 本身真实、路径参数可携带外部数据），但流被 sanitizer 标签截断（safe_join barrier），预期 Phase 2 告警经 triage 归为 FP。
9. **测试/常量/不可达排除**：`django/test/`、`django-db/`、顶层 tests/ 在抽取阶段即被 scope 排除（detection.json）；本步判 fp 的：全部 management 命令（makemessages 64 行、collectstatic 30 行、loaddata、makemigrations 等）、debug.py 固定模板、mail 文件后端（settings 派生）、sqlite 测试库（测试运行器上下文）、gis/geoip2（配置）、archive CLI 流。
10. **完整流 vs 局部包装器**：完整“不可信 source→危险路径参数”流存在且逐条可跟踪（§2 三条主链 + session 键链 + 缓存键链）；仅有“内部包装器→文件 API”局部流的（mail `attach_file`、gis `fromfile`、`File.open` 重开、模板 loader 读取 app 控制名）判 summary/sink + classification=candidate，并注明“仅应用层误用才成为完整流”。

## 3. 关键流判定表

| 流 | source | 传播 | barrier | sink | 结论 |
| --- | --- | --- | --- | --- | --- |
| dev 静态服务 | serve `path` 路由参数 (src-0180) | normpath→join | `safe_join` :36 (snk-0376) | open+FileResponse :50 (snk-0380/0381) | 直连穿越被阻断；残余=前缀式符号链接 + TOCTOU（需先有 root 内链接） |
| staticfiles serve | serve `path` (src-0206) | find summary (snk-0516/0222/0230) | safe_join finders.py:121 + serve 内二次 | 同上（经 0518 委托） | 双重 containment，同样仅剩符号链接残余 |
| admindocs 模板页 | kwargs['template'] (src-0200) | — | safe_join views.py:332 (snk-0511) | open :334 (snk-0513) | 穿越被阻断 |
| 上传文件写 | disposition filename (src-0116) | unquote/_set_name/new_file summary | sanitize_file_name + basename + validate_file_name + PurePath '..' 检查 + storage safe_join | storage os.open :273 等 | 多层守卫；残余=Windows 盘符相对名（文档自认，已注明） |
| session 文件后端 | cookie session_key (src-0111/0112/0077) | _key_to_file join summary (snk-0154) | `VALID_KEY_CHARS` 行内子集检查（file.py:51） | open/os.open/move/unlink (snk-0158/0160/0163/0168) | 键字符集 a-z0-9，穿越不可能；告警预期为 triage FP |
| 文件缓存后端 | cache.get/set 的 key（调用方参数，原生参数流） | md5+join | md5 hexdigest（filebased.py:127-135，行内） | open/remove/file_move_safe | 十六进制文件名不可穿越 |
| CLI --template 解压 | 操作者输入（无远程 source） | handle_template→extract | target_filename 前缀检查（弱） | archive open 写 (snk-0042/0052) | 无远程边界（fp/candidate）；前缀检查弱点评 §4 |

## 4. 需人工复核的点（classification=candidate，38 条）

1. **utils/archive.py `target_filename`（:167/:212，sanitizer/candidate）**：`abspath(join(abspath(to_path), name))` + `startswith(target_path)`，无尾随分隔符——成员名解析到与 to_path **同前缀的兄弟目录**（如 to_path=".../extract"、name="../extract_evil"→".../extract_evil"）可通过检查。绝对 '../' 越界会被拦。Django 内仅 CLI TemplateCommand 可达；若采纳“操作者提供不可信归档”威胁模型则应升级。**建议人工复核。**
2. **views/i18n.py:195/198（source/candidate）**：JavaScriptCatalog 的 `domain`/`packages` kwargs 仅当 URLconf 捕获时才远程可达；packages 有安装应用白名单，而 **domain 未经验证**流入 stdlib `gettext.translation(domain=...)` 的 .mo 文件名构造（在审计树之外）——若站点路由暴露 domain 捕获组，存在穿越读取 `.mo` 的理论路径。**建议人工复核。**
3. **模板 loader / dummy 后端 open（snk-0219/0140）**：template_name 在框架用法中为开发者常量；仅当应用把请求值拼进模板名（已知应用层反模式）才成流。safe_join 已在 `get_template_sources` 拦截。
4. **mail attach_file / gis fromfile / File.open 重开（snk-0329/0331/0143/0144/0062/0064/0237）**：局部“包装器→文件 API”流，取决于应用是否把请求派生路径传入；框架自身无此用法。
5. **ManifestStaticFilesStorage.hashed_name open（snk-0386）**：运行时经 `{% static %}`/url() 触达，name 为应用模板值；storage.path 的 safe_join 兜底。
6. **management/templates.py:286 `shutil.move(the_path, guessed_path)`（fp/0.6）**：目标文件名来自下载响应的 Content-Disposition（服务器可影响、原则上可含分隔符）——仅 CLI 操作者发起，属供应链形态而非远程 CWE-22；如采纳该威胁模型需升级。
7. **对象字段流（summary/candidate 组）**：FieldFile 的 `self.name`（DB 字段值，上传时已经校验链）、session 对象内 `self.session_key`、File.name——这些方法间字段流需要 MySummaries 补边（Phase 2 注意事项，不改变本步判定）。

## 5. 守卫强度结论（对应“6. 不能凭函数名认定 sanitizer”）

- **`safe_join`（6 处，tp/0.85）**：实现为 `abspath(join())` + `normcase` 前缀 + 三例外（分隔符/相等/最根路径），在文件访问前抛异常；对本仓库内的直连穿越（`../`、绝对路径、大小写变体、Windows normcase）均有效。残余：不 resolve 符号链接（root 内链接可指向外）+ 前缀式而非 realpath。
- **`validate_file_name`（3 处）**：拒绝 `''`/`.`/`..` 与任何含路径成分的名字；allow_relative_path 分支用 PurePosixPath 拒绝绝对路径与 '..'。
- **`sanitize_file_name`**：basename 化 + `''`/`.`/`..` 拒绝；docstring 自认“结果仍应视为不可信”（盘符相对名残余），下游存储层兜底。
- **`normpath`/`normcase`/`abspath`/`basename`（非守卫位置）**：全部判 none——仅传播或规范化。
- **`startswith`（cache `_delete`、archive `target_filename`）**：无尾分隔符的同前缀绕过已写入 rationale；前者路径 md5 派生无实害，后者列为人工复核项。

## 6. 结论

738/738 候选全部判定并落盘；labels.json 通过 assets/labels_schema.json 校验。Pass 1 具备 98 个 sink 条目（26 个 tp 调用点）、194 个 source、19 个 sanitizer、27 个 summary；主链均被真实守卫截断，未发现无需人工复核即成立的远程可穿越路径；38 条 candidate 级复核点见 §4。按指令，本步到此为止，**不进入 Phase 2**（Step 4 库生成、Step 5 污点查询、Step 6 过滤报告均未执行）。
