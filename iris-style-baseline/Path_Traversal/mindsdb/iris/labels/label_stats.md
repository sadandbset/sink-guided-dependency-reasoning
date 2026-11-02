# Pass 1 Label Statistics (Path Traversal)

- run_id: `mindsdb-pass1-20261022`
- generated_at: 2026-10-22T08:19:33+00:00
- model: glm-5.3 (in-process LLM analysis, no external API call)
- batches: 8 (S1-S4 sources, K1-K4 sinks)
- raw candidates: 120 source rows + 116 sink rows = 236
- unique entries: 90 sources + 110 sinks = 200
- rows merged in dedup: 30 source + 6 sink

## Role counts

| role | count |
| --- | --- |
| source | 29 |
| sink | 28 |
| sanitizer | 0 |
| summary | 33 |
| none | 110 |

## Classification counts

| classification | count |
| --- | --- |
| tp | 35 |
| fp | 112 |
| candidate | 53 |
| unknown | 0 |

## Role x classification

| role/classification | count |
| --- | --- |
| none/fp | 110 |
| sink/candidate | 13 |
| sink/fp | 2 |
| sink/tp | 13 |
| source/candidate | 7 |
| source/tp | 22 |
| summary/candidate | 33 |

## Confidence distribution

| bucket | count |
| --- | --- |
| high (>=0.8) | 124 |
| medium (0.55-0.79) | 63 |
| low (<0.55) | 13 |

## Batch sizes

| batch | scope | entries |
| --- | --- | --- |
| S1 | internal boundary receiver params (controllers / handlers / storage) | 13 |
| S2 | public HTTP flask request reads (api/http/namespaces + start.py) | 34 |
| S3 | upload attributes, python-multipart callbacks, SQL/mongo/mysql wire boundaries | 15 |
| S4 | internal handler/executor wrapper RPC request.json reads | 28 |
| K1 | pathlib receiver-controlled sinks (mkdir/unlink/rmdir/touch/write_text) | 22 |
| K2 | open() file sinks | 27 |
| K3 | shutil/os directory and file operation sinks | 45 |
| K4 | archive, sqlite, and file-response sinks | 16 |

## High-confidence true-positive sources (tp, conf >= 0.8)

- `S002` mindsdb/interfaces/file/file_controller.py:55 save_file (param) conf=0.85
- `S003` mindsdb/interfaces/file/file_controller.py:55 save_file (param) conf=0.8
- `S005` mindsdb/integrations/handlers/file_handler/file_handler.py:98 _handle_source (param) conf=0.85
- `S006` mindsdb/integrations/handlers/file_handler/file_handler.py:142 _get_data_io (param) conf=0.85
- `S013` mindsdb/interfaces/database/integrations.py:45 add (param) conf=0.85
- `S021` mindsdb/api/http/namespaces/config.py:121 request.json (field) conf=0.9
- `S022` mindsdb/api/http/namespaces/config.py:122 request.form (field) conf=0.85
- `S023` mindsdb/api/http/namespaces/config.py:127 request.files (field) conf=0.85
- `S029` mindsdb/api/http/namespaces/handlers.py:127 request.json (field) conf=0.85
- `S033` mindsdb/api/http/namespaces/file.py:80 request.json (field) conf=0.95
- `S036` mindsdb/api/http/namespaces/sql.py:22 request.json (field) conf=0.95
- `S042` mindsdb/api/http/namespaces/analysis.py:28 request.json (field) conf=0.85
- `S048` mindsdb/api/http/namespaces/config.py:133 filename (field) conf=0.85
- `S049` mindsdb/api/http/namespaces/file.py:43 field_name (field) conf=0.8
- `S050` mindsdb/api/http/namespaces/file.py:44 value (field) conf=0.8
- `S053` mindsdb/api/http/namespaces/file.py:51 file_name (field) conf=0.95
- `S054` mindsdb/api/http/namespaces/handlers.py:98 file_name (field) conf=0.9
- `S057` mindsdb/api/http/namespaces/file.py:42 on_field (param) conf=0.85
- `S059` mindsdb/api/http/namespaces/file.py:49 on_file (param) conf=0.95
- `S060` mindsdb/api/http/namespaces/handlers.py:96 on_file (param) conf=0.9
- `S061` mindsdb/api/mongo/classes/query_sql.py:5 run_sql_command (param) conf=0.85
- `S062` mindsdb/api/mysql/mysql_proxy/mysql_proxy.py:432 process_query (param) conf=0.95

## High-confidence true-positive sinks (tp, conf >= 0.8)

- `K009` mindsdb/api/http/namespaces/handlers.py:136 os.unlink arg=0 (argument) conf=0.9
- `K024` mindsdb/integrations/handlers/file_handler/file_handler.py:158 open arg=0 (argument) conf=0.95
- `K034` mindsdb/api/http/namespaces/file.py:123 open arg=0 (argument) conf=0.9
- `K041` mindsdb/integrations/handlers/bigquery_handler/bigquery_handler.py:47 open arg=0 (argument) conf=0.85
- `K072` mindsdb/api/http/namespaces/file.py:138 os.remove arg=0 (argument) conf=0.9
- `K079` mindsdb/interfaces/file/file_controller.py:100 shutil.move arg=0 (argument) conf=0.9
- `K082` mindsdb/interfaces/file/file_controller.py:100 shutil.move arg=1 (argument) conf=0.9
- `K093` mindsdb/interfaces/database/integrations.py:68 shutil.copy arg=0 (argument) conf=0.9
- `K095` mindsdb/api/http/namespaces/file.py:133 zipfile.ZipFile arg=0 (argument) conf=0.9
- `K096` mindsdb/api/http/namespaces/file.py:136 tarfile.open arg=0 (argument) conf=0.9
- `K097` mindsdb/api/http/namespaces/file.py:134 extractall arg=0 (argument) conf=0.9
- `K098` mindsdb/api/http/namespaces/file.py:137 extractall arg=0 (argument) conf=0.9
- `K105` mindsdb/integrations/handlers/sqlite_handler/sqlite_handler.py:60 sqlite3.connect arg=0 (argument) conf=0.85

## Sanitizers

No candidate row was labeled `sanitizer`: no extraction CSV node is itself a proven neutralization barrier. Barriers verified in source (to be encoded in MySanitizers.qll at Step 4):

- `config.py:133-136` resolve + parents containment for werkzeug integration uploads
- `integrations.py:68-69` copy-then-`Path(arg_value).name` basename for ARG_TYPE.PATH args (partial: the copy at line 68 still reads the raw path)
- `file_controller.py:128` `Path(source_file_path).name` basename on file retrieval
- `fs.py:297-298, 311-312` absolute-path rejection in FileStorage.get_path/delete (partial: '..' segments are not contained)
- `fs.py:314-316` equality-only root check in FileStorage.delete (partial, not containment)
- werkzeug `safe_join` inside `send_from_directory` (framework-internal)

## Unresolved / low-confidence items (manual review)

- `S007` mindsdb/interfaces/storage/fs.py:194 push_path role=summary cls=candidate conf=0.55
- `S008` mindsdb/interfaces/storage/fs.py:203 pull_path role=summary cls=candidate conf=0.55
- `S009` mindsdb/interfaces/storage/fs.py:214 file_set role=summary cls=candidate conf=0.6
- `S010` mindsdb/interfaces/storage/fs.py:226 file_get role=summary cls=candidate conf=0.6
- `S011` mindsdb/interfaces/storage/fs.py:276 get_path role=summary cls=candidate conf=0.55
- `S012` mindsdb/interfaces/storage/fs.py:307 delete role=summary cls=candidate conf=0.55
- `S024` mindsdb/api/http/namespaces/config.py:192 request.json role=source cls=candidate conf=0.55
- `S025` mindsdb/api/http/namespaces/config.py:193 request.form role=source cls=candidate conf=0.55
- `S028` mindsdb/api/http/namespaces/handlers.py:117 request.stream role=source cls=candidate conf=0.6
- `S032` mindsdb/api/http/namespaces/file.py:70 request.stream role=source cls=candidate conf=0.6
- `S051` mindsdb/api/http/namespaces/handlers.py:90 field_name role=source cls=candidate conf=0.6
- `S052` mindsdb/api/http/namespaces/handlers.py:91 value role=source cls=candidate conf=0.6
- `S058` mindsdb/api/http/namespaces/handlers.py:89 on_field role=source cls=candidate conf=0.6
- `S063` mindsdb/integrations/handlers_wrapper/db_handler_wrapper.py:65 request.json.get role=summary cls=candidate conf=0.6
- `S064` mindsdb/integrations/handlers_wrapper/db_handler_wrapper.py:160 request.json role=summary cls=candidate conf=0.6
- `S065` mindsdb/integrations/handlers_wrapper/db_handler_wrapper.py:170 request.json role=summary cls=candidate conf=0.6
- `S066` mindsdb/integrations/handlers_wrapper/db_handler_wrapper.py:181 request.json role=summary cls=candidate conf=0.6
- `S067` mindsdb/integrations/handlers_wrapper/db_handler_wrapper.py:196 request.json role=summary cls=candidate conf=0.6
- `S068` mindsdb/integrations/handlers_wrapper/db_handler_wrapper.py:245 request.json role=summary cls=candidate conf=0.6
- `S069` mindsdb/integrations/handlers_wrapper/db_handler_wrapper.py:263 request.json role=summary cls=candidate conf=0.6
- `S071` mindsdb/integrations/handlers_wrapper/db_handler_wrapper.py:194 request.json.get role=summary cls=candidate conf=0.55
- `S072` mindsdb/integrations/handlers_wrapper/db_handler_wrapper.py:259 request.json.get role=summary cls=candidate conf=0.55
- `S073` mindsdb/integrations/handlers_wrapper/ml_handler_wrapper.py:60 request.json role=summary cls=candidate conf=0.6
- `S074` mindsdb/integrations/handlers_wrapper/ml_handler_wrapper.py:151 request.json.get role=summary cls=candidate conf=0.55
- `S075` mindsdb/integrations/handlers_wrapper/ml_handler_wrapper.py:152 request.json.get role=summary cls=candidate conf=0.55
- `S076` mindsdb/integrations/handlers_wrapper/ml_handler_wrapper.py:177 request.json.get role=summary cls=candidate conf=0.55
- `S077` mindsdb/integrations/handlers_wrapper/ml_handler_wrapper.py:214 request.json.get role=summary cls=candidate conf=0.55
- `S078` mindsdb/integrations/handlers_wrapper/ml_handler_wrapper.py:234 request.json.get role=summary cls=candidate conf=0.55
- `S079` mindsdb/integrations/handlers_wrapper/ml_handler_wrapper.py:258 request.json.get role=summary cls=candidate conf=0.55
- `S080` mindsdb/integrations/handlers_wrapper/ml_handler_wrapper.py:289 request.json.get role=summary cls=candidate conf=0.55
- `S081` mindsdb/api/mysql/mysql_proxy/executor/executor_wrapper.py:124 request.json role=summary cls=candidate conf=0.55
- `S082` mindsdb/api/mysql/mysql_proxy/executor/executor_wrapper.py:189 request.json.get role=summary cls=candidate conf=0.55
- `S083` mindsdb/api/mysql/mysql_proxy/executor/executor_wrapper.py:199 request.json.get role=summary cls=candidate conf=0.55
- `S084` mindsdb/api/mysql/mysql_proxy/executor/executor_wrapper.py:211 request.json role=summary cls=candidate conf=0.55
- `S085` mindsdb/api/mysql/mysql_proxy/executor/executor_wrapper.py:224 request.json role=summary cls=candidate conf=0.55
- `S086` mindsdb/api/mysql/mysql_proxy/executor/executor_wrapper.py:237 request.json role=summary cls=candidate conf=0.55
- `S087` mindsdb/api/mysql/mysql_proxy/executor/executor_wrapper.py:273 request.json role=summary cls=candidate conf=0.55
- `S088` mindsdb/api/mysql/mysql_proxy/executor/executor_wrapper.py:286 request.json role=summary cls=candidate conf=0.55
- `S089` mindsdb/api/mysql/mysql_proxy/executor/executor_wrapper.py:299 request.json role=summary cls=candidate conf=0.55
- `S090` mindsdb/api/mysql/mysql_proxy/executor/executor_wrapper.py:311 request.json role=summary cls=candidate conf=0.55
- `K008` mindsdb/interfaces/storage/fs.py:326 unlink role=sink cls=candidate conf=0.5
- `K016` mindsdb/interfaces/storage/fs.py:328 rmdir role=sink cls=candidate conf=0.5
- `K046` mindsdb/interfaces/storage/fs.py:39 open role=sink cls=candidate conf=0.45
- `K047` mindsdb/interfaces/storage/fs.py:39 open role=sink cls=candidate conf=0.45
- `K048` mindsdb/interfaces/storage/fs.py:220 open role=sink cls=candidate conf=0.5
- `K049` mindsdb/interfaces/storage/fs.py:233 open role=sink cls=candidate conf=0.5
- `K063` mindsdb/interfaces/storage/fs.py:35 shutil.rmtree role=sink cls=candidate conf=0.45
- `K068` mindsdb/interfaces/storage/fs.py:303 os.makedirs role=sink cls=candidate conf=0.5
- `K076` mindsdb/interfaces/storage/fs.py:42 os.remove role=sink cls=candidate conf=0.45
- `K089` mindsdb/interfaces/storage/fs.py:36 shutil.copytree role=sink cls=candidate conf=0.45
- `K090` mindsdb/interfaces/storage/fs.py:36 shutil.copytree role=sink cls=candidate conf=0.45
- `K091` mindsdb/interfaces/storage/fs.py:45 shutil.copy2 role=sink cls=candidate conf=0.45
- `K092` mindsdb/interfaces/storage/fs.py:45 shutil.copy2 role=sink cls=candidate conf=0.45

