# Pass 1 Label Statistics — pyload (Path Traversal, CWE-22/23/36/73)

- run_id: `pyload-pass1-20261023`
- model: glm-5.3 (in-session LLM labeling via Claude Code CLI; no external API calls)
- input: sources.csv = 104 rows, sinks.csv = 663 rows (767 total)
- dedup: 4 exact-duplicate source rows + 7 exact-duplicate sink rows collapsed; 6 Api definition rows extracted in both CSVs merged into single source entries; key = (file, line, callable, flowKind, argIndex, receiver)
- output: 750 unique label entries; labels.json validated against `assets/labels_schema.json` (jsonschema: PASSED)
- batches: 7 (pass1-s1..s3, pass1-k1..k4); every one of the 767 candidate rows has a disposition recorded in labels_raw_pass1.json

## Entries by role

| role | count |
| --- | --- |
| summary | 275 |
| sink | 223 |
| none | 150 |
| source | 87 |
| sanitizer | 15 |

## Entries by role × classification

| role | classification | count |
| --- | --- | --- |
| summary/tp | 187 |
| none/fp | 150 |
| sink/tp | 141 |
| summary/fp | 88 |
| source/tp | 85 |
| sink/candidate | 82 |
| sanitizer/tp | 8 |
| sanitizer/candidate | 7 |
| source/candidate | 2 |

## Candidates by CSV flowKind family (labeled entries)

| family | labeled entries |
| --- | --- |
| path_join | 136 |
| path_stat | 92 |
| file_open | 87 |
| path_part | 86 |
| file_delete | 56 |
| http_form | 49 |
| file_api_def | 40 |
| path_canon | 29 |
| dir_create | 25 |
| template_render | 18 |
| file_chmod | 15 |
| dir_list | 13 |
| http_args | 12 |
| file_move | 11 |
| io_open | 8 |
| cli_arg | 7 |
| dir_walk | 7 |
| api_param | 6 |
| archive_entry | 5 |
| cli | 5 |
| dir_delete | 5 |
| file_copy | 5 |
| path_rel | 5 |
| process_file_write | 5 |
| route_param | 5 |
| path_api_def | 4 |
| archive_extract | 3 |
| chdir | 3 |
| http_file_name | 3 |
| http_iter | 3 |
| http_auth | 2 |
| api_dispatch | 1 |
| file_response | 1 |
| file_save | 1 |
| http_file | 1 |
| http_values | 1 |
| path_containment_check | 1 |

## Confidence distribution

| confidence | entries |
| --- | --- |
| <0.55 | 152 |
| 0.55-0.69 | 254 |
| 0.70-0.84 | 143 |
| >=0.85 | 201 |

## Low-confidence entries (confidence < 0.55, 152 total)

These are deliberately down-weighted, not unresolved: the bulk are metadata-probe/oracle calls (os.path.isfile/isdir/getsize/stat/listdir, path_stat family at 0.45-0.55) where the call itself is only an existence/size oracle and the traversal impact requires a paired file-access sink, plus a few wrapper-internal probes on fixed patterns. No re-ask pass was run: the confidence encodes the API semantics, not labeling uncertainty; each rationale states the reason.

| id | role | conf | location |
| --- | --- | --- | --- |
| P1-K-0001 | sink | 0.5 | src/pyload/plugins/decrypters/AlldebridComTorrent.py:51 |
| P1-K-0004 | sink | 0.5 | src/pyload/plugins/decrypters/AlldebridComTorrent.py:109 |
| P1-K-0005 | sink | 0.5 | src/pyload/plugins/addons/AntiCaptcha.py:111 |
| P1-K-0021 | sink | 0.5 | src/pyload/plugins/addons/Captcha9Kw.py:107 |
| P1-K-0022 | sink | 0.5 | src/pyload/plugins/addons/Checksum.py:16 |
| P1-K-0025 | sink | 0.45 | src/pyload/plugins/addons/Checksum.py:163 |
| P1-K-0026 | sink | 0.5 | src/pyload/plugins/addons/Checksum.py:169 |
| P1-K-0032 | sink | 0.5 | src/pyload/plugins/addons/Checksum.py:287 |
| P1-K-0039 | sink | 0.5 | src/pyload/plugins/addons/DeathByCaptcha.py:144 |
| P1-K-0040 | sink | 0.5 | src/pyload/plugins/decrypters/DebridlinkFrTorrent.py:90 |
| P1-K-0042 | sink | 0.5 | src/pyload/plugins/decrypters/DebridlinkFrTorrent.py:341 |
| P1-K-0043 | sink | 0.5 | src/pyload/plugins/addons/ExpertDecoders.py:48 |
| P1-K-0073 | sink | 0.5 | src/pyload/plugins/addons/ExtractArchive.py:370 |
| P1-K-0075 | sink | 0.5 | src/pyload/plugins/addons/ExtractArchive.py:386 |
| P1-K-0087 | sink | 0.5 | src/pyload/plugins/downloaders/FastshareCz.py:81 |
| P1-K-0088 | sink | 0.5 | src/pyload/plugins/downloaders/FastshareCz.py:86 |
| P1-K-0089 | sink | 0.5 | src/pyload/plugins/downloaders/FastshareCz.py:91 |
| P1-K-0090 | sink | 0.5 | src/pyload/plugins/downloaders/FilerNet.py:60 |
| P1-K-0091 | sink | 0.5 | src/pyload/plugins/downloaders/FilerNet.py:62 |
| P1-K-0097 | sink | 0.5 | src/pyload/plugins/extractors/HjSplit.py:67 |
| P1-K-0098 | sink | 0.5 | src/pyload/plugins/extractors/HjSplit.py:71 |
| P1-K-0100 | sink | 0.5 | src/pyload/plugins/extractors/HjSplit.py:79 |
| P1-K-0101 | sink | 0.5 | src/pyload/plugins/extractors/HjSplit.py:85 |
| P1-K-0116 | summary | 0.5 | src/pyload/plugins/addons/HotFolder.py:90 |
| P1-K-0119 | sink | 0.5 | src/pyload/plugins/addons/HotFolder.py:105 |
| P1-K-0120 | sink | 0.5 | src/pyload/plugins/addons/ImageTyperz.py:79 |
| P1-K-0121 | sink | 0.5 | src/pyload/plugins/downloaders/LetsuploadCo.py:50 |
| P1-K-0122 | sink | 0.5 | src/pyload/plugins/downloaders/LetsuploadCo.py:53 |
| P1-K-0127 | sink | 0.5 | src/pyload/plugins/downloaders/MegaCoNz.py:354 |
| P1-K-0128 | sink | 0.5 | src/pyload/plugins/downloaders/MegaCoNz.py:389 |
| P1-K-0129 | sink | 0.5 | src/pyload/plugins/downloaders/MegaCoNz.py:423 |
| P1-K-0130 | sink | 0.5 | src/pyload/plugins/downloaders/MegaCoNz.py:433 |
| P1-K-0137 | sink | 0.5 | src/pyload/plugins/addons/MergeFiles.py:56 |
| P1-K-0138 | sink | 0.5 | src/pyload/plugins/addons/MergeFiles.py:56 |
| P1-K-0140 | sink | 0.5 | src/pyload/plugins/downloaders/PremiumTo.py:58 |
| P1-K-0141 | sink | 0.5 | src/pyload/plugins/downloaders/PremiumTo.py:61 |
| P1-K-0144 | sink | 0.5 | src/pyload/plugins/decrypters/RealdebridComTorrent.py:82 |
| P1-K-0149 | sink | 0.5 | src/pyload/plugins/decrypters/RealdebridComTorrent.py:179 |
| P1-K-0159 | sink | 0.5 | src/pyload/plugins/extractors/SevenZip.py:204 |
| P1-K-0167 | sink | 0.5 | src/pyload/plugins/containers/TXT.py:44 |
| P1-K-0168 | sink | 0.5 | src/pyload/plugins/containers/TXT.py:72 |
| P1-K-0186 | sink | 0.5 | src/pyload/plugins/extractors/UnRar.py:230 |
| P1-K-0204 | summary | 0.5 | src/pyload/plugins/addons/UpdateManager.py:328 |
| P1-K-0207 | summary | 0.5 | src/pyload/plugins/addons/UpdateManager.py:410 |
| P1-K-0220 | sink | 0.5 | src/pyload/plugins/downloaders/YoutubeCom.py:1044 |
| P1-K-0227 | sink | 0.5 | src/pyload/plugins/downloaders/YoutubeCom.py:1102 |
| P1-K-0237 | sink | 0.5 | src/pyload/plugins/downloaders/YoutubeCom.py:1159 |
| P1-K-0243 | sink | 0.5 | src/pyload/plugins/downloaders/YoutubeCom.py:1192 |
| P1-K-0248 | sink | 0.5 | src/pyload/plugins/downloaders/YoutubeCom.py:1377 |
| P1-K-0252 | sanitizer | 0.5 | src/pyload/core/utils/old/__init__.py:36 |
| P1-K-0253 | summary | 0.5 | src/pyload/core/utils/old/__init__.py:40 |
| P1-K-0254 | sink | 0.45 | src/pyload/core/utils/old/__init__.py:42 |
| P1-K-0255 | summary | 0.5 | src/pyload/core/utils/old/__init__.py:45 |
| P1-K-0256 | summary | 0.5 | src/pyload/core/utils/old/__init__.py:56 |
| P1-K-0257 | summary | 0.5 | src/pyload/core/utils/old/__init__.py:57 |
| P1-K-0263 | summary | 0.5 | src/pyload/core/__init__.py:80 |
| P1-K-0264 | summary | 0.5 | src/pyload/core/__init__.py:80 |
| P1-K-0265 | summary | 0.5 | src/pyload/core/__init__.py:80 |
| P1-K-0294 | summary | 0.5 | src/pyload/core/api/__init__.py:342 |
| P1-K-0295 | summary | 0.5 | src/pyload/core/api/__init__.py:344 |
| P1-K-0332 | summary | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:141 |
| P1-K-0333 | summary | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:141 |
| P1-K-0334 | summary | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:143 |
| P1-K-0335 | summary | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:143 |
| P1-K-0336 | summary | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:146 |
| P1-K-0337 | summary | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:146 |
| P1-K-0338 | summary | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:153 |
| P1-K-0339 | summary | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:153 |
| P1-K-0360 | sink | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:300 |
| P1-K-0361 | sink | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:300 |
| P1-K-0363 | sink | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:306 |
| P1-K-0364 | sink | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:306 |
| P1-K-0365 | sink | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:308 |
| P1-K-0366 | sink | 0.5 | src/pyload/webui/app/blueprints/app_blueprint.py:308 |
| P1-K-0415 | summary | 0.5 | src/pyload/webui/app/filters.py:31 |
| P1-K-0416 | sink | 0.45 | src/pyload/webui/app/filters.py:32 |
| P1-K-0417 | summary | 0.5 | src/pyload/webui/app/filters.py:41 |
| P1-K-0418 | sink | 0.45 | src/pyload/webui/app/filters.py:42 |
| P1-K-0419 | summary | 0.5 | src/pyload/core/utils/format.py:33 |
| P1-K-0421 | sink | 0.5 | src/pyload/core/utils/fs.py:43 |
| P1-K-0422 | sink | 0.45 | src/pyload/core/utils/fs.py:52 |
| P1-K-0424 | summary | 0.5 | src/pyload/core/utils/fs.py:78 |
| P1-K-0427 | sink | 0.45 | src/pyload/core/utils/fs.py:87 |
| P1-K-0429 | sink | 0.45 | src/pyload/core/utils/fs.py:95 |
| P1-K-0430 | sink | 0.45 | src/pyload/core/utils/fs.py:96 |
| P1-K-0431 | summary | 0.5 | src/pyload/core/utils/fs.py:97 |
| P1-K-0432 | sink | 0.5 | src/pyload/core/utils/fs.py:98 |
| P1-K-0434 | sink | 0.5 | src/pyload/core/utils/fs.py:103 |
| P1-K-0435 | summary | 0.5 | src/pyload/core/utils/fs.py:124 |
| P1-K-0436 | summary | 0.5 | src/pyload/core/utils/fs.py:125 |
| P1-K-0437 | sink | 0.5 | src/pyload/core/utils/fs.py:131 |
| P1-K-0438 | summary | 0.5 | src/pyload/core/utils/fs.py:135 |
| P1-K-0439 | summary | 0.5 | src/pyload/core/utils/fs.py:135 |
| P1-K-0443 | sink | 0.45 | src/pyload/core/utils/fs.py:184 |
| P1-K-0444 | sink | 0.45 | src/pyload/core/utils/fs.py:184 |
| P1-K-0445 | sink | 0.45 | src/pyload/core/utils/fs.py:198 |
| P1-K-0452 | sink | 0.45 | src/pyload/core/utils/fs.py:228 |
| P1-K-0456 | sink | 0.45 | src/pyload/core/utils/fs.py:240 |
| P1-K-0458 | summary | 0.5 | src/pyload/core/utils/fs.py:245 |
| P1-K-0459 | sink | 0.45 | src/pyload/core/utils/fs.py:251 |
| P1-K-0460 | summary | 0.5 | src/pyload/core/utils/fs.py:259 |
| P1-K-0463 | sink | 0.45 | src/pyload/core/utils/fs.py:272 |
| P1-K-0464 | sink | 0.5 | src/pyload/core/utils/fs.py:276 |
| P1-K-0466 | sink | 0.45 | src/pyload/core/utils/fs.py:285 |
| P1-K-0467 | summary | 0.5 | src/pyload/core/utils/fs.py:290 |
| P1-K-0468 | sink | 0.5 | src/pyload/core/utils/fs.py:315 |
| P1-K-0469 | sink | 0.5 | src/pyload/core/utils/fs.py:315 |
| P1-K-0471 | summary | 0.5 | src/pyload/core/utils/fs.py:321 |
| P1-K-0473 | sink | 0.45 | src/pyload/core/utils/fs.py:332 |
| P1-K-0475 | sink | 0.45 | src/pyload/core/utils/fs.py:341 |
| P1-K-0479 | sink | 0.45 | src/pyload/core/utils/fs.py:349 |
| P1-K-0480 | sink | 0.45 | src/pyload/core/utils/fs.py:352 |
| P1-K-0481 | sink | 0.5 | src/pyload/core/utils/fs.py:355 |
| P1-K-0482 | sink | 0.5 | src/pyload/core/utils/fs.py:356 |
| P1-K-0483 | sink | 0.5 | src/pyload/core/utils/fs.py:358 |
| P1-K-0485 | sink | 0.45 | src/pyload/core/utils/fs.py:362 |
| P1-K-0486 | sink | 0.5 | src/pyload/core/utils/fs.py:363 |
| P1-K-0487 | summary | 0.5 | src/pyload/core/utils/fs.py:369 |
| P1-K-0488 | summary | 0.5 | src/pyload/core/utils/fs.py:375 |
| P1-K-0492 | summary | 0.5 | src/pyload/plugins/helpers.py:218 |
| P1-K-0493 | sink | 0.5 | src/pyload/plugins/helpers.py:231 |
| P1-K-0495 | sink | 0.45 | src/pyload/plugins/helpers.py:248 |
| P1-K-0496 | summary | 0.5 | src/pyload/plugins/helpers.py:250 |
| P1-K-0497 | sink | 0.5 | src/pyload/plugins/helpers.py:252 |
| P1-K-0498 | sink | 0.45 | src/pyload/plugins/helpers.py:341 |
| P1-K-0499 | sink | 0.45 | src/pyload/plugins/helpers.py:341 |
| P1-K-0500 | summary | 0.5 | src/pyload/plugins/helpers.py:349 |
| P1-K-0501 | summary | 0.5 | src/pyload/plugins/helpers.py:356 |
| P1-K-0508 | summary | 0.5 | src/pyload/plugins/helpers.py:598 |
| P1-K-0515 | summary | 0.5 | src/pyload/plugins/helpers.py:626 |
| P1-K-0521 | sink | 0.5 | src/pyload/plugins/helpers.py:656 |
| P1-K-0526 | sink | 0.45 | src/pyload/core/network/http/http_chunk.py:69 |
| P1-K-0528 | sink | 0.45 | src/pyload/core/network/http/http_chunk.py:100 |
| P1-K-0531 | sink | 0.5 | src/pyload/core/network/http/http_chunk.py:186 |
| P1-K-0541 | sink | 0.5 | src/pyload/core/network/http/http_download.py:267 |
| P1-K-0542 | summary | 0.5 | src/pyload/core/network/http/http_request.py:54 |
| P1-K-0543 | sink | 0.45 | src/pyload/core/network/http/http_request.py:58 |
| P1-K-0546 | sink | 0.5 | src/pyload/core/network/http/http_request.py:255 |
| P1-K-0562 | summary | 0.5 | src/pyload/plugins/base/ocr.py:103 |
| P1-K-0563 | summary | 0.5 | src/pyload/plugins/base/ocr.py:104 |
| P1-K-0566 | summary | 0.5 | src/pyload/plugins/base/ocr.py:129 |
| P1-K-0595 | sink | 0.5 | src/pyload/core/config/parser.py:128 |
| P1-K-0596 | sink | 0.5 | src/pyload/core/config/parser.py:239 |
| P1-K-0598 | summary | 0.5 | src/pyload/core/config/parser.py:306 |
| P1-K-0601 | summary | 0.5 | src/pyload/plugins/base/plugin.py:123 |
| P1-K-0602 | summary | 0.5 | src/pyload/plugins/base/plugin.py:118 |
| P1-K-0604 | sink | 0.45 | src/pyload/plugins/base/plugin.py:134 |
| P1-K-0608 | sink | 0.5 | src/pyload/plugins/base/plugin.py:327 |
| P1-K-0636 | sink | 0.45 | src/pyload/core/network/xdcc/request.py:95 |
| P1-K-0638 | sink | 0.5 | src/pyload/core/network/xdcc/request.py:99 |
| P1-K-0647 | sink | 0.5 | src/pyload/plugins/base/simple_downloader.py:316 |
| P1-K-0648 | sink | 0.5 | src/pyload/plugins/base/simple_downloader.py:320 |

## Batch inventory

| batch | input rows |
| --- | --- |
| pass1-k1 | 123 |
| pass1-k2 | 140 |
| pass1-k3 | 356 |
| pass1-k4 | 44 |
| pass1-s1 | 75 |
| pass1-s2 | 12 |
| pass1-s3 | 17 |
