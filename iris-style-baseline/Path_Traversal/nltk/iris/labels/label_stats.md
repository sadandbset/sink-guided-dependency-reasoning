# Pass 1 Label Statistics (nltk, Path Traversal)

- run_id: nltk-iris-pass1-step3-20261022
- model: glm-5.3 (Claude Code CLI session, deterministic labeling over verified source evidence)
- generated_at: 2026-10-22T00:00:00Z
- input: extraction/sources.csv (70 rows) + extraction/sinks.csv (269 rows) = 339 candidate rows
- dedup: 2 duplicate rows merged (identical file/line/callable/argIndex/role: downloader.py:287 x2, :328 x2 net_xml_attr AST matches) -> 337 unique entries
- batches: 13 (S1-S6 source batches, K1-K7 sink batches); sizes in labels_raw_pass1.json

## Entries by role (all)

| role | count |
| --- | --- |
| source | 46 |
| sink | 128 |
| sanitizer | 0 |
| summary | 92 |
| none | 71 |

## Entries by classification (all)

| classification | count |
| --- | --- |
| tp | 141 |
| fp | 158 |
| candidate | 38 |
| unknown | 0 |

## Source candidates (70 CSV rows -> 68 entries)

role/classification: none/candidate=2, none/fp=20, source/candidate=6, source/tp=40

CSV source families: archive_entry=5, cli_input=8, env=5, http_request_path=1, lib_api_param=40, net_fetch=3, net_xml_attr=8

Exclusions (role=none): env=5 (operator trust: NLTK_DATA/APPDATA x2, NLTK_DOWNLOAD_URL, STANFORD_SEGMENTER x2), cli_input=8 (interactive operator terminal; :1276/:1284 kept as candidate review points), net_fetch=2 (content-only urlopen returns), archive_entry=4 (index-builder local zips / in-archive member scans), lib_api_param=3 (build_index operator tooling; ZipFilePathPointer entry + join - in-archive member names that never become filesystem paths).

## Sink candidates (269 CSV rows -> 269 entries)

role/classification: none/fp=49, sink/candidate=18, sink/fp=56, sink/tp=54, summary/candidate=12, summary/fp=33, summary/tp=47

CSV sink families: archive_open=4, codecs_open=8, db_open=4, dir_create=5, dir_list=5, dir_walk=6, file_open=63, file_remove=20, gzip_open=8, path_decode=4, path_join=75, path_normalize=13, path_stat=54

Role policy applied to sink families: file_open/codecs_open/gzip_open/archive_open/db_open/dir_create/file_remove/dir_list/dir_walk -> 'sink'; path_join/path_normalize/path_decode -> 'summary' (propagation, not dangerous file access by itself); path_stat -> 'none' (guard reads, no neutralization).

## Confidence distribution

| confidence | count |
| --- | --- |
| 0.5 | 20 |
| 0.6 | 64 |
| 0.7 | 52 |
| 0.8 | 177 |
| 0.9 | 24 |

Classification=candidate entries (manual review points, listed in phase1_review.md): 38.

## Sanitizers

None. Verified: no startswith(base)/relative_to/realpath containment, no '..' rejection, no fixed-name mapping except the wordnet_app.py:119 exact-literal guard (recorded as evidence on the guarded sink entry p1-k wordnet:122, not as a callable sanitizer candidate). MySanitizers.qll will resolve to none() (empty isBarrier fallback per WORKFLOW.md 5.1.3).

## Key confirmed channels (tp, conf >= 0.75)

- p1-s-001 source nltk/corpus/reader/api.py:47 conf=0.80 - CorpusReader
- p1-s-002 source nltk/corpus/reader/api.py:47 conf=0.80 - CorpusReader
- p1-s-003 source nltk/corpus/reader/api.py:159 conf=0.80 - CorpusReader
- p1-s-004 source nltk/corpus/reader/api.py:204 conf=0.85 - CorpusReader
- p1-s-006 source nltk/sem/chat80.py:450 conf=0.80 - sql_query(dbname, query): dbname is resolved through nltk
- p1-s-012 source nltk/data.py:324 conf=0.85 - FileSystemPathPointer(_path): constructor applies only os
- p1-s-013 source nltk/data.py:353 conf=0.90 - FileSystemPathPointer
- p1-s-018 source nltk/data.py:589 conf=0.90 - THE resource-resolution boundary: find(resource_name) -> normalize_resource_name (os
- p1-s-019 source nltk/data.py:704 conf=0.75 - retrieve(resource_url, 
- p1-s-020 source nltk/data.py:704 conf=0.80 - retrieve(
- p1-s-023 source nltk/downloader.py:286 conf=0.85 - xml
- p1-s-024 source nltk/downloader.py:287 conf=0.85 - xml
- p1-s-025 source nltk/downloader.py:288 conf=0.85 - xml
- p1-s-026 source nltk/downloader.py:327 conf=0.85 - xml
- p1-s-027 source nltk/downloader.py:328 conf=0.85 - xml
- p1-s-028 source nltk/downloader.py:330 conf=0.85 - xml
- p1-s-042 source nltk/downloader.py:2239 conf=0.80 - unzip(filename, root): filename is the zip to open (zipfile
- p1-s-043 source nltk/downloader.py:2239 conf=0.80 - unzip(filename, root): root is the extraction destination base; the zip's network-controlled entry names are joined onto it with NO containment (:2281/:2287) - the declared root that entry names can escape (CWE-22)
- p1-s-044 source nltk/downloader.py:2249 conf=0.80 - _unzip_iter(filename, root): filename path of the archive to open (ZipFile :2255); caller/downstream-controlled (the downloaded package path join(download_dir, info
- p1-s-045 source nltk/downloader.py:2249 conf=0.80 - _unzip_iter(filename, root): root is the extraction base; entry names escape it via the unfiltered joins (:2281/:2287) -> mkdir (:2283) / open (:2290)
- p1-s-046 source nltk/downloader.py:2264 conf=0.90 - Entry names of the DOWNLOADED package zip: namelist = zf
- p1-s-062 source nltk/corpus/reader/util.py:131 conf=0.75 - StreamBackedCorpusView(fileid): fileid (str or PathPointer) is used directly for os
- p1-s-068 source nltk/app/wordnet_app.py:98 conf=0.95 - self
- p1-k-081 sink nltk/sem/chat80.py:462 conf=0.80 - sqlite3
- p1-k-110 summary nltk/data.py:257 conf=0.85 - normalize_resource_name: os
- p1-k-116 sink nltk/data.py:345 conf=0.95 - THE central resource read: open(self
- p1-k-118 summary nltk/data.py:354 conf=0.90 - THE pointer join: _path = os
- p1-k-119 sink nltk/data.py:482 conf=0.80 - GzipFileSystemPathPointer
- p1-k-120 sink nltk/data.py:484 conf=0.80 - GzipFileSystemPathPointer
- p1-k-129 summary nltk/data.py:650 conf=0.90 - THE unchecked resource join: p = os
- p1-k-130 summary nltk/data.py:650 conf=0.90 - THE unchecked resource join: p = os
- p1-k-132 summary nltk/data.py:657 conf=0.90 - find() zipfile branch: p = os
- p1-k-133 summary nltk/data.py:657 conf=0.90 - find() zipfile branch: p = os
- p1-k-137 sink nltk/data.py:732 conf=0.80 - retrieve() write target: open(filename, 'wb') where filename is the explicit parameter or URL-derived (:718/:720) - unrestricted write channel (CWE-22)
- p1-k-147 summary nltk/downloader.py:270 conf=0.85 - Package
- p1-k-148 summary nltk/downloader.py:700 conf=0.85 - filepath = os
- p1-k-153 summary nltk/downloader.py:709 conf=0.75 - os
- p1-k-154 summary nltk/downloader.py:709 conf=0.75 - os
- p1-k-155 sink nltk/downloader.py:710 conf=0.75 - os
- p1-k-156 sink nltk/downloader.py:710 conf=0.75 - os
- p1-k-157 sink nltk/downloader.py:718 conf=0.85 - Package download write: open(filepath, 'wb') where filepath = join(download_dir, info
- p1-k-158 summary nltk/downloader.py:740 conf=0.75 - zipdir = os
- p1-k-174 sink nltk/downloader.py:2255 conf=0.80 - zipfile
- p1-k-177 summary nltk/downloader.py:2281 conf=0.90 - zip-slip directory join: dirpath = os
- p1-k-179 sink nltk/downloader.py:2283 conf=0.90 - zip-slip DIRECTORY write: os
- p1-k-180 summary nltk/downloader.py:2287 conf=0.90 - zip-slip file join: filepath = os
- p1-k-181 sink nltk/downloader.py:2290 conf=0.95 - zip-slip WRITE: open(filepath, 'wb') with filepath = join(root, *filename
- p1-k-301 sink nltk/corpus/reader/util.py:218 conf=0.75 - open(self
- p1-k-302 sink nltk/corpus/reader/util.py:221 conf=0.75 - open(self
- p1-k-310 sink nltk/twitter/util.py:91 conf=0.75 - open(self
- p1-k-332 summary nltk/app/wordnet_app.py:99 conf=0.90 - unquote_plus(sp) percent-decode of the HTTP request path (CWE-36 decode step; also used for the SHUTDOWN comparison)
- p1-k-333 summary nltk/app/wordnet_app.py:118 conf=0.90 - usp = unquote_plus(sp) - the request-path decode feeding the isfile (:121) and open (:122); %2e%2e%2f would decode to '
