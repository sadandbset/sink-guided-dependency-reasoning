# Pass 1 Label Statistics (Path Traversal - CWE-022/023/036/073)

- Project: opendiamond 10.1.1 (Python; Flask dataretriever + Django scopeserver + Tornado/sockjs blaster + XDR RPC servers)
- Model: glm-5.3 (LLM labeling over the real source tree, 14 batches)
- Generated: 2026-10-22; run_id: `opendiamond-pass1-labeling-20261022`

## Input coverage

| Input | Rows |
| --- | --- |
| sources.csv raw rows | 168 |
| sinks.csv raw rows | 281 |
| **total raw candidate rows** | **449** |

Dedup keys: sources `(file, line, callable, argIndex)`; sinks `(file, line, callable)`. Merged: BinaryExpr/StringLiteral double rows of one route parameter, api/ast double rows of one call site, repeated rows of one call site (74 raw rows merged; no row dropped without a mapping - see labels_raw_pass1.json).

| Unique sites | Count |
| --- | --- |
| source sites | 146 |
| sink sites | 229 |
| **total labeled entries** | **375** |

## Roles (all entries)

| Role | Sources | Sinks | Total |
| --- | --- | --- | --- |
| source | 137 | 0 | 137 |
| sink | 0 | 38 | 38 |
| sanitizer | 0 | 1 | 1 |
| summary | 0 | 70 | 70 |
| none | 9 | 120 | 129 |

## Classifications

| Classification | Sources | Sinks | Total |
| --- | --- | --- | --- |
| tp | 51 | 65 | 116 |
| fp | 91 | 149 | 240 |
| candidate | 4 | 15 | 19 |
| unknown | 0 | 0 | 0 |

## Confidence distribution

| Bucket | Sources | Sinks |
| --- | --- | --- |
| <0.55 | 0 | 0 |
| 0.55-0.79 | 39 | 64 |
| >=0.8 | 107 | 165 |

## Source families (role=source, 137 entries)

- flask route param (incl. <path:...> path-converter): 84 entries
- django view request / form: 27 entries
- XDR RPC params (raw socket): 11 entries
- tornado request body / json.loads: 6 entries
- flask/tornado query param: 4 entries
- sockjs websocket event: 2 entries
- other: 1 entries
- tornado request header: 1 entries
- scope cookie (blaster): 1 entries

## Sink-role entries (38) and dangerous path arg indices

- `send_file` - dataretriever/augment_store.py:165 (fp), confidence 0.85, dangerous path arg index 0
- `open` - dataretriever/augment_store.py:184 (fp), confidence 0.75, dangerous path arg index 0
- `rename` - blobcache.py:71 (candidate), confidence 0.55, dangerous path arg index 0
- `utime` - blobcache.py:83 (candidate), confidence 0.60, dangerous path arg index 0
- `open` - blobcache.py:99 (candidate), confidence 0.75, dangerous path arg index 0
- `link` - blobcache.py:115 (fp), confidence 0.70, dangerous path arg index 1
- `link` - blobcache.py:189 (candidate), confidence 0.60, dangerous path arg index 0
- `copyfile` - blobcache.py:195 (candidate), confidence 0.60, dangerous path arg index 0
- `rename` - blobcache.py:197 (candidate), confidence 0.60, dangerous path arg index 1
- `ZipFile` - blaster/cache.py:50 (fp), confidence 0.70, dangerous path arg index 0
- `rename` - blaster/cache.py:117 (fp), confidence 0.75, dangerous path arg index 0
- `rename` - blaster/cache.py:118 (fp), confidence 0.75, dangerous path arg index 0
- `open` - blaster/cache.py:126 (candidate), confidence 0.75, dangerous path arg index 0
- `rename` - blaster/cache.py:142 (fp), confidence 0.75, dangerous path arg index 0
- `open` - dataretriever/diamond_store.py:48 (fp), confidence 0.75, dangerous path arg index 0
- `open` - dataretriever/diamond_store.py:54 (fp), confidence 0.75, dangerous path arg index 0
- `send_file` - dataretriever/diamond_store.py:137 (tp), confidence 0.98, dangerous path arg index 0
- `open` - server/filter.py:685 (candidate), confidence 0.70, dangerous path arg index 0
- `open` - server/filter.py:702 (candidate), confidence 0.70, dangerous path arg index 0
- `open` - dataretriever/mixer_store.py:83 (fp), confidence 0.70, dangerous path arg index 0
- `open` - dataretriever/mixer_store.py:182 (fp), confidence 0.70, dangerous path arg index 0
- `open` - dataretriever/mixer_store.py:203 (fp), confidence 0.70, dangerous path arg index 0
- `send_file` - dataretriever/mixer_store.py:266 (tp), confidence 0.98, dangerous path arg index 0
- `open` - server/object_.py:293 (tp), confidence 0.88, dangerous path arg index 0
- `open` - server/object_.py:314 (tp), confidence 0.85, dangerous path arg index 0
- `open` - dataretriever/test_store.py:106 (fp), confidence 0.70, dangerous path arg index 0
- `open` - dataretriever/test_store.py:211 (fp), confidence 0.70, dangerous path arg index 0
- `open` - dataretriever/test_store.py:233 (fp), confidence 0.70, dangerous path arg index 0
- `send_file` - dataretriever/test_store.py:296 (tp), confidence 0.98, dangerous path arg index 0
- `open` - dataretriever/util.py:48 (tp), confidence 0.90, dangerous path arg index 0
- `link` - dataretriever/util.py:55 (candidate), confidence 0.65, dangerous path arg index 1
- `open` - dataretriever/util.py:82 (fp), confidence 0.70, dangerous path arg index 0
- `open` - dataretriever/util.py:94 (fp), confidence 0.70, dangerous path arg index 0
- `open` - dataretriever/video_store.py:52 (fp), confidence 0.70, dangerous path arg index 0
- `stat` - dataretriever/video_store.py:104 (candidate), confidence 0.65, dangerous path arg index 0
- `Popen` - dataretriever/video_store.py:136 (tp), confidence 0.88, dangerous path arg index 0
- `Popen` - dataretriever/video_store.py:162 (tp), confidence 0.90, dangerous path arg index 0
- `send_file` - dataretriever/yfcc100m_mysql_store.py:128 (tp), confidence 0.97, dangerous path arg index 0

## Sanitizers

**1 entry.** werkzeug.utils.safe_join (augment_store.py:156) - the only containment guard in the whole dataretriever: rejects absolute paths and any segment escaping the base directory before send_file/open in the augment store. Caveats recorded per-entry: symlinks inside DATAROOT are not resolved; every other store uses a bare os.path.join.

## Batches

| Batch | Scope | Raw rows | Unique sites |
| --- | --- | --- | --- |
| S1 | dataretriever/augment_store.py (Flask 'augment' blueprint) | 15 | 9 |
| S2 | dataretriever/diamond_store.py + gigapan_store.py | 14 | 14 |
| S3 | video_store.py + proxy_store.py + yfcc100m_* stores | 27 | 27 |
| S4 | blaster/handlers.py (Tornado + sockjs JSON Blaster) | 18 | 18 |
| S5 | mixer_store.py + test_store.py (Flask 'cocktail*' blueprints) | 48 | 32 |
| S6 | XDR RPC params (server/search.py, proxy/search.py) + env reads (blobcache, child, config, filter, client) | 19 | 19 |
| S7 | scopeserver Django views (7 apps) | 27 | 27 |
| K1 | filter/__init__.py + helpers.py + bundle.py (filter-side runtime & tooling) | 20 | 19 |
| K2 | blaster/__init__.py, __main__.py, handlers.py, cache.py (JSON Blaster) | 44 | 37 |
| K3 | blobcache.py (BlobCache / ExecutableBlobCache) | 31 | 27 |
| K4 | augment_store.py + diamond_store.py (guarded vs unguarded /obj channels) | 21 | 16 |
| K5 | mixer/test/video/gigapan/yfcc100m_* stores | 49 | 38 |
| K6 | server/child.py, config.py, server/filter.py, server/object_.py, server/server.py | 67 | 49 |
| K7 | scope.py, pyramid.py, proxy/search.py, dataretriever/util.py, test_utils.py, client/util.py | 49 | 43 |
