# Pass 1 Label Statistics — copyparty (Path Traversal, CWE-22/23/36/73)

- run_id: `copyparty-pass1-20261022`
- generated_at: 2026-10-22T01:04:49+00:00
- model: glm-5.3 (in-session LLM labeling via Claude Code CLI; no external API calls)
- input: sources.csv = 225 rows, sinks.csv = 646 rows (871 total)
- dedup: 769 unique label entries (95 api/ast merges, 7 exact duplicate rows dropped; key = file,line,callable,flowKind,argIndex,receiver)
- batches: 8 (s1–s4 source families, k1–k4 sink families); all rows dispositioned

## Entries by role

| role | count |
| --- | --- |
| source | 195 |
| sink | 183 |
| sanitizer | 19 |
| summary | 209 |
| none | 163 |

## Entries by role × classification

| role | classification | count |
| --- | --- | --- |
| none | fp | 163 |
| sanitizer | candidate | 2 |
| sanitizer | tp | 17 |
| sink | candidate | 24 |
| sink | tp | 159 |
| source | tp | 195 |
| summary | candidate | 13 |
| summary | tp | 196 |

## Candidates by CSV flowKind family (labeled entries)

| family | labeled entries |
| --- | --- |
| bos_open | 2 |
| env | 3 |
| file_open | 39 |
| file_serve | 5 |
| form_field | 6 |
| fs_mkdir | 20 |
| fs_open_wrapper | 6 |
| fs_read_wrapper | 4 |
| fs_rename | 3 |
| fs_scandir | 2 |
| fs_sendfile | 1 |
| fs_stat | 41 |
| fs_unlink | 36 |
| ftp_cwd | 8 |
| ftp_param | 2 |
| http_cookie | 4 |
| http_header | 40 |
| http_path | 72 |
| http_query | 27 |
| http_req | 23 |
| http_url_decode | 8 |
| image_open | 1 |
| internal_file_wrapper | 111 |
| json_body | 5 |
| multipart_gen | 4 |
| path_check | 89 |
| path_join | 87 |
| path_resolve | 38 |
| path_sanitize | 14 |
| smb_param | 10 |
| vfs_canonical | 25 |
| vfs_chk_ap | 4 |
| vfs_get | 29 |

## Confidence distribution

| confidence | entries |
| --- | --- |
| <0.55 | 37 |
| 0.55-0.69 | 162 |
| 0.70-0.84 | 319 |
| >=0.85 | 251 |

## Low-confidence / manual-review entries (confidence < 0.55)

| id | role | conf | location |
| --- | --- | --- | --- |
| P1-K-0022 | sink | 0.5 | copyparty/httpcli.py:1661 |
| P1-K-0049 | sink | 0.5 | copyparty/up2k.py:3493 |
| P1-K-0144 | sink | 0.5 | copyparty/mtag.py:67 |
| P1-K-0146 | sink | 0.5 | copyparty/mtag.py:462 |
| P1-K-0147 | sink | 0.5 | copyparty/mtag.py:482 |
| P1-K-0148 | sink | 0.5 | copyparty/mtag.py:522 |
| P1-K-0149 | sink | 0.5 | copyparty/mtag.py:537 |
| P1-K-0163 | sink | 0.5 | copyparty/sutil.py:45 |
| P1-K-0168 | sink | 0.5 | copyparty/th_cli.py:107 |
| P1-K-0169 | sink | 0.5 | copyparty/th_cli.py:131 |
| P1-K-0170 | sink | 0.5 | copyparty/th_srv.py:206 |
| P1-K-0171 | sink | 0.5 | copyparty/th_srv.py:209 |
| P1-K-0173 | sink | 0.5 | copyparty/th_srv.py:264 |
| P1-K-0174 | sink | 0.5 | copyparty/th_srv.py:287 |
| P1-K-0175 | sink | 0.5 | copyparty/th_srv.py:307 |
| P1-K-0176 | sink | 0.5 | copyparty/th_srv.py:312 |
| P1-K-0177 | sink | 0.5 | copyparty/th_srv.py:590 |
| P1-K-0178 | sink | 0.5 | copyparty/th_srv.py:618 |
| P1-K-0179 | sink | 0.5 | copyparty/th_srv.py:657 |
| P1-K-0180 | sink | 0.5 | copyparty/th_srv.py:692 |
| P1-K-0181 | sink | 0.5 | copyparty/th_srv.py:750 |
| P1-K-0182 | sink | 0.5 | copyparty/th_srv.py:754 |
| P1-K-0315 | sanitizer | 0.5 | copyparty/httpcli.py:333 |
| P1-K-0316 | sanitizer | 0.5 | copyparty/httpcli.py:337 |
| P1-K-0493 | summary | 0.5 | copyparty/mtag.py:459 |
| P1-K-0494 | summary | 0.5 | copyparty/mtag.py:521 |
| P1-K-0509 | summary | 0.5 | copyparty/sutil.py:29 |
| P1-K-0520 | summary | 0.5 | copyparty/th_srv.py:688 |
| P1-K-0521 | summary | 0.5 | copyparty/th_srv.py:699 |
| P1-K-0523 | summary | 0.5 | copyparty/u2idx.py:271 |
| P1-K-0526 | summary | 0.5 | copyparty/up2k.py:880 |
| P1-K-0527 | summary | 0.5 | copyparty/up2k.py:967 |
| P1-K-0528 | summary | 0.5 | copyparty/up2k.py:1230 |
| P1-K-0529 | summary | 0.5 | copyparty/up2k.py:1318 |
| P1-K-0542 | summary | 0.5 | copyparty/up2k.py:3488 |
| P1-K-0544 | summary | 0.5 | copyparty/up2k.py:3632 |
| P1-K-0545 | summary | 0.4 | copyparty/up2k.py:3647 |

## Batch inventory

| batch | scope | input rows |
| --- | --- | --- |
| pass1-s1 | HTTP request line / URL path / URL decode source families | 105 |
| pass1-s2 | HTTP query / header / cookie source families | 72 |
| pass1-s3 | JSON body / multipart form / multipart generator source families | 20 |
| pass1-s4 | FTP / SMB / environment source families | 28 |
| pass1-k1 | Direct file-access sink families (open, bos.open, Image.open, ren_open, yieldfile, tx_file/tx_md) | 57 |
| pass1-k2 | Filesystem operation sink families (stat, checks, unlink, rename, mkdir, sendfile, scandir) | 192 |
| pass1-k3 | Path propagation / sanitization / VFS resolution families (join, resolve, undot/sanitize_fn, canonical, vfs.get, chk_ap) | 286 |
| pass1-k4 | Internal wrapper definition rows (functions containing direct fs operations) | 111 |
