# Phase 1 Review — Pass 3 (SSRF / CWE-918), label-studio

Human-review-gate summary (Augur WORKFLOW §4.5, advisory). This step *labels candidates only*; **no vulnerability claim is made here** — confirmation requires the Phase 2 taint queries plus human triage of the resulting paths.

- Run: `label-studio-pass3-ssrf-20261020`, model `glm-5.3`, 4 batches, 292/292 CSV candidates labeled (see `label_stats.md`).
- Artifacts: `labels/labels.json` (schema-valid), `labels/labels_raw_pass3.json` (per-row audit incl. verified source line), `labels/label_stats.md`.

## 1. Label counts (pass 3)

| Role | tp | candidate | fp | unknown | total |
| --- | --- | --- | --- | --- | --- |
| source | 14 | 129 | 0 | 0 | 143 |
| sink | 5 | 1 | 3 | 0 | 9 |
| sanitizer | 0 | 2 | 0 | 0 | 2 |
| none | 0 | 0 | 140 | 0 | 140 |
| summary | 0 | 0 | 0 | 0 | 0 |
| **total** | **19** | **132** | **143** | **0** | **294** (292 CSV + 2 supplementary sanitizers) |

## 2. Top high-risk sink APIs (role=sink, tp)

1. **`requests.get` — label_studio/core/utils/io.py:224** (arg 0, conf 0.95) — inside `ssrf_safe_get()`, the import-by-URL fetch. Real flow: `POST /api/projects/{pk}/import` form field `url` (`data_import/uploader.py:239`, sync path; `data_import/api.py:282` → `ProjectImport.url`, async path) → `load_tasks` → `tasks_from_url` (`uploader.py:131`) → `ssrf_safe_get` → `requests.get(url)`. `validate_upload_url` **always** rejects non-http/https schemes (blocks `file:`/`data:` cross-protocol use), but private-IP blocking and the post-connection peer-IP re-check apply **only when `settings.SSRF_PROTECTION_ENABLED` is True — default False** (`core/settings/base.py:405`). Permission: authenticated user with `projects_change` (project collaborator, not admin) — authentication limits *who* can send the URL, not *what URL* is fetched.
2. **`requests.post` — label_studio/webhooks/utils.py:52** (arg 0, conf 0.90) — webhook delivery `requests.post(webhook.url, headers=webhook.headers, …)`. `Webhook.url` (URLField) and `Webhook.headers` (JSONField) are writable by **any authenticated organization member** via `/api/webhooks` (`WebhookListAPI` permission `IsAuthenticated`); URLField enforces URL *syntax* only. **No scheme allow-list, host, or private-IP validation exists anywhere on the webhook delivery path.**
3. **`requests.Session.request` — label_studio/ml/api_connector.py:81** (URL position, keyword `url=`, conf 0.80) — the single transport for all ML-backend traffic. URL = `urljoin(MLBackend.url, fixed_suffix)`; `MLBackend.url` (TextField) is API-writable via `/api/ml` (`projects_change`); `validate_upload_url` scheme-check is unconditional but local-IP blocking is gated by `ML_BLOCK_LOCAL_IP` (default False, `base.py:601`). Triggered synchronously at backend creation (`ml/serializers.py:18/27` healthcheck/setup) and on every predict/train cycle.
4. **`boto3.Session.client` / `.resource` — label_studio/io_storages/s3/utils.py:38/39** (kwargs `endpoint_url`, conf 0.70/0.65) — S3 endpoint from the API-writable `S3ImportStorage/S3ExportStorage.s3_endpoint` TextField (`/api/storages/s3`, `projects_change`); botocore then issues server-side HTTP against that host.

**Sinks labeled fp (3)**: sqlite.org dll download (operator env URL, Windows startup, `windows_sqlite_fix/__init__.py:28`), hardcoded pypi.org version check (`core/utils/common.py:376`), fixed tele.labelstud.io telemetry (`core/utils/contextlog.py:312` — request data reaches the *payload*, never the destination). **Sink labeled candidate (1)**: `redis.StrictRedis` (`io_storages/redis/models.py:56`) — non-HTTP Redis protocol; server-side TCP connection to attacker-chosen host:port is SSRF-adjacent but kept out of core CWE-918 per protocol distinction; needs human decision.

## 3. Top source APIs

**Confirmed external boundaries (tp)** — the values that demonstrably reach the sinks above:
- `request.data` (`data_import/uploader.py:239`; `data_import/api.py:280/282`) — the import URL itself (permission `projects_change`).
- `webhook.url` / `webhook.headers` field reads (`webhooks/utils.py:53/54`) — DB-mediated: written by one org-member request, consumed by a later event (extraction's DB-field source family).
- `MLBackend.self.url` (`ml/models.py:115/118/122/325`) and `MLBackendSerializer.validate_url.value` (`ml/serializers.py:10`) — ML backend URL entry (framework-dispatched serializer hook, not a mere internal wrapper).
- `S3Storage.self.s3_endpoint` (`io_storages/s3/models.py:66/186`), `request.data` in `StorageValidateAPI` (`io_storages/api.py:142/150` — serializers use `fields='__all__'`, so endpoint fields are directly submittable and `validate_connection()` runs in-request).

**Broad source population (129 candidate)**: all remaining `request.data/GET/POST/query_params/FILES/META/body` reads in DRF/Django view code — genuine authenticated-attacker boundaries, but **no flow from these reads into a server-side network-request URL was demonstrated** in this codebase; labeled `candidate` (conf 0.5–0.55) to preserve recall, expect no alerts from them unless an unexpected path exists.

**Rejected as sources (140 none/fp)**: all `get_env`/`os.environ.get`/`os.getenv` rows (operator env config — incl. `S3_ENDPOINT`, `WINDOWS_SQLITE_BINARY_HOST_PREFIX`, MINIO endpoints, which feed network destinations but are operator-set, per the admin/env-config FP heuristic) and all `sys.argv` rows (CLI operator boundary). Also rejected per the "internal wrapper parameter" rule: `tasks_from_url.url` (`uploader.py:125`, none/fp 0.7 — taint arrives there via normal interprocedural propagation from the real boundary `request.data` at uploader.py:239), `MLBackend.self.url` read at `ml/models.py:97` (`__str__`/logging only), and `s3_endpoint` read at `s3/models.py:57` (cache-key only).

## 4. Sanitizers

- `validate_upload_url` (core/utils/io.py:172, supplementary, candidate, 0.55): **unconditional** http/https scheme rejection (effective against `file:`/`data:`/cross-protocol); **conditional** private-IP blocking gated by `SSRF_PROTECTION_ENABLED` (default **False**) for imports and `ML_BLOCK_LOCAL_IP` (default **False**) for ML backends. Even when enabled it misses IPv6 loopback/ULA, IPv6-mapped IPv4, link-local 169.254.169.254 (cloud metadata), CGNAT 100.64/10, and resolves DNS separately from the fetch (TOCTOU; only partially mitigated by the post-connection peer check in `ssrf_safe_get`, itself default-off).
- `validate_ip` (io.py:199, supplementary, candidate, 0.50): the private-IP subnet check helper — same conditionality and gaps.

**Recommendation for Phase 2**: do *not* model these as an unconditional `isBarrier` — the private-IP component is default-off and incomplete. The scheme component is a genuine always-on barrier against non-HTTP schemes (relevant to CWE-099/610 cross-protocol), which is one reason no `file:`/`data:` flow was labeled: none exists in the DB variant (the on-disk variant's `urlopen` + `CERT_NONE` path is a different codebase state — see §6).

**Not sanitizers** (explicitly checked): Django/DRF authentication & permission checks (limit attacker identity, not URL controllability), URLField format validation (syntax only), `str_to_json` (branch selection, not neutralization), `bool_from_request`/`int_from_request` coercion, HTML/autoescape (irrelevant to network destinations).

## 5. Unresolved / low-confidence items for manual review

1. **Redis storage (non-HTTP)** — `redis.StrictRedis` sink + `self.host/port` sources (candidate 0.5–0.6): server-side TCP connection to API-supplied host:port. Decide whether to include non-HTTP protocols in CWE-918 scope for this project or track separately.
2. **Webhook delivery breadth** — `emit_webhooks*` fire on many annotation events; only `run_webhook_sync` performs the POST. Delivery-side validation absent entirely; also `webhook.headers` gives header control (Pass 10 crossover).
3. **Boto3 kwargs modeling** — `endpoint_url` and redis `host/port` pass through `**kwargs`; positional-argument sink modeling cannot see them (same for the keyword `url=` at `api_connector.py:81`). Phase 2 library generation needs keyword-argument or call-site-level predicates for these five sink entries or the flows will be missed.
4. **`io_storages/api.py:150` (`StorageValidateAPI`) serializer mediation** — DRF serializer internals are outside the DB; the direct `request.data → validate_connection` flow may need a summary/modeling step to be visible to taint tracking.
5. **130 entries at conf 0.5–0.59** (B3 view-field candidates) — expected quiet; spot-check a sample after Pass 3 query run for unexpected hits rather than pre-triaging.

## 6. Corrections to Step 1 exploration output (important for downstream stages)

`exploration/detection.json` was written against the **on-disk** source tree, which is a *different variant* from the code the CodeQL DB (and the extraction CSVs) actually index. Verified against the DB's own `src.zip` snapshot:

| detection.json claim (on-disk variant) | DB snapshot reality (labels follow this) |
| --- | --- |
| import sink = `urlopen(url, context=ctx)` at uploader.py:123 with `CERT_NONE` | import sink = `requests.get(url)` at **core/utils/io.py:224** inside `ssrf_safe_get`; no `urlopen` import exists in the DB variant's uploader.py; SSL verification is default-on (`verify` not disabled) |
| sanitizer = `url_is_local` (io.py:171-192), gated by `SSRF_PROTECTION_ENABLED` | sanitizer = **`validate_upload_url` + `validate_ip`** (io.py:172-217): scheme check **unconditional**, private-IP block gated by `SSRF_PROTECTION_ENABLED` (default False) |
| ML URL validation = `url_is_local` gated by `ML_BLOCK_LOCAL_IP` (ml/serializers.py:10-13) | `validate_upload_url(value, block_local_urls=settings.ML_BLOCK_LOCAL_IP)` (ml/serializers.py:11) |
| webhook POST at webhooks/utils.py:24 | webhook POST at **webhooks/utils.py:52** (`run_webhook_sync`); DB variant has async webhook machinery (`start_job_async_or_sync`) |
| `tasks_from_url(file_upload_ids, project, request, url)` | `tasks_from_url(file_upload_ids, project, user, url, could_be_tasks_list)` — url still index 3 |
| fixed sinks at windows_sqlite_fix:26 / common.py:362 / contextlog.py:177 | same call sites at DB lines 28 / 376 / 312 (all fixed-destination, fp) |

The three genuine user-driven outbound flows identified in Step 1 (import-by-URL, webhook delivery, ML backend) remain valid in the DB variant; the fourth (S3/Redis storage endpoints) is confirmed as API-suppliable endpoints. Also verified: **no `urlopen`/`httpx` call sites exist anywhere in the DB snapshot app code** — all outbound HTTP is `requests.*` + boto3 + redis, so the 9 CSV sink rows cover every app-level network call site (nothing missed; nothing extra to add as sink).

## 7. Coverage & audit

- 292/292 CSV candidates labeled, 0 excluded, 0 deduplicated (two same-line AST-node pairs retained — see `label_stats.md` §1); 2 supplementary sanitizer entries added with recorded reasons.
- Every entry carries source location (DB-snapshot line, matches the CSV), callable, flow kind, dangerous arg index (where applicable), evidence (verified source line + flow chain), and confidence.
- `labels_raw_pass3.json` preserves the raw CSV row, batch id, decision, and the verified source line for every candidate.
- Schema: `labels.json` validates against `augur-0.3.0/assets/labels_schema.json`; the schema's `contains`-constraint on `pass_id == 1` is satisfied by an **explicitly-empty, annotated Pass 1 placeholder** (no Pass 1 labeling was performed in this run).

## 8. Decision requested (gate)

Proceed to Phase 2 (Step 4: generate `MySources/MySinks/MySanitizers/MySummaries.qll` for pass key `ssrf`) with the labels above, giving particular attention to: keyword-argument sink modeling (§5.3), the conditional sanitizers (§4 recommendation), and the manual-review queue (§5). **This run stops here per instruction — Phase 2 is not started.**
