# Pass 3 (SSRF / CWE-918) Label Statistics — label-studio

- **Run**: `label-studio-pass3-ssrf-20261020` (Augur Phase 1, Step 3 — LLM API Candidate Labeling, Pass 3)
- **Generated**: 2026-10-20
- **LLM model**: `glm-5.3` (single model; decisions made per candidate after line-by-line verification of the CodeQL DB source snapshot)
- **Language / framework**: Python / Django + Django REST Framework
- **Scope**: Pass 3 only — CWE-918 (primary), CWE-099, CWE-610 (advisory), per `iris/exploration/detection.json` `scope.passes=[3]`

## 1. Input coverage

| Input | Rows | Labeled | Excluded | Notes |
| --- | --- | --- | --- | --- |
| `extraction/sources.csv` | 283 | 283 | 0 | every row labeled individually |
| `extraction/sinks.csv` | 9 | 9 | 0 | every row labeled individually |
| **Total CSV candidates** | **292** | **292 (100%)** | **0** | |
| Supplementary entries (not in CSV) | — | 2 | — | sanitizers `validate_upload_url` / `validate_ip` (core/utils/io.py) — extraction emitted no sanitizer candidates; added for pass usability, marked as supplementary in each rationale |
| **Total entries in `labels.json`** | | **294** | | unique ids `p3-src-001…283`, `p3-snk-001…009`, `p3-supp-001/002` |

**Dedup audit**: no rows removed. Two pairs of same-line CSV rows are distinct AST nodes on the same line and were both retained (documented, not deduplicated):
- `label_studio/core/utils/common.py:155` — `request.GET` ×2 (two attribute reads in `request.GET.get('page_size', request.GET.get('length', …))`)
- `label_studio/server.py:414` — `get_env` ×2 (`get_env('USERNAME')` and `get_env('PASSWORD')` on one line)

## 2. Batches

| Batch | Description | Size |
| --- | --- | --- |
| B1 | SSRF-core sinks + supplementary sanitizers (core/utils/io.py, webhooks, ml, io_storages, core utils) | 11 |
| B2 | SSRF-core source candidates: import / webhook / ML / storage modules incl. DB-field and param sources | 57 |
| B3 | Web-entry request-field candidates in remaining view/serializer modules (no demonstrated URL→network flow) | 89 |
| B4 | Environment / CLI boundary candidates (`get_env` / `os.environ.get` / `os.getenv` / `sys.argv`) | 137 |

All 292 candidates received a definitive group decision; no re-ask round was needed (no entry left `unknown`).

## 3. Label distribution

### 3.1 By role (294 entries)

| Role | Count | Share |
| --- | --- | --- |
| source | 143 | 48.6% |
| none | 140 | 47.6% |
| sink | 9 | 3.1% |
| sanitizer | 2 | 0.7% |
| summary | 0 | 0% |

### 3.2 By role × classification

| Role | tp | candidate | fp | unknown |
| --- | --- | --- | --- | --- |
| source | 14 | 129 | 0 | 0 |
| sink | 5 | 1 | 3 | 0 |
| sanitizer | 0 | 2 | 0 | 0 |
| none | 0 | 0 | 140 | 0 |
| **total** | **19** | **132** | **143** | **0** |

### 3.3 Confidence buckets

| Bucket | Count | Population |
| --- | --- | --- |
| ≥ 0.90 | 138 | env/CLI `none`/fp (dense, 0.90), fixed-URL sinks (0.90), webhook.url + import URL (0.90–0.95) |
| 0.80–0.89 | 15 | ML flow sources, ML/S3 sinks, async import URL sources |
| 0.70–0.79 | 6 | storage-validate request.data, ML get_versions, S3 resource sink, webhook.headers, s3_endpoint:186 |
| 0.60–0.69 | 5 | redis host/port candidates, s3_endpoint cache-key none, ML `__str__` none, tasks_from_url param none |
| 0.50–0.59 | 130 | B3 view-field source candidates (recall-preserving), redis guards, supplementary sanitizers |

## 4. Key confirmed entries (role=…, classification=tp)

**Sinks (5 tp)**
| Location | Callable | Conf | Why |
| --- | --- | --- | --- |
| core/utils/io.py:224 | `requests.get` (arg 0, inside `ssrf_safe_get`) | 0.95 | import-by-URL fetch; scheme check always on, private-IP block default-off (`SSRF_PROTECTION_ENABLED=False`) |
| webhooks/utils.py:52 | `requests.post` (arg 0) | 0.90 | webhook delivery to org-member-writable `Webhook.url`; no delivery-side SSRF validation |
| ml/api_connector.py:81 | `requests.Session.request` (arg 1, keyword `url=`) | 0.80 | transport for all ML-backend traffic; URL = `MLBackend.url` (API-writable) + fixed suffix |
| io_storages/s3/utils.py:38 | `boto3.Session.client` (kwargs `endpoint_url`) | 0.70 | S3 endpoint from API-writable `s3_endpoint` field |
| io_storages/s3/utils.py:39 | `boto3.Session.resource` (kwargs `endpoint_url`) | 0.65 | same endpoint via resource API |

**Sinks (3 fp, 1 candidate)**: `requests.get` windows_sqlite_fix:28 (operator env URL, 0.85 fp), `requests.get` common.py:376 (hardcoded pypi.org, 0.90 fp), `requests.post` contextlog.py:312 (fixed tele.labelstud.io, 0.90 fp), `redis.StrictRedis` redis/models.py:56 (non-HTTP, 0.55 candidate).

**Sources (14 tp)**: `request.data` uploader.py:239 (0.95, import URL); `request.data` data_import/api.py:280/282 (0.85, async import URL); `request.data` io_storages/api.py:142/150 (0.70/0.75, storage config entry); `webhook.url` webhooks/utils.py:53 (0.90), `webhook.headers` :54 (0.75); `MLBackendSerializer.validate_url.value` ml/serializers.py:10 (0.85); `MLBackend.self.url` ml/models.py:115/118/122 (0.85), :325 (0.80); `S3Storage.self.s3_endpoint` s3/models.py:66 (0.80), :186 (0.75).

**Sanitizers (2 supplementary candidates)**: `validate_upload_url` (io.py:172, 0.55), `validate_ip` (io.py:199, 0.50) — conditional (default-off) private-IP blocking; the http/https scheme check is unconditional.

## 5. Exclusion / deduplication record

- 0 candidates excluded; every CSV row is present in `labels.json` with its original location.
- 0 rows deduplicated (the two same-line pairs above are distinct AST nodes).
- 2 entries added beyond the CSV (sanitizers, see §1) — reasons recorded in each rationale and in `labels.json` metadata notes.

## 6. Important provenance note (affects all line numbers)

The extraction CSVs' line numbers correspond to the **CodeQL DB's own source snapshot** (`label-studio-db/src.zip`, db sha `f8b2fb8`, CLI 2.25.1, created 2026-05-29), which was extracted read-only for verification. The on-disk `label_studio/` tree in the source root is a **different variant** of the project (e.g. on-disk `data_import/uploader.py` fetches via `urlopen` with `ssl.CERT_NONE` and `url_is_local`; the DB variant fetches via `ssrf_safe_get`/`requests.get` with `validate_upload_url`; on-disk `webhooks/utils.py` posts at line 24 vs line 52 in the DB). Labels and locations follow the DB snapshot because that is what the Phase 2 taint queries will analyze. `exploration/detection.json` describes the on-disk variant and is partially superseded — see `phase1_review.md` §6.

## 7. Schema compliance note

`labels.json` conforms to `assets/labels_schema.json` (draft 2020-12). The schema's `passes` array contains a `contains` constraint requiring a pass with `pass_id == 1`; since this run labels Pass 3 only, an **explicitly-empty, clearly-annotated Pass 1 placeholder block** was included solely to satisfy that constraint. No Pass 1 labeling was performed.
