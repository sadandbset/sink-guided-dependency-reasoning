# Phase 1 Step 3 Review — LLM Candidate Labeling, Pass 3 (CWE-918 SSRF), GeoNode

**Status:** Step 3 complete. This document is the advisory checkpoint payload (WORKFLOW.md §4.5) for human review
before Phase 2. Per instructions, Phase 2 was NOT started.

- Artifacts: `labels/labels.json` (schema-valid), `labels/labels_raw_pass3.json`, `labels/label_stats.md`,
  deterministic renderer `labels/build_labels_pass3.py`.
- Model: glm-5.3 (Claude Code CLI). Batches: 11. Candidates labeled: 492/492 (413 sources + 79 sinks), 0 skipped.
- Evidence base: direct reading of the GeoNode sources at commit `abd1baf3d709265604010b7b15c8bfcc2a72a252`
  (Django 3.2.21). No PyVul ground truth, CVE descriptions, fix commits, or pre-existing SSRF analysis files in the
  repo root were consulted.

## 1. Label counts by pass and role

See `label_stats.md` for full tables. Summary: source 306 (tp 11 / candidate 38 / fp 257), sink 79
(tp 9 / candidate 24 / fp 46), summary 13, none 94, sanitizer 0.

## 2. Top high-risk sink APIs (tp)

| Sink | Location | Why |
| --- | --- | --- |
| `http_client.request(_url, ...)` | `geonode/proxy/views.py:194` | URL at arg 0 = `request.GET['url']` after normalization-only processing; view reachable without login |
| `action(url=url, ...)` / `session.get(url, ...)` | `geonode/utils.py:1236/1248` | final `requests.Session` dispatch of the central `HttpClient` (`session.verify=False`); funnel for all tp/candidate flows |
| `http_client.request(self.url)` | `geonode/services/serviceprocessors/base.py:81` | `probe()` fetches the user-supplied service URL **during form validation** |
| `requests.get(f"{base_url}api/ows_endpoints/")` | `geonode/services/serviceprocessors/wms.py:284` | `base_url` = scheme://netloc of user-supplied service URL |
| `WebMapService(cleaned_url.geturl())` | `geonode/services/serviceprocessors/wms.py:96/272` | OWSLib GetCapabilities fetch of the user service URL (wrapper sink; I/O inside external lib) |
| `http_client.get(url)` | `geonode/utils.py:1883` | `is_monochromatic_image` fetch of `ResourceBase.thumbnail_url` (user-settable) |
| `smart_open.open(uri=...)` | `geonode/storage/data_retriever.py:115` | server-side fetch of user-supplied file path/URI (upload form `*_file_path`, DRF dataset replace/append/metadata, documents API `file_path`) |

Top candidate (second-order) sinks: harvester session/OWSLib/arcrest fetches of `Harvester.remote_url` /
`HarvestableResource.unique_identifier` / remote-declared `download_url` (harvesting/*), thumbnail `openURL`
(`thumbs/utils.py:421`), `geoserver/helpers.py:1012-1082` describe calls that can carry
`layer.remote_service` GetCapabilities URLs.

## 3. Top source APIs (tp / key candidates)

- **Direct (tp):** `request.GET["url"]` (`proxy/views.py:97`, unauthenticated + CSRF only);
  `CreateServiceForm.url` + `cleaned_data["url"]`/`.get("url")` + `register_service` `request.POST`
  (`services/forms.py:36/55/64`, `services/views.py:60` — @login_required, any authenticated user);
  `request.data["file"]` of `set_thumbnail` (`base/api/views.py:1343/1346`).
- **Second-order DB fields:** `Service.base_url` (tp 0.8), `ResourceBase.thumbnail_url` (tp 0.85),
  `Harvester.remote_url` (candidate 0.7 — also auto-created from user-registered service URLs at
  `serviceprocessors/wms.py:145` / `arcgis.py:129`), `Dataset.ows_url`, `MapLayer.ows_url`, `Link.url`,
  `Document.doc_url` (low-confidence candidates).
- **Propagation summaries (13):** `get_service_handler(base_url)`, `ServiceHandlerBase/WmsServiceHandler/
  GeoNodeServiceHandler/ArcMapServiceHandler/ArcImageServiceHandler.__init__(url)`, `BaseHarvesterWorker.__init__
  (remote_url)`, `ArcgisHarvesterWorker.__init__(remote_url)`, `download_resource_file(url)`,
  `is_monochromatic_image(image_url)`, `get_map(ogc_server_location)`, `getmap(base_url)`, `proxy(url)`.

## 4. Sanitizer list

**Empty** — no candidate is a valid SSRF sanitizer. Partial mitigations found and documented (not labeled as
sanitizers, and none sufficient): the `PROXY_ALLOWED_HOSTS` allow-list (DEBUG bypass + auto-extension via registered
services + string-only host match + redirect-following underneath), `URLValidator`+extension in `set_thumbnail`
(no host restriction), `is_local_static` (local shortcut only). See `label_stats.md` §Sanitizers.

## 5. Answers to the nine review directives

1. **Untrusted boundaries verified.** `/proxy/` (`proxy/urls.py:25`) carries only `@requires_csrf_token` — no login,
   no permission decorator. `register_service` (`services/views.py:56`) is `@login_required` (any authenticated user,
   no admin gate); the server-side fetch happens *inside form validation*. `set_thumbnail` requires
   `IsAuthenticated + UserHasPerms`. DRF harvester writes require admin (`IsAdminOrListOrListOnly`); DRF management-
   command jobs require `IsAdminUser`. Internal function parameters were NOT treated as attacker-controlled — they
   became `summary` entries, not sources.
2. **Inputs that can influence outbound URLs.** (a) `request.GET['url']` directly; (b) `CreateServiceForm.url`
   (direct fetch at validation + persistence into `Service.base_url`/`Harvester.remote_url` re-fetched later);
   (c) `set_thumbnail` `request.data['file']` → `thumbnail_url` → `is_monochromatic_image` fetch; (d) upload
   `*_file_path` / DRF dataset `base_file`/`metadata_file` / documents `file_path` → `smart_open` fetch;
   (e) harvester payloads (admin-only, fp) and service-registration-derived `Harvester.remote_url` (candidate).
   Ordinary metadata/permission/pagination request fields were verified NOT to reach outbound URLs (fp).
3. **Real propagation chains verified end-to-end in code:** form → `get_service_handler` → handler `__init__` →
   `probe()`/OWSLib/arcrest (services cluster); `thumbnail_url` → `is_monochromatic_image` → `http_client.get`;
   `get_map` → `getmap` → `openURL`; `StorageManager` → `DataItemRetriever` → `smart_open.open`; `Harvester` →
   worker sessions. These are the 13 `summary` entries + their sinks.
4. **Dangerous argument positions.** URL is positional argument 0 for all `requests.get/post/put/delete`,
   `HttpClient.request/get/post`, harvester `http_session.<verb>` and OWSLib/arcrest constructor calls — verified
   per site. The three keyword cases (`action(url=...)`, `smart_open.open(uri=...)`, `CatalogueServiceWeb(url=...)`)
   are recorded with `arg_index 0` + rationale note. `urljoin/urlparse/urlsplit/URL.from_text` were never treated as
   sinks (extraction already excluded them; labeling confirms).
5. **Sanitizer sufficiency.** No scheme allow-list, fixed-host whitelist that cannot be extended by users, redirect
   control, or DNS/private-IP restriction exists on any tp path. The proxy allow-list is undermined by DEBUG mode,
   user-extendable membership (service registration) and string-only host matching; the underlying `requests` session
   follows redirects (only the initial host is checked) and sets `verify=False`.
6. **Auth ≠ sanitizer.** Login/permission gates are recorded as reachability facts in rationales, never as
   sanitizers; `URLValidator`/extension checks are explicitly documented as not host-restricting.
7. **Fixed vs attacker-changeable URLs.** 46 sink sites with settings/CLI/admin-config URL bases
   (`OGC_SERVER LOCATION`, `SITEURL`, `SOCIALACCOUNT_PROVIDERS`, `CATALOGUE`, monitoring config, br/geofence/security
   CLI flows) are labeled `fp` with the provenance in the rationale; 9 tp + 24 candidate sinks carry user-influenced
   or second-order URLs.
8. **file:/data: not merged.** `URLValidator` (set_thumbnail) rejects such schemes; `smart_open` non-http URI
   support (s3://, local paths) is recorded in the entry rationale as a separate cross-protocol/local-file-read
   concern (relevant to path-traversal passes, not CWE-918). No CWE-918 verdict relies on file:/data: semantics.
9. **Internal wrapper params → summary.** All 15 extracted param candidates (proxy `url`, handler `__init__(url)`,
   `get_service_handler(base_url)`, `download_resource_file(url)`, `is_monochromatic_image(image_url)`,
   `get_map/getmap`, harvester worker `remote_url`, `geoserver_proxy` path params) were labeled `summary`
   (or source/candidate only where a route exposes them: `geoserver_proxy` path params), never auto-promoted to
   formal vulnerability sources.

## 6. Unresolved / low-confidence items (human attention before Phase 2)

- 27 entries below 0.55 (list in `labels_raw_pass3.json`): the `Document.doc_url` / `Link.url` chain (no server-side
  fetch consumer found — likely CWE-601 material instead), `catalogue/views.py` pycsw env forwarding (fetch happens
  inside external pycsw — needs a Phase 2 summary edge or manual confirmation), `utils.get_headers` header
  forwarding (Pass 10 material), `management_commands_http` admin-gated command jobs (concrete chain to
  `updategeoip --url` → `requests.get`, but admin-only).
- Wrapper sinks (OWSLib / arcrest / smart_open) perform I/O inside external libraries not present in the database;
  Phase 2 needs `MySummaries.qll` edges from the wrapper call sites (already reflected by `summary` entries).
- DRF serializer glue (`request.data` → serializer → model field, e.g. `HarvesterSerializer.remote_url`) may need
  additional summary edges in Phase 2.

## 7. Known limitations

- 257 request-field boundaries are labeled `source/fp`: they are real untrusted boundaries, but their values provably
  do not reach outbound URLs in this snapshot. Phase 2 library generation must use `classification in (tp, candidate)`
  only, otherwise alert volume will explode.
- `labels.json` contains an empty `pass_id: 1` stub block required by the schema's `contains` clause; documented in
  `label_stats.md` §Conformance notes.
- Duplicate extraction rows (Subscript + Attribute at the same location) were kept as mirrored entries, not deduped.

## 8. Suggested Phase 2 entry set

- `MySources.qll`: 11 tp + 38 candidate source entries.
- `MySinks.qll`: 9 tp + 24 candidate sink entries (by signature; fp sites excluded).
- `MySummaries.qll`: 13 summary entries (get_service_handler, handler constructors, download_resource_file,
  is_monochromatic_image, get_map/getmap, harvester worker constructors, proxy url param).
- `MySanitizers.qll`: empty (`none()` fallback) — no valid sanitizer was identified.
