# Pass 3 (CWE-918 SSRF) Label Statistics — GeoNode

- **Run ID:** `geonode-ssrf-pass3-labeling-20261020`
- **Generated:** 2026-10-20
- **LLM model:** glm-5.3 (agentic labeling via Claude Code CLI; single low-variance pass plus a low-confidence re-verification pass)
- **Labeling batches:** 11 (B1–B10 semantic clusters + B11 low-confidence re-verification; see `labels_raw_pass3.json`)
- **Schema:** `labels.json` validated against `augur-0.3.0/assets/labels_schema.json` with `jsonschema` 4.26.0 — **PASS**
- **Deterministic renderer:** `labels/build_labels_pass3.py` (rerunnable; all semantic decisions encoded after direct source reading)

## Candidate coverage

| Input | Rows |
| --- | --- |
| `extraction/sources.csv` source candidates | 413 |
| `extraction/sinks.csv` sink candidates | 79 |
| **Total candidates labeled** | **492** |
| Unmapped / skipped | 0 |

Every CSV row produced exactly one label entry (`P3-S-0001..0413`, `P3-K-0001..0079`). No candidate was dropped.

## Label distribution — all 492 entries

| Role | Count |
| --- | --- |
| source | 306 |
| sink | 79 |
| summary | 13 |
| sanitizer | 0 |
| none | 94 |

| Classification | Count |
| --- | --- |
| tp | 30 |
| candidate | 65 |
| fp | 397 |
| unknown | 0 |

## Sources (413 entries): role × classification

| Role | tp | candidate | fp |
| --- | --- | --- | --- |
| source (request/form/DB-field boundary) | 11 | 38 | 257 |
| summary (internal propagation wrappers) | 10 | 3 | 0 |
| none (verb discriminators, CLI/config boundaries) | 0 | 0 | 94 |

- `source` + `fp` (257): genuine untrusted request-field boundaries whose values were verified NOT to reach any outbound
  network URL (permission specs, metadata, pagination, filters, ratings, auth tokens). Role keeps the boundary semantics;
  classification marks them pass-3-irrelevant so Phase 2 library generation can exclude them.
- `none` + `fp` (94): `request.method` reads (fixed-vocabulary verb), CLI option reads (`updategeoip --url`,
  `importlayers --host`), and other operator-trusted boundaries.

## Sinks (79 entries): classification

| Classification | Count |
| --- | --- |
| tp (attacker-reachable URL at arg 0) | 9 |
| candidate (second-order / wrapper fetches) | 24 |
| fp (settings/CLI/admin-config URL bases) | 46 |

The 9 **tp sinks**: `proxy/views.py:194` (http_client.request), `utils.py:1236` (action(url=)), `utils.py:1248`
(session.get), `utils.py:1883` (thumbnail fetch), `serviceprocessors/base.py:81` (probe),
`serviceprocessors/wms.py:96/272/284` (registration fetches), `storage/data_retriever.py:115` (smart_open).

## Batch sizes

| Batch | Scope | Entries |
| --- | --- | --- |
| B1 | proxy + geoserver proxy cluster | 48 |
| B2 | service registration cluster | 15 |
| B3 | harvesting cluster | 24 |
| B4 | thumbnail cluster | 11 |
| B5 | storage/upload (smart_open) cluster | 22 |
| B6 | DB URL model fields + CLI boundaries | 11 |
| B7 | operator-config/CLI fetch sites | 46 |
| B8 | bulk request-field sources: auth/middleware/admin | 63 |
| B9 | bulk request-field sources: classic Django views | 182 |
| B10 | bulk request-field sources: DRF/tastypie API layer | 70 |
| B11 | low-confidence (<0.55) re-verification | 27 ids re-examined (no new entries) |

## Phase 2 library input

Entries with `classification` in (`tp`, `candidate`) — 95 total (11 source-tp, 38 source-candidate, 13 summary,
9 sink-tp, 24 sink-candidate) — are the intended input for `MySources.qll` / `MySinks.qll` / `MySummaries.qll`.
All `fp` entries (397) should be excluded from library generation and are retained for audit/filtering only
(e.g. admin-configured URL sinks, per the SSRF false-positive heuristics).

## Sanitizers

**Zero sanitizer entries.** No CSV candidate is a sanitizing API for pass 3. Concrete mitigations found in the code
are documented inside the relevant entries' rationale/evidence instead:

- `proxy/views.py:109-146` `PROXY_ALLOWED_HOSTS` host allow-list (`validate_host(extract_ip_or_domain(...))`) — NOT a
  sufficient barrier: skipped entirely when `settings.DEBUG`; allow-list auto-extended with every registered
  `Service.base_url` host (`:136-138`, any authenticated user can register one) and with OWS-GetCapabilities-shaped
  query hosts (`:120-131`); string-based host comparison with no DNS resolution / private-IP check; redirects are
  followed by the underlying `requests` session, so only the initial URL's host is checked.
- `base/api/views.py:1359-1366` `URLValidator` + image-extension check in `set_thumbnail` — restricts scheme
  (http/https/ftp/ftps) and path suffix, but does NOT restrict the host; not a valid SSRF sanitizer.
- `utils.py:1846` `is_local_static` in `is_monochromatic_image` — only short-circuits local static URLs; no host
  restriction for external URLs.
- `harvesters/base.py:369` basename/`..`-neutralization in `_get_file_name` — sanitizes the *stored file name*, not the
  fetched URL.

## Deduplication / duplicate-row note

The extraction emits separate rows for the same read (Subscript + Attribute at one location). Such duplicates were
NOT removed (each CSV row maps to one entry, mirroring the extraction) but carry identical labels:

- `proxy/views.py:97` (P3-S-0302/0303), `:161` (P3-S-0305/0306), `base/api/views.py:1346` (P3-S-0267/0268),
  `utils.py:413/421/422/441/443` (get_headers pairs), plus various same-line method/GET/POST rows in the view clusters.

## Low-confidence entries (< 0.55)

27 entries (27 ids listed in `labels_raw_pass3.json` → `low_confidence_reverification`): proxy Authorization-header and
body forwarding (0.55/0.5), `utils.get_headers` header-forwarding reads (0.4 ×14), `catalogue/views.py` pycsw env
forwarding (0.5 ×2), `management_commands_http` admin-gated job API (0.5), `Document.doc_url` /
`documents/views.py` doc_url chain (0.45 ×8), `Link.url` (0.5). Each was re-examined against the source and kept as
`candidate` (no verified direct fetch consumer → not promoted; plausible second-order path remains → not demoted).

## Conformance notes

- A `pass_id: 1` stub block with **zero entries** is present in `labels.json` solely to satisfy the schema's `contains`
  clause (the schema requires an array element with `pass_id == 1`); Pass 1 is out of scope for this run. The Augur
  consumer (`scripts/filter_and_report.py::summarize_labels`) iterates passes and does not depend on pass 1.
- `arg_index` is `null` for `field`/`return` flow kinds; for the three keyword-argument sinks (`utils.py:1236`
  `action(url=...)`, `storage/data_retriever.py:115` `smart_open.open(uri=...)`,
  `catalogue/backends/generic.py:56` `CatalogueServiceWeb(url=...)`) `arg_index` is `0` denoting the URL keyword
  argument, as required by the schema (`flow_kind: argument` ⇒ integer `arg_index ≥ 0`).
