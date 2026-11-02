# Augur Phase 2 — Step 4 Query Generation Notes (Pass 3, CWE-918 SSRF, dtale)

Generated: 2026-10-20 · Model: glm-5.3 (in-session) · Input: reviewed `iris/labels/labels.json` (pass 3, 233 entries) · Target: `dtale_vuln` (git `063423aa`), DB `dtale-db` (creation sha matches) · CodeQL CLI 2.25.1 / `codeql/python-all 7.1.2` (resolves from the local pack cache; same API surface as the validated SSRF/core sibling libraries). **Nothing has been compiled or executed yet** — the generated QLL/query files are written but their first compilation happens at Step 5 execution time.

Artifacts produced (this step, per instruction **no CodeQL execution yet**):

- `iris/libraries/MySources.qll`
- `iris/libraries/MySinks.qll`
- `iris/libraries/MySanitizers.qll`
- `iris/libraries/MySummaries.qll`
- `iris/queries/Pass3_SSRF.ql` (id `py/augur/dtale/pass3-ssrf`, `@kind path-problem`, `@problem.severity error`, `@tags security` + `external/cwe/cwe-918`, pass key `"ssrf"`)

Framework: `DataFlow::ConfigSig` + `TaintTracking::Global<Pass3Config>` + `PathGraph` + `flowPath`, exactly the `assets/taint_query.ql.tmpl` shape. Imports use `libraries.MySources` dotted syntax against `iris/qlpack.yml` (`iris/dtale-cwe918`).

---

## 1. Label ID → QLL predicate mapping

| label id | role/class | site | mapped predicate (module) |
| --- | --- | --- | --- |
| p3-src-0164 | source/tp 0.9 | views.py:3930 `get_str_arg(request, "url")` | `MySources::webUploadQueryArgRead` |
| p3-src-0165 | source/tp 0.9 | views.py:3931 `get_str_arg(request, "proxy")` | `MySources::webUploadQueryArgRead` |
| p3-src-0002/0003/0004 | source/candidate 0.6 | loaders/__init__.py:137/:149/:157 `click.option(...)` (setup_loader_options) | `MySources::cliLoaderOptionValue` |
| p3-src-0013 | source/candidate 0.55 | clickutils.py:91 `click.option(...)` (legacy `loader_options`) | `MySources::cliLoaderOptionValue` |
| p3-sink-0012 | sink/tp 0.95 | clickutils.py:244 `requests.get(path, **req_kwargs)` arg 0 | `MySinks::sinkSite` (arm 1) |
| p3-sink-0016 | sink/candidate 0.6 | datasets.py:40 `requests.get(url)` arg 0 | `MySinks::sinkSite` (arm 2) |
| p3-sup-0001 | none/fp (rejected sanitizer) | clickutils.py:234 `is_url` | `MySanitizers::isBarrier` → `none()` (documented, not modeled) |
| p3-sink-0011 | summary/candidate | clickutils.py:238 `handle_path` | `MySummaries::funnelParamStep` |
| p3-sink-0013/0017/0019 | summary/candidate | csv:28 / excel:28 / json:32 loader wrappers | `MySummaries::kwargsPopStep` |
| p3-sink-0014/0018/0020 | summary/candidate | csv:29 / excel:31 / json:38 `handle_path(...)` call sites | `MySummaries::kwargsPopStep` + standard local arg flow (popped path is argument 0 of the call) |
| p3-sink-0015 | summary/candidate 0.55 | datasets.py:39 `load_zip` | `MySummaries::loadZipParamStep` |

Modeling note (recorded, not a label change): the 4 CLI source labels locate the boundary at the `click.option(...)` constructor rows, but the option **values** materialize as `main(..., **kwargs)`'s `kwargs` parameter (script.py:104-116 — `main` has no named loader parameters). `cliLoaderOptionValue` therefore models that `**kwargs` parameter node as the taint origin. This is the same argv trust boundary the labels describe (rationale: "these values flow find_loader -> loader_func -> handle_path -> requests.get").

All other 217 `none/fp` entries are intentionally not modeled: the 135 remaining `get_*_arg` call sites, `request.args.to_dict()`/`request.json`/`request.form`/`request.files` reads, the 22 script.py bootstrap options, env and config reads, the internal-lifecycle fetches (`views.py:196` kill, `views.py:210` is_up, `app.py:272` reaper — internal instance URLs), the docs demo apps (fixed baseball-reference host) and the 12 `urllib.parse` pure-processing rows.

## 2. Source trust boundaries and propagation basis

- **/web-upload (primary, tp)** — route registered at `dtale/views.py:3921`, handler `web_upload` (:3923). Unauthenticated in the default deployment: `global_state.py:38` `AUTH_SETTINGS = {"active": False, ...}` and `auth.py:40-41` `requires_auth` short-circuits to `f(...)` when inactive (gate installed via `@app.before_request`, app.py:457-458). `url` and `proxy` are read from the query string via `get_str_arg` (:3930-3931) and forwarded as `path=`/`proxy=` keyword arguments to `load_csv`/`load_json`/`load_excel`/`load_parquet` (:3933/:3939/:3945/:3951/:3969). Source node = the call result expression; pinned to file + line + wrapper name + literal parameter name (`"url"`/`"proxy"`), exactly the two reviewed tp rows.
- **CLI loader options (candidate)** — `--csv-path/--csv-proxy/--json-path/--json-proxy/--excel-path/--excel-proxy` (built by `setup_loader_options`, loaders/__init__.py:121-160, from the LOADER_PROPS of csv/json/excel) and `--parquet-path` arrive through `main`'s `**kwargs` and flow `check_loaders(kwargs)` (loaders/__init__.py:167-177) → per-loader `find_loader` → `loader_func(**kwargs)` → `handle_path` → `requests.get`. Trust boundary: the local CLI operator — a weaker attacker model than the web route (reviewed candidate label; expected FP at the filter stage). No internal network-wrapper parameter was promoted to a source (Phase 1 review concern 9).

## 3. Sinks — real network API, dangerous argument index, call sites

`requests.get` is the only HTTP-client API in the tree (requests.post/Session, httpx, aiohttp, `urllib.request.urlopen/urlretrieve` have zero call sites — verified in Phase 1). URL argument is **positional index 0** at both modeled sites:

1. `dtale/cli/clickutils.py:244` — `resp = requests.get(path, **req_kwargs)` inside `handle_path` (def :238). Full attacker URL control from the unauthenticated /web-upload `url` parameter (see §4).
2. `dtale/datasets.py:40` — `response = requests.get(url)` inside `load_zip` (def :39). Reviewed candidate: genuine URL position, but every in-tree caller passes a hardcoded GitHub literal (datasets.py:60/:72/:81) and `/datasets` dispatches fixed dataset names only (views.py:3984 `getattr(datasets, dataset)()`).

The sink predicate is location-pinned (file + line + `requests.get` call shape) rather than a generic `requests.get` signature, because the reviewed labels marked all other `requests.get` sites in the tree as internal-lifecycle / fixed-host / docs-demo false positives. `getSinkAlertMessage()` embeds the reviewed controllability scope in the alert so full-URL control is never mixed with the fixed-literal-caller candidate.

## 4. Scheme, fixed targets, redirects, private addresses, sanitizers

- **Scheme:** `is_url()` (clickutils.py:234-235) is the only check on the funnel path — an `http://`/`https://` prefix test. It blocks `file:`/`data:`/cross-protocol targets but does not restrict host/port/IP/userinfo. Reviewed verdict: **rejected as a sanitizer** (supplemental label p3-sup-0001, none/fp); `MySanitizers::isBarrier` resolves to `none()`.
- **Fixed targets:** `/datasets` dispatch and all `load_zip` callers use hardcoded GitHub literals — sink candidate message states "no attacker control in this tree". The internal lifecycle fetches (kill/is_up/reaper on `build_url(ACTIVE_PORT, ACTIVE_HOST)`) are not modeled as sinks at all.
- **Redirects:** no redirect handling/control exists anywhere on the funnel path — requests defaults follow redirects; not mitigated.
- **Private addresses / DNS:** no IP-range check, no post-DNS-resolution validation exists.
- **Access control:** `auth.requires_auth` is a route gate that is off by default and is not a data-flow sanitizer; not modeled as a barrier (documented in MySanitizers.qll).
- No sanitizer label survived review → zero barriers, per the workflow rule the `isBarrier` predicate still exists and delegates in the query.

## 5. Summary steps and custom propagation edges — source evidence

All three steps are conditional on concrete, verified shapes; none is unconditional:

1. **`kwargsPopStep`** (labels p3-sink-0013/0017/0019, feeding 0014/0018/0020): in the loader wrappers the URL is extracted from the `**kwargs` dict via `kwargs.pop("path")` — `csv_loader.py:29` (inline as handle_path argument 0), `excel_loader.py:29`, `json_loader.py:38`. The step links the `kwargs` receiver node to the pop result, which standard data-flow does not reliably model for `dict.pop` with a literal key. The keyword-argument → `**kwargs` parameter hop at the `load_csv(path=url, proxy=proxy)` call sites relies on CodeQL's built-in star-kwargs modeling (documented reliance, see §6).
2. **`funnelParamStep`** (p3-sink-0011): `handle_path`'s `path` parameter → argument 0 of `requests.get(path, **req_kwargs)` at clickutils.py:244. A direct local edge, deliberately re-encoded as an additional step (belt and braces for the funnel function row).
3. **`loadZipParamStep`** (p3-sink-0015): `load_zip`'s `url` parameter → argument 0 of `requests.get(url)` at datasets.py:40. Currently carries no taint (hardcoded callers); kept per the reviewed candidate label.

**No URL-concatination/`urljoin`/`urlparse` edge is modeled**: the reviewed labels marked all 12 `urllib.parse` rows none/fp, and this tree passes the /web-upload URL through verbatim (no base-URL joining on the tainted path).

## 6. Uncovered APIs, dynamic dispatch, CodeQL limitations

- **Proxy-side flow gap (re-review requested, not silently modeled):** source p3-src-0165 (`proxy`) taints `req_kwargs["proxies"] = dict(http=proxy, https=proxy)` (clickutils.py:240-243) and reaches the `requests.get` **proxies keyword** via the `**req_kwargs` spread — not argument 0. The reviewed sink label (p3-sink-0012) pins argument 0 only, so the proxy flow terminates without a formal alert under the current model. Options: re-review to add a sink entry for the proxies-dict position (clickutils.py:243) or accept that proxy-based request-redirection findings are out of scope for this pass. Recorded here instead of widening the model.
- **Pandas-internal URL fetching:** `pd.read_csv/read_json/read_excel` receive whatever `handle_path` returns, and `pd.read_parquet` receives the raw `/web-upload` parquet `path` **without** `handle_path` (parquet_loader.py:33; web branch views.py:3969). The fetch happens library-internally and is not provable from this tree — not emitted (Phase 1 coverage-gap decision, unchanged).
- **Dynamic dispatch:** `getattr(datasets, dataset)()` (views.py:3984) selects fetch functions by attacker-supplied name, but all selectable functions use fixed URLs — modeled via the candidate sink message, not a source edge. Dynamic custom CLI loaders via `DTALE_CLI_LOADERS` (loaders/__init__.py:108) import arbitrary modules — out of pass scope.
- **CodeQL reliance/limitations:** (a) keyword-argument → `**kwargs` parameter flow (web path) and `**dict`-splat call forwarding (CLI path `loader_func(**kwargs)`) are relied on as built-in modeling — if the CLI candidate path does not fire, that is a known limitation, not a label change; (b) the CLI path additionally traverses a dict comprehension in each `find_loader` closure, another potential flow-loss point; (c) `isBarrier` in the `ConfigSig` API is node-based (no branch-sensitive guard semantics) — irrelevant here since no barrier is modeled; (d) no `API::Node` usage was required: all sinks/steps match syntactic call shapes at label-pinned locations, and every node conversion uses `DataFlow::exprNode`/`DataFlow::parameterNode`.
- **`docs/` demo apps** (embedded_dtale, streamlit scripts): fixed-host fetches outside the dtale package; not modeled (labels none/fp).
- **review_decision.json is absent** from `iris/labels/` — the Phase 1 checkpoint approval was not persisted as an audit artifact. This run proceeds on the reviewed `labels.json` per operator instruction ("经过人工审核的 labels/labels.json"); recommend writing the decision artifact before Phase 2 execution.
- **Diagnostics note:** no separate diagnostics query was needed in this step (the internal-reachability questions were resolved from source). If local reachability of the CLI boundary needs confirmation later, a diagnostics query may be added under `iris/diagnostics/` — its paths must not be counted as formal CWE-918 alerts.

## 7. Reproducibility and independent-evaluation principles

Same principles as the earlier CWE-78 experiments: deterministic rendering from the reviewed labels (predicate ↔ label-id mapping tabled in §1; no ad-hoc signature invention); pass key fixed to `"ssrf"` with no leftover `command_injection` identifiers; no `module` variable name, no non-existent Python AST API, no `API::Node`/`DataFlow::Node` mixing; `matches()` patterns are string literals only; QL variable named for hints avoided where shadowing. No PyVul ground truth, fix commits or CVE locations were consulted — every signature above cites source evidence from the `dtale_vuln` tree (git `063423aa`), and neither the source tree, the database, nor the Phase 1 labels were modified. Execution (Step 5 runs: `codeql database analyze` with `Pass3_SSRF.ql`, sequential, one query at a time against `dtale-db`) is deferred until explicitly requested.
