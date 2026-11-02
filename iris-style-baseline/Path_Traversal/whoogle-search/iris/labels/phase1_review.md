# Phase 1 Step 3 Review — LLM Candidate Labeling — Pass 1 (Path Traversal)

**Project**: whoogle-search 0.8.3 (`whoogle-search_vuln` source tree, CodeQL DB sha 8830615a)
**Pass**: 1 — CWE-22 / CWE-23 / CWE-36 / CWE-73 (Path Traversal)
**Model**: glm-5.3 (inline session LLM, Claude Code CLI; 5 batches, 253 candidate rows → 249 entries; schema-validated OK)
**Artifacts**: `labels/labels.json`, `labels/labels_raw_pass1.json`, `labels/label_stats.md`
**Independence**: no PyVul ground truth, patch diffs, CVE reports, or `path_traversal_sinks.csv` were consulted; labeling is based only on the real source tree and the Augur references (python.md, patterns.md, flask.md, WORKFLOW.md).

---

## 1. The confirmed attack surface (full untrusted→path flow)

The `/config` route (`app/routes.py:416-452`, `@session_required @auth_required`) is the single request-driven filesystem channel, and it is a complete, unvalidated flow:

```
request.args.get('name')                          routes.py:429 (PUT) / :447 (POST)
  -> os.path.join(CONFIG_PATH, name)              routes.py:427-429 / :445-447   [summary step, arg 1 tainted]
  -> open(config_pkl, 'rb') + pickle.load         routes.py:430-431              [sink: arbitrary file READ]
  -> open(join(CONFIG_PATH, name), 'wb') + pickle.dump(request.form.to_dict())  routes.py:442-447  [sink: arbitrary file WRITE]
```

- **Source judgment (Q1)**: `request.args.get('name')` is a genuine untrusted URL-query boundary read (Flask/werkzeug percent-decodes it before the handler). It is not an internal wrapper. Labeled `source`/tp at 0.97 (`src-110`, `src-111`, `src-118`, `src-119`).
- **Sink judgment (Q3)**: both `open()` calls are actual file read/write with the path at argument 0. `os.path.join` itself is **not** labeled a sink (per the rubric, join/`Path(...)`/concat are not dangerous file access by themselves); the two joins carrying the tainted argument are labeled `summary`/tp with arg_index 1 (`snk` entries for routes.py:427/:445).
- **Traversal capability (Q4)**: nothing rejects `..` segments, absolute paths, mixed separators, or Windows drive letters; `os.path.join` semantics let an absolute second argument replace `CONFIG_PATH` entirely. The value is percent-decoded exactly once (werkzeug, framework-level), and no decode/normalize step sits between source and sink, so there is no bypass-scenario ambiguity — the guard simply does not exist. CWE-22/36/73 apply (relative `..` traversal, absolute-path escape from the trusted base, and path-as-name injection outside the intended config container).
- **Guard analysis (Q5/Q6)**: no real containment anywhere in `app/`. `os.path.exists` (routes.py:431) is an existence check — not a sanitizer — and forms a classic **check-then-open TOCTOU** companion of the read sink; this is recorded in the entry rationale and will matter in Phase 2 contextualization. No `normpath`/`resolve`/`basename`/`startswith`/`relative_to`/blacklist exists on this path at all, so no function-name-only sanitizer assumptions were made (Q6: nothing to credit).
- **Auth context (Q8)**: the route is authenticated *only if* `WHOOGLE_USER`/`WHOOGLE_PASS` are set; when unset (default deployment) `auth_required` passes every request (routes.py:64-69). Even for authenticated users, the intended behavior is loading/saving **named config files under CONFIG_PATH** — an unvalidated `name` that escapes the config volume is not an authorized file service, so this is not "intended file access". `CONFIG_DISABLE`/`config_disabled` only guards the PUT/POST branches.

**Verdict**: 2 sink/tp entries (`open` routes.py:430 read, routes.py:445 write) + 2 source/tp entries (`request.args.get('name')` at :429/:447, each with its paired `request.args` attribute row) + 2 summary/tp join steps. This is the finding Phase 2 must surface.

## 2. Second-order / partial flows kept as `candidate` (manual review points)

These are real file APIs whose paths are **not** directly request-controlled; per Q10 they are partial or second-order flows, kept for recall with explicit notes:

| Chain | Entries | Why candidate |
| --- | --- | --- |
| Session-dir maintenance: `os.listdir(SESSION_FILE_DIR)` → `join` (routes.py:94) → `getsize` (:100) → `open`+`pickle.load` (:103) → `os.remove` (:117) | `sink`/candidate 0.6 (open), 0.55 (remove); `summary`/candidate 0.6 (join) | names come from directory contents, not the request; exploitation requires prior file placement in the session dir (e.g. via the /config write primitive). `listdir` itself and `getsize` are `none`/fp (listing a constant dir / size probe). The in-code comment at routes.py:109-113 even documents unrelated files appearing there. |
| `gen_file_hash(path, static_file)` → `open(os.path.join(path, static_file),'rb')` (misc.py:11) | `sink`/candidate 0.6; params `summary`/candidate | real read API on parameter paths, but the only caller (app/__init__.py:156) passes the constant static dir and `os.listdir` results. |
| `gen_bangs_json(bangs_file)` → `open(bangs_file,'w')` (bangs.py:38) | `sink`/candidate 0.55; param `summary`/candidate | real write API on a parameter path; only caller passes the constant `BANG_FILE`. |
| Tor conf: `os.getenv('WHOOGLE_TOR_CONF')` → `isfile` → `open(confloc,'r')` (request.py:45-55) | env `none`/fp 0.75; `open` `sink`/**fp** 0.7 | an env→file-path channel, but env is operator-trust (Q1: not attacker input); flagged as the only env read that actually reaches `open`. |

## 3. Boundary trust decisions (Q1)

- **Untrusted (source/tp)**: all direct Flask request-layer reads — `request.args`/`.get`, `request.form`/`to_dict()`, `request.data`, `request.headers`/`.get`, `request.method`, `request.authorization`, `request.url_root` (Host-derived) — 59 tp entries. Only `name` has current path reachability; the rest are labeled as genuine boundaries with no-path-sink notes (they matter for other passes).
- **Request-derived aliases (source/tp 0.75)**: `g.request_params` / `self.request_params` reads — assigned from `request.args|request.form` in `before_request` (routes.py:140-142) and `Search.__init__` (search.py:61). Phase 2 needs the alias assignment as a `MySummaries` taint step.
- **Semi-trusted (source/candidate 0.55)**: flask `session` subscripts — signed cookie store whose `config` values are written from POST /config `request.form` (routes.py:449) and reloaded via `Config(**session['config'])` (routes.py:155). No session value reaches a file path; kept for recall, flagged for review.
- **Client header/Wsgi-environ on `r` params (source/candidate 0.6)**: `X-Forwarded-*`, `REMOTE_ADDR`, `HTTP_X_FORWARDED_FOR`, `r.full_path` in misc.py — untrusted when ProxyFix is active; URL/IP construction only.
- **Operator trust (none/fp)**: ~55 env rows (`os.getenv`/`os.environ`) incl. the CONFIG_VOLUME base dir — no request value ever flows into env (the only env writes come from the operator CLI at routes.py:624-638) — and 12 CLI rows (`parse_args` + `args.<field>`; no CLI argument is a file path).
- **`url_decode` rows → `summary`/candidate**: `unquote`/`unquote_plus` are taint-preserving decode steps, not boundaries; none of the current sites (routes.py:285/348/383/410, request.py:163, filter.py:634-643) feed file APIs. Marked as summary steps for double-decode bypass recall.
- **`param` rows → `summary`**: internal helpers carrying request-derived values (`Config.from_params(params)`, `Search.__init__(request)`, `Request.__init__(normal_ua, root_path)`, `get_client_ip(r)`, `get_proxy_host_url(r)`) and path-carrying helpers (`gen_file_hash`, `gen_bangs_json`) — all get summary edges; an internal function parameter is never auto-promoted to source (Q1 satisfied).

## 4. Sink-side FP decisions (Q3/Q9)

- `send_file` (routes.py:484/:490): both call sites pass `io.BytesIO` in-memory buffers — **no path argument exists**; `none`/fp 0.9.
- All `app/__init__.py` file rows (51): settings JSONs, whoogle.key, bangs file, makedirs, cache-busting symlink/listdir — operator constants / `__file__`-derived; `none`/fp.
- `os.path.dirname/abspath/splitext`, `pathlib.Path(__file__)` (widgets.py:6): pure path ops on constants — not file access; `none`/fp.
- `os.path.exists/getsize/isfile` probes: `none`/fp (routes.py:431/:100 with TOCTOU notes; constants elsewhere).
- `misc/update-translations.py:39`: dev CLI script, literal f-string components; `none`/fp (Q9).
- Literal-path opens (routes.py:36/144/173, config.py:123, widgets.py:57): `none`/fp.

## 5. Symlinks (Q7)

`os.symlink` appears only at app init for cache-busting build links (`app/__init__.py:157-163`) over internal `os.listdir`-derived names — no symlink creation or following on request-controlled paths. No symlink-following policy exists for the `/config` chain; since no canonicalization happens at all, symlink-based bypass of a (nonexistent) root check is **not applicable** here — the more basic path escape already succeeds. Recorded as N/A.

## 6. Schema and process compliance

- `labels.json` passes the local `augur-0.3.0/assets/labels_schema.json` (jsonschema validation: VALID). Pass ID and field names follow the schema exactly (single pass block, `pass_id: 1`, roles within the enum, `signature.flow_kind` within the enum, `argument` flow kinds carry integer `arg_index`).
- All 253 CSV rows processed; 4 dedups logged with reasons in `labels_raw_pass1.json` (1 exact duplicate source row; 3 cross-CSV param/file_api_def duplicates). Batch/sample counts: B1=98, B2=47, B3=30, B4=17, B5=57.
- Zero `sanitizer` labels (documented: none exist — this is a finding, not a gap) and zero `unknown` labels; all low-confidence entries (0.55) are second-order flows explicitly kept as `candidate` with manual-review notes, above the 0.55 re-ask threshold.
- No source code, CodeQL database, Augur installation, or Phase 1 CSVs were modified. The generator script lives outside `iris/` (workspace root `make_labels.py`); only the four `iris/labels/` artifacts were written.

## 7. Reviewer checklist before Phase 2

1. Confirm the two tp sinks (`open` routes.py:430/:445) and the tainted-join summary steps (arg index 1) render correctly into `MySinks.qll`/`MySummaries.qll`.
2. Decide whether the second-order session-dir chain (routes.py:93-120) should get summary edges in Phase 2 or be filtered at reporting (it is reachable only after a /config write or direct filesystem access).
3. Add the `g.request_params = request.args|request.form` and `Config(**session['config'])` / `from_params` taint steps to `MySummaries.qll` (flagged in detection.json and in the alias/param label rationales).
4. `MySanitizers.qll` will be empty — keep the `isBarrier` predicate with `none()` fallback per WORKFLOW.md §5.2.3.
5. Optional: model Flask's framework-internal `/static/<path:filename>` serving (werkzeug safe_join, outside the DB) as a documented coverage gap, not a labeled candidate.
