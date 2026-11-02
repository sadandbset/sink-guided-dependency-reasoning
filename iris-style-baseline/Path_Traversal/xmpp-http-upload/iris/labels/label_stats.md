# Label Statistics — Augur Phase 1 Step 3 (Pass 1: Path Traversal)

- **Target**: xmpp-http-upload 0.3.0 (Flask HTTP upload service for Prosody `mod_http_upload_external`; server logic = single module `xhu.py`, 236 lines; plus `setup.py` packaging and `config.example.py`)
- **Pass**: 1 — Path Traversal (CWE-022 / CWE-023 / CWE-036 / CWE-073)
- **Model (real)**: `glm-5.3` — in-session LLM analysis (Augur Step 3 is agent-agnostic; no external LLM API call was made; single deterministic pass per batch, no re-ask needed since every confidence ≥ 0.55)
- **Batches**: 3 (batch 1 = sources.csv rows 1–4; batch 2 = sinks.csv rows 1–14; batch 3 = sinks.csv rows 15–28)
- **Candidates processed**: **32 / 32** (4 source candidates + 28 sink candidates); every CSV row was labeled, none deferred
- **Generated**: 2026-10-23T16:30:25Z (UTC; `labels.json` `metadata.generated_at`)
- **Schema**: `labels.json` validated locally against `augur-0.3.0/assets/labels_schema.json` with `jsonschema` 4.26.0 (format checker on) → **VALID**

## 1. Counts by role

| Role | Count | Entries |
| --- | --- | --- |
| source | 4 | src-001 … src-004 |
| sink | 7 | sink-013, sink-019, sink-020, sink-023, sink-024, sink-026, sink-028 |
| sanitizer | **0** | (deliberate — see §5) |
| summary | 8 | sink-005, sink-008, sink-009, sink-010, sink-011, sink-014, sink-016, sink-021 |
| none | 13 | sink-001 … 004, 006, 007, 012, 015, 017, 018, 022, 025, 027 |
| **total** | **32** | |

## 2. Counts by classification

| Classification | Count | Meaning used |
| --- | --- | --- |
| tp | 19 | the role label is confirmed correct for pass 1 against the real source |
| fp | 13 | candidate rejected for pass 1 (rationale recorded per entry) |
| candidate / unknown | 0 | nothing remained unconfirmable — every candidate was decidable from the source code; residual uncertainties are carried as review points in `phase1_review.md` instead |

## 3. Signature flow kinds (schema enum)

| flow_kind | Count | Rows |
| --- | --- | --- |
| argument | 14 | setup.py wrappers (4), `pathlib.Path` ctors (6), `sanitized_join` call sites (2), Div join (1), `send_file` (1) |
| param | 7 | internal `file_api_def` parameter rows (sanitized_join ×2, get_paths, load_metadata, get_info ×2, write_file) |
| receiver | 7 | `.open` ×3, `.unlink`, `.mkdir`, `.stat`, `.absolute` |
| return | 3 | `flask.request.args.get`, `flask.request.headers.get` ×2 |
| field | 1 | `flask.request.stream` attribute read |

CSV `flow_kind` values → schema enum mapping used: `request_arg`/`request_header` → `return`; `request_stream` → `field`; `route_param`/`file_api_def` → `param`; call/ctor/wrapper rows → `argument`; member calls with argIndex −1 → `receiver`. For the Div row (`xhu.py:43`), `arg_index` 1 = right operand (the attacker path), per the extraction column contract.

## 4. Dangerous path argument indices (sink entries)

| Entry | Sink | Path position |
| --- | --- | --- |
| sink-028 | `flask.send_file(str(data_file))` (xhu.py:228) | **argument 0** |
| sink-013 | `metadata_file.open("r")` (xhu.py:57) | receiver |
| sink-019 | `at.open("xb")` (xhu.py:76) | receiver |
| sink-024 | `metadata_file.open("x")` (xhu.py:144) | receiver |
| sink-026 | `data_file.stat()` (xhu.py:197) | receiver |
| sink-023 | `dest_path.parent.mkdir(...)` (xhu.py:137) | receiver (via stdlib `.parent` property) |
| sink-020 | `at.unlink()` (xhu.py:80) | receiver |

## 5. Sanitizers: none (deliberate)

No candidate is labeled `sanitizer`. The only containment logic in the codebase is `sanitized_join` (xhu.py:42–46):

```python
result = (root / path).absolute()
if not str(result).startswith(str(root) + "/"):
    raise ValueError("resulting path is outside root")
```

- `pathlib.Path.absolute()` performs **no `..` normalization and no symlink resolution** (CPython: “Make the path absolute, without normalization or resolving symlinks” — unlike `resolve()`).
- The Werkzeug `path` converter (`[^/].*?`) always yields a **relative** string, so `(root / path)` is a purely textual join and `str(result)` starts with `str(root) + "/"` for **every** converter-supplied path — the guard is textually satisfied even when the path contains `../` segments.
- The `..` segments are then resolved by the OS at `open`/`stat`/`mkdir`/`send_file` time, escaping the declared `DATA_ROOT`.

The wrapper is therefore labeled `summary` (param 0 → return), not `sanitizer`: marking it a barrier would suppress the genuine traversal flow. **Consequence for Step 6**: the generic “explicit `startswith` guard against base dir → FP” heuristic must not be applied to this target’s findings without checking for normalization.

## 6. Dedup decisions

No two CSV rows are literal duplicates (every row is a distinct AST node), but three signature groups collapse at library-generation time:

1. **`pathlib.Path` ctor (6 CSV rows)** — `:50`/`:51` (tainted operand → `summary`) and `:66`/`:109`/`:194`/`:219` (operator `DATA_ROOT` → `none`). Same signature, context-dependent roles; the emitted `Path(arg0) -> result` summary edge applies globally and is vacuous at the four `DATA_ROOT` sites (nothing taints those arguments). Documented conflict, resolved in favor of recall.
2. **`sanitized_join` (4 CSV rows)** — param 0 (`summary`), param 1 (`none`), call sites `:64`/`:107` (both `summary`) → one `arg0 -> return` edge in `MySummaries.qll`.
3. **`pathlib.Path.open` (3 CSV rows)** — `:57` read, `:76` `xb`, `:144` `x` → one receiver-position sink signature (mode distinct but path position identical).

## 7. Exclusions (role `none`, 13 rows)

| Group | Rows | Rationale |
| --- | --- | --- |
| setup.py packaging literals | sink-001 … 004 | `__file__`-derived / literal `README.rst` paths; install-time script, not externally reachable, no untrusted input; `abspath`/`dirname`/`join` are path wrappers, not file access |
| `DATA_ROOT` base operands | sink-006, 015, 017, 022, 025, 027 | operator-configured `app.config["DATA_ROOT"]` (config.example.py:2); never attacker-controlled |
| `Path.absolute()` (xhu.py:43) | sink-007 | neither a file access nor a normalizer — passes path content through unchanged |
| `load_metadata` param (xhu.py:56) | sink-012 | definition row; the real access is the `.open("r")` at :57 (sink-013); output is metadata content, not a path |
| `write_file` param (xhu.py:75) | sink-018 | definition row; real ops are `.open("xb")` :76 / `.unlink()` :80 (sinks) |

## 8. Source recall gap (extraction-side, verified)

`extraction/sources.csv` contains only the 4 `flask.request.*` rows; `detection.json` predicted 7 (including 3 `route_param` rows). Verified root cause via read-only `codeql query run` diagnostics (CLI 2.25.1; outputs in `iris/diagnostics/`): `flaskRouteHandler` in `sources.ql` casts `Function.getADecorator()` to `Attribute`, but for the parameterized decorators `@app.route("/<path:path>", methods=[...])` (xhu.py:104/:189/:214) `getADecorator()` returns the decorator **Call** node (`instanceof Call` holds, `instanceof Attribute` fails). Verified fix pattern: `dec.(Call).getFunc().(Attribute).getName() = "route"` (matches all four handlers). **Phase 2 must add the three route handler `path` parameters (xhu.py:105/:190/:215) to `MySources.qll`**, otherwise `Pass1_PathTraversal.ql` yields zero alerts despite the sink labels. The 4 CSV source rows do not reach any path sink (see `phase1_review.md` §3).

## 9. Confidence distribution

| Confidence | Entries |
| --- | --- |
| ≥ 0.90 | 13 (src-001/002/003; sink-003/004 at 0.95–0.97; sink-001/002, the four 0.95 setup.py rows; sink-028 at 0.90; the 0.90 `DATA_ROOT` operand rows sink-006/015/017/022/025/027) |
| 0.75–0.89 | 12 (src-004, sink-005/009/010/013/019/024/023 at 0.75–0.85, sink-007/012/018) |
| 0.65–0.74 | 7 (sink-020/026 at 0.65; sink-008/011/014/016/021 at 0.70) |
| < 0.55 (re-ask threshold) | **0** — no batch re-ask was required |

All 32 entries carry `location` (file + line), `role`, `flow_kind`, `arg_index` (the dangerous path position for sinks), input-controllability scope (in each rationale), `confidence`, and `evidence` (code citations).
