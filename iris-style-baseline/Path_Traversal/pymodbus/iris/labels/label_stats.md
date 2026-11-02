# Phase 1 Step 3 - Label Statistics (Pass 1: Path Traversal)

- **Run ID**: iris-pymodbus-pathtraversal-pass1-20261023
- **Project**: pymodbus (pymodbus_vuln snapshot, 3.6.0dev; CodeQL DB creation sha 927fa4d4d9ddf1ffaa9a6d83616bc4a279f74555)
- **Language / Framework**: python / aiohttp (secondary: typer, argparse)
- **LLM model**: glm-5.3 (labeling performed in-context by the analysis agent in a Claude Code CLI session; no external LLM API calls, therefore no per-call token/latency stats - see `labels_raw_pass1.json` process block)
- **Batches**: 3 (sizes 12 / 9 / 13), all 34 candidates processed, 0 skipped, 0 re-asks (no entry below the 0.55 confidence threshold; minimum confidence 0.65)

## Candidate accounting

| Input | Rows | Labeled | Skipped |
| --- | --- | --- | --- |
| extraction/sources.csv | 12 | 12 | 0 |
| extraction/sinks.csv | 22 | 22 | 0 |
| **Total** | **34** | **34** | **0** |

## Label counts by role

| Role | Count | Entries |
| --- | --- | --- |
| source | 3 | S05, S06, S07 |
| sink | 8 | K03, K04, K06, K11, K12, K13, K16, K21 |
| sanitizer | 0 | - (no in-code path validation exists anywhere on the static-file flow; see notes) |
| summary | 1 | K10 (os.path.join at http_server.py:262, tainted arg index 1) |
| none | 22 | S01-S04, S08-S12, K01, K02, K05, K07, K08, K09, K14, K15, K17, K18, K19, K20, K22 |

## Label counts by classification

| Classification | Count | Meaning |
| --- | --- | --- |
| tp | 12 | API identification confirmed correct (3 sources + 8 sinks + 1 summary) |
| fp | 22 | candidate rejected: not an untrusted boundary / not a dangerous call site / constant or internal operand / out-of-pass semantics |
| candidate | 0 | - |
| unknown | 0 | - |

## Confidence distribution

- Range: 0.65 - 0.95; mean ≈ 0.79; entries ≥ 0.85: 9; entries < 0.7: 4 (S03, S08, S10, S11, S12, K06, K16, K18, K22 at 0.7 / K21 at 0.65).

## Deduplication

- Exact duplicate CSV rows: 0.
- Same-logical-boundary groups (collapsed at library generation, entries kept for audit):
  - S10/S11/S12 - one argparse CLI boundary (parse_args return + two `args.__dict__` subscript reads in the same loop).
  - S05/S06/S07 - one `request.path` signature at three handler locations (distinct handlers/flows).
  - K01/K02 and K19/K20 - paired certfile/keyfile definition-side params.
- Signature correction: K10 `arg_index` corrected from CSV `argIndex 0` (path_join family convention = base-dir position) to **1**, the attacker-controlled operand position in `os.path.join(self.web_path, page)` (http_server.py:262).

## Main exclusion rationales (full detail in labels.json per entry)

1. **Operator/CLI/constructor config is not an untrusted source** (S01-S04, S08-S12): local operator CLI (`argparse`/typer), library constructor params and public logging-config params have no attacker privilege differential; `json_file`/`modbus_config_path` reads are the operator's own authorized config files. `log_file` is additionally dead config (stored at http_server.py:162, never consumed). `custom_actions_module` feeds `importlib.import_module` (Pass 4 semantics).
2. **Constant-path constructions and internal operands** (K05, K07, K08, K09, K14, K15, K17): fixed web base/template paths, argparse default, `Path.home().joinpath('.pymodhis')`, NamedTemporaryFile-generated temp name - no external input can influence these paths.
3. **Operator TLS / serial communication config** (K01, K02, K18, K19, K20, K22): certfile/keyfile definition-side params and `serial_for_url` device strings are deployment configuration; `load_cert_chain` itself (K21) is kept as a valid file-read sink (tp, 0.65) with no untrusted source able to reach it.

## Sanitizer accounting

No sanitizer entries: the static-file handler path has **no** normpath/abspath/realpath/relative_to/startswith/basename/`'..'`-rejection anywhere in the DB source. The only input filter is the aiohttp route regex `/{tail:[a-z0-9.]*}` (http_server.py:172) - external-library router behavior, not DB code, and its effectiveness could not be confirmed against the actual aiohttp version (aiohttp not in the CodeQL database). Per the labeling rubric ("mark sanitizers only with concrete evidence") it is **not** labeled as a sanitizer; it is recorded as the primary manual-review point in `phase1_review.md`.

## Pass-level coverage check (WORKFLOW 4.4.6)

- Pass 1 has at least one sink (8 sinks) and at least one source (3 sources): satisfied.
- The only request-reachable file flow: `request.path[1:]` (S05, http_server.py:260) → `os.path.join` (K10, :262) → `open` (K11, :264) / `web.FileResponse` (K12, :265).
- Schema validation: labels.json validated against Augur `assets/labels_schema.json` (see phase1_review.md).
