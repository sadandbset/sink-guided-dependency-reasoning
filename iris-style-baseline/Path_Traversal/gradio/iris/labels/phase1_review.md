# Phase 1 Review — Pass 1 (Path Traversal) LLM Candidate Labels

**Run:** `gradio-pathtraversal-pass1-20261022` · **Model:** glm-5.3 (in-session LLM API labeling) · **Date:** 2026-10-22
**Artifacts:** `labels/labels.json` (schema-valid against `assets/labels_schema.json`), `labels/labels_raw_pass1.json` (5 batches × per-candidate decisions), `labels/label_stats.md`.
**Independence note:** labels were produced only from the real sources in `gradio_vuln` plus the Augur references (`patterns.md`, `python.md`, `flask.md`); no PyVul ground truth, patch diffs, or CVE advisories were consulted. The repo-local `VULNERABILITY_AUDIT_REPORT.md` / `优先级策略漏洞审查报告.md` were deliberately not read.

This is the human review-gate payload for Step 3. Phase 2 (library generation, taint queries) has **not** been started.

## 1. Review focus 1 — which sources are genuinely untrusted

Confirmed request/URL boundaries (labeled `source`/tp):

- `file(path)` — URL `<path:path>` variable of `/file` (networking.py:379) **S64, 0.90**
- `static_resource(path)` — URL variable of `/static` (networking.py:139) **S62, 0.90**
- `request.json` reads in predict/flag/interpret/queue_push (networking.py:192, 358, 368, 394, 395) **S54–S58**
- `Interface.process` / `Interface.interpret` raw request lists (interface.py:363, 377) **S46/S47** — internal *form* parameters, but they are the verified dispatch targets of the request payloads above, so they are boundaries, not merely internal helpers
- Component `preprocess(x)` overrides — verified dispatch targets of `process`/`interpret` (interface.py:369-370, 384-386); File/Video/Audio variants consume the client `name` field as a **filesystem path** (**S43, S45, S33, S42 @ 0.90–0.95**)
- `flag_data(input_data, output_data, ...)` — fed directly from `/api/flag` request JSON (networking.py:358-360) **S48–S51**
- `queue.push(input_data, ...)` — second-order: sqlite queue → local re-post → `/api/predict` (networking.py:408-416) **S52/S53**

Rejected as non-boundaries / non-path (labeled `none`/fp):

- `request.form.get("username"/"password")` — auth comparison only (networking.py:153-160) **S60/S61**
- `request.json["hash"]` (queue_status) — sqlite lookup key only **S59**
- `enable_sharing(path)` — URL variable stored into `config["share_url"]`, never touches the filesystem **S63**
- `restore_flagged(data)` × 10 — log.csv cell content re-serialized into config; second-order file-derived data but never used as a path **S20–S29**
- `save_flagged` overrides that only `json.dumps` (Label, Dataframe, CheckboxGroup, Timeseries, KeyValues, HighlightedText, JSON, Carousel) **S01, S02, S07–S09, S14–S19**

## 2. Review focus 2 — path handling chains, step by step (as verified in code)

### 2.1 `/file/<path:path>` (networking.py:377-388) — the primary review item

```
route var path  →  path = secure_filename(path)          # networking.py:380
                →  branch A (encrypt + examples prefix): open(os.path.join(app.cwd, path), "rb")   # :382
                →  branch B: send_file(os.path.join(app.cwd, path))                               # :388
```

- `secure_filename` is **not imported** in gradio/networking.py — the only werkzeug import is `safe_join` from `werkzeug.security` (line 30); `secure_filename` lives in `werkzeug.utils` and is imported nowhere in the module.
- **As written, the handler raises `NameError` at line 380 for every request** — the file access at :382/:388 never executes in CPython as-is. This is a broken-intended-sanitizer situation, not a working barrier.
- Labels: source **S64 tp 0.90**, sinks **K35 tp 0.90** (open :382) and **K44 tp 0.90** (send_file :388). Rationales explicitly record that `secure_filename` must not be modeled as a barrier.
- **Human decision needed:** whether to treat the route as vulnerable (import-fixed code paths / any environment where the name resolves) or as dead code. The branch-A `path.startswith(app.interface.examples)` prefix check (:381) only gates the encrypted branch; branch B has no check at all.

### 2.2 `/static/<path:path>` (networking.py:138-143) — sanitized

`path` → `safe_join(STATIC_PATH_LIB, path)` → `send_file`. Werkzeug `safe_join` is a genuine containment check (raises NotFound on traversal/absolute escape). Source **S62 tp 0.90**, sink **K42 tp 0.85** with the barrier documented; Phase 2 filtering should mark flows through `safe_join` as sanitized.

### 2.3 `is_example` arbitrary file read (predict request → File/Video/Audio preprocess)

```
request.json["data"]  → Interface.process → File.preprocess(x) → process_single_file(f)
  f["name"] (client string), f.get("is_example") (client-settable flag)  # inputs.py:1172
  is_example & type="bytes"  → open(file_name, "rb")                     # inputs.py:1180  (K41)
  is_example & type="file"   → create_tmp_copy_of_file(file_name) → shutil.copy2(file_path, ...)  # processing_utils.py:168  (K47)
  Video:917 / Audio:1001     → create_tmp_copy_of_file(file_name)
```

The client fully controls the path string (`f["name"]`) and the branch selector (`is_example`). This is a complete untrusted-source → dangerous-path-argument flow. Labels: **S43/S45/S33/S42 (0.90–0.95), S54/S46 (0.90), K41/K47 (0.95)**. Note the extracted data is returned into the prediction/response pipeline — confidentiality impact, not just availability.

### 2.4 Flagging flow → tempfile prefix/suffix injection edge

```
/api/flag or /api/predict (auto) request JSON
  → flag_data → component.save_flagged(dir, label, data, key)
  → Component.save_flagged_file → decode_base64_to_file(data, key)      # file_path=None  (component.py:51)
  → decode_base64_to_binary: extension parsed from client data-URI header, no separator filtering
                                                                       # processing_utils.py:124-135
  → tempfile.NamedTemporaryFile(prefix=prefix, suffix="."+extension)    # processing_utils.py:149,151  (K03/K04)
```

- In the **flagging flow** (`file_path=None`), prefix and suffix derive from the client data-URI header; a suffix containing path separators is not filtered and can redirect the `O_EXCL` file creation outside the temp dir (random body and `O_EXCL` constrain but do not canonicalize the joined path).
- In the **preprocess flow** (`file_path=f["name"]`), prefix/extension pass through `os.path.basename` (processing_utils.py:141-145), which strips separators — the same injection is neutralized there.
- Contrast: `create_tmp_copy_of_file` (processing_utils.py:158-167) always basename-filters → **K05/K06 tp 0.65** (filename influenced, traversal blocked).
- Related edge: the extension also propagates into `save_flagged_file`'s `new_file_name` and hence the `shutil.move` destination (**K25 candidate 0.55**).

**Human decision needed:** whether the suffix-injection edge is accepted as a pass-1 sink family (K03/K04 @ 0.80) or downgraded.

### 2.5 Sink candidates that are NOT dangerous file accesses (labeled `none`/fp)

Verified non-sinks: `PIL_image.save`/`plt.savefig`/`send_file` on **BytesIO** (processing_utils.py:63, 71; networking.py:386); `open()` on fixed constants (`VERSION_FILE` networking.py:44; `JSON_PATH` interface.py:717/720/725; `DB_FILE` queue.py:24/46; `log_fp` networking.py:321/334/339/345/348/350 — `flag_path` is never passed by any caller); `tempfile.NamedTemporaryFile` with literal/absent prefix/suffix (external.py:26, outputs.py:429, inputs.py:741/767/1031/1066/1075/1100); `os.listdir`/`os.makedirs` on developer-config or charset-filtered label paths (component.py:56/58, interface.py:304/217); `PIL Image.save` to tempfile names (inputs.py:743/769); `shutil.copy2` destination = tempfile name; `request.form` login fields.

## 3. Review focus 5–7 — guards, sanitizers, symlinks

| Guard | Location | Verdict |
| --- | --- | --- |
| `secure_filename(path)` | networking.py:380 | **not a sanitizer here** — unresolved name (not imported); would sanitize if imported |
| `safe_join(STATIC_PATH_LIB, path)` | networking.py:143 | **effective** containment barrier (werkzeug) |
| `path.startswith(app.interface.examples)` | networking.py:381 | prefix check gating only the encrypted branch of `/file`; string-prefix checks are bypassable in general (no canonicalization), but branch B is unchecked anyway |
| `os.path.basename` | processing_utils.py:141-145, 159-163 | effective for prefix/extension in the `file_path` paths; **not applied** to the mime-header extension (flagging flow) |
| label charset filter (`alnum` + `._- `) | component.py:52 | effective — excludes `/` and `\`; label is developer-configured anyway |
| `os.path.exists` checks | networking.py:281, interface.py:159/297/301, component.py:55, queue.py:23/45 | existence validation only; TOCTOU-adjacent, not barriers |
| symlink policy | — | **not applicable** — no `os.path.islink`, `realpath`, or `Path.resolve()` anywhere in the `gradio/` package; `pathlib.Path` is imported (inputs.py:17) but unused (dead import). No normalize→check→use ordering issues were found beyond those above |

## 4. Review focus 8–10 — intended functionality, tests, completeness

- **Intended file service:** `/static` and `/file` are the app's file-serving routes. `/static` is constrained by `safe_join` to the packaged template directory — normal app functionality. `/file` serving under `app.cwd` (the process working directory) with no working containment check is **not** a normal "user picks an authorized file" feature — nothing in the frontend contract restricts `path`.
- **Flagging save/restore** is the intended persistence feature: destination paths are server-generated; only the content is client data (plus the tempfile-suffix edge in §2.4).
- **Tests / fixed constants / generated files:** the extraction scope already excluded `test/`, `demo/`, `website/`, `setup.py`, and the `gradio-db` CodeQL database directory (verified in detection.json extraction_policy and the CSV contents — every candidate row is under `gradio/`). No labeled candidate comes from test or generated code.
- **Complete vs. partial flows:** the review classified the `/file` route (S64→K35/K44) and the `is_example` read (S43/S45/S54/S46→K41/K47) as complete untrusted-source→dangerous-path flows. The flagging tempfile-suffix flow (S03–S13/S30/S48/S55→K03/K04) is complete up to the temp-file creation step. The FFmpeg chain (S33/S42→K02) is a partial/local flow: path components are client-influenced but basename-constrained.

## 5. Summary counts (see label_stats.md for full tables)

- 114/114 candidates labeled; 0 duplicates removed; 5 batches (19+25+20 / 25+25), no re-asks.
- Roles: source 39, sink 17, none 58, sanitizer 0, summary 0.
- Classifications: tp 53, fp 58, candidate 3 (S51, K25, K45), unknown 0.
- Pass 1 has ≥ 1 sink (17), satisfying the WORKFLOW.md quality gate.

## 6. Recommended human decisions before Phase 2

1. **`secure_filename` NameError (S64/K35/K44):** accept the `/file` route as a modeled source→sink pair (recommended — the sink position is genuinely request-derived and the guard is provably absent), or reject as dead code. If accepted, do **not** generate a `secure_filename` barrier in `MySanitizers.qll`.
2. **`safe_join`:** no sanitizer candidates exist in the CSVs; recommend adding `safe_join(STATIC_PATH_LIB, ·)` as a barrier signature in Step 4 generation (documented here and in entry K42/S62 evidence) — otherwise `/static` flows will surface as alerts and rely on Phase 2 FP filtering.
3. **tempfile suffix edge (K03/K04):** confirm whether to keep the `NamedTemporaryFile` prefix/suffix positions as pass-1 sinks (recommended) and whether K25 stays candidate.
4. **Scalar `preprocess` sources (S31–S44 @ 0.60):** kept for conservative recall; they cannot reach path sinks inside the package, so they will not produce pass-1 alerts — fine to keep or prune.
5. **Summaries:** none labeled; if Step 5 recall is low, add summary edges for the wrapper list from detection.json (`decode_base64_to_file`, `create_tmp_copy_of_file`, `encode_url_or_file_to_base64`, `audio_from_file`, `audio_to_file`, `save_flagged_file`, `flag_data`).
6. **Unresolved entries:** S51 (`flag_index`), K45 (`getsize` on model-returned path) — confirm or drop.
