# Augur Phase 1 Step 3 — Human Review Summary (dfetch, Pass 1: Path Traversal)

Run `iris-dfetch-pathtraversal-pass1-20261022` · 2026-10-22 · model `glm-5.3` ·
160/160 candidates labeled (61 sources + 99 sinks) · `labels.json` schema-VALID.
This is the advisory CHECKPOINT artifact for Step 3; Phase 2 has **not** been started.

## 1. Scope and trust model

dfetch 0.5.1 is a manifest-driven dependency-vendoring CLI with **no web surface**. The
attacker-relevant input boundaries are file content and subprocess output, and the labeling
reflects that:

1. **Manifest content** (`dfetch.yaml`): `yaml.safe_load` (manifest.py:139) and the field
   reads (`dst`/`src`/`patch` at project.py:245/246/248, `yamldata[key]` at :268) are labeled
   **source/tp**. The manifest is attacker-influenced in realistic scenarios: child-manifests
   are read out of *fetched* remote trees (`get_childmanifests`, manifest.py:263-280), and
   `dfetch import` writes manifests whose `dst` values are remote-controlled (see 2). The
   pykwalify schema (`dfetch/resources/schema.yaml`) enforces types only — `dst: str unique`,
   `patch: str`, `src: any` — with **no** path-content constraint.
2. **Subprocess output** (the only fully untrusted boundary in the tool):
   `git submodule foreach` stdout `sm_path` (vcs/git.py:229) and `svn propget svn:externals`
   output (svn.py:46) become `ProjectEntry dst` via `dfetch import` (import_.py:158/:180),
   which is then executed by the next `dfetch update`. Labeled **source/tp**.
3. **Metadata file content** (`.dfetch_data.yaml` inside a fetched destination — a malicious
   repo can ship/modify it): `yaml.safe_load` at metadata.py:71 labeled **source/tp** (0.75);
   current consumers only read version/hash, so field-level impact today is low.
4. **CLI / argparse** (23 rows): labeled **none/fp** — the invoking user is the same trust
   domain as the manifest they run against; `references/python.md` scopes its CLI-arg source
   family to *service-mode* tools. `--outfile` is the operator choosing their own output path.

## 2. Confirmed source→sink chains (all steps verified in real code)

| # | Chain | Impact |
| --- | --- | --- |
| C1 | manifest `dst` (project.py:246) → `VCS.local_path` → `Path(dst).mkdir(parents=True)` (project/git.py:70) / `dirname(dst).mkdir` (svn.py:196) | arbitrary directory creation anywhere (absolute or `..` dst) |
| C2 | manifest `dst` → `safe_rm`/`safe_rmtree` (vcs.py:105 → util.py:33/:39) → `shutil.rmtree` | recursive delete of an arbitrary path before fetch |
| C3 | manifest `src` (project.py:245) → `PurePath(src).parts[0]` → `safe_rmtree` (vcs/git.py:170) | **amplifier**: `src: ../x` recursively deletes the parent of the checkout root; absolute `src` deletes its root component |
| C4 | manifest `src` → `os.listdir(src)` → `shutil.move(src+"/"+file, ".")` (vcs/git.py:168-169) | relocation of files from an arbitrary location into the destination |
| C5 | manifest `dst` → `Metadata.path` (`join`/`realpath`, metadata.py:126-134) → `open(...,"w+")` (:165) / `open(...,"r")` (:70) | arbitrary-path overwrite (fixed YAML content) / bounded read |
| C6 | manifest `patch` (project.py:248) → `patch_ng.fromfile` (vcs.py:134) + `patch_set.apply(root=dst)` (vcs.py:138) | arbitrary file read/parse + patch-driven writes under an unvalidated root (archive-extraction-shaped channel) |
| C7 | manifest `dst` → `in_directory` → `os.chdir` (util.py:52) | CWD escape: all subsequent relative writes (git checkout, sparse-checkout, moves) land in the attacker-chosen tree |
| C8 | remote `.gitmodules`/`svn:externals` → `dfetch import` manifest `dst` → C1-C5 on next `update` | remote-controlled `dst` without any local trust decision |
| C9 | manifest `name` → `f"{project.name}.patch"` → `open(...,"w")` (diff.py:171) | out-of-tree patch-file write (`name: ../evil` → `../evil.patch`) |
| C10 | manifest `dst` → `find_non_matching_files` walk → `os.remove` (svn.py:206) | deletion of files under an escaped root |

The dominant unvalidated value is the manifest **`dst`** field: absolute paths, `..`
components and mixed separators all pass validation and every downstream use (CWD scoping via
`chdir` does **not** confine absolute or escaping paths). No URL/percent decoding exists
anywhere in the pipeline, so no multi-decode concerns apply (detection.json `notObserved`).

## 3. Sanitizers — none exist

Zero entries labeled `sanitizer`, verified exhaustively:

- pykwalify validation: type/structure only (no `..`/absolute/charset constraint);
- `os.path.realpath` (metadata.py:129/:132, manifest.py:247/:270): normalization, never
  compared against a base;
- `relative_to` (manifest.py:274): display prefix; raises uncaught `ValueError`
  (`prefix_runtime_exceptions` catches `RuntimeError` only) — loud failure, not sanitization;
- `basename` (metadata.py:131): neutralizes the filename only; the write's directory
  (`dirname(dst)`) remains unguarded;
- no `islink`/`lexists`/`normpath`/`abspath`; every `startswith` is URL/ref matching;
- the single-'*' restriction on `src` (svn.py:227-236) does not block `..` or absolute paths.

Phase 2 must emit `MySanitizers.qll` with the `none()` fallback (mandated by WORKFLOW.md §5.2.3).

## 4. Candidate / unknown items — manual review requested

| ID | Location | Question | Current label |
| --- | --- | --- | --- |
| sink-015 | vcs/git.py:149 `open('.git/info/sparse-checkout','a')` | Path arg is a literal; the *content* is the manifest `src` (`/{src}` patterns) and git materializes files per those patterns after `fetch`/`reset --hard`. Can a crafted sparse-checkout pattern place files outside the work tree? Decided inside git (patch-ng/git internals not in this database). | sink / **candidate** / 0.5 |
| sink-095 | vcs.py:138 `patch_set.apply(0, root=dst, fuzz=True)` | Patch-internal target paths are parsed by patch-ng 1.17.4 (setup.py:35) — are `../`/absolute targets in patch headers rejected or applied relative to `root`? | sink / tp / 0.75 (root= keyword, no positional index) |
| sink-064 | svn.py:243 `run_on_cmdline` | `dst` sits at positional index **6** only because `rev` is always `'--revision <N>'` (svn.py:179-184 enforces a numeric revision); a future `rev=""` call shifts it to 5. Verify before query generation. | sink / tp / 0.8 |
| metadata trust | metadata.py:71 | Is `.dfetch_data.yaml` inside a fetched destination in-scope for your threat model (dfetch overwrites it after a fetch, but a shipped file is read before that)? | source / tp / 0.75 |

## 5. Known gaps to address in Step 4 (query/library generation)

1. **Property getters** are the propagation backbone but are not call sites and were not
   extractable: `ProjectEntry.destination/source/patch` (project.py:331-343), `VCS.local_path`
   (vcs.py:177-180), `Metadata.path` (metadata.py:125-134). `MySummaries.qll` should add
   taint steps for these getters or rely on the labeled `kwargs.get` sources + wrapper-param
   summaries bracketing them.
2. **f-string / concatenation path building** is invisible to AST extraction (detection.json
   `uncoveredCases`): `f"{project.name}.patch"` (diff.py:114), `src + "/" + file`
   (vcs/git.py:169), `toplevel + "/.gitmodules"` (vcs/git.py:270). The consuming sink/summary
   rows anchor these channels.
3. **git-side subprocess writes** (git init/fetch/reset inside `in_directory(local_path)`)
   write files with CWD set by the chdir sink — the writes themselves are Pass 2 material;
   only the svn export passes an explicit Python-built `dst` argument (labeled at svn.py:243).
4. **CWD invisibility**: child-manifest discovery (`find_file` from `.`) runs with CWD =
   `project.destination`; taint through the process CWD cannot be expressed in the query and
   is instead anchored at the `chdir`/`mkdir` sinks.
5. **TOCTOU** windows exist at vcs.py:103-105 (`exists` → `safe_rm`) and vcs.py:117 → :134
   (`exists` → `fromfile`) — evidence only, not separately extractable.

## 6. Review gate status

- All 160 candidates processed in 11 documented batches; 0 duplicates, 0 exclusions.
- Pass 1 has 16 sinks and 11 sources — the "at least one sink" quality bar is met.
- `labels.json` passes local `assets/labels_schema.json` (jsonschema 4.26.0, draft 2020-12,
  format checker).
- One entry below the 0.55 confidence re-ask threshold (`sink-015`), deliberately held at
  `candidate` rather than re-asked, because the open question is external-library behavior
  (git sparse-checkout patterns), not label ambiguity.

**Decision requested from reviewer:** confirm (a) the manifest-as-untrusted trust model
(rows src-022…src-033), (b) the operator-trust dismissal of the 23 CLI rows, and (c) whether
to keep `sink-015` (sparse-checkout content channel) in the sink set for Phase 2 or downgrade
to summary/none pending a git-behavior check.

## 7. Constraints honored

- No PyVul ground truth, patch diffs, CVE publications, or the repo-root
  `CVE_APPLICATION_REPORT.md` / `PATH_TRAVERSAL_AUDIT_REPORT.md` /
  `GITHUB_PRIVATE_VULN_REPORT*.md` files were opened; labeling is derived only from the
  dfetch source tree and the loaded Augur references (`references/python.md`,
  `references/patterns.md`, `WORKFLOW.md`, `assets/labels_schema.json`). No framework
  reference was loaded (none matches the stdlib argparse CLI).
- No source file, CodeQL database, Augur file, or Phase 1 CSV was modified; the only writes
  were the four artifacts under `iris/labels/`.
- Phase 2 (library/query generation, taint execution) was not started.
