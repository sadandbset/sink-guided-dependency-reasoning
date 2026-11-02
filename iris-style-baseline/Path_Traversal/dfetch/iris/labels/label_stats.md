# Augur Phase 1 Step 3 — Label Statistics (dfetch, Pass 1: Path Traversal)

- **Run ID:** `iris-dfetch-pathtraversal-pass1-20261022`
- **Generated:** 2026-10-22 (UTC)
- **Model:** `glm-5.3` (Claude Code CLI harness)
- **Language / framework:** python / argparse CLI (stdlib) — no web framework, no HTTP surface
- **Pass:** 1 — Path Traversal (CWE-022, CWE-023, CWE-036, CWE-073)
- **Schema:** `labels.json` validated against local Augur `assets/labels_schema.json` (draft 2020-12, format checker enabled) — **VALID**
- **Source candidates processed:** 61/61 (`extraction/sources.csv`)
- **Sink candidates processed:** 99/99 (`extraction/sinks.csv`)
- **Total entries:** 160/160 — every candidate received exactly one label

## Batches

Labeling was performed against the real `dfetch_vuln` source tree in 11 stable batches
(dedup key `file+line+node+callable`; one decision per candidate):

| Batch | Scope | Candidates |
| --- | --- | --- |
| S1 | CLI / argparse boundary source candidates (operator-trust review) | 23 |
| S2 | git/svn subprocess stdout source candidates (remote-content review) | 10 |
| S3 | `yaml.safe_load` manifest/metadata parse boundaries | 4 |
| S4 | manifest/metadata field-level reads (`kwargs.get`, `yamldata[...]` subscripts) | 24 |
| K1 | sink candidates in `dfetch/commands/*`, `dfetch/reporting/*`, `setup.py` | 24 |
| K2 | sink candidates in `dfetch/vcs/git.py`, `dfetch/project/git.py` (git fetch pipeline) | 16 |
| K3 | sink candidates in `dfetch/manifest/manifest.py` | 9 |
| K4 | sink candidates in `dfetch/project/metadata.py` | 10 |
| K5 | sink candidates in `dfetch/project/svn.py` (svn fetch pipeline) | 11 |
| K6 | sink candidates in `dfetch/util/util.py` (shared filesystem helpers) | 23 |
| K7 | sink candidates in `dfetch/project/vcs.py` (VCS base, patch application) | 6 |

## Role counts

| Role | Sources | Sinks | Total |
| --- | --- | --- | --- |
| source | 11 | 0 | **11** |
| sink | 0 | 16 | **16** |
| sanitizer | 0 | 0 | **0** |
| summary | 0 | 33 | **33** |
| none | 50 | 50 | **100** |

## Classification counts

| Classification | Count | Meaning |
| --- | --- | --- |
| tp | 59 | confirmed real for the labeled role in this pass |
| candidate | 1 | probable but requires human confirmation |
| fp | 100 | not relevant for Pass 1 (labeled `none`) |

- Average confidence: **0.801**
- Entries below the 0.55 re-ask threshold: 1 — `sink-015` (`vcs/git.py:149`, sparse-checkout `open`, confidence 0.5, held at `candidate` by design: literal path argument + manifest-controlled content channel whose effect is decided inside git).

## Confirmed sources (11)

| ID | Location | Boundary | Conf. |
| --- | --- | --- | --- |
| src-022 | dfetch/manifest/manifest.py:139 | `yaml.safe_load` of dfetch.yaml — primary manifest parse boundary | 0.85 |
| src-023 | dfetch/manifest/manifest.py:129 | `loaded_yaml["manifest"]` root-dict read | 0.80 |
| src-027 | dfetch/manifest/project.py:245 | manifest field **`src`** (subtree/pattern inside fetched repo) | 0.80 |
| src-028 | dfetch/manifest/project.py:246 | manifest field **`dst`** (the destination path — dominant Pass 1 source) | 0.85 |
| src-029 | dfetch/manifest/project.py:248 | manifest field **`patch`** (patch file path → `patch_ng.fromfile`) | 0.80 |
| src-033 | dfetch/manifest/project.py:268 | `yamldata[key]` field-read loop in `ProjectEntry.from_yaml` | 0.80 |
| src-017 | dfetch/vcs/git.py:229 | `git submodule foreach` stdout — `sm_path` (remote `.gitmodules`) → imported manifest `dst` | 0.90 |
| src-046 | dfetch/project/svn.py:46 | `svn propget svn:externals` stdout — externals `local_path`/`name` → imported `dst` | 0.85 |
| src-025 | dfetch/project/metadata.py:46 | `kwargs.get("destination")` — manifest `dst` entering `Metadata` state | 0.70 |
| src-032/033 | dfetch/project/metadata.py:71 | `yaml.safe_load` / `["dfetch"]` of `.dfetch_data.yaml` (remote-influenced content) | 0.75 |

The 50 `none`/fp source rows are: 23 CLI/operator-boundary rows (S1: `sys.argv`, argparse `args.*`,
`Command.__call__` params — invoker is the same trust domain as the config), 8 non-path
`process_stdout` rows (version/SHA/branch/tag/diff-text/URLs), 17 non-path manifest/metadata
field reads (branch/tag/revision/url/repo-path/hash/remote names — version or URL material, not
local paths), and 2 serialization-side rows.

## Confirmed sinks (16, incl. 1 candidate)

| ID | Location | API (dangerous arg) | Kind | Conf. | Class. |
| --- | --- | --- | --- | --- | --- |
| sink-079 | dfetch/util/util.py:39 | `shutil.rmtree(path)` arg0 — dst, `<dst>/.git`, `PurePath(src).parts[0]` | dir delete | 0.90 | tp |
| sink-054 | dfetch/project/git.py:70 | `Path(dst).mkdir(parents=True)` receiver — the manifest dst | dir create | 0.90 | tp |
| sink-076 | dfetch/util/util.py:33 | `os.remove(path)` arg0 — dst / non-matching files under dst | file delete | 0.85 | tp |
| sink-059 | dfetch/commands/diff.py:171 | `open(patch_name,"w")` arg0 — `project.name + ".patch"` | file write | 0.85 | tp |
| sink-094 | dfetch/project/vcs.py:134 | `patch_ng.fromfile(patch)` arg0 — manifest `patch` | file read/parse | 0.85 | tp |
| sink-089 | dfetch/project/metadata.py:165 | `open(self.path,"w+")` arg0 — `realpath(join(dst,…))` | file write | 0.85 | tp |
| sink-020 | dfetch/vcs/git.py:169 | `shutil.move(src+"/"+file, ".")` arg0 — manifest `src` subtree | file move | 0.85 | tp |
| sink-058 | dfetch/project/svn.py:196 | `Path(dirname(dst)).mkdir(parents=True)` receiver | dir create | 0.85 | tp |
| sink-064 | dfetch/project/svn.py:243 | `run_on_cmdline(['svn','export',…,dst])` idx 6 — process writes tree at dst | process write | 0.80 | tp |
| sink-062 | dfetch/project/svn.py:206 | `os.remove(file)` arg0 — walked files under dst root | file delete | 0.80 | tp |
| sink-081 | dfetch/project/metadata.py:70 | `open(path,"r")` arg0 — metadata read at dst-derived path | file read | 0.75 | tp |
| sink-095 | dfetch/project/vcs.py:138 | `patch_set.apply(root=dst)` (root= keyword, no positional index) | patch write | 0.75 | tp |
| sink-083 | dfetch/util/util.py:52 | `os.chdir(path)` arg0 — CWD scoping to manifest dst/src | cwd escape | 0.65 | tp |
| sink-093 | dfetch/util/util.py:107 | `open(file_path,"rb")` arg0 — hash read under dst root (bounded impact) | file read | 0.65 | tp |
| sink-071 | dfetch/util/util.py:14 | `os.chmod(path,…)` arg0 — rmtree onerror, bounded by rmtree root | perm change | 0.55 | tp |
| sink-015 | dfetch/vcs/git.py:149 | `open('.git/info/sparse-checkout',"a")` arg0 — literal path, tainted CONTENT | content write | 0.50 | **candidate** |

## Summary steps (33)

Internal wrappers (`safe_rm`, `safe_rmtree`, `in_directory`, `find_non_matching_files`,
`hash_directory`, `hash_file`, `Metadata.from_file`, `_dump_patch`, `GitLocalRepo.__init__`,
`checkout_version`, `SvnRepo._export`) and path-construction/normalization/enumeration nodes
(`os.path.join`/`dirname`/`realpath`/`basename`, `Path`/`PurePath` ctors, `.parts[0]`,
`os.walk`, `os.listdir`) that connect the labeled sources to the dangerous sinks. Includes the
notable traversal **amplifier** `PurePath(src).parts[0] → safe_rmtree` (vcs/git.py:170).

## Sanitizers: none

**Zero sanitizer entries.** Verified against the source tree: no
`os.path.islink`/`lexists`/`normpath`/`abspath`; every `startswith` is URL/ref matching; the
single `relative_to` (manifest.py:274) builds a display prefix; the single `basename`
(metadata.py:131) leaves the directory component unguarded; `realpath` uses are normalization
without containment comparison; pykwalify validation is type-only (`dst: str unique`,
`patch: str`, `src: any`). The only content restriction anywhere is the svn single-`*` check
(svn.py:227-236), which does not block `..` or absolute paths. `MySanitizers.qll` must use the
`none()` fallback in Phase 2.

## Dedup and exclusions

- **Duplicates removed:** 0 — all 160 candidate rows are unique by `file+line+node+callable`
  (two rows sharing `metadata.py:71` / `vcs/git.py:170` / `manifest.py:274` / `util.py:83` are
  distinct AST nodes: subscript vs call vs distinct callables).
- **Candidates excluded:** 0 — extraction had already filtered `/tests/`, `/features/`,
  `/dfetch-db/`, `/doc/`; the remaining `setup.py:11` row was labeled `none`/fp on its own
  merits (build script, literal README path) instead of being dropped, for auditability.

## Provenance

- Labeling was done by reading the real `dfetch_vuln` source files (`dfetch/__main__.py`,
  `dfetch/commands/*`, `dfetch/manifest/*`, `dfetch/project/*`, `dfetch/vcs/git.py`,
  `dfetch/util/util.py`, `dfetch/reporting/sbom_reporter.py`, `dfetch/resources/schema.yaml`,
  `setup.py`) — every chain cited in `evidence` was verified in code, not inferred.
- No PyVul ground truth, patch diffs, CVE publications, or the repo-root
  `CVE_APPLICATION_REPORT.md` / `PATH_TRAVERSAL_AUDIT_REPORT.md` /
  `GITHUB_PRIVATE_VULN_REPORT*.md` files were consulted. No source, CodeQL database, Augur
  file, or Phase 1 CSV was modified.
