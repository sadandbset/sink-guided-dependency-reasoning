# Label Statistics - Augur Phase 1 Step 3 (Pass 2, CWE-78)

- run_id: `bikeshed-iris-pass2-step3-20261013`
- generated_at: 2026-10-13T09:18:59+00:00
- model: `glm-5.3`
- candidate rows processed: 153 source + 26 sink = 179 (all mapped, none silently dropped)
- label entries emitted: 49 (26 sink-side + 20 source-side + 3 summary)

## Entries by role

| role | count |
| --- | --- |
| source | 14 |
| sink | 20 |
| sanitizer | 0 |
| summary | 3 |
| none | 12 |

## Entries by classification

| classification | count |
| --- | --- |
| tp | 15 |
| fp | 24 |
| candidate | 10 |
| unknown | 0 |

## Sinks (tp)

- `Popen` (subprocess) @ bikeshed/inlineTags/__init__.py:14 - conf 0.95
- `processTags` (bikeshed.inlineTags) @ bikeshed/inlineTags/__init__.py:7 - conf 0.8
- `system` (os) @ bikeshed/cli.py:669 - conf 0.9
- `system` (os) @ bikeshed/cli.py:675 - conf 0.85
- `handleProfile` (bikeshed.cli) @ bikeshed/cli.py:665 - conf 0.8

## Sinks (candidate)

- `check_call` @ release.py:83 - conf 0.6
- `check_call` @ release.py:97 - conf 0.6
- `check_call` @ release.py:121 - conf 0.6

## Sinks (fp - command API with provably untainted arg)

- `check_output` @ bikeshed/boilerplate.py:36 - conf 0.9
- `check_output` @ bikeshed/boilerplate.py:49 - conf 0.9
- `check_output` @ bikeshed/boilerplate.py:92 - conf 0.85
- `check_output` @ bikeshed/boilerplate.py:103 - conf 0.85
- `check_output` @ release.py:14 - conf 0.85
- `check_output` @ release.py:65 - conf 0.85
- `call` @ release.py:80 - conf 0.85
- `call` @ release.py:109 - conf 0.85
- `check_call` @ release.py:117 - conf 0.85
- `check_call` @ release.py:122 - conf 0.85
- `check_output` @ release.py:128 - conf 0.85
- `check_call` @ release.py:81 - conf 0.85

## Sources (tp)

- `StdinInputSource.read` @ bikeshed/InputSource.py:118 - conf 0.95
- `sys.stdin.readlines` @ bikeshed/InputSource.py:119 - conf 0.9
- `UrlInputSource._fetch` @ bikeshed/InputSource.py:136 - conf 0.9
- `requests.get` @ bikeshed/InputSource.py:137 - conf 0.9
- `UrlInputSource.read` @ bikeshed/InputSource.py:146 - conf 0.9
- `FileInputSource.read` @ bikeshed/InputSource.py:168 - conf 0.95
- `builtins.open` @ bikeshed/InputSource.py:169 - conf 0.9

## Sources (candidate)

- `argparse.ArgumentParser.add_argument` @ bikeshed/cli.py:27 - conf 0.6
- `argparse.ArgumentParser.parse_args` @ bikeshed/fonts.py:218 - conf 0.6
- `sys.stdin.readlines` @ bikeshed/fonts.py:174 - conf 0.55
- `builtins.open` @ bikeshed/fonts.py:176 - conf 0.55
- `builtins.open` @ bikeshed/issuelist.py:31 - conf 0.55
- `builtins.open` @ release.py:23 - conf 0.6
- `builtins.open` @ release.py:28 - conf 0.55

## Summaries (tp)

- `bikeshed.metadata.parse` (param 0) @ bikeshed/metadata.py:1057 - conf 0.85
- `bikeshed.metadata.fromCommandLine` (param 0) @ bikeshed/metadata.py:1110 - conf 0.7
- `bikeshed.metadata.fromJson` (param 0) @ bikeshed/metadata.py:1129 - conf 0.75

## Sanitizers

None labeled: no sanitizer API was extracted or observed. The only neutralization evidence in the codebase is the arg-list/no-shell invocation at `bikeshed/metadata.py:1169` (`check_output(['git','remote','-v'], cwd=...)`), recorded as role=none on p2-sink-012; `MySanitizers.qll` in Phase 2 should use the `none()` fallback per WORKFLOW.md 5.2.3.

## Deduplication

- DR-1: 75 `argparse.add_argument` rows merged into `p2-src-008`.
- DR-2: 12 non-boundary `requests.get` rows merged into `p2-src-016`.
- DR-3: 45 internal data/output `open()` rows merged into `p2-src-018`.
- DR-4: same-signature sink rows kept separate (call-site context drives classification).
- DR-5: no exact duplicate rows present.
- Full per-row audit trail: `labels/labels_raw_pass2.json`.
