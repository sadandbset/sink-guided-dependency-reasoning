# Label Statistics — Pass 2 (CWE-78 Command/Argument Injection)

- Target: transformers (HuggingFace), src/transformers only
- Labeling model: **glm-5.3** (Claude Code CLI agent harness)
- Generated: 2026-10-19T12:00:00+00:00
- Batches: 9 — total candidate rows processed: **1087**
  (1034 source rows -> 760 unique sites; 53 sink rows -> 41 unique sites)
- Schema validation: PASS (jsonschema 4.26.0 against assets/labels_schema.json)

## Batches

| Batch | Scope | Rows |
| --- | --- | --- |
| B1 stdin-cli-entry | sys.stdin / sys.argv / argparse parse_args & parse_known_args CLI boundaries | 213 |
| B2 env-family | os.environ / os.getenv environment reads | 206 |
| B3 json-decode | json.load / json.loads decode boundaries | 404 |
| B4 network-hub | requests.* / huggingface_hub hf_hub_download & cached_download network boundaries | 169 |
| B5 handler-params | *Command.__init__ / export_with_* / convert-script main() handler parameters | 37 |
| B6 internal-transfer | dynamic-dispatch and internal hand-off call sites | 5 |
| B7 exec-api-sinks | subprocess Popen & run & check_output / asyncio.create_subprocess_exec call sites | 25 |
| B8 exec-wrappers | internal functions wrapping an OS-command execution | 10 |
| B9 cmd-construction | f-string / str.join command-construction expressions | 18 |

## Row-level dispositions (audit trail in labels_raw_pass2.json)

| Role | Rows |
| --- | --- |
| none | 30 |
| sink | 25 |
| source | 1029 |
| summary | 3 |

| Classification | Rows |
| --- | --- |
| candidate | 997 |
| fp | 39 |
| tp | 51 |

Total rows: 1087

## Effective signature-level entries (labels.json, pass 2)

| Role | Entries |
| --- | --- |
| sink | 5 |
| source | 30 |
| summary | 3 |

| Classification | Entries |
| --- | --- |
| candidate | 19 |
| tp | 19 |

Total entries: 38 (30 source, 5 sink, 3 summary; 0 sanitizer — none found)

## Deduplication / exclusion summary

- **api/ast double extraction**: 261 source sites and 12 sink sites are emitted twice by the
  extraction queries (API-graph row + syntactic row of the same call). Both rows are kept in the
  raw audit with a dedup note and collapse to one site / one signature entry.
- **Signature-level merge**: 1057 rows map to one of the 38
  signature entries above (merged-into-signature-entry). The ~201 developer conversion-script
  `parse_args` mains are merged into `src-argparse-parse-args` and are FP-filterable in Phase 2.
- **Excluded rows (role none, reason 'redundant wrapper/expression')**: 30
  - 10 `internal_exec_wrapper` function rows: the subprocess/asyncio call inside each wrapper is
    labeled directly; standard intra-procedural flow carries parameters to that call.
  - 18 `cmd_fstring`/`cmd_join` expression rows: command-construction fragments (or non-command
    strings — error messages, print text, URLs). Taint flows through interpolation automatically;
    the executing call is the sink. The audio_utils.py:244 microphone-device-name f-string is kept
    in the raw file as a low-confidence note (see phase1_review.md).
  - 2 `internal_transfer` rows (export_with_*() direct calls): statically resolvable calls whose
    parameter boundary is already labeled source.

## Sanitizers

None. No shlex.quote / pipes.quote / shell-escaping wrapper exists at any exec site in
src/transformers (the only shlex usage is testing_utils.py:1596 `shlex.split` on a generated
command — tokenization, not escaping). The argument-list (no-shell) invocation form is the only
structural mitigation; it is recorded per site in the raw artifact, not as sanitizer labels.
