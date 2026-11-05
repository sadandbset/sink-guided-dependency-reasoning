# Prompt: Lightweight Sink Priority Screening

## Task Objective

In the `tensorflow_vuln` directory, `cmd_sinks.csv` records potential command-execution sinks identified by static rules in the target Python project.

Adopt a **hybrid strategy combining deterministic rule-based pre-screening with LLM semantic classification** to perform lightweight priority triage of candidate sinks, thereby determining the exploration order and scope for subsequent vulnerability analysis.

This stage performs only candidate screening and initial priority classification. It **does not perform complete Source-to-Sink tracing, does not determine whether a vulnerability exists, and does not make final security judgments on candidates**.

## Stage 1: Deterministic Rule-Based Pre-Screening

1. Read `tensorflow_vuln/cmd_sinks.csv`, parse all candidate records, and preserve the original identifier, file path, code location, and sink call information of each record.
2. Based on file paths, file names, and the pre-declared analysis scope, exclude candidates that clearly belong to test code, generated code, or are outside the analysis scope.
3. For calls with similar names but clearly non-target vulnerability semantics, limited local code evidence may be used for exclusion. For example, a function whose name contains `run` or `system` should not be treated as OS command execution based on name alone.
4. Every excluded candidate must be recorded with a specific reason. Candidates that cannot be clearly excluded must be retained; they must not be deleted merely due to lack of vulnerability evidence.

## Stage 2: LLM Lightweight Priority Classification

For all candidate sinks retained after rule-based pre-screening, classify them based on the following information:

- Sink type and call expression;
- File path and file name of the sink;
- Function or method name containing the sink;
- Call site and limited local structural context.

Assign an initial priority to each candidate based on the above information:

**High**

The candidate call has relatively clear security-sensitive operation semantics, and its call site, argument form, or local context indicates that cross-file, interprocedural backward dependency analysis should be prioritized.

**Medium**

The candidate call may involve security-sensitive operations, but current local information is insufficient to clarify its actual call semantics, argument provenance, or risk relevance. Further limited shallow inspection is needed to obtain more evidence.

**Low**

The candidate is primarily obtained through loose name or call-pattern matching, and security-relevant clues in the available local structural information are weak. It is suitable for lightweight batch inspection first, rather than immediate full interprocedural tracing.

## Classification Constraints

1. Priority indicates only the relative priority for allocating subsequent analysis resources to a candidate; **it does not represent vulnerability probability, attacker controllability, or a final security conclusion**.
2. A candidate must not be judged as secure solely because it lacks explicit external input, no Source has yet been found, or no complete propagation path has yet been formed.
3. Complete interprocedural call-chain recovery, deep data-flow tracing, or exploit verification must not be performed at this stage.
4. For candidates with insufficient local evidence for clear classification, adopt a conservative classification principle and state the uncertainty.
5. All candidates not explicitly excluded by rules must receive an initial priority of High, Medium, or Low. Low candidates must be retained for subsequent batch shallow inspection.
6. Python's `exec` and `eval` must not be directly equated with OS command injection. If a candidate involves other vulnerability categories, its possible semantic differences should be noted to avoid confusing CWE-78 with CWE-94.
7. Classification conclusions must be based on actual structural information in the current code version and must not rely on existing CVE identifiers, patch contents, or known vulnerability labels.

## Output Requirements

Save classification results as a structured file containing the following fields:

| Field             | Meaning                              |
| :---------------- | :----------------------------------- |
| `sink_id`         | Original candidate unique identifier |
| `file_path`       | File containing the sink             |
| `line_number`     | Line containing the sink             |
| `sink_expression` | Sink call expression                 |
| `function_name`   | Enclosing function or method         |
| `priority`        | High / Medium / Low                  |

Additionally, save the candidates excluded by rules and their exclusion reasons separately.

Final output summary statistics must include:

- Total number of original candidate sinks;
- Number excluded by rule-based pre-screening;
- Total number of retained candidates;
- Number of High, Medium, and Low candidates respectively.

The following must be checked:

Total original candidates = number excluded + number retained.

Number retained = number of High + number of Medium + number of Low.

Stop after completing this stage. Do not perform full backward dependency analysis. Subsequent analysis should decide whether to expand the exploration scope or raise priorities based on initial priorities and newly obtained code evidence.