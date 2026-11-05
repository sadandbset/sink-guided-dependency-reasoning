# Prompt: Local Sink Semantic Verification and Sensitive Argument Identification

## Task Background

The target Python project has completed candidate sink discovery, deterministic rule-based pre-screening, and initial High/Medium/Low priority classification.

Read the candidate sinks and their initial priorities retained from the previous stage, and perform **local sink semantic verification and sensitive argument identification** to provide an analysis starting point for subsequent evidence-constrained interprocedural backward dependency reasoning.

This stage analyzes only the local security semantics of candidate calls. It is not responsible for recovering complete Source-to-Sink propagation paths and does not make final vulnerability judgments.

## I. Inputs

1. Source code of the target Python project and the fixed analysis version.
2. Candidate sink priority classification results generated in the previous stage.
3. Original sink record files, e.g., `tensorflow_vuln/cmd_sinks.csv`.
4. Current target vulnerability category (CWE-78, CWE-89, CWE-918, or CWE-22).

For each candidate sink, the following information should be preserved:

- `sink_id`: candidate unique identifier;
- `file_path`: file containing the call;
- `line_number`: call location;
- `sink_expression`: candidate call expression;
- `function_name`: enclosing function or method;
- `initial_priority`: priority determined in the previous stage.

The initial priorities from the previous stage must not be recalculated or overwritten.

## II. Analysis Scope

This stage may use only the following local program information:

1. The actual call expression of the candidate sink;
2. Local code of the function or method containing the call;
3. Arguments, objects, and expressions directly related to the candidate call;
4. Limited structural context necessary to determine the current call semantics;
5. When necessary, function or method definitions directly visible in the same file may be inspected to confirm the local semantics of the call.

Complete call-graph recovery, cross-file Source tracing, deep object-state propagation analysis, or exploit verification must not be performed at this stage.

If local evidence is insufficient to determine call semantics, record the uncertainty and retain the candidate rather than expanding the analysis scope of this stage.

## III. Local Semantic Verification Tasks

For each retained candidate, complete the following three judgments in sequence.

### Judgment 1: Does the candidate have sink semantics corresponding to the target vulnerability category?

Inspect the actual function of the candidate call in the current code context, rather than judging solely by function name.

Focus on checking:

- Whether the call actually performs a security-sensitive operation related to the target CWE;
- Whether the call target may be locally defined, object-wrapped, or name-reused in a way that changes semantics;
- Whether there is clear evidence proving that the call actually belongs to another operation category;
- Whether the current local context is sufficient to confirm or deny its sink nature.

Typical judgments for different vulnerability categories are as follows.

**CWE-78: OS Command Injection**

Determine whether the call involves external process launch, system command execution, or shell command interpretation, e.g., `subprocess.run`, `subprocess.Popen`, and related wrapper interfaces.

Command arguments, `shell` configuration, and call-wrapping relationships must be checked.

Calls must not be directly identified as system command execution merely because their names contain `run`, `call`, `system`, or `exec`.

Python's `eval` and `exec` usually have code-execution semantics and must not be directly classified as CWE-78 without concrete justification.

**CWE-89: SQL Injection**

Determine whether the call executes SQL statements against a database, including database cursors, database connections, ORM native SQL interfaces, etc.

The distinction between SQL query expressions and parameter-binding interfaces should be identified, but the existence of an SQL injection vulnerability must not be determined solely based on local dynamic string construction.

**CWE-918: Server-Side Request Forgery**

Determine whether the call may initiate network requests or access external network resources.

URLs, hostnames, request targets, or related configuration parameters that affect the request destination must be identified.

Methods whose names contain `get`, `post`, or `request` must not be directly treated as network request sinks.

**CWE-22: Path Traversal**

Determine whether the call performs file reading, writing, deletion, movement, or other path-sensitive operations.

Focus on identifying path arguments that determine the target file or directory location.

Ordinary string processing, path object creation, or operations without actual path-sensitive behavior must not be directly equated with vulnerabilities.

The above interfaces are intended only to illustrate semantic judgment principles and are not complete sink-matching rules.

### Judgment 2: Which concrete actual argument should serve as the starting point for backward tracing?

For candidates that have target sink semantics or cannot yet be clearly excluded, identify the concrete argument expressions that affect the security of the sensitive operation.

Requirements:

1. Record the actual position and name of the argument in the call expression.
2. Preserve the original code expression; do not replace it with a speculated variable.
3. Explain the local semantic relationship between the argument and the target sensitive operation.
4. If multiple independent sensitive arguments exist, record each separately.
5. If the sensitive argument cannot be uniquely determined from available local evidence, record possible candidate arguments and missing information; do not guess.

For example:

- `subprocess.run(command, shell=True)`: focus on tracing `command`;
- `cursor.execute(query, params)`: focus on identifying the SQL query expression `query` and the relevant parameter-binding form;
- `requests.get(url)`: focus on tracing the request target `url`;
- `open(file_path, mode)`: focus on tracing `file_path`.

**Identification of a sensitive argument only indicates that its value may affect operation security; it does not mean the argument has been proven attacker-controllable.**

### Judgment 3: Is there sufficient local evidence to clearly exclude the candidate?

A candidate may be excluded only when local code provides clear, citable negative evidence.

Typical cases include:

- The call target is clearly resolved to a function unrelated to the target CWE;
- The candidate is a name collision caused by static matching;
- The call actually performs a non-target-category operation;
- The current expression is verified not to have the required sensitive operation semantics.

The exclusion basis must be stated, with file location and actual code provided.

**The following situations must not be used as sole grounds for exclusion:**

1. No explicit HTTP request, command-line input, or other external input appears in the current function.
2. The current argument comes from a function parameter, but the caller cannot be determined from local code.
3. The argument is returned by another function, and its origin cannot currently be traced.
4. No explicit taint propagation path is found in the current local scope.
5. Some validation, filtering, or sanitizer name appears in the code, but its effectiveness on the target propagation path has not been verified.
6. The candidate's initial priority is Low.
7. No clear vulnerability evidence has yet been found.

The above situations indicate only insufficient local information and cannot prove program security.

## IV. Candidate Retention and Exclusion Rules

For each candidate, assign one of the following three statuses:

**KEEP**

Local evidence supports that it has sink semantics of the target vulnerability category. It should be retained and its sensitive arguments provided for subsequent backward tracing.

**UNCERTAIN**

Current local evidence is insufficient to clearly confirm or exclude sink semantics. It should be conservatively retained, and the call relationships or argument information requiring subsequent confirmation should be recorded.

**REJECT**

Clear and citable local evidence proves that the candidate does not correspond to the sensitive operation of the current target CWE.

Note:

- KEEP does not mean a vulnerability exists.
- UNCERTAIN does not mean secure.
- REJECT only means it does not match the current target sink semantics; it does not mean the code has no vulnerabilities of other categories.
- A candidate must not be directly excluded because its initial priority is low.
- Final vulnerability judgment based on attacker controllability must not be made at this stage.

## V. Evidence Requirements

Each judgment should include, as far as possible:

- Relative file path;
- Actual line number or code range;
- Call expression;
- Enclosing function;
- Local code basis supporting the judgment;
- Program relationships not yet determined.

Code locations, function definitions, call relationships, or taint sources must not be fabricated.

If a code file cannot be accessed, its location has changed, or the call target cannot be resolved within the current scope, this should be explicitly recorded; it must not be completed by guessing.

## VI. Output Format

Generate an independent structured record for each candidate.

JSONL format is recommended, with the following fields:

json

```
{
  "sink_id": "candidate_id",
  "file_path": "relative/path.py",
  "line_number": null,
  "function_name": "function_name",
  "sink_expression": "actual_call_expression",
  "initial_priority": "HIGH",
  "target_cwe": "CWE-78",
  "resolved_call_semantics": "description",
  "sink_status": "KEEP",
  "sensitive_arguments": [
    {
      "argument_expression": "command",
      "argument_position": 0,
      "security_relevance": "Process command argument"
    }
  ],
  "local_evidence": [
    {
      "file": "relative/path.py",
      "line_range": "start-end",
      "code_expression": "actual_code",
      "reasoning": "semantic justification"
    }
  ],
  "local_security_checks": [],
  "uncertainties": [],
  "decision_reason": "brief evidence-based reason",
  "next_step": "BACKWARD_TRACE"
}
```



The above JSON is only a field example and does not represent analysis results of any actual project.

For `UNCERTAIN` candidates, state the evidence that needs to be obtained in the next stage. If a specific sensitive argument cannot be determined, mark it as `UNRESOLVED_ARGUMENT`, retain the candidate, and resolve it further before starting backward tracing, rather than constructing a false tracing starting point.

## VII. Statistics Requirements

After completing verification of all candidates, output the following statistics:

- Total number of input candidates;
- Number of KEEP;
- Number of UNCERTAIN;
- Number of REJECT;
- Number of candidates with explicit sensitive arguments;
- Number of candidates whose sensitive arguments still need confirmation.

Check:

Total input candidates = KEEP count + UNCERTAIN count + REJECT count.

The statistical unit is candidate sinks, not the number of sensitive arguments. When one sink contains multiple sensitive arguments, it must not be counted repeatedly in the total candidate count.

This stage uses candidates as the logical judgment unit. Multiple candidates may be processed together, but the number of candidates is not required to correspond one-to-one with the number of LLM model requests.

## VIII. Interface to Subsequent Stages

Output to the subsequent backward dependency reasoning module all candidates that have not been explicitly excluded and that have identifiable sensitive arguments:

text

```
(sink_id, sink, sensitive_argument, initial_priority)
```



For candidates whose sensitive arguments cannot yet be clearly identified, record them separately in a pending-evidence state; they must not be silently deleted.

The subsequent backward dependency reasoning module is responsible for:

- Tracing upstream data origins of sensitive arguments;
- Analyzing interprocedural parameter mapping and indirect state propagation;
- Adjusting exploration priorities based on newly added evidence;
- Checking source controllability and security constraints;
- Constructing candidate Source-to-Sink propagation chains.

**Stop after completing this stage. Do not perform global vulnerability judgment or generate a final vulnerability report.**