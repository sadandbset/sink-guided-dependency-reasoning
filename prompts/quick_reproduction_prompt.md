# Quick Reproduction Prompt — Sink-Guided Python Vulnerability Audit

This is a **lightweight Claude Code audit prompt** for case inspection, not a replacement for the full experimental protocol of the paper.

## Prompt for Claude Code

Audit the Python project `tensorflow_vuln` for potential **OS command injection (CWE-78)**. The file `tensorflow_vuln/cmd_sinks.csv` contains the candidate sink list. Read its actual columns, inspect the corresponding source code, and do not assume that every listed sink is vulnerable.

Follow the workflow below:

### Step 1 — Sink filtering and priority classification
- Record all candidate sinks in `cmd_sinks.csv`.
- Conservatively exclude clearly out-of-scope tests, generated files, or vendored code **only when the source path and stated scope justify exclusion**. Record exclusions; retain uncertain cases.
- Based on sink type, location, enclosing function, nearby context, and filename, classify the remaining candidates as **High**, **Medium**, or **Low** priority, with a brief reason for each.
- Treat priority as a scheduling decision, **not** a security verdict.

### Step 2 — Local semantic validation
For candidates entering analysis, inspect the immediate local context and answer only:
1. Is the call a genuine security-sensitive operation for CWE-78?
2. Which specific actual argument/expression requires backward tracing?
3. Is there clear local evidence conclusively excluding the candidate?

Do not perform full-program reasoning in this step. Keep uncertain candidates for further investigation.

### Step 3 — Priority-aware backward tracing

**Priority-based analysis and promotion**

- **High priority — deep tracing:** Starting from the sensitive argument identified in Step 2, perform detailed backward dependency analysis. Continue investigating relevant callers, helper functions, indirect calls, and state relationships as supported by source code.
- **Medium priority — focused assessment:** Perform a targeted review of the local input influence, calling context, and security checks. If a plausible attacker-controllable path or a relevant unresolved dependency is identified, **promote the candidate to High** and conduct deep backward tracing.
- **Low priority — batch audit:** Review candidates in batches for security-sensitive behavior, possible untrusted input influence, and overlooked indirect calls. When a potentially relevant risk is found, **promote the candidate to Medium**, reassess it, and promote further to High if deep tracing is warranted.
- Record the initial/final priorities and the reason for each promotion. A Low or Medium classification is **not** a determination that the sink is safe.

**Backward-tracing rules**

1. **Trace toward the actual origin.** Follow assignments, expressions, return values, call sites, actual-to-formal parameter mappings, caller relationships, wrappers, dynamic registrations, configuration lookups, and relevant object attribute/state reads and writes. If the sink is inside a callee, inspect its callers and continue until a justified source, trusted endpoint, or stopping condition is reached.
2. **Preserve separate dependency branches.** If a value has multiple possible predecessors or the call graph has multiple feasible branches, investigate them separately. Do not combine incompatible paths into one apparent source-to-sink chain.
3. **Require concrete code evidence.** For each critical dependency step, identify the program operation that supports the relationship, with the file path and relevant `line` or `line range` where available. An apparent name similarity, guessed call edge, or plausible explanation alone does not establish a dependency. Do not fabricate missing links.
4. **Determine attacker controllability.** Trace inputs from requests, command-line arguments, configuration files, environment variables, databases, or other sources as applicable. Do **not** assume that configuration, environment, or database values are inherently attacker-controlled or inherently trusted; explain who can influence the value and under what conditions.
5. **Check execution conditions and defenses.** Inspect relevant control-flow conditions, validation, sanitization, allowlists, and command construction. A defense rules out a path only if the code evidence shows it is effective for that path. For command execution, distinguish **shell injection** from **argument/option injection** by checking the called API and whether a shell is invoked; do not treat shell metacharacters as executed commands when no shell parses them.
6. **Apply clear stopping conditions.** A branch may stop when: (a) an attacker-controllable source is supported by code evidence; (b) a trusted or hardcoded source is established; (c) an effective security constraint rules out the risk on that branch; (d) the **five-level interprocedural expansion limit** is reached; (e) a cycle/repeated tracing state prevents progress; or (f) necessary source-code evidence is unavailable. Count *interprocedural expansions* rather than every assignment or expression.
7. **Distinguish unresolved from safe.** For conditions (d)–(f), mark the branch **Unresolved**, record the reason and missing information, and do not treat the absence of a proven path as evidence of safety. Within the configured limit, investigate all relevant predecessor relationships rather than stopping arbitrarily.
8. **Reconstruct only supported propagation chains.** When reporting a finding, present the investigated chain in **source-to-sink order** and cite the supporting operations for each critical step. Explicitly identify any unresolved gaps. A chain with a critical unsupported link must not be presented as an established vulnerability path.

**Per-candidate conclusion**

Use one of the following evidence-calibrated outcomes:

- **Evidence-supported vulnerability candidate:** the critical source-to-sink relationship and security weakness are supported by inspected code.
- **Cleared for the examined path:** there is code evidence that the analyzed path is not attacker-controllable or is blocked by an effective constraint.
- **Unresolved:** crucial code, a dependency link, or the relevant execution condition remains unverified.

For each analyzed candidate, include the sink location and sensitive argument, potential source and controllability, key propagation steps with code locations, relevant security constraints, the conclusion, and any unresolved assumptions. Do not label a result as independently confirmed exploitable solely on the basis of an agent-generated explanation.

### Step 4 — Write the audit report

**Output one English Markdown file named `vulnerability_audit_report_en.md`. Its format, section order, and presentation should follow the supplied example report `vulnerability_audit_report_en.md`.** Include the actual audit process, code evidence, and findings for `tensorflow_vuln`; do not copy the example project's results.

Use these same report sections:

```markdown
# Vulnerability Audit Report — tensorflow_vuln

**Project**: ...
**Audit target**: ...
**Sink inventory**: ...
**Method**: ...
**Report date**: ...

## Executive Summary
[Overview of candidates, priorities, main findings; short finding table.]

## 1. Sink Classification (Stage 1)
### 1.1 Project overview
### 1.2 Sink inventory
### 1.3 Initial priority classification
[Markdown tables for sinks and High / Medium / Low priorities.]

## 2. Medium-Priority Quick Assessment (Stage 2)
[Local code evidence, semantic assessment, priority changes and verdicts.]

## 3. High-Priority Deep Reverse Tracing (Stage 3)
### 3.1 Vulnerability Findings and Unresolved Cases
[For each finding: location, CWE, source-to-sink flow, code snippets,
a layer-by-layer trace table, controllability, security checks, verdict.]
### 3.2 Trust Boundaries / By-Design Behaviors
### 3.3 Cleared Sinks (Traced to Trusted Sources)

## 4. Low-Priority Batch Audit (Stage 4)
[Low-priority review and any promotion decisions.]

## 5. Remediation Recommendations
### Immediate fixes (P0)
### Long-term improvements (P1)
### Test recommendations

## 6. Summary Statistics
[Counts for candidates, priorities, promotions, findings,
cleared cases, unresolved cases, and tracing limits.]
```

Write the report with ordinary Markdown tables and fenced source-code snippets, as in the example. Cite real code locations; explicitly distinguish facts, inference, and unresolved questions. Do not invent CVSS values, exploit success rates, test outcomes, or vulnerability confirmations. Do not run destructive payloads.

**Deliver only the Markdown audit report**, not a JSON object or separate machine-readable schema. If file writing is unavailable, output its entire contents as Markdown.

## Reproduction scope

This quick prompt starts from an existing sink CSV and produces a **case-level audit**. It does not independently reproduce the full experimental pipeline, repeated-run voting, benchmark recall, or the original structured-agent instructions. Preserve the source-code commit, CSV version, effective model configuration, and Claude Code execution log when available.
