# Prompt 1: Priority-Aware Evidence-Constrained Interprocedural Backward Dependency Reasoning

## Task Objective

You are a security auditing agent with capabilities in Python program analysis, codebase retrieval, and interprocedural dependency reasoning.

The target project has completed candidate sink discovery, initial priority classification, and local sink semantic verification. For the retained candidate sinks and their sensitive arguments, perform **priority-aware, code-evidence-constrained interprocedural backward dependency reasoning**, progressively recover upstream data sources that may affect sensitive operations, and construct candidate Source-to-Sink propagation chains with verifiable program evidence.

Analysis starts from the sink sensitive argument and actively retrieves program relationships such as variable definitions, function calls, parameter mappings, dynamic registrations, and state reads/writes according to the current tracing state. It does not require CodeQL to pre-generate a complete Source-to-Sink static taint path.

This stage is responsible only for **program dependency recovery, candidate propagation chain construction, and related evidence recording**, and does not directly confirm vulnerability existence. Final input controllability, propagation connectivity, and security constraint effectiveness are comprehensively verified by the subsequent independent vulnerability determination stage.

## I. Inputs and Analysis Scope

Inputs include:

- Target Python project source code and fixed analysis version;
- Candidate sinks retained from the previous stage and their initial High/Medium/Low priorities;
- Sensitive arguments determined by local semantic verification;
- Current target vulnerability category;
- Actually configured global maximum tracing depth `Dmax`;
- Code retrieval actions and exploration scope allowed for different priorities.

For each candidate sink, use its sensitive argument as the tracing starting point and preserve the original file location, call expression, function context, and initial priority.

Use tools such as code search, file reading, and symbol location to obtain source code evidence as needed. Propagation relationships must not be inferred from existing vulnerability labels, remediation patches, or prior audit conclusions.

Exploration should follow the actually configured global tracing depth and priority policy, and must not introduce independent token budgets, LLM call count limits, or other undeclared exploration thresholds.

## II. Backward Exploration State and Action Space

For each tracing branch, organize analysis according to the following logical state:

Sk=(vk,ck,Ek,Vk,dk)

Where:

- v_k: the variable, expression, or program value currently being traced;
- c_k: the current function, call site, and necessary control context;
- E_k: program evidence obtained so far for the current branch;
- V_k: abstract analysis states visited by the current branch;
- d_k: current tracing depth.

The initial state uses the sink sensitive argument as the tracing value, with depth set to 0.

According to the current state, existing evidence, and the exploration scope allowed by priority, dynamically select the following analysis actions:

**1. Local data dependency analysis**

Locate variable definitions and assignments, analyze expression computation, string concatenation, container element access, and data transformations, and identify direct upstream dependencies of the current value.

**2. Interprocedural dependency analysis**

Retrieve function definitions and actual call sites, verify actual-argument-to-parameter mappings, return value propagation, wrapper functions, and cross-file call relationships, and distinguish different call contexts.

**3. Indirect state propagation analysis**

Associate writes and reads of object attributes, dictionary fields, and other state carriers. When necessary, analyze object initialization, state updates, persistent storage, or cross-thread data transfer.

**4. Dynamic call and configuration relationship analysis**

Retrieve dynamic registries, function mappings, callback mechanisms, and configuration-driven indirect call relationships, and verify call targets, registration keys, object types, and related execution conditions.

The above actions are not required to be executed in a fixed order. The agent should select necessary retrieval operations according to currently unresolved program relationships and avoid irrelevant code searches.

## III. Code Evidence Constraints

For each candidate upstream dependency, it must be possible to explain based on actual code:

1. The locations of the current value and the candidate predecessor value;
2. The specific program operation between them;
3. The corresponding assignment, parameter passing, return value, or state read/write relationship;
4. Necessary call context, object association, or execution conditions;
5. The file, line number, and relevant code expression supporting the relationship.

Pay special attention:

- A data dependency must not be established solely because variable names are the same or semantically similar;
- Interprocedural parameter mapping must verify actual call sites and function definitions;
- Object attribute and dictionary field propagation must check relevant objects and read/write relationships;
- Dynamic calls must be combined with registration mappings, configuration conditions, and actual call context;
- A distinction should be made between real data propagation relationships and control conditions or configuration conditions;
- LLM speculation must not be used to fill unconfirmed propagation edges.

When multiple possible predecessors exist for the same value, separate tracing branches should be established, retaining their respective code evidence and necessary execution conditions; mutually incompatible program relationships must not be spliced into the same propagation chain.

## IV. Priority-Aware Dynamic Exploration

Use the High, Medium, and Low initial priorities determined earlier, and dynamically adjust the exploration scope according to newly added program evidence.

**High:** Under the global maximum tracing depth limit, relatively thorough cross-file and interprocedural dependency analysis is allowed, including caller retrieval, parameter mapping, indirect state propagation, and dynamic call relationship recovery.

**Medium:** First perform limited shallow backward tracing. If new evidence such as external input reads, relevant parameter passing, or security-sensitive configuration is found, the priority may be raised and the subsequent exploration scope expanded.

**Low:** First perform limited context inspection or batch shallow analysis. If new evidence supporting deeper analysis is obtained, the priority may be raised to Medium or High. A low initial priority does not constitute a security conclusion.

After each exploration obtains new evidence, determine whether priority should be raised:

p′=Promote(pk,ΔEk)

Where ΔEk is the newly added code evidence.

Priority promotion should have a clear code basis and must not rely solely on subjective model speculation.

If no valid predecessor has yet been obtained but new evidence triggers priority promotion, the current state may be rechecked within the updated exploration scope; if a valid predecessor has been obtained, the updated priority is propagated to the corresponding upstream branch.

The priority policy controls only the analysis actions and exploration scope allowed to be executed, and does not set independent token or LLM call count budgets.

## V. Branch Expansion and Termination

For each tracing branch, continuously perform state checking, code retrieval, candidate predecessor verification, and branch expansion.

Each expansion should:

1. Check whether the current program value and call context constitute a repeated state;
2. Determine whether an identifiable input source or trusted constant has been reached;
3. Record input validation, filtering, encoding, permission control, and other security constraints related to the current propagation relationship;
4. Retrieve upstream predecessors within the scope allowed by the current priority;
5. Adjust exploration priority according to newly added evidence;
6. Update evidence, call context, and tracing depth separately for different predecessors.

Stop the current branch when one of the following conditions is met:

- `SOURCE_REACHED`: a potential external input source supported by code evidence is reached;
- `TRUSTED_SOURCE`: data is confirmed to come from a trusted source not influenced by the outside;
- `EFFECTIVE_SECURITY_CONSTRAINT`: sufficient evidence supports that a security constraint effectively blocks the current risk propagation;
- `NO_PREDECESSOR`: no further predecessor relationship supported by evidence can be established;
- `DEPTH_LIMIT`: the global maximum tracing depth is reached;
- `PRIORITY_SCOPE_LIMIT`: the exploration scope allowed by the current priority cannot be further expanded;
- `CYCLE`: a repeated state or cyclic dependency appears.

When a security constraint is found, record its actual code and applicable conditions. Only when its effectiveness on the current branch can be confirmed based on existing evidence may the branch be terminated with this condition; if effectiveness is uncertain, retain the relevant evidence for inspection in the subsequent vulnerability determination stage.

`NO_PREDECESSOR`, `DEPTH_LIMIT`, `PRIORITY_SCOPE_LIMIT`, and `CYCLE` all indicate unresolved exploration and do not constitute proof of program security.

## VI. Candidate Propagation Chain Construction

When tracing reaches a potential external input source supported by code evidence, reconstruct the candidate propagation chain based on the recovered program relationships:

π=⟨s,v1,…,vn,t⟩

Where s denotes the candidate input source, t denotes the sensitive sink, and intermediate nodes denote program dependencies with actual code evidence.

The candidate propagation chain should be organized in the Source-to-Sink direction and retain:

- Code locations of Source and Sink;
- Key intermediate propagation nodes;
- Code evidence for each dependency edge;
- Interprocedural parameter mapping and return value relationships;
- Dynamic calls, state propagation, and necessary execution conditions;
- Security constraints found along the way;
- Program relationships or execution prerequisites not yet confirmed.

A candidate propagation chain is a semantic dependency reasoning result based on code evidence and is not equivalent to a formally proven executable vulnerability path.

Reaching a potential Source does not mean its attacker controllability has been confirmed, nor does it mean the vulnerability exists.

## VII. Final Output Format

This stage uses **structured JSON output** so that subsequent vulnerability determination tasks can read, review, and use it.

For each candidate sink, preserve its basic information, tracing branches, recovered dependency relationships, relevant evidence, and candidate propagation chains.

Use the following JSON structure:

json

```
{
  "project": {
    "name": "project_name",
    "version": "fixed_version",
    "commit": "fixed_commit"
  },
  "target_cwe": "CWE-78",
  "sink_results": [
    {
      "sink_id": "S1",
      "sink": {
        "file": "relative/path.py",
        "line": 0,
        "function": "function_name",
        "expression": "sink_expression",
        "sensitive_argument": "argument_expression"
      },
      "initial_priority": "High",
      "final_priority": "High",
      "priority_updates": [],
      "branches": [
        {
          "branch_id": "B1",
          "source": {
            "file": "relative/source.py",
            "line": 0,
            "expression": "source_expression",
            "source_type": "potential_external_input",
            "attacker_controllability": "NOT_VERIFIED"
          },
          "dependency_edges": [
            {
              "edge_id": "E1",
              "from": "upstream_expression",
              "to": "downstream_expression",
              "dependency_type": "ARGUMENT_PARAMETER",
              "evidence": [
                {
                  "file": "relative/path.py",
                  "line": 0,
                  "code": "relevant_code_expression"
                }
              ],
              "required_conditions": []
            }
          ],
          "security_constraints": [],
          "termination_reason": "SOURCE_REACHED",
          "unresolved_dependencies": []
        }
      ],
      "candidate_chains": [
        {
          "chain_id": "C1",
          "branch_id": "B1",
          "ordered_edge_ids": ["E1"],
          "status": "CANDIDATE",
          "required_conditions": [],
          "missing_evidence": []
        }
      ]
    }
  ]
}
```



The above is only an output structure example and does not represent analysis results of any actual project. All fields must be filled with data obtained from actual analysis; fictional file locations or propagation relationships in the example must not be copied.

### Field Explanations and Constraints

**1. Sink information**

`sink_id` must be consistent with the prior candidate list.

When one sink has multiple sensitive arguments requiring independent tracing, their tracing results should be stored separately while maintaining association with the original sink.

**2. Priority updates**

Fill `priority_updates` only when priority promotion actually occurs, recording the original priority, new priority, triggering evidence, and reason.

Use an empty array when no promotion occurs.

**3. Dependency edges**

Each dependency edge must correspond to an actual program operation and provide verifiable file locations and code evidence.

`dependency_type` may use:

- `ASSIGNMENT`
- `ARGUMENT_PARAMETER`
- `RETURN_VALUE`
- `OBJECT_STATE`
- `DYNAMIC_DISPATCH`
- `INDIRECT_STATE`

Note that dynamic call relationships should indicate whether they are data propagation edges or merely call-validity conditions, and must not be confused.

**4. Branches**

Each independent tracing branch should have a unique identifier.

For branches that do not reach a Source, `source` should be set to `null`, and the termination reason and unresolved dependencies should be explained via `termination_reason` and `unresolved_dependencies`.

A Source must not be fabricated to complete the JSON.

**5. Security constraints**

Record security-related operations found during tracing, including code locations, target objects, and necessary conditions.

For measures whose effectiveness has not yet been verified, explicitly mark them as `NOT_VERIFIED`.

A propagation chain must not be considered blocked merely because a security check exists.

**6. Candidate chains**

Organize only propagation relationships that are supported by actual code evidence and have been traced to a potential Source as candidate propagation chains.

`ordered_edge_ids` must be arranged in the Source-to-Sink direction and must correspond to actual dependency edges of the associated branch.

Dependency edges that have not yet been established must not be added to a complete candidate propagation chain.

**7. Evidence and uncertainty**

When evidence is missing, use `null`, empty arrays, or explicit unresolved statements; code locations, propagation relationships, or execution conditions must not be fabricated.

Strings in the JSON may use concise natural language to explain necessary code semantics.

### Output Consistency Check

Before final output, check:

1. Does each candidate sink retain its original identifier and priority?
2. Does each dependency edge have actual code evidence?
3. Is the termination reason of each branch clear?
4. Does each priority promotion correspond to newly added evidence?
5. Can the candidate propagation chain be reconstructed from the recorded dependency edges?
6. Are unresolved branches incorrectly represented as complete propagation chains?
7. Is a potential input source directly identified as attacker-controllable?
8. Is the existence of a security constraint equated with confirmed effectiveness?

The final output must be **valid, complete, and parseable JSON**. No additional vulnerability analysis conclusions may be added outside the JSON.