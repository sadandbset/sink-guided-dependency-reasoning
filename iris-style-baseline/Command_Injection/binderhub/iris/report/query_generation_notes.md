# Phase 2 Step 4–5 — Query Generation Notes (Pass 2 / CWE-78, BinderHub)

- run_id: `binderhub-iris-pass2-step3-20261014` (labels) → Step 4–5 generation on 2026-10-14
- inputs: `iris/labels/labels.json` (84 pass-2 entries: 29 source, 5 sink, 25 summary, 0 sanitizer, 25 none), `extraction/sources.csv` (74 rows), `extraction/sinks.csv` (10 rows), real sources under `dataset/codeql_databases/binderhub_vuln/binderhub/` (app.py, base.py, build.py, builder.py, main.py, launcher.py, health.py, registry.py, repoproviders.py — re-read during generation)
- toolchain: CodeQL CLI 2.25.1 (E:\codeql), `codeql/python-all` 7.1.2 from `C:\Users\lzh\.codeql\packages`
- pass key: `command_injection`
- generated artifacts: `qlpack.yml` (iris root, newly created — Step 0 had left pack install pending), `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass2_CommandInjection.ql`, `diagnostics/Pass2_DiagnosticParameter.ql`
- no vulnerability ground truth (confirmed_vulns.json, cmd_sinks.csv, cmd_safe_sinks.csv, vulnerability_audit_final_report.md) was read; original labels, sources and databases were not modified

## 1. Library / query contract

All four libraries expose pass-key-dispatched predicates; the formal query's `Pass2Config implements DataFlow::ConfigSig` delegates to exactly these names and types (verified by compiling both queries):

| library | predicate | signature |
| --- | --- | --- |
| `libraries/MySources` | `MySources::isSource` | `(DataFlow::Node source, string passKey)` |
| `libraries/MySinks` | `MySinks::isSink` | `(DataFlow::Node sink, string passKey)` |
| `libraries/MySanitizers` | `MySanitizers::isBarrier` | `(DataFlow::Node node, string passKey)` |
| `libraries/MySummaries` | `MySummaries::isAdditionalTaintStep` | `(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey)` |

Formal query: `py/augur/binderhub/pass2-command-injection`, `@kind path-problem`, `@problem.severity error`, `@precision medium`, tags `external/cwe/cwe-078` (+ cwe-077, cwe-088), built on `TaintTracking::Global<Pass2Config>` + `import Pass2Flow::PathGraph` + `flowPath`. Diagnostic query: `py/augur/binderhub/pass2-diagnostic-parameter` (same structure, different source model).

## 2. Label → QL mapping (sources, 29/29 modeled)

| QL rule (MySources) | label entries | matching semantics |
| --- | --- | --- |
| `tornadoRequestField` | src-004, 005, 006, 007(+dup 008), 009, 010, 011, 014, 024, 025, 028, 030 | attribute read `X.request.<f>` with `<f>` ∈ {path, uri, headers, host, protocol, remote_ip}; node = the attribute expression |
| `handlerPathParam` | src-015, 016, 037, 038, 043, 044, 045 | parameters at index ≥ 1 of `get` methods whose enclosing class name matches `%Handler` (BuildHandler, ParameterizedMainHandler, LegacyRedirectHandler); node = `parameterNode(p)` |
| `specAccessorCall` | src-017, 039 | call results of `get_spec_from_request` (raw spec sliced from `request.path`) |
| `queryArgumentCall` | src-018, 041, 042 | call results of tornado `get_argument` |
| `externalJsonLoad` | src-053, 056, 063, 070, 073 | `json.loads(...)` call results restricted to `binderhub/repoproviders.py` (external provider API responses for user-chosen repo/ref) |

Notes: the family-level matching (all `X.request.<f>` reads, all `%Handler.get` path params, all `get_argument` calls) intentionally generalizes the specific labeled call sites — each rule is still bounded to the observed shape and to non-test binderhub code (`inBinderHubScope`), so the labels' external-control justification carries over. The consolidated duplicate src-008 adds no separate rule.

## 3. Label → QL mapping (sinks, 5/5 modeled)

| QL rule (MySinks) | label | matching semantics |
| --- | --- | --- |
| `subprocessRunCommand` | snk-010 (tp 0.85) | `subprocess.run(cmd, ...)`, node = positional arg 0 |
| `containerArgsKeyword` | snk-004 (tp 0.80) | `V1Container(args=...)`, node = keyword value (CSV keyword-encoding, arg_index −1 → keyword-name match) |
| `envVarValueKeyword` | snk-002 (candidate 0.50) | `V1EnvVar(value=...)`, node = keyword value |
| `createNamespacedPodBody` | snk-005 (tp 0.75) | `create_namespaced_pod(ns, body, ...)`, node = positional arg 1 |
| `getCmdResult` | snk-003 (candidate 0.70) | call result of `Build.get_cmd()` (repo2docker command list) |

All sink rules are receiver-name-bound (`subprocess.run`, `client.V1Container`, `self.api.create_namespaced_pod`, `self.get_cmd`) and scoped to non-test binderhub code.

## 4. Label → QL mapping (summaries, 25/25 modeled as additional taint steps)

| QL rule (MySummaries) | label entries | edge modeled |
| --- | --- | --- |
| `providerConstructionStep` | src-019, src-040 | `get_provider(prefix, spec=…)` → returned provider object (traitlets `spec` kwarg boundary, invisible to dataflow) |
| `specDerivedAttributeStep` | src-020..027, src-049..052, src-054/055, src-057/058, src-059/060, src-064/065, src-069/071/072/074 (22 entries) | tainted object → read of its spec-derived attribute (`spec`, `url`, `repo`, `unresolved_ref`, `quoted_namespace`, `namespace`, `user`, `gist_id`, `record_id`, `resource_id`, `identifier`, `resolved_ref`, `resolved_spec`, `resolved_ref_url`) or Build command field (`ref`, `repo_url`, `image_name`, `appendix`, `git_credentials`) |
| `executorDispatchStep` | snk-006 | `build_pool.submit(build.submit)` → `self` parameter of `Build.submit` (worker-thread invocation semantics) |

## 5. Model refinements beyond the literal label set (code-evidence-based, documented)

Two additional steps were required to make the sink labels' asserted reachability actually traceable; both are conditional on concrete call shapes and were justified by re-reading the sources (not by inventing propagation):

| QL rule | evidence | why needed |
| --- | --- | --- |
| `buildConstructionStep` | builder.py:404-422 `BuildClass(..., repo_url=repo_url, ref=ref, image_name=image_name, appendix=appendix, git_credentials=...)`; build.py:40-142 `Build.__init__` stores these kwargs as attributes consumed by `get_cmd`/`submit` | `BuildClass = self.settings.get('build_class')` is a settings-dict dispatch, so default call resolution cannot link the tainted keyword arguments to the constructor. Without this step snk-003/004/005 are unreachable. |
| `kubeModelStep` | build.py:327-373 `client.V1Pod(... V1PodSpec(containers=[client.V1Container(args=self.get_cmd(), ...)]) ...)`; kubernetes.client models are attribute-holder DTOs (library code not in the DB) | taint must travel from the `V1Container(args=…)` keyword into the constructed pod object to reach `create_namespaced_pod` arg 1 (snk-005). |

Both steps restrict to keyword names that are provably command-construction inputs, so no unconditional propagation is introduced.

## 6. Exclusions (auditable)

- **25 role=none entries** are not modeled anywhere: operator environment variables (JUPYTERHUB_*, GITHUB_*/GITLAB_* tokens, BINDERHUB_BUILD_TOKEN_SECRET, DOCKER_CONFIG) and cluster-internal `json.loads` (k8s pod lists, JupyterHub user data, registry auth/manifests). Rationale: trusted server-side configuration/infrastructure — no external control (labels: fp).
- **Sanitizers**: `MySanitizers::isBarrier` returns `none()` — no sanitizer candidates were extracted or labeled. `sha1_validate`, `_safe_build_slug`, `tokenize_spec` are sanitizer-shaped but unlabeled; they are recorded in the library header as advisory only and were deliberately NOT turned into barriers (no label evidence; sha1_validate does not guard the `git ls-remote` inputs anyway).
- **snk-002 (V1EnvVar.value)** is modeled as a sink but is expected to stay cold in the formal query: its only call site passes `provider.git_credentials`, built from operator tokens (src-061/062/066-068 are role=none). It was kept because the label is `candidate` (recall-oriented); any future alert there would be a new finding, not a false positive of this run.
- **Pass 1 placeholder** in labels.json is not compiled into any library rule (pass key dispatch: only `command_injection` is active).
- **src-027/`get_build_slug` → pod-name path** and the `_safe_build_slug` escaping: no dedicated step; image-name flow relies on default `str.format` modeling and `specDerivedAttributeStep` on `image_name` reads inside `Build`.

## 7. Uncovered APIs / known limitations

1. **Call-resolution dependence.** `provider.get_resolved_ref()` etc. rely on CodeQL's name-based dynamic dispatch to bind receivers to `self` parameters across the provider classes; if resolution is narrower than expected, some paths shorten but the direct attribute-step paths remain.
2. **Appendix flow** (`settings['appendix'].format(repo_url=…, ref_url=…)`) depends on default `str.format` taint modeling; if the installed library version does not propagate through `format(**kwargs)`, the `--appendix` element contributes no alerts (repo_url/ref/`--ref` paths are unaffected).
3. **`specDerivedAttributeStep` is name-based**, not type-based: it applies to any in-scope attribute read with those names. Within binderhub the name set is confined to provider/Build fields (verified by reading the code), but renames in future revisions would silently weaken the model.
4. **`executorDispatchStep`** binds only `Build.submit` (class name + method name + bound-method argument named `submit`); `pool.submit(build.stream_logs)` (snk-007, role none) is intentionally not modeled, and `self.executor.submit(lambda: Build.cleanup_builds(...))` (snk-001, role none) cannot match because argument 0 is a lambda.
5. **No argument-position sinks for k8s keywords in the CSV encoding** (`arg_index = -1`): represented as keyword-name matches; if future extraction switches to real keyword indices, `MySinks` should switch to `getKeyword`-style positional matching.
6. **Alert volume expectations**: formal sources include low-specificity boundary entries kept per the labels' conservative recall (request.host/remote_ip, json.loads of provider API responses). Paths from these reach sinks only via the same provider pipeline, so no new sink families are opened; the human review gate (phase1_review.md §3/§5) already lists them for possible downgrading after the first run.
7. **Diagnostic query semantics**: `diagnostics/Pass2_DiagnosticParameter.ql` swaps the source model for internal parameters (`Build.__init__` keyword-only command fields; `BaseHandler.get_provider` spec parameter). Its alerts mean "this internal parameter reaches a command sink" — reachability evidence only, NOT external control, and must not be counted as formal vulnerability findings.

## 8. Compile validation record (WORKFLOW.md 3.1.1)

```
codeql query compile iris/queries/Pass2_CommandInjection.ql --search-path C:\Users\lzh\.codeql\packages
  -> Done [1/1 comp 13.5s]; 1 warning: unused variable 'node' (MySanitizers.qll:28) — harmless, the barrier predicate keeps its passKey contract.

codeql query compile iris/diagnostics/Pass2_DiagnosticParameter.ql --search-path C:\Users\lzh\.codeql\packages
  -> Done [1/1 comp 13.9s]; same single warning.
```

Errors found and fixed during generation (matching the previously-encountered compile-error classes):

1. `from`/`to` are QL reserved keywords — parameter names in `MySummaries::isAdditionalTaintStep` renamed to `nodeFrom`/`nodeTo` (the template's own naming, which is why the template avoids `from`).
2. Dotted module paths (`libraries.MySources::isSource(...)`) are not valid in expressions — QL expression qualification is `Module::member` only. Fixed by wrapping each QLL's contents in `module <Name> { ... }` (file `libraries/MySources.qll` → module `MySources`, mirroring `semmle/python/dataflow/new/DataFlow.qll` → `DataFlow`) and calling `MySources::isSource(...)` in the queries. Import statements keep the dotted path form `import libraries.MySources` (valid in imports, resolves pack-root-relative to `iris/libraries/MySources.qll` with `qlpack.yml` at the iris root).
3. No QL classes are defined anywhere in the generated code (predicates only), so no parent-type / unbound-`this` class errors are possible; `AstNode.getFile()` is not used (locations go through `getLocation().getFile().getRelativePath()`, the idiom already validated by the Step 2 extraction queries).

Per the run instructions, the queries were only compiled, never executed against the database; Step 5's `codeql database analyze` runs are left for the next stage.
