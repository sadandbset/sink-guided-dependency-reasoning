# Phase 1 Step 3 - Human Review Payload (Pass 2 / CWE-78)

- run_id: `binderhub-iris-pass2-step3-20261014`
- generated_at: 2026-10-14T11:03:24Z
- model: glm-5.3 (Z.ai GLM), labeled in-session via Claude Code CLI; single-pass batches; temperature unset (harness default). Deviations from the WORKFLOW.md 4.4.3/7.3 prompt contract are recorded in `labels_raw_pass2.json` → `deviations`.
- scope: Pass 2 only (CWE-077/078/088, CWE-78 primary). Pass 1 exists in `labels.json` as an empty placeholder required by the schema.
- ground-truth isolation: no PyVul vulnerability truth files in the source tree (`confirmed_vulns.json`, `cmd_sinks.csv`, `cmd_safe_sinks.csv`, `vulnerability_audit_final_report.md`) were consulted. All rationale is derived from the binderhub sources themselves.

## 1. Label counts by pass and role

| pass | entries | source | sink | sanitizer | summary | none |
| --- | --- | --- | --- | --- | --- | --- |
| 1 (placeholder, out of scope) | 0 | - | - | - | - | - |
| 2 (Command/Argument Injection) | 84 | 29 | 5 | 0 | 25 | 25 |

Classification: 8 tp, 51 candidate, 25 fp, 0 unknown.

All 74 `sources.csv` rows and 10 `sinks.csv` rows produced exactly one entry (84/84 row parity across the 5 batches; one exact duplicate CSV row consolidated, `src-008` → `src-007`).

**Reading of the counts**: `tp`/`candidate` never asserts a confirmed vulnerability — `tp` only means the API genuinely plays its labeled role for pass 2 (real sink fed by request data, real request-boundary source).

## 2. Top high-risk sink APIs

| id | signature | class | conf | why it matters |
| --- | --- | --- | --- | --- |
| snk-010 | `subprocess.run` arg 0 @ `binderhub/repoproviders.py:488` | tp | 0.85 | The only local process execution in the non-test package: `git ls-remote <repo> <ref>` with both arguments taken from the URL-decoded user spec (GitRepoProvider). List-form, no `shell=True` → argument-injection class (CWE-78 family), not shell metacharacter injection. `sha1_validate` covers the resolved output, not the inputs. |
| snk-004 | `V1Container.args` @ `binderhub/build.py:343` | tp | 0.80 | Container argv = `Build.get_cmd()`; request-derived `--ref`, `--appendix`, `--image` and trailing `repo_url` are embedded as separate argv elements executed by the build pod. |
| snk-005 | `create_namespaced_pod` arg 1 @ `binderhub/build.py:376` | tp | 0.75 | Submission of the pod body (embedding argv + env) to the Kubernetes API — the execution submission point. |
| snk-003 | `Build.get_cmd` return @ `binderhub/build.py:343` | candidate | 0.70 | Wrapper returning the full repo2docker argv; precise intermediate alert point on the command payload. |
| snk-002 | `V1EnvVar.value` @ `binderhub/build.py:325` | candidate | 0.50 | Env injection into the build pod (`GIT_CREDENTIAL_ENV`); current value is server-side credential config — retained for recall only. |

End-to-end flow the labels encode: `request.path` → `get_spec_from_request` → provider spec → `GitRepoProvider` unquote → **`git ls-remote` argv** (snk-010), and provider accessors → `Build(ref/repo_url/appendix/image_name)` → `get_cmd()` → **container argv / pod submission** (snk-003/004/005).

## 3. Top broad source APIs

| id | signature | class | conf | note |
| --- | --- | --- | --- | --- |
| src-015/016 | `BuildHandler.get` params 1/2 @ `builder.py:223` | tp | 0.90 | `/build/<provider_prefix>/<spec>` URL path captures — the root attacker input of the build flow. |
| src-010/011 | `request.path` @ `base.py:155-156` | tp | 0.85 | Raw request path sliced into the spec (kept un-unquoted deliberately). |
| src-017 | `get_spec_from_request` return @ `builder.py:239` | tp | 0.85 | Canonical raw-spec accessor on the request boundary. |
| src-025 | `request.host` @ `builder.py:311` | candidate | 0.65 | Host header → `binder_launch_host` → appendix → `--appendix` argv. |
| src-070/063/073 | `json.loads` of GitHub/GitLab/Gist API responses | candidate | 0.6-0.65 | External API responses for user-chosen repo/ref; `sha`/`id` become `Build.ref`. |
| src-037/038 | `ParameterizedMainHandler.get` params @ `main.py:48` | candidate | 0.75 | Same input family on `/v2/...`; this handler itself has no command sink. |

Rejected source families (role=none, 25 entries): operator environment variables (`JUPYTERHUB_*`, `GITHUB_*/GITLAB_*` tokens, `BINDERHUB_BUILD_TOKEN_SECRET`, `DOCKER_CONFIG`), and `json.loads` on cluster-internal responses (Kubernetes pod lists, JupyterHub user data, docker registry auth/manifests) — trusted server-side configuration and infrastructure, per the required distinction between user-controlled identifiers/refs/HTTP input and trusted service configuration.

## 4. Sanitizer list

None labeled — the extraction CSVs contained no sanitizer-shaped candidates. Advisory for a future extraction pass: `RepoProvider.sha1_validate`, `_safe_build_slug`/`_generate_build_name` (escapism escaping) and `tokenize_spec` are sanitizer-shaped helpers in the source. The list-form (no-shell) invocation at `repoproviders.py:488` is itself the primary shell-metacharacter defense and is recorded in the sink rationale rather than as a separate sanitizer entry.

## 5. Unresolved / low-confidence items (confidence <= 0.55)

Strictly below the 0.55 WORKFLOW threshold: `src-058` (0.50) and `snk-002` (0.50). The 0.55 entries below sit at the boundary and are listed for reviewer attention:

| id | signature | role | conf | concern |
| --- | --- | --- | --- | --- |
| src-058 | `HydroshareProvider.get_repo_url` @ `repoproviders.py:433` | summary | 0.50 | Second-order use (ref URL → appendix); resource id is regex-constrained to 32 hex chars. |
| src-007 | `request.headers` @ `base.py:93` | source | 0.55 | Log-only enrichment of a token-origin mismatch message. |
| src-014 | `request.uri` @ `builder.py:154` | source | 0.55 | Log-only use on stream close. |
| src-028/030 | `request.host` @ `builder.py:382/497` | source | 0.55 | Event-log 'origin' field only. |
| src-045 | `LegacyRedirectHandler.get` urlpath @ `main.py:127` | source | 0.55 | Redirect query-param use only. |

Also flagged: several `repoproviders.py` CSV rows report line numbers inside a neighboring accessor of the CSV-named callable (details in `labels_raw_pass2.json` → `deviations`); the callable was kept for traceability with the enclosing method recorded in evidence.

## 6. Review decision guidance

Per WORKFLOW.md 4.5 this is the advisory checkpoint before Phase 2 (Step 4 library generation). Recommended reviewer actions:

1. Confirm the sink set (section 2) is acceptable for query generation — in particular whether `snk-002` (V1EnvVar.value, low confidence) and the `summary`-role dispatch entry `snk-006` should carry into `MySinks.qll`/`MySummaries.qll`.
2. Confirm the `summary` labeling of provider accessors (25 entries) as additional taint steps — this is what makes the spec → `git ls-remote` / repo2docker argv paths reachable.
3. Decide whether the low-confidence boundary sources (section 5) should be dropped to reduce alert volume, or kept for conservative recall.
4. Note that no sanitizer library content will be generated (`MySanitizers.qll` will fall back to `none()`), and `isBarrier` must still be emitted per WORKFLOW.md 3.6.

Status: **awaiting human review** — this run stops after Step 3 as instructed; Phase 2 was not started.
