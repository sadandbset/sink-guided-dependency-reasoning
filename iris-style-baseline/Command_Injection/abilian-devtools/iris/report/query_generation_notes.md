# Query Generation Notes — abilian-devtools, Pass 2 (CWE-78)

Augur Phase 2, Step 4 (library generation) + Step 5 (query file generation).

- **Generated at**: 2026-10-14 (session)
- **Labels input**: `iris/labels/labels.json` (run_id `abilian-devtools-iris-pass2-step3-20261014`, human-reviewed)
- **Scope**: Pass 2 only, CWE-78 only (narrowed from Augur's default 077/078/088, consistent with the autogluon and bikeshed experiments)
- **Evidence base**: CodeQL DB creation-time source snapshot (`abilian-devtools-db/src.zip`), which is the code the queries actually run against. The on-disk `src/` tree diverges from the snapshot (see labels.json metadata) and was not used as modeling evidence.
- **Toolchain**: CodeQL CLI 2.25.1, `codeql/python-all 7.0.4` (pinned in `iris/qlpack.yml`)
- **Status**: files generated only; compilation and execution are performed manually by the analyst.

## 1. Generated files

| File | Content |
| --- | --- |
| `iris/libraries/MySources.qll` | `MySources::isSource(node, passKey)` — Pass 2 sources |
| `iris/libraries/MySinks.qll` | `MySinks::isSink(node, passKey)` — Pass 2 sinks |
| `iris/libraries/MySanitizers.qll` | `MySanitizers::isBarrier(node, passKey)` — resolves to `none()` |
| `iris/libraries/MySummaries.qll` | `MySummaries::isAdditionalTaintStep(from, to, passKey)` — resolves to `none()` |
| `iris/queries/Pass2_CommandInjection.ql` | Official path-problem query (`@kind path-problem`, severity error) |
| `iris/diagnostics/Pass2_DiagnosticParameter.ql` | Diagnostic-only companion (not a vulnerability result) |

All four libraries live in `iris/libraries/` and are imported from the query with dotted imports (`import libraries.MySources` etc.), resolved against the qlpack root `iris/`.

## 2. Pass key

All pass-2 dispatch uses the normalized pass key `"command_injection"`. Pass 1 is a schema placeholder in labels.json with an empty entries array and dispatches to no models in any library.

## 3. Label → QL model mapping

| Label ID | Role / class | Confidence | Signature (module / callable / arg / kind) | QL model | Source location |
| --- | --- | --- | --- | --- | --- |
| `p2-supp-001` | source / tp | 0.80 | `devtools.main` / `check` / arg 0 / param | `DataFlow::parameterNode(p)` where `p` is parameter 0 of function `check` in module `abilian.devtools.main`, constrained to a Typer `@app.command()`-family decorator | `src/abilian/devtools/main.py:22` (def; decorator at :21) |
| `p2-sink-001` | sink / tp | 0.90 | `os` / `system` / arg 0 / argument | command argument of any `os.system` call via `API::moduleImport("os").getMember("system").getACall()`, arg 0 or keyword `command` | `src/abilian/devtools/main.py:16` |
| `p2-sink-002` | sink / tp | 0.85 | `devtools.main` / `run` / arg 0 / param (CSV `-1` refined to 0) | `DataFlow::parameterNode(p)` where `p` is parameter 0 of function `run` in module `abilian.devtools.main` | `src/abilian/devtools/main.py:14` |

No sanitizer labels and no summary labels exist for Pass 2; the corresponding library predicates exist and resolve to `none()`.

## 4. Modeling decisions

### 4.1 Source (p2-supp-001)

- Modeled as the **single labeled parameter**, not as "all function parameters": matching requires module name `abilian.devtools.main`, function name `check`, positional parameter 0, and a Typer command/callback registration decorator on the function. Nothing else in the database matches.
- The decorator constraint encodes the actual boundary justification (Typer injects CLI arguments into `@app.command()` handler parameters; console script `adt = abilian.devtools.main:app`). Both the `Call` form (`@app.command()`, the form present here) and the bare `Attribute` form are accepted — this is the exact shape mismatch that caused the Phase 1 extraction miss (sources.csv empty), and the library does not repeat it.
- The parameter node is obtained with `DataFlow::parameterNode(p)` (AST `Parameter` → `DataFlow::Node`), the public conversion used by the framework libraries; `API::Node`/`asSource()` is not applicable because `check` is a project-internal function, not an external-library entry point (API-graph nodes are only created at external boundaries).

### 4.2 Sinks (p2-sink-001, p2-sink-002)

- **Danger levels are differentiated, not uniform over "all subprocess calls"**:
  - `os.system` argument is modeled because its command string is unconditionally shell-interpreted (`/bin/sh -c`), matching the label's tp rationale.
  - No other process API (subprocess family, `os.popen`, `asyncio.create_subprocess_*`, `shell=True`) is modeled: no label marks any of them, and the DB snapshot grep confirms `os.system` (main.py:16) is the only command-execution call in the database.
  - `run`'s parameter 0 is a **param-level wrapper sink for recall** (labeled tp 0.85): it forwards verbatim to `os.system`. It is nested with p2-sink-001, not an alternative danger level. In the current snapshot a tainted path will typically surface at both sinks (parameter node of `run` and argument of `os.system`).
- The `os.system` argument position accepts positional arg 0 **or** keyword `command`, mirroring the standard library's own `OsSystemCall` modeling in `Stdlib.qll`.
- The sink uses `API::moduleImport("os").getMember("system").getACall()` and then `DataFlow::CallCfgNode.getArg(0)` — an explicit `DataFlow::Node` — keeping the `API::Node` → `DataFlow::Node` boundary at a single, standard conversion point.

### 4.3 Barrier (MySanitizers)

- No sanitizer was labeled. `isBarrier` exists in the library and in the query config and resolves to `none()` (WORKFLOW.md 5.2.3 mandatory barrier hook).
- `Path(arg).exists()` (main.py:25-29) was reviewed during labeling and is deliberately **not** a barrier: it is an existence filter only and performs no command sanitization. Recording this here so a future reader does not "helpfully" add it.

### 4.4 Additional flow steps (MySummaries)

- No summary was labeled, so `isAdditionalTaintStep` resolves to `none()`; no always-true step was fabricated.
- Every glue point on the labeled source→sink path was checked against the `python-all` taint library and is already covered by built-in steps:
  - `for arg in args` — standard iteration step;
  - `args2.append(arg)` — `list.append` flow summary (element → list);
  - `args_str = ' '.join(args2)` — `str.join` taint step (iterable → result);
  - f-string interpolation (main.py:33-34) — formatted-string step;
  - `check` → `run` → `os.system` — interprocedural taint tracking.
  The single f-string-relevant caveat is recorded in the labels themselves: `run("mypy --show-error-codes {args_str}")` (main.py:35) is a plain string, not an f-string, so it is not a tainted call site.

## 5. Query metadata

`iris/queries/Pass2_CommandInjection.ql`:

- `@kind path-problem`, `@problem.severity error`
- `@id py/augur/abilian-devtools/pass2-command-injection` (stable, project-scoped)
- `@tags security`, `external/cwe/cwe-078`
- `@precision medium` — narrow source/sink, but includes the recall-oriented param-level wrapper sink
- Data flow: `DataFlow::ConfigSig` (`Pass2Config`) + `TaintTracking::Global<Pass2Config>` (`Pass2Flow`) + `import Pass2Flow::PathGraph`, `flowPath(source, sink)`
- All four config predicates delegate to the generated libraries with the pass key `"command_injection"`.

## 6. Diagnostic query

`iris/diagnostics/Pass2_DiagnosticParameter.ql` is a **separate** `@kind problem` / severity `warning` query (distinct id `py/augur/abilian-devtools/pass2-diagnostic-parameter`, `@tags diagnostics`). It reuses the identical taint configuration and reports each sink node reachable from the internal parameter source, with the source node rendered into the message. It imports no `PathGraph` and is not a path-problem, so it cannot be confused with, or merged into, the official Pass 2 vulnerability results. Purpose: if the official query returns zero findings, run this first — an empty diagnostic means the source or sink model matches nothing (e.g. a refactor renamed `check`/`run` or changed the decorator shape), while a non-empty diagnostic with an empty official query would point to a flow-configuration problem instead.

## 7. Expected result shape (from the label evidence, not from execution)

For the current DB snapshot the labeled evidence predicts: the `check` parameter source reaches both modeled sinks via the f-string call sites at main.py:33-34 (`ruff`/`flake8`); the literal call sites (main.py:35-38, 44-45, 54) and `all()` → `check(["src", "tests"])` (main.py:60) are untainted. Sink-side, expect up to two path results per tainted call site (argument of `os.system` and parameter of `run`). This is a prediction for sanity-checking the run, not a confirmed vulnerability claim.

## 8. Historical-error checklist (how each was avoided)

1. **Dotted imports**: libraries import as `import libraries.MySources` / `MySinks` / `MySanitizers` / `MySummaries` — no slash-style imports anywhere.
2. **`API::Node` vs `DataFlow::Node`**: the only API-graph use is `moduleImport("os").getMember("system").getACall()`, immediately converted to `DataFlow::Node` via `CallCfgNode.getArg`/`getArgByName`; sources use `DataFlow::parameterNode`, not `API::Node.asSource()` (internal function, not an external entry point).
3. **File paths**: no `AstNode.getFile()`; no file-path constraint is needed at all — module identity is constrained via `Function.getEnclosingModule().getName()`.
4. **QL classes**: no classes are declared in the libraries; only predicates with `exists`-bound bodies, so there are no parentless classes and no unbound `this`.
5. **No blanket parameter sources**: exactly one parameter of one labeled function is a source.
6. **Sink danger differentiation**: only `os.system`'s command argument (plus the labeled wrapper parameter) is a sink; the subprocess family is deliberately absent with the reason documented in the library header.
7. **`isBarrier` exists** in both the library and the query config and resolves to `none()`.
8. **No fabricated `isAdditionalFlowStep`**: the summary predicate resolves to `none()`; built-in coverage of every observed glue point is documented instead.

## 9. Manual execution (for the analyst)

```bash
cd iris
codeql pack install

# diagnostic first (optional, not a vulnerability result)
codeql query run diagnostics/Pass2_DiagnosticParameter.ql \
  --database <DB> --output diagnostics/pass2_diagnostic.bqrs
codeql bqrs decode diagnostics/pass2_diagnostic.bqrs --format=csv

# official pass 2 query (sequential, single query at a time)
codeql database analyze <DB> queries/Pass2_CommandInjection.ql \
  --format=sarifv2.1.0 --output results/pass2.sarif
```

with `<DB>` = `C:\Users\lzh\Desktop\github\PyVul-main\dataset\codeql_databases\abilian-devtools-db`.

## 10. Post-run correction (2026-10-14, review session)

The first execution of the official query produced **0 results** (empty SARIF kept
at `results/pass2.sarif.empty-backup`), contradicting the §7 prediction. Root
cause, verified by diagnostic runs against the DB:

- `MySources.qll` (source) and `MySinks.qll` (`run` wrapper sink) constrained the
  enclosing module name to `"abilian.devtools.main"` — the *import path*.
  CodeQL derives module names from the DB source root (`.../src/abilian`), so
  `Function.getEnclosingModule().getName()` is `"devtools.main"` for every
  function in this database. The constraint matched nothing: the source model
  bound 0 nodes, so `flowPath` could never hold.
- The label signature and `sinks.csv` always said `devtools.main` (correct);
  the fully-qualified form was introduced during Step 4 library generation
  without DB verification.

Correction applied: both module constraints changed to `"devtools.main"`
(one string each; documented in the `.qll` file headers). Rerun results:

- Diagnostic query: 2 paths, source `args` (main.py:22) → sink `cmd`.
- Official query: **2 results**, matching the §7 prediction exactly —
  result 1 at main.py:14 (`run` param sink), result 2 at main.py:16
  (`os.system` arg sink); each carries 2 code flows through the tainted
  f-string call sites at main.py:33 (`ruff`) and main.py:34 (`flake8`).
  The plain-string call site at main.py:35 (`mypy`) is correctly absent.

`iris_report.md` predates this correction and still reports zero findings; it
needs regeneration from the corrected `results/pass2.sarif`.

Lesson recorded for WORKFLOW: never rewrite DB-extracted location hints
(module names) into "more canonical" forms without a 10-second
`select f.getEnclosingModule().getName()` verification against the target DB,
and treat an official-query zero-result that contradicts the predicted result
shape as a hard stop that must be reconciled (the §6 diagnostic query exists
precisely for this and had never been run).
