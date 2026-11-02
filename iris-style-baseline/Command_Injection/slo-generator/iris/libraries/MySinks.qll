/**
 * Name: MySinks (Augur Phase 2 Step 4 - generated taint sink library)
 * Description: Sink predicates for Pass 2 / CWE-78 (Command Injection) of the
 *   slo-generator target, rendered deterministically from the reviewed
 *   Phase 1 labels in iris/labels/labels.json
 *   (run `slo-generator-iris-pass2-cwe78-20261016`, LLM model glm-5.3,
 *   12 `sink` entries, all classification `candidate`).
 *
 * Modeling note (important): the target snapshot contains ZERO OS
 * command-execution call sites (no subprocess / os.system / os.popen /
 * exec* / spawn* / shell=True anywhere in the source tree). The labeled CWE-78
 * sinks are therefore the config-controlled name-resolution and
 * dynamic-dispatch boundaries:
 *
 *   1. getattr(name-argument) sinks   - a config-derived string selects a
 *      member that is subsequently invoked (K033, K041, K020, K023, K026);
 *   2. the dynamic-import sink        - importlib.import_module(module-path)
 *      (K042);
 *   3. dispatch-invocation sinks      - invocation of a name-resolved
 *      callable, modeled as "tainted data reaching any argument of the
 *      anchored call" (K034, K032, K014, K022, K025, K028).
 *
 * Every branch is anchored to the label's verified source location
 * (file relative path + start line) and its structural shape (callee name /
 * argument index). All sinks are `candidate` grade: a finding from these
 * predicates is a triage candidate, not a confirmed vulnerability.
 *
 * Label -> predicate mapping and per-entry evidence:
 *   see iris/report/query_generation_notes.md.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {

  /**
   * Holds if `loc` is located in the file whose path relative to the analyzed
   * source root is `relpath` (with an absolute-path fallback anchored to the
   * database sourceLocationPrefix).
   */
  private predicate inFile(Location loc, string relpath) {
    loc.getFile().getRelativePath() = relpath
    or
    loc.getFile().getAbsolutePath() =
      "C:/Users/lzh/Desktop/github/PyVul-main/dataset/codeql_databases/slo-generator_vuln/" + relpath
  }

  /** Holds if `loc` starts at `line` in the file matching `relpath`. */
  private predicate at(Location loc, string relpath, int line) {
    inFile(loc, relpath) and
    loc.getStartLine() = line
  }

  /** Holds if `c` is a call to the builtin `getattr`. */
  private predicate getattrCall(Call c) {
    c.getFunc().(Name).getId() = "getattr"
  }

  /** Gets a positional, keyword or **-unpacked argument expression of `c`. */
  private Expr anArgument(Call c) {
    result = c.getAnArg()
    or
    result = c.getANamedArg().(Keyword).getValue()
    or
    result = c.getANamedArg().(DictUnpacking).getValue()
  }

  /**
   * getattr name-argument sinks: a config-derived string selects a member on
   * a module or instance, and the selected member is invoked.
   */
  private predicate getattrNameSink(DataFlow::Node sink) {
    exists(Call c |
      // K033 (candidate, 0.70): report.py:204 - method = getattr(instance, method);
      // method name read from request-controlled config['spec']['method']
      // (report.py:193, no allowlist) and invoked at report.py:216.
      getattrCall(c) and
      at(c.getLocation(), "slo_generator/report.py", 204) and
      sink = DataFlow::exprNode(c.getArg(1))
    )
    or
    exists(Call c |
      // K041 (candidate, 0.60): utils.py:337 - getattr(importlib.import_module(package), name)
      getattrCall(c) and
      at(c.getLocation(), "slo_generator/utils.py", 337) and
      sink = DataFlow::exprNode(c.getArg(1))
    )
    or
    exists(Call c |
      // K020 (candidate, 0.50): migrator.py:78 - getattr(sys.modules[__name__],
      // f"ebp_v1to{version}") - name from fixed 'v1' + CLI --version
      getattrCall(c) and
      at(c.getLocation(), "slo_generator/migrations/migrator.py", 78) and
      sink = DataFlow::exprNode(c.getArg(1))
    )
    or
    exists(Call c |
      // K023 (candidate, 0.50): migrator.py:87 - getattr(..., f"exporters_v1to{version}")
      getattrCall(c) and
      at(c.getLocation(), "slo_generator/migrations/migrator.py", 87) and
      sink = DataFlow::exprNode(c.getArg(1))
    )
    or
    exists(Call c |
      // K026 (candidate, 0.55): migrator.py:139 - getattr(..., f"slo_config_{curver}to{version}")
      // curver derived from the input file's apiVersion field
      getattrCall(c) and
      at(c.getLocation(), "slo_generator/migrations/migrator.py", 139) and
      sink = DataFlow::exprNode(c.getArg(1))
    )
  }

  /**
   * Dynamic-import sink: the module path argument of
   * importlib.import_module, built from the config-derived class name
   * (utils.import_cls, plugin names imported verbatim, no allowlist).
   */
  private predicate dynamicImportSink(DataFlow::Node sink) {
    exists(Call c, Attribute fn, Expr arg |
      // K042 (candidate, 0.65): utils.py:337 - importlib.import_module(package)
      c.getFunc() = fn and
      fn.getName() = "import_module" and
      fn.getObject().(Name).getId() = "importlib" and
      at(c.getLocation(), "slo_generator/utils.py", 337) and
      arg = c.getArg(0) and
      sink = DataFlow::exprNode(arg)
    )
  }

  /**
   * Dispatch-invocation sinks: invocations of name-resolved callables. A
   * label with flow kind `dispatch_invocation` marks the call site itself;
   * the taint-relevant event is tainted data entering a call whose callee
   * was selected by name, so the sink nodes are the argument expressions of
   * the anchored call.
   */
  private predicate dispatchInvocationSink(DataFlow::Node sink) {
    exists(Call c, Expr arg |
      // K034 (candidate, 0.65): report.py:216 - method(self.timestamp, self.window, config)
      c.getFunc().(Name).getId() = "method" and
      at(c.getLocation(), "slo_generator/report.py", 216) and
      arg = anArgument(c) and
      sink = DataFlow::exprNode(arg)
    )
    or
    exists(Call c, Expr arg |
      // K032 (candidate, 0.60): report.py:203 - cls(client=client, **backend_cfg)
      c.getFunc().(Name).getId() = "cls" and
      at(c.getLocation(), "slo_generator/report.py", 203) and
      arg = anArgument(c) and
      sink = DataFlow::exprNode(arg)
    )
    or
    exists(Call c, Expr arg |
      // K014 (candidate, 0.60): compute.py:119 - instance().export(data, **config)
      c.getFunc().(Attribute).getName() = "export" and
      at(c.getLocation(), "slo_generator/compute.py", 119) and
      arg = anArgument(c) and
      sink = DataFlow::exprNode(arg)
    )
    or
    exists(Call c, Expr arg |
      // K022 (candidate, 0.50): migrator.py:79 - ebp_func(ebp_paths, ...)
      c.getFunc().(Name).getId() = "ebp_func" and
      at(c.getLocation(), "slo_generator/migrations/migrator.py", 79) and
      arg = anArgument(c) and
      sink = DataFlow::exprNode(arg)
    )
    or
    exists(Call c, Expr arg |
      // K025 (candidate, 0.50): migrator.py:89 - exporters_func(exporters_paths, ...)
      c.getFunc().(Name).getId() = "exporters_func" and
      at(c.getLocation(), "slo_generator/migrations/migrator.py", 89) and
      arg = anArgument(c) and
      sink = DataFlow::exprNode(arg)
    )
    or
    exists(Call c, Expr arg |
      // K028 (candidate, 0.55): migrator.py:141 - slo_func(slo_config, ...)
      c.getFunc().(Name).getId() = "slo_func" and
      at(c.getLocation(), "slo_generator/migrations/migrator.py", 141) and
      arg = anArgument(c) and
      sink = DataFlow::exprNode(arg)
    )
  }

  /**
   * Unsafe-deserialization sinks (v2 post-triage remediation):
   * yaml.load called with an unsafe Loader (yaml.Loader / yaml.UnsafeLoader /
   * yaml.FullLoader). Both PyYAML's and ruamel.yaml's full loaders construct
   * arbitrary Python objects from !!python/* tags while parsing, so
   * deserializing crafted YAML is code execution inside the slo-generator
   * process (CWE-502-class boundary; the CWE-78-recorded impact for this
   * project). The taint-relevant event is the stream argument (arg 0)
   * reaching the unsafe loader. `from ruamel import yaml` and
   * `import yaml` both bind the Name `yaml`, so the AST-shape match covers
   * both bindings.
   */
  private predicate unsafeYamlLoadSink(DataFlow::Node sink) {
    exists(Call c, Attribute fn, Keyword kw, Attribute loader |
      // K043 (tp, 0.85): migrator.py:229 - yaml.load(conf, Loader=yaml.Loader)
      // in exporters_v1tov2 (ruamel.yaml full loader, unsafe).
      fn = c.getFunc() and
      fn.getName() = "load" and
      fn.getObject().(Name).getId() = "yaml" and
      kw = c.getANamedArg() and
      kw.getArg() = "Loader" and
      loader = kw.getValue() and
      loader.getObject() instanceof Name and
      (
        loader.getName() = "Loader"
        or
        loader.getName() = "UnsafeLoader"
        or
        loader.getName() = "FullLoader"
      ) and
      at(c.getLocation(), "slo_generator/migrations/migrator.py", 229) and
      sink = DataFlow::exprNode(c.getArg(0))
    )
    or
    exists(Call c, Attribute fn, Keyword kw, Attribute loader |
      // K044 (tp, 0.85): migrator.py:264 - yaml.load(conf, Loader=yaml.Loader)
      // in ebp_v1tov2 (ruamel.yaml full loader, unsafe).
      fn = c.getFunc() and
      fn.getName() = "load" and
      fn.getObject().(Name).getId() = "yaml" and
      kw = c.getANamedArg() and
      kw.getArg() = "Loader" and
      loader = kw.getValue() and
      loader.getObject() instanceof Name and
      (
        loader.getName() = "Loader"
        or
        loader.getName() = "UnsafeLoader"
        or
        loader.getName() = "FullLoader"
      ) and
      at(c.getLocation(), "slo_generator/migrations/migrator.py", 264) and
      sink = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * Holds if `sink` is a taint sink for the given pass.
   * Only pass "command_injection" (Pass 2 / CWE-78) is enabled in this run.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "command_injection" and
    (
      getattrNameSink(sink)
      or
      dynamicImportSink(sink)
      or
      dispatchInvocationSink(sink)
      or
      unsafeYamlLoadSink(sink)
    )
  }
}
