/**
 * Augur Pass 1 (Path Traversal, CWE-022/023/036/073) source model for
 * thefuck 3.30 (`thefuck_vuln` source tree).
 *
 * Generated in Phase 2 Step 4 from the reviewed Phase 1 labels
 * (`iris/labels/labels.json`, pass 1, run `iris-thefuck-pass1-step3-20261023`,
 * model glm-5.3). Every clause cites the label id(s) it renders; only source
 * entries with classification `tp` or `candidate` are rendered (24 of 39:
 * 3 tp + 21 candidate). The 13 `source`/`fp` entries (command attribute reads
 * that reach only stat-only probes in pass 1) and the 466 `none` entries are
 * deliberately not rendered - see `report/query_generation_notes.md`.
 *
 * Source nodes are exact input-boundary reads: archive entry names, the failed
 * command's output/script_parts attribute reads, env-var reads with fixed
 * literal keys, the argparse boundary, `known_args` CLI field reads, and the
 * `shell_logger(output)` entrypoint parameter. No internal wrapper parameter
 * (e.g. `file_handler(path)`-style helpers) is modeled as a source.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySources {

  /**
   * Holds if `node` is a reviewed pass-1 source for pass key
   * `path_traversal`.
   */
  predicate isSource(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    (
      archiveEntryNameSource(node)
      or commandOutputSource(node)
      or commandScriptPartsSource(node)
      or envPathSource(node)
      or cliSource(node)
      or cliEntryParameterSource(node)
    )
  }

  /**
   * Holds if `n` occurs in the module named `moduleName`
   * (e.g. "thefuck.rules.dirty_untar"). Module names are unique in this
   * project, so this pins each clause to the labeled source file without
   * relying on line numbers.
   */
  private predicate inModule(AstNode n, string moduleName) {
    n.getScope().getEnclosingModule().getName() = moduleName
  }

  /**
   * Holds if `n` occurs inside function `funcName` of module `moduleName`.
   * Used where the same attribute/method name is read both in a matching
   * helper (labeled `none`) and in the side effect (labeled source).
   */
  private predicate inFunction(AstNode n, string moduleName, string funcName) {
    inModule(n, moduleName) and
    n.getScope().(Function).getName() = funcName
  }

  /**
   * Archive entry names - the fully attacker-controlled boundary.
   *
   * p1-083 (source/tp, 0.95): `dirty_untar.py:43` `archive.getnames()` inside
   * `side_effect`; each name is passed verbatim to `os.remove(file)` at :45
   * (sink p1-454) with no validation of `..`, absolute paths or separators.
   *
   * p1-086 (source/tp, 0.95): `dirty_unzip.py:47` `archive.namelist()` inside
   * `side_effect`; names flow verbatim to `os.remove(file)` at :49 (sink
   * p1-458). The match-time `namelist()` read at `dirty_unzip.py:10`
   * (p1-084, fp: length-check only) is deliberately NOT matched, hence the
   * `side_effect` restriction.
   */
  private predicate archiveEntryNameSource(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      (
        (
          fn.getName() = "getnames" and
          inFunction(c, "thefuck.rules.dirty_untar", "side_effect")
        )
        or
        (
          fn.getName() = "namelist" and
          inFunction(c, "thefuck.rules.dirty_unzip", "side_effect")
        )
      ) and
      node = DataFlow::exprNode(c)
    )
  }

  /**
   * `command.output` reads - the failed command's terminal output, this
   * tool's untrusted payload channel (attacker-influenceable when the failed
   * command printed attacker-controlled content).
   *
   * p1-352 (source/tp, 0.85): `ssh_known_hosts.py:31` `old_cmd.output` read
   * inside `side_effect`; the regex
   * `(?:Offending (?:key for IP|\S+ key)|Matching host key) in ([^:]+):(\d+)`
   * captures the `filepath` opened for read at :33 and rewrite at :36 (sinks
   * p1-501/p1-502). The match-time `command.output` read at :20 is labeled
   * `none` (warning-pattern check only) and is not matched, hence the
   * `side_effect` restriction.
   *
   * p1-113, p1-114 (source/candidate, 0.50): `fix_file.py:60` and `:66`
   * `command.output` reads; the regex-extracted `{file}` group reaches only
   * `os.path.isfile` (stat-only) in pass 1 (kept as candidate per the
   * reviewed labels).
   */
  private predicate commandOutputSource(DataFlow::Node node) {
    exists(Attribute a |
      a.getName() = "output" and
      a.getObject().(Name).getId() in ["command", "old_cmd", "cmd"] and
      (
        inFunction(a, "thefuck.rules.ssh_known_hosts", "side_effect")
        or inModule(a, "thefuck.rules.fix_file")
      ) and
      node = DataFlow::exprNode(a)
    )
  }

  /**
   * `command.script_parts` reads - the failed command's argv words.
   *
   * p1-082 (source/candidate, 0.65): `dirty_untar.py:42`
   * `old_cmd.script_parts` inside `side_effect`; supplies the archive path
   * to `tarfile.TarFile(...)` at :42 (sink p1-453) whose entry names drive
   * the `os.remove` sink. The reads at :32/:36 (match/get_new_command, used
   * for corrected-command string construction) are labeled `none` and are
   * not matched, hence the `side_effect` restriction.
   *
   * p1-085 (source/candidate, 0.65): `dirty_unzip.py:20`
   * `command.script_parts` inside `_zip_file`; supplies the `.zip` path to
   * `zipfile.ZipFile(...)` at :9/:46 (sinks p1-455/p1-457). `dirty_unzip`
   * has no other `script_parts` read.
   */
  private predicate commandScriptPartsSource(DataFlow::Node node) {
    exists(Attribute a |
      a.getName() = "script_parts" and
      a.getObject().(Name).getId() in ["command", "old_cmd", "cmd"] and
      (
        inFunction(a, "thefuck.rules.dirty_untar", "side_effect")
        or inModule(a, "thefuck.rules.dirty_unzip")
      ) and
      node = DataFlow::exprNode(a)
    )
  }

  /**
   * Environment-variable boundary. Each clause pins the exact literal env
   * key from the label, so same-module env reads with other keys (e.g.
   * `bash.py:64` `TF_SHELL_ALIASES`, `conf.py:93` `THEFUCK_*` settings,
   * `read_log.py:16/:85` `PS1`) - all labeled `none` - are not matched.
   *
   * p1-070 (candidate, 0.70): `conf.py:46`
   * `os.environ.get('XDG_CONFIG_HOME', '~/.config')` - selects the config
   * root flowing into `settings.py` open('w') (p1-435), `rules/` mkdir
   * (p1-443) and `imp.load_source` (p1-444). Local-user trust level.
   *
   * p1-021, p1-362, p1-410 (candidate, 0.65): `bash.py:69`, `tcsh.py:29`,
   * `zsh.py:74` `os.environ.get('HISTFILE', ...)` - the history file read
   * with `io.open` at `generic.py:60` (sink p1-465). Local-user trust.
   *
   * p1-109 (candidate, 0.60): `fix_command.py:16`
   * `os.environ.get('TF_HISTORY')` - the alias-exported history tail that
   * becomes the failed command's script.
   *
   * p1-111 (candidate, 0.60): `fix_command.py:19`
   * `os.environ['TF_HISTORY']`.
   *
   * p1-337, p1-339 (candidate, 0.60/0.65): `read_log.py:65/:93`
   * `os.environ['THEFUCK_OUTPUT_LOG']` - opened read-only with `os.open` at
   * :93 (sink p1-495).
   *
   * p1-390 (candidate, 0.65): `utils.py:228`
   * `os.getenv('XDG_CACHE_HOME', ...)` - cache dir flowing into
   * `os.makedirs` (p1-518), `shelve.open` (p1-514/p1-516).
   */
  private predicate envPathSource(DataFlow::Node node) {
    exists(Call c, Attribute fn, Attribute environ, StringLiteral key |
      c.getFunc() = fn and
      fn.getName() = "get" and
      fn.getObject() = environ and
      environ.getName() = "environ" and
      environ.getObject().(Name).getId() = "os" and
      c.getArg(0) = key and
      (
        (
          key.getText() = "HISTFILE" and
          (
            inModule(c, "thefuck.shells.bash")
            or inModule(c, "thefuck.shells.tcsh")
            or inModule(c, "thefuck.shells.zsh")
          )
        )
        or
        (key.getText() = "XDG_CONFIG_HOME" and inModule(c, "thefuck.conf"))
        or
        (
          key.getText() = "TF_HISTORY" and
          inModule(c, "thefuck.entrypoints.fix_command")
        )
      ) and
      node = DataFlow::exprNode(c)
    )
    or
    exists(Subscript s, Attribute environ, StringLiteral key |
      s.getObject() = environ and
      environ.getName() = "environ" and
      environ.getObject().(Name).getId() = "os" and
      s.getIndex() = key and
      (
        (
          key.getText() = "THEFUCK_OUTPUT_LOG" and
          inModule(s, "thefuck.output_readers.read_log")
        )
        or
        (
          key.getText() = "TF_HISTORY" and
          inModule(s, "thefuck.entrypoints.fix_command")
        )
      ) and
      node = DataFlow::exprNode(s)
    )
    or
    exists(Call c, Attribute fn, StringLiteral key |
      c.getFunc() = fn and
      fn.getName() = "getenv" and
      fn.getObject().(Name).getId() = "os" and
      c.getArg(0) = key and
      key.getText() = "XDG_CACHE_HOME" and
      inModule(c, "thefuck.utils") and
      node = DataFlow::exprNode(c)
    )
  }

  /**
   * The argparse CLI boundary (the `thefuck` console-script entry point;
   * `main.py:18` calls `parser.parse(sys.argv)`).
   *
   * p1-014 (candidate, 0.70): `argument_parser.py:86`
   * `self._parser.parse_args(arguments)` - return value is the Namespace
   * whose `shell_logger`/`force_command`/`command` fields are the labeled
   * CLI sources below.
   *
   * p1-258, p1-259, p1-260 (candidate, 0.60/0.60/0.65): `main.py:30/:32/:38`
   * `known_args.command` / `known_args.shell_logger` attribute reads; :38
   * passes the `-l/--shell-logger` value into `shell_logger()` which opens
   * it with `os.open(O_CREAT|O_TRUNC|O_RDWR)` at `shell_logger.py:74` (sink
   * p1-498). The `help`/`version`/`alias` flag reads (`main.py:20-28`) are
   * labeled `none` and not matched (different attribute names).
   *
   * p1-107, p1-108, p1-110 (candidate, 0.60): `fix_command.py:14/:15`
   * `known_args.force_command` and `:17` `known_args.command` - the failed
   * command's argv words entering `Command.from_raw_script`.
   */
  private predicate cliSource(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "parse_args" and
      inModule(c, "thefuck.argument_parser") and
      node = DataFlow::exprNode(c)
    )
    or
    exists(Attribute a |
      a.getObject().(Name).getId() = "known_args" and
      a.getName() in ["command", "shell_logger", "force_command"] and
      (
        inModule(a, "thefuck.entrypoints.main")
        or inModule(a, "thefuck.entrypoints.fix_command")
      ) and
      node = DataFlow::exprNode(a)
    )
  }

  /**
   * p1-349 (candidate, 0.60): `entrypoints/shell_logger.py:64` - the
   * `output` parameter of `shell_logger(output)`, the entrypoint called
   * from `main.py:38` with `known_args.shell_logger`. It is opened with
   * `os.open(output, O_CREAT|O_TRUNC|O_RDWR)` at :74 (sink p1-498). This is
   * an externally reachable entrypoint parameter carrying a CLI value, not
   * an internal wrapper parameter.
   */
  private predicate cliEntryParameterSource(DataFlow::Node node) {
    exists(Function f, Parameter p |
      f.getName() = "shell_logger" and
      inModule(f, "thefuck.entrypoints.shell_logger") and
      p = f.getArgByName("output") and
      node = DataFlow::parameterNode(p)
    )
  }
}
