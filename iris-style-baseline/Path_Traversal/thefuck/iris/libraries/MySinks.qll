/**
 * Augur Pass 1 (Path Traversal, CWE-022/023/036/073) sink model for
 * thefuck 3.30 (`thefuck_vuln` source tree).
 *
 * Generated in Phase 2 Step 4 from the reviewed Phase 1 labels
 * (`iris/labels/labels.json`, pass 1, run `iris-thefuck-pass1-step3-20261023`,
 * model glm-5.3). Every clause cites the label id(s) it renders; only sink
 * entries with classification `tp` or `candidate` are rendered (17 of 23:
 * 4 tp + 13 candidate). The 6 `sink`/`fp` entries (fixed literal paths:
 * `fish.py:124` history append, the `not_configured.py` tracker/config
 * opens, `utils.py:221` fixed-name cache remove) are deliberately not
 * rendered - see `report/query_generation_notes.md`.
 *
 * Every sink node is the PATH TEXT reaching the dangerous parameter
 * (positional argument or, for member calls, the receiver object), never
 * the returned file/archive object:
 *   - argument-position sinks: `os.remove(file)`, `open(filepath, ...)`,
 *     `os.open(path, ...)`, `io.open(name, ...)`, `imp.load_source(name,
 *     path)`, `tarfile.TarFile(path)`, `zipfile.ZipFile(path, ...)`,
 *     `shelve.open(path)`, `os.makedirs(dir)`;
 *   - receiver-position sinks: `settings_path.open(mode='w')`,
 *     `rules_dir.mkdir(parents=True)`.
 * Pure path construction (`Path(...)`, `join`/`joinpath`, `expanduser`) and
 * stat-only probes (`isfile`/`isdir`/`exists`/`listdir`/`iterdir`) are NOT
 * sinks per the reviewed labels.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySinks {

  /**
   * Holds if `node` is a reviewed pass-1 sink for pass key
   * `path_traversal`.
   */
  predicate isSink(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    (
      osRemoveSink(node)
      or builtinOpenSink(node)
      or osOpenSink(node)
      or ioOpenSink(node)
      or pathlibOpenSink(node)
      or pathlibMkdirSink(node)
      or loadSourceSink(node)
      or archiveOpenSink(node)
      or shelveOpenSink(node)
      or osMakedirsSink(node)
    )
  }

  /**
   * Holds if `n` occurs in the module named `moduleName`
   * (e.g. "thefuck.rules.dirty_untar"). Module names are unique in this
   * project, which pins each clause to the labeled sink site.
   */
  private predicate inModule(AstNode n, string moduleName) {
    n.getScope().getEnclosingModule().getName() = moduleName
  }

  /**
   * `os.remove(file)` - file deletion at argument index 0.
   *
   * p1-454 (sink/tp, 0.95): `dirty_untar.py:45` `os.remove(file)` in
   * `side_effect`, where `file` iterates over `archive.getnames()` (source
   * p1-083) with no validation: `..` segments escape the CWD, absolute
   * paths pass through as-is, separator variants are not rewritten.
   *
   * p1-458 (sink/tp, 0.95): `dirty_unzip.py:49` `os.remove(file)` in
   * `side_effect`, `file` iterates over `archive.namelist()` (source
   * p1-086), same absence of validation.
   */
  private predicate osRemoveSink(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "remove" and
      fn.getObject().(Name).getId() = "os" and
      (
        inModule(c, "thefuck.rules.dirty_untar")
        or inModule(c, "thefuck.rules.dirty_unzip")
      ) and
      node = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * Builtin `open(filepath, mode)` - file read/rewrite at argument index 0.
   *
   * p1-501 (sink/tp, 0.90): `ssh_known_hosts.py:33` `open(filepath, 'r')` -
   * reads the file whose path is regex-extracted from the failed command's
   * terminal output (source p1-352) - arbitrary file read.
   *
   * p1-502 (sink/tp, 0.90): `ssh_known_hosts.py:36` `open(filepath, 'w')` -
   * rewrites that file with the matched line deleted - arbitrary file
   * modification. `ssh_known_hosts` contains no other builtin `open` call.
   */
  private predicate builtinOpenSink(DataFlow::Node node) {
    exists(Call c |
      c.getFunc().(Name).getId() = "open" and
      inModule(c, "thefuck.rules.ssh_known_hosts") and
      node = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * `os.open(path, flags)` - real file open at argument index 0.
   *
   * p1-495 (candidate, 0.60): `output_readers/read_log.py:93`
   * `os.open(os.environ['THEFUCK_OUTPUT_LOG'], os.O_RDONLY)` - read-only
   * open of the env-selected output log (source p1-339).
   *
   * p1-498 (candidate, 0.65): `entrypoints/shell_logger.py:74`
   * `os.open(output, O_CREAT|O_TRUNC|O_RDWR)` - create/truncate at the CLI
   * `-l/--shell-logger` value (sources p1-260/p1-349). This is the only
   * `os.open` in `thefuck.entrypoints.shell_logger`, so the two
   * `shell_logger.py` modules (entrypoints vs output_readers) cannot be
   * confused - module names are matched in full.
   */
  private predicate osOpenSink(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "open" and
      fn.getObject().(Name).getId() = "os" and
      (
        inModule(c, "thefuck.entrypoints.shell_logger")
        or inModule(c, "thefuck.output_readers.read_log")
      ) and
      node = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * p1-465 (candidate, 0.60): `shells/generic.py:60`
   * `io.open(history_file_name, 'r', ...)` - history file read at argument
   * index 0; the path comes from the HISTFILE env sources (p1-021, p1-362,
   * p1-410). The only `io.open` in the package.
   */
  private predicate ioOpenSink(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "open" and
      fn.getObject().(Name).getId() = "io" and
      inModule(c, "thefuck.shells.generic") and
      node = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * p1-435 (candidate, 0.60): `conf.py:39`
   * `settings_path.open(mode='w')` - settings.py CREATE/overwrite. The path
   * text is the RECEIVER (`settings_path = user_dir.joinpath('settings.py')`
   * where `user_dir` derives from XDG_CONFIG_HOME, source p1-070), so the
   * sink node is the receiver expression `fn.getObject()`, matching the
   * label's receiver arg_index -1. The only member `.open(` call in
   * `thefuck.conf`.
   */
  private predicate pathlibOpenSink(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "open" and
      inModule(c, "thefuck.conf") and
      node = DataFlow::exprNode(fn.getObject())
    )
  }

  /**
   * p1-443 (candidate, 0.50): `conf.py:64`
   * `rules_dir.mkdir(parents=True)` - directory creation under the
   * XDG-derived user dir (source p1-070). Path text on the receiver
   * (`rules_dir = user_dir.joinpath('rules')`), matching the label's
   * receiver arg_index -1. The only `.mkdir(` call in `thefuck.conf`.
   */
  private predicate pathlibMkdirSink(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "mkdir" and
      inModule(c, "thefuck.conf") and
      node = DataFlow::exprNode(fn.getObject())
    )
  }

  /**
   * `imp.load_source(name, path)` - code/resource load at argument index 1
   * (the pass-1 "resource loader methods taking path strings" sink family).
   *
   * p1-444 (candidate, 0.60): `conf.py:69`
   * `load_source('settings', text_type(self.user_dir.joinpath('settings.py')))`
   * - loads and executes settings.py from the XDG_CONFIG_HOME-derived dir
   * (source p1-070).
   *
   * p1-504 (candidate, 0.60): `types.py:144`
   * `load_source(name, str(path))` in `Rule.from_path` - loads rule modules
   * from the glob'd dirs (bundled, XDG user rules via `corrector.py:31`,
   * sys.path `thefuck_contrib_*` packages).
   */
  private predicate loadSourceSink(DataFlow::Node node) {
    exists(Call c |
      c.getFunc().(Name).getId() = "load_source" and
      (
        inModule(c, "thefuck.conf")
        or inModule(c, "thefuck.types")
      ) and
      node = DataFlow::exprNode(c.getArg(1))
    )
  }

  /**
   * Archive open at argument index 0 - the archive whose CONTENT (entry
   * names) drives the `os.remove` sinks; the open itself is
   * authorized-by-use (candidate, not tp, per the reviewed labels).
   *
   * p1-453 (candidate, 0.60): `dirty_untar.py:42`
   * `tarfile.TarFile(_tar_file(old_cmd.script_parts)[0])` in `side_effect`
   * (source p1-082). The only `TarFile` call in the package.
   *
   * p1-455, p1-457 (candidate, 0.60): `dirty_unzip.py:9`
   * `zipfile.ZipFile(file, 'r')` in `_is_bad_zip` and `:46`
   * `zipfile.ZipFile(_zip_file(old_cmd), 'r')` in `side_effect` (source
   * p1-085). Both are the only `ZipFile` calls in the package.
   */
  private predicate archiveOpenSink(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      (
        (
          fn.getName() = "TarFile" and
          fn.getObject().(Name).getId() = "tarfile" and
          inModule(c, "thefuck.rules.dirty_untar")
        )
        or
        (
          fn.getName() = "ZipFile" and
          fn.getObject().(Name).getId() = "zipfile" and
          inModule(c, "thefuck.rules.dirty_unzip")
        )
      ) and
      node = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * p1-514, p1-516 (candidate, 0.60): `utils.py:217` and `:222`
   * `shelve.open(cache_path)` - dbm cache open/create at argument index 0;
   * `cache_path = Path(cache_dir).joinpath('thefuck').as_posix()` where
   * `cache_dir` comes from XDG_CACHE_HOME (source p1-390). The two calls
   * are the open and the post-reset retry inside `_setup_db`.
   */
  private predicate shelveOpenSink(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "open" and
      fn.getObject().(Name).getId() = "shelve" and
      inModule(c, "thefuck.utils") and
      node = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * p1-518 (candidate, 0.55): `utils.py:233`
   * `os.makedirs(cache_dir)` - cache directory creation at argument index 0
   * from XDG_CACHE_HOME (source p1-390). The only `os.makedirs` in the
   * package.
   */
  private predicate osMakedirsSink(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "makedirs" and
      fn.getObject().(Name).getId() = "os" and
      inModule(c, "thefuck.utils") and
      node = DataFlow::exprNode(c.getArg(0))
    )
  }
}
