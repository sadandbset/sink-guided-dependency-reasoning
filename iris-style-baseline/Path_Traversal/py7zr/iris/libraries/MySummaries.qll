/**
 * Augur Pass 1 (Path Traversal) additional taint-step model for py7zr.
 *
 * Generated deterministically from the reviewed Pass 1 labels in
 * iris/labels/labels.json (entries with role=summary and
 * classification=tp). Every edge is anchored to the exact labeled call
 * site in the real source - there are no unconditional
 * any-node-to-any-node propagation edges, and no edges for
 * candidate/pending-review summary labels (WindowsPath "\\?\" prefixing
 * at py7zr.py:597, the readlink str->Path conversions in
 * helpers.py:299 / win32compat.py:198).
 *
 * On this toolchain (CodeQL CLI 2.25.1 + codeql/python-all 7.1.x) the
 * return value of an unresolved external call (pathlib.Path, .joinpath,
 * str .decode, .replace on a stdlib str) is NOT tainted by default, and
 * the dict-store/dynamic-load carrier of Worker.register_filelike is
 * invisible to global taint. The edges below are therefore the minimum
 * necessary, all site-anchored:
 *   - read_utf16(...).replace("\\", "/") : receiver -> result
 *     (p1-sink-001, the separator-rewriting decode-boundary transform);
 *   - remove_relative_path_marker(x) : arg 0 -> result at py7zr.py:577,
 *     :580, :582 (p1-sink-044/046/048; the in-tree definition is also
 *     covered by standard interprocedural flow, the call-site edges make
 *     the wrapper explicit per the reviewed labels);
 *   - .joinpath(x) : arg 0 -> result at py7zr.py:577/:582
 *     (p1-sink-042/047, the entry-name join onto the base);
 *   - pathlib.Path(x) : arg 0 -> result at py7zr.py:542/:580/:1343
 *     (p1-sink-037/045/105, str->Path coercion of entry names and of the
 *     raw link-target payload);
 *   - register_filelike(f.id, outfilename) arg 1 (py7zr.py:619/:621)
 *     -> self.target_filepath.get(f.id, None) (py7zr.py:1320)
 *     (p1-sink-119/120: the dict store -> dynamic-load carrier from
 *     SevenZipFile._extract into Worker._extract_single);
 *   - fileish -> fileish.parent at py7zr.py:1328 (realizes the receiver
 *     position of sink p1-sink-101; pathlib .parent is a pure path-text
 *     derivation of the entry-controlled path);
 *   - ofp.read()/omfp.read() -> .decode("utf-8") result at
 *     py7zr.py:1333/:1343 (connects the labeled sources p1-src-057/059
 *     to the labeled sinks p1-sink-104 (arg 1) and p1-sink-105 -> 108;
 *     str.decode is value-preserving).
 *
 * The last two edges are not themselves label rows: .decode/.parent were
 * below the Phase 1 extraction granularity (pure stdlib string/path
 * derivations, no candidate rows emitted). They are interpolated with
 * real-code evidence to realize the reviewed source->sink chains, in the
 * same site-anchored arg/receiver->result style as the labeled summaries.
 * See report/query_generation_notes.md §2.4 and §7.
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /**
   * Holds if there is an additional reviewed Pass 1 taint step from
   * `nodeFrom` to `nodeTo` for pass key `passKey`.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and (
      entryNameReplaceStep(nodeFrom, nodeTo) or
      removeRelativePathMarkerStep(nodeFrom, nodeTo) or
      joinPathStep(nodeFrom, nodeTo) or
      pathConstructorStep(nodeFrom, nodeTo) or
      registerFilelikeStep(nodeFrom, nodeTo) or
      parentAttributeStep(nodeFrom, nodeTo) or
      linkTargetDecodeStep(nodeFrom, nodeTo)
    )
  }

  /** Restricts an AST node to a file base name and a 1-based start line. */
  private predicate matchLoc(AstNode n, string baseName, int line) {
    n.getLocation().getFile().getBaseName() = baseName and
    n.getLocation().getStartLine() = line
  }

  /**
   * p1-sink-001 (summary/tp 0.90): the entry-name separator rewrite at
   * the decode boundary.
   *
   * archiveinfo.py:757:
   *   f["filename"] = read_utf16(buffer).replace("\\", "/")
   *
   * Edge: receiver (the read_utf16 call, i.e. source p1-src-001) ->
   * replace() call result. Taint-preserving transform that rewrites
   * Windows separators into posix separators, making "..\\..\\evil"
   * payloads effective "../../evil" on every platform - it widens
   * traversal reach, never narrows it.
   */
  private predicate entryNameReplaceStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "replace" and
      matchLoc(c, "archiveinfo.py", 757) and
      nodeFrom.asExpr() = f.getObject() and
      nodeTo.asExpr() = c
    )
  }

  /**
   * p1-sink-044, p1-sink-046, p1-sink-048 (summary/tp 0.90): the
   * "./"-stripping wrapper on the extraction path.
   *
   * py7zr.py:577:  pathlib.Path(os.getcwd()).joinpath(remove_relative_path_marker(outname))
   * py7zr.py:580:  outfilename = pathlib.Path(remove_relative_path_marker(outname))
   * py7zr.py:582:  outfilename = path.joinpath(remove_relative_path_marker(outname))
   *
   * Edge: argument 0 -> call result. The wrapper (helpers.py:424-433)
   * strips only one leading "./" and passes everything else through -
   * taint-preserving by construction, and explicitly NOT a barrier.
   */
  private predicate removeRelativePathMarkerStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      (matchLoc(c, "py7zr.py", 577) or matchLoc(c, "py7zr.py", 580) or matchLoc(c, "py7zr.py", 582)) and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "remove_relative_path_marker" and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * p1-sink-042, p1-sink-047 (summary/tp 0.90): the entry-name join onto
   * the extraction base.
   *
   * py7zr.py:577:  pathlib.Path(os.getcwd()).joinpath(remove_relative_path_marker(outname))
   * py7zr.py:582:  outfilename = path.joinpath(remove_relative_path_marker(outname))
   *
   * Edge: argument 0 (the attacker-controlled name; the receiver base is
   * cwd or the caller-supplied output dir) -> joinpath call result. This
   * is the traversal decision point: pathlib joinpath semantics keep ".."
   * segments (and would replace the base for an absolute name - that
   * case is the one the relative_to guards actually catch).
   */
  private predicate joinPathStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "joinpath" and
      (matchLoc(c, "py7zr.py", 577) or matchLoc(c, "py7zr.py", 582)) and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * p1-sink-037, p1-sink-045, p1-sink-105 (summary/tp): the str->Path
   * coercions of the path pipeline.
   *
   * py7zr.py:542:  path = pathlib.Path(path)                          (str output dir, caller side)
   * py7zr.py:580:  outfilename = pathlib.Path(remove_relative_path_marker(outname))   (path=None branch)
   * py7zr.py:1343: sym_target = pathlib.Path(omfp.read().decode("utf-8"))            (link target)
   *
   * Edge: argument 0 -> constructor result. The :580 edge carries the
   * entry-name flow of the path=None branch (extractall() with no path,
   * read(), readall()); the :1343 edge carries the raw link-target
   * payload into the symlink sink. The :542 edge is retained for label
   * fidelity - no promoted source feeds it (the caller path params are
   * candidate labels, not sources).
   */
  private predicate pathConstructorStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "Path" and
      (matchLoc(c, "py7zr.py", 542) or matchLoc(c, "py7zr.py", 580) or matchLoc(c, "py7zr.py", 1343)) and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * p1-sink-119, p1-sink-120 (summary/tp 0.90, moduleHint twins): the
   * dict store -> dynamic-load carrier from _extract into the Worker.
   *
   * py7zr.py:619/:621 (SevenZipFile._extract):
   *   self.worker.register_filelike(f.id, outfilename)
   * py7zr.py:1500-1502 (Worker.register_filelike):
   *   self.target_filepath[id] = fileish
   * py7zr.py:1320 (Worker._extract_single):
   *   fileish = self.target_filepath.get(f.id, None)
   *
   * Edge: argument 1 of the register_filelike calls (outfilename) ->
   * the .get(f.id, None) load at :1320. The reviewed label marks the
   * register_filelike DEFINITION (param `fileish`) as the summary; the
   * edge is realized at the two call sites that carry real paths
   * (:619 symlink/junction, :621 regular files - the :599 (None) and
   * :609 (in-memory MemIO) registrations carry no path text) because the
   * dict store with a dynamic key plus the later dynamic member dispatch
   * is exactly what global taint cannot see. From :1320, standard local
   * flow carries the taint to the fileish receivers of the sinks.
   */
  private predicate registerFilelikeStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call reg, Attribute regf, Call get, Attribute getf |
      reg.getFunc() = regf and
      regf.getName() = "register_filelike" and
      (matchLoc(reg, "py7zr.py", 619) or matchLoc(reg, "py7zr.py", 621)) and
      nodeFrom.asExpr() = reg.getArg(1) and
      get.getFunc() = getf and
      getf.getName() = "get" and
      matchLoc(get, "py7zr.py", 1320) and
      nodeTo.asExpr() = get
    )
  }

  /**
   * Realization edge for sink p1-sink-101 (sink/tp 0.95, receiver
   * position `fileish.parent`): the pathlib .parent derivation.
   *
   * py7zr.py:1328 (Worker._extract_single):
   *   fileish.parent.mkdir(parents=True, exist_ok=True)
   *
   * Edge: `fileish` (the loaded entry-controlled path) -> the
   * `fileish.parent` attribute expression. pathlib .parent is a pure
   * path-text derivation (the parent directory of the attacker-influenced
   * path is still attacker-influenced); the attribute read itself is not
   * a default taint step because pathlib is not part of the database.
   * Not a label row (below extraction granularity) - an evidence-based
   * interpolation in the same site-anchored style; see
   * query_generation_notes.md §2.4/§7.
   */
  private predicate parentAttributeStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Attribute parent, Attribute f, Call c |
      c.getFunc() = f and
      f.getName() = "mkdir" and
      matchLoc(c, "py7zr.py", 1328) and
      f.getObject() = parent and
      parent.getName() = "parent" and
      nodeFrom.asExpr() = parent.getObject() and
      nodeTo.asExpr() = parent
    )
  }

  /**
   * Realization edge connecting the labeled link-target sources
   * (p1-src-057/p1-src-059) to the labeled sinks: the UTF-8 decode of
   * the payload read.
   *
   * py7zr.py:1333:  dst: str = ofp.read().decode("utf-8")
   * py7zr.py:1343:  sym_target = pathlib.Path(omfp.read().decode("utf-8"))
   *
   * Edge: receiver (the ofp.read()/omfp.read() call, i.e. the source
   * nodes) -> .decode() call result. str.decode is value-preserving; the
   * decoded value at :1333 flows to CreateJunction arg 1 (p1-sink-104)
   * and at :1343 through the pathConstructorStep edge to symlink_to arg
   * 0 (p1-sink-108). Not a label row (below extraction granularity) -
   * evidence-based interpolation; see query_generation_notes.md §2.4/§7.
   */
  private predicate linkTargetDecodeStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "decode" and
      (matchLoc(c, "py7zr.py", 1333) or matchLoc(c, "py7zr.py", 1343)) and
      nodeFrom.asExpr() = f.getObject() and
      nodeTo.asExpr() = c
    )
  }
}
