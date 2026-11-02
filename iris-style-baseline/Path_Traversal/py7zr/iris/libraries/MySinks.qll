/**
 * Augur Pass 1 (Path Traversal) sink model for py7zr.
 *
 * Generated deterministically from the reviewed Pass 1 labels in
 * iris/labels/labels.json (entries with role=sink and classification=tp).
 * Only real filesystem access / mutation positions on the extraction path
 * are modeled, and path text is distinguished from already-open file
 * objects:
 *   - receiver-position sinks match the path expression the file API
 *     operates on (fileish / target_dir / outfilename receivers of
 *     .mkdir/.unlink/.chmod/.open/.touch, and the fileish.parent
 *     derivation at py7zr.py:1328);
 *   - argument-position sinks match the dangerous path argument
 *     (os.utime arg 0; CreateJunction arg 0 = link path AND arg 1 =
 *     archive-content target per the reviewed label rationale; symlink_to
 *     arg 0 = archive-content target, plus its receiver);
 *   - the MemIO in-memory branch (py7zr.py:1359, read()/readall() dict
 *     mode) is NOT a sink - it touches no filesystem.
 *
 * Candidate sinks NOT modeled (pending review, see
 * labels/phase1_review.md §5): py7zr.py:545 path.mkdir(parents=True)
 * (caller-authorized output base), and all write-side / archive-open /
 * stat-probe rows (operator-supplied paths).
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /**
   * Holds if `sink` is a reviewed Pass 1 taint sink for pass key `passKey`.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and (
      extractDirectoryMkdirSink(sink) or
      postExtractMetadataSink(sink) or
      workerParentMkdirSink(sink) or
      preLinkUnlinkSink(sink) or
      junctionCreationSink(sink) or
      symlinkCreationSink(sink) or
      extractFileWriteSink(sink) or
      emptyFileTouchSink(sink)
    )
  }

  /** Restricts an AST node to a file base name and a 1-based start line. */
  private predicate matchLoc(AstNode n, string baseName, int line) {
    n.getLocation().getFile().getBaseName() = baseName and
    n.getLocation().getStartLine() = line
  }

  /**
   * p1-sink-052 (sink/tp 0.90): creation of an archive-entry directory
   * outside the guarded join.
   *
   * py7zr.py:623-625 (SevenZipFile._extract):
   *   for target_dir in sorted(target_dirs):
   *     target_dir.mkdir(parents=True)
   *
   * Real file operation: directory creation (mkdir -p semantics). Dangerous
   * position: the receiver `target_dir` - collected at py7zr.py:612 from
   * `outfilename` (the entry-name-derived path), whose "../" traversal
   * passes the relative_to guards (query_generation_notes.md §3).
   */
  private predicate extractDirectoryMkdirSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "mkdir" and
      matchLoc(c, "py7zr.py", 625) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * p1-sink-055 (sink/tp 0.80), p1-sink-056 (sink/tp 0.80), p1-sink-057
   * (sink/tp 0.75): post-extract metadata writes on entry-controlled
   * paths.
   *
   * py7zr.py:658-659: os.utime(str(outfilename), times=(lastmodified, lastmodified))
   * py7zr.py:663:     outfilename.chmod(st_mode)      (st_mode = archive-supplied posix_mode)
   * py7zr.py:668:     outfilename.chmod(outfilename.stat().st_mode & ro_mask)
   *
   * Real file operations: timestamp write (utime) and permission change
   * (chmod). Dangerous positions: os.utime argument 0 (path text via the
   * str() coercion) and the chmod receivers (path text); the times/modes
   * themselves are archive-supplied (lastwritetime / posix_mode,
   * py7zr.py:202-215). Access type: metadata mutation after the extract
   * write, for every extracted file.
   */
  private predicate postExtractMetadataSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "utime" and
      matchLoc(c, "py7zr.py", 659) and
      sink.asExpr() = c.getArg(0)
    )
    or
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "chmod" and
      (matchLoc(c, "py7zr.py", 663) or matchLoc(c, "py7zr.py", 668)) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * p1-sink-101 (sink/tp 0.95): the Worker-side directory creation of the
   * Zip-Slip flow.
   *
   * py7zr.py:1328 (Worker._extract_single):
   *   fileish.parent.mkdir(parents=True, exist_ok=True)
   *
   * Real file operation: directory creation with parents=True walking up
   * any "../"-escaped chain. Dangerous position: the receiver
   * `fileish.parent` - fileish is self.target_filepath.get(f.id)
   * (py7zr.py:1320), i.e. the entry-name-derived outfilename registered by
   * SevenZipFile._extract (register_filelike, py7zr.py:619/:621/:1500).
   * The taint reaches this receiver via the parentAttributeStep summary
   * (MySummaries).
   */
  private predicate workerParentMkdirSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "mkdir" and
      matchLoc(c, "py7zr.py", 1328) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * p1-sink-103 (sink/tp 0.90), p1-sink-107 (sink/tp 0.90): pre-collision
   * deletion at the entry-controlled link location.
   *
   * py7zr.py:1335-1336 (junction branch):
   *   if fileish.exists():
   *     fileish.unlink()
   * py7zr.py:1345-1346 (symlink branch):
   *   if fileish.exists():
   *     fileish.unlink()
   *
   * Real file operation: file deletion (unlink). Dangerous position: the
   * receiver `fileish` (path text). The exists()/unlink() ordering is also
   * the TOCTOU window documented in phase1_review.md §6.
   */
  private predicate preLinkUnlinkSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "unlink" and
      (matchLoc(c, "py7zr.py", 1336) or matchLoc(c, "py7zr.py", 1346)) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * p1-sink-104 (sink/tp 0.95): arbitrary junction creation.
   *
   * py7zr.py:1338 (Worker._extract_single, junction branch):
   *   _winapi.CreateJunction(str(fileish), dst)
   *
   * Real file operation: NTFS junction (reparse point) creation. Dangerous
   * positions: argument 0 - the link path (str(fileish), the
   * entry-name-derived path) - and argument 1 - `dst`, the raw
   * archive-payload link target decoded at py7zr.py:1333. The reviewed
   * label rationale records BOTH sides as attacker-controlled ("link path
   * (fileish...) and target dst ... are BOTH attacker-controlled"), so
   * both argument positions are sink positions; arg 1 carries the
   * p1-src-057 source flow, arg 0 the entry-name flow. Windows-only
   * branch, selected by the archive-supplied is_junction attribute.
   */
  private predicate junctionCreationSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "CreateJunction" and
      matchLoc(c, "py7zr.py", 1338) and
      (sink.asExpr() = c.getArg(0) or sink.asExpr() = c.getArg(1))
    )
  }

  /**
   * p1-sink-108 (sink/tp 0.95): arbitrary symlink creation.
   *
   * py7zr.py:1347 (Worker._extract_single, symlink branch):
   *   fileish.symlink_to(sym_target)
   *
   * Real file operation: symlink creation. Dangerous positions: argument 0
   * - `sym_target` (the archive-payload target converted at py7zr.py:1343,
   * feeding the p1-src-059 source flow) - and the receiver `fileish` (the
   * entry-name-derived link path, per the reviewed label rationale
   * "receiver is the archive-entry-name path, arg 0 is the
   * archive-content link target").
   */
  private predicate symlinkCreationSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "symlink_to" and
      matchLoc(c, "py7zr.py", 1347) and
      (sink.asExpr() = c.getArg(0) or sink.asExpr() = f.getObject())
    )
  }

  /**
   * p1-sink-109 (sink/tp 0.97): THE arbitrary-file-write sink of the
   * Zip-Slip flow.
   *
   * py7zr.py:1349-1350 (Worker._extract_single):
   *   with fileish.open(mode="wb") as obfp:
   *     crc32 = self.decompress(fp, f.folder, obfp, ...)
   *
   * Real file operation: file open for writing + decompressed archive
   * bytes written to it. Dangerous position: the receiver `fileish` (path
   * text, NOT the resulting file object obfp) - the entry-name-derived
   * outfilename whose "../" traversal passes the relative_to guards.
   */
  private predicate extractFileWriteSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "open" and
      matchLoc(c, "py7zr.py", 1349) and
      sink.asExpr() = f.getObject()
    )
  }

  /**
   * p1-sink-110 (sink/tp 0.90): empty-file creation at the entry path.
   *
   * py7zr.py:1354-1357 (Worker._extract_single):
   *   if not isinstance(fileish, MemIO):
   *     fileish.touch()
   *
   * Real file operation: empty-file creation. Dangerous position: the
   * receiver `fileish` (path text). The paired MemIO branch at :1359 is
   * explicitly not a sink (in-memory stub).
   */
  private predicate emptyFileTouchSink(DataFlow::Node sink) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "touch" and
      matchLoc(c, "py7zr.py", 1357) and
      sink.asExpr() = f.getObject()
    )
  }
}
