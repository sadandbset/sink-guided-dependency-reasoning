/**
 * Augur Pass 1 (Path Traversal) source model for py7zr.
 *
 * Generated deterministically from the reviewed Pass 1 labels in
 * iris/labels/labels.json (entries with role=source and classification=tp,
 * with the 32 moduleHint-twin label rows collapsed to their 6 unique AST
 * sites). Only confirmed archive-content-controlled input nodes are
 * modeled: the 7z header entry-name decode and the decompressed
 * symlink/junction target payloads.
 *
 * Deliberately NOT sources here (candidate/pending-review labels, see
 * labels/phase1_review.md §5 and report/query_generation_notes.md):
 *   - CLI argv reads (args.arcfile / args.odir / args.filenames, Cli.run arg)
 *     - local-operator trust;
 *   - public API path parameters (SevenZipFile.__init__ file, _extract
 *     path, extractall/extract path, writeall/write path, is_7zfile file,
 *     unpack_7zarchive/pack_7zarchive params) - caller-authorized paths;
 *     an internal wrapper's path parameter is not promoted to a source
 *     merely to produce a path.
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /**
   * Holds if `source` is a reviewed Pass 1 taint source for pass key
   * `passKey`.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and (
      entryNameDecodeSource(source) or
      entryNameStoreSource(source) or
      entryNameReadSource(source) or
      linkTargetSource(source)
    )
  }

  /** Restricts an AST node to a file base name and a 1-based start line. */
  private predicate matchLoc(AstNode n, string baseName, int line) {
    n.getLocation().getFile().getBaseName() = baseName and
    n.getLocation().getStartLine() = line
  }

  /**
   * p1-src-001 (source/tp 0.95): the archive entry-name decode.
   *
   * archiveinfo.py:755-757 (FilesInfo._read_name, PROPERTY.NAME block):
   *   f["filename"] = read_utf16(buffer).replace("\\", "/")
   *
   * read_utf16 (defined in archiveinfo.py:192) decodes UTF-16LE bytes taken
   * straight from the 7z header; the attacker who supplies the archive
   * controls the entire decoded name string, including "../" segments and
   * (via the .replace) Windows-style separators rewritten to posix form.
   * External input boundary: the 7z archive header content, reachable by
   * any caller that opens an attacker-supplied archive for extraction
   * (SevenZipFile(..., "r") / unpack_7zarchive / py7zr CLI).
   */
  private predicate entryNameDecodeSource(DataFlow::Node source) {
    exists(Call c |
      matchLoc(c, "archiveinfo.py", 757) and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "read_utf16" and
      source.asExpr() = c
    )
  }

  /**
   * p1-src-002 (source/tp 0.95): the dict store where the decoded
   * attacker-controlled name enters the file_info dicts.
   *
   * archiveinfo.py:757: f["filename"] = read_utf16(buffer).replace("\\", "/")
   *
   * The file_info dicts become ArchiveFile objects (py7zr.py:79-81) whose
   * .filename property (:111-113) is the extraction path input. Anchoring a
   * source at the store preserves recall at the write side; the read side
   * is independently anchored by entryNameReadSource because the
   * dict -> ArchiveFile._file_info container crossing is not trackable by
   * default (see query_generation_notes.md §6).
   */
  private predicate entryNameStoreSource(DataFlow::Node source) {
    exists(Subscript s |
      matchLoc(s, "archiveinfo.py", 757) and
      source.asExpr() = s
    )
  }

  /**
   * p1-src-023/p1-src-024 (source/tp 0.95, moduleHint twins) and
   * p1-src-025/p1-src-026 (source/tp 0.90, moduleHint twins): the entry
   * name read into the extraction path pipeline.
   *
   * py7zr.py:561 (SevenZipFile._extract):
   *   outname = f.filename
   * py7zr.py:562-568 (duplicate-name branch):
   *   outname = f.filename + "_%d" % i
   *
   * THE assignments feeding the attacker-controlled entry name into
   * remove_relative_path_marker -> pathlib.Path / path.joinpath ->
   * register_filelike -> Worker fileish -> the filesystem sinks. The
   * "_%d" suffixing is collision handling, not a traversal guard.
   */
  private predicate entryNameReadSource(DataFlow::Node source) {
    exists(Attribute a |
      a.getName() = "filename" and
      (matchLoc(a, "py7zr.py", 561) or matchLoc(a, "py7zr.py", 565)) and
      source.asExpr() = a
    )
  }

  /**
   * p1-src-057/p1-src-058 (source/tp 0.95, moduleHint twins) and
   * p1-src-059/p1-src-060 (source/tp 0.95, moduleHint twins): the
   * decompressed link-target payloads.
   *
   * py7zr.py:1331-1333 (Worker._extract_single, junction branch):
   *   with io.BytesIO() as ofp:
   *     self.decompress(fp, f.folder, ofp, ...)
   *     dst: str = ofp.read().decode("utf-8")
   * py7zr.py:1340-1343 (symlink branch):
   *   with io.BytesIO() as omfp:
   *     self.decompress(fp, f.folder, omfp, ...)
   *     sym_target = pathlib.Path(omfp.read().decode("utf-8"))
   *
   * External input boundary: the archive payload bytes of a link/junction
   * member; the attacker controls the full target string (absolute or
   * "../" relative). These feed _winapi.CreateJunction(str(fileish), dst)
   * (:1338, arg 1) and fileish.symlink_to(sym_target) (:1347, arg 0) with
   * no validation anywhere in between - not even the (weak) relative_to
   * guards apply to the target side.
   */
  private predicate linkTargetSource(DataFlow::Node source) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "read" and
      (matchLoc(c, "py7zr.py", 1333) or matchLoc(c, "py7zr.py", 1343)) and
      source.asExpr() = c
    )
  }
}
