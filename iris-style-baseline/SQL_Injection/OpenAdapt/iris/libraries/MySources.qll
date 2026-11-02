/**
 * Augur Phase 2 Step 4 - generated source library.
 *
 * Pass 5 (CWE-89, SQL Injection) for the OpenAdapt project.
 *
 * Machine-generated from `iris/labels/labels.json` (pass_id 5, role=source,
 * 16 reviewed entries: pass5-src-006, -007, -028..-035, -053, -054, -065,
 * -097, -098, -099). Only entries with the `source` role after human review
 * are modeled; the 101 `none`-role source candidates are intentionally NOT
 * represented here. (The single role=summary label, pass5-src-049, is
 * documented in MySummaries.qll, not modeled as a source.)
 *
 * Modeling notes (see report/query_generation_notes.md for full evidence):
 * - The primary CWE-89 sources are the 8 `recording.<column>` ORM attribute
 *   reads at openadapt/crud.py:142 (label ids pass5-src-028..-035), which are
 *   interpolated unescaped into the raw SQL f-string built by `export_sql`.
 *   DB content is attacker-influenced via the UI/CLI `task_description`
 *   input and via the DB-import channel (`on_import` replaces openadapt.db
 *   from a user-chosen bz2 file). These are DB-resident sources, modeled per
 *   the "DB content reused into SQL" source family; the DB round-trip itself
 *   is not trackable by data-flow analysis.
 * - The remaining source branches mark the external origins of that taint
 *   (fire CLI parameter, nicegui widgets, import channel). They cannot reach
 *   the SQL sinks without the DB round-trip and are retained for recall and
 *   for documentation of the full chain.
 * - File restriction uses basename matching (`File.getShortName()`), which
 *   is path-separator safe; combined with the line/receiver/parameter-name
 *   restrictions from the labels each branch is project-unique.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {

  /** Restricts `n` to the openadapt source file with the given basename. */
  private predicate inPyFile(AstNode n, string basename) {
    n.getLocation().getFile().getShortName() = basename
  }

  /**
   * Labels pass5-src-028..pass5-src-035: the 8 `recording.<column>` reads
   * interpolated into the `export_sql` f-string at openadapt/crud.py:142.
   *
   * crud.py:139 `recording = get_recording_by_id(recording_id)`
   * crud.py:142 `sql = f"INSERT INTO recording VALUES ({recording.id}, ...,
   *              '{recording.platform}', '{recording.task_description}')"`
   */
  private predicate recordingColumnAtCrud142(DataFlow::Node source) {
    exists(Attribute a |
      inPyFile(a, "crud.py") and
      a.getLocation().getStartLine() = 142 and
      a.getObject().(Name).getId() = "recording" and
      a.getName() in [
        "id",
        "timestamp",
        "monitor_width",
        "monitor_height",
        "double_click_interval_seconds",
        "double_click_distance_pixels",
        "platform",
        "task_description"
      ] and
      source.asExpr() = a
    )
  }

  /**
   * Label pass5-src-065: the fire-exposed CLI parameter
   * `record(task_description)` (openadapt/record.py:507-508), the ultimate
   * external origin of `Recording.task_description`.
   */
  private predicate recordTaskDescriptionParam(DataFlow::Node source) {
    exists(Parameter p |
      inPyFile(p, "record.py") and
      p.getLocation().getStartLine() = 508 and
      p.getName() = "task_description" and
      p.getPosition() = 0 and
      exists(Function f |
        f.getName() = "record" and
        f.getArg(0) = p
      ) and
      source = DataFlow::parameterNode(p)
    )
  }

  /**
   * Label pass5-src-007: the nicegui text-input widget call
   * `ui.input(label="Name", ...)` (openadapt/app/cards.py:44) whose typed
   * text becomes the recording name / task description.
   */
  private predicate uiInputWidgetCall(DataFlow::Node source) {
    exists(Call c |
      inPyFile(c, "cards.py") and
      c.getLocation().getStartLine() = 44 and
      c.getFunc().(Attribute).getName() = "input" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "ui" and
      source.asExpr() = c
    )
  }

  /**
   * Labels pass5-src-006 and pass5-src-054: `LocalFilePicker(...)` calls
   * (openadapt/app/cards.py:21 import flow, and
   * openadapt/app/objects/local_file_picker.py:101 module demo) returning
   * user-selected file paths.
   */
  private predicate localFilePickerCall(DataFlow::Node source) {
    exists(Call c |
      c.getFunc().(Name).getId() = "LocalFilePicker" and
      (
        (inPyFile(c, "cards.py") and c.getLocation().getStartLine() = 21)
        or
        (inPyFile(c, "local_file_picker.py") and c.getLocation().getStartLine() = 101)
      ) and
      source.asExpr() = c
    )
  }

  /**
   * Label pass5-src-053: the nicegui grid event payload subscript
   * `msg["args"]` (openadapt/app/objects/local_file_picker.py:87) carrying
   * the user-chosen import file path.
   */
  private predicate pickerEventPayload(DataFlow::Node source) {
    exists(Subscript s |
      inPyFile(s, "local_file_picker.py") and
      s.getLocation().getStartLine() = 87 and
      s.getObject().(Name).getId() = "msg" and
      source.asExpr() = s
    )
  }

  /**
   * Labels pass5-src-097, -098, -099: the DB-import channel argument nodes
   * in `on_import` (openadapt/app/util.py:20-23), which decompress a
   * user-chosen bz2 file over openadapt.db:
   *   :21 `open(src, "wb")`
   *   :22 `bz2.BZ2File(selected_file, "rb")`
   *   :23 `copyfileobj(f2, f)`
   */
  private predicate importChannelArgument(DataFlow::Node source) {
    exists(Call c |
      inPyFile(c, "util.py") and
      source.asExpr() = c.getPositionalArg(0) and
      (
        (
          c.getLocation().getStartLine() = 21 and
          c.getFunc().(Name).getId() = "open"
        )
        or
        (
          c.getLocation().getStartLine() = 22 and
          c.getFunc().(Attribute).getName() = "BZ2File" and
          c.getFunc().(Attribute).getObject().(Name).getId() = "bz2"
        )
        or
        (
          c.getLocation().getStartLine() = 23 and
          c.getFunc().(Name).getId() = "copyfileobj"
        )
      )
    )
  }

  /**
   * Holds if `source` is a CWE-89 taint source for the given pass key.
   * Only `passKey = "sql_injection"` (Pass 5) is defined in this round.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "sql_injection" and
    (
      recordingColumnAtCrud142(source)
      or
      recordTaskDescriptionParam(source)
      or
      uiInputWidgetCall(source)
      or
      localFilePickerCall(source)
      or
      pickerEventPayload(source)
      or
      importChannelArgument(source)
    )
  }
}
