
/**
 * @name Abilian-devtools source candidates (Phase 1, Pass 2, CWE-78)
 * @description Syntactic extraction of external-input candidates for manual
 *              LLM labeling. This project is a Typer CLI tool ("adt"); the
 *              observed input boundary is CLI arguments reaching Typer command
 *              handlers. These are candidates, not confirmed
 *              attacker-controlled sources.
 * @kind problem
 * @id py/abilian-devtools/extraction/sources
 * @problem.severity recommendation
 */

import python

/** Exclude test files (defensive: this repo has no tests/ directory). */
predicate inProductionCode(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    not path.matches("tests/%") and
    not path.matches("%/tests/%") and
    not path.matches("test/%") and
    not path.matches("%/test/%")
  )
}

/**
 * The module declares a Typer application:
 * it imports typer and contains a `typer.Typer()` call at module level.
 */
predicate moduleUsesTyper(Module m) {
  exists(Import i |
    i.getScope() = m and
    i.getAnImportedModuleName() = "typer"
  )
  and
  exists(Call c, Attribute attr, Name recv |
    c.getScope() = m and
    attr = c.getFunc() and
    attr.getName() = "Typer" and
    recv = attr.getObject() and
    recv.getId() = "typer"
  )
}

/**
 * A Typer command/callback handler: a function decorated with
 * `@<app>.command(...)` or `@<app>.callback(...)` in a module that
 * uses Typer. `Function.getADecorator()` returns the decorator call's
 * callee expression, i.e. the `<app>.command` attribute.
 *
 * This is syntactic matching; the LLM labeling step confirms each handler.
 */
predicate isTyperHandler(Function f) {
  moduleUsesTyper(f.getEnclosingModule()) and
  exists(Attribute attr, Name recv |
    attr = f.getADecorator() and
    attr.getName() in ["command", "callback"] and
    recv = attr.getObject()
  )
}

/**
 * Module name for project-internal functions.
 */
string moduleOf(Function f) {
  result = f.getEnclosingModule().getName()
  or
  (
    not exists(f.getEnclosingModule().getName()) and
    result = f.getLocation().getFile().getBaseName()
  )
}

/*
 * Extract external-input candidates.
 *
 * Output fields:
 * 1. AST node
 * 2. candidate type
 * 3. callable name
 * 4. flow kind
 * 5. receiver hint
 * 6. module hint
 * 7. argument index
 * 8. file
 * 9. line
 */
from
  AstNode node,
  string callableName,
  string flowKind,
  string receiverHint,
  string moduleHint,
  int argIndex
where
  inProductionCode(node) and
  (
    // 1. Typer command/callback handler parameters.
    //    Primary CLI input boundary of this project: e.g. `check(args)` in
    //    abilian/devtools/main.py receives user-supplied file/directory names.
    exists(Function f, Parameter p, int i |
      isTyperHandler(f) and
      f.getArg(i) = p and
      node = p.asName() and
      callableName = f.getName() and
      flowKind = "param" and
      receiverHint = "" and
      moduleHint = moduleOf(f) and
      argIndex = i
    )
    or
    // 2. Typer explicit input declarations: typer.Argument / typer.Option.
    //    Framework input family; not used in this repo, yields no rows.
    exists(Call c, Attribute attr, Name recv |
      node = c and
      attr = c.getFunc() and
      attr.getName() in ["Argument", "Option"] and
      recv = attr.getObject() and
      recv.getId() = "typer" and
      callableName = attr.getName() and
      flowKind = "argument" and
      receiverHint = "typer" and
      moduleHint = "typer" and
      argIndex = 0
    )
    or
    // 3. sys.argv subscript access: sys.argv[...].
    //    Generic CLI family; `sys` is imported in this project but argv is
    //    not accessed, so this currently yields no rows.
    exists(Subscript s, Attribute argv, Name sysName |
      node = s and
      argv = s.getObject() and
      argv.getName() = "argv" and
      sysName = argv.getObject() and
      sysName.getId() = "sys" and
      callableName = "__getitem__" and
      flowKind = "return" and
      receiverHint = "sys.argv" and
      moduleHint = "sys" and
      argIndex = -1
    )
    or
    // 4. Plain sys.argv attribute access (e.g. `for a in sys.argv`).
    //    Generic CLI family; currently unused in this repo.
    exists(Attribute argv, Name sysName |
      node = argv and
      argv.getName() = "argv" and
      sysName = argv.getObject() and
      sysName.getId() = "sys" and
      callableName = "argv" and
      flowKind = "field" and
      receiverHint = "sys" and
      moduleHint = "sys" and
      argIndex = -1
    )
  )
select
  node,
  "source_candidate",
  callableName,
  flowKind,
  receiverHint,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getRelativePath(),
  node.getLocation().getStartLine()
