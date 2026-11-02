/**
 * @name openapi-python-client CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   openapi-python-client CodeQL database (snapshot d6970d6, openapi-python-
 *   client 0.5.2 - the typer CLI tool itself is the audit target): the remote
 *   document fetch boundary (httpx.get(url) at openapi_python_client/
 *   __init__.py:71 - the OpenAPI document HTTP fetch whose RETURN VALUE
 *   carries the remote body; url is the operator CLI --url, Pass 3 material -
 *   and the response.content attribute read at :72 where the remote document
 *   bytes enter local flow as yaml_bytes); the document file read boundary
 *   (path.read_bytes() at __init__.py:76 - the CLI --path document file,
 *   operator-selected target, external content); the document parse boundary
 *   (yaml.safe_load(yaml_bytes) at __init__.py:80 - THE boundary where every
 *   remote document field enters: info.title, info.version, paths,
 *   components.schemas names+titles, operation.tags); the config file
 *   boundary (yaml.safe_load(path.read_text()) at openapi_python_client/
 *   config.py:34 inside Config.load_from_path - the --config parse producing
 *   project_name_override / package_name_override / class_overrides, plus
 *   path.read_text() itself at config.py:34 as the config content read); the
 *   pydantic parse boundary (oai.OpenAPI.parse_obj(d) at parser/openapi.py:
 *   300 - the returned object carries title/version/paths/schemas/tags into
 *   GeneratorData); the remote-name field reads that become filesystem names
 *   (openapi.title __init__.py:94 and openapi.version :100,
 *   self.openapi.title :99, openapi.info.title/description/version
 *   parser/openapi.py:311-313, operation.tags openapi.py:51 - later the RAW
 *   f"{tag}.py" file name -, data.title openapi.py:230/:271 feeding
 *   Reference.from_ref); the module-name boundary reads
 *   (model.reference.module_name / enum.reference.module_name inside the
 *   f-string join expressions __init__.py:196 and :203 - the remote-derived
 *   module name at the moment it becomes a file name); the config-derived
 *   field reads (self.project_name_override / self.package_name_override at
 *   __init__.py:94/:97 and self.class_overrides at config.py:21); and the
 *   typer CLI entry parameters (config of cli() cli.py:34 - decorated
 *   @app.callback -, url/path of generate() cli.py:97 and update()
 *   cli.py:115 - decorated @app.command -, and path of _process_config()
 *   cli.py:20 - the --config Option callback target - OPERATOR-TRUST level,
 *   recorded for labeling to classify, not automatically attacker sources).
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong shape
 *   for candidate tables and @kind table is not assumed to exist.
 * @id iris/openapi-python-client/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql and to the prior projects in
 * this series):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (e.g. "get", "content",
 *                   "read_bytes", "safe_load", "parse_obj", "title", "tags",
 *                   "module_name", "project_name_override", the function
 *                   name for cli_param parameter rows)
 *   4. flow_kind  - "http_fetch" (httpx.get document fetch; the RETURN VALUE
 *                   carries the remote body), "http_content"
 *                   (response.content - the remote document bytes),
 *                   "doc_read" (path.read_bytes - the CLI --path document
 *                   file content), "yaml_load" (yaml.safe_load of the
 *                   document - the dominant parse boundary),
 *                   "config_read" (path.read_text of the CLI --config file),
 *                   "config_load" (yaml.safe_load of the config file),
 *                   "parse_obj" (oai.OpenAPI.parse_obj - the pydantic parse
 *                   boundary; the return value carries the parsed document
 *                   fields), "openapi_field" (attribute reads of the
 *                   remote-document name fields that become filesystem
 *                   names: title/version/tags), "name_field"
 *                   (model.reference.module_name / enum.reference.
 *                   module_name reads inside the f-string joins),
 *                   "config_field" (self.project_name_override /
 *                   self.package_name_override / self.class_overrides reads
 *                   - config-derived name overrides), "cli_param" (the typer
 *                   entry parameters: config of cli, url/path of
 *                   generate/update, path of _process_config -
 *                   operator-trust level)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "httpx"/"response"/"path"/"yaml"/"oai"/
 *                   "self" etc., or "" if none; the root base name
 *                   ("model"/"enum") for the name_field rows; enclosing
 *                   class name for parameter rows if any)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "httpx"/"yaml" for the external channels
 *   7. arg_index  - 0-based positional argument index (index of the
 *                   carrying argument for keyed reads); -1 when the tainted
 *                   value is the return value, the attribute itself, or the
 *                   receiver; for "cli_param" rows the 0-based parameter
 *                   position in the function definition (including the
 *                   self/cls slot for methods)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no source row is expected to resolve at API level:
 * the HTTP/YAML boundaries flow through external libraries not part of the
 * database (httpx, yaml, pydantic, typer - only openapi_python_client and
 * tests are in the database), and the field boundaries flow through instance
 * attributes on local variables. All families below are AST-level matches
 * and the match_kind column is kept "ast" for cross-project contract
 * consistency.
 *
 * Excluded paths (applied to every row): /tests/ (unit test tree),
 * /end_to_end_tests/ (fastapi fixture app + golden-master generated client
 * + regen script), /openapi-python-client-db/ (the CodeQL database
 * directory sits inside the source tree).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  have no dotted module name; their file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
}

/** Forward-slash-normalized absolute path of the file containing n, so path
 *  matching works with both CodeQL path styles on Windows. */
string normalizedPathOf(AstNode n) {
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
}

/** Base name of the object expression of an attribute access, used as a receiver hint. */
string receiverHint(Attribute a) {
  result = a.getObject().(Name).getId()
  or
  result = a.getObject().(Attribute).getName()
  or
  not a.getObject() instanceof Name and
  not a.getObject() instanceof Attribute and
  result = "<expr>"
}

/** True iff the candidate's file path is one of the excluded trees. Path is
 *  normalized to forward slashes before matching so the query works on both
 *  CodeQL path styles. bindingset[path] declares that the caller passes a
 *  bound path (the path only appears in checked positions such as the
 *  receiver of replaceAll/matches inside this predicate). */
bindingset[path]
predicate excludedPath(string path) {
  path.replaceAll("\\", "/").matches("%/tests/%")
  or
  path.replaceAll("\\", "/").matches("%/end_to_end_tests/%")
  or
  path.replaceAll("\\", "/").matches("%/openapi-python-client-db/%")
}

/* ------------------------------------------------------------------ */
/* Shared openapi-python-client shapes (kept consistent with sinks.ql)   */
/* ------------------------------------------------------------------ */

/** The generator core module (openapi_python_client/__init__.py) where the
 *  document fetch/read, the yaml parse, the project_dir construction and all
 *  file operations live. bindingset rationale as in excludedPath. */
bindingset[path]
private predicate generatorCoreModule(string path) {
  path.matches("%/openapi_python_client/__init__.py")
}

/** The config module (openapi_python_client/config.py). Same bindingset
 *  rationale as excludedPath. */
bindingset[path]
private predicate configModule(string path) {
  path.matches("%/openapi_python_client/config.py")
}

/** The OpenAPI parser module (openapi_python_client/parser/openapi.py).
 *  Same bindingset rationale as excludedPath. */
bindingset[path]
private predicate parserModule(string path) {
  path.matches("%/openapi_python_client/parser/openapi.py")
}

/** The typer CLI module (openapi_python_client/cli.py). Same bindingset
 *  rationale as excludedPath. */
bindingset[path]
private predicate cliModule(string path) {
  path.matches("%/openapi_python_client/cli.py")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: remote document fetch boundary: httpx.get(url) -
     openapi_python_client/__init__.py:71 inside _get_document (the --url
     branch). The RETURN VALUE (the httpx Response) carries the remote
     document body, hence argIndex -1. The url argument itself is the
     operator CLI --url value (Pass 3 SSRF material, recorded there; the
     document CONTENT is the Pass 1 relevant input). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Name).getId() = "httpx" and
    generatorCoreModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "http_fetch" and
    callableName = "get" and
    argIndex = -1 and
    receiver = "httpx" and
    moduleHint = "httpx" and
    matchKind = "ast"
  )
  or
  /* family 2: remote document content read: response.content -
     __init__.py:72 - the remote document bytes entering local data flow as
     yaml_bytes (the value passed to yaml.safe_load). The attribute VALUE
     carries the remote content, hence argIndex -1. */
  exists(Attribute a |
    a.getName() = "content" and
    a.getObject().(Name).getId() = "response" and
    generatorCoreModule(normalizedPathOf(a)) and
    node = a and
    flowKind = "http_content" and
    callableName = "content" and
    argIndex = -1 and
    receiver = "response" and
    moduleHint = "httpx" and
    matchKind = "ast"
  )
  or
  /* family 3: document file read boundary: path.read_bytes() -
     __init__.py:76 inside _get_document (the --path branch): reads the
     CLI-selected OpenAPI document file. The RETURN VALUE carries the
     document bytes, hence argIndex -1. Operator-selected target file,
     external content - trust classification is left to the labeling step. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "read_bytes" and
    func.getObject().(Name).getId() = "path" and
    generatorCoreModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "doc_read" and
    callableName = "read_bytes" and
    argIndex = -1 and
    receiver = "path" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 4: document/config parse boundary: yaml.safe_load(...) -
     __init__.py:80 (yaml.safe_load(yaml_bytes) inside _get_document - THE
     document parse boundary: every remote document field, including
     info.title, components.schemas names+titles and operation.tags, enters
     as the returned dict) and config.py:34 (yaml.safe_load(
     path.read_text()) inside Config.load_from_path - the --config parse
     producing project_name_override / package_name_override /
     class_overrides). The RETURN VALUE carries the parsed external
     content, hence argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "safe_load" and
    func.getObject().(Name).getId() = "yaml" and
    (
      (
        generatorCoreModule(normalizedPathOf(c)) and
        flowKind = "yaml_load"
      )
      or
      (
        configModule(normalizedPathOf(c)) and
        flowKind = "config_load"
      )
    ) and
    node = c and
    callableName = "safe_load" and
    argIndex = -1 and
    receiver = "yaml" and
    moduleHint = "yaml" and
    matchKind = "ast"
  )
  or
  /* family 5: config file content read: path.read_text() - config.py:34
     (the read whose result is passed to yaml.safe_load): the CLI --config
     file content entering the config parse. Return value boundary,
     argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "read_text" and
    func.getObject().(Name).getId() = "path" and
    configModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "config_read" and
    callableName = "read_text" and
    argIndex = -1 and
    receiver = "path" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6: pydantic parse boundary: oai.OpenAPI.parse_obj(d) -
     parser/openapi.py:300 inside GeneratorData.from_dict: validates and
     types the remote dict; the RETURNED object carries info.title,
     info.version, paths, components.schemas and operation tags into
     GeneratorData, hence argIndex -1. */
  exists(Call c, Attribute func, Attribute mid |
    func = c.getFunc().(Attribute) and
    func.getName() = "parse_obj" and
    mid = func.getObject().(Attribute) and
    mid.getName() = "OpenAPI" and
    mid.getObject().(Name).getId() = "oai" and
    parserModule(normalizedPathOf(c)) and
    node = c and
    flowKind = "parse_obj" and
    callableName = "parse_obj" and
    argIndex = -1 and
    receiver = "oai.OpenAPI" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 7: remote-document name field reads (the fields that become
     filesystem names):
     - openapi.title / openapi.version on the local GeneratorData variable
       in __init__.py:94/:100 (project_name and version construction -
       `.replace(' ', '-').lower()` at :94 is cosmetic, not a path guard),
     - self.openapi.title at __init__.py:99 (package_description),
     - openapi.info.title / .description / .version at parser/openapi.py:
       311-313 (GeneratorData fields),
     - operation.tags at parser/openapi.py:51 (EndpointCollection tag -
       later used RAW as the f"{tag}.py" module file name),
     - data.title at parser/openapi.py:230/:271 (Model/Enum reference
       source: Reference.from_ref(data.title or name)).
     The attribute VALUE carries the remote name, hence argIndex -1. */
  exists(Attribute a |
    (
      (
        (
          a.getName() = "title" or
          a.getName() = "version"
        ) and
        a.getObject().(Name).getId() = "openapi" and
        generatorCoreModule(normalizedPathOf(a))
      )
      or
      (
        a.getName() = "title" and
        a.getObject().(Attribute).getName() = "openapi" and
        a.getObject().(Attribute).getObject().(Name).getId() = "self" and
        generatorCoreModule(normalizedPathOf(a))
      )
      or
      (
        (
          a.getName() = "title" or
          a.getName() = "description" or
          a.getName() = "version"
        ) and
        a.getObject().(Attribute).getName() = "info" and
        a.getObject().(Attribute).getObject().(Name).getId() = "openapi" and
        parserModule(normalizedPathOf(a))
      )
      or
      (
        a.getName() = "tags" and
        a.getObject().(Name).getId() = "operation" and
        parserModule(normalizedPathOf(a))
      )
      or
      (
        a.getName() = "title" and
        a.getObject().(Name).getId() = "data" and
        parserModule(normalizedPathOf(a))
      )
    )
    and
    node = a and
    flowKind = "openapi_field" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 8: module-name boundary reads: model.reference.module_name /
     enum.reference.module_name inside the f-string join expressions
     __init__.py:196 (models_dir / f"{model.reference.module_name}.py") and
     :203 (models_dir / f"{enum.reference.module_name}.py") - the
     remote-derived module name at the exact moment it becomes a file name.
     The attribute VALUE carries the name, hence argIndex -1; receiver is
     the ROOT base name of the chain (model/enum). */
  exists(Attribute a, Attribute base |
    a.getName() = "module_name" and
    base = a.getObject().(Attribute) and
    base.getName() = "reference" and
    base.getObject() instanceof Name and
    generatorCoreModule(normalizedPathOf(a)) and
    node = a and
    flowKind = "name_field" and
    callableName = "module_name" and
    argIndex = -1 and
    receiver = base.getObject().(Name).getId() and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 9: config-derived field reads: self.project_name_override /
     self.package_name_override at __init__.py:94/:97 (Project class
     attributes, set from the config file in config.py:29-30 - they replace
     the title-derived project/package names) and self.class_overrides at
     config.py:21 (the Reference override map populated from the config:
     Reference(**dict(class_data)) at config.py:25 injects config-controlled
     class_name/module_name). The attribute VALUE carries the config
     content, hence argIndex -1. */
  exists(Attribute a |
    (
      (
        (
          a.getName() = "project_name_override" or
          a.getName() = "package_name_override"
        ) and
        a.getObject().(Name).getId() = "self" and
        (
          generatorCoreModule(normalizedPathOf(a))
          or
          configModule(normalizedPathOf(a))
        )
      )
      or
      (
        a.getName() = "class_overrides" and
        a.getObject().(Name).getId() = "self" and
        configModule(normalizedPathOf(a))
      )
    )
    and
    node = a and
    flowKind = "config_field" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "self" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 10: typer CLI entry parameters: config (position 1) of cli()
     cli.py:34 (decorated @app.callback - the --config Option parameter),
     url/path (positions 0/1) of generate() cli.py:97 and update()
     cli.py:115 (decorated @app.command - the --url/--path Option
     parameters), and path (position 0) of _process_config() cli.py:20 (the
     --config Option callback target invoked by typer with the option
     value). OPERATOR-TRUST level: the person invoking the CLI is the same
     trust domain as the options they pass - recorded for the labeling step
     to classify, not automatically attacker sources. The decorated handlers
     are identified via getADecorator() (there is no Decorator AST class). */
  exists(Function f, Parameter p |
    (
      (
        f.getName() = "cli" and
        p.getName() = "config"
      )
      or
      (
        (f.getName() = "generate" or f.getName() = "update") and
        (p.getName() = "url" or p.getName() = "path")
      )
    ) and
    cliModule(normalizedPathOf(f)) and
    exists(Expr dec | dec = f.getADecorator()) and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "cli_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    (
      f.getEnclosingScope() instanceof Class and
      receiver = f.getEnclosingScope().(Class).getName()
      or
      not f.getEnclosingScope() instanceof Class and
      receiver = ""
    )
  )
  or
  exists(Function f, Parameter p |
    f.getName() = "_process_config" and
    cliModule(normalizedPathOf(f)) and
    p.getName() = "path" and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "cli_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    (
      f.getEnclosingScope() instanceof Class and
      receiver = f.getEnclosingScope().(Class).getName()
      or
      not f.getEnclosingScope() instanceof Class and
      receiver = ""
    )
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "source_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
