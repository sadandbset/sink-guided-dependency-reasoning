/**
 * @name LangChain source candidate extraction (Pass 2, CWE-78)
 * @description
 *   Extracts input-boundary API candidates for CWE-78 labeling from the
 *   LangChain codebase (vulnerable snapshot, pre-0.0.2xx layout with
 *   agents/chains/tools/utilities). Boundaries are derived from repository
 *   evidence:
 *   - tool input boundary: run/_run/_arun/__call__ methods of BaseTool
 *     subclasses (tool input originates from LLM output / AgentAction),
 *   - chain input boundary: call/_call/acall/_acall of Chain subclasses
 *     (AgentExecutor extends Chain; user input enters here),
 *   - LLM output boundary: generate/_generate/call/_call of
 *     BaseLLM / BaseChatModel subclasses (prompt-injection carrier),
 *   - agent output parsers: parse() of AgentOutputParser subclasses
 *     (produces AgentAction.tool_input from raw LLM text),
 *   - AgentAction.tool_input reads in the agent loop,
 *   - deserialization (json.loads) of LLM/external text,
 *   - environment variables and sys.argv reads.
 *   Columns: node, kind, api, module, receiver, flow_kind, arg_index,
 *   file, line, boundary.
 * @kind problem
 * @id py/augur/langchain/extract-sources
 * @problem.severity recommendation
 */

import python

/* ------------------------------------------------------------------ */
/* Input boundary shapes                                              */
/* ------------------------------------------------------------------ */

/**
 * Holds if class `c` is named `name`, declares a base expression named
 * `name`, or transitively inherits through same-named base declarations
 * (`Class.getABase()` yields unresolved base expressions in this pack).
 */
predicate classHasBaseNamed(Class c, string name) {
  c.getName() = name
  or
  exists(Expr e | e = c.getABase() and e.(Name).getId() = name)
  or
  exists(Class b, Expr e |
    e = c.getABase() and
    e.(Name).getId() = b.getName() and
    classHasBaseNamed(b, name)
  )
}

/**
 * A run/_run/_arun/__call__ method defined on a BaseTool subclass.
 * The single input argument is the tool input, which agents populate
 * from AgentAction.tool_input (LLM output).
 */
class ToolInputMethod extends Function {
  ToolInputMethod() {
    this.getScope() instanceof Class and
    classHasBaseNamed(this.getScope().(Class), "BaseTool") and
    this.getName() in ["run", "_run", "_arun", "__call__"]
  }

  /** Gets the input parameter of the tool entrypoint (first non-callback). */
  Parameter getToolInputParam() {
    result = this.getAnArg() and
    not result.getName() in [
      "run_manager", "verbose", "color", "callbacks", "self", "cls",
      "start_color", "tags", "metadata", "kwargs"
    ]
  }
}

/**
 * A call/_call/acall/_acall/run method defined on a Chain subclass
 * (including AgentExecutor). `inputs` is the user-facing boundary.
 */
class ChainInputMethod extends Function {
  ChainInputMethod() {
    this.getScope() instanceof Class and
    classHasBaseNamed(this.getScope().(Class), "Chain") and
    this.getName() in ["call", "_call", "acall", "_acall", "run", "arun"]
  }

  /** Gets the inputs parameter of the chain entrypoint. */
  Parameter getChainInputParam() {
    result = this.getAnArg() and
    result.getName() in ["inputs", "input"]
  }
}

/**
 * A generate/_generate/call/predict method defined on a BaseLLM or
 * BaseChatModel subclass. Return values carry raw LLM output, the
 * prompt-injection carrier for agent-driven command injection.
 */
class LlmOutputMethod extends Function {
  LlmOutputMethod() {
    this.getScope() instanceof Class and
    (
      classHasBaseNamed(this.getScope().(Class), "BaseLLM") or
      classHasBaseNamed(this.getScope().(Class), "BaseChatModel") or
      classHasBaseNamed(this.getScope().(Class), "BaseLanguageModel")
    ) and
    this.getName() in ["generate", "_generate", "call", "predict", "generate_prompt"]
  }
}

/**
 * A parse() method on an AgentOutputParser subclass. It converts raw LLM
 * text into AgentAction(action, tool_input, ...); the returned object's
 * tool_input field is the direct ancestor of tool arguments.
 */
class AgentParseMethod extends Function {
  AgentParseMethod() {
    this.getScope() instanceof Class and
    classHasBaseNamed(this.getScope().(Class), "AgentOutputParser") and
    this.getName() = "parse"
  }
}

/**
 * A read of `<obj>.tool_input` under langchain/agents/**, the value the
 * agent loop forwards into tool.run(...).
 */
class AgentToolInputRead extends Attribute {
  AgentToolInputRead() {
    this.getName() = "tool_input" and
    this.getLocation().getFile().getRelativePath().matches("langchain/agents/%")
  }
}

/** A call to `json.loads` / `json.load` (deserialized LLM/external text). */
class JsonLoadCall extends Call {
  JsonLoadCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() in ["loads", "load"] and
    this.getFunc().(Attribute).getObject().(Name).getId() = "json"
  }
}

/** A read of `os.environ` (including `os.environ[...]` / `.get(...)`). */
class OsEnvironRead extends Attribute {
  OsEnvironRead() {
    this.getName() = "environ" and
    this.getObject().(Name).getId() = "os"
  }
}

/** A call to `os.getenv(name, ...)`. */
class OsGetenvCall extends Call {
  OsGetenvCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() = "getenv" and
    this.getFunc().(Attribute).getObject().(Name).getId() = "os"
  }
}

/** A read of `sys.argv` (including `sys.argv[...]`). */
class SysArgvRead extends Attribute {
  SysArgvRead() {
    this.getName() = "argv" and
    this.getObject().(Name).getId() = "sys"
  }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/** Test/fixture paths, excluded from candidate extraction. */
predicate isExcludedPath(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    (
      path.matches("tests/%")
      or path.matches("%/tests/%")
      or path.matches("test/%")
      or path.matches("%/test_%")
      or path.matches("%/test/%")
    )
  )
}

/**
 * Gets the receiver label for a function definition: the enclosing class
 * name for methods, "-" otherwise.
 */
string definitionReceiver(Function f) {
  exists(Class c | c = f.getEnclosingScope() | result = c.getName())
  or
  (
    not f.getEnclosingScope() instanceof Class and
    result = "-"
  )
}

/* ------------------------------------------------------------------ */
/* Candidate rows                                                     */
/* ------------------------------------------------------------------ */

/**
 * Holds if `n` is a source candidate with the given metadata.
 * `flowKind`: "return" (call/method yields untrusted data),
 *             "value" (attribute read of untrusted data),
 *             "param" (definition parameter).
 */
predicate sourceCandidate(
  AstNode n, string kind, string api, string moduleName, string receiver,
  string flowKind, int argIndex, string boundary
) {
  /* tool entrypoint definitions: BaseTool subclass run/_run/_arun */
  exists(ToolInputMethod f, Parameter p |
    n = p and
    p = f.getToolInputParam() and
    kind = "tool_input_param" and
    api = f.getQualifiedName() and
    moduleName = f.getEnclosingModule().getName() and
    receiver = definitionReceiver(f) and
    flowKind = "param" and
    argIndex = p.getPosition() and
    boundary = "tool_input_from_agent_action"
  )
  or
  /* chain entrypoint definitions: Chain subclass call/_call/acall/_acall */
  exists(ChainInputMethod f, Parameter p |
    n = p and
    p = f.getChainInputParam() and
    kind = "chain_input_param" and
    api = f.getQualifiedName() and
    moduleName = f.getEnclosingModule().getName() and
    receiver = definitionReceiver(f) and
    flowKind = "param" and
    argIndex = p.getPosition() and
    boundary = "chain_user_input"
  )
  or
  /* LLM/chat generation methods: return values carry LLM output */
  exists(LlmOutputMethod f |
    n = f and
    kind = "definition" and
    api = f.getQualifiedName() and
    moduleName = f.getEnclosingModule().getName() and
    receiver = definitionReceiver(f) and
    flowKind = "return" and
    argIndex = -1 and
    boundary = "llm_output"
  )
  or
  /* agent output parsers: AgentAction.tool_input ancestor */
  exists(AgentParseMethod f |
    n = f and
    kind = "definition" and
    api = f.getQualifiedName() and
    moduleName = f.getEnclosingModule().getName() and
    receiver = definitionReceiver(f) and
    flowKind = "return" and
    argIndex = -1 and
    boundary = "parsed_llm_action"
  )
  or
  /* `<agent_action>.tool_input` reads in the agent loop */
  exists(AgentToolInputRead a |
    n = a and
    kind = "attribute_read" and
    api = "AgentAction.tool_input" and
    moduleName = a.getEnclosingModule().getName() and
    receiver = a.getObject().toString() and
    flowKind = "value" and
    argIndex = -1 and
    boundary = "agent_tool_input"
  )
  or
  /* `json.loads` / `json.load`: deserialized LLM/external text */
  exists(JsonLoadCall c |
    n = c and
    kind = "call" and
    api = "json." + c.getFunc().(Attribute).getName() and
    moduleName = c.getEnclosingModule().getName() and
    receiver = "json" and
    flowKind = "return" and
    argIndex = 0 and
    boundary = "deserialized_text"
  )
  or
  /* `os.environ` reads */
  exists(OsEnvironRead a |
    n = a and
    kind = "attribute_read" and
    api = "os.environ" and
    moduleName = a.getEnclosingModule().getName() and
    receiver = "os" and
    flowKind = "value" and
    argIndex = -1 and
    boundary = "environment"
  )
  or
  /* `os.getenv()` calls */
  exists(OsGetenvCall c |
    n = c and
    kind = "call" and
    api = "os.getenv" and
    moduleName = c.getEnclosingModule().getName() and
    receiver = "os" and
    flowKind = "return" and
    argIndex = 0 and
    boundary = "environment"
  )
  or
  /* `sys.argv` reads */
  exists(SysArgvRead a |
    n = a and
    kind = "attribute_read" and
    api = "sys.argv" and
    moduleName = a.getEnclosingModule().getName() and
    receiver = "sys" and
    flowKind = "value" and
    argIndex = -1 and
    boundary = "cli_args"
  )
}

from AstNode n, string kind, string api, string moduleName, string receiver, string flowKind, int argIndex, string boundary
where
  sourceCandidate(n, kind, api, moduleName, receiver, flowKind, argIndex, boundary) and
  not isExcludedPath(n)
select n, "source_candidate", api, moduleName, receiver, flowKind, argIndex,
  n.getLocation().getFile().getRelativePath(),
  n.getLocation().getStartLine(),
  boundary
