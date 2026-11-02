# Augur IRIS Report

Generated at: `2026-10-15T05:27:39.126949+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 414 | 21 | 0 | 5 | 46 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 8 | 0 | 8 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `langchain/utilities/bash.py:73` `py/augur/langchain/pass2-command-injection`: Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `langchain/utilities/bash.py:77` `py/augur/langchain/pass2-command-injection`: Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `langchain/utilities/bash.py:102` `py/augur/langchain/pass2-command-injection`: Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `langchain/utilities/jira.py:192` `py/augur/langchain/pass2-command-injection`: Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `langchain/utilities/python.py:19` `py/augur/langchain/pass2-command-injection`: Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `langchain/tools/python/tool.py:58` `py/augur/langchain/pass2-command-injection`: Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `langchain/tools/python/tool.py:108` `py/augur/langchain/pass2-command-injection`: Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `langchain/tools/shell/tool.py:69` `py/augur/langchain/pass2-command-injection`: Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
Untrusted input flows from [untrusted source](1) into a command/code execution sink ([execution sink](2)). Augur pass 2 (CWE-078, prompt-injection threat model): the source is a reviewed tp label, and the sink is a labeled shell/exec surface in the agent tool-dispatch chain (AgentExecutor -> BaseTool.run -> ShellTool/PythonREPL* -> BashProcess -> subprocess/exec). Review before treating as a vulnerability.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
