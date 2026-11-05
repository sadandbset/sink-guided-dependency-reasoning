/**
 * @name Universal RCE & Deserialization Sink Finder (Max Recall)
 * @description Broadly locates potential OS command injection, code injection, and insecure deserialization sinks using pure AST matching.
 * @id python/universal-rce-deserialization-sinks
 * @kind problem
 * @problem.severity warning
 */

import python

// 定义所有可能导致命令执行、代码执行或反序列化的函数名集合
predicate is_dangerous_func_name(string name) {
  name in [
    // 1. subprocess & commands 模块 (包含隐式 shell=True 的高危函数)
    "Popen", "call", "check_call", "check_output", "run", 
    "getstatusoutput", "getoutput", "getstatus",
    
    // 2. os 模块 (执行与衍生)
    "system", "popen", "popen2", "popen3", "popen4",
    "execv", "execve", "execl", "execle", "execlp", "execlpe", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "startfile", // Windows 特有执行函数
    
    // 3. asyncio 异步执行
    "create_subprocess_shell", "create_subprocess_exec",
    
    // 4. pty 及其他底层模块
    "spawn",
    
    // 5. 动态代码执行 (CWE-94)
    "exec", "eval", "compile",
    
    // 6. 动态导入 (常用于沙箱逃逸或执行恶意模块)
    "__import__", "import_module",
    
    // 7. 反序列化 (CWE-502) - 覆盖 yaml, pickle, marshal, joblib, torch
    "load", "loads", "unsafe_load"
  ]
}

from AstNode sink, string funcName
where
  // ==========================================
  // 1. 捕获所有常规危险函数/方法调用
  // ==========================================
  exists(Call call, Expr func |
    call.getFunc() = func and
    (
      func.(Name).getId() = funcName or
      func.(Attribute).getName() = funcName
    ) and
    is_dangerous_func_name(funcName) and
    sink = call
  )
  or
  // ==========================================
  // 2. 专项捕获 shelve.open
  // 限制必须是 shelve.open，防止把普通的 open(file) 全部抓出来导致误报爆炸
  // ==========================================
  exists(Call call, Attribute attr |
    call.getFunc() = attr and
    attr.getName() = "open" and
    attr.getObject().(Name).getId() = "shelve" and
    funcName = "shelve.open" and
    sink = call
  )
  or
  // ==========================================
  // 3. 捕获 Python 2 的 exec 语句 (Statement)
  // ==========================================
  exists(Exec execStmt |
    sink = execStmt and
    funcName = "exec (statement)"
  )
select sink,
  "Potential RCE/Deserialization sink (" + funcName + ") found at " + 
  sink.getLocation().getFile().getRelativePath() + ":" + 
  sink.getLocation().getStartLine().toString()
