/**
 * @name Universal Path Traversal Sink Finder (Max Recall)
 * @description Broadly locates potential Path Traversal (CWE-22) sinks using pure AST matching, including path construction, resolution, file operations, and security rule matching. Designed for maximum recall across all Python projects.
 * @id python/universal-path-traversal-sinks
 * @kind problem
 * @problem.severity warning
 */

import python

// 定义所有可能导致路径穿越/任意文件操作/安全规则绕过的函数/方法/类名集合
predicate is_path_traversal_func_name(string name) {
  name in [
    // --- 新增：路径构建与解析 (漏洞的真正起点) ---
    "join",         // os.path.join
    "abspath",      // os.path.abspath
    "realpath",     // os.path.realpath
    "normpath",     // os.path.normpath
    "expanduser",   // os.path.expanduser
    "expandvars",   // os.path.expandvars
    "resolve",      // pathlib.Path.resolve

    // --- 新增：路径验证与匹配 (安全规则绕过，如 Flask-CORS 漏洞) ---
    "match",        // re.match, try_match
    "search",       // re.search
    "startswith",   // str.startswith (常用于前缀检查)
    "endswith",     // str.endswith
    "fnmatch",      // fnmatch.fnmatch
    "validate_path",// 常见的自定义验证函数名
    "check_access", // 常见的自定义权限检查函数名
    "try_match",    // Flask-CORS 等库中的匹配函数

    // 1. 基础文件读写 (内置函数与 pathlib.Path 方法)
    "open", "read_text", "read_bytes", "write_text", "write_bytes",
    
    // 2. os 模块 (文件与目录的危险操作)
    "remove", "unlink", "rename", "renames", "replace", 
    "mkdir", "makedirs", "rmdir", "removedirs", "chdir",
    "chmod", "chown", "lchown", "utime", "truncate",
    
    // 3. shutil 模块 (高级文件/目录操作)
    "copy", "copy2", "copyfile", "copytree", "move", "rmtree", 
    "make_archive", "unpack_archive",
    
    // 4. 压缩包操作 (常用于 Zip Slip 漏洞或读取任意文件)
    "ZipFile", "TarFile", "extract", "extractall",
    
    // 5. Web 框架专用文件发送函数 (Flask, Django, FastAPI, aiohttp 等)
    "send_file", "send_from_directory", "FileResponse"
  ]
}

from AstNode sink, string funcName
where
  // 捕获所有函数/方法/类实例化调用
  exists(Call call, Expr func |
    call.getFunc() = func and
    (
      func.(Name).getId() = funcName or
      func.(Attribute).getName() = funcName
    ) and
    is_path_traversal_func_name(funcName) and
    sink = call
  )
  // 新增：捕获 pathlib 的除法运算符重载 (Path(base) / user_input)
  or
  exists(BinaryExpr binop |
    binop.getOp() instanceof Div and
    sink = binop and
    funcName = "pathlib_division (/)"
  )
select sink,
  "Potential Path Traversal sink (" + funcName + ") found at " + 
  sink.getLocation().getFile().getRelativePath() + ":" + 
  sink.getLocation().getStartLine().toString()
