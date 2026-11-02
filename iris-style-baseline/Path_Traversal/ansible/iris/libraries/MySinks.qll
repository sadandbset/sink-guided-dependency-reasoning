/**
 * !! MACHINE-GENERATED from iris/labels/labels.json (pass 1, run ansible-pathtraversal-pass1-step3-20261021) !!
 * !! Do not edit by hand: regenerate with labels/work/build_libraries.py !!
 *
 * Sink nodes for the Pass 1 (Path Traversal) taint query of ansible.
 *
 * Every rule below is the CodeQL rendering of reviewed Pass 1 label entries
 * (role=sink). The label id -> predicate mapping, with source-code evidence,
 * is documented in report/query_generation_notes.md. Pass key: "path_traversal".
 */

private import python
private import semmle.python.dataflow.new.DataFlow

module MySinks {

  /* Shared call-shape helpers (AST level only; matched nodes are converted
     to DataFlow::Node via asExpr()/getParameter()). */

  /** A call to a bare name, e.g. open(...) / mkstemp(...) / to_bytes(...). */
  private predicate nameCall(Call c, string name) {
    c.getFunc().(Name).getId() = name
  }

  /** A module-qualified call, e.g. os.remove(...) / shutil.copyfile(...). */
  private predicate moduleCall(Call c, string mod, string func) {
    exists(Attribute f |
      f = c.getFunc().(Attribute) and
      f.getName() = func and
      f.getObject().(Name).getId() = mod
    )
  }

  /** os.path.<func>(...) in both spellings: `os.path.f(...)` and the
      `from os import path` form `path.f(...)`. */
  private predicate osPathCall(Call c, string func) {
    exists(Attribute f |
      f = c.getFunc().(Attribute) and
      f.getName() = func and
      (
        f.getObject().(Attribute).getName() = "path" and
        f.getObject().(Attribute).getObject().(Name).getId() = "os"
        or
        f.getObject().(Name).getId() = "path"
      )
    )
  }

  /** A method call whose receiver is `self`, or an attribute `receiver`
      (e.g. self._loader / self._connection). */
  private predicate methodCall(Call c, string method, string receiver) {
    exists(Attribute f, Expr obj |
      f = c.getFunc().(Attribute) and
      f.getName() = method and
      obj = f.getObject() and
      (obj.(Name).getId() = receiver or obj.(Attribute).getName() = receiver)
    )
  }

  /* ------------------------------------------------------------------
   * K1 - direct filesystem-operation argument sinks.
   * Node = the dangerous argument expression itself (the path TEXT, not a
   * file object). The receiver-split label signatures (bare-name form vs
   * os-qualified form of the same call sites) are folded into one rule per
   * API; module-side sites are included by the labels and only fire when
   * taint reaches them.
   * ------------------------------------------------------------------ */

  /** open/os.open/io.open/shelve.open argument 0 - read or create/write. */
  class FileOpenArg extends DataFlow::Node {
    FileOpenArg() {
      exists(Call c |
        (
          nameCall(c, "open")
          or moduleCall(c, "os", "open")
          or moduleCall(c, "io", "open")
          or moduleCall(c, "shelve", "open")
        ) and
        this.asExpr() = c.getArg(0)
      )
    }
  }

  /** os.remove/os.unlink/os.rmdir/shutil.rmtree argument 0 - deletion. */
  class FileDeleteArg extends DataFlow::Node {
    FileDeleteArg() {
      exists(Call c |
        (
          moduleCall(c, "os", "remove")
          or moduleCall(c, "os", "unlink")
          or moduleCall(c, "os", "rmdir")
          or moduleCall(c, "shutil", "rmtree")
        ) and
        this.asExpr() = c.getArg(0)
      )
    }
  }

  /** os.makedirs/os.mkdir argument 0, plus the ansible makedirs_safe(name)
      wrapper (utils/path.py:65-90 - realpath guard covers creation only). */
  class FileDirCreateArg extends DataFlow::Node {
    FileDirCreateArg() {
      exists(Call c |
        (
          moduleCall(c, "os", "makedirs")
          or moduleCall(c, "os", "mkdir")
          or nameCall(c, "makedirs_safe")
        ) and
        this.asExpr() = c.getArg(0)
      )
    }
  }

  /** os.symlink/os.link argument 1 - the created link path. */
  class FileCreateArg extends DataFlow::Node {
    FileCreateArg() {
      exists(Call c |
        (
          moduleCall(c, "os", "symlink")
          or moduleCall(c, "os", "link")
        ) and
        this.asExpr() = c.getArg(1)
      )
    }
  }

  /** os.rename/shutil.move argument 0 (destination argument 1 is equally
      path-relevant and covered when tainted via the default call-arg flow). */
  class FileMoveArg extends DataFlow::Node {
    FileMoveArg() {
      exists(Call c |
        (
          moduleCall(c, "os", "rename")
          or moduleCall(c, "shutil", "move")
        ) and
        this.asExpr() = c.getArg(0)
      )
    }
  }

  /** shutil.copyfile/copy/copy2/copytree argument 0 (source); the
      destination argument 1 is the write side. */
  class FileCopyArg extends DataFlow::Node {
    FileCopyArg() {
      exists(Call c |
        (
          moduleCall(c, "shutil", "copyfile")
          or moduleCall(c, "shutil", "copy")
          or moduleCall(c, "shutil", "copy2")
          or moduleCall(c, "shutil", "copytree")
        ) and
        this.asExpr() = c.getArg(0)
      )
    }
  }

  /** os.stat/os.lstat/os.path.getsize argument 0 - metadata/existence
      oracle (candidate-grade sinks kept for recall). */
  class FileStatArg extends DataFlow::Node {
    FileStatArg() {
      exists(Call c |
        (
          moduleCall(c, "os", "stat")
          or moduleCall(c, "os", "lstat")
          or osPathCall(c, "getsize")
        ) and
        this.asExpr() = c.getArg(0)
      )
    }
  }

  /** os.listdir/os.walk/os.readlink argument 0 - enumeration/link-target
      oracle (candidate-grade sinks kept for recall). */
  class FileReadArg extends DataFlow::Node {
    FileReadArg() {
      exists(Call c |
        (
          moduleCall(c, "os", "listdir")
          or moduleCall(c, "os", "walk")
          or moduleCall(c, "os", "readlink")
        ) and
        this.asExpr() = c.getArg(0)
      )
    }
  }

  /** os.chmod/os.chown/os.utime argument 0 - attribute change (candidate). */
  class FilePermsArg extends DataFlow::Node {
    FilePermsArg() {
      exists(Call c |
        (
          moduleCall(c, "os", "chmod")
          or moduleCall(c, "os", "chown")
          or moduleCall(c, "os", "utime")
        ) and
        this.asExpr() = c.getArg(0)
      )
    }
  }

  /** glob.glob argument 0 - enumeration via attacker-influenced pattern. */
  class PathGlobArg extends DataFlow::Node {
    PathGlobArg() {
      exists(Call c |
        moduleCall(c, "glob", "glob") and
        this.asExpr() = c.getArg(0)
      )
    }
  }

  /** tarfile.open(...)/ZipFile(...) argument 0 - archive read. */
  class ArchiveOpenArg extends DataFlow::Node {
    ArchiveOpenArg() {
      exists(Call c |
        (
          moduleCall(c, "tarfile", "open")
          or nameCall(c, "ZipFile")
          or moduleCall(c, "zipfile", "ZipFile")
        ) and
        this.asExpr() = c.getArg(0)
      )
    }
  }

  /* ------------------------------------------------------------------
   * K2 - galaxy role archive extraction (label p1-snk-269).
   * role_tar_file.extract(member, self.path) at galaxy/role.py:330.
   * Labeled arg_index 1 (self.path destination) is kept; argument 0 (the
   * member whose .name was rebuilt from untrusted parts at :329) is added
   * at generation time because tarfile writes files named member.name -
   * recorded as a review-return item in report/query_generation_notes.md.
   * ------------------------------------------------------------------ */
  class GalaxyExtractArg extends DataFlow::Node {
    GalaxyExtractArg() {
      exists(Call c |
        c.getFunc().(Attribute).getName() = "extract" and
        c.getFunc().(Attribute).getObject().(Name).getId() = "role_tar_file" and
        c.getScope().getEnclosingModule().getName() = "ansible.galaxy.role" and
        (this.asExpr() = c.getArg(0) or this.asExpr() = c.getArg(1))
      )
    }
  }

  /* ------------------------------------------------------------------
   * K3 - ansible wrapper call-site argument sinks.
   * Sinking the ARGUMENT node at the call site does not rely on CodeQL
   * resolving self._loader/self/self._connection dispatch.
   * ------------------------------------------------------------------ */

  /** self._loader.<m>(path) for m in get_real_file/_get_file_contents/
   * load_from_file/cleanup_tmp_file - argument 0 reaches the DataLoader
   * open() (dataloader.py:157/:355). */
  class LoaderCallArg extends DataFlow::Node {
    LoaderCallArg() {
      exists(Call c, string m |
        (
          m = "get_real_file"
          or m = "_get_file_contents"
          or m = "load_from_file"
          or m = "cleanup_tmp_file"
        ) and
        methodCall(c, m, "_loader") and
        this.asExpr() = c.getArg(0)
      )
    }
  }

  /** self.<m>(path) for m in _transfer_file/_transfer_data/
   * _execute_remote_stat/_remote_checksum - ActionBase file channel. */
  class ActionCallArg extends DataFlow::Node {
    ActionCallArg() {
      exists(Call c, string m, int idx |
        (
          m = "_transfer_file" and idx in [0, 1]
          or m = "_transfer_data" and idx = 0
          or m = "_execute_remote_stat" and idx = 0
          or m = "_remote_checksum" and idx = 0
        ) and
        methodCall(c, m, "self") and
        this.asExpr() = c.getArg(idx)
      )
    }
  }

  /** self._connection.fetch_file/put_file(src, dst) - argument 1 is the
      transfer destination (controller-side for fetch; fetch.py:172). */
  class ConnectionCallArg extends DataFlow::Node {
    ConnectionCallArg() {
      exists(Call c, string m, int idx |
        (m = "fetch_file" or m = "put_file") and
        idx in [0, 1] and
        methodCall(c, m, "_connection") and
        this.asExpr() = c.getArg(idx)
      )
    }
  }

  /* ------------------------------------------------------------------
   * K4 - ansible wrapper DEFINITION parameter sinks (file_api_def labels).
   * Secondary recall: fires only when CodeQL resolves the call to the
   * definition (argument-to-parameter edge).
   * ------------------------------------------------------------------ */
  private predicate defSinkSpec(string moduleName, string funcName, int paramIdx) {
    (moduleName = "ansible.parsing.dataloader" and funcName = "_get_file_contents" and paramIdx = 1)
    or (moduleName = "ansible.parsing.dataloader" and funcName = "cleanup_tmp_file" and paramIdx = 1)
    or (moduleName = "ansible.parsing.dataloader" and funcName = "get_real_file" and paramIdx = 1)
    or (moduleName = "ansible.parsing.dataloader" and funcName = "list_directory" and paramIdx = 1)
    or (moduleName = "ansible.parsing.dataloader" and funcName = "load_from_file" and paramIdx = 1)
    or (moduleName = "ansible.parsing.vault.__init__" and funcName = "_read_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.action.__init__" and funcName = "_execute_remote_stat" and paramIdx = 1)
    or (moduleName = "ansible.plugins.action.__init__" and funcName = "_get_diff_data" and paramIdx = 2)
    or (moduleName = "ansible.plugins.action.__init__" and funcName = "_remote_checksum" and paramIdx = 1)
    or (moduleName = "ansible.plugins.action.__init__" and funcName = "_transfer_data" and paramIdx = 1)
    or (moduleName = "ansible.plugins.action.__init__" and funcName = "_transfer_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.action.__init__" and funcName = "_transfer_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.buildah" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.buildah" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.buildah" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.buildah" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.chroot" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.chroot" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.chroot" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.chroot" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.docker" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.docker" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.docker" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.docker" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.funcd" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.funcd" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.funcd" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.funcd" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.jail" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.jail" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.jail" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.jail" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.kubectl" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.kubectl" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.kubectl" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.kubectl" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.libvirt_lxc" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.libvirt_lxc" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.libvirt_lxc" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.libvirt_lxc" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.local" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.local" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.local" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.local" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.lxc" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.lxc" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.lxc" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.lxc" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.lxd" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.lxd" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.lxd" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.lxd" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.paramiko_ssh" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.paramiko_ssh" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.paramiko_ssh" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.paramiko_ssh" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.persistent" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.persistent" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.persistent" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.persistent" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.podman" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.podman" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.podman" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.podman" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.psrp" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.psrp" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.psrp" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.psrp" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.qubes" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.qubes" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.qubes" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.qubes" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.saltstack" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.saltstack" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.saltstack" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.saltstack" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.ssh" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.ssh" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.ssh" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.ssh" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.vmware_tools" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.vmware_tools" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.vmware_tools" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.vmware_tools" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.winrm" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.winrm" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.winrm" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.winrm" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.zone" and funcName = "fetch_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.zone" and funcName = "fetch_file" and paramIdx = 2)
    or (moduleName = "ansible.plugins.connection.zone" and funcName = "put_file" and paramIdx = 1)
    or (moduleName = "ansible.plugins.connection.zone" and funcName = "put_file" and paramIdx = 2)
    or (moduleName = "ansible.utils.path" and funcName = "cleanup_tmp_file" and paramIdx = 0)
    or (moduleName = "ansible.utils.path" and funcName = "makedirs_safe" and paramIdx = 0)
  }

  class WrapperDefParam extends DataFlow::ParameterNode {
    WrapperDefParam() {
      exists(Function f, int idx |
        defSinkSpec(f.getScope().getEnclosingModule().getName(), f.getName(), idx) and
        this.getParameter() = f.getArg(idx)
      )
    }
  }

  /** Pass-1 sink predicate. passKey must be "path_traversal". */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and
    (
      sink instanceof FileOpenArg
      or sink instanceof FileDeleteArg
      or sink instanceof FileDirCreateArg
      or sink instanceof FileCreateArg
      or sink instanceof FileMoveArg
      or sink instanceof FileCopyArg
      or sink instanceof FileStatArg
      or sink instanceof FileReadArg
      or sink instanceof FilePermsArg
      or sink instanceof PathGlobArg
      or sink instanceof ArchiveOpenArg
      or sink instanceof GalaxyExtractArg
      or sink instanceof LoaderCallArg
      or sink instanceof ActionCallArg
      or sink instanceof ConnectionCallArg
      or sink instanceof WrapperDefParam
    )
  }
}
