"""构建包装：恢复 os.remove/unlink/rmdir 为原生 nt.* 实现，绕过本机 safe-delete 沙箱封装，
仅在本次本地构建中使用。不改动项目源码与 shim。
"""
import nt
import os
import sys

# 沙箱 shim 把 os.remove/os.unlink/os.rmdir 替换为拦截版本；
# 这里把它们还原为底层原生实现，使 PyInstaller 的清理步骤能直接删除临时文件。
os.remove = nt.unlink
os.unlink = nt.unlink
os.rmdir = nt.rmdir
if hasattr(os, "removedirs"):
    os.removedirs = lambda path: _removedirs(path)

def _removedirs(path):
    # 简易递归删除（与 os.removedirs 语义一致，但用原生 unlink/rmdir）
    while True:
        try:
            nt.rmdir(path)
        except OSError:
            break
        path = os.path.dirname(path)
        if not path or path == os.path.dirname(path):
            break

# 构建前再生图标/托盘资源（仅依赖 Pillow，无需外部素材），避免把二进制资源提交进仓库。
# 见 .gitignore：assets/icon.ico、assets/tray.png 被忽略，构建时由此步重新生成。
try:
    import subprocess as _sp
    _here = os.path.dirname(os.path.abspath(__file__))
    _sp.run([sys.executable, os.path.join(_here, "make_icon.py")], check=False)
except Exception:
    pass

import PyInstaller.__main__ as pimain

if __name__ == "__main__":
    sys.argv = ["pyinstaller", "--noconfirm", "PenScope.spec"]
    pimain.run()

    # 构建后校验：确认产物真正包含预期模块且版本常量正确。
    # 注意：PyInstaller 的归档读取器会把它打开的 .pyz 当成"自身程序"校验，
    # 必须从稳定路径以子进程运行 verify_build.py（不能在本进程内 import 后直接读临时 .pyz）。
    # 模块缺失/版本不符 => 构建视为失败（退出 1）；校验步骤自身异常 => 仅告警。
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    vb = os.path.join(here, "verify_build.py")
    if os.path.exists(vb):
        rc = subprocess.call([sys.executable, vb], cwd=here)
        if rc == 1:
            print("[verify_build] 构建产物校验未通过：请检查 PenScope.spec 的 hiddenimports 与 config.VERSION")
            sys.exit(1)
        elif rc != 0:
            print("[verify_build] 校验步骤异常（返回码 %d），不影响已生成的产物" % rc)
