# -*- coding: utf-8 -*-
"""
PenScope —— 发布自动化脚本（本地辅助工具）

职责（对应发布规范）：
  1) 语义化版本号自动管理：读取 / 递增 config.py 的 VERSION（MAJOR.MINOR.PATCH）。
  2) 发布说明自动生成：从 CHANGELOG.md 读取最新版本段落作为 Release 正文。
  3) 构建产物输出到 dist/（由 PenScope.spec 决定）。
  4) 打标签：git tag -a v<version>。
  5) 仓库初始化与远程推送 / 创建 GitHub Release（经 gh CLI，需先 `gh auth login`）。

用法：
  python tools/release.py current                     # 打印 应用名 + 当前版本
  python tools/release.py bump [major|minor|patch]    # 递增版本并写回 config.py
  python tools/release.py build                       # 运行 build_nowrap.py 产出 dist/PenScope.exe
  python tools/release.py notes                       # 打印 CHANGELOG.md 最新段落（Release 正文）
  python tools/release.py tag [--message "..."]       # 打 annotated tag v<version>
  python tools/release.py publish [--draft]           # build + tag + push + gh release（需 gh）

说明：
  - 本脚本只负责“本地 + gh”路径；CI 自动发布由 .github/workflows/release.yml 完成
    （push 到 main 或打 v* 标签即触发，自动构建 exe 并作为 GitHub Release 资产公开）。
  - 仓库私有期间 Release 亦私有；在 GitHub 仓库 Settings → Change visibility 翻为 Public 后即公开。
  - 严禁将任何密钥 / 凭据提交进仓库（见 .gitignore）。
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONFIG = os.path.join(ROOT, "config.py")
CHANGELOG = os.path.join(ROOT, "CHANGELOG.md")
SPEC_EXE = "PenScope.exe"  # 与 PenScope.spec 的 name= 一致；CI 也用此名


def _sh(cmd, cwd=ROOT, check=True):
    print("+ " + " ".join(cmd) if isinstance(cmd, list) else "+ " + cmd)
    return subprocess.run(cmd, cwd=cwd, check=check, shell=False)


# git 标签名 / 分支名等外部引用的允许字符集（拒绝空格、引号、分号、$() 等注入风险字符）
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def _safe_ref(name, what="引用"):
    """校验 git 标签名 / 分支名等外部引用，拒绝含 shell/路径注入风险的字符。"""
    if not _REF_RE.match(name or ""):
        raise SystemExit("%s含非法字符，已拒绝执行：%r" % (what, name))
    return name


def read_app_info():
    """从 config.py 读取 APP_NAME 与 VERSION（唯一来源）。"""
    txt = open(CONFIG, encoding="utf-8").read()
    m_name = re.search(r'^APP_NAME\s*=\s*"([^"]+)"', txt, re.M)
    m_ver = re.search(r'^VERSION\s*=\s*"(\d+\.\d+\.\d+)"', txt, re.M)
    if not m_ver:
        raise SystemExit("无法在 config.py 解析 VERSION")
    return (m_name.group(1) if m_name else "PenScope", m_ver.group(1))


def write_version(new_ver):
    txt = open(CONFIG, encoding="utf-8").read()
    txt = re.sub(r'^(VERSION\s*=\s*)"\d+\.\d+\.\d+"',
                 r'\g<1>"%s"' % new_ver, txt, count=1, flags=re.M)
    open(CONFIG, "w", encoding="utf-8").write(txt)


def parse_ver(v):
    return [int(x) for x in v.split(".")]


def bump(part):
    name, ver = read_app_info()
    maj, mn, pt = parse_ver(ver)
    if part == "major":
        maj, mn, pt = maj + 1, 0, 0
    elif part == "minor":
        mn, pt = mn + 1, 0
    elif part == "patch":
        pt += 1
    else:
        raise SystemExit("bump 参数须为 major|minor|patch")
    new = "%d.%d.%d" % (maj, mn, pt)
    write_version(new)
    print("%s -> %s" % (ver, new))
    return new


def build():
    _sh([sys.executable, "build_nowrap.py"], cwd=ROOT)
    exe = os.path.join(ROOT, "dist", SPEC_EXE)
    if not os.path.exists(exe):
        raise SystemExit("构建失败：未生成 %s" % exe)
    print("构建产物：", exe, os.path.getsize(exe), "bytes")


def read_notes(version=None):
    if not os.path.exists(CHANGELOG):
        return "See CHANGELOG.md"
    txt = open(CHANGELOG, encoding="utf-8").read()
    if version:
        # 指定版本：精确提取该版本的 CHANGELOG 段落（用于按 tag 重新发布旧版本）
        pat = re.compile(r"^##\s+\[v" + re.escape(version) + r"\].*?(?=^##\s|\Z)",
                         re.M | re.S)
        m = pat.search(txt)
        return m.group(0).strip() if m else "See CHANGELOG.md"
    # 未指定版本：提取第一个 "## [vX.Y.Z]" 段落（CHANGELOG 按版本倒序，即最新版）
    m = re.search(r"^##\s+\[v[^\]]+\].*?(?=^##\s|\Z)", txt, re.M | re.S)
    return m.group(0).strip() if m else "See CHANGELOG.md"


def tag(message=None):
    name, ver = read_app_info()
    tagname = "v" + ver
    _safe_ref(tagname, "标签名")
    msg = message or ("%s %s" % (name, tagname))
    _sh(["git", "tag", "-a", tagname, "-m", msg], cwd=ROOT)
    print("已打标签", tagname)
    return tagname


def publish(draft=False):
    name, ver = read_app_info()
    tagname = "v" + ver
    # 检查 gh 可用性
    if subprocess.run(["gh", "--version"], cwd=ROOT, capture_output=True).returncode != 0:
        raise SystemExit("未检测到 gh CLI。请先 `gh auth login`，或将代码推送到 GitHub 由 "
                         ".github/workflows/release.yml 自动发布。")
    build()
    # 若标签不存在则创建
    have = subprocess.run(["git", "tag", "-l", tagname], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    if not have:
        tag()
    _sh(["git", "push", "origin", "main"], cwd=ROOT)
    _sh(["git", "push", "origin", tagname], cwd=ROOT)
    notes = read_notes()
    notes_file = os.path.join(ROOT, ".release_notes.md")
    open(notes_file, "w", encoding="utf-8").write(notes)
    cmd = ["gh", "release", "create", tagname,
           "--title", "%s %s" % (name, tagname),
           "--notes-file", notes_file,
           os.path.join("dist", SPEC_EXE)]
    if draft:
        cmd.append("--draft")
    else:
        cmd.append("--latest")
    try:
        _sh(cmd, cwd=ROOT)
    finally:
        try:
            os.remove(notes_file)
        except OSError:
            pass
    print("已创建 GitHub Release：%s" % tagname)


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "current":
        name, ver = read_app_info()
        print("%s %s" % (name, ver))
    elif cmd == "bump":
        part = args[1] if len(args) > 1 else "patch"
        bump(part)
    elif cmd == "build":
        build()
    elif cmd == "notes":
        ver = None
        if "--version" in args:
            ver = args[args.index("--version") + 1]
        print(read_notes(ver))
    elif cmd == "tag":
        msg = None
        if "--message" in args:
            msg = args[args.index("--message") + 1]
        tag(msg)
    elif cmd == "publish":
        draft = "--draft" in args
        publish(draft)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
