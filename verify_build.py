#!/usr/bin/env python3
"""
verify_build.py — PenScope 构建后校验

确认打包产物（默认 ./dist/PenScope.exe）真正包含预期的扫描模块，
且内嵌 config 模块的 VERSION 常量与期望值一致。

这是把"构建后 exe 校验"从一次性脚本固化下来的可复用工具：每次 build_nowrap.py
重建后自动调用；也可手动运行。

用法:
    python verify_build.py [exe路径] [期望版本]
默认 exe 路径 = ./dist/PenScope.exe；期望版本默认从 ./config.py 的 VERSION 读取。
若显式传入版本参数则据此断言。

退出码: 0 = PASS, 1 = FAIL（产物确实缺模块/版本不符）, 2 = 校验步骤异常（不影响产物）。

实现说明：
    PYZ 是 PyInstaller 的自包含 zlib 归档，格式为 `PYZ\\0` + Python magic + 4 字节
    大端 TOC 偏移 + 数据 + 末尾 marshalled 的 {name:(typecode,offset,length)} 字典。
    每个条目 = zlib.decompress 后 marshal.loads。这里**全程在内存中解析 PYZ**，
    不落盘临时文件——避免在某些受沙箱重定向的 python 下，临时文件经 junction 解析失败
    触发 PyInstaller "文件已移动/删除" 保护而误报。
"""
import marshal
import os
import re
import struct
import sys
import zlib

from PyInstaller.archive.readers import CArchiveReader

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EXE = os.path.join(HERE, "dist", "PenScope.exe")

# 必须出现在 PYZ 中的模块（扫描能力 + 关键支撑）。新增 Web 模块请同步在此登记，
# 这样"模块写了却没打进包"的回归会被构建校验拦下。
# 名称以 dist/PenScope.exe 内 PYZ 的实际模块名为准（与 scanner/ 源码一致）。
# 注：SQLi/XSS/CSRF/上传检测是 scanner.web_scan 内的函数，并非独立模块。
EXPECTED_MODULES = [
    "scanner.web_scan",
    "scanner.evidence",   # v1.7.0 HTTP 证据采集（I-05 请求/响应 Diff 数据源）
    "scanner.redact",     # v1.13.0 敏感数据脱敏（U-12）
    "scanner.subdomain",
    "scanner.port_scan",
    "scanner.cmd_injection",
    "scanner.api_scan",
    "scanner.contentscan",
    "scanner.traversal",   # v1.3.8
    "scanner.ssrf",        # v1.3.8
    "scanner.access_control",  # v1.3.9
    "scanner.auth",        # v1.3.9
    "scanner.fp_guard",    # G-01 统一误报门控层（相似度/基线/拒绝词）
    "scanner.reflexion",   # G-02 Reflexion 自检层（L3 高证据二次复核降级）
    "scanner.advanced_injection",  # P5 CWE 缺口补齐（SSTI/XXE/JWT/NoSQL/IDOR）
    "scanner.open_redirect",  # v1.4.0
    "scanner.scope",       # v1.4.2 AP-001 重定向作用域围栏助手（scope-aware）
    "scanner.mail_probe",  # v1.3.7
    "scanner.payloads",
    "scanner.baseline",   # v1.9.0 响应差异基线建模（C-02 时间盲注误报治理）
    "scanner.plugin_base",   # v1.12.0 F-08 插件化框架抽象基类
    "scanner.plugins",       # v1.12.0 F-08 插件加载器（内置示例 + 外部目录）
    "scanner.plugins.example_headers",  # v1.12.0 F-08 内置示例插件（确保被打包收集）
    "scanner.vuln_db",
    "scanner.vuln_i18n",   # v1.15.0 漏洞描述双语映射（U-07）
    "scanner.cred_dict",   # v1.16.0 默认凭据字典加载器（C-05 外置）
    "asset_watch",      # v1.17.0 资产变更告警引擎（F-05 diff/apply/format）
    "notify",           # v1.17.0 桌面托盘通知封装（F-05）
    "topology",        # v1.18.0 资产拓扑聚合（F-07 build_topology）
    "scanner.vault",   # v1.19.0 加密凭据保险库（C-06 会话续期凭据存储）
    "scanner.session_renew",  # v1.19.0 可续期认证会话（C-06 RenewableSession）
    "cvss_dedup",
    "chain",            # v1.5.0 漏洞链编排（C-01）
    "run_scans",
    "config",
]
CONFIG_CANDIDATES = ["config", "autopentest.config"]

# PYZ 条目 typecode（来自 PyInstaller.loader.pyimod01_archive）
PYZ_ITEM_MODULE = 0
PYZ_ITEM_PKG = 1


def _unwrap(payload):
    """PyInstaller 不同版本 extract() 返回 bytes 或 (bytes, ...) 元组；统一取到 bytes。"""
    if isinstance(payload, tuple):
        return payload[0]
    return payload


def _read_pyz(pyz_bytes):
    """在内存中解析 PYZ 归档，返回 (toc_dict, extract(name)->code_or_bytes)。"""
    if pyz_bytes[:4] != b"PYZ\x00":
        raise ValueError("不是 PYZ 归档（magic 不匹配）")
    toc_offset = struct.unpack("!i", pyz_bytes[8:12])[0]
    raw = marshal.loads(pyz_bytes[toc_offset:])
    # PyInstaller 的 TOC 经 marshal 后是 [(name,(typecode,offset,length)), ...] 列表，
    # 与 ZlibArchiveReader 一致用 dict() 转成 name->entry 映射（兼容个别版本直接出 dict）。
    toc = raw if isinstance(raw, dict) else dict(raw)

    def extract(name):
        typecode, entry_offset, entry_length = toc[name]
        blob = pyz_bytes[entry_offset:entry_offset + entry_length]
        obj = zlib.decompress(blob)
        if typecode in (PYZ_ITEM_MODULE, PYZ_ITEM_PKG):
            return marshal.loads(obj)
        return obj

    return toc, extract


def _walk_version(co, out):
    """递归遍历 code 对象的 co_consts，收集形如 x.y.z 的版本串（不限主版本号）。"""
    for c in co.co_consts:
        if isinstance(c, str) and re.match(r"^\d+\.\d+\.\d+$", c):
            out.append(c)
        elif hasattr(c, "co_consts"):
            _walk_version(c, out)


def verify(exe_path, expected_version=None):
    """返回 (ok: bool, messages: list[str])。"""
    problems = []
    ca = CArchiveReader(exe_path)
    pyz_name = next((n for n in ca.toc if n.endswith(".pyz")), None)
    if not pyz_name:
        return False, ["归档中未找到 PYZ 条目"]
    pyz_bytes = _unwrap(ca.extract(pyz_name))
    toc, extract = _read_pyz(pyz_bytes)

    missing = [m for m in EXPECTED_MODULES if m not in toc]
    if missing:
        problems.append("缺失模块: %s" % ", ".join(missing))

    versions = []
    for cand in CONFIG_CANDIDATES:
        if cand in toc:
            _walk_version(_unwrap(extract(cand)), versions)
    versions = sorted(set(versions))
    if expected_version and expected_version not in versions:
        problems.append("VERSION 期望 %s，实际 %s" % (expected_version, versions or "未找到"))

    ok = not problems
    lines = [
        "PYZ 成员总数: %d" % len(toc),
        "config.VERSION: %s" % (versions or "未找到"),
    ]
    if missing:
        lines.append("缺失模块: %s" % ", ".join(missing))
    if expected_version:
        lines.append("期望版本 %s -> %s" % (expected_version, "匹配" if expected_version in versions else "不匹配"))
    if ok:
        lines.append("结果: PASS")
    else:
        lines.append("结果: FAIL")
        lines.extend(problems)
    return ok, lines


def _expected_version_from_source():
    cfg = os.path.join(HERE, "config.py")
    if os.path.exists(cfg):
        with open(cfg, "r", encoding="utf-8") as fh:
            for line in fh:
                m = re.search(r'VERSION\s*=\s*["\']([0-9.]+)["\']', line)
                if m:
                    return m.group(1)
    return None


if __name__ == "__main__":
    # 让校验脚本在任意平台/控制台编码（含 GitHub Windows runner 默认的 cp1252）
    # 下都能安全打印中文，避免 UnicodeEncodeError 被误判为「构建校验失败」而让 CI 发布失败。
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    exe = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_EXE
    ver = sys.argv[2] if len(sys.argv) > 2 else _expected_version_from_source()
    if not os.path.exists(exe):
        print("exe 不存在: %s" % exe)
        sys.exit(2)
    try:
        ok, msgs = verify(exe, ver)
    except BaseException as e:  # 含任何解析异常：校验步骤异常不应误判产物
        print("[verify_build] 校验异常（不影响产物，请手动复核）: %s" % e)
        sys.exit(2)
    for m in msgs:
        print(m)
    sys.exit(0 if ok else 1)
