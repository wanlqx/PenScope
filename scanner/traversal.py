"""PenScope —— 路径遍历（CWE-22）只读响应检测模块。

仅做"只读探测"：向 URL 查询参数与表单字段注入 ../ 序列（含多种编码变体），
观察响应是否泄露本地文件内容（Linux /etc/passwd、Windows win.ini）。

误报治理（延续项目"降低误报"主线）：
  - 仅当响应中确实出现文件内容特征、且"无载荷基线响应"不含该特征时才判定，
    避免把页面原本就存在的内容（如自带示例）误报为漏洞；
  - 所有判定均为 unverified / L2，明确标注"需人工复核"，不夸大结论。
"""
import requests
from urllib.parse import urlparse, urlunparse, parse_qs
from scanner.web_scan import discover, _send_form, _mk
from cvss_dedup import cwe_for

# Linux /etc/passwd 与 Windows win.ini 的内容特征
_PASSWD_MARKERS = (
    "root:x:0:0:",
    "root:*:0:0:",
    ":/bin/bash",
    ":/bin/sh",
    ":/sbin/nologin",
)
_WIN_MARKERS = (
    "[extensions]",
    "; for 16-bit app support",
    "C:\\Windows\\",
    "C:\\WINNT\\",
)

# 遍历载荷（含常见编码/绕过变体）：原始、URL 编码、双重编码、点斜杠、Windows 反斜杠
_TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//....//....//etc/passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows\\win.ini",
]


def _detect_file_content(text):
    """返回命中的 (os, marker) 或 None。"""
    if not text:
        return None
    for m in _PASSWD_MARKERS:
        if m in text:
            return ("linux", m)
    for m in _WIN_MARKERS:
        if m in text:
            return ("win", m)
    return None


def _url_param_points(url):
    """从 URL 查询参数提取 (target, method, param, fields)。"""
    points = []
    q = urlparse(url)
    base = urlunparse(q._replace(query="", fragment=""))
    for k in parse_qs(q.query).keys():
        points.append((base, "get", k, [k]))
    return points


def scan_traversal(url, session, timeout=6.0, verify_ssl=True):
    """路径遍历响应检测：遍历 URL 参数与表单字段，注入 ../ 序列，检测本地文件内容泄露。"""
    findings = []
    forms = discover(url, session, timeout, verify_ssl)
    points = list(_url_param_points(url))
    for f in forms:
        inj = [n for n in f["fields"] if n not in f["file_fields"]]
        for field in inj:
            points.append((f["action"], f["method"], field, f["fields"]))
    if not points:
        return findings

    seen = set()
    # 基线：抓取目标页面（GET 无载荷），排除页面固有内容误报
    baseline = ""
    try:
        r0 = session.get(url, timeout=timeout, verify=verify_ssl)
        baseline = r0.text or ""
    except requests.RequestException:
        baseline = ""

    for target, method, p, fields in points:
        if (target, method, p) in seen:
            continue
        seen.add((target, method, p))
        hit = None
        for payload in _TRAVERSAL_PAYLOADS:
            try:
                r = _send_form(session, target, method, fields, p, payload, timeout, verify_ssl)
            except requests.RequestException:
                continue
            det = _detect_file_content(r.text)
            if det and det[1] not in baseline:
                hit = (det, payload, (r.text or "")[:200])
                break
        if hit:
            (osname, marker), payload, evidence = hit
            findings.append(_mk(
                "路径遍历", f"参数 '{p}' 疑似存在路径遍历（{osname}，泄露本地文件）", "Medium",
                f"向参数 {p}（端点 {target}，方法 {method.upper()}）注入遍历序列后，响应中出现本地文件内容特征"
                f"（{marker!r}），可能存在任意文件读取（CWE-22）。基线响应未见该特征，已排除页面固有内容误报。",
                evidence.replace("\n", " ")[:200],
                "对用户可控的路径/文件名做白名单校验与规范化（realpath + 前缀绑定）；禁止拼接 ../；"
                "以最小权限运行服务进程，限制其可访问目录范围。",
                target,
                cwe=cwe_for("路径遍历"), endpoint=target, http_method=method.upper(),
                verification_status="unverified", evidence_level="L2",
                poc=f"curl '{target}?{p}={payload}'",
            ))
    return findings
