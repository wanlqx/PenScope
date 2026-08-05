"""PenScope —— SSRF（CWE-918）只读响应检测模块。

分两层，贯彻项目"降低误报、保守判定"的原则：
  1) 潜在 SSRF 注入点发现（Low）：识别 URL/file 类参数名（url/path/file/redirect/avatar…），
     给出"待人工验证"观察项，与既有的上传点/API 被动检测风格一致，不夸大为已利用。
  2) 强证据利用检测（High，仍标记 unverified/L3）：注入 file:///etc/passwd 或云元数据地址
     （169.254.169.254/latest/meta-data），仅当响应出现明确内容特征（本地文件内容 / 元数据 JSON）
     才判定，避免把"参数恰好回显输入"误判为 SSRF。
"""
import re
from urllib.parse import parse_qs, urlparse, urlunparse

import requests

from cvss_dedup import cwe_for
from scanner import fp_guard
from scanner.web_scan import _mk, _send_form, discover

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

# 云元数据响应特征（需多特征同时出现才判定为高置信度）
_META_MARKERS = (
    # JSON 格式元数据响应（IMDS 部分接口返回 JSON）
    '"instance-id"', '"ami-id"', '"local-ipv4"', '"public-ipv4"',
    '"instance-type"',
    # 纯文本格式元数据响应（IMDS v1 默认返回字段名列表）
    "instance-id", "ami-id", "local-ipv4", "public-ipv4",
    "instance-type", "availability-zone", "accountId", "privateIp",
)

# 高置信度元数据判定：至少命中 N 个不同特征（防止单关键词 URL 回显误报）
_META_MIN_HITS = 2

# 响应正文含这些标志时为错误页（非真实元数据），应排除
_ERROR_PAGE_MARKERS = (
    "404", "not found", "找不到", "文件或目录", "bad request",
    "forbidden", "error", "exception", "服务器错误", "内部错误",
    "gateway", "timeout", "unavailable",
)

def _count_meta_markers(text):
    """统计响应体中命中的元数据特征数量。"""
    if not text:
        return 0
    low = text.lower()
    return sum(1 for m in _META_MARKERS if m.lower() in low)


def _is_error_page(text):
    """判断响应是否为错误页（非真实内容）。"""
    if not text:
        return True
    low = text.lower()
    return any(m in low for m in _ERROR_PAGE_MARKERS)


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
    """SSRF 只读响应检测：注入 file:// 与云元数据地址做强证据判定，并对 URL 类参数给出注入点观察。

    降噪（v1.1+）：
      ① 仅 200 响应参与强证据判定（404/403/502 等不可能是真实文件/元数据泄露）
      ② 基线 404 相似度比对（排除软 404 回显 URL 的误报）
      ③ 元数据需 ≥2 个特征同时出现（防止单关键词 URL 回显误报）
      ④ 错误页关键词排除（含 404/not found/forbidden 等自动降级）
    """
    findings = []
    forms = discover(url, session, timeout, verify_ssl)
    points = list(_url_param_points(url))
    for f in forms:
        inj = [n for n in f["fields"] if n not in f["file_fields"]]
        for field in inj:
            points.append((f["action"], f["method"], field, f["fields"]))
    if not points:
        return findings

    # —— 基线 404 探针（与 access_control.py / contentscan.py 对齐）——
    from urllib.parse import urlunparse, urlparse as _uparse
    parsed = _uparse(url)
    root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
    baseline_text = fp_guard.baseline_probe(session, root, verify_ssl, timeout)

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
            # ① 仅 200 响应才可能是真实文件内容泄露
            if r.status_code != 200:
                continue
            text = r.text or ""
            # ② 排除错误页（200 但含 404/not found 等关键词）
            if _is_error_page(text):
                continue
            # ③ 软 404 排除：与基线高度相似
            if fp_guard.soft404_filter(text, baseline_text):
                continue
            m = _detect_file_content(text)
            if m:
                file_hit = (m, payload, text[:200])
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
            # ① 仅 200 响应才可能是真实元数据泄露（404/403/502 不可能）
            if r.status_code != 200:
                continue
            text = r.text or ""
            # ② 排除错误页
            if _is_error_page(text):
                continue
            # ③ 软 404 排除：与基线高度相似 → URL 回显在错误页中
            if fp_guard.soft404_filter(text, baseline_text):
                continue
            # ④ 需 ≥2 个不同元数据特征同时出现（防止单关键词 URL 回显误报）
            if _count_meta_markers(text) < _META_MIN_HITS:
                continue
            m = _detect_metadata(text)
            if m:
                meta_hit = (m, payload, text[:200], _count_meta_markers(text))
                break
        if meta_hit:
            marker, payload, evidence, marker_count = meta_hit
            seen_hit.add((target, method, p))
            findings.append(_mk(
                "SSRF", f"参数 '{p}' 疑似 SSRF 命中云实例元数据端点", "High",
                f"向参数 {p}（端点 {target}，方法 {method.upper()}）注入云元数据地址后，"
                f"响应 200 且出现 {marker_count} 个元数据特征（含 {marker!r}），"
                f"可能泄露云凭证/实例信息（CWE-918）。需人工确认目标是否位于云环境且未隔离元数据服务。",
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
