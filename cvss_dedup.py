"""PenScope —— 共享的 CVSS / CWE 映射与语义去重工具（纯标准库，无外部依赖）

借鉴 VulnClaw（v0.3.6）的 config/finding_similarity.py 思路，但适配本工具的
「确定性本地扫描器」：发现以普通 dict 传递（而非 pydantic 模型），因此相似度
函数直接接收 dict（含 category / title / detail / evidence / target_ref /
endpoint 等字段）。

本模块刻意只依赖标准库，以便 db.py / reports.py / scanner/* 都能安全 import，
不会引入循环依赖。
"""
import re
from urllib.parse import parse_qs, urlsplit

# ──────────────────────────────────────────────────────────────
# CVSS 3.1 近似评分（按漏洞类型）
# ──────────────────────────────────────────────────────────────
_CVSS_MAP = {
    "SQL注入":   {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "XSS":       {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "CSRF":      {"score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"},
    "文件上传":  {"score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
    "命令注入":  {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "API安全":   {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "已知漏洞":  {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "资产暴露":  {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "环境指纹":  {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "利用验证":  {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    # P1：子域枚举 / 目录与敏感信息扫描
    "子域资产":  {"score": 0.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
    "敏感信息泄露": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "目录暴露":  {"score": 3.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    # P2：覆盖缺口补齐（来自知识库 gap 分析）—— SSRF / 路径遍历
    "SSRF":      {"score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"},
    "路径遍历":  {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    # P3：访问控制与认证（v1.3.9）—— CWE-862 / CWE-287
    "缺失授权":  {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "认证缺陷":  {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    # P4：开放重定向（v1.4.0，知识库缺口分析驱动）—— CWE-601
    "开放重定向": {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
}


def cvss_for(category, risk):
    """按漏洞类型返回 CVSS 3.1 近似评分与向量。

    风险等级用于在类型基分上做合理收敛：
    - Info/Low 向下收敛；
    - Medium 落在 4.0–6.9；
    - High：对本身即可达 9.8 的高危类（SQL 注入 / 利用验证）保留基分，
      其余 High 收敛到 7.0–8.9；
    - Critical：不低于 9.0。
    """
    base = _CVSS_MAP.get(category, {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"})
    score = base["score"]
    if risk == "Info":
        score = min(score, 0.0)
    elif risk == "Low":
        score = min(score, 3.9)
    elif risk == "Medium":
        score = min(max(score, 4.0), 6.9)
    elif risk == "High":
        if base["score"] >= 9.0:
            score = base["score"]
        else:
            score = min(max(score, 7.0), 8.9)
    elif risk == "Critical":
        score = max(score, 9.0)
    return round(score, 1), base["vector"]


# ──────────────────────────────────────────────────────────────
# CWE 映射（按漏洞类型）
# ──────────────────────────────────────────────────────────────
CWE_MAP = {
    "SQL注入": "CWE-89",
    "XSS": "CWE-79",
    "CSRF": "CWE-352",
    "文件上传": "CWE-434",
    "命令注入": "CWE-78",
    "API安全": "CWE-200",
    "已知漏洞": "CWE-1104",
    "资产暴露": "CWE-668",
    "环境指纹": "CWE-200",
    "利用验证": "CWE-89",
    # P1：子域枚举 / 目录与敏感信息扫描
    "子域资产": "CWE-200",
    "敏感信息泄露": "CWE-200",
    "目录暴露": "CWE-538",
    # P2：覆盖缺口补齐（知识库 gap 分析驱动）
    "SSRF": "CWE-918",
    "路径遍历": "CWE-22",
    # P3：访问控制与认证（v1.3.9）
    "缺失授权": "CWE-862",
    "认证缺陷": "CWE-287",
    # P4：开放重定向（v1.4.0，知识库缺口分析驱动）—— CWE-601
    "开放重定向": "CWE-601",
}


def cwe_for(category):
    return CWE_MAP.get(category, "")


# ──────────────────────────────────────────────────────────────
# 漏洞类型归一化（借鉴 VulnClaw 的别名表）
# ──────────────────────────────────────────────────────────────
_VULN_TYPE_ALIASES = {
    "sqli": "sql_injection", "sql注入": "sql_injection", "sql injection": "sql_injection",
    "盲注": "sql_injection", "注入漏洞": "sql_injection", "sql_injection": "sql_injection",
    "xss": "cross_site_scripting", "跨站脚本": "cross_site_scripting", "反射型xss": "cross_site_scripting",
    "xss跨站脚本": "cross_site_scripting", "cross site scripting": "cross_site_scripting",
    "cross_site_scripting": "cross_site_scripting",
    "csrf": "cross_site_request_forgery", "跨站请求伪造": "cross_site_request_forgery",
    "cross site request forgery": "cross_site_request_forgery",
    "文件上传": "file_upload", "上传漏洞": "file_upload", "file_upload": "file_upload",
    "已知漏洞": "known_vuln", "known_vuln": "known_vuln",
    "端口暴露": "port_exposure", "开放端口": "port_exposure", "资产暴露": "port_exposure", "port_exposure": "port_exposure",
    "环境指纹": "info_disclosure", "信息泄露": "info_disclosure", "info_disclosure": "info_disclosure",
    "利用验证": "exploit_verified", "exploit_verified": "exploit_verified",
    # P2：SSRF / 路径遍历 别名（知识库 gap 分析驱动）
    "ssrf": "ssrf", "服务端请求伪造": "ssrf", "server side request forgery": "ssrf",
    "路径遍历": "path_traversal", "目录遍历": "path_traversal", "任意文件读取": "path_traversal",
    "path traversal": "path_traversal", "traversal": "path_traversal", "file read": "path_traversal",
    "directory traversal": "path_traversal",
    # P3：缺失授权 / 认证缺陷 别名（v1.3.9）
    "缺失授权": "缺失授权", "未授权访问": "缺失授权", "broken access control": "缺失授权",
    "越权": "缺失授权", "水平越权": "缺失授权", "垂直越权": "缺失授权", "idor": "缺失授权",
    "access control": "缺失授权", "missing authorization": "缺失授权", "forced browsing": "缺失授权",
    "认证缺陷": "认证缺陷", "弱口令": "认证缺陷", "弱密码": "认证缺陷", "默认凭据": "认证缺陷",
    "弱默认凭据": "认证缺陷", "authentication": "认证缺陷", "auth defect": "认证缺陷",
    "missing authentication": "认证缺陷", "弱认证": "认证缺陷", "authentication weakness": "认证缺陷",
    # P4：开放重定向 别名（v1.4.0）
    "开放重定向": "开放重定向", "开放重定向漏洞": "开放重定向", "open redirect": "开放重定向",
    "url redirect": "开放重定向", "openredirection": "开放重定向", "跳转漏洞": "开放重定向",
}


def normalize_vuln_type(vuln_type):
    if not vuln_type:
        return ""
    key = re.sub(r"\s+", " ", str(vuln_type).strip().lower())
    if key in _VULN_TYPE_ALIASES:
        return _VULN_TYPE_ALIASES[key]
    underscore = key.replace(" ", "_")
    if underscore in _VULN_TYPE_ALIASES:
        return _VULN_TYPE_ALIASES[underscore]
    spaced = key.replace("_", " ")
    if spaced in _VULN_TYPE_ALIASES:
        return _VULN_TYPE_ALIASES[spaced]
    return underscore


# ──────────────────────────────────────────────────────────────
# 文本 / URL 归一化与相似度
# ──────────────────────────────────────────────────────────────
_URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9一-鿿]+", re.IGNORECASE)
_NOISE_TAGS = ("[自动]", "[已确认]", "[未验证]", "[已验证]")


def _normalize_url_path(url):
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.lower()
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    if len(path) > 1:
        path = path.rstrip("/")
    return f"{host}{path}"


def normalize_text(text):
    if not text:
        return ""
    result = text
    for tag in _NOISE_TAGS:
        result = result.replace(tag, " ")
    result = _URL_RE.sub(lambda m: _normalize_url_path(m.group(0)), result)
    result = result.lower()
    result = re.sub(r"\s+", " ", result).strip()
    return result


def _tokenize(text):
    return set(_TOKEN_RE.findall(text))


def text_similarity(a, b):
    na, nb = normalize_text(a), normalize_text(b)
    if not na and not nb:
        return 1.0
    if not na or not nb:
        return 0.0
    ta, tb = _tokenize(na), _tokenize(nb)
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def url_similarity(a, b):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    pa, pb = urlsplit(a.strip()), urlsplit(b.strip())
    if not (pa.scheme or pa.netloc) and not (pb.scheme or pb.netloc):
        return text_similarity(a, b)

    ha, hb = (pa.hostname or "").lower(), (pb.hostname or "").lower()
    host_sim = 1.0 if ha == hb else (0.0 if (ha and hb) else (1.0 if not ha and not hb else 0.0))

    seg_a = {s for s in pa.path.split("/") if s}
    seg_b = {s for s in pb.path.split("/") if s}
    if not seg_a and not seg_b:
        path_sim = 1.0
    elif not seg_a or not seg_b:
        path_sim = 0.0
    else:
        path_sim = len(seg_a & seg_b) / len(seg_a | seg_b)

    qa = set(parse_qs(pa.query).keys())
    qb = set(parse_qs(pb.query).keys())
    if not qa and not qb:
        query_sim = 1.0
    elif not qa or not qb:
        query_sim = 0.0
    else:
        query_sim = len(qa & qb) / len(qa | qb)

    return host_sim * 0.3 + path_sim * 0.4 + query_sim * 0.3


_LOCATION_RE = re.compile(r'(?:https?://[^\s<>"\')\]]+)|(?:/[\w%&=?\-./]+)|(?::\d+)')


def _extract_location(f):
    """从发现 dict 中提取位置：优先 endpoint，其次 target_ref，再次 evidence 中的 URL/路径。"""
    for field in (f.get("endpoint") or "", f.get("target_ref") or "", f.get("evidence") or ""):
        if not field:
            continue
        m = _URL_RE.search(field)
        if m:
            return m.group(0)
        m = _LOCATION_RE.search(field)
        if m:
            return m.group(0)
    return ""


def _vuln_type_similarity(a, b):
    ra, rb = (a or "").strip().lower(), (b or "").strip().lower()
    if ra and rb and ra == rb:
        return 1.0
    na, nb = normalize_vuln_type(a), normalize_vuln_type(b)
    if na and nb and na == nb:
        return 0.8
    return 0.0


def finding_similarity(a, b):
    """综合比较两个发现 dict 的语义相似度（权重同 VulnClaw）：
    vuln_type 0.3 + location 0.4 + description 0.3。"""
    type_sim = _vuln_type_similarity(a.get("category", ""), b.get("category", ""))
    loc_a, loc_b = _extract_location(a), _extract_location(b)
    if not loc_a and not loc_b:
        loc_sim = 0.5
    else:
        loc_sim = url_similarity(loc_a, loc_b)
    desc_a = f"{a.get('title', '')} {a.get('detail', '')}".strip()
    desc_b = f"{b.get('title', '')} {b.get('detail', '')}".strip()
    desc_sim = text_similarity(desc_a, desc_b)
    return type_sim * 0.3 + loc_sim * 0.4 + desc_sim * 0.3


# ──────────────────────────────────────────────────────────────
# 证据强度比较（用于去重时保留更强一方）
# ──────────────────────────────────────────────────────────────
_LIFECYCLE_RANK = {
    "rejected": 0, "candidate": 1, "pending": 1,
    "pending_verification": 2, "needs_manual_review": 3, "verified": 4,
}
_LEVEL_RANK = {"L1": 1, "L2": 2, "L3": 3, "L4": 4}


def evidence_strength(f):
    """返回 (已验证, 生命周期等级, 证据等级, 证据长度) 元组，越大越强。"""
    verified = 1 if f.get("verification_status") == "verified" or f.get("verified") else 0
    life = _LIFECYCLE_RANK.get(f.get("verification_status") or "pending", 1)
    lvl = _LEVEL_RANK.get(f.get("evidence_level") or "L1", 1)
    return (verified, life, lvl, len(f.get("evidence") or ""))


def finding_id_of(category, location):
    """生成稳定的去重键：类型 + 位置（小写）。"""
    return f"{normalize_vuln_type(category) or category}:{normalize_text(location)}"
