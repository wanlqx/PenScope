"""PenScope —— 缺失授权 / Broken Access Control（CWE-862）只读检测模块。

贯彻项目"降低误报、保守分级"原则，拆出两类可只读、可保守判定的子能力：

  1) 强制浏览（Forced Browsing）：内置敏感路径词表，对每个目标发"无会话" GET
     （新建一个无 Cookie 的探测会话，模拟未登录访客），并与"应用基线 404 行为"对比。
     仅当响应 200、正文明显异于基线（非登录跳转、非软 404、非静态资源）才报
     "潜在未授权访问（强制浏览）"，中危 / 待确认 / L2，unverified。

  2) 权限指示参数被动观察：URL 查询参数 / 表单字段出现 role= / admin= / uid= 等
     名称 → 低危"潜在越权（IDOR / 水平越权）注入点"观察项（L1），与既有 SSRF
     注入点观察同风格，不夸大为已利用。

四重降噪（防误报）：① 基线差异（与 404 基线页对比）② 静态资源后缀排除
③ 敏感路径白名单（仅检查语义敏感路径）④ 软 404 相似度（自定义 404 返回 200 时靠
正文相似度排除）。初版宁漏不夸。
"""
import re
from urllib.parse import parse_qs, urlparse, urlunparse

import requests

from cvss_dedup import cwe_for
from scanner.web_scan import _mk, discover

_UA = "PenScope/1.0 (authorized security test)"

# 敏感路径词表（强制浏览候选，拼接在主机根下）。聚焦"管理/内部/配置/备份/源码"语义。
_SENSITIVE_PATHS = [
    "/admin", "/admin/", "/admin/index.php", "/admin/login.php", "/admin.php",
    "/manage", "/management", "/manager", "/console",
    "/dashboard", "/control", "/control-panel", "/cpanel", "/wp-admin",
    "/administrator", "/admincp",
    "/api/internal", "/api/admin", "/api/private", "/internal",
    "/.env", "/config", "/config.php", "/configuration",
    "/backup", "/backups", "/bak", "/www.zip", "/site.zip", "/db.sql",
    "/phpinfo.php", "/info.php", "/status", "/server-status",
    "/.git/config", "/.svn/entries", "/debug", "/test",
    "/user", "/users", "/account", "/profile", "/settings",
    "/private", "/secret", "/secrets", "/logs", "/log",
]

# 静态资源后缀（不参与强制浏览判定，排除噪点）
_STATIC_EXT = (
    ".css", ".js", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".json", ".txt", ".pdf",
    ".xml", ".webmanifest",
)

# 响应正文出现这些标志时，说明访问实际已被拒绝或要求登录，应排除"未授权访问"误报
_DENIED_MARKERS = (
    "unauthorized", "forbidden", "access denied", "access is denied",
    "not authorized", "please login", "please log in", "login required",
    "authentication required", "requires authentication", "sign in",
    "permission denied", "not permitted",
    "需要登录", "请登录", "无权限", "没有权限", "拒绝访问", "未授权",
    "登录后", "请先登录", "权限不足", "鉴权失败",
)

# JS 客户端重定向模式：部分应用用 JS（而非 HTTP 30x）跳转登录页
# 匹配 window.location / parent.location / top.location 赋值（绝对或相对 URL）
_RE_JS_REDIRECT = re.compile(
    r'window\.(?:location|parent\.location|top\.location)\s*[\.\w]*\s*=\s*'
    r'[\'"]?(?:https?://[^\'"\s]*|/[^\'"\s]*(?:login|signin|auth|account)[^\'"\s]*)',
    re.IGNORECASE,
)

# 权限指示参数（潜在 IDOR / 越权）：标识用户身份/权限的字段名
_PRIV_PARAM_RE = re.compile(
    r"(?i)\b(role|admin|root|uid|userid|user_id|level|priv|privilege|"
    r"permission|acl|owner|group|superuser|isadmin|moderator|access|"
    r"memberid|member_id|accountid|account_id|orderid|order_id)\b"
)

# 用于取得"404 基线"的确定不存在路径（拼接在主机根下）
_BASELINE_NONCE = "_ap_probe_nonexistent_9F3A"

# 本就应对外公开的路径（登录入口/用户公开页），不报"未授权访问"
_PUBLIC_PATHS = frozenset({
    "/login", "/admin/login", "/admin/login.php", "/wp-admin", "/wp-login.php",
    "/user", "/users", "/account", "/profile", "/settings",
})


def _similarity(a, b):
    """基于 token Jaccard 的文本相似度（0~1），用于识别"软 404"。"""
    if not a or not b:
        return 0.0
    sa = set(re.findall(r"[a-z0-9一-鿿]+", a.lower()))
    sb = set(re.findall(r"[a-z0-9一-鿿]+", b.lower()))
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _host_root(url):
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, "/", "", "", ""))


def scan_access_control(url, session, timeout=6.0, verify_ssl=True, probe_session=None):
    """缺失授权只读检测：强制浏览（无会话 GET + 基线差分）+ 权限指示参数被动观察。

    probe_session：可选注入的"无会话"探测会话，便于测试；默认新建一个无 Cookie 会话，
    以模拟未登录访客（这是强制浏览判定的核心——测试资源是否无需认证即可访问）。
    """
    findings = []
    if probe_session is None:
        probe_session = requests.Session()
        probe_session.headers.update({"User-Agent": _UA})

    root = _host_root(url)

    # 基线：请求一个确定不存在的路径，记录其响应作为"无内容"基准（软 404 比对用）
    baseline_text = ""
    try:
        r0 = probe_session.get(root + _BASELINE_NONCE, timeout=timeout,
                               verify=verify_ssl, allow_redirects=False)
        baseline_text = r0.text or ""
    except requests.RequestException:
        baseline_text = ""

    seen = set()
    for path in _SENSITIVE_PATHS:
        if path.lower().endswith(_STATIC_EXT):
            continue
        target = root.rstrip("/") + path
        try:
            r = probe_session.get(target, timeout=timeout, verify=verify_ssl,
                                  allow_redirects=False)
        except requests.RequestException:
            continue
        # 重定向（多为跳登录）= 访问受控，排除
        if r.status_code in (301, 302, 303, 307, 308):
            continue
        if r.status_code != 200:
            continue
        # 公开路径白名单：登录页/用户公开页本就应对外返回 200，不报未授权
        if path in _PUBLIC_PATHS:
            continue
        text = r.text or ""
        # 软 404：正文与基线高度相似（自定义 404 返回 200）= 排除
        if baseline_text and _similarity(text, baseline_text) > 0.85:
            continue
        # 访问已被拒绝或要求登录：排除"未授权访问"误报
        low_text = text.lower()
        if any(d in low_text for d in _DENIED_MARKERS):
            continue
        # JS 客户端重定向到登录页：应用用 JS（而非 HTTP 30x）做认证跳转，实际受保护
        if _RE_JS_REDIRECT.search(text):
            continue
        if (target, "forced_browsing") in seen:
            continue
        seen.add((target, "forced_browsing"))
        findings.append(_mk(
            "缺失授权", f"路径 '{path}' 疑似未授权可访问（强制浏览）", "Medium",
            f"对 {target} 以无会话 GET 请求，返回 200 且正文明显异于应用的 404 基线"
            f"（非登录跳转、非软 404）。可能存在未授权访问 / 缺失授权（CWE-862）。"
            f"需人工确认该路径是否真的无需认证即可访问敏感功能。",
            (text[:160]).replace("\n", " "),
            "对所有敏感/管理路径实施统一的认证与授权校验（默认拒绝，白名单放行）；"
            "不要依赖'不暴露链接'来隐藏管理功能；对访问做审计。",
            target,
            cwe=cwe_for("缺失授权"), endpoint=target, http_method="GET",
            verification_status="unverified", evidence_level="L2",
            poc=f"curl -I '{target}'",
        ))

    # 权限指示参数被动观察（在已爬取页面的参数/字段上识别，不发送额外请求）
    priv_hits = set()
    for k in parse_qs(urlparse(url).query).keys():
        if _PRIV_PARAM_RE.search(k) and k not in priv_hits:
            priv_hits.add(k)
            findings.append(_mk(
                "缺失授权", f"参数 '{k}' 疑似权限/身份指示参数（潜在越权/IDOR 注入点）", "Low",
                f"参数 {k}（端点 {url}）名称疑似标识用户身份/权限（role/admin/uid 等），"
                f"可能存在水平/垂直越权（IDOR）风险，需人工尝试篡改该值验证是否越权访问他人数据。",
                f"param={k}",
                "对对象级访问实施服务端授权校验（验证当前用户是否有权访问目标对象），"
                "不要仅凭客户端参数决定权限；使用不可预测的 ID 并校验所有权。",
                url,
                cwe=cwe_for("缺失授权"), endpoint=url, http_method="GET",
                verification_status="unverified", evidence_level="L1",
                poc=f"篡改 {k} 的值为其他用户 ID 并观察响应",
            ))
    try:
        forms = discover(url, session, timeout, verify_ssl)
    except requests.RequestException:
        forms = []
    for f in forms:
        for field in f["fields"]:
            if _PRIV_PARAM_RE.search(field) and field not in priv_hits:
                priv_hits.add(field)
                findings.append(_mk(
                    "缺失授权", f"表单字段 '{field}' 疑似权限/身份指示字段（潜在越权/IDOR 注入点）", "Low",
                    f"表单字段 {field}（端点 {f['action']}，方法 {f['method'].upper()}）名称疑似标识"
                    f"用户身份/权限，存在水平/垂直越权（IDOR）风险，需人工越权验证。",
                    f"field={field} method={f['method'].upper()}",
                    "对对象级访问实施服务端授权校验，验证所有权后再返回数据。",
                    f["action"],
                    cwe=cwe_for("缺失授权"), endpoint=f["action"], http_method=f["method"].upper(),
                    verification_status="unverified", evidence_level="L1",
                    poc=f"提交时篡改 {field} 的值为其他用户 ID",
                ))
    return findings
