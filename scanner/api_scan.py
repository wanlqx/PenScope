"""PenScope —— API 安全检测模块

对疑似 API 端点（路径含 /api/、/v1/、/graphql 等，或常见 API/文档路径）做**被动**安全检测，
全程只读（GET / OPTIONS / 带 Origin 头），不修改任何数据：

 - CORS 配置错误：响应 Access-Control-Allow-Origin 含外部源且
   Access-Control-Allow-Credentials 为 true（CWE-942）
 - 敏感数据暴露：JSON 响应含明文密码 / 令牌 / 密钥 / 证件号等（CWE-200）
 - 缺失 / 弱鉴权：未携带凭证即可访问数据（启发式，CWE-306）
 - 详细错误 / 堆栈泄露：响应含异常堆栈或数据库错误详情（CWE-209）
 - HTTP 方法滥用：OPTIONS 暴露 PUT / DELETE 等状态变更方法（CWE-650）
 - 凭据出现在 URL 查询串：Token / Key 经 GET 传递（CWE-598）

检测均为启发式，标记为 unverified / L2，需人工结合授权范围确认。
"""
import re
import requests
from urllib.parse import urlparse, urljoin
from scanner.web_scan import _mk
from cvss_dedup import cwe_for

_API_PATH_HINTS = (
    "/api/", "/v1/", "/v2/", "/rest/", "/graphql", "/swagger", "/api-docs",
    "/actuator", "/oauth", "/openapi", "/json", "/metrics", "/admin/api",
)
_API_WORDLIST = [
    "/api/", "/api/v1/", "/api/v2/", "/api/users", "/api/user", "/api/login",
    "/api/account", "/api/orders", "/api/products", "/api/config", "/api/status",
    "/api/health", "/graphql", "/swagger.json", "/swagger-ui.html", "/api-docs",
    "/v2/api-docs", "/actuator", "/actuator/health", "/openapi.json",
    "/api/token", "/api/auth", "/api/profile", "/api/keys",
]

_SKIP_STATUS = (404, 403, 401, 400, 405, 410, 301, 302, 307, 308)

_SENSITIVE_KEY_RE = re.compile(
    r'"(password|passwd|pwd|token|access_token|refresh_token|secret|api_key|apikey|'
    r'private_key|auth|sessionid|session_id|authorization|id_card|idcard|'
    r'ssn|credit_card|bank_card|phone|mobile)"\s*:', re.IGNORECASE)
_SECRET_VALUE_RE = re.compile(
    r'(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|'
    r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})')
_STACK_RE = re.compile(
    r'(traceback \(most recent call last\)|java\.lang\.\w+Exception|'
    r'\.java:\d+|at com\.[a-z]|PHP Fatal error|#0 .*\(.*\):\s|'
    r'SQLSTATE\[|SQLException|org\.springframework\.|stack trace)', re.IGNORECASE)
_QUERY_SECRET_RE = re.compile(
    r'[?&](token|api[_-]?key|apikey|secret|access[_-]?token|auth|password|pwd)=',
    re.IGNORECASE)


def _candidate_urls(base_url, pages):
    """汇总 API 候选端点：爬取到的 API 风格链接 + 常见 API/文档路径。"""
    seen = set()
    out = []
    host_part = "{0}://{1}".format(*urlparse(base_url)[:2])
    for p in pages:
        low = p.lower()
        if any(h in low for h in _API_PATH_HINTS):
            u = p.split("#")[0]
            if u not in seen:
                seen.add(u)
                out.append(u)
    for w in _API_WORDLIST:
        u = urljoin(base_url, w).split("#")[0]
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def scan_api(base_url, session, pages=None, timeout=6.0, verify_ssl=True):
    """API 安全被动检测。pages 为 web_detect 阶段爬取到的同主机页面集合。"""
    findings = []
    if not pages:
        pages = []
    candidates = _candidate_urls(base_url, pages)
    evil_origin = "https://evil.example.com"

    for url in candidates:
        # 1) 常规 GET
        try:
            r = session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
        except requests.RequestException:
            continue
        status = r.status_code
        ctype = r.headers.get("Content-Type", "")
        body = r.text or ""
        # 跳过明确无接口的响应：仅当 URL 完全不像 API 端点时才跳过纯 HTML
        # （API 路径下的 HTML 错误页/文档页仍应检测堆栈与 CORS）
        if status in _SKIP_STATUS:
            continue
        if "text/html" in ctype and not any(h in url.lower() for h in _API_PATH_HINTS):
            continue

        # 2) CORS 配置错误检测（带外部 Origin 重发）
        try:
            rc = session.get(url, headers={"Origin": evil_origin}, timeout=timeout,
                             verify=verify_ssl, allow_redirects=False)
        except requests.RequestException:
            rc = r
        acao = rc.headers.get("Access-Control-Allow-Origin", "")
        acac = (rc.headers.get("Access-Control-Allow-Credentials") or "").lower()
        if acao and (acao.strip() == "*" or evil_origin in acao) and acac == "true":
            findings.append(_mk(
                "API安全", f"端点 {url} 存在 CORS 配置错误（允许任意源携带凭据）", "Medium",
                "响应头 Access-Control-Allow-Origin 包含外部来源，且 "
                "Access-Control-Allow-Credentials 为 true；攻击者可借已登录用户浏览器跨域读取该接口数据。",
                f"ACAO={acao} ACAC={acac}",
                "仅对可信域名放开 CORS；不要在允许凭据时返回 '*'；改用显式白名单并校验 Origin。",
                url,
                cwe="CWE-942", endpoint=url, http_method="GET",
                verification_status="unverified", evidence_level="L2",
                poc=f"curl -H 'Origin: {evil_origin}' '{url}'",
            ))

        # 3) 敏感数据暴露（JSON 响应）
        is_json = "application/json" in ctype or body.lstrip().startswith(("{", "["))
        if is_json:
            keys = set(m.group(1).lower() for m in _SENSITIVE_KEY_RE.finditer(body))
            secrets = _SECRET_VALUE_RE.findall(body)
            if keys or secrets:
                detail = "响应 JSON 含敏感字段："
                if keys:
                    detail += "字段=" + ", ".join(sorted(keys)) + "；"
                if secrets:
                    detail += f"命中密钥特征串 {len(secrets)} 处（如 AWS Key / JWT / OpenAI Key）。"
                findings.append(_mk(
                    "API安全", f"端点 {url} 响应暴露敏感数据", "Medium",
                    detail,
                    f"keys={sorted(keys)[:8]} secrets={len(secrets)}",
                    "敏感字段（密码/令牌/密钥/证件号）禁止出现在响应中；使用字段白名单投影；"
                    "对日志与 API 响应做脱敏处理。",
                    url,
                    cwe="CWE-200", endpoint=url, http_method="GET",
                    verification_status="unverified", evidence_level="L2",
                    poc=f"curl '{url}'",
                ))

        # 4) 详细错误 / 堆栈泄露
        m_stack = _STACK_RE.search(body)
        if m_stack:
            findings.append(_mk(
                "API安全", f"端点 {url} 响应泄露堆栈 / 错误详情", "Low",
                "响应中包含异常堆栈或数据库错误详情，可能辅助攻击者构造利用。",
                m_stack.group(0)[:80],
                "生产环境统一异常处理，返回通用错误码；详细日志仅记录在服务端。",
                url,
                cwe="CWE-209", endpoint=url, http_method="GET",
                verification_status="unverified", evidence_level="L2",
                poc=f"curl '{url}'",
            ))

        # 5) HTTP 方法滥用（OPTIONS 暴露 PUT/DELETE）
        try:
            ro = session.options(url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
            allow = (ro.headers.get("Allow") or "").upper()
            if any(m in allow for m in ("PUT", "DELETE")):
                findings.append(_mk(
                    "API安全", f"端点 {url} 允许 PUT / DELETE 等方法", "Low",
                    f"OPTIONS 返回 Allow: {allow}，提示接口支持状态变更方法，需确认是否做了鉴权与幂等保护。",
                    f"Allow={allow}",
                    "对 PUT / DELETE 等危险方法做严格鉴权与审计；非必要则禁用。",
                    url,
                    cwe="CWE-650", endpoint=url, http_method="OPTIONS",
                    verification_status="unverified", evidence_level="L2",
                    poc=f"curl -X OPTIONS '{url}'",
                ))
        except requests.RequestException:
            pass

        # 6) 凭据出现在 URL 查询串
        if _QUERY_SECRET_RE.search(url):
            findings.append(_mk(
                "API安全", f"端点 {url} 经 URL 传递敏感凭据", "Low",
                "请求 URL 中包含 token / api_key / secret 等敏感参数，易被代理、日志、Referer 泄露。",
                "敏感参数出现在 query string",
                "敏感凭据改由 Authorization 头 / 请求体传递；避免在 URL 中携带密钥。",
                url,
                cwe="CWE-598", endpoint=url, http_method="GET",
                verification_status="unverified", evidence_level="L2",
                poc=f"curl '{url}'",
            ))
    return findings
