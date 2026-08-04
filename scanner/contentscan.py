# -*- coding: utf-8 -*-
"""scanner/contentscan.py —— 目录/敏感信息被动扫描（资产暴露面）

设计原则（合规/非破坏性）：
- 全程只读：仅对内置路径字典做 HEAD / GET（GET 以 stream + 限长读取，绝不下载整文件）。
- 绝不写入、上传、删除任何内容；不发送 POST/PUT/DELETE。
- 仅记录「暴露面」类发现（信息/低危为主）：敏感信息泄露、目录/文件暴露。
- 所有发现均 unverified / L2，需人工结合授权范围确认；命中疑似真实密钥等中危项时
  不自动验证（验证=触碰数据，超出只读探测边界）。

暴露检测项：
 - 敏感信息泄露：内部 IP、云 AK/SK、JWT、私钥、SQL/DB 报错、调试堆栈、.env 明文、
   备份文件内容、目录列表开启。
 - 目录/文件暴露：管理台/登录页、配置文件、版本控制目录(.git/.svn)、备份文件、
   信息泄露端点(phpinfo)等可访问或被拒绝(403)存在。
"""
import re
from urllib.parse import urljoin

from scanner.web_scan import _mk

# 只探测「已知敏感/常见」路径；规模克制，不做无差别全字典爆破（避免噪音与合规风险）
_PATH_WORDLIST = [
    # 管理/登录面
    "/admin", "/admin/login", "/login", "/wp-admin", "/phpmyadmin", "/manager",
    "/console", "/control", "/backend", "/sysadmin", "/root",
    # 配置/密钥文件
    "/.env", "/.env.bak", "/.env.local", "/config.php", "/web.config", "/app.config",
    "/config.yml", "/config.json", "/settings.py", "/application.yml", "/.env.production",
    # 版本控制 / 元数据
    "/.git/HEAD", "/.git/config", "/.svn/entries", "/.hg/store", "/.idea/.gitignore",
    # 备份文件
    "/backup", "/backup.zip", "/wwwroot.zip", "/site.zip", "/www.zip", "/web.zip",
    "/db.sql", "/dump.sql", "/backup.sql", "/index.php.bak", "/index.bak", "/app.bak",
    # 信息泄露端点
    "/phpinfo.php", "/info.php", "/status", "/actuator", "/actuator/env", "/debug",
    "/_profiler", "/.well-known/security.txt",
    # 常见目录
    "/uploads", "/images", "/static", "/assets", "/tmp", "/test", "/api", "/api/v1",
    # 机器人/地图
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
]

# 命中即视为「明确敏感存储」的路径后缀（200 时按中危记录）
_SENSITIVE_PATH_HINTS = (
    ".env", "config", "web.config", "phpinfo", "actuator", ".git", ".svn", ".hg",
    ".sql", "backup", "dump", ".bak", "phpinfo",
)

# —— 敏感内容正则（仅只读匹配，不外传）——
_RE_INTERNAL_IP = re.compile(
    r'(?:\b(?:10|127|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b)')
_RE_AK = re.compile(
    r'(AKIA[0-9A-Z]{16}|AKID[A-Za-z0-9]{13,}|LTAI[A-Za-z0-9]{12,}|'
    r'sk-[A-Za-z0-9]{20,}|ASIA[0-9A-Z]{16})')
_RE_JWT = re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}')
_RE_PRIVKEY = re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----')
_RE_SQLERR = re.compile(
    r'(SQL syntax|mysql_fetch|SQLSTATE\[\w+\]|ORA-\d{5}|SQLite3::|'
    r'Microsoft SQL Server|Unknown column|supplied argument|'
    r'PostgreSQL.*ERROR|You have an error in your SQL)')
_RE_STACK = re.compile(
    r'(traceback \(most recent call last\)|java\.lang\.\w+Exception|'
    r'PHP Fatal error|#0 .*\(.*\):\s|Stack trace|at com\.[a-z])', re.IGNORECASE)
_RE_SECRET_KV = re.compile(
    r'(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|'
    r'private[_-]?key|client[_-]?secret)\s*[:=]\s*[\'"]?[^\s\'"]{4,}', re.IGNORECASE)
_RE_DIRINDEX = re.compile(r'(<title>\s*index of|directory listing for|ftp listing)', re.IGNORECASE)

_READ_LIMIT = 65536  # 单次 GET 最多读取 64KB 用于内容判定


def _read_body(r):
    """以 stream 方式限长读取响应体，避免下载大文件。"""
    try:
        chunks = []
        total = 0
        for chunk in r.iter_content(chunk_size=8192):
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= _READ_LIMIT:
                break
        return b"".join(chunks).decode("utf-8", "ignore")
    except Exception:
        return ""


def _classify_path(url):
    low = url.lower()
    for h in _SENSITIVE_PATH_HINTS:
        if h in low:
            return True
    return False


def scan_content(base_url, session, timeout=6.0, verify_ssl=True, paths=None):
    """对 base_url 所在主机做目录/敏感信息被动扫描。仅只读 GET/HEAD。"""
    findings = []
    paths = paths or _PATH_WORDLIST

    for p in paths:
        url = urljoin(base_url, p).split("#")[0]
        try:
            r = session.get(url, timeout=timeout, verify=verify_ssl,
                            allow_redirects=False, stream=True)
        except Exception:
            continue
        try:
            status = r.status_code
            ctype = (r.headers.get("Content-Type") or "").lower()
            if status == 404:
                continue
            body = _read_body(r) if status == 200 else ""

            # —— 目录/文件暴露（存在性）——
            is_sens = _classify_path(url)
            if status == 200 and is_sens:
                findings.append(_mk(
                    "目录暴露", f"敏感路径可访问：{url}", "Medium" if is_sens else "Low",
                    "目标存在可被直接访问的敏感路径（配置/密钥/备份/版本控制/信息泄露端点），"
                    "可能泄露凭据或系统细节。",
                    f"status=200 content-type={ctype[:40]} bytes={len(body)}",
                    "将该类路径移出 Web 根目录或限制访问来源（IP/认证）；禁止在 Web 可访问位置存放"
                    "密钥与备份；关闭目录列表。",
                    url, cwe="CWE-538", endpoint=url, http_method="GET",
                    verification_status="unverified", evidence_level="L2",
                    poc=f"curl -I '{url}'",
                ))
            elif status == 200 and _RE_DIRINDEX.search(body):
                findings.append(_mk(
                    "目录暴露", f"目录列表开启：{url}", "Low",
                    "目标开启了目录列表（Index of），可浏览目录下文件，可能泄露备份/源码等。",
                    "status=200 命中目录列表标识",
                    "关闭 Web 服务器目录列表（Indexes）；对静态目录显式提供索引或返回 403。",
                    url, cwe="CWE-548", endpoint=url, http_method="GET",
                    verification_status="unverified", evidence_level="L2",
                    poc=f"curl '{url}'",
                ))

            # —— 敏感信息泄露（仅对 200 响应体做只读匹配）——
            if status == 200 and body:
                hits = []
                if _RE_AK.search(body):
                    hits.append("云访问密钥(AK/SK)")
                if _RE_JWT.search(body):
                    hits.append("JWT 令牌")
                if _RE_PRIVKEY.search(body):
                    hits.append("私钥")
                if _RE_SQLERR.search(body):
                    hits.append("SQL/数据库报错")
                if hits:
                    findings.append(_mk(
                        "敏感信息泄露", f"响应泄露敏感数据：{url}", "Medium",
                        "响应体中命中疑似真实凭据/密钥特征：" + "、".join(sorted(set(hits))) +
                        "。此类信息若属实，可能被直接用于未授权访问。",
                        "命中特征：" + "、".join(sorted(set(hits))),
                        "禁止在响应/前端/日志中回显密钥与令牌；统一脱敏；轮换已暴露凭据。",
                        url, cwe="CWE-200", endpoint=url, http_method="GET",
                        verification_status="unverified", evidence_level="L2",
                        poc=f"curl '{url}'",
                    ))
                    continue  # 已按中危记录，避免重复低危
                # 低危级：内部 IP / 调试堆栈 / 明文密钥键值
                low_hits = []
                if _RE_INTERNAL_IP.search(body):
                    low_hits.append("内部 IP 地址")
                if _RE_STACK.search(body):
                    low_hits.append("调试/异常堆栈")
                if _RE_SECRET_KV.search(body):
                    low_hits.append("明文密钥键值")
                if low_hits:
                    findings.append(_mk(
                        "敏感信息泄露", f"响应泄露信息：{url}", "Low",
                        "响应体暴露内网信息/调试细节：" + "、".join(sorted(set(low_hits))) +
                        "，可用于进一步侦察或辅助利用。",
                        "命中：" + "、".join(sorted(set(low_hits))),
                        "生产环境关闭详细错误输出；内网拓扑不应对外暴露；统一异常返回。",
                        url, cwe="CWE-200", endpoint=url, http_method="GET",
                        verification_status="unverified", evidence_level="L2",
                        poc=f"curl '{url}'",
                    ))
        finally:
            try:
                r.close()
            except Exception:
                pass
    return findings


if __name__ == "__main__":
    import sys

    import requests
    b = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18099"
    s = requests.Session()
    s.headers.update({"User-Agent": "PenScope/1.0 (authorized scan)"})
    for f in scan_content(b, s):
        print(f["risk"], f["category"], f["title"])
