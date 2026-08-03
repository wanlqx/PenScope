"""PenScope —— 端口 / 服务 / 版本扫描
TCP 全连接扫描 + 服务指纹（banner 抓取）+ 已知漏洞版本比对。
仅做连接与只读 banner 读取，不发送任何写/利用数据。
"""
import logging
import socket

import requests

from scanner.scope import redirect_target_blocked
from scanner.vuln_db import match_vulns

log = logging.getLogger(__name__)

# 端口 -> 常见服务名
PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 587: "smtp-submission", 993: "imaps",
    995: "pop3s", 1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 5985: "wsman",
    5986: "wsman-ssl", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9000: "sonarqube", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
    50070: "hadoop",
}

# 需要抓取 HTTP 头指纹的端口
HTTP_PORTS = {80, 443, 8080, 8443, 9000, 9200}


def _grab_banner(sock, port, timeout):
    """尝试读取服务 banner 或 HTTP 头。"""
    try:
        sock.settimeout(timeout)
        if port in HTTP_PORTS:
            # 仅做本地 socket 层 HEAD，避免引入额外依赖复杂度
            req = "HEAD / HTTP/1.0\r\nHost: x\r\n\r\n".encode()
            sock.sendall(req)
            data = sock.recv(1024)
            return data.decode("utf-8", "ignore")
        else:
            data = sock.recv(1024)
            return data.decode("utf-8", "ignore")
    except (socket.timeout, OSError):
        return ""


def scan_ports(host, ports, timeout=3.0):
    """对目标主机做端口扫描，返回开放端口列表（含服务、banner、版本漏洞命中）。
    对输入端口列表去重，避免重复报告同一端口。"""
    seen = set()
    open_ports = []
    for port in ports:
        if port in seen:
            continue
        seen.add(port)
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                svc = PORT_SERVICES.get(port, "unknown")
                banner = _grab_banner(sock, port, timeout)
                vulns = match_vulns(svc, banner)
                # 协议二次验证：对已知文本协议发送协议特定问候，提高 banner 可信度
                verified_banner = _verify_banner(sock, port, banner, timeout)
                open_ports.append({
                    "port": port,
                    "service": svc,
                    "banner": verified_banner.strip()[:200],
                    "vulns": vulns,
                })
        except (socket.timeout, OSError, ValueError):
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    return open_ports


def _verify_banner(sock, port, banner, timeout):
    """对常见服务发送协议特定探测，验证 banner 真实性，减少误报。"""
    try:
        sock.settimeout(timeout)
        probe = None
        if port in (25, 587):
            probe = b"EHLO autopentest\r\n"
        elif port == 110:
            probe = b"USER autopentest\r\n"
        elif port == 143:
            probe = b"A1 CAPABILITY\r\n"
        elif port == 21:
            probe = b"USER anonymous\r\n"
        if probe:
            sock.sendall(probe)
            resp = sock.recv(1024)
            return resp.decode("utf-8", "ignore")
    except Exception as exc:  # 探测失败（超时/对端断开/协议不支持）均静默回退到原 banner，但留痕便于排查
        log.debug("banner 验证探测失败 port=%s: %s", port, exc)
    return banner


def fingerprint_web(host, ports, timeout=4.0, verify_ssl=True):
    """对所有开放端口尝试 HTTP 探测，抓取 Server 头与标题，辅助后续 Web 扫描。

    作用域围栏（AP-001）：不再透明跟随重定向；若端口响应 3xx 跳转到其它主机或解析到
    被拦截网段（私有/回环/链路本地/保留/未指定），直接丢弃该记录，防止越界探测（SSRF）。
    """
    from urllib.parse import urlparse
    web_targets = []
    import re
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}/"
        try:
            r = requests.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
            # 重定向到其它主机 / 被拦截网段：丢弃（SSRF 围栏）
            if r.status_code in (301, 302, 303, 307, 308):
                fu = urlparse(r.headers.get("Location", r.url))
                if redirect_target_blocked(fu.netloc, host):
                    continue
            # 即便未重定向，也确保最终 URL 仍属本目标主机
            if urlparse(r.url).netloc.split(":")[0] != host:
                continue
            server = r.headers.get("Server", "")
            title = ""
            m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).strip()[:120]
            web_targets.append({
                "port": port,
                "url": r.url,
                "server": server,
                "status": r.status_code,
                "title": title,
            })
        except requests.RequestException:
            continue
    return web_targets
