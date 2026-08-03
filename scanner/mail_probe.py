# -*- coding: utf-8 -*-
"""邮件/协议感知：对 SMTP/POP3/IMAP 端口做只读协议指纹与明文传输检测。

设计原则（合规、非破坏性）：
  - 仅建立 TCP 连接、读取服务横幅(greeting)，并发送 EHLO / CAPA / CAPABILITY 探测
    STARTTLS 支持情况；**绝不登录、绝不认证、绝不发送邮件、绝不爆破**。
  - 仅产出 Info / Low / Medium 级别的「资产暴露 / 配置缺陷」发现，不触碰任何利用。
  - 端口模板按服务类型选择（而非仅 Web 80/443），弥补此前仅 Web 端口检测的盲区。

判定：
  - 隐式 TLS 端口（465/995/993）：Info —— 已启用隐式 TLS 传输层加密。
  - 明文端口（25/587/110/143）且通告 STARTTLS：Low —— 支持 STARTTLS，建议强制并禁用明文认证。
  - 明文端口且无 STARTTLS：Medium —— 明文传输端口无 STARTTLS 保护，凭证可能明文暴露。
"""
import socket

# 端口 -> 协议标识
MAIL_PORTS = {
    25: ("smtp", False),       # 明文 SMTP
    465: ("smtps", True),      # 隐式 TLS SMTP
    587: ("submission", False),# 明文 submission（应 STARTTLS）
    110: ("pop3", False),      # 明文 POP3
    995: ("pop3s", True),      # 隐式 TLS POP3
    143: ("imap", False),      # 明文 IMAP
    993: ("imaps", True),      # 隐式 TLS IMAP
}

_CRLF = b"\r\n"


def _recv_all(sock, total_timeout=4.0, idle_timeout=0.6):
    """读取响应：直到 idle_timeout 内无新数据或达到 total_timeout。"""
    sock.settimeout(idle_timeout)
    chunks = []
    import time
    deadline = time.time() + total_timeout
    while time.time() < deadline:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
        if len(b"".join(chunks)) > 65536:
            break
    return b"".join(chunks).decode("utf-8", "replace")


def _classify(service, port, greeting, capa_text):
    """纯函数：根据服务/端口/横幅/能力文本给出（risk, title, detail）分类，便于单测。"""
    implicit = MAIL_PORTS.get(port, (service, False))[1]
    if implicit:
        return ("Info",
                f"{service.upper()} 端口 {port} 使用隐式 TLS",
                f"服务横幅：{greeting.strip()[:200]}\n该端口使用隐式 TLS（传输层已加密），"
                f"无明文暴露风险；仍建议确认所使用 TLS 版本/密码套件无已知弱点。")
    has_starttls = "STARTTLS" in (capa_text or "").upper()
    if has_starttls:
        return ("Low",
                f"{service.upper()} 明文端口 {port} 支持 STARTTLS",
                f"服务横幅：{greeting.strip()[:200]}\n能力声明：{capa_text.strip()[:300]}\n"
                f"该明文端口通告 STARTTLS，建议服务端强制 STARTTLS 并禁用明文认证，"
                f"避免降级攻击导致凭证明文暴露。")
    return ("Medium",
            f"{service.upper()} 明文端口 {port} 无 STARTTLS 保护",
            f"服务横幅：{greeting.strip()[:200]}\n能力声明：{capa_text.strip()[:300]}\n"
            f"该明文端口既未使用隐式 TLS、也未通告 STARTTLS，凭证可能以明文形式在网络中传输，"
            f"存在被中间人窃听/劫持的风险（CWE-319 明文传输）。")


def scan_mail(host, port, timeout=6.0):
    """对单个邮件端口做只读探测，返回发现字典列表（run_scans 用 add_finding 入库）。"""
    if port not in MAIL_PORTS:
        return []
    service, _implicit = MAIL_PORTS[port]
    findings = []
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return [{
            "category": "已知漏洞", "title": f"{service.upper()} 端口 {port} 连接失败",
            "risk": "Info", "detail": f"无法连接 {host}:{port}（{e}），跳过明文传输检测。",
            "evidence": "", "remediation": "确认该端口服务是否存活。",
            "target_ref": f"{host}:{port}", "cwe": "CWE-200",
            "verification_status": "info", "evidence_level": "L1",
            "endpoint": f"{host}:{port}", "http_method": service.upper(),
        }]
    try:
        greeting = _recv_all(sock, total_timeout=4.0)
        capa = ""
        try:
            if service in ("smtp", "submission"):
                sock.sendall(b"EHLO autopentest-ai.local" + _CRLF)
                capa = _recv_all(sock, total_timeout=4.0)
            elif service == "pop3":
                sock.sendall(b"CAPA" + _CRLF)
                capa = _recv_all(sock, total_timeout=4.0)
            elif service == "imap":
                sock.sendall(b"A1 CAPABILITY" + _CRLF)
                capa = _recv_all(sock, total_timeout=4.0)
        except OSError:
            capa = ""
        risk, title, detail = _classify(service, port, greeting, capa)
        findings.append({
            "category": "邮件服务配置", "title": title, "risk": risk,
            "detail": detail,
            "evidence": f"greeting={greeting.strip()[:200]}\ncapa={capa.strip()[:300]}",
            "remediation": ("对明文端口强制 STARTTLS 并禁用明文认证；升级到支持现代 TLS 的版本；"
                            "如非必要，关闭公网明文邮件端口。") if risk != "Info" else
                           "确认 TLS 版本/密码套件无已知弱点，保持隐式 TLS 启用。",
            "target_ref": f"{host}:{port}", "cwe": "CWE-319" if risk == "Medium" else "CWE-200",
            "verification_status": "info" if risk == "Info" else "unverified",
            "evidence_level": "L1",
            "endpoint": f"{host}:{port}", "http_method": service.upper(),
        })
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return findings
