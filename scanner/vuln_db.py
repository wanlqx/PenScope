"""PenScope —— 已知漏洞库（内置常见服务版本 → CVE 映射）
说明：仅收录公开、用于"版本比对告警"的条目，用于提示风险，不提供可用利用代码。
真实平台应接入 NVD / CVE 数据源定时更新。
"""

# 每条: 服务关键字(在 banner/产品名中出现) -> 列表[最小危险版本描述, 风险, CVE, 修复建议]
KNOWN_VULNS = [
    {
        "service": "vsftpd",
        "pattern": r"vsftpd\s*([\d.]+)",
        "vuln_versions": ["2.3.4"],
        "risk": "Critical",
        "cve": "CVE-2011-2523",
        "detail": "vsftpd 2.3.4 存在后门命令注入（笑脸漏洞），攻击者可获取 root shell。",
        "remediation": "升级至 vsftpd 3.x 官方修复版本，并禁用匿名访问。",
    },
    {
        "service": "OpenSSH",
        "pattern": r"OpenSSH[_-]?([\d.]+)",
        "vuln_versions": ["2.3", "3.", "4.", "5.", "6.", "7.0", "7.1", "7.2", "7.3", "7.4", "7.5", "7.6", "7.7", "7.8", "7.9"],
        "risk": "High",
        "cve": "CVE-2018-15473 (用户枚举) 等多项",
        "detail": "OpenSSH < 7.7 存在多个已知漏洞（用户枚举、CVE-2020-15778 scp 命令注入等）。",
        "remediation": "升级 OpenSSH 至 8.x 以上，禁用弱密码算法，启用密钥登录。",
    },
    {
        "service": "ProFTPD",
        "pattern": r"ProFTPD\s*([\d.]+)",
        "vuln_versions": ["1.3.3", "1.3.4", "1.3.5"],
        "risk": "High",
        "cve": "CVE-2015-3306 等",
        "detail": "ProFTPD 多个版本存在远程代码执行 / 目录遍历漏洞。",
        "remediation": "升级至 ProFTPD 1.3.6+ 并正确配置。",
    },
    {
        "service": "Apache",
        "pattern": r"Apache/([\d.]+)",
        "vuln_versions": ["2.2", "2.3", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5", "2.4.6", "2.4.7", "2.4.8", "2.4.9", "2.4.10", "2.4.11", "2.4.12", "2.4.13", "2.4.14", "2.4.15", "2.4.16", "2.4.17", "2.4.18", "2.4.19", "2.4.20", "2.4.21", "2.4.22", "2.4.23", "2.4.24", "2.4.25", "2.4.26", "2.4.27", "2.4.28", "2.4.29", "2.4.30", "2.4.31", "2.4.32", "2.4.33", "2.4.34", "2.4.35", "2.4.36", "2.4.37", "2.4.38", "2.4.39", "2.4.40", "2.4.41"],
        "risk": "High",
        "cve": "CVE-2021-41773 / CVE-2021-42013 等",
        "detail": "Apache 2.4.49/2.4.50 存在路径遍历导致 RCE；多个旧版存在解析漏洞。",
        "remediation": "升级至 Apache 2.4.52+，关闭 CGI，限制目录访问。",
    },
    {
        "service": "nginx",
        "pattern": r"nginx/([\d.]+)",
        "vuln_versions": ["0.", "1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10", "1.11", "1.12", "1.13", "1.14", "1.15", "1.16", "1.17", "1.18", "1.19", "1.20"],
        "risk": "Medium",
        "cve": "CVE-2019-9511 等",
        "detail": "部分旧版 nginx 存在请求走私 / 拒绝服务风险。",
        "remediation": "升级至 nginx 1.22+ 稳定版。",
    },
    {
        "service": "Redis",
        "pattern": r"redis_version:([\d.]+)",
        "vuln_versions": ["2.", "3.0", "3.1", "3.2", "4.0", "5.0", "6.0", "6.1", "6.2"],
        "risk": "High",
        "cve": "CVE-2022-0543 等",
        "detail": "Redis 未授权访问 / Lua 沙箱逃逸可导致远程代码执行。",
        "remediation": "禁止公网暴露，启用 requirepass 与 bind 127.0.0.1，以低权限运行。",
    },
    {
        "service": "MySQL",
        "pattern": r"([\d.]+)-MariaDB|MariaDB",
        "vuln_versions": [],
        "risk": "Info",
        "cve": "-",
        "detail": "检测到数据库服务，需确认是否限制访问来源与强口令。",
        "remediation": "限制数据库端口仅内网可达，使用强口令并定期轮换。",
    },
]

import re


def match_vulns(service_name, banner):
    """依据服务名与 banner 匹配已知漏洞，返回命中列表。"""
    hits = []
    if not banner:
        return hits
    for entry in KNOWN_VULNS:
        m = re.search(entry["pattern"], banner, re.IGNORECASE)
        if m and (entry["service"].lower() in (service_name or "").lower() or m.group(0)):
            version = m.group(1) if m.groups() else ""
            # 判断版本是否落在危险区间（以起始号前缀匹配）
            is_vuln = False
            if entry["vuln_versions"]:
                for v in entry["vuln_versions"]:
                    if version.startswith(v):
                        is_vuln = True
                        break
            else:
                is_vuln = True  # 仅信息提示类
            if is_vuln:
                hits.append({
                    "service": entry["service"],
                    "version": version,
                    "risk": entry["risk"],
                    "cve": entry["cve"],
                    "detail": entry["detail"],
                    "remediation": entry["remediation"],
                })
    return hits
