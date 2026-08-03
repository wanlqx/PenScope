# -*- coding: utf-8 -*-
"""scanner/subdomain.py —— 被动子域枚举（资产发现）

设计原则（合规/非破坏性）：
- 仅做「被动 + 只读」发现：证书透明度日志(crt.sh) + 常见子域 DNS 解析。
- 不做大规模主动爆破；DNS 解析为只读系统调用，不产生任何写入/包注入。
- 发现的兄弟子域**只记录为「资产发现」信息级发现**，**绝不自动创建扫描任务**；
  若需进一步扫描，必须经二次授权（作用域围栏），由使用者在应用内手动添加目标。
- resolver / fetcher 可注入，便于离线单元测试（无需真实外网）。
"""
import json
import socket

# 多段顶级域（取基础域名时需多退一层）
_MULTI_TLD = (
    "edu.cn", "com.cn", "gov.cn", "org.cn", "net.cn", "ac.cn", "co.cn",
    "co.uk", "org.uk", "gov.uk", "com.au", "co.jp", "com.br", "com.tw",
    "com.hk", "org.hk", "gov.hk",
)

# 常见子域字典（用于 DNS 被动解析补全；规模克制，不主张主动爆破）
_WORDLIST = [
    "www", "mail", "smtp", "pop", "imap", "mx", "dns", "ns", "ftp", "vpn",
    "db", "api", "app", "m", "mobile", "admin", "administrator", "manage",
    "manager", "console", "dashboard", "portal", "oa", "crm", "erp", "hr",
    "bbs", "forum", "blog", "news", "shop", "store", "pay", "payment",
    "auth", "sso", "login", "cas", "idp", "oauth", "gw", "gateway", "cdn",
    "img", "static", "assets", "files", "file", "doc", "docs", "wiki",
    "git", "svn", "jenkins", "jira", "confluence", "test", "dev", "staging",
    "pre", "demo", "beta", "alpha", "internal", "intranet", "yun", "cloud",
    "minio", "storage", "oss", "webmail", "exchange", "owa", "mailserver",
]

_CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"

# 进程级缓存：同一基础域名的枚举结果复用，避免同组织多目标重复 crt.sh 拉取与 DNS 风暴
_ENUM_CACHE = {}


def base_domain(host):
    """从主机名推导基础注册域名（支持多段 TLD）。"""
    host = (host or "").strip().lower()
    if not host:
        return ""
    if host.startswith("*."):
        host = host[2:]
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_TLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def _default_resolver(host):
    """只读 DNS 解析；失败返回 None。"""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _default_fetcher(url, timeout=8):
    """读取 crt.sh JSON；失败返回 None。依赖 requests，调用处捕获异常。"""
    try:
        import requests
        r = requests.get(url, timeout=timeout, verify=True,
                         headers={"User-Agent": "PenScope/1.0 (authorized recon)"})
        if r.status_code == 200:
            return r.text
    except Exception:
        return None
    return None


def _parse_crt(text):
    """解析 crt.sh 返回的 JSON，提取所有 name_value（去通配与自身）。"""
    out = set()
    if not text:
        return out
    try:
        data = json.loads(text)
    except Exception:
        return out
    if not isinstance(data, list):
        return out
    for item in data:
        nv = item.get("name_value")
        if not nv:
            continue
        for name in nv.split("\n"):
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name and "*" not in name:
                out.add(name)
    return out


def enum_subdomains(domain, resolve=True, fetch_crt=True, wordlist=None,
                    _resolver=None, _fetcher=None):
    """被动枚举指定域名下的兄弟子域。

    返回已「解析成功」的子域列表（去重；不含入参 domain 自身）。
    参数：
      domain      —— 当前目标主机名（如 mail.jxnu.edu.cn）
      resolve     —— 是否对候选做 DNS 解析（仅保留能解析的）
      fetch_crt   —— 是否查询证书透明度日志
      wordlist    —— 自定义子域字典；None 用内置 _WORDLIST
      _resolver   —— 注入式 DNS 解析器（测试用）
      _fetcher    —— 注入式 crt.sh 抓取器（测试用）
    """
    base = base_domain(domain)
    if not base:
        return []
    resolver = _resolver or _default_resolver
    fetcher = _fetcher or _default_fetcher

    # 缓存键：基础域名 + 是否查 crt + 是否使用内置字典（注入自定义字典则不复用）
    cache_key = (base, bool(fetch_crt), wordlist is _WORDLIST)
    cached = _ENUM_CACHE.get(cache_key)

    candidates = set()
    if fetch_crt:
        text = fetcher(_CRT_URL.format(domain=base))
        for name in _parse_crt(text):
            if name == base or name.endswith("." + base):
                candidates.add(name)
    wl = wordlist if wordlist is not None else _WORDLIST
    if wl:
        for w in wl:
            candidates.add(f"{w}.{base}")

    # 排除自身（基础域名与其自身主机名都不纳入）
    candidates.discard(domain.lower())
    candidates.discard(base)

    if cached is not None:
        return [c for c in cached if c != domain.lower() and c != base]
    found = []
    seen_ip = set()
    for cand in sorted(candidates):
        if resolve:
            ip = resolver(cand)
            if not ip:
                continue
            # 同一 IP 只记一次，避免 CDN/同 IP 多 vhost 噪音
            if ip in seen_ip:
                continue
            seen_ip.add(ip)
        found.append(cand)
    # 缓存基础结果；返回时再排除自身，使缓存可跨同域不同目标复用
    _ENUM_CACHE[cache_key] = found
    return [c for c in found if c != domain.lower() and c != base]


def scan_subdomain_assets(domain, _resolver=None, _fetcher=None):
    """便捷封装：返回 [(subdomain, ip)] 资产发现列表。"""
    found = enum_subdomains(domain, resolve=True, _resolver=_resolver, _fetcher=_fetcher)
    resolver = _resolver or _default_resolver
    out = []
    for sub in found:
        ip = resolver(sub)
        out.append((sub, ip or ""))
    return out


if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv) > 1 else "jxnu.edu.cn"
    print("base:", base_domain(d))
    for sub, ip in scan_subdomain_assets(d):
        print("  %s -> %s" % (sub, ip))
