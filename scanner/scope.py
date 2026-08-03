"""PenScope —— 作用域围栏助手（AP-001 整改）

供爬虫 / 指纹识别在**跟随 HTTP 重定向**时复用，闭合「重定向目的不复核作用域」的
SSRF 围栏缺口（CWE-918）。

与 run_scans._is_private_host 的区别：
- run_scans._is_private_host 放行回环地址（起始目标若为使用者本机，本地评估合理）；
- 本模块对**重定向目的**做作用域复核：仅当重定向目标与起始目标在同一作用域时才跟随，
  否则丢弃（防止借工具之手把外部目标的重定向当作跳板去探测内网/本机/云元数据）。

关键设计（修复 localhost 靶场回归）：
- 相对重定向（无 netloc）视为同主机，跟随；
- 同主机重定向，跟随；
- 跨主机但指向受保护内网地址（回环/链路本地/保留/未指定/RFC1918）时：
    · 若起始目标本身就在同一类内网（使用者在扫自己的靶场），则视为同作用域，跟随；
    · 否则属 SSRF，丢弃；
- 其它跨主机重定向一律视为越界，丢弃（与爬虫的同源链接策略一致）。
"""

import ipaddress
import socket


def _resolve_ip(host):
    """解析主机名为 IPv4 地址；失败返回 None（不阻断，交由上层作用域校验兜底）。"""
    if not host:
        return None
    h = str(host).split(":")[0]
    try:
        return socket.gethostbyname(h)
    except (socket.gaierror, UnicodeError, ValueError, OSError):
        return None


def _is_protected(ip):
    """True 表示地址属受保护内网/保留段（回环、链路本地、私有、保留、未指定）。"""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.split(":")[0])
    except ValueError:
        return False
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_unspecified)


def redirect_target_blocked(redirect_netloc, base_host):
    """判断「跟随到 redirect_netloc 的重定向」是否越界（应丢弃）。

    :param redirect_netloc: 重定向 Location 的 netloc（可能为空——相对路径重定向）
    :param base_host: 起始目标主机（不含端口），如 "127.0.0.1" / "example.com"
    :return: True=越界应丢弃；False=同作用域可跟随
    """
    # 相对重定向（无 netloc）视为同主机，跟随
    if not redirect_netloc:
        return False
    rh = redirect_netloc.split(":")[0]
    # 同主机重定向，跟随
    if rh == base_host:
        return False
    # 解析失败：无法确认作用域，保守丢弃（防止借 DNS 失败逃逸）
    rip = _resolve_ip(rh)
    if not rip:
        return True
    # 指向受保护内网地址
    if _is_protected(rip):
        base_ip = _resolve_ip(base_host)
        # 起始目标本身也在同一类内网（使用者在扫自己的靶场）→ 视为同作用域，跟随
        if _is_protected(base_ip):
            return False
        # 外部目标重定向到内网/本机/云元数据 → SSRF，丢弃
        return True
    # 其它跨主机（公网不同主机）重定向 → 越界，丢弃
    return True
