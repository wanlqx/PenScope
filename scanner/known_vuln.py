"""已知漏洞端点被动探针 —— 基于 POC-main/wpoc 整理的端点映射。

设计约束（与 PenScope 安全围栏一致）：
- **只读 GET**：对每个已知端点只发一次 GET 判断"是否可达"（200/301/302/403/405）。
  绝不发送任何利用 payload，绝不 POST 带参，绝不爆破/写/篡改。
- 命中只标记为 **需人工确认的被动线索（L1/L2）**，绝不直接判定为已利用漏洞。
- 仅对 status=approved 目标运行；请求数有上限（默认 8）。

数据来源：POC-main/wpoc（2,506 POC，wy876 漏洞库镜像），复制整理于
scanner/data/known_vuln_endpoints.json。
"""
import json
import os
from urllib.parse import urljoin

_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "known_vuln_endpoints.json")

_cache = None


def _load():
    global _cache
    if _cache is not None:
        return _cache
    try:
        with open(_DATA_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {"aliases": {}, "products": {}}
    _cache = data
    return _cache


# 高价值产品：即使仅 body 命中也触发已知漏洞端点探针（避免 oa/xg 类真实 OA 被漏掉）。
# 这些产品的已知漏洞端点现实高危（OA/框架类），且 body 关键词特异、误报可控。
_HIGH_VALUE_PRODUCTS = [
    "用友OA", "泛微OA", "通达OA", "九思OA", "致远OA", "金和OA", "万户OA", "宏景OA",
    "蓝凌OA", "金蝶", "JeecgBoot", "Apache", "WordPress", "锐捷", "海康威视", "大华",
    "亿赛通", "Weblogic", "Tomcat", "Springboot", "Apache Shiro", "F5 BIG-IP",
    "Confluence", "Gitlab", "Jboss", "Jenkins", "PHPUnit", "ThinkPHP", "Sunlogin",
    "Log4j", "ActiveMQ", "Flink", "Kylin", "Spark", "Apereo-CAS",
]


def _build_hv_aliases():
    data = _load()
    s = set()
    for p in _HIGH_VALUE_PRODUCTS:
        s.add(p.lower())
        s.update(str(a).lower() for a in data.get("aliases", {}).get(p, []))
    return s


_HV_ALIASES = _build_hv_aliases()


def resolve_highvalue(cms_list):
    """返回 cms 列表中属于高价值产品的 canonical 产品（用于触发端点探针）。"""
    cms_lower = [str(c).lower() for c in cms_list]
    hv = [c for c in cms_list if str(c).lower() in _HV_ALIASES]
    return resolve_products(hv)


def resolve_products(cms_list):
    """把 mitan 指纹命中的 cms 名称映射到 canonical 产品（用于查 known_vuln 端点）。"""
    data = _load()
    aliases = data.get("aliases", {})
    products = data.get("products", {})
    matched = set()
    cms_lower = [str(c).lower() for c in cms_list]
    for product in products:
        toks = [product.lower()] + [str(a).lower() for a in aliases.get(product, [])]
        for cl in cms_lower:
            if any(tok and tok in cl for tok in toks):
                matched.add(product)
                break
    return sorted(matched)


def lookup_endpoints(product_names, max_endpoints=8):
    """聚合命中产品的已知端点（按 path 去重），返回 list[dict]。"""
    data = _load()
    products = data.get("products", {})
    seen = {}
    for p in product_names:
        for ep in products.get(p, {}).get("endpoints", []):
            path = ep.get("path")
            if not path or path in seen:
                continue
            seen[path] = {"product": p, **ep}
    items = list(seen.values())
    return items[:max_endpoints]


# 可达性判定：仅被动观察，不利用
_REACHABLE = {200, 201, 202, 203, 204, 301, 302, 307, 308}
_EXISTS_DENIED = {401, 403, 405, 406, 429}

# 认证敏感类端点（未授权访问 / 认证绕过）：单纯 200 可达 ≠ 缺失鉴权已利用。
# 这类端点（/admin/、/manager/html、/jmx-console/ 等）返回 200 往往是登录页或认证挑战页，
# 断言 "Missing Authentication (CWE-306) Medium" 属过度断言 → 降噪为 Info(L1)，
# 仅保留需人工确认的被动线索，避免把认证挑战页误判为高危缺失鉴权（误报治理）。
_AUTH_SENSITIVE = {"Unauth", "AuthBypass"}


def passive_probe(session, base_url, endpoints, timeout=6.0, verify_ssl=True, home_body=None):
    """对已知端点做只读 GET 可达性探针。

    :param home_body: 首页响应体（可选）。若某端点返回 200 且响应体与此相同，
                      判定为 SPA/全站兜底伪 200（catch-all），跳过，避免误报。
    :returns: list[dict] 每个命中端点的被动线索（仅 flag，不含利用）。
    """
    findings = []
    for ep in endpoints:
        path = ep.get("path")
        if not path:
            continue
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
            code = r.status_code
            body = r.text or ""
        except Exception:
            continue  # 不可达/超时 → 视为不存在，跳过
        if code in _REACHABLE:
            # SPA/全站统一响应（catch-all 伪 200）：与首页同体 → 噪声，跳过
            if code == 200 and home_body is not None and body == home_body:
                continue
            sev = ep.get("severity") or "Medium"  # 端点可带 severity 降级（如仅用于识别产品的登录页设为 Info）
            # 认证敏感类端点：200 可达不代表缺失鉴权已利用（可能是登录/认证挑战页），降噪为 Info
            if sev == "Medium" and ep.get("vuln") in _AUTH_SENSITIVE:
                sev = "Info"
            findings.append({
                "product": ep.get("product"),
                "path": path,
                "vuln": ep.get("vuln"),
                "note": ep.get("note"),
                "status": code,
                "verdict": "reachable",
                "severity": sev,
                "evidence_level": "L2" if sev == "Medium" else "L1",
                "detail": "已知漏洞端点可达（被动 GET %d），需人工确认是否可利用。未发送任何利用 payload。" % code,
            })
        elif code in _EXISTS_DENIED:
            findings.append({
                "product": ep.get("product"),
                "path": path,
                "vuln": ep.get("vuln"),
                "note": ep.get("note"),
                "status": code,
                "verdict": "exists_denied",
                "severity": "Info",
                "evidence_level": "L1",
                "detail": "端点存在但被拒绝/受限（被动 GET %d）。" % code,
            })
        # 404 / 其他 → 视为不存在，不产出
    return findings


if __name__ == "__main__":
    # 离线自测
    cms = ["用友NC", "泛微 OA"]
    print("resolve ->", resolve_products(cms))
    print("endpoints ->", [e["path"] for e in lookup_endpoints(resolve_products(cms))])
