"""PenScope —— 开放重定向（Open Redirect，CWE-601）只读检测模块。

贯彻"降低误报、保守分级"原则：仅向 URL 参数 / 表单字段注入重定向 sink 载荷，
观察服务端是否返回 3xx 且 Location 指向**站外主机**（含协议相对 `//evil` 与外显
`https://evil`）。命中即报"潜在开放重定向"（中危 / 待确认 / L2，unverified）。

关键保守点（防误报）：
  - 只认"Location 主机 ≠ 原主机"的外部跳转；同源跳转（`/dashboard`、同域绝对路径）
    一律排除，避免把正常业务跳转误报。
  - 不跟随重定向、不向 evil 域名发起任何实际请求（仅读取 Location 头），纯只读、零外联。
  - 重定向 sink 参数名（redirect/url/next…）额外给一条低危 L1"潜在注入点"被动观察，
    与既有 SSRF / 缺失授权被动观察同风格。

为何不夸大：开放重定向单独危害有限（多被用于钓鱼前置），故判中危 L2 而非高危；
真正利用需结合其他环节，故 verification_status=unverified。
"""
import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

import requests
from scanner.web_scan import discover, _mk
from cvss_dedup import cwe_for

_UA = "PenScope/1.0 (authorized security test)"

# 重定向 sink 参数/字段名（用于被动观察 + 优先注入）
_REDIRECT_PARAM_RE = re.compile(
    r"(?i)\b(redirect|redir|url|link|next|return|returnurl|return_url|ret|to|"
    r"target|goto|forward|continue|callback|dest|destination|back|logout|site|"
    r"rurl|redirecturl|redirect_url|goto_url|jump|navto)\b"
)

# 注入载荷：覆盖外显 scheme 与协议相对两种常见开放重定向形态
_PAYLOADS = [
    "https://evil.example.com/",
    "//evil.example.com/",
]


def _norm_host(netloc):
    """去掉 userinfo 与端口，得到用于比较的主机名。"""
    host = netloc.lower().split("@")[-1]
    return host.split(":")[0]


def _is_external_redirect(resp, orig_host_norm, orig_scheme):
    """resp 是否为指向站外主机的重定向。站外 = Location 主机 ≠ 原主机。"""
    if resp.status_code not in (301, 302, 303, 307, 308):
        return False
    loc = (resp.headers.get("Location") or "").strip()
    if not loc:
        return False
    # 以原 scheme 补全协议相对 / 相对路径，得到绝对 URL
    abs_url = urlparse(loc, scheme=orig_scheme)
    netloc = abs_url.netloc
    if not netloc:
        return False  # 相对路径（同源），非开放重定向
    return _norm_host(netloc) != orig_host_norm


def _set_query_param(url, param, value):
    p = urlparse(url)
    q = parse_qs(p.query)
    q[param] = [value]
    new_q = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))


def _post_form_no_redirect(session, action, method, fields, inject_field, value,
                           timeout, verify_ssl):
    data = {n: value if n == inject_field else "1" for n in fields}
    if method == "post":
        return session.post(action, data=data, timeout=timeout,
                             verify=verify_ssl, allow_redirects=False)
    return session.get(action, params=data, timeout=timeout,
                       verify=verify_ssl, allow_redirects=False)


def scan_open_redirect(url, session, timeout=6.0, verify_ssl=True):
    """开放重定向只读检测：URL 参数 + 表单字段注入，观察是否 3xx 跳站外。"""
    findings = []
    parsed = urlparse(url)
    orig_host_norm = _norm_host(parsed.netloc)
    orig_scheme = parsed.scheme or "http"

    seen_strong = set()      # (endpoint) 去重强证据
    seen_passive = set()     # (param/field 名) 去重被动观察

    def _emit_passive(name, endpoint):
        if name in seen_passive:
            return
        seen_passive.add(name)
        findings.append(_mk(
            "开放重定向", f"参数 '{name}' 疑似重定向 sink（潜在开放重定向注入点）", "Low",
            f"参数 {name}（端点 {endpoint}）名称疑似控制跳转目标（redirect/url/next 等），"
            f"存在开放重定向（CWE-601）风险，需人工注入外部地址验证是否真跳站外。",
            f"param={name}",
            "对重定向目标做白名单校验（仅允许站内相对路径或已知安全主机）；"
            "不要在重定向前信任用户输入；对外部跳转加风险提示页。",
            endpoint,
            cwe=cwe_for("开放重定向"), endpoint=endpoint, http_method="GET",
            verification_status="unverified", evidence_level="L1",
            poc=f"注入 {name}=https://evil.example.com/ 观察是否 3xx 跳站外",
        ))

    # ---- URL 查询参数 ----
    for param in parse_qs(parsed.query).keys():
        if _REDIRECT_PARAM_RE.search(param):
            _emit_passive(param, url)
        for payload in _PAYLOADS:
            target = _set_query_param(url, param, payload)
            try:
                r = session.get(target, timeout=timeout, verify=verify_ssl,
                                allow_redirects=False)
            except requests.RequestException:
                continue
            if _is_external_redirect(r, orig_host_norm, orig_scheme):
                loc = (r.headers.get("Location") or "").strip()
                if (target,) in seen_strong:
                    continue
                seen_strong.add((target,))
                findings.append(_mk(
                    "开放重定向", f"参数 '{param}' 疑似开放重定向（跳转到站外）", "Medium",
                    f"对 {target} 注入重定向载荷，服务端返回 {r.status_code} 且 Location 指向站外"
                    f"主机（{loc}）。可能存在开放重定向（CWE-601），可被用于钓鱼前置。"
                    f"需人工确认该跳转是否完全由用户输入控制且无白名单校验。",
                    f"status={r.status_code} location={loc} payload={payload}",
                    "对重定向目标实施站内白名单校验；禁止直接信任用户输入的跳转地址；"
                    "外部跳转前展示风险提示页；设置 SameSite Cookie 降低被利用面。",
                    target,
                    cwe=cwe_for("开放重定向"), endpoint=target, http_method="GET",
                    verification_status="unverified", evidence_level="L2",
                    poc=f"curl -I '{target}'",
                ))

    # ---- 表单字段 ----
    try:
        forms = discover(url, session, timeout, verify_ssl)
    except requests.RequestException:
        forms = []
    for f in forms:
        action = f.get("action") or url
        method = (f.get("method") or "get").lower()
        fields = f.get("fields", [])
        if not fields:
            continue
        ap = urlparse(action)
        ap_host_norm = _norm_host(ap.netloc) if ap.netloc else orig_host_norm
        for field in fields:
            if _REDIRECT_PARAM_RE.search(field):
                _emit_passive(field, action)
            for payload in _PAYLOADS:
                try:
                    r = _post_form_no_redirect(session, action, method, fields,
                                               field, payload, timeout, verify_ssl)
                except requests.RequestException:
                    continue
                if _is_external_redirect(r, ap_host_norm, ap.scheme or orig_scheme):
                    loc = (r.headers.get("Location") or "").strip()
                    if (action, field) in seen_strong:
                        continue
                    seen_strong.add((action, field))
                    findings.append(_mk(
                        "开放重定向",
                        f"表单字段 '{field}' 疑似开放重定向（跳转到站外）", "Medium",
                        f"对表单（action={action}，方法 {method.upper()}）字段 {field} 注入重定向载荷，"
                        f"服务端返回 {r.status_code} 且 Location 指向站外主机（{loc}）。"
                        f"可能存在开放重定向（CWE-601）。需人工确认。",
                        f"status={r.status_code} location={loc} field={field} payload={payload}",
                        "对重定向目标实施站内白名单校验；外部跳转前展示风险提示页。",
                        action,
                        cwe=cwe_for("开放重定向"), endpoint=action,
                        http_method=method.upper(),
                        verification_status="unverified", evidence_level="L2",
                        poc=f"提交时令 {field}={payload} 观察响应 Location",
                    ))
    return findings
