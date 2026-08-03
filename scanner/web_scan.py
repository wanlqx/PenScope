"""PenScope —— Web 漏洞检测模块
覆盖：SQL 注入（错误型 + 布尔盲注 + 时间盲注）、反射型 XSS、CSRF 防护缺失、文件上传点发现。
所有检测均为"只读探测"，不写入/不破坏目标；文件上传的实际测试由人工闸门控制。

每个发现除风险等级外，还附带：CWE 编号、结构化位置（endpoint/method）、
验证状态（verified/unverified/info）、证据等级（L1-L4）与 PoC 片段，
供报告生成与语义去重使用（借鉴 VulnClaw 的结构化发现模型）。
"""
import re
import requests
from scanner.payloads import PayloadGenerator, detect_waf, detect_db_from_error
from scanner.scope import redirect_target_blocked
from cvss_dedup import cwe_for


# 布尔盲注多轮采样参数（误报率降低：要求多轮稳定差异才判定，消除动态内容干扰）
_SQLI_BOOL_TRUE = "' AND 1=1-- "
_SQLI_BOOL_FALSE = "' AND 1=2-- "
_BOOL_ROUNDS = 3
_BOOL_REL_DIFF = 0.15  # 基线归一化后的相对长度差异阈值


def _get_inputs(html, base_url):
    """解析 HTML 表单，提取 (action, method, 字段名列表, 文件字段, 是否含文件上传)。"""
    forms = []
    # 同时捕获开标签属性与内部内容，action 位于开标签中
    for tag_attrs, inner in re.findall(r"<form\s+([^>]*)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
        action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', tag_attrs, re.IGNORECASE)
        method = re.search(r'method\s*=\s*["\']([^"\']*)["\']', tag_attrs, re.IGNORECASE)
        names = re.findall(r'name\s*=\s*["\']([^"\']*)["\']', inner, re.IGNORECASE)
        # 识别文件上传字段名（兼容 name 在 type 前/后两种写法）
        file_fields = set(re.findall(
            r'type\s*=\s*["\']file["\'][^>]*?name\s*=\s*["\']([^"\']*)["\']', inner, re.IGNORECASE))
        file_fields |= set(re.findall(
            r'name\s*=\s*["\']([^"\']*)["\'][^>]*?type\s*=\s*["\']file["\']', inner, re.IGNORECASE))
        has_file = bool(file_fields)
        a = action.group(1) if action else ""
        if a and not a.startswith("http"):
            from urllib.parse import urljoin
            a = urljoin(base_url, a)
        elif not a:
            a = base_url
        forms.append({
            "action": a,
            "method": (method.group(1) if method else "get").lower(),
            "fields": [n for n in names if n],
            "file_fields": list(file_fields),
            "has_file": has_file,
        })
    return forms


def _send_form(session, target, method, fields, inject_field, value, timeout, verify_ssl=True):
    """按表单声明的字段集提交：除注入字段外，其余字段给良性占位值（如 '1'），
    以触发目标真实的表单处理分支（许多应用用 isset($_POST['submit']) 判断是否执行查询）。"""
    data = {}
    for n in fields:
        data[n] = value if n == inject_field else "1"
    if method == "post":
        return session.post(target, data=data, timeout=timeout, verify=verify_ssl)
    return session.get(target, params=data, timeout=timeout, verify=verify_ssl)


def _fetch_html(session, url, timeout=6.0, verify_ssl=True):
    """抓取页面 HTML（用于 CSRF 自定义 Header 防护信号识别）。失败时返回空串。"""
    try:
        r = session.get(url, timeout=timeout, verify=verify_ssl)
        if "text/html" in r.headers.get("Content-Type", ""):
            return r.text or ""
    except requests.RequestException:
        pass
    return ""


def discover(url, session, timeout=6.0, verify_ssl=True):
    """发现页面表单与参数，返回表单列表。"""
    try:
        r = session.get(url, timeout=timeout, verify=verify_ssl)
    except requests.RequestException:
        return []
    return _get_inputs(r.text, url)


def collect_pages(start_url, session, max_pages=30, timeout=6.0, verify_ssl=True):
    """有界同主机爬虫：从起始 URL 出发，仅跟随同主机链接，收集可达的 HTML 页面。

    用于让 Web 检测覆盖目标的多个页面（例如漏洞靶场中分散在各路径的漏洞模块），
    而不是只扫描首页。默认上限 30 页，避免无限爬取；仅抓取 text/html，跳过锚点/
    javascript/mailto/data 等伪链接，且不离开目标主机。

    作用域围栏（AP-001）：不再使用 allow_redirects=True 透明跟随重定向，而是手动
    逐跳跟随，对每一跳的 Location 复检——必须停留同一主机名、且解析到的 IP 不属于
    私有/回环/链路本地/保留/未指定网段；任一跳越界则丢弃该分支，防止恶意目标借工具
    之手探测内网 / 云元数据（SSRF / CWE-918）。
    """
    from urllib.parse import urljoin, urlparse
    try:
        base_netloc = urlparse(start_url).netloc
    except Exception:
        return [start_url]
    base_host = base_netloc.split(":")[0]
    visited = set()
    to_visit = [start_url]
    pages = []
    while to_visit and len(pages) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            r = _safe_follow(session, url, timeout, verify_ssl, base_host)
        except requests.RequestException:
            continue
        if r is None:
            continue
        if r.status_code != 200 or "text/html" not in r.headers.get("Content-Type", ""):
            continue
        # 最终 URL 也必须停留同主机（重定向目的越界已在 _safe_follow 内被丢弃）
        if urlparse(r.url).netloc.split(":")[0] != base_host:
            continue
        pages.append(r.url)
        for href in re.findall(r'href\s*=\s*["\']([^"\']+)["\']', r.text, re.IGNORECASE):
            if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue
            absu = urljoin(r.url, href)
            pu = urlparse(absu)
            if pu.netloc != base_netloc:
                continue
            clean = absu.split("#")[0]
            if clean and clean not in visited and clean not in to_visit:
                to_visit.append(clean)
    return pages


def _safe_follow(session, url, timeout, verify_ssl, base_host, max_hops=5):
    """发起请求并手动跟随同主机重定向；任一跳跨主机或解析到被拦截网段则停止，返回最终响应或 None。"""
    from urllib.parse import urljoin, urlparse
    r = session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
    hops = 0
    while r.status_code in (301, 302, 303, 307, 308) and "Location" in r.headers and hops < max_hops:
        loc = r.headers["Location"]
        next_url = urljoin(r.url, loc)
        nu = urlparse(next_url)
        nh = nu.netloc.split(":")[0]
        # 作用域校验：仅跟随与起始目标同作用域的重定向（SSRF 围栏，AP-001）
        if redirect_target_blocked(nu.netloc, base_host):
            return None
        r = session.get(next_url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
        hops += 1
    return r


def _sql_poc(target, method, field, payload):
    """生成 SQL 注入的可复现 curl 命令（示意，含触发字段占位）。"""
    if method == "post":
        return f"curl -X POST '{target}' --data '{field}={payload}&submit=1'"
    return f"curl '{target}?{field}={payload}'"


def scan_sqli(url, session, pg, timeout=6.0, verify_ssl=True):
    """SQL 注入检测：错误型 + 布尔盲注 + 时间盲注二次验证。按表单声明的 GET/POST 方法提交（含全部字段）。"""
    from urllib.parse import urlparse, urlunparse, parse_qs
    findings = []
    forms = discover(url, session, timeout, verify_ssl)
    test_points = []  # (target, method, param, all_fields)
    for f in forms:
        inj_fields = [n for n in f["fields"] if n not in f["file_fields"]]
        for field in inj_fields:
            test_points.append((f["action"], f["method"], field, f["fields"]))
    # URL 查询参数（去除已有 query 避免重复参数导致注入值被忽略）
    q = urlparse(url)
    base = urlunparse(q._replace(query="", fragment=""))
    for k in parse_qs(q.query).keys():
        test_points.append((base, "get", k, [k]))
    if not test_points:
        return findings

    seen = set()
    for target, method, p, fields in test_points:
        if (target, method, p) in seen:
            continue
        seen.add((target, method, p))
        # 1) 错误型：发送单引号，看是否触发数据库报错（属强证据，标记 verified）
        try:
            r = _send_form(session, target, method, fields, p, "'", timeout, verify_ssl)
            db_name = detect_db_from_error(r.text)
            if db_name:
                findings.append(_mk(
                    "SQL注入", f"参数 '{p}' 存在错误型 SQL 注入（疑似 {db_name}）", "High",
                    f"向参数 {p}（端点 {target}，方法 {method.upper()}）注入单引号后，响应中出现 {db_name} 数据库报错特征。",
                    r.text[:160].replace("\n", " "),
                    "使用参数化查询/预编译语句，杜绝字符串拼接 SQL；对输入做白名单校验。",
                    target,
                    cwe=cwe_for("SQL注入"), endpoint=target, http_method=method.upper(),
                    verification_status="verified", evidence_level="L3",
                    poc=_sql_poc(target, method, p, "%27"),
                    resp=r, payload="'",
                ))
                continue
        except requests.RequestException:
            pass
        # 2) 布尔盲注：多轮采样 + 基线归一化，仅在"多轮稳定差异"时判定，避免动态内容干扰误报
        #    （改进方案 §2 误报率降低：单轮/不稳定差异不再判定为漏洞）
        try:
            true_lens, false_lens = [], []
            stable = True
            saw_diff = False
            for _ in range(_BOOL_ROUNDS):
                rt = _send_form(session, target, method, fields, p, _SQLI_BOOL_TRUE, timeout, verify_ssl)
                rf = _send_form(session, target, method, fields, p, _SQLI_BOOL_FALSE, timeout, verify_ssl)
                if rt.status_code != rf.status_code:
                    stable = False
                    break
                # 基线归一化：以较长响应为基准，看条件真假导致的相对长度差异（消除动态内容绝对值干扰）
                base = max(len(rt.text), len(rf.text), 1)
                rel = (len(rt.text) - len(rf.text)) / base
                true_lens.append(len(rt.text))
                false_lens.append(len(rf.text))
                if len(rt.text) > len(rf.text) and abs(rel) > _BOOL_REL_DIFF:
                    saw_diff = True
                else:
                    stable = False
            if saw_diff and stable:
                diff = abs(true_lens[0] - false_lens[0])
                b = _verify_sqli_time(session, target, method, fields, p, verify_ssl)
                if b:
                    findings.append(_mk(
                        "SQL注入", f"参数 '{p}' 存在时间盲注", "High",
                        f"注入 SLEEP/延迟载荷后响应明显延迟，确认该参数存在 SQL 注入（时间盲注）。",
                        f"time-based delay verified; baseline={b}",
                        "使用参数化查询/预编译语句；对数据库账户最小权限化；部署 WAF 与输入校验。",
                        target,
                        cwe=cwe_for("SQL注入"), endpoint=target, http_method=method.upper(),
                        verification_status="verified", evidence_level="L4",
                        poc=_sql_poc(target, method, p, "1%20AND%20(SELECT%20SLEEP(2)%20FROM%20dual)--%20-"),
                    ))
                else:
                    findings.append(_mk(
                        "SQL注入", f"参数 '{p}' 疑似存在布尔盲注（多轮稳定差异）", "Medium",
                        f"连续 {_BOOL_ROUNDS} 轮注入恒真/恒假条件，响应长度均稳定差异"
                        f"（基准 {true_lens[0]} vs {false_lens[0]} 字节），可能存在注入；"
                        f"建议进一步人工确认或时间盲注验证。",
                        f"true_len={true_lens[0]} false_len={false_lens[0]} rounds={_BOOL_ROUNDS}",
                        "使用参数化查询；对布尔条件做统一错误处理，避免响应差异泄露。",
                        target,
                        cwe=cwe_for("SQL注入"), endpoint=target, http_method=method.upper(),
                        verification_status="unverified", evidence_level="L2",
                        poc=_sql_poc(target, method, p, "%27%20AND%201=1--%20-"),
                    ))
            # saw_diff 但 unstable => 动态内容干扰，按改进方案不判定（不再产生误报）
        except requests.RequestException:
            pass
    return findings


def _verify_sqli_time(session, target, method, fields, p, verify_ssl, delay=2.0):
    """对指定参数发送 MySQL/PostgreSQL 通用 SLEEP 载荷，若响应延迟**显著高于良性基线分布**
    则视为验证通过（C-02 基线建模：用 5 次良性响应统计分布 + 3σ 抖动吸收替代单点基线，
    显著降低时间盲注误报）。

    返回：验证通过时返回基线摘要 dict（truthy，供证据记录）；否则返回 False。
    """
    import time as _time
    from scanner.baseline import sample_times, is_significant_delay, baseline_digest

    payloads = [
        f"1 AND (SELECT SLEEP({int(delay)}) FROM dual)-- ",
        f"' AND (SELECT SLEEP({int(delay)}) FROM dual)-- ",
        f"' OR (SELECT SLEEP({int(delay)}) FROM dual)-- ",
    ]

    def _benign():
        t0 = _time.time()
        try:
            _send_form(session, target, method, fields, p, "1", 6, verify_ssl)
        except Exception:
            pass
        return _time.time() - t0

    baseline_times = sample_times(_benign, n=5)
    for payload in payloads:
        try:
            t0 = _time.time()
            _send_form(session, target, method, fields, p, payload, 6, verify_ssl)
            dt = _time.time() - t0
        except requests.exceptions.ReadTimeout:
            dt = _time.time() - t0
        except requests.RequestException:
            continue
        if is_significant_delay(dt, baseline_times, delay):
            return baseline_digest(baseline_times)
    return False


def scan_xss(url, session, pg, timeout=6.0, verify_ssl=True):
    """反射型 XSS 检测：先发送唯一标记确认反射点，再验证 payload 是否在可执行上下文中回显，减少误报。"""
    from urllib.parse import urlparse, urlunparse, parse_qs
    findings = []
    forms = discover(url, session, timeout, verify_ssl)
    test_points = []
    for f in forms:
        inj_fields = [n for n in f["fields"] if n not in f["file_fields"]]
        for field in inj_fields:
            test_points.append((f["action"], f["method"], field, f["fields"]))
    q = urlparse(url)
    base = urlunparse(q._replace(query="", fragment=""))
    for k in parse_qs(q.query).keys():
        test_points.append((base, "get", k, [k]))
    if not test_points:
        return findings

    markers = pg.xss_payloads()
    seen = set()
    for target, method, p, fields in test_points:
        if (target, method, p) in seen:
            continue
        seen.add((target, method, p))
        for marker in markers[:3]:
            verified = _verify_xss_reflection(session, target, method, fields, p, marker, timeout, verify_ssl)
            if verified:
                context, evidence, resp = verified
                findings.append(_mk(
                    "XSS", f"参数 '{p}' 存在反射型 XSS（{context}）", "High",
                    f"向参数 {p}（端点 {target}，方法 {method.upper()}）注入 XSS 载荷后，在可执行上下文（{context}）中未经转义回显。",
                    evidence,
                    "对所有输出做 HTML 实体转义（如 Jinja 默认自动转义）；启用 CSP（Content-Security-Policy）；对输入做白名单校验。",
                    target,
                    cwe=cwe_for("XSS"), endpoint=target, http_method=method.upper(),
                    verification_status="verified", evidence_level="L4",
                    poc=marker, resp=resp, payload=marker,
                ))
                break
    return findings


def _verify_xss_reflection(session, target, method, fields, p, payload, timeout, verify_ssl):
    """XSS 验证：1) 发送唯一标记确认参数确实被回显；2) 确认 payload 在 script/on-event/svg 等可执行上下文回显。
    返回 (context_description, evidence, response) 或 None（response 用于 I-05 抓包）。"""
    import uuid
    probe = "apxss_" + uuid.uuid4().hex[:8]
    try:
        r_probe = _send_form(session, target, method, fields, p, probe, timeout, verify_ssl)
        if probe not in r_probe.text:
            return None
    except requests.RequestException:
        return None
    try:
        r = _send_form(session, target, method, fields, p, payload, timeout, verify_ssl)
        text = r.text
        if payload not in text:
            return None
        # 检查是否在危险上下文中回显
        if re.search(r"<script[^>]*>[\s\S]*?" + re.escape(payload) + r"[\s\S]*?</script>", text, re.IGNORECASE):
            return ("script 标签内", payload, r)
        if re.search(r"\s(on\w+)\s*=\s*['\"]?[^'\"]*" + re.escape(payload), text, re.IGNORECASE):
            return ("HTML 事件处理器", payload, r)
        if re.search(r"<svg[^>]*onload\s*=\s*['\"]?[^'\"]*" + re.escape(payload), text, re.IGNORECASE):
            return ("SVG onload 事件", payload, r)
        # 原始 payload 包含 <script> 且未被转义成 &lt;script&gt;
        raw = payload.replace("&lt;", "").replace("&gt;", "")
        if raw in text and "&lt;" + raw.split("<")[1] if "<" in raw else False:
            pass
        if "<script>" in payload and "<script>" in text:
            return ("HTML 标签内（未转义）", payload, r)
        return None
    except requests.RequestException:
        return None


def _csrf_poc(action, fields):
    """生成 CSRF 概念验证 HTML（自动提交表单，仅用于说明风险，不实际发动攻击）。"""
    inputs = "\n".join(
        f'  <input type="hidden" name="{n}" value="attacker_value">' for n in fields if n != "submit"
    )
    return (
        f'<form action="{action}" method="POST" id="f">\n{inputs}\n'
        '  <script>document.getElementById("f").submit();</script>\n</form>'
    )


# 自定义 Header / 同源校验 / 双提交 Cookie 等"无显式 token 字段"防护的信号
_CSRF_HEADER_RE = re.compile(
    r"x-requested-with|x-csrf-token|x-xsrf-token|csrf-token|csrfheader|"
    r"anticsrf|double[- ]?submit|setrequestheader|xmlhttprequest",
    re.IGNORECASE)


def _csrf_header_protected(page_html):
    """页面 JS / meta 中是否暗示采用自定义 Header / 同源校验等防护（无显式 token 字段）。"""
    return bool(page_html) and bool(_CSRF_HEADER_RE.search(page_html))


def _server_rejects_csrf(session, f, timeout, verify_ssl):
    """提交一次不含 token 的良性 POST，看服务端是否拒绝（4xx / 明显拒绝文案）。
    返回 True=服务端存在校验；False=未拒绝；None=无法判定。"""
    try:
        r = _send_form(session, f["action"], "post", f["fields"], None, "1", timeout, verify_ssl)
    except requests.RequestException:
        return None
    if r.status_code >= 400:
        return True
    txt = (r.text or "").lower()
    if re.search(r"csrf|invalid.{0,12}token|missing.{0,12}token|forbidden|403|"
                r"校验失败|非法请求|token.{0,12}required|access.{0,12}denied", txt):
        return True
    return False


def scan_csrf(url, session, timeout=6.0, verify_ssl=True):
    """CSRF 防护检测（改进方案 §2 误报率降低）：仅对"状态变更 + 无任一防护"的表单报 Medium，
    其余降级为 Info 观察项，避免把"受 SameSite/自定义 Header/服务端校验保护"的表单误报为漏洞。

    判定链：
      1) 表单含 token 字段 -> 视为已防护，跳过；
      2) 页面暗示自定义 Header / 同源校验防护 -> 降级 Info；
      3) 不含 token 且提交良性 POST 被服务端拒绝 -> 服务端校验存在，降级 Info；
      4) 以上皆无且服务端接受 -> 真实风险，报 Medium。
    """
    findings = []
    forms = discover(url, session, timeout, verify_ssl)
    page_html = _fetch_html(session, url, timeout, verify_ssl)
    for f in forms:
        if f["method"] != "post":
            continue
        # 跳过明显无状态变更的表单（搜索框）
        if _is_search_only_form(f):
            continue
        token_present = any(
            re.search(r"csrf|token|_token|authenticity", n, re.IGNORECASE) for n in f["fields"]
        )
        if token_present:
            continue  # 有 token 字段，视为已防护
        # 无显式 token 字段：进一步判断是否存在其它防护
        if _csrf_header_protected(page_html):
            findings.append(_mk(
                "CSRF", f"表单（{f['action']}）未检测到显式 CSRF Token，但疑似采用自定义 Header/同源校验防护",
                "Info",
                "检测到 POST 表单无显式 CSRF Token 字段，但页面 JS/配置暗示使用自定义 Header（如 X-Requested-With）"
                "或同源校验等防护，需人工确认。未直接判定为漏洞。",
                f"method=post fields={f['fields']}",
                "确认现有自定义 Header/同源校验机制覆盖所有状态变更接口；对高敏感操作保留一次性 Token。",
                f["action"],
                cwe=cwe_for("CSRF"), endpoint=f["action"], http_method="POST",
                verification_status="unverified", evidence_level="L1",
                poc=_csrf_poc(f["action"], f["fields"]),
            ))
            continue
        rejected = _server_rejects_csrf(session, f, timeout, verify_ssl)
        if rejected:
            findings.append(_mk(
                "CSRF", f"表单（{f['action']}）无显式 Token，但服务端对无 Token 请求进行了拒绝/校验",
                "Info",
                "提交不含 Token 的良性 POST 被服务端拒绝（4xx 或拒绝文案），说明存在服务端校验，"
                "CSRF 风险较低。未直接判定为漏洞。",
                f"method=post fields={f['fields']}",
                "保持并审计服务端校验逻辑；对高敏感操作可叠加一次性 Token 进一步加固。",
                f["action"],
                cwe=cwe_for("CSRF"), endpoint=f["action"], http_method="POST",
                verification_status="unverified", evidence_level="L1",
                poc=_csrf_poc(f["action"], f["fields"]),
            ))
            continue
        # 无 token + 无 header 信号 + 服务端接受 => 真实风险 Medium
        findings.append(_mk(
            "CSRF", f"表单（{f['action']}）缺少 CSRF 防护", "Medium",
            "检测到 POST 表单未包含 CSRF Token 字段，且提交不含 Token 的良性请求被服务端接受，"
            "存在跨站请求伪造风险（状态变更操作且未校验 Referer/Origin/Token）。",
            f"method=post fields={f['fields']}",
            "为每个状态变更请求引入一次性 CSRF Token，并校验 Referer/Origin 同源；对敏感操作增加二次确认。",
            f["action"],
            cwe=cwe_for("CSRF"), endpoint=f["action"], http_method="POST",
            verification_status="unverified", evidence_level="L2",
            poc=_csrf_poc(f["action"], f["fields"]),
        ))
    return findings


def _is_search_only_form(f):
    """简单启发式：若表单 action/字段名只含 search/query/keyword，且 submit 外无其他数据字段，则视为搜索表单。"""
    action = (f.get("action") or "").lower()
    names = [n.lower() for n in f["fields"]]
    search_terms = ("search", "query", "keyword", "q")
    has_search_keyword = any(t in action for t in search_terms) or any(t in names for t in search_terms)
    non_submit = [n for n in names if n not in ("submit", "search", "query", "keyword", "q")]
    return has_search_keyword and len(non_submit) == 0


def find_upload_forms(url, session, timeout=6.0, verify_ssl=True):
    """发现文件上传表单（仅探测，实际测试需人工授权闸门）。返回上传入口列表。"""
    forms = discover(url, session, timeout, verify_ssl)
    uploads = [f for f in forms if f["has_file"]]
    return uploads


def _mk(category, title, risk, detail, evidence, remediation, ref, **extra):
    """构造一个发现 dict；extra 可携带 cwe / endpoint / http_method / verification_status /
    evidence_level / poc / impact 等结构化字段（供报告与语义去重使用）。

    I-05：若传入 resp（触发该发现的 requests.Response）与 payload（注入载荷），
    则重建请求 / 响应文本并写入 evidence_meta，供前端"请求/响应 Diff"视图使用。
    resp / payload 仅作内部消费，不会作为字段残留在发现 dict 中。
    """
    resp = extra.pop("resp", None)
    payload = extra.pop("payload", None)
    if resp is not None:
        try:
            from scanner.evidence import build_evidence_meta, capture_request, capture_response
            meta = build_evidence_meta(
                payload=payload,
                request=capture_request(resp),
                response=capture_response(resp),
            )
            if meta:
                extra["evidence_meta"] = meta
        except Exception:
            pass
    d = {
        "category": category,
        "title": title,
        "risk": risk,
        "detail": detail,
        "evidence": evidence,
        "remediation": remediation,
        "target_ref": ref,
    }
    d.update(extra)
    return d
