"""PenScope —— 认证缺陷（CWE-287）检测模块。

默认被动（全 L1 观察），主动默认凭据探测为 opt-in（默认关）：

  - 被动：① 识别登录端点（含 password 字段的表单）；② 检测凭证出现在 URL query
    （user=/pass=/token= 等，CWE-287 相关 + 信息泄露）；③ 检测明文 HTTP 传输认证
    （表单 action 为 http 且含 password 字段）；④ 检测 Basic/Digest Auth 走非 HTTPS。
  - 主动（enable_auth_probe=True，需用户显式开启）：对登录端点用常见默认凭据做只读
    登录尝试；成功登录 → 中/高危（CWE-287 弱默认凭据）/ L2–L3，unverified。

为何默认关：登录尝试属半攻击行为，易触发账号锁定 / 被判定爆破。遵循本工具
"默认只读、不爆破、不写"原则，把主动动作交给用户明确授权（config.ENABLE_AUTH_PROBE）。
"""
import re
from urllib.parse import parse_qs, urlparse

import requests

from cvss_dedup import cwe_for
from scanner.cred_dict import load_default_creds
from scanner.web_scan import _mk, discover

_UA = "PenScope/1.0 (authorized security test)"

# 常见默认凭据（仅用于 opt-in 主动探测，命中即报告为弱默认凭据）。不穷举、不爆破。
# 字典已外置到 config/dicts/default_creds.txt（见 C-05），由 scanner.cred_dict 加载，
# 支持用户自定义字典路径（config.AUTH_PROBE_DICT_PATH / 环境变量 / 设置项 auth_probe_dict）。

# URL query 中疑似携带凭据/会话的参数名
_CRED_PARAM_RE = re.compile(
    r"(?i)\b(user|username|uname|login|uid|userid|pass|password|pwd|token|"
    r"apikey|api_key|secret|auth|sessionid|session|ticket|key)\b"
)

# 登录失败信号（用于主动探测判定"未成功"）
_FAIL_HINTS = ("incorrect", "invalid", "failed", "失败", "错误", "denied",
               "wrong", "mismatch", "no such", "invalid username", "login failed")

# 隐藏字段名（CSRF token 等）正则，用于主动探测时提取并回填真实值
_TOKEN_NAME_RE = re.compile(r"(?i)(token|csrf|_token|xsrf|authenticity|nonce|secret|sig)")


def _extract_hidden_fields(html):
    """从登录页 HTML 提取所有 type=hidden 输入框的 name->value，用于 CSRF 感知回填。

    正则强化（防漏提 CSRF token）：
      - re.DOTALL 容许属性串跨行（`<input\\n type="hidden" ...>`）；
      - name/value 引号放宽为可选，覆盖无引号属性（`name=csrf value=abc`）；
      - 显式校验 type 为 hidden 才收，避免误收普通文本框。
    """
    out = {}
    if not html:
        return out
    for m in re.finditer(r"<input\b([^>]*)>", html, re.IGNORECASE | re.DOTALL):
        attrs = m.group(1)
        if not re.search(r"type=['\"]?hidden['\"]?", attrs, re.IGNORECASE):
            continue
        nm = re.search(r"name=['\"]?([^'\"\s>]+)", attrs, re.IGNORECASE)
        if not nm:
            continue
        vl = re.search(r"value=['\"]?([^'\"]*)['\"]?", attrs, re.DOTALL)
        out[nm.group(1)] = vl.group(1) if vl else ""
    return out


def _is_http(url):
    return urlparse(url).scheme.lower() == "http"


def _form_has_password(f):
    return any(re.search(r"(?i)(pass|pwd)", n) for n in f.get("fields", []))


def scan_auth(url, session, timeout=6.0, verify_ssl=True, enable_auth_probe=False,
              cred_dict_path=None):
    """认证缺陷检测：被动观察（默认）+ 受开关控制的主动默认凭据探测。

    cred_dict_path：可选，自定义默认凭据字典文件路径（用户导入）；为空则按
    scanner.cred_dict.load_default_creds 的优先级（env / config / 内置 / 内嵌）解析。
    """
    findings = []
    parsed = urlparse(url)

    # ---- 被动 ①：识别登录端点（含密码字段的表单）----
    try:
        forms = discover(url, session, timeout, verify_ssl)
    except requests.RequestException:
        forms = []
    login_forms = [f for f in forms if _form_has_password(f)]
    login_seen = set()
    for f in login_forms:
        action = f["action"]
        if action in login_seen:
            continue
        login_seen.add(action)
        findings.append(_mk(
            "认证缺陷", f"发现疑似登录端点: {action}", "Low",
            f"页面 {url} 含密码输入框的表单（action={action}，方法 {f['method'].upper()}），"
            f"为候选登录入口。建议人工评估其认证强度与防爆破机制。",
            f"method={f['method'].upper()} fields={f['fields']}",
            "启用强密码策略与多因素认证（MFA）；实施登录失败锁定与速率限制，防止爆破。",
            action,
            cwe=cwe_for("认证缺陷"), endpoint=action, http_method=f["method"].upper(),
            verification_status="unverified", evidence_level="L1",
            poc=f"POST {action} 提交凭据",
        ))
        # 被动 ③：明文 HTTP 传输认证
        if _is_http(action):
            findings.append(_mk(
                "认证缺陷", f"登录端点以明文 HTTP 传输凭据: {action}", "Low",
                f"登录表单 action（{action}）使用 http 而非 https，凭据将以明文在网络中传输，"
                f"存在被中间人窃听风险（CWE-287 相关）。",
                f"scheme=http method={f['method'].upper()}",
                "强制全站 HTTPS（HSTS），登录与所有认证请求仅经 TLS 传输；禁用明文 HTTP 表单提交。",
                action,
                cwe=cwe_for("认证缺陷"), endpoint=action, http_method=f["method"].upper(),
                verification_status="unverified", evidence_level="L1",
                poc=f"观察 {action} 是否为 http://",
            ))

    # ---- 被动 ②：凭证出现在 URL query ----
    cred_in_url = [k for k in parse_qs(parsed.query).keys() if _CRED_PARAM_RE.search(k)]
    if cred_in_url:
        findings.append(_mk(
            "认证缺陷", f"URL 中疑似携带凭据/会话参数: {', '.join(cred_in_url)}", "Low",
            f"URL {url} 的查询字符串中包含疑似凭据/会话参数（{', '.join(cred_in_url)}），"
            f"凭据出现在 URL 中易被浏览器历史、代理日志、Referer 头记录而泄露（CWE-287 相关 + 信息泄露）。",
            f"params={cred_in_url}",
            "不要在 URL 中传递密码/令牌；改用 POST body 或 Authorization 头；"
            "对会话 ID 设置 HttpOnly + Secure 属性。",
            url,
            cwe=cwe_for("认证缺陷"), endpoint=url, http_method="GET",
            verification_status="unverified", evidence_level="L1",
            poc=f"检查 URL query 是否含 {cred_in_url}",
        ))

    # ---- 被动 ④：Basic/Digest Auth 走非 HTTPS ----
    try:
        r = session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
        if r.status_code == 401 and "WWW-Authenticate" in r.headers:
            scheme = (r.headers.get("WWW-Authenticate") or "").split()[0].lower()
            if _is_http(url):
                findings.append(_mk(
                    "认证缺陷", f"Basic/Digest 认证经明文 HTTP 传输（{scheme}）", "Low",
                    f"端点 {url} 以 HTTP（非 TLS）发起 {scheme} 认证，凭据将以明文或弱散列传输，"
                    f"易被窃听（CWE-287 相关）。",
                    f"auth_scheme={scheme} scheme=http",
                    "对涉及身份认证的端点强制 HTTPS；避免在明文通道上使用 Basic/Digest 认证。",
                    url,
                    cwe=cwe_for("认证缺陷"), endpoint=url, http_method="GET",
                    verification_status="unverified", evidence_level="L1",
                    poc=f"观察 {url} 是否 http:// 且返回 401 WWW-Authenticate",
                ))
    except requests.RequestException:
        pass

    # ---- 主动：默认凭据探测（opt-in）----
    if enable_auth_probe:
        creds = load_default_creds(cred_dict_path)
        for f in login_forms:
            action = f["action"]
            fields = f["fields"]
            user_field = next((n for n in fields if re.search(r"(?i)(user|uname|login|email|account)", n)), None)
            pass_field = next((n for n in fields if re.search(r"(?i)(pass|pwd)", n)), None)
            if not user_field or not pass_field:
                continue
            hit = _try_default_creds(session, action, f["method"], fields,
                                     user_field, pass_field, timeout, verify_ssl, creds=creds)
            if hit:
                findings.append(_mk(
                    "认证缺陷", f"登录端点存在可用默认/弱凭据: {action} ({hit[0]}/{hit[1]})", "High",
                    f"对登录端点 {action}（方法 {f['method'].upper()}）用常见默认凭据尝试，"
                    f"凭据 {hit[0]}/{hit[1]} 疑似登录成功（响应不再含登录表单且无失败提示）。"
                    f"存在弱默认凭据（CWE-287），需人工确认并立即整改。",
                    f"user_field={user_field} pass_field={pass_field} cred={hit[0]}/{hit[1]}",
                    "强制在部署/初始化阶段修改所有默认凭据；启用强密码策略与 MFA；"
                    "实施登录失败锁定与速率限制，防止爆破。",
                    action,
                    cwe=cwe_for("认证缺陷"), endpoint=action, http_method=f["method"].upper(),
                    verification_status="unverified", evidence_level="L3",
                    poc=f"curl -X POST '{action}' --data '{user_field}={hit[0]}&{pass_field}={hit[1]}'",
                ))
                break  # 每个登录端点只报一次
    return findings


def _try_default_creds(session, action, method, fields, user_field, pass_field, timeout, verify_ssl, creds=None):
    """对登录端点逐一尝试默认凭据。成功判定为启发式（保守）：响应不含密码输入框、
    无失败提示、且发生了跳转或命中 logout/welcome/dashboard 标记。返回 (user, pass) 或 None。

    creds：[(user, pass), ...]，由调用方经 load_default_creds 解析（已外置，见 C-05）。
    """
    creds = creds if creds is not None else load_default_creds()
    for username, password in creds:
        try:
            data = {n: "1" for n in fields if n not in (user_field, pass_field)}
            data[user_field] = username
            data[pass_field] = password
            # CSRF 感知：抓取登录页，回填真实隐藏字段（尤其 token），覆盖 DVWA 等带
            # CSRF 校验的目标；无 token 的端点不受影响（隐藏字段为空，行为不变）。
            try:
                lp = session.get(action, timeout=timeout, verify=verify_ssl, allow_redirects=False)
                for k, v in _extract_hidden_fields(lp.text or "").items():
                    if k not in (user_field, pass_field):
                        data[k] = v
            except requests.RequestException:
                pass
            if method == "post":
                r = session.post(action, data=data, timeout=timeout, verify=verify_ssl, allow_redirects=True)
            else:
                r = session.get(action, params=data, timeout=timeout, verify=verify_ssl, allow_redirects=True)
        except requests.RequestException:
            continue
        text = (r.text or "").lower()
        fail = any(s in text for s in _FAIL_HINTS)
        still_login = 'type="password"' in text or "type=password" in text
        if fail or still_login:
            continue
        moved = (r.url or "").rstrip("/") != action.rstrip("/")
        if moved or any(m in text for m in ("logout", "welcome", "dashboard", "控制台", "管理后台")):
            return (username, password)
    return None
