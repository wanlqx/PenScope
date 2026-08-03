"""PenScope —— C-06 可续期认证会话。

用于在「已授权目标」上做需要登录态的扫描时，自动维持/续期认证会话，
避免长扫描中途会话过期，导致后续请求落到登录页、漏检已认证区域（CWE-287 相关）。

核心组件：
  - AuthProfile：目标登录配置（登录端点 / 字段名 / 凭据 / 额外字段 / 续期上限）。
  - SessionRenewal：控制器。先登录一次拿到认证 Cookie（存入共享 CookieJar）；
    之后每次请求若检测到会话失效（重定向到登录页 / 响应含登录表单 / 401 需重登），
    自动用保险库凭据重新登录并重试原请求，最多重登 max_renewals 次，并计数。
  - RenewableSession(requests.Session)：对 requests 的薄封装，透明地做失效检测 + 续期，
    供 run_scans 的逐页扫描器（以及外层 banner/爬取/API 探测）复用同一认证态。

安全约束：凭据由 scanner.vault 加密存储，本模块仅在扫描时由控制器从保险库解密取出，
绝不落日志、绝不外传前端。
"""
import re
from urllib.parse import urlparse

import requests
from requests.cookies import RequestsCookieJar

# 判定为「登录/会话失效页」的信号
_LOGIN_FORM_RE = re.compile(r"type\s*=\s*[\"']?\s*password", re.IGNORECASE)
_LOGOUT_MARKERS = ("登录已过期", "会话已过期", "session expired", "session has expired",
                   "请重新登录", "请先登录", "please log in", "please sign in",
                   "your session", "re-enter your password")
_LOGIN_PATH_RE = re.compile(r"(?i)(login|signin|sign-in|auth|session|reauth|sso)", re.IGNORECASE)


def _login_form_present(resp):
    if resp is None:
        return False
    return bool(_LOGIN_FORM_RE.search(resp.text or ""))


def _login_markers_present(resp):
    if resp is None:
        return False
    low = (resp.text or "").lower()
    return any(m in low for m in _LOGOUT_MARKERS)


def _resp_to_login(resp, url):
    """响应是否把人带到了登录页（重定向到登录路径 + 落地页含登录表单）。"""
    if _login_form_present(resp):
        return True
    # 未跟随重定向时，location 指向登录路径
    loc = (resp.headers.get("Location") or "").lower()
    if resp.status_code in (301, 302, 303, 307, 308) and _LOGIN_PATH_RE.search(loc):
        return True
    return False


class SessionRenewal:
    """会话续期控制器：登录一次 + 按需自动重登。"""

    def __init__(self, profile, verify_ssl=True, max_renewals=None):
        self.profile = profile or {}
        self.verify_ssl = verify_ssl
        self.login_url = (self.profile.get("login_url") or "").strip()
        self.method = (self.profile.get("method") or "post").lower()
        self.user_field = self.profile.get("user_field") or ""
        self.pass_field = self.profile.get("pass_field") or ""
        self.username = self.profile.get("username") or ""
        self.password = self.profile.get("password") or ""
        self.extra_fields = self.profile.get("extra_fields") or []
        self.csrf_autodetect = bool(self.profile.get("csrf_autodetect", True))
        self.max_renewals = int(max_renewals if max_renewals is not None
                                 else (self.profile.get("max_renewals") or 5) or 5)
        self._jar = RequestsCookieJar()
        self.renew_count = 0
        self.last_renew_at = None
        self.authed = False
        self.last_error = None  # 最近一次登录失败原因（网络异常 / 状态码 / 仍停留登录页），供诊断包读取

    # ---------------- 登录 ----------------
    def _login(self):
        """执行一次登录；成功返回 True 并把 Cookie 写入共享 CookieJar。

        关键：登录请求 allow_redirects=False，直接从登录端点（302/200）响应里取
        Set-Cookie 合并进共享 CookieJar；避免跟随重定向时 requests 偶发丢弃中间响应的
        Set-Cookie，导致后续请求拿不到认证态。

        失败可观测性：所有失败路径都写入 self.last_error（不落敏感凭据），
        供诊断包与调用方读取，便于排查"为何会话续期没生效"。"""
        self.last_error = None  # 进入新一轮登录尝试，重置上次失败原因
        if not self.login_url or not self.user_field or not self.pass_field:
            self.last_error = "配置缺失：login_url / user_field / pass_field 未填写"
            return False
        from scanner.auth import _extract_hidden_fields  # 复用隐藏字段提取（CSRF 感知）
        headers = {"User-Agent": "PenScope/1.0 (authorized security test)"}
        try:
            # 抓取登录页，回填隐藏字段（CSRF token 等）
            lp = requests.get(self.login_url, headers=headers, timeout=8,
                              verify=self.verify_ssl, allow_redirects=False)
            hidden = _extract_hidden_fields(lp.text or "") if self.csrf_autodetect else {}
            data = {}
            for name, val in hidden.items():
                if name not in (self.user_field, self.pass_field):
                    data[name] = val
            for name, val in self.extra_fields:
                if name not in (self.user_field, self.pass_field):
                    data[name] = val
            data[self.user_field] = self.username
            data[self.pass_field] = self.password
            if self.method == "get":
                r = requests.get(self.login_url, params=data, headers=headers, timeout=8,
                                 verify=self.verify_ssl, allow_redirects=False)
            else:
                r = requests.post(self.login_url, data=data, headers=headers, timeout=8,
                                  verify=self.verify_ssl, allow_redirects=False)
        except requests.RequestException as e:
            self.last_error = f"网络异常：{type(e).__name__}: {e}"
            return False
        if r.status_code >= 400:
            self.last_error = f"登录端点返回 HTTP {r.status_code}"
            return False
        # 收集登录端点下发的 Set-Cookie（成功时）
        self._jar.update(r.cookies)
        # 失败判定：仍停留在登录页（凭据错误 / 需二次验证）→ 登录失败
        if _login_form_present(r):
            self.last_error = "凭据无效或需二次验证：响应仍停留登录页"
            return False
        # 成功：发生重定向（离开登录页）或返回非登录页内容（部分站点登录后返回 200 落地页）
        self.authed = True
        return True

    def login(self):
        """对外入口：尝试登录。"""
        return self._login()

    # ---------------- 续期 ----------------
    def _renew(self):
        """会话失效时重登一次；受 max_renewals 约束。成功返回 True。"""
        if self.renew_count >= self.max_renewals:
            return False
        if not self._login():
            return False
        self.renew_count += 1
        try:
            from datetime import datetime
            self.last_renew_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        return True

    def session(self):
        """返回一个与该控制器共享认证态、且会自动续期的会话对象。"""
        return RenewableSession(self)

    def _looks_expired(self, resp, url):
        """判断对 url 的响应是否表明会话已失效（且当前请求并非登录端点本身）。"""
        if resp is None:
            return False
        if _same_path(url, self.login_url):
            # 登录端点本身的响应不算失效
            return False
        if _resp_to_login(resp, url):
            return True
        if resp.status_code == 401 and "WWW-Authenticate" in resp.headers:
            return True
        if _login_markers_present(resp):
            return True
        return False


def _same_path(a, b):
    if not a or not b:
        return False
    pa, pb = urlparse(a), urlparse(b)
    return (pa.netloc == pb.netloc and pa.path.rstrip("/") == pb.path.rstrip("/"))


class RenewableSession(requests.Session):
    """继承 requests.Session：透明地检测会话失效并触发续期后重试一次。

    与控制器共享同一个 CookieJar（self.cookies 直接引用 ctrl._jar），
    因此多个 RenewableSession 实例天然共享同一认证态——正好适配 run_scans
    逐页并发扫描器各自持有一个会话、却都要保持登录的设计。
    """

    def __init__(self, ctrl):
        super().__init__()
        self._ctrl = ctrl
        self.headers.update({"User-Agent": "PenScope/1.0 (authorized security test)"})
        # 共享 CookieJar：接收到的 Set-Cookie 与续期重登写入都汇总到控制器
        self.cookies = ctrl._jar

    def request(self, method, url, **kwargs):
        # 仅重试一次，避免失效检测误判导致无限循环
        resp = super().request(method, url, **kwargs)
        if self._ctrl._looks_expired(resp, url):
            if self._ctrl._renew():
                # CookieJar 已随重登更新，直接重试原请求
                resp = super().request(method, url, **kwargs)
        return resp
