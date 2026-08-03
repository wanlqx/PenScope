"""CWE-287 默认凭据探针：CSRF 感知回填测试（无真实网络，全部 mock）。

证明：开启 ENABLE_AUTH_PROBE 后，对带 CSRF token 的登录端点（如 DVWA），探针会
先抓取登录页、提取并回填真实 token，从而用 admin/password 命中默认凭据（High/L3）。
（若没有 CSRF 感知，user_token 会被填成占位值 "1"，DVWA 返回 "CSRF token is incorrect"
而判失败——本测试即守护该增强行为。）
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unittest.mock import patch

import scanner.auth as auth_mod
from scanner.auth import scan_auth


class _Resp:
    def __init__(self, status, location=None, text=""):
        self.status_code = status
        self.headers = {}
        if location is not None:
            self.headers["Location"] = location
        self.text = text
        self.url = location or "http://127.0.0.1:8090/login"


LOGIN_HTML = (
    '<form action="http://127.0.0.1:8090/login" method="post">'
    '<input type="hidden" name="user_token" value="ABC123">'
    '<input name="username" type="text">'
    '<input name="password" type="password">'
    '<input type="submit" name="Login">'
    '</form>'
)


class _CsrfSession:
    def get(self, url, params=None, timeout=6.0, verify=False, allow_redirects=True):
        return _Resp(200, text=LOGIN_HTML)

    def post(self, url, data=None, timeout=6.0, verify=False, allow_redirects=True):
        data = data or {}
        ok = (data.get("user_token") == "ABC123" and data.get("username") == "admin"
              and data.get("password") == "password")
        if ok:
            return _Resp(302, location="http://127.0.0.1:8090/dashboard",
                         text='<a href="/logout">Logout</a> welcome dashboard')
        return _Resp(200, text=LOGIN_HTML)  # 仍含密码框 -> 判定失败


def _login_form(*a, **k):
    return [{"action": "http://127.0.0.1:8090/login", "method": "post",
             "fields": ["username", "password", "user_token", "Login"]}]


def test_csrf_aware_default_cred_probe():
    s = _CsrfSession()
    with patch.object(auth_mod, "discover", _login_form):
        fs = scan_auth("http://127.0.0.1:8090/login", s, enable_auth_probe=True)
    high = [f for f in fs if f["risk"] == "High" and "admin/password" in f["title"]]
    assert high, f"开启 CSRF 感知后应能用 admin/password 命中默认凭据，实际 {fs}"
    assert high[0]["cwe"] == "CWE-287"
    assert high[0]["evidence_level"] == "L3"
