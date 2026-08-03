"""单元测试：缺失授权(CWE-862) 与 认证缺陷(CWE-287) 检测模块（纯本地 mock，无真实网络）。

覆盖：
  - 缺失授权：强制浏览命中 / 基线防误报（404 基线页不报）/ 无 200 不报；权限指示参数观察(L1)
  - 认证缺陷：被动登录端点识别(L1) / 凭证出现在 URL query(L1)；opt-in 默认凭据命中(High/L3)
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scanner.access_control as ac
import scanner.auth as auth
from scanner.access_control import scan_access_control
from scanner.auth import scan_auth

_BASELINE = "_ap_probe_nonexistent_9F3A"
ADMIN_DASH = "<html><body><h1>Admin Dashboard</h1><p>secret config here</p></body></html>"
NOTFOUND = "<html><body><h1>404 Not Found</h1><p>page missing</p></body></html>"
LOGIN_HTML = ('<html><body><form action="http://t/login.php" method="post">'
              '<input name="username"><input type="password" name="password">'
              '<input type="submit" name="Login"></form></body></html>')
DASH_HTML = "<html><body>Welcome to dashboard <a href=/logout>Logout</a></body></html>"


class _Resp:
    def __init__(self, text, status=200, url="", headers=None):
        self.text = text
        self.status_code = status
        self.url = url
        self.headers = headers or {}


class _MockSession:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def get(self, url, params=None, timeout=None, verify=None, allow_redirects=None, **kw):
        self.calls.append(("GET", url, params))
        return _Resp(self.responder("GET", url, params), url=url)

    def post(self, url, data=None, timeout=None, verify=None, allow_redirects=None, **kw):
        self.calls.append(("POST", url, data))
        return _Resp(self.responder("POST", url, data), url=url)


# ---------- 缺失授权：强制浏览 ----------
def test_force_browsing_positive():
    def resp(method, url, payload):
        if _BASELINE in url:
            return NOTFOUND
        if "/admin" in url:
            return ADMIN_DASH
        return NOTFOUND
    s = _MockSession(resp)
    fs = scan_access_control("http://t/", s, probe_session=s)
    fb = [f for f in fs if f["risk"] == "Medium" and f["cwe"] == "CWE-862"]
    assert len(fb) >= 1, f"期望至少 1 条强制浏览命中，实际 {fs}"
    assert fb[0]["evidence_level"] == "L2"
    assert fb[0]["verification_status"] == "unverified"
    print("PASS test_force_browsing_positive")


def test_force_browsing_fp_avoid():
    # 所有路径（含 /admin）都返回与基线相同的 404 页 -> 软 404 相似度排除，不报
    def resp(method, url, payload):
        return NOTFOUND
    s = _MockSession(resp)
    fs = scan_access_control("http://t/", s, probe_session=s)
    fb = [f for f in fs if f["risk"] == "Medium" and f["cwe"] == "CWE-862"]
    assert len(fb) == 0, f"基线已含相同内容时不应报，实际 {fb}"
    print("PASS test_force_browsing_fp_avoid")


def test_force_browsing_no_200():
    # 所有路径返回 404 状态（非 200）-> 不报
    def resp(method, url, payload):
        if _BASELINE in url:
            return NOTFOUND
        return NOTFOUND
    s = _MockSession(resp)
    fs = scan_access_control("http://t/", s, probe_session=s)
    fb = [f for f in fs if f["risk"] == "Medium" and f["cwe"] == "CWE-862"]
    assert len(fb) == 0, f"无 200 响应不应报，实际 {fb}"
    print("PASS test_force_browsing_no_200")


def test_priv_param_url():
    def resp(method, url, payload):
        return "<html>normal</html>"
    s = _MockSession(resp)
    fs = scan_access_control("http://t/?role=5", s, probe_session=s)
    low = [f for f in fs if f["risk"] == "Low" and "参数" in f["title"] and f["cwe"] == "CWE-862"]
    assert len(low) >= 1, f"期望 1 条越权参数观察，实际 {fs}"
    assert low[0]["evidence_level"] == "L1"
    print("PASS test_priv_param_url")


# ---------- 认证缺陷：被动 + 主动 ----------
def test_auth_login_endpoint():
    def resp(method, url, payload):
        return LOGIN_HTML  # 任何 GET 都返回含密码框的登录页
    s = _MockSession(resp)
    fs = scan_auth("http://t/", s)
    login = [f for f in fs if f["title"].startswith("发现疑似登录端点") and f["cwe"] == "CWE-287"]
    assert len(login) == 1, f"期望 1 条登录端点观察，实际 {fs}"
    assert login[0]["risk"] == "Low"
    high = [f for f in fs if f["risk"] == "High"]
    assert len(high) == 0, "未开启主动探测不应有 High"
    print("PASS test_auth_login_endpoint")


def test_auth_cred_in_url():
    def resp(method, url, payload):
        return LOGIN_HTML
    s = _MockSession(resp)
    fs = scan_auth("http://t/login.php?password=secret&user=admin", s)
    cred = [f for f in fs if "URL" in f["title"] and "凭据" in f["title"]]
    assert len(cred) == 1, f"期望 1 条 URL 凭据观察，实际 {fs}"
    print("PASS test_auth_cred_in_url")


def test_auth_default_cred_hit():
    def resp(method, url, payload):
        if method == "POST":
            vals = [str(v) for v in (payload or {}).values()]
            # admin/password 命中 -> 返回仪表盘（无密码框）；其余 -> 登录页
            if "password" in vals and "admin" in vals:
                return DASH_HTML
            return LOGIN_HTML
        return LOGIN_HTML
    s = _MockSession(resp)
    fs = scan_auth("http://t/", s, enable_auth_probe=True)
    high = [f for f in fs if f["risk"] == "High" and f["cwe"] == "CWE-287"]
    assert len(high) == 1, f"期望 1 条默认凭据 High，实际 {fs}"
    assert high[0]["evidence_level"] == "L3"
    assert "admin/password" in high[0]["title"]
    print("PASS test_auth_default_cred_hit")


def test_auth_probe_off_no_high():
    def resp(method, url, payload):
        return LOGIN_HTML
    s = _MockSession(resp)
    fs = scan_auth("http://t/", s, enable_auth_probe=False)
    high = [f for f in fs if f["risk"] == "High"]
    assert len(high) == 0, "默认关闭主动探测不应有 High"
    print("PASS test_auth_probe_off_no_high")


if __name__ == "__main__":
    test_force_browsing_positive()
    test_force_browsing_fp_avoid()
    test_force_browsing_no_200()
    test_priv_param_url()
    test_auth_login_endpoint()
    test_auth_cred_in_url()
    test_auth_default_cred_hit()
    test_auth_probe_off_no_high()
    print("\nALL TESTS PASSED")
