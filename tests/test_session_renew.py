"""C-06 可续期会话单元测试：用本地 HTTP 服务器模拟登录 / 会话失效 / 自动续期。"""
import http.server
import socketserver
import threading
import urllib.parse

import pytest

from scanner.session_renew import SessionRenewal, _login_form_present


LOGIN_FORM = (
    "<html><body><form method=post action=/login>"
    "<input type=hidden name=csrf value=TOK123>"
    "<input type=text name=user>"
    "<input type=password name=pass>"
    "<input type=submit></form></body></html>"
)


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/login":
            self._send(200, LOGIN_FORM)
        elif path == "/home":
            cookie = self.headers.get("Cookie", "")
            if "sid=valid" in cookie:
                self._send(200, "welcome dashboard <a href=/secret>secret</a>")
            else:
                self._send(302, "", {"Location": "/login"})
        else:
            self._send(404, "not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/login":
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8")
            data = urllib.parse.parse_qs(body)
            user = (data.get("user") or [""])[0]
            pw = (data.get("pass") or [""])[0]
            if user == "admin" and pw == "admin":
                self._send(302, "", {"Location": "/home", "Set-Cookie": "sid=valid; Path=/"})
            else:
                self._send(200, LOGIN_FORM)  # 登录失败：停留在登录页（含 password 输入框）
        else:
            self._send(404, "not found")


@pytest.fixture
def server():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _profile(base, password="admin"):
    return {
        "login_url": base + "/login",
        "method": "post",
        "user_field": "user",
        "pass_field": "pass",
        "username": "admin",
        "password": password,
        "extra_fields": [],
        "csrf_autodetect": True,
        "max_renewals": 5,
    }


def test_login_success(server):
    ctrl = SessionRenewal(_profile(server))
    assert ctrl.login() is True
    s = ctrl.session()
    r = s.get(server + "/home")
    assert r.status_code == 200
    assert "welcome" in r.text


def test_renewal_on_expiry(server):
    ctrl = SessionRenewal(_profile(server))
    assert ctrl.login() is True
    s = ctrl.session()
    r = s.get(server + "/home")
    assert "welcome" in r.text
    # 模拟会话过期：清空共享 CookieJar
    ctrl._jar.clear()
    r2 = s.get(server + "/home")
    # 失效检测 → 自动重登 → 重试，最终仍拿到已认证内容
    assert ctrl.renew_count == 1
    assert "welcome" in r2.text


def test_wrong_password(server):
    ctrl = SessionRenewal(_profile(server, password="wrong"))
    assert ctrl.login() is False
    assert ctrl.authed is False


def test_max_renewals_bound(server):
    ctrl = SessionRenewal(_profile(server))
    ctrl.max_renewals = 2
    calls = {"n": 0}

    def fake_login():
        calls["n"] += 1
        ctrl._jar.set("sid", "valid")
        return True

    ctrl._login = fake_login
    assert ctrl._renew() is True   # count 1
    assert ctrl._renew() is True   # count 2
    assert ctrl._renew() is False  # 超出上限
    assert ctrl.renew_count == 2


def test_expiry_heuristics(server):
    ctrl = SessionRenewal(_profile(server))
    login = server + "/login"

    class FakeResp:
        def __init__(self, status=200, text="", headers=None, url=login):
            self.status_code = status
            self.text = text
            self.headers = headers or {}
            self.url = url

    # 登录端点本身含登录表单 → 不算失效
    assert ctrl._looks_expired(FakeResp(200, "<input type=password>", url=login), login) is False
    # 受保护页返回登录表单 → 失效
    assert ctrl._looks_expired(FakeResp(200, "<input type=password>"), server + "/home") is True
    # 401 + WWW-Authenticate → 失效
    assert ctrl._looks_expired(FakeResp(401, "", {"WWW-Authenticate": "Basic"}), server + "/home") is True
    # 登出标记 → 失效
    assert ctrl._looks_expired(FakeResp(200, "your session has expired"), server + "/home") is True
    # 正常页 → 未失效
    assert ctrl._looks_expired(FakeResp(200, "normal content"), server + "/home") is False


def test_login_form_present():
    class R:
        text = '<form><input type="password" name="pass"></form>'
    assert _login_form_present(R()) is True
    R.text = "<form><input type=text name=user></form>"
    assert _login_form_present(R()) is False
