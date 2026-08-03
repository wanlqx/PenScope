"""AP-001 回归测试：重定向作用域围栏（闭合 SSRF 缺口 CWE-918）。

验证 collect_pages 不再透明跟随跨主机 / 被拦截网段的重定向；redirect_target_blocked
对「外部目标重定向到受保护内网」判定为越界（SSRF），但对同主机、相对重定向、
以及使用者在扫自己内网靶场时的内网重定向判定为同作用域（可跟随，避免 localhost 靶场回归）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.scope import redirect_target_blocked
from scanner.web_scan import collect_pages


class FakeResp:
    def __init__(self, status_code, url, text="", headers=None):
        self.status_code = status_code
        self.url = url
        self.text = text
        self.headers = headers or {}
        self.content = text.encode()


class FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def get(self, url, timeout=None, verify=None, allow_redirects=None):
        self.requests.append(url)
        r = self.routes.get(url)
        if r is None:
            r = FakeResp(200, url, "<html></html>", {"Content-Type": "text/html"})
        return r


def test_redirect_target_blocked_for_external_base():
    # 外部目标（t.test）重定向到内网/云元数据/回环 → 拦截（SSRF 围栏）
    assert redirect_target_blocked("127.0.0.1", "t.test") is True
    assert redirect_target_blocked("169.254.169.254", "t.test") is True       # 云元数据
    assert redirect_target_blocked("10.0.0.5", "t.test") is True              # RFC1918
    assert redirect_target_blocked("192.168.1.1", "t.test") is True
    # 跨主机公网跳转 → 越界丢弃
    assert redirect_target_blocked("evil.other", "t.test") is True
    # 同主机 → 跟随
    assert redirect_target_blocked("t.test", "t.test") is False
    # 解析失败 → 保守丢弃（防止借 DNS 失败逃逸作用域）
    assert redirect_target_blocked("unresolvable.invalid", "t.test") is True


def test_redirect_target_allowed_for_internal_base():
    # 使用者在扫自己的靶场（base 为内网/回环）：重定向到同网段内网视为同作用域，跟随
    assert redirect_target_blocked("127.0.0.1", "127.0.0.1") is False
    assert redirect_target_blocked("169.254.169.254", "192.168.1.50") is False
    assert redirect_target_blocked("192.168.1.99", "192.168.1.50") is False
    # 相对重定向（无 netloc）→ 同主机，跟随
    assert redirect_target_blocked("", "192.168.1.50") is False
    # 但内网 base 重定向到外网不同主机 → 仍越界丢弃
    assert redirect_target_blocked("evil.other", "192.168.1.50") is True


def test_collect_pages_follows_same_host_redirect():
    routes = {
        "http://t.test:8080/": FakeResp(302, "http://t.test:8080/",
                                         "", {"Location": "/dashboard"}),
        "http://t.test:8080/dashboard": FakeResp(
            200, "http://t.test:8080/dashboard",
            "<html><a href='/page2'>x</a></html>", {"Content-Type": "text/html"}),
        "http://t.test:8080/page2": FakeResp(
            200, "http://t.test:8080/page2",
            "<html></html>", {"Content-Type": "text/html"}),
    }
    pages = collect_pages("http://t.test:8080/", FakeSession(routes), max_pages=10)
    assert "http://t.test:8080/dashboard" in pages
    assert "http://t.test:8080/page2" in pages


def test_collect_pages_drops_redirect_to_cloud_metadata():
    routes = {
        "http://t.test:8080/": FakeResp(
            302, "http://t.test:8080/", "",
            {"Location": "http://169.254.169.254/latest/meta-data/"}),
    }
    sess = FakeSession(routes)
    pages = collect_pages("http://t.test:8080/", sess, max_pages=10)
    assert pages == []
    # 工具绝不应向被拦截网段（云元数据）发起请求
    assert not any("169.254.169.254" in u for u in sess.requests)


def test_collect_pages_drops_cross_host_redirect():
    routes = {
        "http://t.test:8080/": FakeResp(
            302, "http://t.test:8080/", "",
            {"Location": "http://evil.other/"}),
    }
    sess = FakeSession(routes)
    pages = collect_pages("http://t.test:8080/", sess, max_pages=10)
    assert pages == []
    assert not any("evil.other" in u for u in sess.requests)
