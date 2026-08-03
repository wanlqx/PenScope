"""CWE-601 开放重定向：只读检测单元测试（无真实网络，全部 mock）。

覆盖：外部跳转强证据（中危/L2）、站外同域跳转的 FP 防护、无跳转零发现、
仅 sink 参数名的被动 L1 观察、表单字段注入外部跳转。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unittest.mock import patch

import scanner.open_redirect as orm
from scanner.open_redirect import scan_open_redirect


class _Resp:
    def __init__(self, status, location=None, text=""):
        self.status_code = status
        self.headers = {}
        if location is not None:
            self.headers["Location"] = location
        self.text = text
        self.url = location or ""


class _MockSession:
    def __init__(self, responder):
        self._responder = responder

    def get(self, url, params=None, timeout=6.0, verify=False, allow_redirects=True):
        return self._responder(url, "get", params)

    def post(self, url, data=None, timeout=6.0, verify=False, allow_redirects=True):
        return self._responder(url, "post", data)


def _external(url, method, data):
    blob = url + " " + str(data)
    if "evil.example.com" in blob:
        if "//evil.example.com" in blob or "%2F%2Fevil.example.com" in blob:
            return _Resp(302, location="//evil.example.com/")
        return _Resp(302, location="https://evil.example.com/")
    return _Resp(200)


def _samehost(url, method, data):
    blob = url + " " + str(data)
    if "evil.example.com" in blob:
        # 应用把外部输入"归一"回站内 -> 不应判为开放重定向（FP 防护）
        return _Resp(302, location="http://127.0.0.1:8090/dashboard")
    if any(k in blob for k in ("redirect", "next", "url", "to", "return")):
        return _Resp(302, location="/dashboard")  # 相对路径，同源
    return _Resp(200)


def _none(url, method, data):
    return _Resp(200)


def _no_forms(*a, **k):
    return []


def _form_with_url_field(*a, **k):
    return [{"action": "http://127.0.0.1:8090/login", "method": "post",
             "fields": ["username", "password", "url"]}]


def test_external_url_param_detected():
    s = _MockSession(_external)
    with patch.object(orm, "discover", _no_forms):
        fs = scan_open_redirect("http://127.0.0.1:8090/page?redirect=home", s)
    strong = [f for f in fs if f["risk"] == "Medium" and "站外" in f["title"]]
    passive = [f for f in fs if f["risk"] == "Low" and "潜在开放重定向" in f["title"]]
    assert strong, f"期望检测到外部跳转强证据，实际 {fs}"
    assert passive, f"期望有被动 L1 观察，实际 {fs}"
    assert all(f["cwe"] == "CWE-601" for f in fs), fs
    assert all(f["evidence_level"] == "L2" for f in strong)


def test_fp_samehost_no_false_positive():
    s = _MockSession(_samehost)
    with patch.object(orm, "discover", _no_forms):
        fs = scan_open_redirect("http://127.0.0.1:8090/page?redirect=home", s)
    strong = [f for f in fs if f["risk"] == "Medium" and "站外" in f["title"]]
    assert not strong, f"站外同域/相对跳转不应报强证据，实际 {fs}"


def test_no_redirect_clean():
    s = _MockSession(_none)
    with patch.object(orm, "discover", _no_forms):
        fs = scan_open_redirect("http://127.0.0.1:8090/page?q=search", s)
    assert fs == [], f"无重定向不应有任何发现，实际 {fs}"


def test_passive_only_no_false_positive():
    s = _MockSession(_none)
    with patch.object(orm, "discover", _no_forms):
        fs = scan_open_redirect("http://127.0.0.1:8090/page?next=1", s)
    med = [f for f in fs if f["risk"] == "Medium"]
    assert not med, f"无实际跳转不应有中危发现，实际 {fs}"
    low = [f for f in fs if f["risk"] == "Low" and "潜在开放重定向" in f["title"]]
    assert len(low) == 1, f"期望恰好 1 条被动 L1，实际 {fs}"


def test_form_field_external_detected():
    s = _MockSession(_external)
    with patch.object(orm, "discover", _form_with_url_field):
        fs = scan_open_redirect("http://127.0.0.1:8090/", s)
    strong = [f for f in fs if f["risk"] == "Medium" and "站外" in f["title"]]
    assert strong, f"表单字段 url 注入应检出外部跳转，实际 {fs}"
