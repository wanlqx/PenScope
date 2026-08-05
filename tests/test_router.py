# -*- coding: utf-8 -*-
"""P4 启发式路由调度层（scanner.router）单元测试。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import MagicMock

from scanner.router import (
    probe_signals,
    plan,
    ADV_CATS,
    CAT_SSTI,
    CAT_XXE,
    CAT_JWT,
    CAT_NOSQL,
    CAT_IDOR,
)

_BASE = ["SQL注入", "XSS", "CSRF", "文件上传", "命令注入", "路径遍历", "SSRF",
         "缺失授权", "认证缺陷", "开放重定向", "SSTI", "XXE", "JWT算法混淆",
         "NoSQL注入", "IDOR"]


def _mock_resp(headers=None, text="", url="http://x/"):
    r = MagicMock()
    r.headers = headers or {}
    r.text = text
    r.url = url
    return r


def test_adv_cats_complete():
    assert set(ADV_CATS) == {CAT_SSTI, CAT_XXE, CAT_JWT, CAT_NOSQL, CAT_IDOR}


def test_probe_signals_keys():
    s = MagicMock()
    s.get.return_value = _mock_resp({"Content-Type": "text/html"}, "<html></html>")
    sig = probe_signals(s, "http://x/")
    assert set(sig) == {"content_type", "has_jwt", "template_err", "object_id", "json_api"}


def test_probe_signals_xml_boost():
    s = MagicMock()
    s.get.return_value = _mock_resp({"Content-Type": "application/xml"}, "<a/>")
    assert "xml" in probe_signals(s, "http://x/")["content_type"]


def test_probe_signals_jwt():
    s = MagicMock()
    s.get.return_value = _mock_resp({"Set-Cookie": "t=eyJhbGc.eyJzdWI.abc"}, "x")
    assert probe_signals(s, "http://x/")["has_jwt"] is True


def test_probe_signals_template_err():
    s = MagicMock()
    s.get.return_value = _mock_resp({}, "jinja2.exceptions.TemplateNotFound")
    assert probe_signals(s, "http://x/")["template_err"] is True


def test_probe_signals_object_id():
    s = MagicMock()
    s.get.return_value = _mock_resp({}, "ok")
    assert probe_signals(s, "http://x/view?id=5")["object_id"] is True


def test_probe_signals_json_api():
    s = MagicMock()
    s.get.return_value = _mock_resp({"Content-Type": "application/json"}, "{}")
    assert probe_signals(s, "http://x/api/users")["json_api"] is True


def test_probe_signals_exception_safe():
    s = MagicMock()
    s.get.side_effect = Exception("net down")
    sig = probe_signals(s, "http://x/")
    assert set(sig) == {"content_type", "has_jwt", "template_err", "object_id", "json_api"}


def test_plan_boosts_xxe_on_xml():
    sig = {"content_type": "application/xml", "has_jwt": False, "template_err": False,
           "object_id": False, "json_api": False}
    ordered = plan(sig, _BASE)
    assert ordered[0] == CAT_XXE
    assert len(ordered) == len(_BASE)  # 零误报优先：不删项


def test_plan_boosts_idor_on_object_id():
    sig = {"content_type": "", "has_jwt": False, "template_err": False,
           "object_id": True, "json_api": False}
    assert plan(sig, _BASE)[0] == CAT_IDOR


def test_plan_no_signal_keeps_order():
    sig = {"content_type": "", "has_jwt": False, "template_err": False,
           "object_id": False, "json_api": False}
    assert plan(sig, _BASE) == _BASE


def test_plan_multiple_boosts_preserve_coverage():
    sig = {"content_type": "application/xml", "has_jwt": True, "template_err": False,
           "object_id": False, "json_api": False}
    ordered = plan(sig, _BASE)
    assert ordered[0] == CAT_XXE
    assert CAT_JWT in ordered[:2]
    assert set(ordered) == set(_BASE)
