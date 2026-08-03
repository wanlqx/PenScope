"""Api 错误 / 成功信封单元测试（纯逻辑，无 GUI / 网络）。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app_api


def test_ok_envelope_merges_payload():
    r = app_api._ok({"version": "1.0.0"})
    assert r["ok"] is True
    assert r["version"] == "1.0.0"


def test_err_envelope_basic():
    r = app_api._err("E_INTERNAL", "保存失败")
    assert r == {"ok": False, "code": "E_INTERNAL", "error": "保存失败", "hint": None}


def test_err_envelope_with_hint():
    r = app_api._err("E_INVALID", "路径非法", hint="/foo/bar")
    assert r["ok"] is False
    assert r["code"] == "E_INVALID"
    assert r["error"] == "路径非法"
    assert r["hint"] == "/foo/bar"
