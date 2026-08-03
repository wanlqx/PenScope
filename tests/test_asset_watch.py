"""F-05 资产变更告警引擎测试：diff 纯逻辑 + db 基线捕获/读取（临时 DB）。

遵循项目约定：临时 DB 单测用 _tmp_db() 覆盖 config.DB_PATH / db.DB_PATH，finally 中 os.remove。
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asset_watch
import config as cfg
import db as dbmod


def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    cfg.DB_PATH = path
    dbmod.DB_PATH = path
    dbmod.init_db()
    return path


def _snap(fp="", title="", headers=None, ports=None, subdomains=None):
    return {
        "fingerprint": fp, "title": title,
        "headers": headers or [], "ports": ports or [], "subdomains": subdomains or [],
    }


def test_diff_first_baseline_no_change():
    # 首次（old=None）建立基线，不应报变更
    changes = asset_watch.diff_asset_snapshot(None, _snap("Server: nginx"))
    assert changes == []


def test_diff_scalar_changed():
    old = _snap(fp="Server: nginx", title="Old")
    new = _snap(fp="Server: Apache", title="New")
    changes = asset_watch.diff_asset_snapshot(old, new)
    types = {(c["type"], c["field"]) for c in changes}
    assert ("scalar_changed", "fingerprint") in types
    assert ("scalar_changed", "title") in types
    by_field = {c["field"]: c for c in changes}
    assert by_field["fingerprint"]["old"] == "Server: nginx"
    assert by_field["fingerprint"]["new"] == "Server: Apache"


def test_diff_set_added_removed():
    old = _snap(ports=["80", "443"])
    new = _snap(ports=["80", "8080"])
    changes = asset_watch.diff_asset_snapshot(old, new)
    added = [c for c in changes if c["type"] == "added"]
    removed = [c for c in changes if c["type"] == "removed"]
    assert any(c["value"] == "8080" for c in added)
    assert any(c["value"] == "443" for c in removed)


def test_diff_no_change_identical():
    old = _snap(fp="Server: nginx", headers=["Server: nginx"], subdomains=["a.example.com"])
    new = _snap(fp="Server: nginx", headers=["Server: nginx"], subdomains=["a.example.com"])
    assert asset_watch.diff_asset_snapshot(old, new) == []


def test_format_changes_text():
    changes = [
        {"type": "scalar_changed", "field": "title", "old": "A", "new": "B"},
        {"type": "added", "field": "ports", "value": "8080"},
        {"type": "removed", "field": "subdomains", "value": "old.example.com"},
    ]
    txt = asset_watch.format_changes("example.com", changes)
    assert "example.com" in txt
    assert "页面标题" in txt and "开放端口" in txt and "子域" in txt
    assert "8080" in txt


def test_capture_and_get_baseline_roundtrip():
    path = _tmp_db()
    try:
        dbmod.capture_baseline(1, _snap(fp="Server: nginx", title="Home", headers=["Server: nginx"]))
        b = dbmod.get_baseline(1)
        assert b is not None
        assert b["fingerprint"] == "Server: nginx"
        assert b["title"] == "Home"
        assert b["headers"] == ["Server: nginx"]
        # 无记录目标返回 None
        assert dbmod.get_baseline(999) is None
    finally:
        os.remove(path)


def test_check_and_apply_baseline_detects_change_and_stores_last_change():
    path = _tmp_db()
    try:
        # 首次建立基线
        old, changes = asset_watch.check_and_apply_baseline(1, _snap(fp="Server: nginx"))
        assert old is None and changes == []
        b0 = dbmod.get_baseline(1)
        assert b0["last_change"] == []

        # 第二次变化
        old, changes = asset_watch.check_and_apply_baseline(1, _snap(fp="Server: Apache"))
        assert any(c["field"] == "fingerprint" for c in changes)
        b1 = dbmod.get_baseline(1)
        assert b1["fingerprint"] == "Server: Apache"
        assert len(b1["last_change"]) >= 1
        assert b1["last_change_at"]

        # 第三次不变（指纹相同），last_change 应保持不变（仍保留上次）
        old, changes = asset_watch.check_and_apply_baseline(1, _snap(fp="Server: Apache"))
        assert changes == []
        b2 = dbmod.get_baseline(1)
        assert b2["last_change"] == b1["last_change"]
    finally:
        os.remove(path)
