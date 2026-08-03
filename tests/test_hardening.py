"""安全审计整改回归测试：H-4（font_size 校验）、H-5（列名白名单）、AP-002（verify_tls 持久化）。

使用临时 SQLite 库，避免污染真实 autopentest.db。
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app_api
import config
import db as dbmod


def _tmp_db():
    tmp = tempfile.mktemp(suffix=".db")
    config.DB_PATH = tmp
    dbmod.DB_PATH = tmp
    dbmod.init_db()
    return tmp


def test_h5_update_scan_rejects_unknown_column():
    tmp = _tmp_db()
    try:
        # 非法列名必须抛 ValueError（防列名拼接注入）
        with __import__("pytest").raises(ValueError):
            dbmod.update_scan(1, evil_column="x")
        # 合法列名不抛错（即便目标行不存在，也不应触发列名校验失败）
        dbmod.update_scan(1, status="completed")
    finally:
        os.remove(tmp)


def test_ap2_target_verify_tls_persisted():
    tmp = _tmp_db()
    try:
        # 默认校验
        tid = dbmod.add_target("1.2.3.4", "common", "", "auth", "me")
        assert dbmod.get_target(tid)["verify_tls"] == 1
        # 显式跳过校验
        tid2 = dbmod.add_target("5.6.7.8", "common", "", "auth", "me", verify_tls=0)
        assert dbmod.get_target(tid2)["verify_tls"] == 0
        # 编辑改回校验
        dbmod.update_target(tid2, "5.6.7.8", "common", "", "auth", verify_tls=1)
        assert dbmod.get_target(tid2)["verify_tls"] == 1
        # 不传 verify_tls 时不应改动原值
        dbmod.update_target(tid2, "5.6.7.8", "common", "", "auth")
        assert dbmod.get_target(tid2)["verify_tls"] == 1
    finally:
        os.remove(tmp)


def test_h4_set_settings_font_size_validation():
    tmp = _tmp_db()
    try:
        api = app_api.Api()
        assert api.set_settings({"font_size": "14"}) == {"ok": True}
        # 越界 -> 拒绝，不落库
        r = api.set_settings({"font_size": "25"})
        assert r["ok"] is False
        # 非数值 -> 拒绝
        r = api.set_settings({"font_size": "abc"})
        assert r["ok"] is False
        # 合法值仍被接受
        assert api.set_settings({"font_size": "16"}) == {"ok": True}
    finally:
        os.remove(tmp)
