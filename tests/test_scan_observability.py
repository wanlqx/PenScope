"""I-02 阶段甘特图数据源 / U-06 失败根因分类 单元测试。

使用临时 SQLite 库；不触达真实目标网络（仅验证异常归类与事件/归因记录逻辑）。
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import db as dbmod
import run_scans
import requests


def _tmp_db():
    tmp = tempfile.mktemp(suffix=".db")
    config.DB_PATH = tmp
    dbmod.DB_PATH = tmp
    dbmod.init_db()
    return tmp


def test_classify_error_categories():
    import socket
    assert run_scans._classify_error(socket.gaierror("nodename"))[0] == "network_unreachable"
    assert run_scans._classify_error(requests.exceptions.SSLError("bad cert"))[0] == "ssl_error"
    assert run_scans._classify_error(requests.exceptions.ReadTimeout("slow"))[0] == "timeout"
    assert run_scans._classify_error(ValueError("boom"))[0] == "exception"


def test_fail_scan_records_category():
    tmp = _tmp_db()
    try:
        tid = dbmod.add_target("1.2.3.4", "common", "", "auth", "me")
        dbmod.approve_target(tid, "me")
        sid = dbmod.create_scan(tid, "t", "me")
        dbmod.fail_scan(sid, "ssl_error", "TLS 校验失败：self-signed")
        s = dbmod.get_scan(sid)
        assert s["status"] == "failed"
        assert s["failure_category"] == "ssl_error"
        assert s["failure_detail"] == "TLS 校验失败：self-signed"
        summ = __import__("json").loads(s["summary"])
        assert summ["failure_category"] == "ssl_error"
    finally:
        os.remove(tmp)


def test_stage_events_recorded():
    tmp = _tmp_db()
    try:
        tid = dbmod.add_target("1.2.3.4", "common", "", "auth", "me")
        dbmod.approve_target(tid, "me")
        sid = dbmod.create_scan(tid, "t", "me")
        dbmod.record_stage_event(sid, "recon", "start")
        dbmod.record_stage_event(sid, "recon", "done")
        evs = dbmod.stage_events(sid)
        assert len(evs) == 2
        assert evs[0]["stage"] == "recon" and evs[0]["status"] == "start"
        assert evs[1]["status"] == "done"
    finally:
        os.remove(tmp)


def test_get_scan_stages_api():
    tmp = _tmp_db()
    try:
        tid = dbmod.add_target("1.2.3.4", "common", "", "auth", "me")
        dbmod.approve_target(tid, "me")
        sid = dbmod.create_scan(tid, "t", "me")
        dbmod.record_stage_event(sid, "scope_check", "start")
        dbmod.record_stage_event(sid, "scope_check", "done")
        dbmod.record_stage_event(sid, "recon", "start")
        import app_api
        api = app_api.Api()
        r = api.get_scan_stages(sid)
        assert r["ok"] is True
        stages = r["stages"]
        assert stages[0]["stage"] == "scope_check"
        assert stages[0]["status"] == "done"
        assert stages[0]["duration_ms"] is not None
        assert stages[1]["stage"] == "recon"
        assert stages[1]["status"] == "start"   # 尚未结束
        assert stages[1]["end"] is None
    finally:
        os.remove(tmp)


def test_process_scan_catches_exception_and_classifies():
    """U-06：阶段异常被捕获并归类为失败，避免扫描卡在 running。
    process_scan 为单阶段执行，故用 monkeypatch 把一个阶段替换为必抛异常的桩来触发异常路径。"""
    tmp = _tmp_db()
    try:
        tid = dbmod.add_target("1.2.3.4", "common", "", "auth", "me")
        dbmod.approve_target(tid, "me")
        sid = dbmod.create_scan(tid, "t", "me")

        def _boom(scan):
            raise RuntimeError("kaboom")

        orig = run_scans._STAGE_FUNCS
        run_scans._STAGE_FUNCS = dict(orig)
        run_scans._STAGE_FUNCS["scope_check"] = _boom
        try:
            scan = dbmod.get_scan(sid)
            run_scans.process_scan(scan)
        finally:
            run_scans._STAGE_FUNCS = orig
        s = dbmod.get_scan(sid)
        assert s["status"] == "failed"
        assert s["failure_category"] == "exception"
    finally:
        os.remove(tmp)
