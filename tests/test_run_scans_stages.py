"""run_scans.process_scan 阶段机单元测试（mock 各阶段，验证流转 / 闸门 / 失败 / 完成）。

不触发任何真实扫描逻辑（无网络 / 无 GUI）；用无副作用的假阶段替换 _STAGE_FUNCS，
仅验证 process_scan 对阶段推进、人工闸门暂停、异常失败、已完成不推进的处理是否正确。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import db
import run_scans


def _env(monkeypatch):
    tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_stage_test.db")
    config.DB_PATH = tmp
    db.DB_PATH = tmp
    db.init_db()
    tid = db.add_target("1.2.3.4", "80", "note", "auth", "me")
    sid = db.create_scan(tid, "s", "me")
    # 用无副作用的假阶段替换真实扫描器
    monkeypatch.setattr(run_scans, "_STAGE_FUNCS", {
        "scope_check": lambda scan: None,
        "recon": lambda scan: None,
        "subdomain_enum": lambda scan: None,
        "web_detect": lambda scan: None,
        "exploit_verify": lambda scan: None,
        "upload_test": lambda scan: None,
        "report": lambda scan: None,
    })
    return db.get_scan(sid)


def test_stage_advances_to_next(monkeypatch):
    scan = _env(monkeypatch)
    run_scans.process_scan(scan)
    refreshed = db.get_scan(scan["id"])
    assert refreshed["stage"] == "recon"
    assert refreshed["status"] == "running"


def test_gate_pauses_when_awaiting_review(monkeypatch):
    scan = _env(monkeypatch)

    def _gate_stage(scan):
        db.update_scan(scan["id"], status="awaiting_review")

    monkeypatch.setitem(run_scans._STAGE_FUNCS, "scope_check", _gate_stage)
    run_scans.process_scan(scan)
    refreshed = db.get_scan(scan["id"])
    assert refreshed["status"] == "awaiting_review"
    assert refreshed["stage"] == "scope_check"  # 闸门暂停，阶段不变


def test_failure_marks_failed(monkeypatch):
    scan = _env(monkeypatch)

    def _boom(scan):
        raise RuntimeError("boom")

    monkeypatch.setitem(run_scans._STAGE_FUNCS, "scope_check", _boom)
    run_scans.process_scan(scan)
    refreshed = db.get_scan(scan["id"])
    assert refreshed["status"] == "failed"


def test_completed_does_not_advance(monkeypatch):
    scan = _env(monkeypatch)

    def _done(scan):
        db.update_scan(scan["id"], status="completed")

    monkeypatch.setitem(run_scans._STAGE_FUNCS, "scope_check", _done)
    run_scans.process_scan(scan)
    refreshed = db.get_scan(scan["id"])
    assert refreshed["status"] == "completed"
    assert refreshed["stage"] == "scope_check"
