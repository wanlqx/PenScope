"""db.add_finding 语义去重单元测试（临时库隔离，不触碰真实 autopentest.db）。"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import db


def _tmp_db():
    tmp = tempfile.mktemp(suffix=".db")
    config.DB_PATH = tmp
    db.DB_PATH = tmp
    db.init_db()
    return tmp


def test_distinct_findings_inserted_separately():
    tmp = _tmp_db()
    try:
        sid = db.create_scan(1, "s", "me")
        a = db.add_finding(sid, "SQL注入", "登录处 SQLi", "High", "d", "e", "r",
                           "https://x/login", endpoint="https://x/login")
        b = db.add_finding(sid, "XSS", "评论框 XSS", "Medium", "d2", "e2", "r2",
                           "https://x/comment", endpoint="https://x/comment")
        assert a != b
        assert len(db.findings_of(sid)) == 2
    finally:
        os.remove(tmp)


def test_similar_finding_merged_keeps_stronger_evidence():
    tmp = _tmp_db()
    try:
        sid = db.create_scan(1, "s", "me")
        db.add_finding(sid, "SQL注入", "登录 SQL 注入", "High", "登录处存在注入点", "原证据",
                       "e", "https://x/login", endpoint="https://x/login")
        # 同类型 + 同位置 + 描述高度相似 -> 应去重合并为 1 条，并保留证据更详尽的一方
        db.add_finding(sid, "SQL注入", "登录 SQL 注入", "High", "登录处存在注入点", "更详细的证据补充",
                       "e", "https://x/login", endpoint="https://x/login")
        fs = db.findings_of(sid)
        assert len(fs) == 1
        assert "更详细的证据补充" in fs[0]["evidence"]
    finally:
        os.remove(tmp)


def test_set_finding_fix_status_reflected_in_stats():
    tmp = _tmp_db()
    try:
        sid = db.create_scan(1, "s", "me")
        fid = db.add_finding(sid, "SQL注入", "登录 SQL 注入", "High", "d", "e", "r",
                             "https://x/login", endpoint="https://x/login")
        db.set_finding_fix_status(fid, "fixed")
        # db_stats 现已按 'fixed'（而非旧误用的 'done'）统计「已修复」
        stats = db.db_stats()
        assert stats["findings_done"] == 1
        assert stats["findings"] == 1
    finally:
        os.remove(tmp)
