"""I-03 漏洞矩阵视图 / F-03 漏洞对比基线 Diff 单元测试。

使用临时 SQLite 库；不触达真实目标网络（仅验证聚合与差集逻辑）。
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import db as dbmod
import app_api


def _tmp_db():
    tmp = tempfile.mktemp(suffix=".db")
    config.DB_PATH = tmp
    dbmod.DB_PATH = tmp
    dbmod.init_db()
    return tmp


def _add_scan(target_host="1.2.3.4"):
    tid = dbmod.add_target(target_host, "common", "", "auth", "me")
    dbmod.approve_target(tid, "me")
    sid = dbmod.create_scan(tid, "t", "me")
    dbmod.update_scan(sid, status="completed")
    return tid, sid


def _add_two_scans(target_host="1.1.1.1"):
    """在同一目标下创建两次已完成扫描，供对比测试。"""
    tid = dbmod.add_target(target_host, "common", "", "auth", "me")
    dbmod.approve_target(tid, "me")
    sidA = dbmod.create_scan(tid, "scan A", "me")
    sidB = dbmod.create_scan(tid, "scan B", "me")
    dbmod.update_scan(sidA, status="completed")
    dbmod.update_scan(sidB, status="completed")
    return tid, sidA, sidB


def test_findings_matrix_aggregates():
    tmp = _tmp_db()
    try:
        _, sid = _add_scan()
        dbmod.add_finding(sid, "SQL Injection", "SQLi in login", "High", "d", "e", "r",
                          "http://x/a", endpoint="http://x/a")
        dbmod.add_finding(sid, "XSS", "XSS in search", "Medium", "d", "e", "r",
                          "http://x/a", endpoint="http://x/a")
        dbmod.add_finding(sid, "XSS", "XSS in profile", "Critical", "d", "e", "r",
                          "http://x/b", endpoint="http://x/b")
        m = dbmod.findings_matrix(sid)
        assert m["total"] == 3
        assert set(m["endpoints"]) == {"http://x/a", "http://x/b"}
        assert set(m["categories"]) == {"SQL Injection", "XSS"}
        # 同一端点不同漏洞类型分列
        assert m["cells"]["http://x/a"]["SQL Injection"]["risk"] == "High"
        assert m["cells"]["http://x/a"]["XSS"]["risk"] == "Medium"
        # 另一端点 XSS 为 Critical
        assert m["cells"]["http://x/b"]["XSS"]["risk"] == "Critical"
        assert m["cells"]["http://x/a"]["SQL Injection"]["count"] == 1
        assert m["cells"]["http://x/a"]["SQL Injection"]["fid"] is not None
    finally:
        os.remove(tmp)


def test_findings_matrix_cell_max_risk_and_count():
    """直接插入两条 (端点, 类型) 完全相同、风险不同的发现（绕过语义去重），
    验证矩阵单元格取最高风险、计数累加、代表 fid 指向最高风险行。"""
    tmp = _tmp_db()
    try:
        _, sid = _add_scan()
        ts = "2026-01-01 00:00:00"
        c = dbmod._conn()
        c.execute(
            "INSERT INTO findings (scan_id,category,title,risk,detail,created_at,finding_id,target_ref,endpoint) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (sid, "XSS", "low", "Low", "d", ts, "XSS|http://x/b", "http://x/b", "http://x/b"),
        )
        cur = c.execute(
            "INSERT INTO findings (scan_id,category,title,risk,detail,created_at,finding_id,target_ref,endpoint) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (sid, "XSS", "crit", "Critical", "d", ts, "XSS|http://x/b", "http://x/b", "http://x/b"),
        )
        high_fid = cur.lastrowid
        c.commit(); c.close()
        m = dbmod.findings_matrix(sid)
        cell = m["cells"]["http://x/b"]["XSS"]
        assert cell["count"] == 2
        assert cell["risk"] == "Critical"
        assert cell["fid"] == high_fid
    finally:
        os.remove(tmp)


def test_compare_scans_new_resolved_persistent():
    tmp = _tmp_db()
    try:
        _, sidA, sidB = _add_two_scans("1.1.1.1")  # 同目标两次扫描
        # 基线 A：SQLi + XSS
        dbmod.add_finding(sidA, "SQL Injection", "SQLi", "High", "d", "e", "r",
                          "http://x/a", endpoint="http://x/a")
        dbmod.add_finding(sidA, "XSS", "XSS", "Medium", "d", "e", "r",
                          "http://x/b", endpoint="http://x/b")
        # 当前 B：SQLi（持续）+ Open Redirect（新增）；XSS 缺失（已解决）
        dbmod.add_finding(sidB, "SQL Injection", "SQLi", "High", "d", "e", "r",
                          "http://x/a", endpoint="http://x/a")
        dbmod.add_finding(sidB, "Open Redirect", "OR", "Low", "d", "e", "r",
                          "http://x/c", endpoint="http://x/c")
        d = dbmod.compare_scans(sidA, sidB)
        assert d is not None
        assert d["prev_scan_id"] == sidA and d["curr_scan_id"] == sidB
        assert d["counts"]["prev"] == 2 and d["counts"]["curr"] == 2
        assert d["counts"]["resolved"] == 1
        assert d["counts"]["new"] == 1
        assert d["counts"]["persistent"] == 1
        assert any(f["category"] == "XSS" for f in d["resolved"])
        assert any(f["category"] == "Open Redirect" for f in d["new"])
        assert any(f["category"] == "SQL Injection" for f in d["persistent"])
    finally:
        os.remove(tmp)


def test_compare_scans_cross_target_returns_none():
    tmp = _tmp_db()
    try:
        _, sidA = _add_scan("1.1.1.1")
        _, sidOther = _add_scan("2.2.2.2")  # 不同目标
        d = dbmod.compare_scans(sidA, sidOther)
        assert d is None
        api = app_api.Api()
        r = api.compare_scans(sidA, sidOther)
        assert r["ok"] is True
        assert r["available"] is False
    finally:
        os.remove(tmp)


def test_findings_matrix_api_ok():
    tmp = _tmp_db()
    try:
        _, sid = _add_scan()
        dbmod.add_finding(sid, "XSS", "x", "High", "d", "e", "r",
                          "http://x/a", endpoint="http://x/a")
        api = app_api.Api()
        r = api.findings_matrix(sid)
        assert r["ok"] is True
        assert r["total"] == 1
        assert r["cells"]["http://x/a"]["XSS"]["risk"] == "High"
        # 不存在的扫描返回 E_NOT_FOUND
        r2 = api.findings_matrix(999999)
        assert r2["ok"] is False
        assert r2["code"] == "E_NOT_FOUND"
    finally:
        os.remove(tmp)
