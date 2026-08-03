import importlib

import config as _cfg
import db as _db


def test_db_stats_counts(monkeypatch, tmp_path):
    # 保存原始 DB_PATH，测试结束后还原，避免 reload 污染同一会话内的其它用例
    orig_cfg_path = _cfg.DB_PATH
    orig_db_path = _db.DB_PATH
    try:
        # 使用独立临时 DB，确保不会碰触开发者本地数据库
        db_file = tmp_path / "autopentest_test.db"
        monkeypatch.setenv("AUTOPENTEST_DB", str(db_file))
        # reload config to pick up env override
        importlib.reload(_cfg)
        importlib.reload(_db)

        # initialize DB
        _db.init_db()

        # create a target, scan, and a fixed finding
        tid = _db.add_target("127.0.0.1", "common", "", "local confirmation", "tester", verify_tls=1)
        sid = _db.create_scan(tid, "smoke", "tester")
        conn = _db._conn()
        conn.execute(
            "INSERT INTO findings (scan_id, category, title, risk, created_at, fix_status) VALUES (?,?,?,?,?,?)",
            (sid, "Info", "t", "Info", _db._now(), "fixed"),
        )
        conn.commit()
        conn.close()

        stats = _db.db_stats()
        assert stats["targets"] >= 1
        assert stats["scans"] >= 1
        assert stats["findings"] >= 1
        assert stats["findings_done"] >= 1
    finally:
        _cfg.DB_PATH = orig_cfg_path
        _db.DB_PATH = orig_db_path
