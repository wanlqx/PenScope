"""v1.10.0 数据归档（P-04）单元测试

覆盖：
  - set_scan_archived 单条归档/取消，归档后 list_scans 默认隐藏、include_archived 可显
  - archive_scans_before 按日期批量归档（仅 completed 且未归档且 finished_at 早于截止）
  - 非 completed / 无 finished_at 的扫描不被归档
全部使用 temp DB（沿用 test_scan_observability 的 _tmp_db 约定），finally 删除。
"""
import os
import tempfile

import config
import db as dbmod


def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    config.DB_PATH = path
    dbmod.DB_PATH = path
    dbmod.init_db()
    return path


def _add_scan(target_host="1.1.1.1", status="completed", finished_at="2024-01-01T00:00:00"):
    tid = dbmod.add_target(target_host, "common", "", "auth", "me")
    dbmod.approve_target(tid, "me")
    sid = dbmod.create_scan(tid, "t", "me")
    dbmod.update_scan(sid, status=status, finished_at=finished_at)
    return tid, sid


def test_set_scan_archived_hides_from_default_list():
    tmp = _tmp_db()
    try:
        _, sid = _add_scan()
        assert any(s["id"] == sid for s in dbmod.list_scans(50))           # 默认可见
        assert dbmod.set_scan_archived(sid, 1) is True
        assert not any(s["id"] == sid for s in dbmod.list_scans(50))      # 默认隐藏
        assert any(s["id"] == sid for s in dbmod.list_scans(50, include_archived=True))  # 含归档可见
        assert dbmod.set_scan_archived(sid, 0) is True
        assert any(s["id"] == sid for s in dbmod.list_scans(50))          # 取消归档后重新可见
    finally:
        os.remove(tmp)


def test_archive_scans_before_only_old_completed():
    tmp = _tmp_db()
    try:
        # 旧 + 已完成 => 应被归档
        _, old = _add_scan("1.1.1.1", "completed", "2020-01-01T00:00:00")
        # 新 + 已完成 => 不应被归档
        _, new = _add_scan("1.1.1.2", "completed", "2099-01-01T00:00:00")
        # 旧 + 未完成 => 不应被归档
        _, running = _add_scan("1.1.1.3", "running", "2020-01-01T00:00:00")
        n = dbmod.archive_scans_before("2023-01-01T00:00:00")
        assert n == 1
        ids = {s["id"] for s in dbmod.list_scans(50, include_archived=True)}
        assert old in ids and new in ids and running in ids
        archived_ids = {s["id"] for s in dbmod.list_scans(50, include_archived=True) if s["archived"] == 1}
        assert archived_ids == {old}
    finally:
        os.remove(tmp)


def test_archive_scans_before_scoped_to_target():
    tmp = _tmp_db()
    try:
        tid_a, sa = _add_scan("1.1.1.1", "completed", "2020-01-01T00:00:00")
        tid_b, sb = _add_scan("2.2.2.2", "completed", "2020-01-01T00:00:00")
        n = dbmod.archive_scans_before("2023-01-01T00:00:00", target_id=tid_a)
        assert n == 1
        archived = {s["id"] for s in dbmod.list_scans(50, include_archived=True) if s["archived"] == 1}
        assert archived == {sa}   # 仅目标 A 的旧扫描被归档
    finally:
        os.remove(tmp)


def test_set_scan_archived_unknown_returns_false():
    tmp = _tmp_db()
    try:
        assert dbmod.set_scan_archived(99999, 1) is False
    finally:
        os.remove(tmp)
