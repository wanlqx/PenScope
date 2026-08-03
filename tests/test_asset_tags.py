"""v1.14.0 目标标签分组（F-06）单元测试

覆盖：
  - set_target_tags 规范化：去空白 / 去空 / 去重 / 限长(≤32) / 限数(≤20)，返回生效列表
  - get_target_tags 升序返回
  - list_target_tags 计数：按数量降序、标签升序
  - list_targets / get_target 携带 tags 字段
  - delete_target / trash_target 级联清除 target_tags
全部使用 temp DB（沿用 test_scan_archival 的 _tmp_db 约定），finally 删除。
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


def _add_target(host="1.1.1.1"):
    return dbmod.add_target(host, "common", "", "auth", "me")


def test_set_target_tags_normalizes_dedup_strip_empty():
    tmp = _tmp_db()
    try:
        tid = _add_target()
        out = dbmod.set_target_tags(tid, [" web", "web", "", "  ", "api", "web "])
        # 去空白 + 去重 + 去空，保留首次出现顺序
        assert out == ["web", "api"]
    finally:
        os.remove(tmp)


def test_set_target_tags_truncates_long_tag():
    tmp = _tmp_db()
    try:
        tid = _add_target()
        long_tag = "x" * 40
        out = dbmod.set_target_tags(tid, [long_tag])
        assert len(out) == 1
        assert len(out[0]) == 32          # 超长被截断到 32
        assert out[0] == "x" * 32
    finally:
        os.remove(tmp)


def test_set_target_tags_limits_count_to_20():
    tmp = _tmp_db()
    try:
        tid = _add_target()
        many = ["tag%02d" % i for i in range(25)]   # 25 个唯一标签
        out = dbmod.set_target_tags(tid, many)
        assert len(out) == 20                        # 超限只保留前 20
    finally:
        os.remove(tmp)


def test_get_target_tags_sorted():
    tmp = _tmp_db()
    try:
        tid = _add_target()
        dbmod.set_target_tags(tid, ["c", "a", "b"])
        assert dbmod.get_target_tags(tid) == ["a", "b", "c"]   # 升序
    finally:
        os.remove(tmp)


def test_list_target_tags_counts_sorted():
    tmp = _tmp_db()
    try:
        t1 = _add_target("1.1.1.1")
        t2 = _add_target("1.1.1.2")
        dbmod.set_target_tags(t1, ["web", "api"])
        dbmod.set_target_tags(t2, ["web"])
        tags = dbmod.list_target_tags()
        # 按数量降序（web=2, api=1），同数按标签升序
        assert tags == [{"tag": "web", "count": 2}, {"tag": "api", "count": 1}]
    finally:
        os.remove(tmp)


def test_list_targets_includes_tags():
    tmp = _tmp_db()
    try:
        tid = _add_target()
        dbmod.set_target_tags(tid, ["dmz"])
        rows = dbmod.list_targets()
        matched = [r for r in rows if r["id"] == tid]
        assert matched, "目标应出现在列表"
        assert matched[0]["tags"] == ["dmz"]
    finally:
        os.remove(tmp)


def test_get_target_includes_tags():
    tmp = _tmp_db()
    try:
        tid = _add_target()
        dbmod.set_target_tags(tid, ["prod", "critical"])
        t = dbmod.get_target(tid)
        assert t is not None
        assert sorted(t["tags"]) == ["critical", "prod"]
    finally:
        os.remove(tmp)


def test_delete_target_cascades_tags():
    tmp = _tmp_db()
    try:
        tid = _add_target()
        dbmod.set_target_tags(tid, ["web", "api"])
        assert dbmod.delete_target(tid) >= 1
        assert dbmod.get_target_tags(tid) == []
        assert dbmod.list_target_tags() == []
    finally:
        os.remove(tmp)


def test_trash_target_cascades_tags():
    tmp = _tmp_db()
    try:
        tid = _add_target()
        dbmod.set_target_tags(tid, ["web"])
        token = dbmod.trash_target(tid)
        assert token is not None
        assert dbmod.get_target_tags(tid) == []
        assert dbmod.list_target_tags() == []
    finally:
        os.remove(tmp)
