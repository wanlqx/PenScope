"""F-08：扫描器插件化框架单元测试。

覆盖：BaseScanner 抽象约束、ScanContext 受限上下文转发、load_plugins 发现内置示例（含缓存）、
以及 run_plugin_scanners 端到端集成（借助临时 DB + 假 session，验证示例插件产出发现）。
不依赖真实网络 / GUI。
"""
import os
import tempfile

import config as cfg
import db as dbmod
import run_scans as rs
from scanner.plugin_base import BaseScanner, ScanContext


class _FakeResp:
    def __init__(self, headers=None):
        self.headers = headers or {}


class _FakeSession:
    def get(self, url, **kw):
        return _FakeResp(headers={})  # 不含任何安全头 -> 示例插件应产出 3 条发现


def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    dbmod.DB_PATH = path
    try:
        dbmod._conn.cache_clear()
    except Exception:
        pass
    dbmod.init_db()
    return path


def _make_scan():
    tid = dbmod.add_target("1.2.3.4", "common", "", "auth", "me")
    dbmod.approve_target(tid, "me")
    sid = dbmod.create_scan(tid, "t", "me")
    dbmod.update_scan(sid, status="running")
    return dbmod.get_scan(sid)


def test_base_scanner_cannot_instantiate_without_scan():
    class Bad(BaseScanner):
        pass
    try:
        Bad()
        assert False, "未实现 scan() 的子类应无法实例化"
    except TypeError:
        pass


def test_scan_context_forwards_add_finding():
    recorded = {}

    def fake_add(scan_id, category, title, risk, detail, poc, remediation, target_ref, **kw):
        recorded.update(scan_id=scan_id, category=category, title=title)
        return 1

    def fake_audit(created_by, action, target, note):
        recorded["audit"] = (action, target)

    ctx = ScanContext(99, {"url": "http://x/"}, None, False, fake_add, fake_audit, created_by="me")
    ctx.add_finding("C", "T", "Info", "D", "", "R", "http://x/")
    assert recorded["scan_id"] == 99
    assert recorded["category"] == "C"
    ctx.audit("act", "tgt", "note")
    assert recorded["audit"] == ("act", "tgt")


def test_load_plugins_returns_example_and_caches():
    insts = rs.load_plugins(force=True)
    names = [getattr(p, "name", "") for p in insts]
    assert "example-security-headers" in names
    again = rs.load_plugins()
    assert again is insts  # 缓存：同一对象


def test_run_plugin_scanners_adds_findings():
    tmp = _tmp_db()
    try:
        scan = _make_scan()
        wt = {"url": "http://1.2.3.4/", "server": "", "title": ""}
        before = len(dbmod.findings_of(scan["id"]))
        rs.run_plugin_scanners(scan, _FakeSession(), False, wt)
        after = dbmod.findings_of(scan["id"])
        # 示例插件整合为单条「安全响应头缺失」发现（host 去重会把结构相同的多条合并，
        # 故断言>=1 且类别正确，并验证其详情确实报告了缺失头）。
        assert len(after) >= before + 1, "示例插件应至少产出 1 条发现"
        fh = [f for f in after if f["category"] == "安全响应头缺失"]
        assert fh, "应产出「安全响应头缺失」类别发现"
        assert "Strict-Transport-Security" in fh[0]["detail"], "发现详情应列出缺失的具体安全头"
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def test_run_plugin_scanners_disabled_is_noop():
    tmp = _tmp_db()
    prev = cfg.ENABLE_PLUGINS
    cfg.ENABLE_PLUGINS = False
    try:
        scan = _make_scan()
        wt = {"url": "http://1.2.3.4/", "server": "", "title": ""}
        before = len(dbmod.findings_of(scan["id"]))
        rs.run_plugin_scanners(scan, _FakeSession(), False, wt)
        assert len(dbmod.findings_of(scan["id"])) == before, "关闭开关后不应产出任何插件发现"
    finally:
        cfg.ENABLE_PLUGINS = prev
        try:
            os.remove(tmp)
        except OSError:
            pass
