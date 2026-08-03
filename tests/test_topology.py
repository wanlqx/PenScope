"""F-07 资产拓扑测试：build_topology 聚合（临时 DB）。

覆盖：目标/子域/端口节点与资产层级边、host 风险聚合、漏洞链 finding 节点与链边生成。
遵循项目约定：临时 DB 单测用 _tmp_db() 覆盖 config.DB_PATH / db.DB_PATH，finally 中 os.remove。
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as cfg
import db as dbmod
import topology
from db import (
    add_target, approve_target, create_scan, update_scan,
    add_finding, findings_of,
)


def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    cfg.DB_PATH = path
    dbmod.DB_PATH = path
    dbmod.init_db()
    return path


def _rm(path):
    # Windows WAL 模式下，最后一个连接关闭后 -wal/-shm 句柄可能短暂滞留，
    # 直接 os.remove 会触发 WinError 32；重试几次即可安全删除临时 DB。
    import time
    for _ in range(20):
        try:
            os.remove(path)
            return
        except (PermissionError, OSError):
            time.sleep(0.05)
    try:
        os.remove(path)
    except (PermissionError, OSError):
        pass


def _set_target_fields(tid, ports, subdomains, tags=None):
    # 端口 / 子域来自资产基线（与 build_topology 读取来源一致）
    from db import capture_baseline
    capture_baseline(tid, {"ports": ports, "subdomains": subdomains})
    if tags is not None:
        from db import set_target_tags
        set_target_tags(tid, tags)


def _mk_scan_with_findings(tid, findings):
    """创建并完成一次扫描，写入若干发现，返回 scan_id。"""
    sid = create_scan(tid, "scan-%d" % tid, "tester")
    update_scan(sid, status="completed", finished_at=dbmod._now())
    for f in findings:
        add_finding(sid, f["category"], f.get("title", f["category"]), f["risk"],
                    f.get("detail", ""), f.get("evidence", ""), f.get("remediation", ""),
                    f.get("target_ref", ""))
    return sid


def test_topology_asset_nodes_and_edges():
    path = _tmp_db()
    try:
        tid = add_target("example.com", "443", "note", "auth", "tester")
        approve_target(tid, "tester")
        _set_target_fields(tid, ["443", "8080"], ["api.example.com"], tags=["prod"])
        # 目标级发现（target_ref 为空 → 计入 target 节点）
        _mk_scan_with_findings(tid, [
            {"category": "SQL注入", "risk": "high", "target_ref": "http://example.com/a"},
            # 子域级发现（target_ref 含子域 → 计入 host 节点）
            {"category": "XSS", "risk": "medium", "target_ref": "http://api.example.com/login"},
        ])
        topo = topology.build_topology()
        ids = {n["id"] for n in topo["nodes"]}
        assert "t:%d" % tid in ids
        assert "h:%d:api.example.com" % tid in ids
        assert "p:%d:443" % tid in ids
        assert "p:%d:8080" % tid in ids
        # 资产层级边：target→host、target→port
        asset_edges = [e for e in topo["edges"] if e["kind"] == "asset"]
        pairs = {(e["source"], e["target"]) for e in asset_edges}
        assert ("t:%d" % tid, "h:%d:api.example.com" % tid) in pairs
        assert ("t:%d" % tid, "p:%d:443" % tid) in pairs
        # target 节点携带发现数与最高风险
        tnode = next(n for n in topo["nodes"] if n["id"] == "t:%d" % tid)
        assert tnode["findingCount"] == 1
        assert tnode["maxRisk"] == "high"
        assert tnode["tags"] == ["prod"]
        # host 节点风险
        hnode = next(n for n in topo["nodes"] if n["id"] == "h:%d:api.example.com" % tid)
        assert hnode["findingCount"] == 1
        assert hnode["maxRisk"] == "medium"
    finally:
        _rm(path)


def test_topology_chain_nodes_and_edges():
    path = _tmp_db()
    try:
        tid = add_target("shop.test", "80", "note", "auth", "tester")
        approve_target(tid, "tester")
        _set_target_fields(tid, ["80"], [])
        # SQL注入(trigger) + 敏感信息泄露(support) → CHAIN-SQLI-EXFIL
        _mk_scan_with_findings(tid, [
            {"category": "SQL注入", "risk": "high", "target_ref": "http://shop.test/p"},
            {"category": "敏感信息泄露", "risk": "medium", "target_ref": "http://shop.test/p"},
        ])
        topo = topology.build_topology()
        chain_edges = [e for e in topo["edges"] if e["kind"] == "chain"]
        assert len(chain_edges) >= 1, "应生成至少一条漏洞链边"
        assert chain_edges[0]["chain"] == "SQL注入 → 敏感数据提取"
        # 链涉及的两个发现应作为 finding 节点存在
        fnode_ids = {n["id"] for n in topo["nodes"] if n["type"] == "finding"}
        # finding 节点 id = f:<finding_id>
        fs = findings_of(_last_scan(tid))
        fids = {"f:%s" % f["id"] for f in fs}
        assert fids.issubset(fnode_ids)
    finally:
        _rm(path)


def _last_scan(tid):
    scans = dbmod.scans_of_target(tid)
    return max(scans, key=lambda s: s["id"])["id"]


def test_topology_empty():
    path = _tmp_db()
    try:
        topo = topology.build_topology()
        assert topo["nodes"] == []
        assert topo["edges"] == []
    finally:
        _rm(path)
