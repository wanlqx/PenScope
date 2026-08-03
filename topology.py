"""F-07 资产拓扑可视化：从目标 / 子域 / 端口 / 发现 / 漏洞链聚合出拓扑图数据。

设计原则：
- 纯只读、基于已有库数据做聚合，不发起任何新请求；
- 节点类型：target（根）/ host（子域）/ port（开放端口）/ finding（漏洞链中的发现）；
- 边类型：asset（资产层级，实线：target→host、target→port、host/finding 挂载）/ chain（漏洞利用链，虚线）；
- 每个 host 节点携带其范围内发现的最高风险与数量，作为「暴露面风险热图」；
- 链路边仅在存在漏洞链时生成，前端可开关。

该模块只依赖 db / chain，便于单测（临时 DB + 直接调用 build_topology）。
"""
import json

from db import list_targets, scans_of_target, findings_of_target, findings_of, get_baseline
from chain import analyze_chains

_RISK_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
              "": 0, None: 0}
_RISK_ORDER = ["info", "low", "medium", "high", "critical"]


def _json_list(v):
    """把 DB 中的 TEXT(JSON) 或已是 list 的值统一成 list。"""
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return []
        try:
            x = json.loads(s)
            return x if isinstance(x, list) else [s]
        except (ValueError, TypeError):
            return [s]
    return [v]


def _max_risk(risks):
    best, best_rank = "", -1
    for r in risks:
        rk = _RISK_RANK.get((r or "").lower(), 0)
        if rk > best_rank:
            best_rank, best = rk, (r or "")
    return best


def _host_key(ref, host, subs):
    """将发现的 target_ref 归一化到「目标根」或「某个子域」节点。
    ref 可能是完整 URL 或裸 host；命中子域优先子域，否则回落目标根。
    subs 为已解析的子域列表（来自资产基线，targets 行本身不含该列）。"""
    ref_l = (ref or "").lower()
    host_l = (host or "").lower().strip()
    for s in subs:
        if s and s in ref_l:
            return "h", s
    if host_l and host_l in ref_l:
        return "t", host_l
    return "t", host_l


def build_topology():
    """返回全量资产拓扑：{"nodes": [...], "edges": [...]}。

    节点字段：
      target: id, type, label, tags, maxRisk, findingCount, status
      host:   id, type, label, parent, maxRisk, findingCount
      port:   id, type, label, parent
      finding: id, type, label, risk, parent, findingId
    边字段：
      asset: {source, target, kind:"asset"}
      chain: {source, target, kind:"chain", chain}
    """
    targets = list_targets()
    nodes, edges = [], []
    seen = set()

    def add(node):
        if node["id"] not in seen:
            seen.add(node["id"])
            nodes.append(node)

    for t in targets:
        tid = t["id"]
        host = (t.get("host") or "").strip()
        # 端口 / 子域来自资产基线（扫描后采集的当前暴露面快照），targets 表本身不含这两列。
        bl = get_baseline(tid) or {}
        ports = [str(p).strip() for p in _json_list(bl.get("ports")) if str(p).strip()]
        subs = [str(s).strip() for s in _json_list(bl.get("subdomains")) if str(s).strip()]
        findings = findings_of_target(tid)

        # 按 host 节点聚合发现风险
        by_host = {}
        for f in findings:
            kind, key = _host_key(f.get("target_ref"), host, subs)
            by_host.setdefault((kind, key), []).append(f)

        # 目标根节点（含「挂在目标本身」的发现：target_ref 为空或等于 host）
        tkey = ("t", host)
        tf = by_host.get(tkey, [])
        add({
            "id": "t:%d" % tid, "type": "target", "label": host or ("#%d" % tid),
            "tags": t.get("tags") or [], "maxRisk": _max_risk([f["risk"] for f in tf]),
            "findingCount": len(tf), "status": t.get("status"),
        })

        # 子域 host 节点
        for sub in subs:
            sf = by_host.get(("h", sub), [])
            hid = "h:%d:%s" % (tid, sub)
            add({
                "id": hid, "type": "host", "label": sub, "parent": "t:%d" % tid,
                "maxRisk": _max_risk([f["risk"] for f in sf]), "findingCount": len(sf),
            })
            edges.append({"source": "t:%d" % tid, "target": hid, "kind": "asset"})

        # 端口节点（仅目标级端口，子域端口未知不臆造）
        for p in ports:
            pid = "p:%d:%s" % (tid, p)
            add({"id": pid, "type": "port", "label": p, "parent": "t:%d" % tid})
            edges.append({"source": "t:%d" % tid, "target": pid, "kind": "asset"})

    # 漏洞链：取每个目标最近一次 completed 扫描的分析结果，作为 finding 节点 + 链边
    for t in targets:
        tid = t["id"]
        host = (t.get("host") or "").strip()
        scans = scans_of_target(tid)
        completed = [s for s in scans if s.get("status") == "completed"]
        if not completed:
            continue
        latest = max(completed, key=lambda s: s.get("id", 0))
        fs = findings_of(latest["id"])
        chains = analyze_chains(fs)
        for ch in chains:
            prev = None
            for fid in (ch.get("finding_ids") or []):
                fmeta = next((f for f in fs if f.get("id") == fid), None)
                if not fmeta:
                    continue
                kind, key = _host_key(fmeta.get("target_ref"), host, subs)
                parent = ("h:%d:%s" % (tid, key)) if kind == "h" else ("t:%d" % tid)
                fnode = "f:%s" % fid
                add({
                    "id": fnode, "type": "finding", "label": fmeta.get("category") or "finding",
                    "risk": fmeta.get("risk"), "parent": parent, "findingId": fid,
                })
                edges.append({"source": parent, "target": fnode, "kind": "asset"})
                if prev is not None:
                    edges.append({"source": prev, "target": fnode,
                                  "kind": "chain", "chain": ch.get("name")})
                prev = fnode

    return {"nodes": nodes, "edges": edges}
