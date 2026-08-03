"""资产变更告警引擎（F-05）。

职责：
1. 维护每个目标的资产基线（指纹 / 标题 / 关键响应头 / 端口 / 子域）。
2. 对比相邻两次快照，输出结构化变更记录（纯函数，便于单元测试）。
3. 在扫描完成后调用 check_and_apply_baseline：读旧基线 → 比对 → 写新基线 →
   返回变更；由调用方（run_scans）按设置决定是否通知 / 自动增量扫描。

设计要点：
- 首次建立基线不算「变更」，不告警（避免上线即轰炸）。
- 集合型字段（headers/ports/subdomains）按增删分别报；标量字段（fingerprint/
  title）按是否不同报。
- 不引入网络 / 扫描逻辑，仅做数据比对，保证可测试与无副作用。
"""

import json

# 标量字段：值不同即视为变更
_SCALAR_FIELDS = ("fingerprint", "title")
# 集合字段：按元素增删分别报
_SET_FIELDS = ("headers", "ports", "subdomains")

# 字段中文名（通知/报告展示）
_FIELD_CN = {
    "fingerprint": "Web 指纹",
    "title": "页面标题",
    "headers": "响应头",
    "ports": "开放端口",
    "subdomains": "子域",
}


def _as_set(v):
    if v is None:
        return set()
    if isinstance(v, (list, tuple, set)):
        return set(str(x).strip() for x in v if str(x).strip())
    return set(str(v).strip().splitlines())


def normalize_snapshot(snapshot):
    """规整快照：确保集合字段为 list（可 JSON 序列化）、标量字段为 str。"""
    out = dict(snapshot or {})
    for f in _SET_FIELDS:
        out[f] = sorted(_as_set(out.get(f))) if out.get(f) is not None else []
    for f in _SCALAR_FIELDS:
        out[f] = ("" if out.get(f) is None else str(out.get(f))).strip()
    return out


def diff_asset_snapshot(old, new):
    """对比两个基线快照，返回变更记录列表。

    每个变更记录形如：
      {"type": "scalar_changed", "field": "title", "old": "...", "new": "..."}
      {"type": "added",  "field": "ports", "value": "8080"}
      {"type": "removed","field": "ports", "value": "3306"}
    首次（old 为 None）返回 []（建立基线，不告警）。
    """
    if old is None:
        return []
    new = normalize_snapshot(new)
    old_n = normalize_snapshot(old)
    changes = []
    for f in _SCALAR_FIELDS:
        ov, nv = old_n.get(f, ""), new.get(f, "")
        if ov != nv:
            changes.append({"type": "scalar_changed", "field": f,
                            "old": ov, "new": nv})
    for f in _SET_FIELDS:
        oset, nset = _as_set(old_n.get(f)), _as_set(new.get(f))
        for v in sorted(nset - oset):
            changes.append({"type": "added", "field": f, "value": v})
        for v in sorted(oset - nset):
            changes.append({"type": "removed", "field": f, "value": v})
    return changes


def check_and_apply_baseline(target_id, new_snapshot):
    """读旧基线、比对、写新基线，返回 (old_baseline, changes)。

    调用方应据此决定是否通知/自动扫描。无 DB 依赖之外的副作用。
    依赖 db.capture_baseline / db.get_baseline（延迟 import 以避免循环）。
    """
    from db import get_baseline, capture_baseline
    old = get_baseline(target_id)
    changes = diff_asset_snapshot(old, new_snapshot)
    snap = normalize_snapshot(new_snapshot)
    if changes:
        snap["last_change"] = changes
        snap["last_change_at"] = _now()
    capture_baseline(target_id, snap)
    return old, changes


def _now():
    import datetime
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def format_changes(host, changes):
    """把变更记录渲染为单行通知文本（桌面气泡用）。"""
    if not changes:
        return ""
    parts = []
    for c in changes:
        cn = _FIELD_CN.get(c["field"], c["field"])
        if c["type"] == "scalar_changed":
            parts.append(f"{cn} 变化：{c['old'] or '(空)'} → {c['new'] or '(空)'}")
        elif c["type"] == "added":
            parts.append(f"{cn} 新增：{c['value']}")
        elif c["type"] == "removed":
            parts.append(f"{cn} 消失：{c['value']}")
    return f"[{host}] 资产变更 {len(changes)} 项：" + "；".join(parts)


def changes_to_html(changes):
    """把变更记录渲染为 HTML 片段（目标中心展示用），无变更返回空串。"""
    if not changes:
        return ""
    rows = []
    for c in changes:
        cn = _FIELD_CN.get(c["field"], c["field"])
        if c["type"] == "scalar_changed":
            badge = "变化"
            detail = f"<code>{_esc(c['old'] or '(空)')}</code> → <code>{_esc(c['new'] or '(空)')}</code>"
        elif c["type"] == "added":
            badge = "新增"
            detail = f"<code>{_esc(c['value'])}</code>"
        else:
            badge = "消失"
            detail = f"<code>{_esc(c['value'])}</code>"
        rows.append(
            f'<div class="li"><span class="tag chip on">{_esc(badge)}</span> '
            f'<b>{_esc(cn)}</b> {detail}</div>'
        )
    return "".join(rows)


def _esc(s):
    import html
    return html.escape(str(s))
