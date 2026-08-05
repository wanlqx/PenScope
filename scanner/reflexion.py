# -*- coding: utf-8 -*-
"""PenScope —— Reflexion 自检层（G-02）

扫描完成后，对所有「高证据」发现（evidence_level ∈ {L3, L4} 或 verification_status=verified）
做**独立二次复核**——类比补天工作流的"三路收敛复现"。每个发现用独立 session 重发其
endpoint 的 GET 请求，与软 404 基线 / 拒绝页 / 错误页 / 状态码比对：

- 3xx 重定向        → 访问实际受控（跳登录等）→ 降级
- 404 / 5xx         → 当前不可达，原高证据可能基于 transient 状态 → 降级
- 200 且软 404      → 原判定基于错误页回显 → 降级
- 200 且拒绝/登录页 → 访问实际受控 → 降级
- 200 且错误页      → 非真实内容 → 降级
- 200 且正常        → 保留（附加 reflexion 通过标记）
- 400/401/403/405/429 → 保守保留（GET 不被允许/需认证，不贸然降级）

降级 = evidence_level→L2 + verification_status→unverified + detail 追加 reflexion 说明
（**保守不剔除**，因目标可能临时变化，保留供人工裁决；仅当确认无任何证据才剔除——本层不做剔除）。

设计原则：只读 GET，allow_redirects=False，不写入/不爆破；独立 session 模拟"另一客户端"
（不同 UA），规避同一会话 cookie/缓存带来的偏见。纯逻辑（_decide）与 db 读写（review_scan）
分离，便于单测。
"""
import re
from urllib.parse import urlparse

import requests

from scanner import fp_guard

# 仅复核这些证据等级 / 状态（注入点 L1 观察类不在范围）
_REVIEW_EVIDENCE_LEVELS = ("L3", "L4")
_REVIEW_STATUS = ("verified",)

# endpoint 须是 http(s):// 才做 GET 复核；纯参数/表单类（需重放 payload）保守保留
_URL_RE = re.compile(r"^https?://")


def _extract_review_url(finding):
    """从发现中提取待复核的 URL（优先 endpoint，其次从 poc 的 curl URL 解析）。"""
    ep = finding.get("endpoint") or ""
    if _URL_RE.match(ep):
        return ep.split("#")[0]
    poc = finding.get("poc") or ""
    m = re.search(r"https?://[^\s'\"\\]+", poc)
    if m:
        return m.group(0).rstrip("'\"\\")
    return None


def _decide(finding, session, verify_ssl, timeout):
    """对单个高证据发现独立复核，返回 (verdict, reason)。verdict ∈ keep/downgrade。"""
    url = _extract_review_url(finding)
    if not url:
        # 无法提取 URL（如纯表单 action 需重放 payload）→ 保守保留
        return "keep", "no_reviewable_url"
    try:
        r = session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
    except Exception as e:
        # 网络/解析异常无法复核 → 保守保留（不降级，因可能是临时问题）
        return "keep", f"request_error:{type(e).__name__}"

    code = r.status_code
    # 重定向（多为跳登录）= 访问受控 → 降级
    if 300 <= code < 400:
        return "downgrade", f"redirected_{code}"
    # 404 / 5xx = 当前不可达或错误 → 降级
    if code in (404, 410, 500, 502, 503, 504):
        return "downgrade", f"status_now_{code}"
    # 400/401/403/405/429 = GET 不被允许/需认证 → 保守保留
    if code in (400, 401, 403, 405, 429):
        return "keep", f"conservative_status_{code}"
    # 其余（含 200）→ 继续软 404 / 拒绝页 / 错误页判定
    text = r.text or ""
    root = urlparse(url)._replace(path="/", query="", fragment="").geturl()
    baseline = fp_guard.baseline_probe(session, root, verify_ssl, timeout)
    if fp_guard.soft404_filter(text, baseline):
        return "downgrade", "soft404_now"
    if fp_guard.is_denied_page(text):
        return "downgrade", "denied_page_now"
    if fp_guard.is_error_page(text):
        return "downgrade", "error_page_now"
    return "keep", "pass"


def review_scan(scan_id, session=None, verify_ssl=True, timeout=6.0, audit=None):
    """对 scan 的全部高证据发现做 reflexion 二次复核，降级误报。返回统计 dict。

    session: 复用主扫描 session；为 None 时新建独立 session（不同 UA）。
    audit:   可选审计回调 audit(action, target, note)，不传则静默。
    """
    from db import findings_of, update_finding_fields

    if session is None:
        session = requests.Session()
        session.headers.update({"User-Agent": "PenScope-Reflexion/1.0 (independent recheck)"})

    findings = findings_of(scan_id)
    reviewed = downgraded = 0
    log = []
    for f in findings:
        el = f.get("evidence_level") or "L1"
        vs = f.get("verification_status") or ""
        if el not in _REVIEW_EVIDENCE_LEVELS and vs not in _REVIEW_STATUS:
            continue
        reviewed += 1
        verdict, reason = _decide(f, session, verify_ssl, timeout)
        if verdict == "downgrade":
            downgraded += 1
            note = (f"[Reflexion 自检降级] 原 {el}/{vs} 发现经独立复核判定为疑似误报 "
                    f"（{reason}），已降级为 L2/unverified，保留供人工裁决。")
            new_detail = (f.get("detail") or "") + "\n" + note
            update_finding_fields(
                f["id"],
                detail=new_detail,
                verification_status="unverified",
                evidence_level="L2",
            )
            log.append({"id": f["id"], "title": f["title"], "reason": reason})
            if audit:
                audit("reflexion_downgrade",
                      f.get("endpoint") or f.get("target_ref") or "",
                      f"#{f['id']} {f['title']} -> {reason}")
    return {"reviewed": reviewed, "downgraded": downgraded, "log": log}
