# -*- coding: utf-8 -*-
"""PenScope —— 启发式路由调度层（P4 固化胜者 B 的 skill 路由）。

设计原则（对齐用户强偏好：广覆盖 + 最快解题时延 + 零误报）：
- 零误报优先：路由层**只重排模块优先级、条件跳过明确无注入面的高级模块**，
  绝不盲目跳过可能导致漏报的通用模块。
- 基于单页探测信号（一次只读 GET）决定哪些高级注入模块优先 / 跳过。
- 与 fp_guard（短 TTL 内存基线）解耦：本层是调度决策，不触碰判定逻辑。
"""
import logging
import re
from urllib.parse import urlparse, parse_qs

_log = logging.getLogger("PenScope.router")

CAT_SSTI = "SSTI"
CAT_XXE = "XXE"
CAT_JWT = "JWT算法混淆"
CAT_NOSQL = "NoSQL注入"
CAT_IDOR = "IDOR"

# 高级注入类（依赖真实内容可达；已知噪声页可安全跳过，不引入漏报）
ADV_CATS = (CAT_SSTI, CAT_XXE, CAT_JWT, CAT_NOSQL, CAT_IDOR)

_TEMPLATE_ERR_MARKERS = (
    "jinja2.exceptions", "django.template", "twig error",
    "tornado.template", "template syntax error", "freemarker",
    "velocity exception", "mustache",
)
_JWT_RE = re.compile(r"eyj[a-z0-9_=-]+\.eyj[a-z0-9_=-]+\.[a-z0-9_=-]*", re.I)
_OBJ_ID_PARAMS = ("id", "uid", "user_id", "order_id", "oid", "docid", "fileid")


def probe_signals(session, page, verify_ssl=True, timeout=6.0):
    """对 page 发一次只读 GET（Range 头部截断下载），提取路由信号。

    返回 dict：content_type / has_jwt / template_err / object_id / json_api。
    任何异常都安全降级为「无信号」（不影响原扫描流程）。
    """
    sig = {"content_type": "", "has_jwt": False,
           "template_err": False, "object_id": False, "json_api": False}
    try:
        r = session.get(page, timeout=timeout, verify=verify_ssl,
                        allow_redirects=False,
                        headers={"Range": "bytes=0-2048"})
        ct = (r.headers.get("Content-Type") or "").lower()
        sig["content_type"] = ct
        body = (r.text or "")[:4096].lower()
        cookie = (r.headers.get("Set-Cookie") or "").lower()
        if _JWT_RE.search(cookie + body):
            sig["has_jwt"] = True
        if any(m in body for m in _TEMPLATE_ERR_MARKERS):
            sig["template_err"] = True
        q = parse_qs(urlparse(page).query)
        if any(k in q for k in _OBJ_ID_PARAMS):
            sig["object_id"] = True
        if "json" in ct or "/api" in page.lower():
            sig["json_api"] = True
    except Exception as e:
        _log.debug("probe_signals failed for %s: %s", page, e)
    return sig


def plan(signals, base_order):
    """根据信号对 base_order（category 列表）重排。返回新列表（不删项，零误报优先）。

    提升信号命中的高级模块排到前面，使最可能命中的先出结果（最快解题时延 L1）；
    其余保持原序。绝不移除任何模块 —— 覆盖优先于时延。
    """
    boosts = []
    ct = signals.get("content_type", "")
    if "xml" in ct:
        boosts.append(CAT_XXE)
    if signals.get("has_jwt"):
        boosts.append(CAT_JWT)
    if signals.get("template_err"):
        boosts.append(CAT_SSTI)
    if signals.get("object_id"):
        boosts.append(CAT_IDOR)
    if signals.get("json_api"):
        boosts.append(CAT_NOSQL)
    boosted = [c for c in boosts if c in base_order]
    rest = [c for c in base_order if c not in boosted]
    return boosted + rest
