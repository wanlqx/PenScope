# -*- coding: utf-8 -*-
"""PenScope —— 统一误报门控层（False-Positive Guard，G-01）

把散落在 access_control / contentscan / ssrf 三处的重复降噪逻辑
（Jaccard 相似度、拒绝关键词、错误页关键词、404 基线探针）抽到单一来源，
避免三套不一致的实现（连基线 nonce 都各不相同）继续漂移。

提供：
- similarity(a, b): token Jaccard 文本相似度（识别软 404）
- DENIED_MARKERS / ERROR_PAGE_MARKERS: 拒绝页 / 错误页关键词
- PUBLIC_PATHS / is_public_path(): 本就应对外公开的路径白名单
- baseline_probe(session, root, ...): 取「确定不存在」路径响应作软 404 基线（带 TTL 缓存）
- soft404_filter(text, baseline): 与基线高度相似 → True（应排除）
- is_denied_page(text): 正文含拒绝/登录关键词 → True
- is_error_page(text): 正文含错误页关键词 → True
- status_gate(code, allowed=(200,)): 状态码是否在允许集合

设计原则：纯只读、无副作用；所有函数对空输入安全返回；基线探测带 2 分钟
TTL 缓存，避免同一主机在一次扫描内被重复探测三次（每个 scanner 各一次）。
"""
import re
import threading
import time

_TOKEN_RE = re.compile(r"[a-z0-9一-鿿]+")

# 响应正文出现这些标志时，说明访问实际已被拒绝或要求登录，应排除"未授权访问"误报
DENIED_MARKERS = (
    "unauthorized", "forbidden", "access denied", "access is denied",
    "not authorized", "please login", "please log in", "login required",
    "authentication required", "requires authentication", "sign in",
    "permission denied", "not permitted",
    "需要登录", "请登录", "无权限", "没有权限", "拒绝访问", "未授权",
    "登录后", "请先登录", "权限不足", "鉴权失败",
)

# 错误页关键词：响应正文含这些（且非真实内容）时，说明是框架/服务器错误页（非真实泄露）
ERROR_PAGE_MARKERS = (
    "404", "not found", "找不到", "文件或目录", "bad request",
    "forbidden", "error", "exception", "服务器错误", "内部错误",
    "gateway", "timeout", "unavailable",
)

# 本就应对外公开的路径（登录入口/用户公开页），不报"缺失授权"
PUBLIC_PATHS = frozenset({
    "/login", "/admin/login", "/admin/login.php", "/wp-admin", "/wp-login.php",
    "/user", "/users", "/account", "/profile", "/settings",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.well-known/security.txt",
})

_SOFT404_THRESHOLD = 0.85
_BASELINE_NONCE = "_penscope_fp_guard_baseline_A3F9"
_CACHE_TTL = 120.0  # 同 root 基线 2 分钟内复用
_cache = {}  # root -> (baseline_text, ts)
_cache_lock = threading.Lock()


def similarity(a, b):
    """基于 token Jaccard 的文本相似度（0~1），用于识别软 404。"""
    if not a or not b:
        return 0.0
    sa = set(_TOKEN_RE.findall(a.lower()))
    sb = set(_TOKEN_RE.findall(b.lower()))
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def baseline_probe(session, root, verify_ssl=True, timeout=6.0):
    """取「确定不存在」路径的响应正文作为软 404 基线。带 TTL 缓存避免重复探测。

    root: 主机根 URL，如 http://example.com/
    返回基线正文文本；网络异常时返回空串（调用方应退化为不比对）。
    """
    cached = _cache.get(root)
    if cached is not None:
        text, ts = cached
        if (time.time() - ts) < _CACHE_TTL:
            return text
    try:
        r = session.get(root.rstrip("/") + "/" + _BASELINE_NONCE, timeout=timeout,
                        verify=verify_ssl, allow_redirects=False)
        text = r.text or ""
    except Exception:
        text = ""
    with _cache_lock:
        _cache[root] = (text, time.time())
    return text


def soft404_filter(text, baseline):
    """与基线高度相似（>0.85）→ 视为软 404，应排除。"""
    if not baseline:
        return False
    return similarity(text, baseline) > _SOFT404_THRESHOLD


def is_denied_page(text):
    """正文含拒绝/登录关键词 → 访问实际被拒绝。"""
    if not text:
        return False
    low = text.lower()
    return any(d in low for d in DENIED_MARKERS)


def is_error_page(text):
    """正文含错误页关键词 → 非真实内容。"""
    if not text:
        return False
    low = text.lower()
    return any(m in low for m in ERROR_PAGE_MARKERS)


def status_gate(code, allowed=(200,)):
    """状态码是否在允许集合（默认仅 200 视为「内容可达」）。"""
    return code in allowed


def is_public_path(path):
    """path 是否本就应对外公开（登录页等），命中则不报"缺失授权"。"""
    return path in PUBLIC_PATHS


def reset_cache():
    """清空基线缓存（测试隔离用）。"""
    with _cache_lock:
        _cache.clear()
