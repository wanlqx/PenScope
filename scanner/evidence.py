"""PenScope —— HTTP 证据采集助手（I-05 请求/响应 Diff 的数据来源）

纯标准库实现，供各扫描器在「已验证」发现处调用，把触发漏洞的 HTTP 请求 / 响应
重建成可读文本，连同注入载荷一起存入发现的 `evidence_meta` 字段。前端据此渲染
"注入前 / 注入后" 的差异视图，帮助分析者快速定位 payload 落点、自查是否误报。

设计原则：
- 只读重建，不发任何新请求；
- 不写入磁盘，仅返回 JSON 字符串；
- 对超长响应做截断，避免 findings 表体积膨胀。
"""
import json


def capture_request(resp):
    """从 requests.Response 重建请求文本（请求行 + 头 + 体）。

    resp.request 是 requests 发出的 PreparedRequest（可能经过重定向，已是最末跳）。
    返回 None 表示无法重建（无 request 对象）。
    """
    req = getattr(resp, "request", None)
    if req is None:
        return None
    try:
        method = (req.method or "GET").upper()
        url = req.url or ""
        lines = ["%s %s" % (method, url)]
        hdrs = getattr(req, "headers", None) or {}
        for k, v in hdrs.items():
            lines.append("%s: %s" % (k, v))
        body = getattr(req, "body", None)
        if body:
            if isinstance(body, bytes):
                try:
                    body = body.decode("utf-8", "replace")
                except Exception:
                    body = repr(body)
            else:
                body = str(body)
            lines.append("")
            lines.append(body)
        return "\n".join(lines)
    except Exception:
        return None


def capture_response(resp, max_len=2400):
    """从 requests.Response 重建响应文本（状态行 + 头 + 截断后的响应体）。"""
    try:
        lines = ["HTTP %s" % resp.status_code]
        hdrs = getattr(resp, "headers", None) or {}
        for k, v in hdrs.items():
            lines.append("%s: %s" % (k, v))
        lines.append("")
        txt = resp.text or ""
        if len(txt) > max_len:
            txt = txt[:max_len] + "\n...[截断 %d 字符]" % (len(txt) - max_len)
        lines.append(txt)
        return "\n".join(lines)
    except Exception:
        return None


def build_evidence_meta(payload=None, request=None, response=None, baseline_request=None):
    """组装 evidence_meta：仅收集非空字段，返回 JSON 字符串；全空返回 None。

    - request / response：触发发现的请求 / 响应（来自 capture_request/capture_response）；
    - baseline_request：注入前的基线请求（若扫描器同时采集了未注入样本，可用于 true diff）；
    - payload：注入的载荷字符串，前端据此在请求文本中高亮。
    """
    meta = {}
    if request:
        meta["request"] = request
    if response:
        meta["response"] = response
    if payload:
        meta["payload"] = payload
    if baseline_request:
        meta["baseline_request"] = baseline_request
    if not meta:
        return None
    try:
        return json.dumps(meta, ensure_ascii=False)
    except Exception:
        return None
