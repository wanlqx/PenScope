"""U-12 敏感数据脱敏。

对可能在报告/证据/诊断包中泄露的凭据做保守正则脱敏：
- AWS Access Key ID
- Bearer / Authorization 令牌
- JWT
- PEM 私钥块
- 常见密码/密钥键值对（password / secret / api_key / token ...）
- 会话 Cookie（session= / token= / auth= 等值）

设计原则：宁可少脱敏也不误伤正常文本。命中后以 ``***REDACTED***`` 或带前缀的掩码
替换，保留足够的可识别上下文以便人工核对「哪里有密钥」，但不暴露真实值。
"""

import re

# 每个元素：(编译后的正则, 替换函数/字符串)
# 替换保留少量前缀以便识别类别，其余以 * 填充。
_AWS_RE = re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
# 键值对：password/secret/api_key/token/access_token ... = <值>
_KV_RE = re.compile(
    r"(?P<key>(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|private[_-]?key|auth[_-]?token)"
    r"(?P<sep>[\"']?\s*[:=]\s*[\"']?))"
    r"(?P<val>[^\s\"',}{\]]+)",
    re.IGNORECASE,
)
# Bearer 令牌（标头或裸串）
_BEARER_RE = re.compile(r"(?P<pre>[Bb]earer\s+)(?P<tok>[A-Za-z0-9\-._~+/]+=*)")
# 会话类 Cookie / 查询参数值
_SESSION_RE = re.compile(
    r"(?P<pre>(?:session|sid|token|auth|jwt|csrf|access_token|refresh_token)=)"
    r"(?P<val>[A-Za-z0-9_\-]{8,})"
)


def _mask(match, keep=4):
    """保留前 keep 个字符，其余用 * 填充。"""
    s = match.group(0)
    if len(s) <= keep:
        return "*" * len(s)
    return s[:keep] + "*" * (len(s) - keep)


def redact_sensitive(text):
    """对给定文本做敏感数据脱敏，返回脱敏后的字符串。

    非字符串输入原样返回（避免调用方误传导致崩溃）。
    """
    if not isinstance(text, str):
        return text
    out = text
    # 顺序：先整块（PEM/JWT），再键值/Bearer/会话，避免内部子串被二次处理。
    out = _PEM_RE.sub("***REDACTED_PRIVATE_KEY***", out)
    out = _JWT_RE.sub("***REDACTED_JWT***", out)
    out = _AWS_RE.sub(lambda m: _mask(m, keep=4), out)
    out = _KV_RE.sub(lambda m: m.group("key") + "***REDACTED***", out)
    out = _BEARER_RE.sub(lambda m: m.group("pre") + "***REDACTED***", out)
    out = _SESSION_RE.sub(lambda m: m.group("pre") + _mask(m, keep=0), out)
    return out


def redact_dict(obj):
    """递归对 dict/list/str 做脱敏（用于诊断包等结构化数据）。"""
    if isinstance(obj, str):
        return redact_sensitive(obj)
    if isinstance(obj, dict):
        return {k: redact_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_dict(v) for v in obj]
    return obj
