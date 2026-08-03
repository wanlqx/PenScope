"""PenScope —— 漏洞链编排（C-01）

将单次扫描中彼此孤立的发现，按已知攻击路径模式关联为"漏洞利用链"，
辅助分析员理解"组合利用"带来的更高影响。例如：
  - SSRF → 以内网为目标做横向探测（端口暴露 / 已知漏洞 / 敏感信息泄露）
  - 缺失授权（越权）→ 访问敏感接口 / API（敏感信息泄露 / API安全）
  - 文件上传 → 命令注入 / 代码执行（RCE）
  - SQL注入 → 敏感数据提取（敏感信息泄露）
  - XSS → 会话劫持 → CSRF / 认证缺陷
  - 认证缺陷 → 缺失授权

设计原则：
  - 纯只读、基于已有发现做关联推理，不发起任何新请求；
  - 每条链由"触发类发现" + "支撑类发现"至少各命中一项组成；
  - 链的聚合风险不低于其规则基线（组合利用放大影响），并取涉及发现中的最高风险。
"""
import json

# 风险等级排序
_RISK_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


def _risk_rank(r):
    try:
        return _RISK_ORDER.index(r)
    except ValueError:
        return 0


# 预定义攻击链规则。trigger / support 均为发现 category 字符串（见各 scanner 模块）。
_CHAIN_RULES = [
    {
        "id": "CHAIN-SSRF-INT",
        "name": "SSRF → 内网横向探测",
        "trigger": ["SSRF"],
        "support": ["端口暴露", "资产暴露", "已知漏洞", "敏感信息泄露", "目录暴露"],
        "base_risk": "High",
        "narrative": "服务端请求伪造（SSRF）可作为跳板向内网发起请求。与暴露的端口、已知漏洞或敏感信息泄露结合后，"
                     "即构成向内部网络的横向移动起点，可能进一步触及本不可从外网到达的资产。",
    },
    {
        "id": "CHAIN-BROKENAC-EXFIL",
        "name": "缺失授权（越权）→ 访问敏感接口",
        "trigger": ["缺失授权"],
        "support": ["敏感信息泄露", "API安全"],
        "base_risk": "High",
        "narrative": "存在缺失授权（强制浏览 / 潜在越权 IDOR）意味着敏感功能或数据未按需鉴权。"
                     "与敏感信息泄露 / API 安全缺陷结合，可直接演变为未授权读取内部数据或调用特权接口。",
    },
    {
        "id": "CHAIN-UPLOAD-RCE",
        "name": "文件上传 → 命令注入 / 代码执行",
        "trigger": ["文件上传"],
        "support": ["命令注入"],
        "base_risk": "Critical",
        "narrative": "若上传点未严格校验类型/内容，可被用于落地可执行脚本；再配合命令注入（或服务端对该文件的处理缺陷），"
                     "即可升级为远程代码执行（RCE），影响最为严重。",
    },
    {
        "id": "CHAIN-SQLI-EXFIL",
        "name": "SQL注入 → 敏感数据提取",
        "trigger": ["SQL注入"],
        "support": ["敏感信息泄露"],
        "base_risk": "High",
        "narrative": "SQL 注入可直接读取后台数据库。与敏感信息泄露类发现结合，表明不仅存在注入点，"
                     "且目标确实承载可被提取的敏感数据，数据泄露风险显著上升。",
    },
    {
        "id": "CHAIN-XSS-SESSION",
        "name": "XSS → 会话劫持 → CSRF / 认证缺陷",
        "trigger": ["XSS"],
        "support": ["CSRF", "认证缺陷"],
        "base_risk": "High",
        "narrative": "反射/存储型 XSS 可窃取会话 Cookie 或冒充登录用户发起请求。与 CSRF / 认证缺陷结合，"
                     "即可在无需已知凭据的情况下劫持会话、绕过身份校验发起状态变更。",
    },
    {
        "id": "CHAIN-AUTH-BROKENAC",
        "name": "认证缺陷 → 缺失授权",
        "trigger": ["认证缺陷"],
        "support": ["缺失授权"],
        "base_risk": "High",
        "narrative": "弱认证 / 明文凭据传输降低了身份门槛，与缺失授权（越权）叠加后，攻击者在通过薄弱身份验证后"
                     "还能访问未受保护的敏感功能，形成「先进入、再越权」的利用链。",
    },
]


def analyze_chains(findings):
    """对一批发现做漏洞链关联推理。

    findings: findings_of 返回的发现列表（dict）。
    返回按风险从高到低排序的链列表；每条链含 id / name / risk / narrative /
    steps（有序发现摘要）/ finding_ids。

    防御性输入校验：非 list / 非 dict 元素一律忽略，避免上游传入 None / 单 dict
    时 `for f in findings` 抛 TypeError 中断链分析。
    """
    if not isinstance(findings, list):
        return []
    chains = []
    for rule in _CHAIN_RULES:
        trig = [f for f in findings if isinstance(f, dict) and f.get("category") in rule["trigger"]]
        supp = [f for f in findings if isinstance(f, dict) and f.get("category") in rule["support"]]
        if not trig or not supp:
            continue
        involved = trig + supp
        # 聚合风险：取规则基线 与 涉及发现最高风险 的较高者
        max_inv = max((_risk_rank(f.get("risk")) for f in involved), default=0)
        base = _risk_rank(rule["base_risk"])
        agg = _RISK_ORDER[max(base, max_inv)]
        steps = sorted(
            involved,
            key=lambda f: -_risk_rank(f.get("risk"))
        )
        chains.append({
            "id": rule["id"],
            "name": rule["name"],
            "risk": agg,
            "narrative": rule["narrative"],
            "steps": [
                {
                    "category": f.get("category"),
                    "title": f.get("title"),
                    "risk": f.get("risk"),
                    "endpoint": f.get("endpoint") or f.get("target_ref") or "",
                }
                for f in steps
            ],
            "finding_ids": [f.get("id") for f in involved],
        })
    chains.sort(key=lambda c: -_risk_rank(c["risk"]))
    return chains


def chains_json(scan, findings):
    """供 API / JSON 导出使用的链数据。

    包裹异常：分析过程任何意外（数据结构异常等）都降级为空链返回，
    不让链渲染拖垮报告 / API 导出。get_chains 调用方已有兜底，此处为双重保险。
    """
    try:
        return analyze_chains(findings)
    except Exception:
        return []
