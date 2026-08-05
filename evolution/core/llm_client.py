# -*- coding: utf-8 -*-
"""
可插拔 LLM 客户端。
- 若配置了外部 API (OPENAI_API_KEY / PENSCOPE_LLM_BASE), 走真实模型主导推理。
- 否则降级为离线启发式 (按漏洞类型给出结构化 plan), 保证框架零依赖可跑通。
"""
from __future__ import annotations

import os

# 离线启发式: 漏洞类型 -> 推荐利用技术 (模拟 LLM 的"推理结果")
_HEURISTIC_PLAN = {
    "sqli": "尝试 union/boolean 注入, 提取数据列",
    "xss": "构造 <script> 反射/存储 payload",
    "ssrf": "诱导服务端请求内部/云元数据地址",
    "lfi": "利用 ../ 跳出 web 根读取敏感文件",
    "cmdi": "在主机参数中拼接 shell 元字符",
    "upload": "上传危险扩展名/webshell 内容",
    "missing_auth": "直接访问应受保护端点验证暴露",
    "open_redirect": "构造外部 next 参数验证跳转",
    "cloud_meta": "指向 169.254.169.254 IMDS 取凭据",
    "ai_infra_leak": "读取暴露的 AI 服务配置/密钥",
    "chain_ssrf": "先取 token, 再带 token 访问 admin",
    "chain_xss": "先用 XSS 设 admin cookie, 再访问 admin",
    "chain_sqli": "认证绕过取 session, 再取 flag",
    "pivot": "先发现内网主机, 再访问内网服务",
    # —— 移植自公开 CTF 题型 (Z1 扩展) ——
    "ssti": "服务端模板注入, 注入 {{7*7}} 等表达式求值",
    "xxe": "构造含外部实体的 XML, 触发文件读取/SSRF",
    "jwt": "篡改 JWT alg=none 或弱密钥, 提权为 admin",
    "nosql": "向 MongoDB 查询注入 {$ne:''} 绕过认证",
    "idor": "篡改对象 ID 越权访问他人资源",
    "cookie_tamper": "篡改 Cookie 中的 role 字段提权",
    "csrf": "缺少 CSRF 令牌的状态变更被冒用",
    # —— Z2 CVE / 云 / AI 基础设施 ——
    "log4shell": "注入 ${jndi:ldap://} 触发远程类加载",
    "spring4shell": "Spring 数据绑定 class.module 绕过 RCE",
    "backup_leak": "访问遗留备份/源码文件泄露机密",
    "ai_prompt_leak": "诱导暴露系统提示词/AI 服务配置",
    "s3_bucket": "公开对象存储列举, 取私密对象",
    # —— Z3 链式 / Z4 内网 ——
    "stored_xss": "存储型 XSS 被管理员触发后取凭据",
    "lfi_chain": "LFI 读配置取凭据, 再用凭据提权",
    "oauth_chain": "OAuth code->token->资源 三步链式",
    "privesc": "利用弱口令/硬编码密钥从低权升管理员",
    "internal_ssrf": "SSRF 打内网管理面板",
    "leaked_creds": "内网凭据Dump泄露, 直接取机密",
    "xff_bypass": "伪造 X-Forwarded-For 绕过内网信任",
    "lateral": "发现内网多主机, 横向移动到目标",
    "trust_boundary": "利用内部信任标记绕过鉴权",
}


class LLMClient:
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("PENSCOPE_LLM_KEY")
        self.base = os.environ.get("PENSCOPE_LLM_BASE", "")
        self.mode = "api" if self.api_key else "heuristic"

    def reason(self, challenge: dict) -> dict:
        """返回 {technique, steps, confidence}。"""
        if self.mode == "api":
            # 真实模型调用占位 (MVP 未接 key 时不触发)
            try:
                return self._call_api(challenge)
            except Exception:
                return self._heuristic(challenge)
        return self._heuristic(challenge)

    def _heuristic(self, challenge: dict) -> dict:
        t = challenge.get("type", "")
        return {
            "technique": _HEURISTIC_PLAN.get(t, "通用探测"),
            "steps": challenge.get("chain", []),
            "confidence": 0.9 if t in _HEURISTIC_PLAN else 0.4,
        }

    def _call_api(self, challenge: dict) -> dict:
        # 预留: 用 openai / 兼容端点调用。MVP 不启用。
        raise NotImplementedError("API mode not enabled in MVP")
