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
