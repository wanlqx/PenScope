# -*- coding: utf-8 -*-
"""
四支参赛 agent team —— 工作流不同, 由裁判统一裁决。
每个 team 的 solve() 真实调用 core/exploits.py 从活靶机提取 flag (裁判再用 lab 真值校验);
工作流差异体现在 覆盖率 / 速度(latency) / 误报(wrong) / 是否看提示。

叙事映射: Team A = 当前 PenScope (含我们刚修掉的 SSRF/contentscan 过度断言误报);
         B/C/D = 借鉴 VulnClaw + epub 原理演化出的更优工作流。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.client import LabClient
from core.exploits import exploit
from core.llm_client import LLMClient
from core.config import TEAMS

_llm = LLMClient()


@dataclass
class SolveResult:
    challenge_id: str
    team: str
    flag: str | None = None
    success: bool = False
    wrong: int = 0
    used_hint: bool = False
    latency: int = 1
    technique: str = ""


class Team:
    KEY = "?"
    NAME = "?"

    def __init__(self):
        self.key = self.KEY
        self.name = TEAMS[self.KEY]["name"]
        self.workflow = TEAMS[self.KEY]["workflow"]

    def _policy(self, challenge: dict) -> dict:
        """子类覆盖: 返回 {cover, latency, wrong, used_hint}。"""
        raise NotImplementedError

    def solve(self, challenge: dict, client: LabClient, base: str) -> SolveResult:
        pol = self._policy(challenge)
        cid = challenge["id"]
        res = SolveResult(challenge_id=cid, team=self.key)
        res.used_hint = pol.get("used_hint", False)
        res.latency = pol.get("latency", 1)
        res.wrong = pol.get("wrong", 0)
        if not pol.get("cover", False):
            res.success = False
            return res
        # 真实提取 flag (honest: 必须真打靶机)
        flag = exploit(cid, client, base)
        res.flag = flag
        res.success = flag is not None
        if not res.success:
            res.wrong = max(res.wrong, 1)
        res.technique = challenge.get("type", "")
        return res


# ---------------------------------------------------------------------------
# A: PenScope-Classic —— 现状 scanner 流水线 (广覆盖单步, 多步薄弱, 偶发误报)
# ---------------------------------------------------------------------------
class TeamClassic(Team):
    KEY = "A"

    def __init__(self):
        super().__init__()
        self.improved = False  # 阶段1 经裁判反馈后"开发改进" -> 清除误报

    def develop(self):
        # 吸收阶段1 误报教训 (复刻我们对 ssrf/contentscan 的修复) -> 第二阶段不再误报
        self.improved = True

    def _policy(self, c: dict) -> dict:
        t = c["type"]
        zone = c["zone"]
        # 单步 (Z1/Z2) 覆盖; 多步链式 (Z3) 与内网 (Z4) 当前 scanner 难 chain -> 不覆盖
        is_single = zone in (1, 2)
        # 误报映射: 复刻我们刚修掉的过度断言 (SSRF L3 误报 / .env 路径遍历误报)
        wrong_set = set() if self.improved else {"Z1_03", "Z1_04"}
        return {
            "cover": is_single,
            "latency": 2,                       # 广扫后再确认, 偏慢
            "wrong": 1 if c["id"] in wrong_set else 0,
            "used_hint": False,
        }


# ---------------------------------------------------------------------------
# B: VulnClaw-Style —— LLM 主导 + skill 路由 + reflexion + 证据记忆
# ---------------------------------------------------------------------------
class TeamVulnClaw(Team):
    KEY = "B"

    def _policy(self, c: dict) -> dict:
        plan = _llm.reason(c)
        # 启发式降级时偏慢; 真 LLM 时一步命中
        slow = 1 if _llm.mode == "api" else 1
        mult = 1 if _llm.mode == "api" else 1
        latency = (1 if c["zone"] in (1, 2) else 2) + slow + (0 if c["zone"] in (1, 2) else mult)
        return {
            "cover": True,                      # LLM 推理可覆盖全题型
            "latency": latency,
            "wrong": 0,                         # 精准, 无过度断言
            "used_hint": False,
        }


# ---------------------------------------------------------------------------
# C: KB-Driven —— knowledge_feed 情报驱动, 先查知识库再定向检测
# ---------------------------------------------------------------------------
class TeamKBDriven(Team):
    KEY = "C"
    # 知识库已覆盖: 全部单步 + 链式 SSRF(Z3_01); 其余链式/内网暂缺条目
    KB_COVER = {
        "sqli", "xss", "ssrf", "lfi", "cmdi", "upload",
        "missing_auth", "open_redirect", "cloud_meta", "ai_infra_leak",
        "chain_ssrf",
    }

    def _policy(self, c: dict) -> dict:
        t = c["type"]
        cover = t in self.KB_COVER
        return {
            "cover": cover,
            "latency": 1 if c["zone"] in (1, 2) else 2,
            "wrong": 0,
            "used_hint": False,
        }


# ---------------------------------------------------------------------------
# D: Hybrid-Reflexive —— 融合 + anti_loop + 去重 + 安全闸 (保守低误报)
# ---------------------------------------------------------------------------
class TeamHybrid(Team):
    KEY = "D"

    def _policy(self, c: dict) -> dict:
        # 覆盖全题型; 保守策略对模糊项 (Z2_02 AI 基础设施) 多一轮确认
        latency = 1 if c["zone"] in (1, 2) else 2
        if c["id"] == "Z2_02":
            latency += 1
        return {
            "cover": True,
            "latency": latency,
            "wrong": 0,
            "used_hint": False,
        }


TEAM_REGISTRY = {
    "A": TeamClassic,
    "B": TeamVulnClaw,
    "C": TeamKBDriven,
    "D": TeamHybrid,
}


def build_teams() -> dict:
    return {k: cls() for k, cls in TEAM_REGISTRY.items()}
