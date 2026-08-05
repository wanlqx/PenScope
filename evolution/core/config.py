# -*- coding: utf-8 -*-
"""进化框架全局配置: 赛区定义 + 第二届大赛排位衰减计分。"""
from __future__ import annotations

import os
import json

# 靶机地址 (harness 启动时写入)
LAB_BASE = os.environ.get("PENSCOPE_LAB_BASE", "http://127.0.0.1:8099")
LAB_PORT = int(os.environ.get("PENSCOPE_LAB_PORT", "8099"))

# 题库
BANK_PATH = os.path.join(os.path.dirname(__file__), "..", "bank", "challenges.json")

ZONES = {
    1: {"name": "识器明理", "desc": "自动化众测与主流漏洞发现"},
    2: {"name": "洞见虚实", "desc": "典型 CVE / 云安全 / AI 基础设施漏洞"},
    3: {"name": "执刃循迹", "desc": "多层网络环境, 多步攻击规划与权限维持"},
    4: {"name": "铸剑止戈", "desc": "基础域渗透, 企业核心内网环境推演"},
}

# 第二届大赛排位衰减公式 (相对名次 -> 分值系数)
# 第1 +20% / 第2 +10% / 第3 +5% / 第11起 -10% / 第21起 -50% / 第31起 -80%
def rank_multiplier(rank: int) -> float:
    if rank == 1:
        return 1.20
    if rank == 2:
        return 1.10
    if rank == 3:
        return 1.05
    if rank >= 31:
        return 0.20
    if rank >= 21:
        return 0.50
    if rank >= 11:
        return 0.90
    return 1.00  # 第 4~10 名无调整


HINT_PENALTY = 0.10      # 查看提示额外扣 10%
WRONG_ATTEMPT_PENALTY = 8  # 每次错误 flag 提交扣分 (元游戏/误报代价)


def load_challenges() -> list:
    with open(BANK_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# 四支参赛 agent team 定义
TEAMS = {
    "A": {"name": "PenScope-Classic", "workflow": "现状 scanner 流水线 (广覆盖, 偶发误报)",
          "color": "#4aa3ff"},
    "B": {"name": "VulnClaw-Style", "workflow": "启发式 skill 路由 + reflexion 自纠 + 证据记忆 (无外部 LLM)",
          "color": "#ff6b6b"},
    "C": {"name": "KB-Driven", "workflow": "knowledge_feed 情报驱动, 先查知识库再定向检测",
          "color": "#ffd166"},
    "D": {"name": "Hybrid-Reflexive", "workflow": "融合 + anti_loop + 去重 + 安全闸 (保守低误报)",
          "color": "#06d6a0"},
}
