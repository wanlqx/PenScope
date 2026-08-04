# -*- coding: utf-8 -*-
"""
裁判 Agent —— 持答案真值, 验证提交, 按第二届大赛排位衰减公式计分, 收尾发放答案。
- 答题期间答案保密: team 永远拿不到 FLAGS; 只有裁判导入 lab 真值做校验。
- 排位衰减: 每题按"谁先解出"(latency 升序) 排名, 第1 +20% ... 第31后 -80%。
- 误报/看提示均扣分。
"""
from __future__ import annotations

import os
import sys

# 裁判特权: 导入靶机真值 FLAGS 作为答案密钥
_LAB_DIR = os.path.join(os.path.dirname(__file__), "lab")
if _LAB_DIR not in sys.path:
    sys.path.insert(0, _LAB_DIR)
from vuln_lab import FLAGS  # noqa: E402

from core.config import rank_multiplier, WRONG_ATTEMPT_PENALTY, HINT_PENALTY  # noqa: E402


def verify(challenge_id: str, submitted_flag: str | None) -> bool:
    """校验提交 flag 是否等于靶机真值。"""
    if not submitted_flag:
        return False
    return submitted_flag == FLAGS.get(challenge_id)


def rank_and_score(challenge_points: int, results: list) -> dict:
    """
    对单题的成功提交按 latency 升序排名并计分。
    返回 {team_key: score} (仅含成功队)。失败队不在此 dict, 外部计 0。
    """
    succeeded = [r for r in results if r.success and verify(r.challenge_id, r.flag)]
    succeeded.sort(key=lambda r: (r.latency, r.team))
    out = {}
    for rank, r in enumerate(succeeded, 1):
        mult = rank_multiplier(rank)
        penalty = r.wrong * WRONG_ATTEMPT_PENALTY
        if r.used_hint:
            penalty += challenge_points * HINT_PENALTY
        out[r.team] = round(challenge_points * mult - penalty, 2)
    return out


def aggregate(per_challenge: list, teams: list) -> dict:
    """汇总所有题目得分 -> {team_key: total}, 并给出总排名。"""
    totals = {t: 0.0 for t in teams}
    for pc in per_challenge:
        for t, s in pc.items():
            totals[t] += s
    ranking = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
    return {"totals": totals, "ranking": ranking}


def release_answers(challenges: list) -> dict:
    """收尾发放答案 (答题期结束后才调用)。"""
    return {c["id"]: FLAGS.get(c["id"], "???") for c in challenges}
