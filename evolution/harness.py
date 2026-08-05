# -*- coding: utf-8 -*-
"""
对抗模拟 harness —— 复刻第二届大赛两阶段赛制。
阶段1 (前 ~1/2 题, 序贯): 各队逐一解题 -> 裁判反馈 -> 各队"开发改进"一轮。
阶段2 (后 ~1/2 题, 同场开放): 排位衰减计分 + 元游戏(进攻/防御, 每队≥1次进攻)。
收尾: 裁判发放答案 + 按公式算总分 -> 胜者即此后主 agent 工作流。
"""
from __future__ import annotations

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))

from core.config import LAB_PORT, LAB_BASE, TEAMS, load_challenges  # noqa: E402
from core.client import LabClient  # noqa: E402
from teams.agents import build_teams  # noqa: E402
from referee import rank_and_score, aggregate, release_answers, WRONG_ATTEMPT_PENALTY  # noqa: E402

_LAB_DIR = os.path.join(os.path.dirname(__file__), "lab")


def start_lab(port: int = LAB_PORT):
    """在后台线程启动靶机。"""
    sys.path.insert(0, _LAB_DIR)
    import vuln_lab
    t = threading.Thread(target=vuln_lab.run_lab, args=(port,), daemon=True)
    t.start()
    time.sleep(1.2)  # 等监听起来
    return t


def _solve_all(challenges, teams, base):
    """各队对每个 challenge 求解, 返回 {cid: [SolveResult...]}。"""
    out = {}
    for c in challenges:
        results = []
        for key, team in teams.items():
            client = LabClient(base)
            r = team.solve(c, client, base)
            results.append(r)
        out[c["id"]] = results
    return out


def run_simulation(port: int = LAB_PORT, challenges: list | None = None):
    base = f"http://127.0.0.1:{port}"
    if challenges is None:
        challenges = load_challenges()
    teams = build_teams()

    # 阶段切分
    split = len(challenges) // 2
    phase1 = challenges[:split]
    phase2 = challenges[split:]

    # ---- 阶段1: 序贯解题 + 开发改进 ----
    phase1_results = _solve_all(phase1, teams, base)
    # 裁判反馈后, 各队"开发改进" (Team A 清除误报; 其余微调 latency)
    for team in teams.values():
        if hasattr(team, "develop"):
            team.develop()

    # ---- 阶段2: 同场开放 + 元游戏 ----
    phase2_results = _solve_all(phase2, teams, base)
    meta_actions = run_meta_game(teams)

    # ---- 计分 ----
    per_challenge = []
    detail = []
    for c in challenges:
        cid = c["id"]
        results = phase1_results.get(cid) or phase2_results.get(cid)
        scores = rank_and_score(c["points"], results)
        per_challenge.append(scores)
        detail.append({
            "id": cid, "zone": c["zone"], "title": c["title"], "points": c["points"],
            "scores": scores,
            "results": [{"team": r.team, "success": r.success, "wrong": r.wrong,
                         "latency": r.latency, "flag": (r.flag[:12] + "..." if r.flag else None)}
                        for r in results],
        })

    agg = aggregate(per_challenge, list(teams.keys()))
    answers = release_answers(challenges)

    # 元游戏成本: 进攻队每队一次性 +1 wrong 成本 (非逐题累加)
    totals = agg["totals"]
    for key, act in meta_actions.items():
        if act["type"] == "attack":
            totals[key] -= WRONG_ATTEMPT_PENALTY

    ranking = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
    agg["totals"] = totals
    agg["ranking"] = ranking

    return {
        "base": base,
        "phase1": [c["id"] for c in phase1],
        "phase2": [c["id"] for c in phase2],
        "meta_actions": meta_actions,
        "detail": detail,
        "totals": totals,
        "ranking": ranking,
        "answers": answers,
        "teams": {k: {"name": v.name, "workflow": v.workflow} for k, v in teams.items()},
    }


def run_meta_game(teams: dict) -> dict:
    """
    元游戏: 每队至少进攻1次。
    - attack: 提交诱饵 flag 消耗裁判校验 (失败干扰, 自身 +1 wrong 成本)。
    - defend: 加固自身工作流 (本框架中以"保守"队选择, 不增 wrong)。
    分配: A/B/C 进攻, D(保守) 防御。
    """
    actions = {}
    for key in teams:
        if key == "D":
            actions[key] = {"type": "defend", "desc": "加固工作流 (降误报, 不增成本)"}
        else:
            actions[key] = {"type": "attack",
                            "desc": "向裁判提交诱饵 flag 干扰 (自身 +1 wrong 成本)"}
    return actions


if __name__ == "__main__":
    start_lab()
    res = run_simulation()
    import json
    print(json.dumps(res["ranking"], ensure_ascii=False, indent=2))
