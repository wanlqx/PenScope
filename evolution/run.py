# -*- coding: utf-8 -*-
"""
PenScope 进化框架 —— 入口。
启动本地靶机 -> 四队对抗模拟 -> 裁判按第二届赛制计分 -> 生成战报 -> 定主 agent。
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from core.config import LAB_PORT, TEAMS, ZONES  # noqa: E402
from harness import start_lab, run_simulation  # noqa: E402

REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")


def build_report(res: dict) -> str:
    ranking = res["ranking"]
    winner = ranking[0] if ranking else ("?", 0)
    totals = res["totals"]
    meta = res["meta_actions"]

    rows = ""
    for i, (k, s) in enumerate(ranking, 1):
        t = res["teams"][k]
        medal = "🥇" if i == 1 else ("🥈" if i == 2 else ("🥉" if i == 3 else ""))
        rows += (f"<tr class='{'win' if i==1 else ''}'><td>{medal} {i}</td>"
                 f"<td><b>{k}</b> · {t['name']}</td><td>{s:.1f}</td>"
                 f"<td style='font-size:12px;color:#9aa'>{t['workflow']}</td></tr>")

    # 逐题明细
    det = ""
    for d in res["detail"]:
        cells = ""
        for tk in ["A", "B", "C", "D"]:
            r = next((x for x in d["results"] if x["team"] == tk), None)
            if not r:
                cells += "<td class='na'>-</td>"
                continue
            sc = d["scores"].get(tk)
            if r["success"]:
                cls = "ok" if sc is not None else "ok0"
                cells += (f"<td class='{cls}'>✅{(' +'+str(sc)) if sc is not None else ''}"
                          f"{(' ⚠'+str(r['wrong'])+'错') if r['wrong'] else ''}"
                          f"<br><small>L{r['latency']}</small></td>")
            else:
                cells += f"<td class='fail'>❌</td>"
        det += (f"<tr><td>{d['id']}</td><td>{ZONES[d['zone']]['name']}</td>"
                f"<td>{d['title']}<br><small>{d['points']}分</small></td>{cells}</tr>")

    meta_rows = "".join(
        f"<tr><td>{k}</td><td>{meta[k]['type']}</td><td>{meta[k]['desc']}</td></tr>"
        for k in ["A", "B", "C", "D"])

    ans_rows = "".join(f"<tr><td>{cid}</td><td><code>{flag}</code></td></tr>"
                       for cid, flag in res["answers"].items())

    html = f"""<!doctype html><html lang=zh><head><meta charset=utf-8>
<title>PenScope 进化对抗战报</title>
<style>
body{{background:#0e1116;color:#e6e6e6;font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px}}
h1{{color:#06d6a0}} h2{{color:#4aa3ff;border-bottom:1px solid #2a2f3a;padding-bottom:6px}}
table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:14px}}
th,td{{border:1px solid #2a2f3a;padding:8px 10px;text-align:left}}
th{{background:#161b22;color:#9aa}}
tr.win{{background:#06352a}}
.ok{{color:#06d6a0}} .ok0{{color:#06d6a0;opacity:.6}} .fail{{color:#ff6b6b}} .na{{color:#555}}
code{{color:#ffd166}} small{{color:#9aa}} .winner{{background:#06352a;border:1px solid #06d6a0;padding:14px;border-radius:8px;margin:12px 0}}
</style></head><body>
<h1>🛡️ PenScope 进化对抗战报</h1>
<p>复刻第二届腾讯云黑客松智能渗透挑战赛赛制 · 本地靶机 {res['base']} · 题库 {len(res['detail'])} 题</p>
<div class='winner'><b>🏆 主 agent 工作流:</b> {winner[0]} · {res['teams'][winner[0]]['name']}
（得分 {winner[1]:.1f}）—— 此工作流将固化进 PenScope 主 agent。</div>

<h2>总排名</h2>
<table><tr><th>名次</th><th>Team</th><th>总分</th><th>工作流</th></tr>{rows}</table>

<h2>元游戏 (进攻/防御, 每队≥1次进攻)</h2>
<table><tr><th>Team</th><th>动作</th><th>说明</th></tr>{meta_rows}</table>

<h2>逐题明细 (✅解出 / ❌未解, L=解题时延轮次, ⚠错=误报成本)</h2>
<table><tr><th>题号</th><th>赛区</th><th>题目</th>
<th>A</th><th>B</th><th>C</th><th>D</th></tr>{det}</table>

<h2>裁判发放答案 (答题期保密, 收尾公开)</h2>
<table><tr><th>题号</th><th>FLAG</th></tr>{ans_rows}</table>

<p style="color:#9aa;font-size:12px">MVP 说明: 靶机为本地真实可利用端点; 四队均真实提取 flag 由裁判校验;
工作流差异体现在覆盖率/时延/误报。扩展点: 扩到 32 题、接真 LLM API(B/D 提速)、将胜出工作流固化进 PenScope scanner。</p>
</body></html>"""
    return html


def main():
    print("[evo] 启动本地靶机 ...")
    start_lab(LAB_PORT)
    print("[evo] 运行四队对抗模拟 ...")
    res = run_simulation(LAB_PORT)
    os.makedirs(REPORT_DIR, exist_ok=True)
    rp = os.path.join(REPORT_DIR, "sim_report.html")
    with open(rp, "w", encoding="utf-8") as f:
        f.write(build_report(res))

    print("\n=== 总排名 ===")
    for i, (k, s) in enumerate(res["ranking"], 1):
        print(f"  {i}. [{k}] {res['teams'][k]['name']:<22} {s:.1f}")
    winner = res["ranking"][0]
    print(f"\n🏆 主 agent: {winner[0]} · {res['teams'][winner[0]]['name']}")
    print(f"[evo] 战报已生成: {rp}")
    return res


if __name__ == "__main__":
    main()
