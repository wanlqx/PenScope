"""PenScope v1.3.0 —— 端到端验证驱动脚本（配合新 exe 使用）

用法：在 autopentest-ai 目录下，先启动 demo 靶场与新 exe（均设置同一 AUTOPENTEST_DB），
再运行本脚本。本脚本只负责：注入已授权目标 + 排队扫描 + 自动批准人工闸门 + 收集结果，
真正的扫描阶段全部在 exe 进程的 worker 中执行（验证冻结包内的新代码）。

演示重复发现（语义去重）的预期：
  - /login 表单出现在首页 /、/login、/admin → 错误型 SQLi 应合并为 1 条（而非 3）
  - /sqli 同时有 GET ?id= 与 POST 表单 → 时间盲注应合并为 1 条（而非 2）
"""
import json
import os
import time

import db
import reports

DB = os.environ.get("AUTOPENTEST_DB") or "autopentest.db"
print(f"[driver] using DB={DB}")

db.init_db()

# 1) 注入已授权目标（本机演示靶场）
tid = db.add_target(
    "127.0.0.1", "18080",
    "PenScope 端到端验证演示靶场（本地漏洞演示应用）",
    "已获书面授权：本机 127.0.0.1:18080 演示漏洞靶场，仅供安全工具测试",
    "e2e",
)
db.approve_target(tid, "e2e")
print(f"[driver] target#{tid} added + approved")

# 2) 排队扫描
sid = db.create_scan(tid, "E2E 验证扫描 v1.3.0（本地漏洞演示靶）", "e2e")
print(f"[driver] scan#{sid} queued; waiting for exe worker...")

# 3) 轮询：自动批准人工闸门，直到完成/失败
deadline = time.time() + 600
last_stage = None
while time.time() < deadline:
    s = db.get_scan(sid)
    if s is None:
        print("[driver] scan missing?!"); break
    st = s["status"]
    if st != last_stage:
        print(f"[driver] stage={s.get('stage')} status={st}")
        last_stage = st
    if st == "awaiting_review":
        for rv in db.pending_reviews():
            if rv.get("scan_id") == sid:
                db.decide_review(rv["id"], "approve", "e2e")
                db.update_scan(sid, status="approved")
                print(f"[driver] approved gate {rv['kind']} (review#{rv['id']})")
    if st in ("completed", "failed"):
        break
    time.sleep(4)

s = db.get_scan(sid)
print(f"[driver] FINAL status={s['status']} stage={s['stage']}")

# 4) 收集发现，验证语义去重 / 验证状态 / PoC / CVSS / CWE
fs = db.findings_of(sid)
print(f"\n===== 发现共 {len(fs)} 条 =====")
cats = {}
for f in fs:
    cats.setdefault(f["category"], 0)
    cats[f["category"]] += 1
print("分类统计:", json.dumps(cats, ensure_ascii=False))

# 去重验证
login_sql = [f for f in fs if f["category"] == "SQL注入" and "/login" in (f["endpoint"] or f["target_ref"] or "")]
sqli_sql = [f for f in fs if f["category"] == "SQL注入" and "/sqli" in (f["endpoint"] or f["target_ref"] or "")]
print(f"[去重] /login 错误型 SQLi 合并后条数 = {len(login_sql)} (期望 1，原始 3)")
print(f"[去重] /sqli 时间盲注合并后条数 = {len(sqli_sql)} (期望 1，原始 2)")

# 验证状态分布
vs = {}
for f in fs:
    vs[f["verification_status"]] = vs.get(f["verification_status"], 0) + 1
print("验证状态分布:", json.dumps(vs, ensure_ascii=False))

print("\n===== 逐条发现 =====")
for f in fs:
    has_poc = bool(f.get("poc_script"))
    print(f" - [{f['risk']:6}] {f['category']:6} | {f['title']}")
    print(f"     endpoint={f.get('endpoint') or f.get('target_ref')} method={f.get('http_method')} "
          f"cwe={f.get('cwe')} cvss={f.get('cvss_score')} vec={f.get('cvss_vector')} "
          f"vs={f.get('verification_status')} el={f.get('evidence_level')} poc={'Y' if has_poc else 'N'}")

# 5) 生成报告 HTML
html = reports.build_report(db.get_scan(sid))
out = os.path.join(os.path.dirname(DB) if os.path.isabs(DB) else ".", "e2e_vuln_demo_report.html")
with open(out, "w", encoding="utf-8") as fh:
    fh.write(html)
print(f"\n[driver] report saved -> {out} ({len(html)} bytes)")
print("[driver] DONE")
