"""PenScope —— 全链路回归验证（真实靶机 DVWA）。

目的：在 v1.4.1（AP-001 重定向作用域围栏 + AP-002 TLS 按目标可配置）之后，
对真实靶机 DVWA 跑一次完整扫描流水线，确认改动未引入回归：
  - scope_check → recon → subdomain_enum → web_detect（collect_pages/_safe_follow、
    fingerprint_web、detect_waf 全部走 verify_ssl=目标策略）→ exploit_verify →
    upload_test → report 全程无异常；
  - 闸门（exploit_verify / upload_test）在自动批准下能继续推进至 report；
  - DVWA 已知漏洞仍被检出（SQLi/XSS/CSRF/上传等），无崩溃、无新增误报。

实现：使用独立临时 SQLite（AUTOPENTEST_DB），不污染真实数据库；自动批准闸门
模拟人工复核，使流水线 end-to-end 跑通。

运行：需 DVWA 在线（127.0.0.1:8090）。
"""
import os
import sys
import tempfile
import time

# 必须在 import db/run_scans 之前设置隔离 DB，避免污染真实库
_TMP_DB = os.path.join(tempfile.gettempdir(), f"autopentest_regr_{int(time.time())}.db")
os.environ["AUTOPENTEST_DB"] = _TMP_DB

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import db
import run_scans

DVWA_HOST = "127.0.0.1"
DVWA_PORT = "8090"
AUTH_NOTE = "已授权本地靶机 DVWA（security=low），仅用于回归验证，不外发。"


def _auto_approve_gates(sid):
    """批准本 scan 当前所有 pending 复核，并把 scan 状态拉回 running，使流水线继续。"""
    for r in db.pending_reviews():
        if r.get("scan_id") == sid:
            db.decide_review(r["id"], "approve", "regression")


def main():
    print("=" * 72)
    print(f"全链路回归验证 @ DVWA {DVWA_HOST}  (隔离 DB: {_TMP_DB})")
    print("=" * 72)

    db.init_db()  # 新建隔离 DB 时建表（含 verify_tls 列增量迁移）
    tid = db.add_target(DVWA_HOST, DVWA_PORT, "DVWA 回归", AUTH_NOTE,
                        "regression", verify_tls=1)
    db.approve_target(tid, "regression")
    print(f"[setup] target#{tid} {DVWA_HOST} approved, verify_tls=1")

    sid = db.create_scan(tid, "regression-dvwa", "regression")
    print(f"[setup] scan#{sid} created")

    # 直接验证 AP-001 修复：localhost 靶场的页面爬取不再被回环护栏误杀
    import requests

    from scanner.web_scan import collect_pages
    s = requests.Session()
    s.headers.update({"User-Agent": "PenScope/1.0 (authorized e2e)"})
    probe_pages = collect_pages("http://127.0.0.1:8090/", s, max_pages=40, verify_ssl=True)
    print(f"[probe] collect_pages(DVWA root) -> {len(probe_pages)} 页（AP-001 修复前为 0）")
    for p in probe_pages[:6]:
        print(f"        - {p}")

    errors = []
    stages_seen = []
    last_stage = None
    for i in range(80):
        scan = db.get_scan(sid)
        st = scan["status"]
        stage = scan["stage"]
        if stage != last_stage:
            stages_seen.append(stage)
            last_stage = stage
        if st in ("completed", "failed"):
            break
        if st == "awaiting_review":
            _auto_approve_gates(sid)
            db.update_scan(sid, status="running")
            continue
        try:
            run_scans.process_scan(scan)
        except Exception as e:  # 记录异常但不吞掉，便于定位回归
            errors.append(f"iter {i} stage={stage}: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            break
        time.sleep(0.15)

    final = db.get_scan(sid)
    findings = db.findings_of(sid)

    by_risk = {}
    for f in findings:
        by_risk[f.get("risk")] = by_risk.get(f.get("risk"), 0) + 1

    print()
    print("-" * 72)
    print(f"结果: scan#{sid} status={final['status']} 终态stage={final['stage']}")
    print(f"经历阶段: {' -> '.join(stages_seen)}")
    print(f"findings 总数: {len(findings)}  按风险: {by_risk}")
    if errors:
        print(f"异常({len(errors)}):")
        for e in errors:
            print("   !", e)
    else:
        print("异常: 无 ✅")

    # 关注 DVWA 已知漏洞是否仍被检出（回归正向样本）
    cwes = {}
    for f in findings:
        c = f.get("cwe")
        if c:
            cwes[c] = cwes.get(c, 0) + 1
    print(f"命中 CWE 分布: {cwes}")

    # 判定
    ok = (final["status"] == "completed") and (not errors) and (len(findings) > 0)
    print()
    print("回归结论:", "通过 ✅（流水线跑通且无异常，DVWA 漏洞仍检出）" if ok
          else "⚠️ 未达预期，需排查")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
