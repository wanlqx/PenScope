"""PenScope —— 命令注入 + API 安全 模块 E2E 验证驱动

流程：启动本地模拟靶场 -> 登记并审批授权目标 -> 真实阶段机跑通
scope_check -> recon -> web_detect（触发 exploit_verify 闸门）-> 人工批准闸门
-> exploit_verify（命令注入时间盲注证明）-> report。最后断言发现并生成报告。

使用独立测试数据库（AUTOPENTEST_DB），不污染正式库。
"""
import os
import time

# 必须在导入 db/config 前设置，确保使用独立测试库
_TEST_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_new_modules.db")
if os.path.exists(_TEST_DB):
    os.remove(_TEST_DB)
os.environ["AUTOPENTEST_DB"] = _TEST_DB

import vuln_demo2
import db
import run_scans
import reports


def main():
    port = 18099
    srv = vuln_demo2.start(port)
    base = f"http://127.0.0.1:{port}"
    time.sleep(0.5)

    db.init_db()
    tid = db.add_target("127.0.0.1", "18099",
                        "本地模拟靶场（命令注入+API安全）", "本地授权测试", "tester")
    db.approve_target(tid, "tester")
    sid = db.create_scan(tid, "E2E-CMD-API", "tester")
    print(f"[setup] target#{tid} approved, scan#{sid} created")

    # 1) 驱动阶段机：scope_check -> recon -> web_detect（含命令注入/API安全，触发闸门）
    for _ in range(20):
        s = db.get_scan(sid)
        if s["status"] in ("awaiting_review", "completed", "failed"):
            break
        run_scans.process_scan(s)
    s1 = db.get_scan(sid)
    print(f"[web_detect] status={s1['status']} stage={s1['stage']}")
    cats1 = {}
    for f in db.findings_of(sid):
        cats1[f["category"]] = cats1.get(f["category"], 0) + 1
    print(f"[web_detect] findings: {cats1}")

    # 2) 人工批准 exploit_verify 闸门（命令注入时间盲注证明）
    reviews = db.pending_reviews()
    print(f"[gate] pending reviews: {[(r['id'], r['kind']) for r in reviews]}")
    assert any(r["kind"] == "exploit_verify" for r in reviews), "exploit_verify 闸门未触发"
    for r in reviews:
        db.decide_review(r["id"], "approve", "tester")

    # 3) 继续阶段机：exploit_verify（命令注入时间盲注证明）-> report
    for _ in range(20):
        s = db.get_scan(sid)
        if s["status"] in ("completed", "failed"):
            break
        run_scans.process_scan(s)

    s2 = db.get_scan(sid)
    print(f"[final] status={s2['status']} stage={s2['stage']}")
    cats2 = {}
    for f in db.findings_of(sid):
        cats2[f["category"]] = cats2.get(f["category"], 0) + 1
    print(f"[final] findings: {cats2}")

    cmd_exploit = [f for f in db.findings_of(sid)
                   if f["category"] == "利用验证" and "命令注入" in f["title"]]
    print(f"[final] 命令注入已验证(利用验证)条目: {len(cmd_exploit)}")

    # 3) 报告
    html = reports.build_report(db.get_scan(sid))
    print(f"[report] len={len(html)} | 含命令注入:{('命令注入' in html)} "
          f"含API安全:{('API安全' in html)} 含利用验证:{('利用验证' in html)}")

    # 4) 断言
    assert cats2.get("命令注入", 0) >= 1, "未检测到命令注入"
    assert cats2.get("API安全", 0) >= 1, "未检测到 API 安全问题"
    assert len(cmd_exploit) >= 1, "命令注入未通过闸门时间盲注验证"
    assert s2["status"] == "completed", "扫描未完成"
    assert "命令注入" in html and "API安全" in html, "报告未包含新模块"
    print("\n=== ALL ASSERTIONS PASSED ===")

    srv.shutdown()


if __name__ == "__main__":
    main()
