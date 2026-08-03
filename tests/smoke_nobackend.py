"""无后端模式 Python 侧冒烟测试：验证接口层与数据层可正常 import 并工作。"""
import os
import tempfile

# 用临时数据库，避免污染项目库
_tmp = os.path.join(tempfile.gettempdir(), "autopentest_nobackend_test.db")
if os.path.exists(_tmp):
    os.remove(_tmp)
os.environ["AUTOPENTEST_DB"] = _tmp

import config
import db
import app_api

print("== config ==")
print("VERSION:", config.VERSION, "| DB_PATH:", config.DB_PATH)
print("BUNDLE_DIR exists:", os.path.isdir(config.BUNDLE_DIR))
print("frontend exists:", os.path.isfile(os.path.join(config.BUNDLE_DIR, "frontend", "index.html")))

db.init_db()
api = app_api.Api()

print("\n== app_info ==")
print(api.app_info())

print("\n== add_target (未授权应被拒) ==")
r = api.add_target("http://127.0.0.1", "common", "", "", False)
print(r)

print("\n== add_target (已授权应自动批准) ==")
r = api.add_target("http://127.0.0.1:80", "common", "note", "PT-2026-0731", True)
print(r)
tid = r.get("tid")

print("\n== list_targets ==")
ts = api.list_targets()
print("count:", len(ts), "| status:", ts[0]["status"] if ts else None)

print("\n== create_scan ==")
r = api.create_scan(tid, "冒烟测试扫描")
print(r)
sid = r.get("sid")

print("\n== list_scans ==")
print("count:", len(api.list_scans(50)))

print("\n== get_scan / findings_of ==")
print("scan:", api.get_scan(sid))
print("findings:", api.findings_of(sid))

print("\n== build_report (空扫描应返回 html) ==")
r = api.build_report(sid)
print("ok:", r.get("ok"), "| html_len:", len(r.get("html", "")))

print("\n== settings 默认/读写 ==")
print("default:", api.get_settings())
api.set_settings({"language": "en", "theme": "light", "font_size": "16", "layout": "compact"})
print("updated:", api.get_settings())

print("\n== 发现去重 ==")
# 模拟同一次扫描连续写入相同发现
from db import add_finding, findings_of
add_finding(sid, "端口暴露", "开放端口 22/ssh", "Info", "服务: ssh", "SSH-2.0", "关闭端口", "192.168.1.1:22")
add_finding(sid, "端口暴露", "开放端口 22/ssh", "Info", "服务: ssh", "SSH-2.0", "关闭端口", "192.168.1.1:22")
add_finding(sid, "端口暴露", "开放端口 22/ssh", "Info", "服务: ssh", "duplicate evidence", "关闭端口", "192.168.1.1:22")
print("findings count after 3 dup inserts:", len(findings_of(sid)))

print("\n== build_report 内容检查 ==")
r = api.build_report(sid)
html = r.get("html", "")
print("contains CVSS:", "CVSS 3.1" in html)
print("contains 复现步骤:", "复现步骤" in html or "Reproduction Steps" in html)
print("contains 修复建议:", "修复建议" in html or "Remediation" in html)
print("contains 预防措施:", "预防措施" in html or "Prevention" in html)

print("\n== reviews / scheduler / audit ==")
print("reviews:", api.list_reviews())
print("schedules:", api.list_schedules())
print("audit_tail(3):", len(api.audit_tail(3)))

print("\nALL OK")
if os.path.exists(_tmp):
    os.remove(_tmp)
