# -*- coding: utf-8 -*-
"""scanner/advanced_injection.py 单元测试 + 靶机集成验证（P5 CWE 缺口补齐）。

纯逻辑单测（无网络）+ 启动 evolution 靶机对 5 类端点验证均能产出正确 CWE 发现，
并验证非漏洞端点不误报。
"""
import os
import sys
import threading
import time

import pytest
import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "evolution"))
sys.path.insert(0, os.path.join(ROOT, "evolution", "lab"))

from scanner.advanced_injection import (
    scan_ssti, scan_xxe, scan_jwt_none, scan_nosql, scan_idor,
    _xxe_file_hit, _collect_points,
)
from scanner import fp_guard

import vuln_lab

LAB_PORT = 8096


# ---------------------------------------------------------------------------
# 靶机启停（module 级：只启动一次）
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module", autouse=True)
def lab_base():
    t = threading.Thread(target=vuln_lab.run_lab, args=(LAB_PORT,), daemon=True)
    t.start()
    time.sleep(1.0)
    base = f"http://127.0.0.1:{LAB_PORT}"
    # 健康检查：等靶机就绪
    for _ in range(20):
        try:
            requests.get(base + "/ch/z1_07", timeout=1, verify=False)
            break
        except requests.RequestException:
            time.sleep(0.1)
    yield base


def _session():
    s = requests.Session()
    s.headers.update({"User-Agent": "PenScope/1.0"})
    return s


# ---------------------------------------------------------------------------
# 纯逻辑单测（无网络）
# ---------------------------------------------------------------------------
def test_xxe_file_hit():
    assert _xxe_file_hit("root:x:0:0:root:/root:/bin/bash") is True
    assert _xxe_file_hit("normal response page") is False
    assert _xxe_file_hit("") is False


def test_collect_points_parses_query():
    fp_guard.reset_cache()

    class MockResp:
        def __init__(self, text):
            self.text = text
            self.status_code = 200

    class MockSess:
        def get(self, url, **kw):
            return MockResp("<html>no forms here</html>")

    pts = _collect_points("http://x/page?token=1&id=2", MockSess(), 6.0, False)
    params = {p for _, _, p, _ in pts}
    assert "token" in params and "id" in params


def test_ssti_no_false_positive_on_reflected(lab_base):
    """非 SSTI 端点（反射但未求值，仍原样回显 {{）不应报 SSTI。"""
    findings = scan_ssti(f"{lab_base}/ch/z1_02?name=guest", _session(), verify_ssl=False)
    assert findings == [], "反射型但模板未求值的端点不应误报 SSTI"


# ---------------------------------------------------------------------------
# 靶机集成验证：5 类端点均应产出对应 CWE 发现
# ---------------------------------------------------------------------------
def test_ssti_lab(lab_base):
    findings = scan_ssti(f"{lab_base}/ch/z1_09?name=guest", _session(), verify_ssl=False)
    assert len(findings) >= 1, "Z1_09 应检出 SSTI"
    assert any(f["cwe"] == "CWE-1336" for f in findings), findings
    # 强证据：算术被求值（49）
    assert any("49" in (f.get("evidence") or "") for f in findings), "应命中 49 求值强证据"


def test_xxe_lab(lab_base):
    findings = scan_xxe(f"{lab_base}/ch/z1_10", _session(), verify_ssl=False)
    assert len(findings) >= 1, "Z1_10 应检出 XXE"
    assert any(f["cwe"] == "CWE-611" for f in findings), findings


def test_jwt_none_lab(lab_base):
    findings = scan_jwt_none(f"{lab_base}/ch/z1_11?token=x", _session(), verify_ssl=False)
    assert len(findings) >= 1, "Z1_11 应检出 JWT alg:none"
    assert any(f["cwe"] == "CWE-347" for f in findings), findings


def test_nosql_lab(lab_base):
    findings = scan_nosql(f"{lab_base}/ch/z1_12", _session(), verify_ssl=False)
    assert len(findings) >= 1, "Z1_12 应检出 NoSQL 注入"
    assert any(f["cwe"] == "CWE-943" for f in findings), findings


def test_idor_lab(lab_base):
    findings = scan_idor(f"{lab_base}/ch/z1_13?file=1", _session(), verify_ssl=False)
    assert len(findings) >= 1, "Z1_13 应检出 IDOR"
    assert any(f["cwe"] == "CWE-639" for f in findings), findings
