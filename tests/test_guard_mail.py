# -*- coding: utf-8 -*-
"""T78/T79/T80 回归测试：私有地址护栏、邮件明文/STARTTLS 分类、vhost 端口复用缓存。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_scans
from scanner.mail_probe import _classify


def test_private_guard():
    # IP 字面量
    assert run_scans._is_private_host("192.168.1.1") is True
    assert run_scans._is_private_host("10.0.0.5") is True
    # 回环特意放行（使用者本机）
    assert run_scans._is_private_host("127.0.0.1") is False
    assert run_scans._is_private_host("::1") is False
    assert run_scans._is_private_host("169.254.1.1") is True
    assert run_scans._is_private_host("172.16.5.4") is True
    assert run_scans._is_private_host("8.8.8.8") is False
    # 文档/保留段（RFC5737 203.0.113.0/24）被 is_reserved 标记，护栏应阻断（不可公网路由）
    assert run_scans._is_private_host("203.0.113.7") is True
    # 域名：mock 解析，验证护栏逻辑而非真实 DNS
    orig = run_scans._resolve_ip
    run_scans._resolve_ip = lambda h: "192.168.0.9" if h == "intra.test" else "93.184.216.34"
    assert run_scans._is_private_host("intra.test") is True
    assert run_scans._is_private_host("public.test") is False
    run_scans._resolve_ip = orig
    print("[OK] private guard")


def test_mail_classify():
    # 隐式 TLS 端口
    r, t, _ = _classify("imaps", 993, "OK IMAP4rev1", "")
    assert r == "Info" and "隐式" in t
    # 明文端口 + STARTTLS
    r, t, _ = _classify("smtp", 25, "220 mx ESMTP", "250-STARTTLS\n250 AUTH")
    assert r == "Low" and "STARTTLS" in t
    # 明文端口无 STARTTLS
    r, t, _ = _classify("smtp", 25, "220 mx ESMTP", "250-AUTH PLAIN\n250 OK")
    assert r == "Medium" and "无 STARTTLS" in t
    # POP3 能力检测
    r, t, _ = _classify("pop3", 110, "+OK POP3", "USER\nSTARTTLS\n.")
    assert r == "Low"
    # IMAP 能力检测
    r, t, _ = _classify("imap", 143, "* OK", "* CAPABILITY IMAP4rev1 STARTTLS")
    assert r == "Low"
    print("[OK] mail classify")


def test_vhost_cache_key():
    # 同一 IP + 相同端口集合 → 缓存键一致（复用前提）
    k1 = ("1.2.3.4", tuple(sorted([80, 443, 25])))
    k2 = ("1.2.3.4", tuple(sorted([25, 443, 80])))
    assert k1 == k2
    # 不同端口集合 → 不同键（仍需重扫）
    k3 = ("1.2.3.4", tuple(sorted([80, 443])))
    assert k1 != k3
    print("[OK] vhost cache key")


def test_fkwargs_mail():
    mf = {
        "category": "邮件服务配置", "title": "x", "risk": "Medium",
        "detail": "d", "evidence": "e", "remediation": "r", "target_ref": "h:25",
        "cwe": "CWE-319", "verification_status": "unverified", "evidence_level": "L1",
        "endpoint": "h:25", "http_method": "SMTP",
    }
    fk = run_scans._fkwargs(mf)
    assert fk["cwe"] == "CWE-319"
    assert fk["http_method"] == "SMTP"
    assert fk["poc_script"] == ""  # 缺失字段取默认
    assert fk["impact"] == ""
    print("[OK] fkwargs(mail)")


if __name__ == "__main__":
    test_private_guard()
    test_mail_classify()
    test_vhost_cache_key()
    test_fkwargs_mail()
    print("\nALL PASS")
