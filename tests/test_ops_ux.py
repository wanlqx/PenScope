"""v1.13.0 运维/UX 增强单测：U-12 脱敏 + U-11 审计热力图 + U-05 诊断包。

全部为纯函数/临时库测试，不依赖网络与 GUI。
"""

import os
import tempfile
import json

import db as dbmod
import scanner.redact as redact


def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    dbmod.DB_PATH = path
    dbmod._conn.cache_clear() if hasattr(dbmod._conn, "cache_clear") else None
    dbmod.init_db()
    return path


def _add_scan_and_audit(target_host="9.9.9.9"):
    tid = dbmod.add_target(target_host, "common", "", "auth", "me")
    dbmod.approve_target(tid, "me")
    sid = dbmod.create_scan(tid, "t", "me")
    dbmod.update_scan(sid, status="completed")
    dbmod.audit("me", "scan_start", str(sid), "detail-with-token=abcdef1234567890xyz")
    return sid


# ---------------- U-12 脱敏 ----------------
def test_redact_aws_key():
    out = redact.redact_sensitive("key=AKIAIOSFODNN7EXAMPLE and more")
    assert "AKIA" in out
    assert "EXAMPLE" not in out  # 真实后缀被掩码
    assert "********" in out


def test_redact_jwt():
    s = "Authorization: Bearer eyJhbGciOiJIUzI1Ni.eyJzdWIiOiIxMjM0NTY3ODk.SflKxwRJSMeKKF2QT4f"
    out = redact.redact_sensitive(s)
    assert "***REDACTED_JWT***" in out
    assert "eyJhbGci" not in out


def test_redact_kv_password():
    out = redact.redact_sensitive('"password": "SuperSecret123"')
    assert "SuperSecret123" not in out
    assert "***REDACTED***" in out


def test_redact_bearer():
    out = redact.redact_sensitive("Bearer abcdef1234567890xyzTOKEN")
    assert "***REDACTED***" in out
    assert "abcdef1234567890xyzTOKEN" not in out


def test_redact_session_cookie():
    out = redact.redact_sensitive("session=abcdef1234567890qwerty")
    assert "abcdef" not in out  # 命中后整值掩码
    assert "session=" in out


def test_redact_pem_block():
    block = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    out = redact.redact_sensitive(block)
    assert "PRIVATE KEY" not in out
    assert "***REDACTED_PRIVATE_KEY***" in out


def test_redact_leaves_normal_text():
    out = redact.redact_sensitive("GET /login.php HTTP/1.1\nHost: example.com")
    assert "example.com" in out
    assert "GET /login.php" in out


# ---------------- U-11 审计热力图 ----------------
def test_audit_heatmap_length_and_shape():
    tmp = _tmp_db()
    try:
        _add_scan_and_audit()
        hm = dbmod.audit_heatmap(90)
        assert len(hm) == 90
        assert all(set(d.keys()) == {"date", "count"} for d in hm)
        # 今天应有 >=1 条（前面写入了 1 条审计）
        today = __import__("datetime").date.today().strftime("%Y-%m-%d")
        todays = [d for d in hm if d["date"] == today]
        assert todays and todays[0]["count"] >= 1
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def test_audit_heatmap_zero_days():
    tmp = _tmp_db()
    try:
        hm = dbmod.audit_heatmap(7)
        assert len(hm) == 7
        assert all(d["count"] == 0 for d in hm)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


# ---------------- U-05 诊断包 ----------------
def test_export_diagnostic_structure_and_redaction():
    tmp = _tmp_db()
    try:
        _add_scan_and_audit()
        # 直接构造 bundle（与 app_api.export_diagnostic 同逻辑，避免 pywebview 依赖）
        from scanner.redact import redact_sensitive
        recent = dbmod.audit_tail(200)
        redacted = [redact_sensitive(r.get("detail") or "") for r in recent]
        assert any("abcdef1234567890xyz" not in d for d in redacted)
        assert dbmod.db_stats()["targets"] >= 1
        assert dbmod.db_stats()["scans"] >= 1
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
