"""v1.9.0 检测深度三件套（C-02/C-03/C-04）单元测试

覆盖：
  - C-02 响应差异基线建模：is_significant_delay 的 3σ 抖动吸收 / 单点退化
  - C-03 WAF 自适应：_evade_for 按 WAF 分派规避变换 + 去重
  - C-04 CVE 联动：match_vulns 版本命中（含"已修补版本不告警"）
全部为纯函数测试，不依赖数据库 / 网络。
"""
import pytest

import scanner.baseline as baseline
import scanner.payloads as payloads
import scanner.vuln_db as vuln_db


# ---------------- C-02 ----------------
def test_is_significant_delay_flags_real_injection():
    # 良性基线：稳定 ~0.1s；注入导致 2s 延迟 => 应判定为显著
    base = [0.10, 0.12, 0.11, 0.13, 0.10]
    assert baseline.is_significant_delay(2.0, base, delay=2.0) is True


def test_is_significant_delay_rejects_within_jitter():
    # 瞬时抖动（0.25s）仍在 3σ 内，远低于注入延迟量级 => 不误报
    base = [0.10, 0.12, 0.11, 0.13, 0.10]
    assert baseline.is_significant_delay(0.25, base, delay=2.0) is False


def test_is_significant_delay_rejects_below_magnitude():
    # 延迟太小（< delay*0.6），即便高于基线也不算（可能是慢响应）
    base = [0.10, 0.11, 0.10, 0.12, 0.10]
    assert baseline.is_significant_delay(0.5, base, delay=2.0) is False


def test_is_significant_delay_falls_back_when_few_samples():
    # 基线样本不足（<3）：退化为保守单点比较（dt >= mean + max(delay*0.75, 1.5)）
    base = [0.10]
    assert baseline.is_significant_delay(2.0, base, delay=2.0) is True   # 远超 1.5 阈值
    assert baseline.is_significant_delay(0.4, base, delay=2.0) is False  # 低于 1.5 阈值


def test_sample_times_collects_and_skips_errors():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")  # 模拟一次超时/异常
        return 0.1 * calls["n"]

    times = baseline.sample_times(fn, n=5)
    assert len(times) == 4          # 异常那次被跳过
    assert times == pytest.approx([0.1, 0.3, 0.4, 0.5])


def test_baseline_digest_shape():
    d = baseline.baseline_digest([0.1, 0.2, 0.15])
    assert d["n"] == 3
    assert isinstance(d["mean"], float) and isinstance(d["std"], float)
    assert baseline.baseline_digest([])["n"] == 0


# ---------------- C-03 ----------------
def test_evade_none_returns_unchanged():
    pl = ["' OR 1=1--", "<script>alert(1)</script>"]
    assert payloads._evade_for(None, pl) == pl


def test_evade_cloudflare_inserts_inline_comment():
    variants = payloads._evade_for("Cloudflare", ["' OR 1=1--"])
    assert "' OR 1=1--" in variants
    # Cloudflare 策略含内联注释变换 => 至少出现一个含 /**/ 的变体
    assert any("/**/" in v for v in variants)


def test_evade_modsecurity_inserts_tab():
    variants = payloads._evade_for("ModSecurity", ["' OR 1=1--"])
    assert any("\t" in v for v in variants)  # ModSecurity 策略含 _t_tab


def test_evade_unknown_waf_uses_generic_set():
    # 已知但无专属策略 / 疑似 WAF => 通用规避（含 URL 编码变体）
    variants = payloads._evade_for("未知WAF", ["<script>alert(1)</script>"])
    assert any("%3C" in v or "%3c" in v for v in variants)


def test_evade_dedupes():
    # 多种变换可能生成相同变体，结果应去重
    variants = payloads._evade_for("Cloudflare", ["' OR 1=1--"])
    assert len(variants) == len(set(variants))


# ---------------- C-04 ----------------
def test_match_vulns_apache_vulnerable_version():
    hits = vuln_db.match_vulns("", "Apache/2.4.41 (Win64) OpenSSL/1.1.1")
    assert any(h["service"] == "Apache" and h["version"] == "2.4.41" for h in hits)


def test_match_vulns_openssh_vulnerable():
    hits = vuln_db.match_vulns("", "OpenSSH_7.4p1 Debian-10")
    assert any(h["service"] == "OpenSSH" for h in hits)


def test_match_vulns_patched_version_not_flagged():
    # 已修补版本（不在危险版本列表）不应告警（vsftpd 仅 2.3.4 命中，3.0.3 安全）
    hits = vuln_db.match_vulns("", "vsftpd 3.0.3")
    assert hits == []


def test_match_vulns_nginx_old_flagged():
    # 1.17.x 属于 CVE-2019-9511 影响范围，应命中
    hits = vuln_db.match_vulns("", "nginx/1.17.2")
    assert any(h["service"] == "nginx" for h in hits)


def test_match_vulns_nginx_patched_not_flagged():
    # 1.18.0 及以后已修复 CVE-2019-9511，不应告警
    assert vuln_db.match_vulns("", "nginx/1.18.0") == []
    assert vuln_db.match_vulns("", "nginx/1.21.0") == []
    assert vuln_db.match_vulns("", "nginx/1.21.6") == []


def test_match_vulns_empty_banner_no_hits():
    assert vuln_db.match_vulns("", "") == []
