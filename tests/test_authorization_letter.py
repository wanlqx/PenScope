"""v1.14.0 渗透测试授权书（U-10）单元测试

覆盖 build_authorization_letter：
  - 返回完整 HTML 字符串（含 DOCTYPE / 浅色主题 / 打印 CSS）
  - 嵌入目标 host / 端口 / 文档编号 / 备注
  - 含签署栏（Signature）与 30 天有效期声明
  - 对目标字段做 HTML 转义（防 XSS 注入）
  - 支持 date_str 覆盖签发日期
  - 无备注时不渲染「目标备注」段
"""
import reports


def _target(host="192.168.1.10", ports="80,443", ref="AUTH-2026-001", note="内部测试"):
    return {"host": host, "port_range": ports, "authorization": ref, "note": note}


def test_letter_is_full_html_with_light_theme():
    html = reports.build_authorization_letter(_target(), "analyst")
    assert isinstance(html, str)
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert "</html>" in html
    assert "渗透测试授权书" in html
    # 浅色文档主题（白底）
    assert "#fff" in html
    # 打印优化 CSS
    assert "@media print" in html


def test_letter_contains_scope_and_sign_and_validity():
    html = reports.build_authorization_letter(_target(), "analyst")
    assert "192.168.1.10" in html                 # 测试目标主机
    assert "80,443" in html                        # 端口范围
    assert "AUTH-2026-001" in html                 # 文档编号
    assert "签署" in html and "Signature" in html  # 签署栏
    assert "30" in html                            # 30 个自然日有效期
    assert "内部测试" in html                       # 目标备注


def test_letter_escapes_host_to_prevent_xss():
    html = reports.build_authorization_letter(
        _target(host='<script>alert(1)</script>'), "me"
    )
    # 原始标签不得原样出现（已被转义）
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_letter_date_override():
    html = reports.build_authorization_letter(
        _target(), "me", date_str="2026-08-02"
    )
    assert "2026-08-02" in html


def test_letter_omits_note_when_empty():
    html = reports.build_authorization_letter(
        _target(note=""), "me"
    )
    assert "目标备注" not in html
