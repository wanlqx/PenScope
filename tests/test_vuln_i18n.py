"""v1.15.0 漏洞描述双语映射（U-07）单元测试

覆盖 scanner.vuln_i18n：
  - localize 命中返回目标语言文本；缺失字段/缺失 CWE 回退 default
  - localize 对非法 lang 回退 zh
  - map_for_lang 仅返回该语言有定义的字段，且结构为 {cwe: {name, remediation}}
  - 已知 CWE（如 CWE-79 / CWE-89）在两种语言下均有 name 定义
"""
from scanner.vuln_i18n import VULN_I18N, localize, map_for_lang


def test_localize_returns_lang_text():
    assert localize("CWE-79", "name", "en") == "Cross-site Scripting (XSS)"
    assert localize("CWE-79", "name", "zh") == "跨站脚本（XSS）"


def test_localize_missing_field_falls_back():
    # 不存在的字段 / 不存在的 CWE → 回退到传入 default
    assert localize("CWE-79", "nope", "en", "DFLT") == "DFLT"
    assert localize("CWE-0000", "name", "en", "DFLT") == "DFLT"


def test_localize_invalid_lang_falls_back_to_zh():
    assert localize("CWE-89", "name", "fr") == "SQL 注入"


def test_map_for_lang_structure_and_fields():
    m = map_for_lang("en")
    assert "CWE-79" in m
    assert m["CWE-79"]["name"] == "Cross-site Scripting (XSS)"
    # 仅含该语言有定义的字段
    assert set(m["CWE-79"].keys()) <= {"name", "remediation"}
    # 每个条目必含 name 或 remediation 之一（map_for_lang 丢弃空项）
    for cwe, item in m.items():
        assert item


def test_known_cwes_have_both_lang_names():
    for cwe in ("CWE-79", "CWE-89", "CWE-22", "CWE-918", "CWE-601",
                "CWE-862", "CWE-287", "CWE-200", "CWE-693", "CWE-1035"):
        assert cwe in VULN_I18N, "已知 CWE 应纳入双语映射"
        assert VULN_I18N[cwe]["name"]["en"]
        assert VULN_I18N[cwe]["name"]["zh"]
