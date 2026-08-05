# -*- coding: utf-8 -*-
"""scanner/fp_guard.py 单元测试 —— 统一误报门控层。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import fp_guard


def test_similarity_identical():
    assert fp_guard.similarity("a b c", "a b c") == 1.0


def test_similarity_near():
    s = fp_guard.similarity("page not found 404", "page not found 404 oops")
    assert 0.7 < s < 1.0


def test_similarity_distinct():
    assert fp_guard.similarity("DB_HOST=x", "welcome nginx") < 0.3


def test_similarity_empty():
    assert fp_guard.similarity("", "x") == 0.0
    assert fp_guard.similarity("", "") == 0.0  # 双空无内容可比，保守不相似


def test_soft404_filter():
    assert fp_guard.soft404_filter("not found 404", "not found 404") is True
    assert fp_guard.soft404_filter("real env DB_HOST=localhost", "not found 404") is False
    # 无基线时退化为不比对（False）
    assert fp_guard.soft404_filter("anything", "") is False


def test_is_denied_page():
    assert fp_guard.is_denied_page("please login to continue") is True
    assert fp_guard.is_denied_page("需要登录后访问") is True
    assert fp_guard.is_denied_page("welcome home") is False
    assert fp_guard.is_denied_page("") is False


def test_is_error_page():
    assert fp_guard.is_error_page("404 Not Found file or directory") is True
    assert fp_guard.is_error_page("internal server error") is True
    assert fp_guard.is_error_page("normal content") is False


def test_is_public_path():
    assert fp_guard.is_public_path("/login") is True
    assert fp_guard.is_public_path("/wp-admin") is True
    assert fp_guard.is_public_path("/admin") is False


def test_status_gate():
    assert fp_guard.status_gate(200) is True
    assert fp_guard.status_gate(404) is False
    assert fp_guard.status_gate(302, (200, 302)) is True


def test_baseline_probe_cache():
    class MockResp:
        def __init__(self, text):
            self.text = text
            self.status_code = 200

    class MockSess:
        def __init__(self):
            self.calls = 0

        def get(self, url, **kw):
            self.calls += 1
            return MockResp("generic 404 page")

    fp_guard.reset_cache()
    s = MockSess()
    b1 = fp_guard.baseline_probe(s, "http://x/")
    b2 = fp_guard.baseline_probe(s, "http://x/")  # 缓存命中，不重复请求
    assert s.calls == 1, s.calls
    assert b1 == "generic 404 page"
