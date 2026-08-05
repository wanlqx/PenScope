# -*- coding: utf-8 -*-
"""scanner/reflexion.py 单元测试 —— Reflexion 自检层（_decide 纯逻辑）。

用按 URL 区分的 mock session 模拟真实场景：
- baseline 探针（含 nonce）返回 404 页
- target（真实 endpoint）返回不同响应
从而验证软 404 / 拒绝页 / 非 200 等判定正确降级，正常内容正确保留。

autouse fixture 在每个 test 前重置 fp_guard 基线缓存，避免跨 test 污染。
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import fp_guard, reflexion

@pytest.fixture(autouse=True)
def _reset_fp_cache():
    fp_guard.reset_cache()
    yield


_BASELINE = "not found 404 page generic"


class MockResp:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code


class MockSessURL:
    """按 URL 区分响应：baseline(nonce) 返回 404 页，target 返回指定内容。"""

    def __init__(self, target_text, target_status=200):
        self.target_text = target_text
        self.target_status = target_status

    def get(self, url, **kw):
        if "penscope_fp_guard_baseline" in url:
            return MockResp(_BASELINE, 200)
        return MockResp(self.target_text, self.target_status)


def _finding(el="L3", vs="unverified"):
    return {"id": 1, "endpoint": "http://x/admin", "evidence_level": el,
            "verification_status": vs}


def test_decide_soft404_downgrade():
    sess = MockSessURL(_BASELINE, 200)  # target 与基线相同 = 软 404
    verdict, reason = reflexion._decide(_finding(), sess, True, 6)
    assert verdict == "downgrade" and reason == "soft404_now"


def test_decide_denied_downgrade():
    sess = MockSessURL("please login to continue", 200)
    verdict, reason = reflexion._decide(_finding(), sess, True, 6)
    assert verdict == "downgrade" and reason == "denied_page_now"


def test_decide_404_downgrade():
    sess = MockSessURL("not found", 404)
    verdict, reason = reflexion._decide(_finding(), sess, True, 6)
    assert verdict == "downgrade" and reason == "status_now_404"


def test_decide_redirect_downgrade():
    sess = MockSessURL("moved", 302)
    verdict, reason = reflexion._decide(_finding(), sess, True, 6)
    assert verdict == "downgrade" and reason == "redirected_302"


def test_decide_pass():
    sess = MockSessURL("real admin dashboard content secret data", 200)
    verdict, reason = reflexion._decide(_finding(), sess, True, 6)
    assert verdict == "keep" and reason == "pass"


def test_decide_conservative_status_keep():
    # 405/403 等 GET 不被允许 -> 保守保留，不降级
    sess = MockSessURL("method not allowed", 405)
    verdict, reason = reflexion._decide(_finding(), sess, True, 6)
    assert verdict == "keep" and reason == "conservative_status_405"


def test_decide_no_url_keep():
    f = {"id": 1, "endpoint": "", "evidence_level": "L3", "verification_status": "unverified"}
    sess = MockSessURL("x", 200)
    verdict, reason = reflexion._decide(f, sess, True, 6)
    assert verdict == "keep" and reason == "no_reviewable_url"


def test_decide_request_error_keep():
    class ErrSess:
        def get(self, url, **kw):
            raise RuntimeError("network down")

    f = _finding()
    verdict, reason = reflexion._decide(f, ErrSess(), True, 6)
    assert verdict == "keep" and reason.startswith("request_error")
