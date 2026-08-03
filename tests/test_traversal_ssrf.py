"""单元测试：路径遍历(CWE-22) 与 SSRF(CWE-918) 检测模块（纯本地 mock，无真实网络）。

覆盖：
  - 路径遍历：强证据命中 / 基线已含特征(防误报) / 无特征不报
  - SSRF：file:// 本地文件读取命中 / 云元数据命中 / 仅 URL 参数(注入点观察) / 无相关参数不报
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.ssrf import _URL_PARAM_RE, _detect_metadata, scan_ssrf
from scanner.traversal import _detect_file_content, scan_traversal


class _Resp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status


class _MockSession:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def get(self, url, params=None, timeout=None, verify=None, allow_redirects=None, **kw):
        self.calls.append(("GET", url, params))
        return _Resp(self.responder("GET", url, params))

    def post(self, url, data=None, timeout=None, verify=None, **kw):
        self.calls.append(("POST", url, data))
        return _Resp(self.responder("POST", url, data))


PASSWD = "root:x:0:0:root:/root:/bin/bash\nroot:*:0:0:"


def _vals(payload):
    """_send_form 以 dict(params/data) 形式传递输入，这里取出实际注入值字符串。"""
    if isinstance(payload, dict):
        return " ".join(str(v) for v in payload.values())
    return str(payload) if payload is not None else ""


# ---------- 路径遍历 ----------
def test_traversal_positive():
    def resp(method, url, payload):
        # 无载荷(passwd=None)返回空：既无表单也无基线特征
        if "etc/passwd" in _vals(payload) or "win.ini" in _vals(payload):
            return PASSWD
        return ""
    s = _MockSession(resp)
    fs = scan_traversal("http://t/?file=1", s)
    assert len(fs) == 1, f"期望 1 条命中，实际 {len(fs)}: {fs}"
    f = fs[0]
    assert f["category"] == "路径遍历"
    assert f["risk"] == "Medium"
    assert f["cwe"] == "CWE-22"
    assert f["verification_status"] == "unverified"
    assert f["evidence_level"] == "L2"
    print("PASS test_traversal_positive")


def test_traversal_fp_avoid():
    # 基线已含 passwd 特征 -> 不应判定（防把页面固有内容当漏洞）
    def resp(method, url, payload):
        return PASSWD  # 任何请求都返回 passwd，包括基线
    s = _MockSession(resp)
    fs = scan_traversal("http://t/?file=1", s)
    assert len(fs) == 0, f"基线已含特征时不应报，实际 {len(fs)}"
    print("PASS test_traversal_fp_avoid")


def test_traversal_no_marker():
    def resp(method, url, payload):
        return "<html>normal page</html>"
    s = _MockSession(resp)
    fs = scan_traversal("http://t/?name=1", s)
    assert len(fs) == 0, f"无特征不应报，实际 {len(fs)}"
    print("PASS test_traversal_no_marker")


def test_traversal_detect_helper():
    assert _detect_file_content(PASSWD) == ("linux", "root:x:0:0:")
    assert _detect_file_content("; for 16-bit app support") == ("win", "; for 16-bit app support")
    assert _detect_file_content("hello") is None
    print("PASS test_traversal_detect_helper")


# ---------- SSRF ----------
def test_ssrf_file_hit():
    def resp(method, url, payload):
        if _vals(payload) == "file:///etc/passwd":
            return PASSWD
        return ""
    s = _MockSession(resp)
    fs = scan_ssrf("http://t/?url=http://x", s)
    hit = [f for f in fs if f["risk"] == "High"]
    assert len(hit) == 1, f"期望 1 条 High(file)，实际 {fs}"
    assert hit[0]["cwe"] == "CWE-918"
    assert hit[0]["evidence_level"] == "L3"
    print("PASS test_ssrf_file_hit")


def test_ssrf_metadata_hit():
    def resp(method, url, payload):
        if "169.254.169.254" in _vals(payload):
            return '{"instance-id":"i-abc","local-ipv4":"10.0.0.1"}'
        return ""
    s = _MockSession(resp)
    fs = scan_ssrf("http://t/?url=http://x", s)
    hit = [f for f in fs if "元数据" in f["title"]]
    assert len(hit) == 1, f"期望 1 条元数据 High，实际 {fs}"
    assert _detect_metadata('{"instance-id":"i-abc"}') == '"instance-id"'
    print("PASS test_ssrf_metadata_hit")


def test_ssrf_sink_only():
    # 普通 URL 参数，无强证据 -> 仅 Low 注入点观察
    def resp(method, url, payload):
        return "<html>ok</html>"
    s = _MockSession(resp)
    fs = scan_ssrf("http://t/?url=http://example.com", s)
    low = [f for f in fs if f["risk"] == "Low" and "注入点" in f["title"]]
    high = [f for f in fs if f["risk"] == "High"]
    assert len(low) == 1, f"期望 1 条 Low 注入点，实际 {fs}"
    assert len(high) == 0, "无强证据不应报 High"
    print("PASS test_ssrf_sink_only")


def test_ssrf_no_url_param():
    def resp(method, url, payload):
        return "<html>ok</html>"
    s = _MockSession(resp)
    fs = scan_ssrf("http://t/", s)  # 无查询参数、无表单
    assert len(fs) == 0, f"无相关参数不应报，实际 {len(fs)}"
    print("PASS test_ssrf_no_url_param")


def test_ssrf_param_regex():
    assert _URL_PARAM_RE.search("url")
    assert _URL_PARAM_RE.search("avatar")
    assert _URL_PARAM_RE.search("redirect")
    assert not _URL_PARAM_RE.search("name")
    assert not _URL_PARAM_RE.search("q")
    print("PASS test_ssrf_param_regex")


if __name__ == "__main__":
    test_traversal_detect_helper()
    test_traversal_positive()
    test_traversal_fp_avoid()
    test_traversal_no_marker()
    test_ssrf_param_regex()
    test_ssrf_file_hit()
    test_ssrf_metadata_hit()
    test_ssrf_sink_only()
    test_ssrf_no_url_param()
    print("\nALL TESTS PASSED")
