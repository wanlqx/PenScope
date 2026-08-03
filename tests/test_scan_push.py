"""P-06：pywebview 事件推送（替代前端轮询）单元测试。

验证 run_scans.push_scan_event 在注册窗口后能将阶段事件序列化为合法 JS 并调用
window.evaluate_js；未注册窗口时静默 no-op；窗口异常时吞掉不崩溃。纯函数测试，不依赖数据库 / 网络。
"""
import run_scans as rs


class _FakeWindow:
    def __init__(self):
        self.calls = []
        self.raise_on_call = False

    def evaluate_js(self, js):
        if self.raise_on_call:
            raise RuntimeError("window not ready")
        self.calls.append(js)


def setup_function(_):
    rs.set_push_window(None)  # 每个用例前复位


def test_no_window_is_noop():
    rs.set_push_window(None)
    rs.push_scan_event(123, stage="web_detect", status="start")  # 不应抛异常


def test_push_builds_expected_js():
    w = _FakeWindow()
    rs.set_push_window(w)
    rs.push_scan_event(123, stage="web_detect", status="done", note="ok")
    assert len(w.calls) == 1
    js = w.calls[0]
    assert "window.__autopentestOnScanEvent(" in js
    assert '"scan_id": 123' in js
    assert '"stage": "web_detect"' in js
    assert '"status": "done"' in js
    assert '"type": "scan_event"' in js
    # 整体应是可解析的 JS 调用（以分号结尾）
    assert js.strip().endswith(";")


def test_push_window_exception_swallowed():
    w = _FakeWindow()
    w.raise_on_call = True
    rs.set_push_window(w)
    # 窗口未就绪时不应向上抛，前端仍有兜底轮询
    rs.push_scan_event(1, stage="init", status="start")


def test_set_push_window_none_resets():
    w = _FakeWindow()
    rs.set_push_window(w)
    rs.push_scan_event(5, stage="report", status="done")
    assert len(w.calls) == 1
    rs.set_push_window(None)
    rs.push_scan_event(5, stage="report", status="done")
    assert len(w.calls) == 1  # 复位后不再推送
