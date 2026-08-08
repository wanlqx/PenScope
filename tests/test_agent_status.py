"""F-10 桌面端 Agent 状态栏 —— 状态模型与推送 seam 单元测试。

纯函数 / 纯逻辑，不依赖数据库、网络或 GUI。验证：默认态、状态切换、
订阅回调、非法态拒绝、推送 no-op（无窗口）、推送正确 JS（有窗口）。
"""
import unittest

from scanner import agent_status as m


class _FakeWindow:
    def __init__(self):
        self.calls = []

    def evaluate_js(self, js):
        self.calls.append(js)


class TestAgentStatusBar(unittest.TestCase):
    def test_default_state_is_idle(self):
        bar = m.AgentStatusBar()
        self.assertEqual(bar.get_state(), m.STATE_IDLE)
        snap = bar.snapshot()
        self.assertEqual(snap["state"], m.STATE_IDLE)
        self.assertIn("ts", snap)
        self.assertIn("meta", snap)

    def test_set_state_updates_snapshot_and_note(self):
        bar = m.AgentStatusBar()
        snap = bar.set_state(m.STATE_SCANNING, note="端口扫描中")
        self.assertEqual(bar.get_state(), m.STATE_SCANNING)
        self.assertEqual(snap["note"], "端口扫描中")
        self.assertEqual(bar.snapshot()["note"], "端口扫描中")

    def test_set_state_carries_meta(self):
        bar = m.AgentStatusBar()
        bar.set_state(m.STATE_VERIFYING, scan_id="s1", target_id="t2", progress=0.5)
        meta = bar.snapshot()["meta"]
        self.assertEqual(meta.get("scan_id"), "s1")
        self.assertEqual(meta.get("target_id"), "t2")
        self.assertEqual(meta.get("progress"), 0.5)

    def test_invalid_state_rejected_as_error(self):
        bar = m.AgentStatusBar()
        snap = bar.set_state("bogus_state", note="x")
        self.assertEqual(snap["state"], m.STATE_ERROR)
        self.assertIn("未知状态被拒绝", snap["note"])

    def test_subscriber_called_on_change(self):
        bar = m.AgentStatusBar()
        seen = []
        unsub = bar.subscribe(lambda s: seen.append(s))
        bar.set_state(m.STATE_RECON, note="指纹识别")
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["state"], m.STATE_RECON)
        # 取消订阅后不再收到
        unsub()
        bar.set_state(m.STATE_REPORTING)
        self.assertEqual(len(seen), 1)

    def test_reset_returns_to_idle(self):
        bar = m.AgentStatusBar()
        bar.set_state(m.STATE_ERROR, note="boom")
        bar.reset()
        self.assertEqual(bar.get_state(), m.STATE_IDLE)
        self.assertIsNone(bar.snapshot()["note"])


class TestPushAgentStatus(unittest.TestCase):
    def test_no_window_is_noop(self):
        # 不注册窗口，也不传 window -> 静默返回，不抛异常
        try:
            m.push_agent_status(m.STATE_THINKING, note="路由中")
        except Exception as e:  # pragma: no cover
            self.fail("无窗口时不应抛异常: %s" % e)

    def test_pushes_correct_js_with_window(self):
        win = _FakeWindow()
        m.push_agent_status(m.STATE_SCANNING, note="主动探针", window=win,
                            scan_id="s9", target_id="t9")
        self.assertEqual(len(win.calls), 1)
        js = win.calls[0]
        self.assertIn("window.__autopentestOnAgentStatus &&", js)
        self.assertIn('"type": "agent_status"', js)
        self.assertIn('"state": "scanning"', js)
        self.assertIn('"scan_id": "s9"', js)
        self.assertIn('"target_id": "t9"', js)
        self.assertIn('"note": "主动探针"', js)

    def test_window_exception_swallowed(self):
        class BoomWindow:
            def evaluate_js(self, js):
                raise RuntimeError("window gone")

        try:
            m.push_agent_status(m.STATE_ERROR, window=BoomWindow())
        except Exception as e:  # pragma: no cover
            self.fail("窗口异常应被静默吞掉: %s" % e)


if __name__ == "__main__":
    unittest.main()
