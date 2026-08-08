"""F-10：桌面端 Agent 状态栏 —— 状态模型与推送脚手架（仅后端，未落地 GUI）。

PenScope 是 pywebview 纯本地桌面工具。扫描执行期间，前端需要一个常驻的
"Agent 状态栏"展示 AI 副驾当前所处阶段（思考 / 侦查 / 扫描 / 验证 / 待人工 /
出报告 / 出错），让用户随时知道后台在干什么，避免"卡住"观感。

本模块是**脚手架**：只提供
  1) 线程安全的 Agent 状态机（AgentStatusBar）；
  2) 与 run_scans.push_scan_event 同构的推送 seam（push_agent_status）；
  3) 可选订阅回调（供测试 / 非 GUI 场景复用）。

GUI 落地（前端 DOM 元素 + window.__autopentestOnAgentStatus 渲染 + fx-off 视觉闸）
属"需用户确认"级，见 docs/status_bar_design.md，不在本次自动循环内落地。

仅依赖标准库 + scanner.logctx（无循环依赖、无 GUI 依赖），可被任意模块 / 测试导入。
"""
import json
import threading
import time

from scanner.logctx import get_scan_context

# Agent 生命周期状态（字符串常量，便于 JSON 序列化直推前端）。
STATE_IDLE = "idle"
STATE_THINKING = "thinking"          # AI 推理 / 路由调度
STATE_RECON = "recon"                # 侦查 / 指纹识别
STATE_SCANNING = "scanning"          # 只读主动探针
STATE_VERIFYING = "verifying"        # 证据收敛 / 三路裁决
STATE_AWAITING_HUMAN = "awaiting_human"  # 人工复核闸门待决（高危动作拦截）
STATE_REPORTING = "reporting"        # 报告生成
STATE_ERROR = "error"

VALID_STATES = {
    STATE_IDLE, STATE_THINKING, STATE_RECON, STATE_SCANNING,
    STATE_VERIFYING, STATE_AWAITING_HUMAN, STATE_REPORTING, STATE_ERROR,
}

# 推送窗口（由 main_gui 在窗口创建后注册；未注册时静默 no-op）。
_PUSH_WINDOW = None


def set_agent_status_window(w):
    """main_gui 在创建窗口后注册可推送的 pywebview 窗口对象（落地时调用）。"""
    global _PUSH_WINDOW
    _PUSH_WINDOW = w


class AgentStatusBar:
    """线程安全的 Agent 状态机。

    持有当前状态 + 备注 + 时间戳 + 可选 meta（scan_id / target_id / progress）。
    支持订阅回调：状态变更时同步通知所有订阅者（测试 / 日志桥接 / 未来 GUI 适配器）。
    """

    def __init__(self, state=STATE_IDLE):
        self._lock = threading.Lock()
        self._state = state if state in VALID_STATES else STATE_IDLE
        self._note = None
        self._meta = {}
        self._ts = int(time.time() * 1000)
        self._subscribers = []

    def set_state(self, state, note=None, **meta):
        """切换状态（含校验），并广播给所有订阅者。meta 可携带 scan_id/target_id/progress。"""
        if state not in VALID_STATES:
            # 非法状态不静默吞掉，显式转 error 并留痕，避免前端渲染未知态。
            state = STATE_ERROR
            note = (note or "") + " [未知状态被拒绝]"
        with self._lock:
            self._state = state
            self._note = note
            self._meta = dict(meta)
            self._ts = int(time.time() * 1000)
            snap = self.snapshot()
        for cb in list(self._subscribers):
            try:
                cb(snap)
            except Exception:
                # 订阅者异常不得中断状态机主流程。
                pass
        return snap

    def get_state(self):
        with self._lock:
            return self._state

    def snapshot(self):
        """返回当前状态的不可变副本（dict），可直接 JSON 序列化推前端。"""
        with self._lock:
            return {
                "state": self._state,
                "note": self._note,
                "ts": self._ts,
                "meta": dict(self._meta),
            }

    def subscribe(self, cb):
        """注册状态变更回调（fn(snapshot)）。返回取消函数。"""
        with self._lock:
            self._subscribers.append(cb)

        def _unsubscribe():
            with self._lock:
                if cb in self._subscribers:
                    self._subscribers.remove(cb)
        return _unsubscribe

    def reset(self):
        self.set_state(STATE_IDLE, note=None)


def push_agent_status(state, note=None, window=None, **meta):
    """把一次 Agent 状态变更推送至前端（无窗口时静默 no-op）。

    与 run_scans.push_scan_event 同构：通过 window.evaluate_js 调用
    window.__autopentestOnAgentStatus(payload)。窗口异常（未就绪 / 已销毁 /
    线程调度异常）静默忽略，绝不中断扫描 worker。

    meta 会自动补齐当前 scan 上下文（scan_id / target_id），便于前端按扫描聚合。
    """
    win = window if window is not None else _PUSH_WINDOW
    if win is None:
        return
    # 自动合并当前扫描上下文（若有），避免每个调用点手动传 scan_id。
    ctx = get_scan_context()
    if ctx:
        sid, tid = ctx
        meta.setdefault("scan_id", sid)
        meta.setdefault("target_id", tid)
    payload = json.dumps({
        "type": "agent_status",
        "state": state,
        "note": note,
        "meta": meta,
        "ts": int(time.time() * 1000),
    }, ensure_ascii=False)
    js = ("window.__autopentestOnAgentStatus && "
          "window.__autopentestOnAgentStatus(" + payload + ");")
    try:
        win.evaluate_js(js)
    except Exception:
        pass


# 进程级默认状态栏单例（供 run_scans / 插件在落地时直接 import 使用）。
default_bar = AgentStatusBar()
