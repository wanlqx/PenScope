"""PenScope —— 桌面原生窗口入口（无后端模式）

直接创建 pywebview 原生窗口，加载本地静态前端（frontend/index.html），
并通过 js_api 把本地 Python 扫描引擎暴露给前端（window.pywebview.api）。
不再启动任何 HTTP 服务、不再有登录/会话/账号体系——纯本地桌面工具。
增加系统托盘菜单（显示/隐藏、设置、打开数据目录、退出）；关闭窗口时最小化到托盘。
控制台输出重定向到文件日志，便于 --windowed（无终端）打包后排错。
"""
import ctypes
import logging
import logging.handlers
import os
import sys
import threading
import time

import app_api
import config
import db
import run_scans

# ---------------- 文件日志（替代控制台，避免 --windowed 下无输出） ----------------
# 使用 RotatingFileHandler：单文件上限 10MB，保留最近 5 个备份，防止日志无限增长占满磁盘。
_LOG_PATH = os.path.join(config.BASE_DIR, "autopentest.log")
_handlers = [logging.handlers.RotatingFileHandler(
    _LOG_PATH, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")]
if sys.stdout is not None:
    _handlers.append(logging.StreamHandler())
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=_handlers,
)


# 结构化日志格式化器（含扫描上下文注入）统一收容到 scanner.logctx，便于测试与复用。
from scanner.logctx import CtxFormatter as _CtxFormatter

# F-10 桌面端 Agent 状态栏：窗口创建后注册推送目标（与 set_push_window 同构）。
from scanner.agent_status import set_agent_status_window

for _h in logging.getLogger().handlers:
    _h.setFormatter(_CtxFormatter("%(asctime)s [%(levelname)s] %(message)s"))

log = logging.getLogger("PenScope")
logging.getLogger("werkzeug").setLevel(logging.ERROR)

# ---------------- 托盘 / 窗口依赖（可选） ----------------
try:
    import pystray
    import webview
    from PIL import Image
    from pystray import Menu, MenuItem
    HAS_TRAY = True
    HAS_WEBVIEW = True
except Exception as e:  # 无 WebView2/pystray 时无法运行（无后端可回退）
    webview = None
    HAS_TRAY = False
    HAS_WEBVIEW = False
    log.warning("窗口依赖不可用：%s", e)

window = None
tray_icon = None
_closing = False
_WINDOW_TITLE = config.APP_NAME + " · 自动化渗透测试"  # 与 create_window 标题一致，供 FindWindowW 定位

import notify as _notify  # F-05：扫描线程经此推送桌面气泡（进程内单例引用）


def _asset(path):
    return os.path.join(config.BUNDLE_DIR, path)


def _frontend_path():
    return os.path.join(config.BUNDLE_DIR, "frontend", "index.html")


def _open_data_folder():
    """用系统文件管理器打开数据目录（autopentest.db 所在处）。"""
    d = config.BASE_DIR
    try:
        if sys.platform.startswith("win"):
            os.startfile(os.path.normpath(d))
        else:
            import webbrowser
            webbrowser.open(f"file://{d}")
    except Exception as e:
        log.warning("打开数据目录失败：%s", e)


def _get_hwnd():
    """获取 pywebview 原生窗口 HWND（Windows）。用于直接 ShowWindow，避免 hide/show 造成任务栏图标重复堆叠。"""
    try:
        w = window
        if w is None:
            return None
        hw = getattr(w, "_native_window", None)
        if hw:
            return hw
        if webview.windows:
            return getattr(webview.windows[0], "_native_window", None)
    except Exception:
        return None
    return None


def _activate_existing_instance():
    """已有实例运行时，可靠地把其窗口带到前台（规避 Windows 前台锁）。

    用于多实例保护：新实例检测到互斥锁已存在时，激活已有窗口而非重复启动。
    单纯 ShowWindow + SetForegroundWindow 在跨进程时常被系统前台锁拦截，导致"重复点击
    启动器却看不见窗口"，必须借助 AllowSetForegroundWindow / AttachThreadInput 桥接。
    """
    try:
        hwnd = ctypes.windll.user32.FindWindowW(None, _WINDOW_TITLE)
        if not hwnd:
            return False
        ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        # 本进程申请置前权限后尝试；失败则桥接当前前台线程，强制置前
        try:
            ctypes.windll.user32.AllowSetForegroundWindow(
                ctypes.windll.kernel32.GetCurrentProcessId())
        except Exception:
            pass
        if not ctypes.windll.user32.SetForegroundWindow(hwnd):
            try:
                fg = ctypes.windll.user32.GetForegroundWindow()
                if fg:
                    fg_tid = ctypes.windll.user32.GetWindowThreadProcessId(fg, None)
                    cur_tid = ctypes.windll.kernel32.GetCurrentThreadId()
                    attached = ctypes.windll.user32.AttachThreadInput(cur_tid, fg_tid, True)
                    ctypes.windll.user32.SetForegroundWindow(hwnd)
                    if attached:
                        ctypes.windll.user32.AttachThreadInput(cur_tid, fg_tid, False)
            except Exception:
                pass
        return True
    except Exception:
        return False


def exit_app():
    """干净退出：停止托盘、销毁窗口、强制终止进程。

    供托盘「退出」与应用内「退出」按钮共用。幂等：多次调用安全。
    """
    global _closing, tray_icon, window
    if _closing:
        return
    _closing = True
    log.info("应用请求退出")
    try:
        if tray_icon is not None:
            tray_icon.stop()
    except Exception:
        pass
    try:
        if window is not None:
            window.destroy()
    except Exception:
        pass
    os._exit(0)


def on_tray_show():
    hw = _get_hwnd()
    if hw:
        try:
            ctypes.windll.user32.ShowWindow(hw, 9)   # SW_RESTORE
            try:
                ctypes.windll.user32.AllowSetForegroundWindow(
                    ctypes.windll.kernel32.GetCurrentProcessId())
            except Exception:
                pass
            ctypes.windll.user32.SetForegroundWindow(hw)
        except Exception:
            pass
    elif window:
        window.show()


def on_tray_settings():
    if window:
        try:
            window.evaluate_js("location.hash='#settings';")
        except Exception:
            pass


def on_tray_exit():
    exit_app()


def _on_gate(kind, note, scan_id=None, target_id=None):
    """U-02：闸门触发时推送系统托盘气泡 + 任务栏闪烁。"""
    title = "PenScope · 复核闸门"
    msg = f"[{kind}] {note}"
    try:
        if tray_icon is not None:
            tray_icon.notify(msg, title)
    except Exception as e:
        log.warning("托盘通知失败：%s", e)
    try:
        if window is not None and hasattr(window, "flash"):
            window.flash()
    except Exception:
        pass


def _build_tray():
    global tray_icon
    icon_path = _asset(os.path.join("assets", "tray.png"))
    try:
        image = Image.open(icon_path)
    except Exception:
        image = Image.new("RGBA", (64, 64), (15, 20, 25, 255))
    menu = Menu(
        MenuItem("显示主窗口", lambda _: on_tray_show()),
        MenuItem("关于", lambda _: on_tray_settings()),
        MenuItem("打开数据目录", lambda _: _open_data_folder()),
        Menu.SEPARATOR,
        MenuItem("退出", lambda _: on_tray_exit()),
    )
    tray_icon = pystray.Icon(config.APP_NAME.lower(), image, config.APP_NAME + " · 自动化渗透测试", menu)
    _notify.register_tray(tray_icon)  # F-05：注入托盘引用，供后端扫描线程推送变更通知
    tray_icon.run()


def main():
    # ---------------- 自检测试模式（bug-hunter skill 驱动，仅本地、无副作用） ----------------
    SELFTEST = "--selftest" in sys.argv
    SELFTEST_PLAN = None
    for _a in sys.argv:
        if _a.startswith("--selftest-plan="):
            SELFTEST_PLAN = _a.split("=", 1)[1]

    if not HAS_WEBVIEW:
        log.error("缺少 pywebview / WebView2 运行时，无法启动界面。请安装 Microsoft Edge WebView2。")
        print("[错误] 缺少 WebView2 运行时，无法启动界面。")
        return

    # ---- 多实例保护：Windows 命名互斥锁（自检测试模式跳过，避免被已有实例挡住） ----
    if not SELFTEST:
        _MUTEX_NAME = config.APP_NAME + "_SingleInstance_Mutex"
        _mutex = ctypes.windll.kernel32.CreateMutexW(None, False, _MUTEX_NAME)
        if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            log.warning("检测到已有实例运行，通过已存在实例激活窗口")
            # 尝试激活已有窗口（通过窗口标题定位），用 SW_RESTORE 避免重复创建
            try:
                _activate_existing_instance()
            except Exception:
                pass
            return

    db.init_db()
    # 后台 Worker：扫描编排 + 定时/批量调度
    run_scans.set_gate_listener(_on_gate)  # U-02：闸门托盘通知
    threading.Thread(target=run_scans.worker_loop, daemon=True).start()
    threading.Thread(target=run_scans.scheduler_thread, daemon=True).start()

    # 启动系统托盘（独立线程）
    def _safe_tray():
        try:
            _build_tray()
        except Exception as e:
            log.warning("系统托盘启动失败（不影响主窗口）：%s", e)

    threading.Thread(target=_safe_tray, daemon=True).start()

    def on_closing():
        global _closing
        if _closing:
            return True
        # 读取关闭行为设置：minimize（最小化到托盘）或 exit（完全退出）
        close_behavior = db.get_setting("close_behavior", "minimize")
        if close_behavior == "exit":
            log.info("关闭行为设为「退出」，直接关闭窗口并退出")
            exit_app()
            return True
        # 默认：最小化到托盘。用真实 HWND 隐藏（SW_HIDE），避免 pywebview hide/show
        # 重建窗口导致 Windows 任务栏图标无限叠加。
        hw = _get_hwnd()
        if hw:
            try:
                ctypes.windll.user32.ShowWindow(hw, 0)  # SW_HIDE
            except Exception:
                pass
        elif window:
            window.hide()
        return False

    global window
    window = webview.create_window(
        _WINDOW_TITLE,
        url=_frontend_path(),
        js_api=app_api.Api(),
        width=1320,
        height=840,
        min_size=(1024, 680),
        background_color="#0f1419",
        text_select=False,
        confirm_close=False,
    )
    run_scans.set_push_window(window)  # P-06：注册窗口，阶段事件即可主动推送前端
    set_agent_status_window(window)    # F-10：注册窗口，Agent 状态栏推送目标
    window.events.closing += on_closing

    # ---- 自检测试驱动线程：等待前端桥就绪 → 触发 runSelfTest → 等待报告 → 退出 ----
    if SELFTEST:
        def _selftest_driver():
            import json as _json
            plan = None
            if SELFTEST_PLAN and os.path.exists(SELFTEST_PLAN):
                try:
                    plan = _json.load(open(SELFTEST_PLAN, encoding="utf-8"))
                except Exception:
                    plan = None
            out = os.path.join(os.getcwd(), "selftest_report.json")
            if os.path.exists(out):
                try:
                    os.remove(out)
                except Exception:
                    pass
            dl = time.time() + 60
            while time.time() < dl:
                try:
                    ready = window.evaluate_js("typeof window.__app !== 'undefined' && typeof window.__app.runSelfTest === 'function'")
                except Exception:
                    ready = False
                if ready:
                    try:
                        window.evaluate_js("window.__app.runSelfTest(" + (_json.dumps(plan) if plan else "null") + ")")
                    except Exception as e:
                        log.warning("selftest 触发失败：%s", e)
                    break
                time.sleep(0.5)
            rdl = time.time() + 120
            while time.time() < rdl:
                if os.path.exists(out):
                    try:
                        d = _json.load(open(out, encoding="utf-8"))
                        s = d.get("summary", {})
                        log.info("[selftest] 报告就绪：总错误 %s，前端 %s，后端 %s",
                                 s.get("totalErrors"), s.get("jsErrors", s.get("consoleErrors")), s.get("backendErrors"))
                    except Exception:
                        pass
                    break
                time.sleep(1)
            try:
                window.destroy()
            except Exception:
                pass

        threading.Thread(target=_selftest_driver, daemon=True).start()

    webview.start()
    if SELFTEST:
        # 自检测试完成后由驱动线程 destroy 窗口，webview.start 返回即退出
        return
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        on_tray_exit()


if __name__ == "__main__":
    main()
