"""桌面通知（F-05 资产变更告警）：封装系统托盘气泡，GUI 不可用时安全降级。

设计：本模块不直接依赖 pystray，避免后端线程 / 构建期循环导入。GUI 进程
（main_gui.py）在创建托盘图标后调用 register_tray(icon) 注入引用；扫描线程
通过 notify(title, msg) 推送气泡。无托盘（CLI/构建期）时自动 no-op 返回 False。
"""

_tray = None


def register_tray(icon):
    """由 main_gui 注入托盘图标引用（进程内单例）。"""
    global _tray
    _tray = icon


def notify(title, msg):
    """推送桌面气泡。成功返回 True；无托盘或异常返回 False（不抛错，降级静默）。"""
    if _tray is None:
        return False
    try:
        _tray.notify(msg, title)
        return True
    except Exception:
        return False
