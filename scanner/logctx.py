"""F-09：结构化日志上下文载体。

通过 contextvars 在扫描执行期间携带 scan_id / target_id，
使任意模块（端口扫描、web 扫描、插件等）的日志在经 CtxFormatter 渲染时
自动附带 [scan=.. target=..]，无需每个模块手动绑定 LoggerAdapter。

仅依赖标准库，可被 main_gui / run_scans / 测试无循环依赖地导入。
"""
import contextvars
import logging

# (scan_id, target_id) 或 None
_SCAN_CTX = contextvars.ContextVar("penscope_scan_ctx", default=None)


def set_scan_context(scan_id, target_id=None):
    """在当前执行上下文（线程）绑定一次扫描的身份，供日志格式化器读取。"""
    _SCAN_CTX.set((scan_id, target_id))


def clear_scan_context():
    """清除当前上下文的扫描身份（扫描阶段结束/异常时调用）。"""
    _SCAN_CTX.set(None)


def get_scan_context():
    """返回当前上下文的 (scan_id, target_id)，未绑定时为 None。"""
    return _SCAN_CTX.get()


class CtxFormatter(logging.Formatter):
    """结构化日志格式化器：当日志记录携带 scan_id / target_id / worker 上下文时，
    在行尾追加 [scan=.. target=.. worker=..]，便于问题追踪与日志聚合。
    上下文来源优先级：日志记录显式属性 > 当前扫描 contextvar > 无（保持原样）。
    """

    def format(self, record):
        s = super().format(record)
        scan = getattr(record, "scan_id", None)
        tid = getattr(record, "target_id", None) or getattr(record, "target", None)
        # 记录未显式携带上下文时，回退到当前扫描 contextvar
        if scan is None and tid is None:
            ctx = get_scan_context()
            if ctx:
                scan, tid = ctx
        worker = getattr(record, "worker", None)
        parts = []
        if scan and scan != "-":
            parts.append("scan=%s" % scan)
        if tid and tid != "-":
            parts.append("target=%s" % tid)
        if worker and worker != "-":
            parts.append("worker=%s" % worker)
        if parts:
            s += "  [" + " ".join(parts) + "]"
        return s
