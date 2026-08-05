"""结构化日志（F-09）单元测试：CtxFormatter 通过显式属性或 contextvar 注入
scan/target 上下文，使扫描相关日志自动携带 [scan=.. target=..] 便于聚合追踪。

不触达真实目标网络；纯本地 logging 行为验证。
"""
import io
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.logctx import CtxFormatter, set_scan_context, clear_scan_context


def _make_logger():
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(CtxFormatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger = logging.getLogger("test.logging.ctx.%d" % id(buf))
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    return logger, buf


def test_explicit_attrs_render_context():
    log, buf = _make_logger()
    log.info("probe done", extra={"scan_id": "5", "target_id": "12"})
    out = buf.getvalue()
    assert "[scan=5 target=12]" in out, out


def test_contextvar_injected_when_no_explicit_attr():
    log, buf = _make_logger()
    set_scan_context("7", "21")
    try:
        log.info("scanning ports")
        out = buf.getvalue()
        assert "[scan=7 target=21]" in out, out
    finally:
        clear_scan_context()


def test_no_context_no_brackets():
    log, buf = _make_logger()
    clear_scan_context()
    log.info("plain app log")
    out = buf.getvalue()
    # 格式串本身含 [INFO]（levelname 括号），只需确认无扫描上下文标记即可。
    assert "scan=" not in out and "target=" not in out, out


def test_contextvar_cleared_after_clear():
    log, buf = _make_logger()
    set_scan_context("9", "33")
    clear_scan_context()
    log.info("after clear")
    out = buf.getvalue()
    assert "scan=" not in out, out


def test_worker_field_supported():
    log, buf = _make_logger()
    log.info("work", extra={"scan_id": "1", "target_id": "2", "worker": "A"})
    out = buf.getvalue()
    assert "[scan=1 target=2 worker=A]" in out, out
