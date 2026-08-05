# -*- coding: utf-8 -*-
"""PenScope —— 证据记忆落盘（P4 固化胜者 B 的证据记忆）。

持久化观测证据（端点噪声判定 / 历史裁决），支撑**跨扫描去噪**：
- 同一目标二次扫描时，历史被判软 404 / 拒绝页 / 错误页的端点直接跳过高级注入模块，
  不再重复探测，缩短时延且不引入漏报（噪声页本无注入面）。
- 与 fp_guard.baseline_probe（短 TTL 内存缓存）互补：本层为跨扫描持久（db），TTL 默认 7 天。

全部读写经模块级 RLock 串行化（与 db._db_lock 同策略），连接独立、WAL + busy_timeout。
只读 GET 良性，不写不爆破。
"""
import datetime
import logging
import sqlite3
import threading

from config import DB_PATH

_log = logging.getLogger("PenScope.evidence_store")
_lock = threading.RLock()

SIG_SOFT404 = "soft404"
SIG_DENIED = "denied"
SIG_ERROR = "error"
SIG_VERDICT = "verdict"
_NOISE_SIGNALS = (SIG_SOFT404, SIG_DENIED, SIG_ERROR)
_DEFAULT_TTL_DAYS = 7


def _now_iso():
    return datetime.datetime.utcnow().isoformat()


def _conn():
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA busy_timeout=5000")
    return con


def record(target_id, url, signal_type, signal_value, verdict, ttl_days=_DEFAULT_TTL_DAYS):
    """落盘一条证据。signal_value 为关键值（如基线指纹），verdict 为结论。"""
    try:
        expired = (datetime.datetime.utcnow() + datetime.timedelta(days=ttl_days)).isoformat()
        with _lock:
            con = _conn()
            try:
                con.execute(
                    "INSERT OR REPLACE INTO evidence_store "
                    "(target_id, url, signal_type, signal_value, verdict, created_at, ttl) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (target_id, url, signal_type, signal_value, verdict, _now_iso(), expired))
                con.commit()
            finally:
                con.close()
    except Exception as e:
        _log.debug("evidence record failed: %s", e)


def lookup(target_id, url, signal_type):
    """返回 (signal_value, verdict) 或 None（过期/不存在）。"""
    try:
        with _lock:
            con = _conn()
            try:
                row = con.execute(
                    "SELECT signal_value, verdict FROM evidence_store "
                    "WHERE target_id=? AND url=? AND signal_type=? AND ttl>?",
                    (target_id, url, signal_type, _now_iso())).fetchone()
                return row
            finally:
                con.close()
    except Exception:
        return None


def is_known_noise(target_id, url):
    """该 url 历史被判为软 404 / 拒绝页 / 错误页（未过期）→ 跨扫描去噪可跳过。"""
    for sig in _NOISE_SIGNALS:
        if lookup(target_id, url, sig):
            return True
    return False


def prune_expired():
    """清理过期证据。"""
    try:
        with _lock:
            con = _conn()
            try:
                con.execute("DELETE FROM evidence_store WHERE ttl<?", (_now_iso(),))
                con.commit()
            finally:
                con.close()
    except Exception as e:
        _log.debug("evidence prune failed: %s", e)
