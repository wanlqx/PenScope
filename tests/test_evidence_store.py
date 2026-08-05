# -*- coding: utf-8 -*-
"""P4 证据记忆落盘（scanner.evidence_store）单元测试。"""
import datetime
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import evidence_store as es

_SCHEMA = """CREATE TABLE evidence_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    signal_type TEXT NOT NULL,
    signal_value TEXT,
    verdict TEXT,
    created_at TEXT NOT NULL,
    ttl TEXT
)"""


@pytest.fixture
def store(monkeypatch):
    fd, path = __import__("tempfile").mkstemp(suffix=".db")
    os.close(fd)
    monkeypatch.setattr(es, "DB_PATH", path)
    con = sqlite3.connect(path)
    con.execute(_SCHEMA)
    con.commit()
    con.close()
    yield
    os.remove(path)


def _insert_expired(target_id, url, signal_type):
    expired = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat()
    con = sqlite3.connect(es.DB_PATH)
    con.execute(
        "INSERT INTO evidence_store (target_id,url,signal_type,signal_value,verdict,created_at,ttl) "
        "VALUES (?,?,?,?,?,?,?)",
        (target_id, url, signal_type, "v", "noise", "2020-01-01T00:00:00", expired))
    con.commit()
    con.close()


def test_record_and_lookup(store):
    es.record(1, "http://a/", es.SIG_DENIED, "v", "noise")
    row = es.lookup(1, "http://a/", es.SIG_DENIED)
    assert row is not None and row[1] == "noise"


def test_is_known_noise_true(store):
    es.record(1, "http://a/", es.SIG_SOFT404, "x", "soft404")
    assert es.is_known_noise(1, "http://a/") is True


def test_is_known_noise_false(store):
    assert es.is_known_noise(1, "http://b/") is False


def test_lookup_expired_returns_none(store):
    _insert_expired(1, "http://a/", es.SIG_DENIED)
    assert es.lookup(1, "http://a/", es.SIG_DENIED) is None


def test_prune_expired(store):
    _insert_expired(1, "http://a/", es.SIG_DENIED)
    es.prune_expired()
    assert es.lookup(1, "http://a/", es.SIG_DENIED) is None


def test_record_then_known_noise_multi_signal(store):
    es.record(2, "http://z/", es.SIG_ERROR, "err", "error-page")
    assert es.is_known_noise(2, "http://z/") is True
