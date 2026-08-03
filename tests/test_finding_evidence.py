"""I-04 证据分级 / I-05 请求响应证据 / I-06 CVSS 计算器 单元测试。

使用临时 SQLite 库；不触达真实目标网络。覆盖：
- scanner.evidence 的抓包与 evidence_meta 组装；
- add_finding 持久化 evidence_meta（含去重合并时的 COALESCE 保留）；
- get_finding 读取与不存在返回 None；
- set_finding_cvss 的向量格式守门（合法写入 / 非法拒绝 / 评分越界拒绝）；
- db._CVSS31_RE 对标准向量的接受与拒绝。
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import db as dbmod
from scanner import evidence as evmod


def _tmp_db():
    tmp = tempfile.mktemp(suffix=".db")
    config.DB_PATH = tmp
    dbmod.DB_PATH = tmp
    dbmod.init_db()
    return tmp


class _FakeResp:
    """最小化的 requests.Response 替身，供 capture_request / capture_response 使用。"""
    def __init__(self, method="GET", url="http://x/vuln?p=1", headers=None, body=None,
                 status=200, resp_headers=None, text="<html>echo 'x'</html>"):
        self.method = method
        self.url = url
        self._req_headers = headers or {"Host": "x", "User-Agent": "PenScope/1.0"}
        self.body = body
        self.status_code = status
        self._resp_headers = resp_headers or {"Content-Type": "text/html"}
        self.text = text

    @property
    def request(self):
        class _Req:
            pass
        r = _Req()
        r.method = self.method
        r.url = self.url
        r.headers = self._req_headers
        r.body = self.body
        return r

    @property
    def headers(self):
        return self._resp_headers


def test_capture_builds_meta():
    resp = _FakeResp(method="POST", url="http://x/login", body="u=admin&p='",
                     text="SQL syntax error near '''")
    meta = json.loads(evmod.build_evidence_meta(payload="'", request=evmod.capture_request(resp),
                                                  response=evmod.capture_response(resp)))
    assert "request" in meta and "response" in meta and meta["payload"] == "'"
    assert "POST http://x/login" in meta["request"]
    assert "SQL syntax error" in meta["response"]
    # 空输入返回 None
    assert evmod.build_evidence_meta() is None


def test_add_finding_persists_evidence_meta():
    tmp = _tmp_db()
    try:
        tid = dbmod.add_target("1.2.3.4", "common", "", "auth", "me")
        dbmod.approve_target(tid, "me")
        sid = dbmod.create_scan(tid, "t", "me")
        meta = json.dumps({"request": "GET /a", "payload": "'"})
        fid = dbmod.add_finding(sid, "SQL注入", "错误型注入", "High", "detail", "ev",
                                 "rem", "http://1.2.3.4/a", cwe="CWE-89",
                                 endpoint="http://1.2.3.4/a", http_method="GET",
                                 evidence_meta=meta)
        f = dbmod.get_finding(fid)
        assert f is not None
        assert f["evidence_meta"] == meta
    finally:
        os.remove(tmp)


def test_evidence_meta_survives_dedup_merge():
    tmp = _tmp_db()
    try:
        tid = dbmod.add_target("1.2.3.4", "common", "", "auth", "me")
        dbmod.approve_target(tid, "me")
        sid = dbmod.create_scan(tid, "t", "me")
        meta = json.dumps({"request": "GET /a", "payload": "'"})
        dbmod.add_finding(sid, "SQL注入", "错误型注入", "High", "detail A", "ev", "rem",
                          "http://1.2.3.4/a", cwe="CWE-89", endpoint="http://1.2.3.4/a",
                          evidence_meta=meta)
        # 相似发现（同类型同端点，证据不同）应被去重合并；合并时 COALESCE 保留已有 evidence_meta
        dbmod.add_finding(sid, "SQL注入", "错误型注入", "High", "detail B", "ev2", "rem",
                          "http://1.2.3.4/a", cwe="CWE-89", endpoint="http://1.2.3.4/a",
                          evidence_meta=None)
        rows = dbmod.findings_of(sid)
        assert len(rows) == 1, "相似发现应被合并为 1 条"
        assert rows[0]["evidence_meta"] == meta, "合并后 evidence_meta 不应被清空"
    finally:
        os.remove(tmp)


def test_get_finding_not_found():
    tmp = _tmp_db()
    try:
        assert dbmod.get_finding(999999) is None
    finally:
        os.remove(tmp)


def test_set_finding_cvss_valid_and_invalid():
    tmp = _tmp_db()
    try:
        tid = dbmod.add_target("1.2.3.4", "common", "", "auth", "me")
        dbmod.approve_target(tid, "me")
        sid = dbmod.create_scan(tid, "t", "me")
        fid = dbmod.add_finding(sid, "SQL注入", "x", "High", "d", "e", "r", "ref")
        good_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert dbmod.set_finding_cvss(fid, 9.8, good_vec) is True
        f = dbmod.get_finding(fid)
        assert abs(f["cvss_score"] - 9.8) < 1e-6
        assert f["cvss_vector"] == good_vec
        # 非法向量（缺度量）应被拒绝，且不改变原值
        assert dbmod.set_finding_cvss(fid, 5.0, "CVSS:3.1/AV:N") is False
        # 评分越界应被拒绝
        assert dbmod.set_finding_cvss(fid, 11.0, good_vec) is False
        # 不存在的发现应被拒绝
        assert dbmod.set_finding_cvss(999999, 5.0, good_vec) is False
    finally:
        os.remove(tmp)


def test_cvss31_regex_accepts_and_rejects():
    good = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert dbmod._CVSS31_RE.match(good)
    assert not dbmod._CVSS31_RE.match("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert not dbmod._CVSS31_RE.match("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert not dbmod._CVSS31_RE.match("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
