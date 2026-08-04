# -*- coding: utf-8 -*-
"""极简 HTTP 客户端: 带 cookie jar, 支持 GET/POST/表单, 供各 team 复用。"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request


class LabClient:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.cookies: dict = {}

    def _hdr(self):
        h = {"User-Agent": "PenScopeEvo/1.0"}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        return h

    def _store_cookies(self, resp_headers):
        sc = resp_headers.get("Set-Cookie")
        if sc:
            for part in sc.split(","):
                part = part.split(";")[0]
                if "=" in part:
                    k, v = part.split("=", 1)
                    self.cookies[k.strip()] = v.strip()

    def get(self, path: str, params: dict | None = None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers=self._hdr())
        try:
            r = urllib.request.urlopen(req, timeout=8)
            body = r.read(16384).decode("utf-8", "ignore")
            self._store_cookies(r.headers)
            return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            body = e.read(16384).decode("utf-8", "ignore")
            self._store_cookies(e.headers)
            return e.code, body, dict(e.headers)
        except Exception as e:  # noqa
            return 0, f"ERROR:{e}", {}

    def post_json(self, path: str, payload: dict):
        url = self.base + path
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={
            **self._hdr(), "Content-Type": "application/json"})
        try:
            r = urllib.request.urlopen(req, timeout=8)
            body = r.read(16384).decode("utf-8", "ignore")
            self._store_cookies(r.headers)
            return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            body = e.read(16384).decode("utf-8", "ignore")
            self._store_cookies(e.headers)
            return e.code, body, dict(e.headers)
        except Exception as e:  # noqa
            return 0, f"ERROR:{e}", {}
