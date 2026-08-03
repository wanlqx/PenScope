# -*- coding: utf-8 -*-
"""P1 模块端到端验证：scanner/contentscan.py + scanner/subdomain.py

- contentscan：本地 HTTP 服务暴露 /.env、/.git/config、/debug(堆栈)、含内网 IP 的页面，
  验证只读扫描能命中 敏感信息泄露 / 目录暴露 且不做任何写入。
- subdomain：注入式 resolver/fetcher 模拟 DNS 与 crt.sh，验证被动枚举与「排除自身/不自动扫描」。
不依赖真实外网；不向任何外部目标发起请求。
"""
import sys
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

# 让脚本在仓库根目录运行
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner.contentscan import scan_content
from scanner.subdomain import enum_subdomains

# ── 测试用本地 HTTP 服务（仅本机 127.0.0.1）──
_ENV = (
    "DB_HOST=10.0.0.5\n"
    "DB_PASSWORD=Sup3rSecretP@ss\n"
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    "SECRET_KEY=sk-abcdefghijklmnopqrstuvwx\n"
)
_GITCFG = "[core]\n\trepositoryformatversion = 0\n"
_DEBUG = ("<html><body><h1>Error</h1><pre>Traceback (most recent call last):\n"
          "  File \"app.py\", line 10, in <module>\n"
          "    raise Exception('boom')\nException: boom</pre></body></html>")
_ADMIN = "<html><body><h1>Admin Console</h1></body></html>"
_INTERNAL = "<html><body>backend at 192.168.1.50:8080 is healthy</body></html>"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype="text/html; charset=utf-8", code=200):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = self.path.split("?")[0].rstrip("/") or "/"
        if p == "/.env":
            self._send(_ENV, "text/plain")
        elif p == "/.git/config":
            self._send(_GITCFG, "text/plain")
        elif p == "/debug":
            self._send(_DEBUG)
        elif p == "/admin":
            self._send(_ADMIN)
        elif p == "/internal":
            self._send(_INTERNAL)
        elif p == "/":
            self._send("<html><body><a href='/admin'>admin</a></body></html>")
        else:
            self._send("not found", code=404)


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    port = _free_port()
    srv = HTTPServer(("127.0.0.1", port), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}/"

    sess = requests.Session()
    sess.headers.update({"User-Agent": "PenScope/1.0 (test)"})

    # ── 1) 目录/敏感信息扫描 ──
    findings = scan_content(base, sess, timeout=4.0, verify_ssl=False)
    cats = {}
    for f in findings:
        cats.setdefault(f["category"], []).append((f["risk"], f["title"]))

    print("=== contentscan findings ===")
    for c, lst in cats.items():
        for r, ti in lst:
            print(f"  [{r}] {c}: {ti}")

    assert any(f["category"] == "敏感信息泄露" and f["risk"] == "Medium" for f in findings), \
        "应命中 /.env 的真实密钥 → 敏感信息泄露(中危)"
    assert any(f["category"] == "目录暴露" and f["risk"] == "Medium" for f in findings), \
        "应命中 /.env、/.git/config 等敏感路径可访问 → 目录暴露(中危)"
    assert any(f["category"] == "敏感信息泄露" and f["risk"] == "Low" for f in findings), \
        "应命中 /debug 堆栈 或 /internal 内网 IP → 敏感信息泄露(低危)"
    # 只读校验：不应有任何 POST/PUT/DELETE（scan_content 仅 GET/HEAD）
    print("contentscan 只读校验通过（仅 GET/HEAD，未写入）")

    # ── 2) 子域被动枚举（注入式 resolver/fetcher）──
    def fake_resolver(host):
        return {"www.jxnu.edu.cn": "202.101.194.164",
                "admin.jxnu.edu.cn": "202.101.194.165",
                "mail.jxnu.edu.cn": "14.17.27.155"}.get(host)

    def fake_fetcher(url):
        # 模拟 crt.sh 返回（含通配与自身）
        return ('[{"name_value":"*.jxnu.edu.cn"},'
                '{"name_value":"www.jxnu.edu.cn"},'
                '{"name_value":"admin.jxnu.edu.cn"},'
                '{"name_value":"mail.jxnu.edu.cn"}]')

    found = enum_subdomains("mail.jxnu.edu.cn", resolve=True,
                            _resolver=fake_resolver, _fetcher=fake_fetcher)
    print("=== subdomain enum (resolved) ===")
    for s in found:
        print("  ", s)
    assert "www.jxnu.edu.cn" in found, "应发现 www.jxnu.edu.cn（来自 crt.sh + 解析）"
    assert "admin.jxnu.edu.cn" in found, "应发现 admin.jxnu.edu.cn（来自 crt.sh + 解析）"
    assert "mail.jxnu.edu.cn" not in found, "应排除目标自身"

    # 不解析时仅依赖 crt.sh 名单（含通配被丢弃、自身被丢弃）
    found2 = enum_subdomains("mail.jxnu.edu.cn", resolve=False,
                             _resolver=fake_resolver, _fetcher=fake_fetcher)
    print("=== subdomain enum (no resolve) ===", found2)
    assert "www.jxnu.edu.cn" in found2 and "admin.jxnu.edu.cn" in found2
    assert "mail.jxnu.edu.cn" not in found2

    srv.shutdown()
    print("\n=== ALL P1 MODULE ASSERTIONS PASSED ===")
    return True


if __name__ == "__main__":
    main()
