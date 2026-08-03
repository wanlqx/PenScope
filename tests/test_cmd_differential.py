"""PenScope —— 命令注入差分标记 回归测试（防反射型误报）

核心验证：
  * /exec    端点会"真正执行"差分载荷，输出计算结果标记 => 应被判定为命令注入。
  * /reflect 端点仅原样回显用户输入（安全应用常见行为）=> 绝不应被判定为命令注入。
    （这正是 mail.jxnu.edu.cn / Exchange OWA 同款误报的根因，现应归零。）

直接断言 scan_cmd 在两种场景下的产出，避免回归。
"""
import re
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import requests

from scanner.cmd_injection import scan_cmd

_EXEC_RE = re.compile(r"APCMD_\$\(\((\d+)\+(\d+)\)\)")


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/exec":
            host = parse_qs(p.query).get("host", ["x"])[0]
            if _EXEC_RE.search(host):
                a, b = _EXEC_RE.search(host).groups()
                out = "result: APCMD_" + str(int(a) + int(b))  # 真正执行
            else:
                out = "pong " + host
            self._send(200, f"<pre>{escape(out)}</pre>"
                             f'<form method="get" action="/exec">'
                             f'<input name="host" value="{escape(out)}"></form>')
            return
        if p.path == "/reflect":
            host = parse_qs(p.query).get("host", ["x"])[0]
            # 安全应用：仅原样回显用户输入，不执行任何命令
            self._send(200, f"<pre>你输入了: {escape(host)}</pre>"
                             f'<form method="get" action="/reflect">'
                             f'<input name="host" value="{escape(host)}"></form>')
            return
        self._send(404, "<p>404</p>")


def _start(port):
    srv = HTTPServer(("127.0.0.1", port), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    port = 18111
    srv = _start(port)
    base = f"http://127.0.0.1:{port}"
    s = requests.Session()

    exec_findings = scan_cmd(f"{base}/exec", s, None)
    reflect_findings = scan_cmd(f"{base}/reflect", s, None)

    print(f"[exec]    findings={len(exec_findings)} -> {[f['title'] for f in exec_findings]}")
    print(f"[reflect] findings={len(reflect_findings)} -> {[f['title'] for f in reflect_findings]}")

    assert len(exec_findings) >= 1, "真正执行型端点未被检出（差分检测失效）"
    assert len(reflect_findings) == 0, "反射型端点被误判为命令注入（误报未消除）"
    print("\n=== 差分标记防误报回归测试 PASSED ===")
    srv.shutdown()


if __name__ == "__main__":
    main()
