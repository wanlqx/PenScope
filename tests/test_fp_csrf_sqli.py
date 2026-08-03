"""PenScope —— CSRF / SQLi 误报治理 回归测试（改进方案 §2）

验证：
  CSRF：
    * 含 token 字段的表单 -> 0 发现
    * 页面暗示自定义 Header 防护 -> 仅 Info，不报 Medium（误报消除）
    * 提交不含 token 的良性 POST 被服务端拒绝 -> 仅 Info，不报 Medium（误报消除）
    * 真无防护且服务端接受 -> 报 Medium（真阳性保留）
  SQLi 布尔盲注：
    * 响应含动态内容（长度随请求抖动）-> 不判定（误报消除）
    * 恒真/恒假响应长度稳定差异 -> 报 Medium（真阳性保留）
"""
import threading
import random
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import requests
from scanner.web_scan import scan_csrf, scan_sqli
from scanner.payloads import PayloadGenerator

_PG = PayloadGenerator()


def _form(action, method, fields):
    ins = "".join(f'<input name="{n}">' for n in fields)
    return (f'<form action="{action}" method="{method}">'
            f'{ins}<input type="submit" name="submit" value="go"></form>')


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
        if p.path == "/csrf-token":
            # 含 csrf_token 字段 => 视为已防护
            self._send(200, _form("", "post", ["csrf_token", "name"]))
        elif p.path == "/csrf-header":
            # 无 token 字段，但页面 JS 暗示 X-Requested-With 防护
            self._send(200,
                       '<script>xhr.setRequestHeader("X-Requested-With","xmlhttprequest");</script>'
                       + _form("", "post", ["name", "email"]))
        elif p.path == "/csrf-reject":
            # 无 token 字段，服务端对 POST 一律拒绝（403）
            self._send(200, _form("", "post", ["name", "email"]))
        elif p.path == "/csrf-vuln":
            # 无 token 字段，服务端接受 POST => 真实风险
            self._send(200, _form("", "post", ["name", "email"]))
        elif p.path == "/sqli-real":
            # 稳定布尔盲注：含 1=1 长响应，含 1=2 短响应，其余正常长度
            q = parse_qs(p.query).get("q", [""])[0]
            if "1=1" in q:
                body = _form("", "get", ["q"]) + "A" * 500
            elif "1=2" in q:
                body = _form("", "get", ["q"]) + "A" * 100
            else:
                body = _form("", "get", ["q"]) + "A" * 300
            self._send(200, body)
        elif p.path == "/sqli-fp":
            # 动态内容：响应长度随请求抖动，且每轮内 TRUE/FALSE 长度无法保持一致（误报源）
            self.server.fp = getattr(self.server, "fp", 0) + 1
            pair = self.server.fp // 2
            length = 500 if pair % 2 == 0 else 100
            self._send(200, _form("", "get", ["q"]) + "x" * length)
        else:
            self._send(404, "<p>404</p>")

    def do_POST(self):
        p = urlparse(self.path)
        if p.path == "/csrf-reject":
            self._send(403, "<p>forbidden: missing csrf token</p>")
        else:
            self._send(200, "<p>ok</p>")


def _start(port):
    srv = HTTPServer(("127.0.0.1", port), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    port = 18122
    srv = _start(port)
    base = f"http://127.0.0.1:{port}"
    s = requests.Session()

    # ---- CSRF ----
    def _csrf_cat(url):
        fs = scan_csrf(f"{base}{url}", s)
        return [f["risk"] for f in fs], [f["category"] for f in fs]

    risks_token, _ = _csrf_cat("/csrf-token")
    risks_header, _ = _csrf_cat("/csrf-header")
    risks_reject, _ = _csrf_cat("/csrf-reject")
    risks_vuln, _ = _csrf_cat("/csrf-vuln")

    print(f"[csrf-token ] risks={risks_token}")
    print(f"[csrf-header] risks={risks_header}")
    print(f"[csrf-reject] risks={risks_reject}")
    print(f"[csrf-vuln  ] risks={risks_vuln}")

    assert "Medium" not in risks_token, "含 token 表单不应报 Medium"
    assert "Medium" not in risks_header, "自定义Header防护被误报为 Medium（误报未消除）"
    assert "Medium" not in risks_reject, "服务端拒绝被误报为 Medium（误报未消除）"
    assert "Medium" in risks_vuln, "真实无防护表单未报 Medium（真阳性丢失）"
    assert "Info" in risks_header, "自定义Header防护应降级为 Info"
    assert "Info" in risks_reject, "服务端拒绝应降级为 Info"

    # ---- SQLi 布尔盲注 ----
    fp = scan_sqli(f"{base}/sqli-fp", s, _PG)
    real = scan_sqli(f"{base}/sqli-real", s, _PG)
    fp_sql = [f for f in fp if f["category"] == "SQL注入"]
    real_sql = [f for f in real if f["category"] == "SQL注入"]

    print(f"[sqli-fp  ] SQL注入 findings={len(fp_sql)} (应为 0)")
    print(f"[sqli-real] SQL注入 findings={len(real_sql)} (应 >=1)")

    # 动态内容抖动 => 不应判定（误报消除）
    assert len(fp_sql) == 0, "动态内容导致布尔盲注误报（误报未消除）"
    # 稳定差异 => 应判定（真阳性保留）
    assert len(real_sql) >= 1, "稳定布尔盲注未被检出（真阳性丢失）"

    print("\n=== CSRF/SQLi 误报治理回归测试 PASSED ===")
    srv.shutdown()


if __name__ == "__main__":
    main()
