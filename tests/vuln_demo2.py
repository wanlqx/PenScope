"""PenScope —— 命令注入 + API 安全 模拟靶场（仅用于本地验证，非真实漏洞）

用一个标准库 http.server 模拟存在以下问题的端点，用于端到端验证
scanner.cmd_injection / scanner.api_scan 的检测与阶段机集成：
 - /ping?host= ：模拟命令注入（输出回显标记 / 时间延迟）
 - /api/users   ：JSON 暴露明文密码/token（敏感数据）+ CORS 任意源带凭据
 - /api/orders  ：正常 JSON（用于对照）
 - /api/debug   ：返回堆栈式错误（verbose error）
 - /graphql     ：GraphQL 文档页
首页链接上述端点，供 collect_pages 爬取发现。
"""
import re
import threading
import time
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

_MARKER_EXEC_RE = re.compile(r"APCMD_\$\(\((\d+)\+(\d+)\)\)")
_CMD_DELAY_RE = re.compile(r"sleep")


def _page(title, body_html):
    return ("<html><head><title>%s</title></head><body>"
            "<h1>%s</h1>%s"
            '<p><a href="/ping">/ping</a> | <a href="/api/users">/api/users</a> | '
            '<a href="/api/orders">/api/orders</a> | <a href="/api/debug">/api/debug</a> | '
            '<a href="/graphql">/graphql</a></p>'
            "</body></html>" % (title, title, body_html))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # 静默

    def _send(self, code, body, headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        # 仅当调用方未指定 Content-Type 时才用默认 text/html，避免重复头
        if not headers or "Content-Type" not in headers:
            self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self._send(200, _page("Demo Home", "<p>本地模拟靶场首页</p>"))
            return
        if parsed.path == "/ping":
            qs = parse_qs(parsed.query)
            host = qs.get("host", ["localhost"])[0]
            # 模拟命令注入：用户输入被拼进命令并"真正执行"，输出计算结果（差分执行态）
            if _CMD_DELAY_RE.search(host):
                time.sleep(3)  # 时间盲注证明
                out = "pong (delayed)"
            elif _MARKER_EXEC_RE.search(host):
                a, b = _MARKER_EXEC_RE.search(host).groups()
                out = "result: APCMD_" + str(int(a) + int(b))  # 命令执行：输出计算结果
            else:
                out = "pong " + host
            html = (_page("Ping", f"<pre>{escape(out)}</pre>")  # 转义输出：避免误触发 XSS 检测
                    + f'<form method="get" action="/ping">'
                      # 命令注入靶机回显的是"命令输出"(out)而非原始输入(host)，
                      # 避免字面载荷被回显而干扰差分标记的反射判定
                      f'<input name="host" value="{escape(out)}">'
                      f'<input type="submit" name="submit" value="ping"></form>')
            self._send(200, html)
            return
        if parsed.path == "/api/users":
            body = ('{"users":[{"id":1,"username":"admin","password":"Admin@123",'
                    '"token":"eyJhbGciOiJIUzI1Ni.example.sig","api_key":"sk-abc123DEF456ghi789JKL"},'
                    '{"id":2,"username":"alice","phone":"13800000000"}]}')
            self._send(200, body, {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            })
            return
        if parsed.path == "/api/orders":
            body = '{"orders":[{"id":101,"amount":99.0},{"id":102,"amount":12.5}]}'
            self._send(200, body, {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            })
            return
        if parsed.path == "/api/debug":
            body = ("HTTP Status 500 - Internal Server Error<br>"
                    "java.lang.NullPointerException<br>"
                    "  at com.demo.api.UserController.list(UserController.java:42)<br>"
                    "  at com.demo.api.UserController$FastClass.invoke(Unknown Source)")
            self._send(500, body)
            return
        if parsed.path == "/graphql":
            self._send(200, _page("GraphiQL", "<div>GraphQL IDE</div>"))
            return
        self._send(404, _page("Not Found", "<p>404</p>"))

    def do_OPTIONS(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self.send_response(204)
            self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send(404, "n/a")


def start(port=18099):
    srv = HTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


if __name__ == "__main__":
    p = 18099
    start(p)
    print(f"demo running on http://127.0.0.1:{p}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
