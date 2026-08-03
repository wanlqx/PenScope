"""PenScope —— CWE-862 / CWE-287 对 DVWA 的端到端（E2E）验证脚本。

目标：
  A) 受控本地服务（无 CSRF、模拟真实暴露）：
       - /admin 未保护即返回敏感内容  -> 验证 CWE-862 强制浏览正样本判定（Medium/L2）
       - /login 接受 admin/password   -> 验证 CWE-287 默认凭据探针正样本（High/L3）
       - /redirect?to= 反射外部地址    -> 验证 CWE-601 开放重定向正样本（Medium/L2）
       - 登录端点带 CSRF token          -> 验证 CWE-287 探针 CSRF 感知回填（High/L3）
  B) 真实靶机 DVWA（http://127.0.0.1:8090，security=low）：
       - 强制浏览：未登录访问管理页被 302 拦回 -> 模块正确地不报（负样本，无 FP）
       - 认证：被动识别登录端点 + 明文 HTTP（L1）；并 token 感知登录确证 admin/password 有效
  C) 如实记录 DVWA 的 CSRF 校验会拦下通用默认凭据探针这一事实。

运行：需 DVWA 在线（python -S 127.0.0.1:8090 -t D:/phpstudy_pro/WWW/DVWA）。
     本脚本自带受控服务，不依赖 DVWA 即可验证模块逻辑。
"""
import re
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

from scanner.access_control import scan_access_control
from scanner.auth import scan_auth
from scanner.open_redirect import scan_open_redirect

DVWA_BASE = "http://127.0.0.1:8090"
LOCAL_PORT = 8099
LOCAL_BASE = f"http://127.0.0.1:{LOCAL_PORT}"

# ---------------------------------------------------------------------------
# 受控本地服务
# ---------------------------------------------------------------------------
LOGIN_FORM = (
    '<html><body><h1>Controlled Login</h1>'
    '<form action="{base}/login" method="post">'
    '<input name="username" type="text">'
    '<input name="password" type="password">'
    '<input type="submit" name="Login" value="Login">'
    '</form></body></html>'
)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静默
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode("utf-8", "replace"))

    def do_GET(self):
        p = self.path.split("?")[0].rstrip("/")
        if p in ("", "/index.html"):
            self._send(200, LOGIN_FORM.format(base=LOCAL_BASE))
        elif p == "/admin":
            # 未保护的管理/配置页：强制浏览正样本
            self._send(200, "SECRET_CONFIG: DB_PASSWORD=supersecret123 ; API_KEY=abc123")
        elif p == "/dashboard":
            self._send(200, "<h1>Welcome admin</h1><p>Dashboard</p><a href='/logout'>Logout</a>")
        elif p == "/redirect":
            # 开放重定向正样本：把 to 参数原样反射进 302 Location
            qs = urllib.parse.parse_qs(self.path.split("?")[-1])
            to = (qs.get("to") or [""])[0]
            if to:
                self.send_response(302)
                self.send_header("Location", to)
                self.end_headers()
                return
            self._send(200, "<h1>Redirect target missing</h1>")
        else:
            self._send(404, "Not Found")

    def do_POST(self):
        if self.path.split("?")[0].rstrip("/") == "/login":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", "replace")
            data = urllib.parse.parse_qs(raw)
            user = (data.get("username") or [""])[0]
            pwd = (data.get("password") or [""])[0]
            if user == "admin" and pwd == "password":
                # 重定向到 dashboard（含 welcome/dashboard 标记）
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.end_headers()
                return
            # 失败：回到登录页并带失败提示
            self._send(200, LOGIN_FORM.format(base=LOCAL_BASE).replace(
                "</h1>", "</h1><p>invalid username or password</p>"))
            return
        self._send(404, "Not Found")


def _start_local():
    srv = ThreadingHTTPServer(("127.0.0.1", LOCAL_PORT), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# ---------------------------------------------------------------------------
# DVWA token 感知登录（确证 admin/password 有效）
# ---------------------------------------------------------------------------
def dvwa_login(session, user, pwd):
    try:
        r = session.get(DVWA_BASE + "/login.php", timeout=8, verify=False, allow_redirects=True)
        m = re.search(r"name=['\"]user_token['\"] value=['\"]([^'\"]+)", r.text or "")
        token = m.group(1) if m else ""
        r2 = session.post(DVWA_BASE + "/login.php", timeout=8, verify=False, allow_redirects=True,
                          data={"username": user, "password": pwd, "user_token": token, "Login": "Login"})
        text = (r2.text or "").lower()
        ok = ("logout" in text) or ("index.php" in (r2.url or "")) or ("welcome" in text)
        return ok, (r2.url or ""), ("CSRF" if "csrf token" in text else "")
    except requests.RequestException as e:
        return False, "", f"ERR:{e}"


# ---------------------------------------------------------------------------
# 断言助手
# ---------------------------------------------------------------------------
def _find(findings, cwe, risk=None, must_contain=None):
    out = [f for f in findings if f.get("cwe") == cwe]
    if risk:
        out = [f for f in out if f.get("risk") == risk]
    if must_contain:
        out = [f for f in out if must_contain in f.get("title", "")]
    return out


def main():
    srv = _start_local()
    sess = requests.Session()
    sess.headers.update({"User-Agent": "PenScope/1.0 (authorized e2e)"})
    results = []

    print("=" * 70)
    print("A) 受控本地服务：CWE-862 强制浏览正样本 + CWE-287 默认凭据探针正样本")
    print("=" * 70)
    ac_local = scan_access_control(LOCAL_BASE + "/", sess, timeout=5, verify_ssl=False)
    fb = _find(ac_local, "CWE-862", must_contain="强制浏览")
    print(f"  [CWE-862] 强制浏览 findings: {len(fb)}")
    for f in fb:
        print(f"     - {f['risk']}/{f['evidence_level']}: {f['title']}  | {f['target_ref']}")
    assert fb, "CWE-862 正样本未检出：/admin 未保护页应被报为强制浏览"
    results.append(("CWE-862 强制浏览正样本", len(fb) > 0))

    sa_local = scan_auth(LOCAL_BASE + "/", sess, timeout=5, verify_ssl=False, enable_auth_probe=True)
    dc = _find(sa_local, "CWE-287", risk="High", must_contain="默认")
    le = _find(sa_local, "CWE-287", must_contain="登录端点")
    print(f"  [CWE-287] 默认凭据探针 High findings: {len(dc)}")
    for f in dc:
        print(f"     - {f['risk']}/{f['evidence_level']}: {f['title']}")
    print(f"  [CWE-287] 被动登录端点 L1 findings: {len(le)}")
    assert dc, "CWE-287 默认凭据探针未检出 admin/password（受控端点）"
    results.append(("CWE-287 默认凭据探针正样本", len(dc) > 0))

    # CWE-601 开放重定向正样本：/redirect?to= 反射外部地址进 302 Location
    or_local = scan_open_redirect(LOCAL_BASE + "/redirect?to=home", sess, timeout=5, verify_ssl=False)
    or_strong = _find(or_local, "CWE-601", risk="Medium", must_contain="站外")
    or_passive = _find(or_local, "CWE-601", risk="Low", must_contain="潜在开放重定向")
    print(f"  [CWE-601] 开放重定向强证据 Medium findings: {len(or_strong)} | 被动 L1: {len(or_passive)}")
    for f in or_strong:
        print(f"     - {f['risk']}/{f['evidence_level']}: {f['title']}  | {f['target_ref']}")
    assert or_strong, "CWE-601 正样本未检出：/redirect?to=https://evil 应被报为开放重定向"
    results.append(("CWE-601 开放重定向正样本", len(or_strong) > 0))

    print()
    print("=" * 70)
    print("B) 真实靶机 DVWA（127.0.0.1:8090，security=low）")
    print("=" * 70)
    # 强制浏览：未登录管理页应被 302 拦回 -> 无 FP
    try:
        ac_dvwa = scan_access_control(DVWA_BASE + "/", sess, timeout=6, verify_ssl=False)
        fb_dvwa = _find(ac_dvwa, "CWE-862", must_contain="强制浏览")
        print(f"  [CWE-862] DVWA 强制浏览 findings: {len(fb_dvwa)} （期望 0：管理页 302 拦回，无 FP）")
        results.append(("CWE-862 DVWA 负样本(0 FP)", len(fb_dvwa) == 0))
    except requests.RequestException as e:
        print(f"  [CWE-862] DVWA 扫描异常（可能 DVWA 未运行）: {e}")
        results.append(("CWE-862 DVWA（DVWA 未运行，跳过）", None))

    # 认证：被动登录端点 + 明文 HTTP（L1）
    try:
        sa_dvwa = scan_auth(DVWA_BASE + "/login.php", sess, timeout=6, verify_ssl=False,
                            enable_auth_probe=True)
        le_dvwa = _find(sa_dvwa, "CWE-287", must_contain="登录端点")
        http_dvwa = _find(sa_dvwa, "CWE-287", must_contain="明文 HTTP")
        dc_dvwa = _find(sa_dvwa, "CWE-287", risk="High", must_contain="默认")
        print(f"  [CWE-287] DVWA 被动登录端点 L1: {len(le_dvwa)} | 明文 HTTP L1: {len(http_dvwa)}")
        print(f"  [CWE-287] DVWA 默认凭据探针 High: {len(dc_dvwa)} "
              f"（v1.4.0 CSRF 感知回填后，admin/password + 真实 token 应命中）")
        results.append(("CWE-287 DVWA 被动登录端点", len(le_dvwa) > 0))
        results.append(("CWE-287 DVWA 明文HTTP L1", len(http_dvwa) > 0))
        results.append(("CWE-287 DVWA 探针CSRF感知命中(期望>0)", len(dc_dvwa) > 0))
    except requests.RequestException as e:
        print(f"  [CWE-287] DVWA 扫描异常（可能 DVWA 未运行）: {e}")
        results.append(("CWE-287 DVWA（DVWA 未运行，跳过）", None))

    # token 感知登录确证 admin/password 有效
    ok, final_url, note = dvwa_login(sess, "admin", "password")
    print(f"  [DVWA] token 感知登录 admin/password -> 成功={ok} 终址={final_url} {('('+note+')' if note else '')}")
    results.append(("DVWA admin/password 真实有效", ok))

    print()
    print("=" * 70)
    print("汇总")
    print("=" * 70)
    all_pass = True
    for name, val in results:
        if val is None:
            mark = "SKIP"
        else:
            mark = "PASS" if val else "FAIL"
            if not val:
                all_pass = False
        print(f"  [{mark}] {name}")
    srv.shutdown()
    print()
    print("E2E 结论:", "全部通过 ✅" if all_pass else "存在未达预期项 ⚠️")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
