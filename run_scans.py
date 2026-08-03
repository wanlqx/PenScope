"""PenScope —— 扫描编排 Worker（项目根目录）
阶段机：scope_check → recon → subdomain_enum → web_detect → [闸门] exploit_verify → [闸门] upload_test → report
关键决策节点（exploit_verify / upload_test）会被暂停，等待安全分析员在复核队列批准后才继续。
"""
import json
import time
import socket
import ipaddress
import datetime
import asyncio
import requests
import config
from config import COMMON_PORTS, DEFAULT_TIMEOUT, ENABLE_AUTH_PROBE
from db import (
    get_scan, update_scan, get_target, add_finding, findings_of,
    create_review, pending_scans, audit, create_scan, list_schedules,
    update_schedule, record_stage_event, fail_scan, get_setting,
)
from scanner.port_scan import scan_ports, fingerprint_web
from scanner.web_scan import scan_sqli, scan_xss, scan_csrf, find_upload_forms, collect_pages, _send_form, discover
from scanner.cmd_injection import scan_cmd
from scanner.api_scan import scan_api
from scanner.subdomain import scan_subdomain_assets
from scanner.contentscan import scan_content
from scanner.mail_probe import scan_mail, MAIL_PORTS
from scanner.traversal import scan_traversal
from scanner.ssrf import scan_ssrf
from scanner.access_control import scan_access_control
from scanner.auth import scan_auth
from scanner.open_redirect import scan_open_redirect
from scanner.payloads import PayloadGenerator, detect_waf, detect_db_from_error
from scanner.vuln_db import match_vulns
from scanner.plugins import load_plugins
from scanner.plugin_base import ScanContext
from cvss_dedup import cwe_for
import re

# U-02：闸门通知钩子（由 main_gui 注册，用于系统托盘气泡 + 任务栏闪烁）。
# 解耦设计：run_scans 不直接依赖 GUI；main_gui 在启动时注册监听器，
# 扫描到关键节点暂停时通过此钩子即时推送通知，无需轮询。
_gate_listener = None


def set_gate_listener(fn):
    """注册一个闸门监听器 fn(kind, note, scan_id=None, target_id=None)。"""
    global _gate_listener
    _gate_listener = fn


def _fire_gate(kind, note, scan_id=None, target_id=None):
    if _gate_listener:
        try:
            _gate_listener(kind, note, scan_id=scan_id, target_id=target_id)
        except Exception:
            pass


# ---------------- P-06：pywebview 事件推送（替代前端轮询） ----------------
# 解耦设计：run_scans 不直接依赖 GUI；main_gui 在创建窗口后调用 set_push_window(window)，
# 任一阶段事件（记录到 scan_stage_events 的同时）通过 window.evaluate_js 主动把进度推给前端，
# 前端 window.__autopentestOnScanEvent 收到即刷新当前扫描详情，无需 4 秒轮询。
_PUSH_WINDOW = None


def set_push_window(w):
    """main_gui 在窗口创建后注册可推送的 pywebview 窗口对象。"""
    global _PUSH_WINDOW
    _PUSH_WINDOW = w


def push_scan_event(scan_id, stage=None, status=None, note=None):
    """把一次扫描阶段事件推送至前端（无窗口时静默 no-op）。"""
    if _PUSH_WINDOW is None:
        return
    payload = json.dumps({
        "type": "scan_event",
        "scan_id": scan_id,
        "stage": stage,
        "status": status,
        "note": note,
        "ts": int(time.time() * 1000),
    }, ensure_ascii=False)
    js = ("window.__autopentestOnScanEvent && "
          "window.__autopentestOnScanEvent(" + payload + ");")
    try:
        _PUSH_WINDOW.evaluate_js(js)
    except Exception:
        # 窗口未就绪 / 已销毁 / 线程调度异常 —— 静默忽略，前端仍有兜底轮询。
        pass



def _classify_error(e):
    """U-06：将扫描阶段抛出的异常归类为可读的失败归因类别。
    命中类别越具体越优先；默认兜底为 exception（未预期错误）。
    注意顺序：requests.exceptions.SSLError 在 requests 体系中是 ConnectionError 的子类，
    故必须把 SSL / 超时 / 重定向等更具体的分支放在宽泛的 ConnectionError 之前。"""
    if isinstance(e, socket.gaierror):
        return ("network_unreachable", f"域名解析失败：{e}")
    if isinstance(e, requests.exceptions.SSLError):
        return ("ssl_error", f"TLS 证书校验失败：{e}")
    if isinstance(e, (ConnectionError, ConnectionRefusedError, ConnectionResetError)):
        return ("network_unreachable", f"无法连接目标（网络不通或端口未开放）：{e}")
    if isinstance(e, requests.exceptions.ConnectionError):
        return ("network_unreachable", f"无法连接目标（连接被拒或网络不通）：{e}")
    if isinstance(e, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout)):
        return ("timeout", f"目标响应超时（网络慢或被防火墙丢弃）：{e}")
    if isinstance(e, requests.exceptions.TooManyRedirects):
        return ("redirect_loop", f"重定向环路：{e}")
    return ("exception", f"未预期错误：{repr(e)}")


def _fkwargs(f):
    """从扫描器返回的发现 dict 中抽取结构化字段，透传给 add_finding。"""
    return {
        "cwe": f.get("cwe", ""),
        "endpoint": f.get("endpoint", ""),
        "http_method": f.get("http_method", ""),
        "poc_script": f.get("poc", ""),
        "verification_status": f.get("verification_status", "pending"),
        "evidence_level": f.get("evidence_level", "L1"),
        "impact": f.get("impact", ""),
        "evidence_meta": f.get("evidence_meta"),
    }

_session = requests.Session()
_session.headers.update({"User-Agent": "PenScope/1.0 (authorized security test)"})

# 同 IP 多 vhost 端口探测复用缓存：以「解析 IP + 端口集合」为键，避免对共享公网 IP 的
# 多个子域重复做整轮端口扫描（仅复用端口结果，vhost 级 Web 检测仍逐主机执行）。
_PORT_CACHE = {}


def _resolve_ip(host):
    """解析域名到 IP；IP 字面量直接返回；解析失败返回 None。"""
    if _re_ip_literal(host):
        return host
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return None


def _re_ip_literal(host):
    try:
        ipaddress.ip_address(host.split(":")[0])
        return True
    except ValueError:
        return False


def _is_private_host(host):
    """目标解析到的 IP 是否属于「需内网授权环境」的网段。

    命中即阻断公网扫描：RFC1918 私有段（10/172.16-31/192.168）、链路本地
    （169.254）、保留/文档段（如 203.0.113）、未指定（0.0.0.0）。
    **回环（127.0.0.0/8、::1）特意放行**：那是使用者自己的主机，本地测试/
    本机评估属合理场景，不应被护栏误阻。
    解析失败返回 False（不因 DNS 瞬时失败而误阻断授权目标）。"""
    ip = _resolve_ip(host)
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.split(":")[0])
    except ValueError:
        return False
    if addr.is_loopback:
        return False
    return (addr.is_private or addr.is_link_local
            or addr.is_reserved or addr.is_unspecified)


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _parse_ports(port_range):
    if not port_range or port_range == "common":
        return COMMON_PORTS
    if port_range == "top1000":
        return list(range(1, 1001))
    ports = []
    for part in port_range.split(","):
        if "-" in part:
            a, b = part.split("-")[:2]
            ports += range(int(a), int(b) + 1)
        else:
            ports.append(int(part))
    return ports[:1000]


def _stage_scope_check(scan):
    t = get_target(scan["target_id"])
    if not t or t["status"] != "approved":
        fail_scan(scan["id"], "scope_unauthorized", "目标未通过授权审批，已阻断扫描",
                  error_summary="目标未通过授权审批，已阻断扫描")
        audit(scan["created_by"], "scan_blocked", t["host"] if t else "?",
              "目标未授权/未审批，依据授权围栏策略拒绝扫描")
        return False
    # 私有地址护栏：解析到 RFC1918 私有段 / 链路本地 / 保留 / 未指定网段的目标，从公网
    # 不可达且属内网范围，必须阻断并提示需内网授权环境，防止误扫内网（作用域围栏）。
    # 回环地址特意放行（使用者本机，本地评估合理场景）。
    if _is_private_host(t["host"]):
        fail_scan(scan["id"], "scope_private",
                  f"目标 {t['host']} 解析到私有/内网网段，已阻断",
                  error_summary=f"目标 {t['host']} 解析到私有/内网网段，已阻断")
        audit(scan["created_by"], "scan_blocked_private", t["host"],
              f"目标 {t['host']} 解析到私有/内网网段，依据私有地址护栏拒绝公网扫描"
              f"（如需评估请在授权内网环境中单独进行）")
        return False
    return True


def _stage_recon(scan):
    t = get_target(scan["target_id"])
    host = t["host"]
    vs = bool(t.get("verify_tls", 1))  # AP-002：按目标 TLS 校验策略
    ports = _parse_ports(t["port_range"])
    audit(scan["created_by"], "port_scan_start", host, f"扫描 {len(ports)} 个端口")
    # 同 IP 多 vhost 端口探测复用：解析 IP 命中缓存则跳过整轮端口扫描（仅复用端口结果，
    # vhost 级 Web 检测仍在后续 web_detect 阶段逐主机执行）。
    ip = _resolve_ip(host)
    cache_key = (ip, tuple(sorted(ports))) if ip else None
    if cache_key is not None and cache_key in _PORT_CACHE:
        open_ports = _PORT_CACHE[cache_key]
        audit(scan["created_by"], "port_scan_cache_hit", host,
              f"解析 IP {ip} 命中端口探测缓存，复用 {len(open_ports)} 个开放端口（避免重复扫描）")
    else:
        open_ports = scan_ports(host, ports, DEFAULT_TIMEOUT)
        if cache_key is not None:
            _PORT_CACHE[cache_key] = open_ports
    web_targets = fingerprint_web(host, [p["port"] for p in open_ports], verify_ssl=vs)
    for op in open_ports:
        add_finding(scan["id"], "资产暴露", f"开放端口 {op['port']}/{op['service']}",
                    "Info", f"服务: {op['service']}\nbanner: {op['banner']}",
                    op["banner"], "关闭不必要的服务端口；仅对必要端口开放并加访问控制。",
                    f"{host}:{op['port']}",
                    cwe=cwe_for("资产暴露"), verification_status="info", evidence_level="L1",
                    endpoint=f"{host}:{op['port']}", http_method="TCP",
                    poc_script=f"nmap -sV -p {op['port']} {host}")
        for v in op.get("vulns", []):
            add_finding(scan["id"], "已知漏洞", f"{v['service']} {v['version']} 存在已知漏洞",
                        v["risk"], v["detail"], f"CVE: {v['cve']}", v["remediation"],
                        f"{host}:{op['port']}",
                        cwe=cwe_for("已知漏洞"), verification_status="unverified", evidence_level="L2",
                        endpoint=f"{host}:{op['port']}", http_method="TCP", impact=v.get("impact", ""))
    # 邮件/协议感知：对开放邮件端口做只读 STARTTLS/明文传输检测（不改密、不登录、不爆破）
    for op in open_ports:
        if op["port"] in MAIL_PORTS:
            try:
                for mf in scan_mail(host, op["port"], DEFAULT_TIMEOUT):
                    add_finding(scan["id"], mf["category"], mf["title"], mf["risk"], mf["detail"],
                                mf["evidence"], mf["remediation"], mf["target_ref"], **_fkwargs(mf))
            except Exception as e:
                audit(scan["created_by"], "mail_probe_err", f"{host}:{op['port']}",
                      f"邮件端口探测异常: {e}")
    summary = {"open_ports": open_ports, "web_targets": web_targets, "host": host}
    update_scan(scan["id"], stage="web_detect", summary=json.dumps(summary))
    audit(scan["created_by"], "port_scan_done", host,
          f"开放 {len(open_ports)} 端口，发现 {len(web_targets)} 个 Web 服务")
    return True


def _stage_subdomain_enum(scan):
    """被动子域枚举（资产发现）：仅对域名型目标做被动发现，绝不自动创建扫描任务。

    发现的兄弟子域仅记录为 Info 级「资产发现」发现；如需进一步扫描，必须由使用者
    在应用内二次授权后手动添加目标（作用域围栏），避免越权扫描未知资产。
    """
    import re as _re
    t = get_target(scan["target_id"])
    host = t["host"]
    # 仅对域名型目标枚举；纯 IP 目标无有意义的基础域名，跳过
    if _re.fullmatch(r"[\d.]+", host) or ":" in host:
        audit(scan["created_by"], "subdomain_skip", host, "纯 IP 目标，跳过子域枚举")
        return True
    audit(scan["created_by"], "subdomain_start", host, "被动子域枚举（crt.sh + DNS）")
    try:
        assets = scan_subdomain_assets(host)
    except Exception as e:
        audit(scan["created_by"], "subdomain_err", host, f"子域枚举异常: {e}")
        return True
    for sub, ip in assets:
        add_finding(scan["id"], "子域资产", f"被动发现兄弟子域：{sub}", "Info",
                    f"通过证书透明度/常见子域被动解析发现 {sub}，解析到 {ip}。"
                    f"该资产不在本次授权目标清单内，如需扫描须经二次授权后单独添加目标。",
                    f"resolved_ip={ip}", "如发现未授权资产，请经二次授权后在「授权目标」中手动添加"
                    f"并审批，再发起扫描（作用域围栏）。", sub,
                    cwe="CWE-200", endpoint=sub, http_method="DNS",
                    verification_status="info", evidence_level="L1")
    audit(scan["created_by"], "subdomain_done", host,
          f"子域枚举完成，发现 {len(assets)} 个被动子域（仅记录，未自动扫描）")
    return True


# ---------------- P-01：asyncio 并发 Web 检测 ----------------
async def _detect_page_async(page, vs, pg, scan, renewal=None):
    """并发运行某页面的多个独立扫描器（IO 密集型并行）。
    每个扫描器使用独立 Session，结果回主线程写库，避免共享 Session 与计数竞争。
    renewal：C-06 会话续期控制器。若提供，则每个扫描器复用「与该控制器共享认证态、
    且会自动续期」的 RenewableSession，使已授权目标的登录态在整个扫描周期保持有效。"""
    def _jobs():
        # C-05：默认凭据探测开关可由代码主闸门（ENABLE_AUTH_PROBE）或设置项
        # enable_auth_probe 开启；自定义字典经设置项 auth_probe_dict 传入。
        enable_probe = (str(get_setting("enable_auth_probe") or "").lower() in ("1", "true")) or ENABLE_AUTH_PROBE
        custom_dict = (get_setting("auth_probe_dict") or "").strip() or None
        return [
            ("SQL注入", lambda s: scan_sqli(page, s, pg, verify_ssl=vs)),
            ("XSS", lambda s: scan_xss(page, s, pg, verify_ssl=vs)),
            ("CSRF", lambda s: scan_csrf(page, s, verify_ssl=vs)),
            ("文件上传", lambda s: find_upload_forms(page, s, verify_ssl=vs)),
            ("命令注入", lambda s: scan_cmd(page, s, pg, verify_ssl=vs)),
            ("路径遍历", lambda s: scan_traversal(page, s, verify_ssl=vs)),
            ("SSRF", lambda s: scan_ssrf(page, s, verify_ssl=vs)),
            ("缺失授权", lambda s: scan_access_control(page, s, verify_ssl=vs)),
            ("认证缺陷", lambda s: scan_auth(page, s, enable_auth_probe=enable_probe,
                                            cred_dict_path=custom_dict, verify_ssl=vs)),
            ("开放重定向", lambda s: scan_open_redirect(page, s, verify_ssl=vs)),
        ]

    async def _run(cat, fn):
        # C-06：若启用会话续期，复用续期会话（共享认证态 + 自动重登）；否则独立裸会话。
        s = renewal.session() if renewal is not None else requests.Session()
        s.headers.update({"User-Agent": "PenScope/1.0"})
        try:
            return cat, await asyncio.to_thread(fn, s)
        except Exception as e:  # 单个扫描器异常不影响其它
            return cat, e

    results = await asyncio.gather(*[_run(c, f) for c, f in _jobs()])
    uploads, sql_h, cmd_h = [], 0, 0
    for cat, out in results:
        if isinstance(out, Exception):
            audit(scan["created_by"], "web_scan_err", page, f"{cat}并发检测异常: {out}")
            continue
        if cat == "文件上传":
            for u in out:
                uploads.append(u)
                add_finding(scan["id"], "文件上传", f"发现文件上传入口: {u['action']}",
                            "Medium", "检测到文件上传表单，需人工授权后验证是否存在限制缺失。",
                            f"method={u['method']} fields={u['fields']}",
                            "严格校验文件类型/大小/Content-Type；重命名并存储于非执行目录；限制可执行权限。",
                            u["action"], cwe=cwe_for("文件上传"), verification_status="unverified",
                            evidence_level="L2", endpoint=u["action"], http_method=u["method"].upper())
            continue
        for f in out:
            add_finding(scan["id"], cat, f["title"], f["risk"], f["detail"],
                        f["evidence"], f["remediation"], f["target_ref"], **_fkwargs(f))
            if cat == "SQL注入" and f["risk"] in ("High", "Critical"):
                sql_h += 1
            if cat == "命令注入" and f["risk"] in ("High", "Critical"):
                cmd_h += 1
    return uploads, sql_h, cmd_h


def _web_tech_banner(session, url, verify_ssl):
    """抓取 Web 组件指纹串（C-04 关联数据源）：Server / X-Powered-By / 框架头 / 页面标题。

    被动只读 GET（allow_redirects=False，跟随由上层作用域围栏约束），失败返回空串。
    """
    parts = []
    try:
        r = session.get(url, timeout=5, verify=verify_ssl, allow_redirects=False)
        for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator",
                  "X-Drupal-Cache", "X-Varnish", "X-Backend"):
            v = r.headers.get(h)
            if v:
                parts.append(f"{h}: {v}")
        m = re.search(r"<title>(.*?)</title>", r.text or "", re.IGNORECASE | re.DOTALL)
        if m:
            parts.append(m.group(1).strip()[:120])
    except requests.RequestException:
        pass
    return " ".join(parts)


def run_plugin_scanners(scan, session, vs, wt):
    """F-08：对单个 Web 目标运行所有已注册插件扫描器。

    纯增量、异常隔离：单个插件异常仅 audit 记录，不阻断主流水线；无插件或开关关闭时零开销。
    """
    if not getattr(config, "ENABLE_PLUGINS", True):
        return
    plugins = load_plugins()
    if not plugins:
        return
    created_by = scan.get("created_by")
    for p in plugins:
        try:
            ctx = ScanContext(scan["id"], wt, session, vs, add_finding, audit, created_by=created_by)
            p.scan(ctx)
            audit(created_by, "plugin_run", getattr(p, "name", "?"),
                  f"插件 {getattr(p, 'name', '?')} 在 {wt.get('url', '')} 执行完成")
        except Exception as e:
            audit(created_by, "plugin_err", getattr(p, "name", "?"),
                  f"插件 {getattr(p, 'name', '?')} 异常: {e}")


async def _web_detect_all_async(scan, web_targets, vs, session, renewal=None):
    """逐 Web 主机：指纹 + 爬取（顺序），页面内多扫描器并发（P-01）。
    renewal：C-06 会话续期控制器，透传给逐页扫描器以复用认证态。"""
    all_uploads, sql_high, cmd_high = [], 0, 0
    seen_pages = set()
    seen_cve = set()  # C-04：按 (组件, 版本) 去重，避免同组件在多个页面重复告警
    # F-05：采集资产基线信号（指纹/标题/关键响应头），扫描结束后比对变更
    _snap_banners, _snap_titles = [], []
    for wt in web_targets:
        url = wt["url"]
        audit(scan["created_by"], "web_scan_start", url, "检测 SQLi/XSS/CSRF/上传点（含页面爬取）")
        pg = PayloadGenerator(waf=detect_waf(session, url, verify_ssl=vs))
        add_finding(scan["id"], "环境指纹", f"Web 服务识别: {wt.get('server','')}",
                    "Info", f"Server: {wt.get('server','')}\n标题: {wt.get('title','')}",
                    "", "记录环境信息以辅助后续自适应载荷生成。", url,
                    cwe=cwe_for("环境指纹"), verification_status="info", evidence_level="L1",
                    endpoint=url, http_method="GET")
        # C-04：Web 组件 CVE 联动（被动版本命中，零误报）
        # 将 Web 组件指纹（Server / 框架头 / 标题）与已知漏洞库关联，输出"组件+版本+CVE"。
        # 仅依据版本识别命中，标记 info 且注明需结合补丁状态确认可利用性。
        try:
            banner = _web_tech_banner(session, url, vs)
            if banner:
                _snap_banners.append(banner)
            if wt.get("title"):
                _snap_titles.append(wt["title"])
            for h in match_vulns("", banner):
                key = (h["service"], h["version"])
                if key in seen_cve:
                    continue
                seen_cve.add(key)
                add_finding(scan["id"], "组件CVE", f"{h['service']} {h['version']} 存在已知漏洞（{h['cve']}）",
                            h["risk"],
                            f"依据 Web 组件指纹被动命中已知漏洞库：{h['detail']} "
                            f"命中组件 {h['service']} 版本 {h['version']}（CVE: {h['cve']}）。"
                            f"该结论基于版本识别，实际可利用性需结合目标补丁状态确认。",
                            f"service={h['service']} version={h['version']} cve={h['cve']} banner={banner[:160]}",
                            h["remediation"], url,
                            cwe="CWE-1035", endpoint=url, http_method="GET",
                            verification_status="info", evidence_level="L1")
            if seen_cve:
                audit(scan["created_by"], "cve_correlate", url,
                      f"组件 CVE 联动命中 {len(seen_cve)} 项（被动版本识别）")
        except Exception as e:
            audit(scan["created_by"], "cve_correlate_err", url, f"CVE 联动异常: {e}")
        # F-08：插件化框架 —— 对当前 Web 目标运行已注册插件扫描器（异常隔离，无插件时零开销）。
        try:
            run_plugin_scanners(scan, session, vs, wt)
        except Exception as e:
            audit(scan["created_by"], "plugin_err", url, f"插件执行异常: {e}")
        try:
            pages = collect_pages(url, session, max_pages=40, verify_ssl=vs)
        except Exception as e:
            audit(scan["created_by"], "web_scan_err", url, f"页面爬取异常: {e}")
            pages = [url]
        if not pages:
            pages = [url]
        for page in pages:
            if page in seen_pages:
                continue
            seen_pages.add(page)
            try:
                ups, s_h, c_h = await _detect_page_async(page, vs, pg, scan, renewal=renewal)
            except Exception as e:
                audit(scan["created_by"], "web_scan_err", page, f"并发检测异常: {e}")
                ups, s_h, c_h = [], 0, 0
            all_uploads.extend(ups)
            sql_high += s_h
            cmd_high += c_h
    # ---- F-05 资产变更告警：扫描结束后比对相邻快照，按设置通知 / 自动增量扫描 ----
    _apply_asset_baseline(scan, _snap_banners, _snap_titles)
    return all_uploads, sql_high, cmd_high, seen_pages


def _apply_asset_baseline(scan, banners, titles):
    """F-05：把本次 Web 扫描采集到的指纹/标题构建为快照，比对历史基线并触发告警。

    设置项（db.get_setting）：
      asset_change_alert  : 总开关（默认关）—— 开启才做变更检测与后续动作
      asset_change_notify : 桌面气泡通知（默认开）
      asset_autoscan      : 变更后自动创建增量扫描（默认关）
    首次建立基线不告警；无变更不动作。"""
    try:
        from db import get_setting, create_scan, audit, get_target
        import asset_watch
        import notify
        if not (str(get_setting("asset_change_alert") or "").lower() in ("1", "true")):
            # 总开关关闭：仍建立/刷新基线，便于日后开启即具备对比历史
            asset_watch.check_and_apply_baseline(scan["target_id"],
                                                 _build_snapshot(banners, titles))
            return
        old, changes = asset_watch.check_and_apply_baseline(
            scan["target_id"], _build_snapshot(banners, titles))
        if not changes:
            return
        t = get_target(scan["target_id"]) or {}
        host = t.get("host", str(scan.get("target_id", "?")))
        audit(scan["created_by"], "asset_change", host,
              asset_watch.format_changes(host, changes), "")
        if str(get_setting("asset_change_notify") or "").lower() not in ("0", "false"):
            # 默认开启（未配置/空字符串视为开）
            notify.notify("PenScope · 资产变更",
                          asset_watch.format_changes(host, changes))
        if str(get_setting("asset_autoscan") or "").lower() in ("1", "true"):
            create_scan(scan["target_id"], f"[资产变更增量]{host}", "asset_watch")
            audit(scan["created_by"], "scan_create", host,
                  "资产变更触发自动增量扫描", "")
    except Exception as e:
        try:
            from db import audit
            audit(scan.get("created_by", "system"), "asset_watch_err", "",
                  f"资产变更检测异常: {e}")
        except Exception:
            pass


def _build_snapshot(banners, titles):
    """由采集到的 banner 串与标题构建规范化快照。"""
    fingerprint = " | ".join(sorted(set(b.strip() for b in banners if b and b.strip())))
    headers = []
    for b in banners:
        for line in b.splitlines():
            line = line.strip()
            if ":" in line and not line.lower().startswith("<title"):
                headers.append(line)
    title = titles[0] if titles else ""
    return {
        "fingerprint": fingerprint,
        "title": title,
        "headers": sorted(set(headers)),
        "ports": [],
        "subdomains": [],
    }


def _build_renewal(t, vs):
    """C-06：若目标已配置凭据且会话续期开启，构造并登录续期控制器；否则返回 None。
    登录失败仅审计、不阻断扫描（降级为匿名会话继续）。"""
    try:
        from scanner.vault import get_vault
        from scanner.session_renew import SessionRenewal
        from config import ENABLE_SESSION_RENEW, SESSION_RENEW_MAX
        if not ((str(get_setting("enable_session_renew") or "").lower() in ("1", "true")) or ENABLE_SESSION_RENEW):
            return None
        profile = get_vault().get(t["id"])
        if not profile:
            return None
        ctrl = SessionRenewal(profile, verify_ssl=vs, max_renewals=SESSION_RENEW_MAX)
        if ctrl.login():
            audit(t.get("created_by", "system"), "session_renew_login", t["host"],
                  "已用存储凭据建立认证会话（会话续期已启用）", "")
            return ctrl
        audit(t.get("created_by", "system"), "session_renew_login_fail", t["host"],
              "存储凭据登录失败，降级为匿名会话继续扫描", "")
        return None
    except Exception as e:
        try:
            from db import audit
            audit(t.get("created_by", "system"), "session_renew_err", t.get("host", "?"),
                  f"会话续期初始化异常: {e}")
        except Exception:
            pass
        return None


def _stage_web_detect(scan):
    summary = json.loads(scan["summary"] or "{}")
    web_targets = summary.get("web_targets", [])
    if not web_targets:
        update_scan(scan["id"], stage="report")
        return True
    t = get_target(scan["target_id"])
    vs = bool(t.get("verify_tls", 1))  # AP-002：按目标 TLS 校验策略
    # C-06：会话续期 —— 已配置凭据且开启时，建立认证会话并注入 Web 检测全流程
    renewal = _build_renewal(t, vs)
    wsession = renewal.session() if renewal is not None else _session
    # P-01：异步并发编排 Web 检测（IO 密集型，多扫描器并行）；process_scan 同步 API 不变
    all_uploads, sql_high, cmd_high, seen_pages = asyncio.run(
        _web_detect_all_async(scan, web_targets, vs, wsession, renewal=renewal))
    # API 安全被动检测：基于已爬取页面集合，对疑似 API 端点做一次整体扫描
    try:
        api_base = web_targets[0]["url"] if web_targets else None
        if api_base:
            audit(scan["created_by"], "api_scan_start", api_base, "被动检测 CORS/敏感数据/鉴权/方法滥用")
            for f in scan_api(api_base, wsession, list(seen_pages), verify_ssl=vs):
                add_finding(scan["id"], "API安全", f["title"], f["risk"], f["detail"],
                            f["evidence"], f["remediation"], f["target_ref"], **_fkwargs(f))
    except Exception as e:
        audit(scan["created_by"], "api_scan_err", api_base or "", f"API安全检测异常: {e}")
    # 目录 / 敏感信息被动扫描（只读 GET/HEAD，不写不删）：基于已发现 Web 主机逐一探测
    try:
        _done_hosts = set()
        for wt in web_targets:
            from urllib.parse import urlparse
            netloc = urlparse(wt["url"]).netloc
            if netloc in _done_hosts:
                continue
            _done_hosts.add(netloc)
            for f in scan_content(wt["url"], wsession):
                add_finding(scan["id"], f["category"], f["title"], f["risk"], f["detail"],
                            f["evidence"], f["remediation"], f["target_ref"], **_fkwargs(f))
        audit(scan["created_by"], "content_scan_done", api_base or "", "目录/敏感信息被动扫描完成")
    except Exception as e:
        audit(scan["created_by"], "content_scan_err", api_base or "", f"目录扫描异常: {e}")
    # C-06：若本次扫描发生了自动续期，审计并写一条 Info 发现，便于报告呈现续期行为
    if renewal is not None and renewal.renew_count > 0:
        audit(scan["created_by"], "session_renewed", t["host"],
              f"扫描期间自动续期 {renewal.renew_count} 次（维持目标认证会话）", "")
        add_finding(scan["id"], "认证会话", f"扫描期间自动续期认证会话 {renewal.renew_count} 次",
                    "Info",
                    f"目标 {t['host']} 已配置会话续期；本次扫描过程中检测到会话失效并自动重新登录 "
                    f"{renewal.renew_count} 次，确保已认证区域持续被评估（避免中途登录态过期漏检）。",
                    f"renew_count={renewal.renew_count} max_renewals={renewal.max_renewals}",
                    "确认续期行为符合预期；若续期频繁，说明目标会话有效期过短，可结合业务评估风险。",
                    t["host"], cwe="CWE-287", endpoint=t["host"], http_method="AUTH",
                    verification_status="info", evidence_level="L1")
    summary["uploads"] = all_uploads
    # 闸门备注以「入库去重后」的发现为准，避免原始多分隔符计数虚高（见 scan_cmd 去重）
    _stored = findings_of(scan["id"])
    _sql_high = sum(1 for f in _stored if f["category"] == "SQL注入" and f["risk"] in ("High", "Critical"))
    _cmd_high = sum(1 for f in _stored if f["category"] == "命令注入" and f["risk"] in ("High", "Critical"))
    # 若存在需验证的高危注入或上传点，先进入人工闸门（关键决策节点）
    if _sql_high or all_uploads or _cmd_high:
        update_scan(scan["id"], stage="exploit_verify", summary=json.dumps(summary))
        _gate(scan, "exploit_verify",
              f"发现 {_sql_high} 项高危 SQL 注入、{_cmd_high} 项命令注入、{len(all_uploads)} 个上传入口，"
              f"将进行利用验证（含命令注入时间盲注证明，会造成目标短暂延迟），需人工批准")
        return True
    update_scan(scan["id"], stage="report", summary=json.dumps(summary))
    return True


def _gate(scan, kind, note):
    create_review(kind, note, target_id=scan["target_id"], scan_id=scan["id"])
    update_scan(scan["id"], status="awaiting_review")
    audit(scan["created_by"], "gate_paused", f"scan#{scan['id']}",
          f"关键节点 [{kind}] 已暂停，等待人工复核：{note}")
    # U-02：即时推送托盘通知 + 任务栏闪烁
    _fire_gate(kind, note, scan_id=scan["id"], target_id=scan["target_id"])


def _verify_sqli(ref, verify_ssl=True):
    """对 SQLi 发现的端点做时间盲注验证，返回延迟秒数（0 表示未验证）。
    兼容 GET 查询参数与 POST 表单两种入口；自动提交表单全部字段（含 submit 等触发字段，
    否则目标查询不执行——与 scan_sqli 的表单分支保持一致）；尝试多种上下文载荷（数字/字符、
    单双引号、AND/OR），以适配不同注入点（Pikachu 各模块：数字型 sqli_id、字符型 sqli_str /
    sqli_blind_t 等）。
    采用 (SELECT SLEEP(N) FROM dual) 使休眠在多数情况下只执行一次；若因逐行求值导致请求超时，
    该超时本身即证明注入可控（正常页面不会因该载荷挂起），故一并计为验证成功。"""
    from urllib.parse import urlparse, urlunparse, parse_qs
    # 使用独立的新会话做验证，避免扫描爬取阶段累积的 Cookie 影响目标行为（已观察到
    # 残留会话态导致部分时间盲注不再触发的非确定性），保证验证可复现。
    vsession = requests.Session()
    vsession.headers.update({"User-Agent": "PenScope/1.0 (authorized security test)"})
    candidates = []
    q = urlparse(ref)
    base = urlunparse(q._replace(query="", fragment=""))
    # 探查目标页面表单，获取完整字段集合（含 submit 触发字段），GET/POST 均需要
    try:
        forms = discover(base, vsession)
    except Exception:
        forms = []
    if q.query:
        # GET 入口：去掉已有查询，对照表单找到含该参数的表单，以完整字段提交
        for k in parse_qs(q.query).keys():
            for f in forms:
                if k in f["fields"]:
                    candidates.append((f["action"], f["method"], f["fields"], k))
                    break
            else:
                candidates.append((base, "get", [k], k))
    else:
        for f in forms:
            inj = [n for n in f["fields"] if n not in f["file_fields"]]
            # 对每个可注入字段都生成一个候选（字段在 HTML 中的顺序不确定，
            # submit/按钮 可能排在数据字段之前，若只取第一个可能注入到错误字段而漏报）
            for field in inj:
                candidates.append((f["action"], f["method"], f["fields"], field))
    # 多上下文载荷：数字(AND真) / 字符(OR，左右引号各一) / 简单 AND /
    # 通配符 AND（适配 LIKE '%x%'，OR 会被 LIKE '%' 短路，需用 AND 且左侧为真）
    payloads = [
        "1 AND (SELECT SLEEP(2) FROM dual)-- ",
        '" OR (SELECT SLEEP(2) FROM dual)-- ',
        "' OR (SELECT SLEEP(2) FROM dual)-- ",
        "1 AND SLEEP(2)-- ",
        "' AND (SELECT SLEEP(2) FROM dual)-- ",
        "%' AND (SELECT SLEEP(2) FROM dual)-- ",
        '" AND (SELECT SLEEP(2) FROM dual)-- ',
    ]
    for target, method, fields, p in candidates:
        for payload in payloads:
            t0 = time.time()
            try:
                _send_form(vsession, target, method, fields, p, payload, timeout=6, verify_ssl=verify_ssl)
                dt = time.time() - t0
            except requests.exceptions.ReadTimeout:
                # 超时（多为休眠被逐行触发）即视为可利用证据
                dt = time.time() - t0
            except requests.RequestException:
                continue
            if dt >= 1.5:
                return dt
    # 时间盲注未触发时，回退为"错误型复现"验证：复现数据库报错即证明注入点可控
    if candidates:
        target, method, fields, p = candidates[0]
        try:
            r = _send_form(vsession, target, method, fields, p, "'", timeout=6, verify_ssl=verify_ssl)
            if detect_db_from_error(r.text):
                return -1.0  # 错误型复现验证成功（非时间延迟）
        except requests.RequestException:
            pass
    return 0


def _verify_cmd(ref, verify_ssl=True):
    """对命令注入发现的端点做时间盲注证明，返回延迟秒数（0 表示未验证）。

    自动提交表单全部字段（与 scan_cmd 分支保持一致），尝试多种命令分隔符与
    `sleep` 载荷；若响应明显延迟则视为命令被执行（正常页面不会因该载荷挂起）。
    使用独立会话避免残留 Cookie 影响目标行为，保证验证可复现。
    仅证明可利用，不提取数据、不执行破坏性命令。"""
    vsession = requests.Session()
    vsession.headers.update({"User-Agent": "PenScope/1.0 (authorized security test)"})
    from urllib.parse import urlparse, urlunparse, parse_qs
    q = urlparse(ref)
    base = urlunparse(q._replace(query="", fragment=""))
    try:
        forms = discover(base, vsession)
    except Exception:
        forms = []
    candidates = []
    if q.query:
        for k in parse_qs(q.query).keys():
            for f in forms:
                if k in f["fields"]:
                    candidates.append((f["action"], f["method"], f["fields"], k))
                    break
            else:
                candidates.append((base, "get", [k], k))
    else:
        for f in forms:
            for field in [n for n in f["fields"] if n not in f["file_fields"]]:
                candidates.append((f["action"], f["method"], f["fields"], field))
    payloads = ["; sleep 3", "| sleep 3", "& sleep 3", "$(sleep 3)",
                "`sleep 3`", "|| sleep 3", "&& sleep 3"]
    for target, method, fields, p in candidates:
        for payload in payloads:
            t0 = time.time()
            try:
                _send_form(vsession, target, method, fields, p, payload, timeout=8, verify_ssl=verify_ssl)
                dt = time.time() - t0
            except requests.exceptions.ReadTimeout:
                dt = time.time() - t0
            except requests.RequestException:
                continue
            if dt >= 2.0:
                return dt
    return 0


def _stage_exploit_verify(scan):
    """利用验证（已授权）：对确认的高危 SQLi / 命令注入 做时间盲注证明，仅证明可利用，不提取数据。"""
    findings = findings_of(scan["id"])
    t = get_target(scan["target_id"])
    vs = bool(t.get("verify_tls", 1))  # AP-002：按目标 TLS 校验策略
    verified = 0
    for f in findings:
        if f["category"] == "SQL注入" and f["risk"] in ("High", "Critical"):
            ref = f["target_ref"]
            dt = _verify_sqli(ref, vs)
            if dt >= 1.5:
                verified += 1
                add_finding(scan["id"], "利用验证", f"[已验证] {f['title']}",
                            "Critical", f"时间盲注证明成功：响应延迟约 {dt:.1f}s，确认注入可利用。",
                            f"delay={dt:.1f}s",
                            "立即修复 SQL 注入；对数据库账户最小权限化；部署 WAF 与输入校验。",
                            ref,
                            cwe=cwe_for("利用验证"), verification_status="verified",
                            evidence_level="L4", endpoint=ref, http_method="", poc_script=_fkwargs(f).get("poc_script", ""))
            elif dt == -1.0:
                verified += 1
                add_finding(scan["id"], "利用验证", f"[已验证] {f['title']}",
                            "Critical", "错误型复现验证成功：复现数据库报错特征，确认注入点可控、可被利用。",
                            "error_repro=1",
                            "立即修复 SQL 注入；对数据库账户最小权限化；部署 WAF 与输入校验。",
                            ref,
                            cwe=cwe_for("利用验证"), verification_status="verified",
                            evidence_level="L4", endpoint=ref, http_method="")
        elif f["category"] == "命令注入" and f["risk"] in ("High", "Critical"):
            ref = f["target_ref"]
            dt = _verify_cmd(ref, vs)
            if dt >= 2.0:
                verified += 1
                add_finding(scan["id"], "利用验证", f"[已验证] {f['title']}",
                            "Critical", f"时间盲注证明成功：响应延迟约 {dt:.1f}s，确认命令注入可利用。",
                            f"delay={dt:.1f}s",
                            "立即修复命令注入；禁止拼接系统命令；使用参数化的子进程 API 并最小权限运行服务。",
                            ref,
                            cwe=cwe_for("命令注入"), verification_status="verified",
                            evidence_level="L4", endpoint=ref, http_method="",
                            poc_script=_fkwargs(f).get("poc_script", ""))
    audit(scan["created_by"], "exploit_verify", f"scan#{scan['id']}",
          f"利用验证完成，{verified} 项高危注入确认为可利用（时间盲注证明）")
    summary = json.loads(scan["summary"] or "{}")
    if summary.get("uploads"):
        update_scan(scan["id"], stage="upload_test")
        _gate(scan, "upload_test",
              f"将对 {len(summary['uploads'])} 个文件上传入口进行上传测试，可能写入测试文件")
        return
    update_scan(scan["id"], stage="report")


def _stage_upload_test(scan):
    """上传测试（已授权）：上传良性 .txt 测试文件，验证上传功能是否可用（不执行、不传恶意内容）。"""
    summary = json.loads(scan["summary"] or "{}")
    uploads = summary.get("uploads", [])
    t = get_target(scan["target_id"])
    vs = bool(t.get("verify_tls", 1))  # AP-002：按目标 TLS 校验策略
    done = 0
    for u in uploads:
        try:
            files = {"file": ("TEST_autopentest_marker.txt",
                              b"AUTOPENTEST_SAFE_MARKER_9F3A", "text/plain")}
            r = _session.post(u["action"], files=files, timeout=10, verify=vs)
            if r.status_code in (200, 201, 302):
                done += 1
                add_finding(scan["id"], "利用验证", f"[已验证] 上传入口可用: {u['action']}",
                            "High", "在授权下上传良性测试文件成功，说明上传功能无类型/执行限制，存在被滥用风险。",
                            f"status={r.status_code} len={len(r.content)}",
                            "校验扩展名与 MIME；禁止执行目录写权限；对上传文件做病毒扫描与隔离存储。",
                            u["action"],
                            cwe=cwe_for("利用验证"), verification_status="verified",
                            evidence_level="L4", endpoint=u["action"], http_method=u["method"].upper())
        except requests.RequestException:
            pass
    audit(scan["created_by"], "upload_test", f"scan#{scan['id']}",
          f"上传测试完成，{done}/{len(uploads)} 个入口上传成功（已上传良性测试文件）")
    update_scan(scan["id"], stage="report")


def _stage_report(scan):
    findings = findings_of(scan["id"])
    counts = {lv: 0 for lv in ["Critical", "High", "Medium", "Low", "Info"]}
    for f in findings:
        counts[f["risk"]] = counts.get(f["risk"], 0) + 1
    summary = json.loads(scan["summary"] or "{}")
    summary["risk_counts"] = counts
    summary["total_findings"] = len(findings)
    update_scan(scan["id"], status="completed", finished_at=_now(),
                summary=json.dumps(summary))
    audit(scan["created_by"], "scan_completed", f"scan#{scan['id']}",
          f"扫描完成，共 {len(findings)} 项发现（严重 {counts['Critical']}/高危 {counts['High']}）")


_STAGE_FUNCS = {
    "scope_check": _stage_scope_check,
    "recon": _stage_recon,
    "subdomain_enum": _stage_subdomain_enum,
    "web_detect": _stage_web_detect,
    "exploit_verify": _stage_exploit_verify,
    "upload_test": _stage_upload_test,
    "report": _stage_report,
}

_NEXT_STAGE = {
    "init": "scope_check",
    "scope_check": "recon",
    "recon": "subdomain_enum",
    "subdomain_enum": "web_detect",
    "web_detect": "exploit_verify",
    "exploit_verify": "report",
    "upload_test": "report",
}


def process_scan(scan):
    """执行当前阶段的扫描，并记录阶段生命周期事件（I-02 甘特图数据源）。
    任一阶段抛出异常都会被捕获并归类为结构化失败（U-06），避免扫描卡在 running。"""
    sid = scan["id"]
    stage = scan["stage"] or "init"
    if stage == "init":
        update_scan(sid, status="running", started_at=_now(), stage="scope_check")
        stage = "scope_check"
    func = _STAGE_FUNCS.get(stage)
    if not func:
        return

    def _evt(st, stt, note=None):
        # 阶段事件：同时落库（甘特图数据源）与推送前端（P-06 实时进度）。
        record_stage_event(sid, st, stt, note)
        push_scan_event(sid, stage=st, status=stt, note=note)

    _evt(stage, "start")
    try:
        func(scan)
    except Exception as e:
        _evt(stage, "failed", note=str(e)[:500])
        cat, detail = _classify_error(e)
        fail_scan(sid, cat, detail, error_summary=str(e)[:500])
        audit(scan["created_by"], "scan_failed", f"scan#{sid}",
              f"阶段 [{stage}] 异常终止：{cat} - {detail}")
        return
    refreshed = get_scan(sid)
    if refreshed["status"] == "awaiting_review":
        _evt(stage, "paused")
        return
    if refreshed["status"] == "failed":
        _evt(stage, "failed")
        return
    if refreshed["status"] == "completed":
        _evt(stage, "done")
        return
    nxt = _NEXT_STAGE.get(stage)
    if nxt and nxt != stage:
        _evt(stage, "done")
        update_scan(sid, stage=nxt)


def worker_loop(interval=5):
    while True:
        try:
            for scan in pending_scans():
                process_scan(scan)
        except Exception as e:
            try:
                audit("system", "worker_error", "", str(e))
            except Exception:
                pass
        time.sleep(interval)


def scheduler_thread(interval=60):
    """定时/批量调度线程：按间隔检查定时任务，到点则为每个已授权目标批量创建扫描。"""
    while True:
        try:
            scheds = list_schedules()
            now = datetime.datetime.now()
            for sc in scheds:
                if not sc["enabled"]:
                    continue
                last = sc["last_run"]
                due = True
                if last:
                    try:
                        lt = datetime.datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
                        due = (now - lt).total_seconds() >= sc["interval_minutes"] * 60
                    except Exception:
                        due = True
                if due:
                    for tid in [int(x) for x in sc["target_ids"].split(",") if x]:
                        t = get_target(tid)
                        if t and t["status"] == "approved":
                            create_scan(tid, f"[定时]{sc['name']}", "scheduler")
                            audit("scheduler", "scan_create", t["host"],
                                  "定时任务触发 扫描（批量）", "")
                    update_schedule(sc["id"], last_run=now.strftime("%Y-%m-%d %H:%M:%S"))
        except Exception as e:
            try:
                audit("system", "scheduler_error", "", str(e))
            except Exception:
                pass
        time.sleep(interval)
