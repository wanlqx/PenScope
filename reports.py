"""PenScope —— 渗透测试报告生成
生成包含 CVSS 3.1 评分、漏洞分类、复现步骤、影响范围、修复与预防建议的完整 HTML 报告。
PDF 输出依赖可选库 weasyprint / pdfkit；未安装时返回 html 供浏览器打印保存。
"""
import datetime
import json
import os

from chain import analyze_chains
from config import BASE_DIR, RISK_CN, VERSION
from cvss_dedup import cvss_for
from db import findings_of, get_target

# SARIF 2.1.0 风险等级 → 结果 severity
_SARIF_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Info": "none",
}

_RISK_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_RISK_COLOR = {
    "Critical": "#ff4d4f",
    "High": "#ff7a45",
    "Medium": "#ffc53d",
    "Low": "#52c41a",
    "Info": "#4096ff",
}

# 验证状态 → （标签, 颜色）
_VERIFY_BADGE = {
    "verified": ("已验证", "#52c41a"),
    "unverified": ("待确认", "#ffc53d"),
    "heuristic": ("疑似", "#ffc53d"),
    "pending": ("待验证", "#8b949e"),
    "rejected": ("已排除", "#ff4d4f"),
    "info": ("信息", "#4096ff"),
}


def _verify_badge(status):
    label, color = _VERIFY_BADGE.get((status or "pending"), ("待验证", "#8b949e"))
    return f'<span class="badge" style="background:{color};color:#0f1419">{label}</span>'


def _esc(s):
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def _repro_steps(category, finding, target):
    """按漏洞类型生成从环境准备到利用的完整复现步骤。"""
    ref = finding.get("target_ref") or ""
    detail = finding.get("detail") or ""
    evidence = finding.get("evidence") or ""
    host = target.get("host") if target else "目标主机"

    common_env = (
        "<h4>环境准备</h4><ol>"
        f'<li>确认已获得 {host} 的书面授权，并在授权范围内测试。</li>'
        '<li>准备测试环境：Kali Linux / Parrot OS 或本地 Python + requests 环境。</li>'
        '<li>确保网络可达目标，建议通过 VPN 或授权跳板机访问。</li></ol>'
    )

    if category == "SQL注入":
        return (
            common_env +
            "<h4>复现步骤</h4><ol>"
            f'<li>访问存在注入的端点：<code>{_esc(ref)}</code></li>'
            '<li>在可疑参数（如 <code>id</code> / <code>name</code> / <code>username</code>）中输入单引号 <code>\'</code> 或双引号 <code>"</code>，观察响应是否出现数据库报错。</li>'
            '<li>若报错被屏蔽，尝试时间盲注载荷，例如：<br><code>1 AND (SELECT SLEEP(3) FROM dual)-- </code></li>'
            '<li>对比正常请求与注入请求的响应时间；若延迟 ≈ 3 秒，则确认注入存在。</li>'
            '<li>（仅用于验证，不提取数据）可进一步使用 <code>ORDER BY</code> 或布尔条件判断列数。</li></ol>'
            f'<h4>Payload / 证据</h4><pre>{_esc(evidence or detail)}</pre>'
        )
    if category == "XSS":
        return (
            common_env +
            "<h4>复现步骤</h4><ol>"
            f'<li>定位到可输入点：<code>{_esc(ref)}</code></li>'
            '<li>在输入框或 URL 参数中提交以下 payload：<br><code>&lt;script&gt;alert(document.domain)&lt;/script&gt;</code></li>'
            '<li>提交后观察页面是否弹出 alert 框，或审查元素确认脚本被浏览器解析执行。</li>'
            '<li>尝试更隐蔽的向量，如 <code>&quot;&gt;&lt;svg/onload=alert(1)&gt;</code>，测试不同上下文下的过滤情况。</li></ol>'
            f'<h4>Payload / 证据</h4><pre>{_esc(evidence or detail)}</pre>'
        )
    if category == "CSRF":
        return (
            common_env +
            "<h4>复现步骤</h4><ol>"
            f'<li>抓取目标表单的正常请求：<code>{_esc(ref)}</code>（方法 POST）。</li>'
            '<li>检查表单字段中是否不存在 <code>csrf_token</code> / <code>authenticity_token</code> 等一次性令牌。</li>'
            '<li>构造一个恶意 HTML 页面，包含自动提交的相同表单，并诱导已登录用户访问：</li>'
            '</ol><pre>&lt;form action="' + _esc(ref) + '" method="POST" id="f"&gt;\n'
            '  &lt;input name="敏感字段" value="恶意值"&gt;\n'
            '  &lt;script&gt;document.getElementById("f").submit();&lt;/script&gt;\n'
            '&lt;/form&gt;</pre>'
            '<ol start="4"><li>若用户浏览器已持有目标站点 Cookie 且请求成功执行状态变更，则确认 CSRF 存在。</li></ol>'
        )
    if category == "文件上传":
        return (
            common_env +
            "<h4>复现步骤</h4><ol>"
            f'<li>定位上传入口：<code>{_esc(ref)}</code></li>'
            '<li>准备测试文件（良性）：<code>TEST_autopentest_marker.txt</code>，内容为 <code>AUTOPENTEST_SAFE_MARKER</code>。</li>'
            '<li>通过浏览器或 curl 提交文件，观察返回状态码与上传后文件路径。</li>'
            '<li>尝试修改扩展名 / Content-Type（如 .php → .phtml）绕过前端校验，验证服务端是否严格校验。</li></ol>'
            f'<h4>上传点信息</h4><pre>{_esc(evidence or detail)}</pre>'
        )
    if category == "命令注入":
        return (
            common_env +
            "<h4>复现步骤</h4><ol>"
            f'<li>定位可输入点：<code>{_esc(ref)}</code></li>'
            '<li>在参数中提交含命令替换的差分载荷，如 <code>; echo APCMD_$((123+456))</code> 或 '
            '<code>$(echo APCMD_$((123+456)))</code>：若响应出现计算结果 <code>APCMD_579</code> '
            '（而非字面串 <code>APCMD_$((123+456))</code>），说明命令被真正执行。</li>'
            '<li>确认可利用后，使用时间盲注进一步证明：<code>; sleep 3</code>，若响应延迟约 3 秒则确证命令被执行。</li>'
            '<li>（仅用于验证，不提取数据、不执行破坏性命令）</li></ol>'
            f'<h4>Payload / 证据</h4><pre>{_esc(evidence or detail)}</pre>'
        )
    if category == "API安全":
        return (
            common_env +
            "<h4>复现步骤</h4><ol>"
            f'<li>定位 API 端点：<code>{_esc(ref)}</code></li>'
            '<li>CORS：<code>curl -H "Origin: https://evil.example.com" ' + _esc(ref) + '</code> 观察响应头。</li>'
            '<li>敏感数据：<code>curl ' + _esc(ref) + '</code> 检查响应体是否含明文令牌/密钥。</li>'
            '<li>方法滥用：<code>curl -X OPTIONS ' + _esc(ref) + '</code> 查看 Allow 头是否暴露 PUT/DELETE。</li>'
            '<li>记录越权访问 / 凭据泄露 / 错误详情，按补天平台流程负责任披露。</li></ol>'
            f'<h4>证据</h4><pre>{_esc(evidence or detail)}</pre>'
        )
    if category in ("端口暴露", "资产暴露"):
        return (
            common_env +
            "<h4>复现步骤</h4><ol>"
            f'<li>使用 nmap / nc 扫描目标端口：<code>nmap -sV -p {ref.split(":")[-1] if ":" in ref else "PORT"} {host}</code></li>'
            '<li>观察服务 banner、版本号与默认配置。</li>'
            '<li>在 CVE 数据库检索该版本是否存在公开漏洞。</li></ol>'
            f'<h4>Banner 证据</h4><pre>{_esc(evidence or detail)}</pre>'
        )
    if category == "已知漏洞":
        return (
            common_env +
            "<h4>复现步骤</h4><ol>"
            f'<li>通过 banner/版本识别受影响服务：<code>{_esc(ref)}</code></li>'
            '<li>在 NVD / CVE 数据库检索对应版本漏洞（参考证据中的 CVE 编号）。</li>'
            '<li>在授权范围内使用公开 PoC 或本地搭建的相同版本环境验证可利用性。</li></ol>'
            f'<h4>版本 / CVE 证据</h4><pre>{_esc(evidence or detail)}</pre>'
        )
    if category == "利用验证":
        return (
            common_env +
            "<h4>验证过程</h4><ol>"
            f'<li>对前述发现进行受控复现：<code>{_esc(ref)}</code></li>'
            f'<li>记录验证指标：{_esc(evidence or detail)}</li>'
            '<li>确认漏洞可被利用，但未执行破坏性操作或越权提取敏感数据。</li></ol>'
        )
    if category == "子域资产":
        return (
            common_env +
            "<h4>复现步骤</h4><ol>"
            '<li>被动来源：证书透明度日志（crt.sh）与常见子域 DNS 解析（只读）。</li>'
            f'<li>发现兄弟子域：<code>{_esc(ref)}</code>（解析 IP：{_esc(evidence or "—")}）。</li>'
            '<li>该资产不在本次授权清单内，工具未自动扫描；如需测试，请经二次授权后于「授权目标」'
            '手动添加并审批，再发起扫描（作用域围栏）。</li></ol>'
        )
    if category == "敏感信息泄露":
        return (
            common_env +
            "<h4>复现步骤</h4><ol>"
            f'<li>定位暴露端点：<code>{_esc(ref)}</code></li>'
            '<li>直接请求该 URL：<code>curl ' + _esc(ref) + '</code>，检查响应体是否含内网 IP、'
            '云 AK/SK、JWT、私钥、SQL 报错或调试堆栈。</li>'
            '<li>对疑似真实密钥项，确认是否存在于响应/前端/日志；如属实应立即轮换凭据并修复脱敏。</li></ol>'
            f'<h4>证据</h4><pre>{_esc(evidence or detail)}</pre>'
        )
    if category == "目录暴露":
        return (
            common_env +
            "<h4>复现步骤</h4><ol>"
            f'<li>定位敏感/常见路径：<code>{_esc(ref)}</code></li>'
            '<li>请求该路径：<code>curl -I ' + _esc(ref) + '</code>，观察状态码'
            '（200 可访问 / 403 受限 / 目录列表开启）。</li>'
            '<li>确认是否为遗留调试/备份/版本控制目录，按最小暴露原则处理。</li></ol>'
            f'<h4>证据</h4><pre>{_esc(evidence or detail)}</pre>'
        )
    # 通用
    return (
        common_env +
        "<h4>复现步骤</h4><ol>"
        f'<li>定位受影响组件：<code>{_esc(ref)}</code></li>'
        f'<li>依据以下证据复现异常行为：</li></ol>'
        f'<pre>{_esc(evidence or detail)}</pre>'
    )


def _affected_scope(finding, target):
    """生成受影响系统/服务/端口描述。"""
    host = target.get("host") if target else "未知主机"
    ref = finding.get("target_ref") or ""
    category = finding.get("category") or ""
    port = ""
    if ":" in ref:
        port = ref.rsplit(":", 1)[-1]
    if category in ("端口暴露", "资产暴露"):
        return f"主机 {host} 的 TCP {port} 端口；对外暴露 {finding.get('title', '').split(' ')[-1]} 服务。"
    if category in ("SQL注入", "XSS", "CSRF", "文件上传", "命令注入"):
        return f"主机 {host} 的 Web 应用（URL：{ref}）；涉及前端输入处理与后端业务逻辑。"
    if category == "API安全":
        return f"主机 {host} 的 API 接口（URL：{ref}）；涉及接口鉴权、CORS 与数据暴露控制。"
    if category == "已知漏洞":
        return f"主机 {host} 的受影响服务（{ref}）；版本信息见证据字段。"
    if category == "子域资产":
        return f"域名资产面：发现兄弟子域 {ref}（解析 {finding.get('evidence') or '—'}）；属授权范围外的被动发现。"
    if category in ("敏感信息泄露", "目录暴露"):
        return f"主机 {host} 的 Web 服务（URL：{ref}）；涉及信息暴露与目录访问控制。"
    return f"主机 {host}；参考位置 {ref}。"


def _prevention(category):
    """预防措施（通用加固建议）。"""
    tips = {
        "SQL注入": "采用 ORM / 参数化查询；启用 WAF；对数据库账户最小权限；定期代码审计与渗透测试。",
        "XSS": "默认对输出做 HTML 实体转义；启用 CSP；使用现代框架自动转义；过滤危险 DOM 操作。",
        "CSRF": "所有状态变更请求携带一次性 CSRF Token；校验 Origin/Referer；使用 SameSite=Lax/Strict Cookie。",
        "文件上传": "服务端校验扩展名与 MIME；重命名文件；存储到非执行目录；限制文件大小与类型白名单。",
        "已知漏洞": "建立资产清单与补丁管理流程；订阅厂商安全通告；及时升级存在公开 CVE 的组件。",
        "端口暴露": "关闭非必要端口；使用防火墙/安全组限制源地址；对暴露服务启用认证与加密传输。",
        "资产暴露": "收敛对外暴露的服务面，仅对必要端口开放并叠加防火墙/访问控制；公网明文邮件端口建议启用隐式 TLS 或强制 STARTTLS。",
        "环境指纹": "隐藏 Server 头与版本号；禁用默认页面；统一错误处理，避免信息泄露。",
        "命令注入": "禁止将用户输入拼接到 shell 命令；使用 exec 族/子进程的列表参数（不启用 shell）；"
                    "或彻底避免调用系统命令，改用语言内原生 API；对输入做严格白名单与长度限制。",
        "API安全": "为所有接口实施鉴权与最小权限；CORS 白名单化且不配合凭据返回 '*'；"
                   "响应字段白名单投影并对敏感数据脱敏；统一异常处理避免堆栈泄露；禁用非必要 HTTP 方法。",
        "利用验证": "对高危漏洞优先修复；在测试环境复现验证；建立漏洞闭环管理流程。",
        "子域资产": "维护正式资产清单；对未授权发现的子域，经审批流程确认归属与授权后再纳入测试；"
                    "收敛 DNS 区域传输与证书透明度暴露面（如使用 CDN/CAA 记录限制）。",
        "敏感信息泄露": "禁止在响应/前端/日志回显密钥、令牌与内网拓扑；统一脱敏；生产关闭详细错误；"
                         "对静态资源与备份做访问控制；定期扫描源码与配置泄露。",
        "目录暴露": "将配置/密钥/备份移出 Web 根；关闭目录列表；对管理/调试路径加认证与来源限制；"
                    "移除遗留测试/版本控制目录。",
    }
    return tips.get(category, "遵循最小权限原则；保持组件更新；定期进行安全评估与代码审计。")


# 各漏洞类型 → 合规控制域映射（F-01 合规对照版）。
_COMPLIANCE_MAP = {
    "SQL注入": {"pci": "PCI-DSS v4.0 Req 6.3.1 / 6.3.2（安全编码，防注入）", "mlps": "等保2.0 安全计算环境：入侵防范（8.1.4）/ 访问控制（8.1.3）"},
    "XSS": {"pci": "PCI-DSS v4.0 Req 6.3.1 / 6.4.3（输出编码 / 输入校验）", "mlps": "等保2.0 安全计算环境：入侵防范（8.1.4）"},
    "CSRF": {"pci": "PCI-DSS v4.0 Req 6.3.1（反 CSRF 令牌 / 来源校验）", "mlps": "等保2.0 安全计算环境：访问控制（8.1.3）/ 安全审计（8.1.5）"},
    "文件上传": {"pci": "PCI-DSS v4.0 Req 6.3.2 / 6.5.6（服务端校验与隔离）", "mlps": "等保2.0 安全计算环境：入侵防范（8.1.4）"},
    "命令注入": {"pci": "PCI-DSS v4.0 Req 6.3.1 / 6.3.2（禁止拼接 shell 命令）", "mlps": "等保2.0 安全计算环境：入侵防范（8.1.4）"},
    "API安全": {"pci": "PCI-DSS v4.0 Req 4.2.1 / 6.5（传输加密 / 接口鉴权）", "mlps": "等保2.0 通信网络：通信传输（8.2.2）/ 安全计算环境：访问控制"},
    "敏感信息泄露": {"pci": "PCI-DSS v4.0 Req 3.3 / 3.4（敏感数据保护 / 脱敏）", "mlps": "等保2.0 安全计算环境：数据完整性（8.1.6）/ 保密性（8.1.7）"},
    "已知漏洞": {"pci": "PCI-DSS v4.0 Req 6.3.3 / 11.3（补丁管理 / 漏洞扫描）", "mlps": "等保2.0 安全计算环境：漏洞与风险管理（8.1.2）"},
    "端口暴露": {"pci": "PCI-DSS v4.0 Req 2.2 / 11.2（最小化服务 / 端口扫描）", "mlps": "等保2.0 安全区域边界：边界防护（8.2.1）"},
    "资产暴露": {"pci": "PCI-DSS v4.0 Req 2.2 / 11.2（最小化服务 / 端口扫描）", "mlps": "等保2.0 安全区域边界：边界防护（8.2.1）"},
    "子域资产": {"pci": "PCI-DSS v4.0 Req 11.1（资产发现与监控）", "mlps": "等保2.0 安全运维管理：资产与拓扑（8.3）"},
    "目录暴露": {"pci": "PCI-DSS v4.0 Req 6.3.2 / 6.4.2（移除遗留调试目录）", "mlps": "等保2.0 安全计算环境：访问控制（8.1.3）"},
    "环境指纹": {"pci": "PCI-DSS v4.0 Req 6.3.2（隐藏版本指纹）", "mlps": "等保2.0 安全计算环境：入侵防范（8.1.4）"},
    "利用验证": {"pci": "PCI-DSS v4.0 Req 6.5.1（验证修复有效性）", "mlps": "等保2.0 安全计算环境：入侵防范（8.1.4）"},
}


def _report_shared(scan):
    """提取报告通用数据：目标、发现、风险计数、最高 CVSS。"""
    tid = scan["target_id"]
    target = get_target(tid)
    findings = findings_of(scan["id"])
    summary = {}
    try:
        summary = json.loads(scan["summary"] or "{}")
    except Exception:
        pass
    counts = summary.get("risk_counts", dict.fromkeys(_RISK_ORDER, 0))
    total = summary.get("total_findings", len(findings))
    max_cvss = 0.0
    for f in findings:
        score, _ = cvss_for(f["category"], f["risk"])
        max_cvss = max(max_cvss, score)
    return tid, target, findings, counts, total, max_cvss


def _header_html(scan, target, counts, total, max_cvss):
    """报告头：标题、元信息、整体 CVSS、风险柱状图、验证图例。"""
    bars = "".join(
        f'<div class="stat"><span class="num" style="color:{_RISK_COLOR[lv]}">{counts.get(lv,0)}</span>'
        f'<span class="lbl">{RISK_CN[lv]}</span></div>' for lv in _RISK_ORDER)
    cvss_color = (_RISK_COLOR['Critical'] if max_cvss >= 9 else _RISK_COLOR['High'] if max_cvss >= 7
                  else _RISK_COLOR['Medium'] if max_cvss >= 4 else '#888')
    return f"""<h1>渗透测试报告 #{scan['id']}</h1>
  <div class="sub">目标：{_esc(target['host'] if target else 'N/A')} ｜ 扫描名称：{_esc(scan['name'])} ｜ 执行人：{_esc(scan['created_by'])}</div>
  <div class="meta">状态：{_esc(scan['status'])} ｜ 开始：{_esc(scan.get('started_at') or '-')} ｜ 完成：{_esc(scan.get('finished_at') or '-')}</div>
  <div class="cvss-box"><b>整体最高 CVSS 3.1 评分：</b> <span style="font-size:22px;color:{cvss_color}">{max_cvss}</span>
    <span style="color:#8b949e;margin-left:12px">（基于发现项中最高风险估算）</span></div>
  <div class="summary">{bars}</div>
  <div class="legend">验证状态：<span class="badge" style="background:#52c41a;color:#0f1419">已验证</span> 经探针确认可利用
    ｜ <span class="badge" style="background:#ffc53d;color:#0f1419">待确认</span> 疑似/启发式（需人工复核）
    ｜ <span class="badge" style="background:#4096ff;color:#0f1419">信息</span> 仅信息收集（非漏洞）</div>"""


def _detail_sections(findings, target):
    """F-01 技术详情版：逐漏洞完整复现/修复/PoC 明细。"""
    sections = []
    for idx, f in enumerate(sorted(findings, key=lambda x: _RISK_ORDER.index(x["risk"]) if x["risk"] in _RISK_ORDER else 99), start=1):
        fscore = f.get("cvss_score")
        fvector = f.get("cvss_vector")
        if fscore in (None, ""):
            fscore, fvector = cvss_for(f["category"], f["risk"])
        else:
            fscore = float(fscore)
        color = _RISK_COLOR.get(f["risk"], "#888")
        cwe = f.get("cwe") or ""
        endpoint = f.get("endpoint") or f.get("target_ref") or ""
        method = f.get("http_method") or ""
        poc = f.get("poc_script") or ""
        meta_line = (f'<div class="f-meta">{_verify_badge(f.get("verification_status"))}'
                     + (f'<span class="tag">{_esc(cwe)}</span>' if cwe else "")
                     + (f'<span class="tag">{_esc(method)}</span>' if method else "") + '</div>')
        poc_block = f'<h4>概念验证（PoC）</h4><pre>{_esc(poc)}</pre>' if poc else ""
        endpoint_block = f'<h4>受影响端点 / 位置</h4><p>{_esc(endpoint)}</p>' if endpoint else ""
        sections.append(f"""
        <div class="finding" id="f{idx}">
          <div class="f-head">
            <div><span class="badge" style="background:{color}">{RISK_CN.get(f['risk'], f['risk'])}</span>
              <b>#{idx} {_esc(f['category'])} — {_esc(f['title'])}</b></div>
            <div class="cvss">CVSS 3.1: <b>{fscore}</b> <span class="vector">{_esc(fvector)}</span></div>
          </div>
          <div class="f-body">
            {meta_line}
            <div class="col2">
              <div><h4>漏洞类型</h4><p>{_esc(f['category'])}{('（' + _esc(cwe) + '）') if cwe else ''}</p></div>
              <div><h4>风险等级</h4><p>{RISK_CN.get(f['risk'], f['risk'])}</p></div>
            </div>
            <h4>受影响系统 / 服务 / 端口</h4>
            <p>{_esc(_affected_scope(f, target))}</p>
            {endpoint_block}
            {_repro_steps(f['category'], f, target)}
            {poc_block}
            <h4>修复建议</h4>
            <p>{_esc(f['remediation'])}</p>
            <h4>预防措施</h4>
            <p>{_esc(_prevention(f['category']))}</p>
          </div>
        </div>""")
    return sections


def _chain_section(chains):
    """C-01 漏洞链编排：在报告中渲染关联出的利用链。"""
    if not chains:
        return ""
    rows = ""
    for c in chains:
        step_txt = " → ".join(
            '<span class="tag">%s</span>' % _esc(s["category"]) for s in c["steps"])
        rows += (
            '<div class="finding"><div class="f-head"><div>'
            '<span class="badge" style="background:%s">%s</span>'
            '<b>%s</b></div></div>'
            '<div class="f-body">'
            '<div class="f-meta">%s</div>'
            '<h4>利用路径</h4><p>%s</p>'
            '<h4>风险评估</h4><p>组合利用将单一发现的影响放大；该链聚合风险为 <b>%s</b>，'
            '建议优先处置链路起点（触发类发现）。</p>'
            '</div></div>'
        ) % (_RISK_COLOR.get(c["risk"], "#888"), RISK_CN.get(c["risk"], c["risk"]),
             _esc(c["name"]), step_txt, _esc(c["narrative"]), RISK_CN.get(c["risk"], c["risk"]))
    return ('<h3 style="margin:18px 0 10px;">漏洞利用链（%d 条）</h3>' % len(chains)
            + (rows if rows else ""))


def build_report(scan, template="tech"):
    """生成单个扫描的 HTML 报告字符串。

    template:
      - "tech"       技术详情版（默认）：含 CVSS、复现步骤、影响范围、修复与预防；
      - "summary"    执行摘要版：面向管理者，精简结论、风险概览与修复优先级；
      - "compliance" 合规对照版：将发现映射到 PCI-DSS / 等保 2.0 控制项。
    """
    tid, target, findings, counts, total, max_cvss = _report_shared(scan)
    if template == "summary":
        return _render_summary(scan, target, findings, counts, total, max_cvss)
    if template == "compliance":
        return _render_compliance(scan, target, findings, counts, total, max_cvss)
    return _render_tech(scan, target, findings, counts, total, max_cvss)


def _render_tech(scan, target, findings, counts, total, max_cvss):
    """技术详情版（原完整报告）。"""
    sections = _detail_sections(findings, target)
    chains = analyze_chains(findings)
    toc = ''.join(f'<a href="#f{i}">#{i} {_esc(f["category"])}</a>'
                  for i, f in enumerate(sorted(findings, key=lambda x: _RISK_ORDER.index(x["risk"]) if x["risk"] in _RISK_ORDER else 99), start=1))
    return _wrap(
        f"渗透测试报告 #{scan['id']} - {_esc(target['host'] if target else '')}",
        _header_html(scan, target, counts, total, max_cvss)
        + f'<div class="toc"><b>目录</b>{toc}</div>'
        + _chain_section(chains)
        + f'<h3 style="margin:0 0 14px;">发现明细（共 {total} 项）</h3>'
        + (''.join(sections) if sections else '<p style="color:#8b949e">未发现风险</p>')
        + _compliance_note(scan["id"], scan["target_id"]),
    )


def _render_summary(scan, target, findings, counts, total, max_cvss):
    """执行摘要版：面向管理者，精简结论 + 风险概览表 + Top 修复优先级。"""
    # 按风险排序后取前 5 作为修复优先级
    ranked = sorted(findings, key=lambda x: _RISK_ORDER.index(x["risk"]) if x["risk"] in _RISK_ORDER else 99)
    rows = ""
    for i, f in enumerate(ranked, start=1):
        rows += (f'<tr><td>{i}</td><td>{_esc(f["category"])}</td>'
                 f'<td><span class="badge" style="background:{_RISK_COLOR.get(f["risk"], "#888")}">{RISK_CN.get(f["risk"], f["risk"])}</span></td>'
                 f'<td class="mono">{_esc(f.get("endpoint") or f.get("target_ref") or "")}</td>'
                 f'<td>{_esc((f.get("remediation") or "")[:80])}</td></tr>')
    priority = "".join(
        f'<li><b>#{i} {_esc(f["category"])}（{RISK_CN.get(f["risk"], f["risk"])}）</b>：{_esc(f.get("remediation") or "")}</li>'
        for i, f in enumerate(ranked[:5], start=1)) or '<li>无高危项，继续保持。</li>'
    chains = analyze_chains(findings)
    body = (_header_html(scan, target, counts, total, max_cvss)
            + _chain_section(chains)
            + '<h3 style="margin:18px 0 10px;">风险概览（共 %d 项）</h3>' % total
            + '<table><thead><tr><th>#</th><th>漏洞类型</th><th>风险</th><th>受影响端点</th><th>修复建议</th></tr></thead><tbody>'
            + (rows if rows else '<tr><td colspan="5" class="muted">无发现</td></tr>') + '</tbody></table>'
            + '<h3 style="margin:18px 0 10px;">修复优先级（Top 5）</h3><ol>' + priority + '</ol>'
            + _compliance_note(scan["id"], scan["target_id"]))
    return _wrap(f"渗透测试报告（摘要） #{scan['id']}", body)


def _render_compliance(scan, target, findings, counts, total, max_cvss):
    """合规对照版：将发现映射到 PCI-DSS / 等保 2.0 控制项。"""
    # 聚合：控制域 → 关联发现
    agg = {}
    for f in findings:
        m = _COMPLIANCE_MAP.get(f["category"], {"pci": "—", "mlps": "—"})
        key = (m["pci"], m["mlps"])
        agg.setdefault(key, []).append(f)
    map_rows = ""
    for (pci, mlps), fs in sorted(agg.items(), key=lambda kv: -len(kv[1])):
        cat = ", ".join(sorted({x["category"] for x in fs}))
        map_rows += (f'<tr><td>{_esc(cat)}</td><td>{_esc(pci)}</td><td>{_esc(mlps)}</td>'
                     f'<td style="text-align:center">{len(fs)}</td></tr>')
    # 逐发现明细（含映射）
    detail = ""
    for idx, f in enumerate(sorted(findings, key=lambda x: _RISK_ORDER.index(x["risk"]) if x["risk"] in _RISK_ORDER else 99), start=1):
        m = _COMPLIANCE_MAP.get(f["category"], {"pci": "—", "mlps": "—"})
        detail += (f'<div class="finding"><div class="f-head"><div>'
                   f'<span class="badge" style="background:{_RISK_COLOR.get(f["risk"], "#888")}">{RISK_CN.get(f["risk"], f["risk"])}</span>'
                   f'<b>#{idx} {_esc(f["category"])} — {_esc(f["title"])}</b></div></div>'
                   f'<div class="f-body"><div class="col2">'
                   f'<div><h4>PCI-DSS</h4><p>{_esc(m["pci"])}</p></div>'
                   f'<div><h4>等保 2.0</h4><p>{_esc(m["mlps"])}</p></div></div>'
                   f'<h4>受影响系统 / 服务 / 端口</h4><p>{_esc(_affected_scope(f, target))}</p>'
                   f'<h4>修复建议</h4><p>{_esc(f["remediation"])}</p></div></div>')
    body = (_header_html(scan, target, counts, total, max_cvss)
            + '<h3 style="margin:18px 0 10px;">合规控制项映射</h3>'
            + '<table><thead><tr><th>关联漏洞</th><th>PCI-DSS v4.0</th><th>等保 2.0</th><th>数量</th></tr></thead><tbody>'
            + (map_rows if map_rows else '<tr><td colspan="4" class="muted">无发现</td></tr>') + '</tbody></table>'
            + '<h3 style="margin:18px 0 10px;">发现明细（共 %d 项）</h3>' % total
            + (detail if detail else '<p style="color:#8b949e">未发现风险</p>')
            + _compliance_note(scan["id"], scan["target_id"]))
    return _wrap(f"渗透测试报告（合规） #{scan['id']}", body)


_REPORT_HEAD = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>__TITLE__</title>
<style>
  body{font-family:-apple-system,'Segoe UI',Roboto,'Microsoft YaHei',sans-serif;margin:0;background:#0f1419;color:#e6edf3;padding:32px;}
  h1{font-size:24px;margin:0 0 4px;} .sub{color:#8b949e;margin-bottom:18px;}
  .meta{font-size:12px;color:#8b949e;margin-bottom:8px;}
  .summary{display:flex;gap:12px;margin:18px 0 26px;flex-wrap:wrap;}
  .stat{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px 18px;text-align:center;min-width:84px;}
  .stat .num{display:block;font-size:26px;font-weight:700;} .stat .lbl{font-size:12px;color:#8b949e;}
  .cvss-box{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px 18px;margin-bottom:20px;}
  .legend{margin:0 0 18px;font-size:12px;color:#8b949e;display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
  .finding{background:#161b22;border:1px solid #30363d;border-radius:12px;margin-bottom:18px;overflow:hidden;}
  .f-head{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid #30363d;background:#21262d;}
  .f-body{padding:16px 18px;line-height:1.7;}
  .f-body h4{margin:16px 0 6px;font-size:14px;color:#c9d1d9;}
  .f-body p{margin:4px 0 10px;color:#b0b8c4;}
  .col2{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
  pre{background:#0d1117;padding:10px 12px;border-radius:8px;color:#7ee787;font-size:12px;overflow:auto;white-space:pre-wrap;word-break:break-word;}
  code{background:#0d1117;padding:2px 6px;border-radius:4px;color:#7ee787;font-size:12px;}
  .badge{color:#0f1419;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:700;margin-right:8px;}
  .f-meta{margin:6px 0 2px;display:flex;gap:8px;flex-wrap:wrap;}
  .finding .tag{display:inline-block;background:#30363d;color:#c9d1d9;padding:1px 8px;border-radius:10px;font-size:12px;}
  .cvss{font-size:13px;color:#b0b8c4;} .cvss b{font-size:18px;color:#ff7a45;}
  .vector{font-family:ui-monospace,Consolas,monospace;color:#8b949e;}
  table{width:100%;border-collapse:collapse;background:#161b22;border-radius:10px;overflow:hidden;margin-top:14px;}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #30363d;font-size:13px;vertical-align:top;}
  th{background:#21262d;color:#c9d1d9;}
  .note{margin-top:26px;padding:14px;background:#161b22;border-left:3px solid #4096ff;border-radius:6px;font-size:13px;color:#8b949e;}
  .toc{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px 18px;margin-bottom:20px;}
  .toc a{color:#8b949e;display:block;margin:4px 0;}
  @media print{body{background:#fff;color:#000;} .finding,.stat,.cvss-box,.toc,.note{border-color:#ccc;}}
</style></head><body>
"""
_REPORT_TAIL = "</body></html>"


def _wrap(title, body):
    """拼接报告 HTML（使用占位符替换，避免 % 格式化与正文内容冲突）。"""
    return _REPORT_HEAD.replace("__TITLE__", title) + body + _REPORT_TAIL


def _compliance_note(scan_id, target_id):
    return f"""  <div class="note">
    <b>授权与合规声明：</b>本报告仅针对已通过授权审批的目标（编号 #{target_id}）在授权范围内执行，所有利用验证动作均经安全分析员人工复核批准。
    检测与验证均为只读或良性探针，未对目标系统进行破坏性操作。报告内容含敏感安全信息，请按最小知悉原则保管。
  </div>"""


def build_pdf_report(scan, out_path=None, template="tech"):
    """若系统已安装 weasyprint / pdfkit，则生成 PDF 并返回路径；否则返回 None。
    调用方应优先使用 build_report 的 HTML，并引导用户通过浏览器打印保存 PDF。"""
    html = build_report(scan, template)
    if out_path is None:
        out_path = os.path.join(BASE_DIR, f"autopentest_report_{scan['id']}.pdf")
    try:
        import weasyprint
        weasyprint.HTML(string=html).write_pdf(out_path)
        return out_path
    except Exception:
        pass
    try:
        import pdfkit
        pdfkit.from_string(html, out_path)
        return out_path
    except Exception:
        pass
    return None


def build_sarif(scan):
    """生成 SARIF 2.1.0 JSON（兼容 VS Code / GitHub Code Scanning）。

    每个发现映射为一条 result：ruleId 取 CWE（无则取漏洞类别），level 由风险等级决定，
    message 含标题与修复建议，locations.physicalLocation.artifactLocation.uri 指向
    endpoint / target_ref / 主机。properties 中保留 risk/cvss/cwe/verification 等结构化字段。
    """
    tid, target, findings, counts, total, max_cvss = _report_shared(scan)
    host = target.get("host") if target else "unknown"

    rule_index = {}
    rules = []
    results = []
    for f in findings:
        cat = f.get("category") or "未知漏洞"
        cwe = f.get("cwe") or ""
        rid = cwe if cwe else cat
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append({
                "id": rid,
                "name": cat,
                "shortDescription": {"text": ("%s（%s）" % (cat, cwe)) if cwe else cat},
                "fullDescription": {"text": _esc(f.get("title") or cat)},
                "properties": {"category": cat, "cwe": cwe},
            })
        score, vector = cvss_for(f["category"], f["risk"])
        level = _SARIF_LEVEL.get(f["risk"], "warning")
        uri = f.get("endpoint") or f.get("target_ref") or host
        msg = f.get("title") or cat
        results.append({
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": level,
            "message": {"text": "%s\n修复建议：%s" % (msg, f.get("remediation") or "")},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": uri}},
            }],
            "properties": {
                "risk": f["risk"],
                "cvss": score,
                "cvssVector": vector,
                "cwe": cwe,
                "category": cat,
                "verification": f.get("verification_status") or "pending",
                "host": host,
            },
        })

    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PenScope",
                    "version": VERSION,
                    "informationUri": "https://github.com/autopentest/autopentest-ai",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {
                "scanId": scan["id"],
                "targetId": tid,
                "targetHost": host,
                "maxCvss": max_cvss,
                "riskCounts": counts,
                "totalFindings": total,
            },
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


def build_json(scan):
    """生成机器可读的 JSON 报告（标准化结构，供下游平台 / API / SIEM 消费）。"""
    tid, target, findings, counts, total, max_cvss = _report_shared(scan)
    host = target.get("host") if target else "unknown"
    items = []
    for f in findings:
        score, vector = cvss_for(f["category"], f["risk"])
        items.append({
            "id": f.get("id"),
            "category": f.get("category"),
            "cwe": f.get("cwe") or "",
            "title": f.get("title"),
            "risk": f["risk"],
            "cvss": {"score": score, "vector": vector},
            "endpoint": f.get("endpoint") or f.get("target_ref") or "",
            "httpMethod": f.get("http_method") or "",
            "verification": f.get("verification_status") or "pending",
            "detail": f.get("detail") or "",
            "evidence": f.get("evidence") or "",
            "poc": f.get("poc_script") or "",
            "remediation": f.get("remediation") or "",
            "affectedScope": _affected_scope(f, target),
        })
    doc = {
        "tool": "PenScope",
        "schemaVersion": "1.0",
        "generatedBy": VERSION,
        "scan": {
            "id": scan["id"],
            "name": scan.get("name"),
            "targetId": tid,
            "targetHost": host,
            "status": scan.get("status"),
            "createdBy": scan.get("created_by"),
            "startedAt": scan.get("started_at"),
            "finishedAt": scan.get("finished_at"),
        },
        "summary": {
            "totalFindings": total,
            "riskCounts": counts,
            "maxCvss": max_cvss,
        },
        "chains": analyze_chains(findings),
        "findings": items,
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


def build_authorization_letter(target, operator, date_str=None):
    """U-10：生成渗透测试授权书（Authorization Letter）的 HTML 文档（自带浅色主题 + 打印优化）。

    target：db.get_target 返回的目标 dict（含 host / port_range / authorization / note）。
    operator：执行方标识（本机使用者）。
    返回可直接嵌入 iframe(srcdoc) 或另存为 HTML 再由浏览器「打印 → 另存为 PDF」的完整 HTML 字符串。
    """
    if date_str is None:
        date_str = datetime.date.today().strftime("%Y-%m-%d")
    host = _esc(target.get("host") or "")
    ports = _esc(target.get("port_range") or "common")
    ref = _esc(target.get("authorization") or "—")
    note = _esc(target.get("note") or "")
    operator = _esc(operator or "analyst")

    body = (
        '<h1>渗透测试授权书</h1>'
        '<div class="sub-en">Penetration Testing Authorization Letter</div>'
        '<table class="meta">'
        '<tr><th>文档编号 / Ref</th><td>' + ref + '</td></tr>'
        '<tr><th>签发日期 / Date</th><td>' + _esc(date_str) + '</td></tr>'
        '<tr><th>委托方（资产所有者）/ Client</th><td>________________________（请填写）</td></tr>'
        '<tr><th>执行方 / Tester</th><td>PenScope（' + operator + '）</td></tr>'
        '<tr><th>测试目标 / Scope</th><td>主机 / IP：<code>' + host + '</code>；端口范围：<code>' + ports + '</code></td></tr>'
        '</table>'

        '<h2>一、授权范围 / Authorized Scope</h2>'
        '<p>委托方在此确认已拥有对上述目标（<code>' + host + '</code>）的合法所有权或书面授权，'
        '并明确授权 PenScope 在所列端口与协议范围内，于授权时间内对该目标实施<strong>自动化渗透测试</strong>。'
        '本次测试仅覆盖上述明确列出的资产，任何未列明的资产（含子域、同网段其他主机）均不在授权范围内。</p>'

        '<h2>二、允许与禁止的动作 / Permitted &amp; Prohibited</h2>'
        '<ul>'
        '<li>允许：被动信息收集、漏洞探测与<strong>只读 / 良性</strong>的利用验证（如时间盲注判定、反射型验证、良性标记文件上传）。</li>'
        '<li>禁止：任何破坏性操作、数据提取、拒绝服务（DoS）测试、权限提升后的横向移动，或超出授权范围的任何动作。</li>'
        '<li>涉及真实利用验证、文件上传等高危动作，须由委托方在复核闸门中<strong>逐项显式批准</strong>后方可执行。</li>'
        '</ul>'

        '<h2>三、双方责任与声明 / Responsibilities</h2>'
        '<ul>'
        '<li>执行方承诺仅在授权范围内测试，对测试过程中接触到的任何敏感信息严格保密，并依据最小知悉原则保管测试产出（含报告、证据）。</li>'
        '<li>委托方承诺目标系统为其合法所有或已获授权，并已在测试前完成必要的备份与业务影响评估。</li>'
        '<li>本授权书仅用于合法的安全评估目的；任何超出本授权范围的测试行为，执行方概不负责。</li>'
        '</ul>'

        '<h2>四、有效期 / Validity</h2>'
        '<p>本授权书自签发之日起 <strong>30 个自然日</strong>内有效，逾期须重新签署。超过有效期或超出上述范围的测试视为未授权。</p>'

        '<h2>五、签署 / Signatures</h2>'
        '<table class="sign">'
        '<tr><th>委托方（资产所有者）</th><th>执行方（PenScope）</th></tr>'
        '<tr><td><div class="line">签字 / Signature：____________________</div>'
        '<div class="line">姓名 / Name：____________________</div>'
        '<div class="line">日期 / Date：____________________</div></td>'
        '<td><div class="line">工具 / Tool：PenScope v' + _esc(VERSION) + '</div>'
        '<div class="line">操作人 / Operator：' + operator + '</div>'
        '<div class="line">日期 / Date：' + _esc(date_str) + '</div></td></tr>'
        '</table>'

        '<p class="note">本授权书由 PenScope 自动生成，作为测试合法性的书面凭证，请与测试报告一并归档保存。'
        + (('目标备注：' + note) if note else '') + '</p>'
    )
    return _wrap_letter(body)


def _wrap_letter(body):
    """授权书专用包裹：浅色文档主题 + 打印优化（与报告主题解耦，便于直接打印 / 另存 PDF）。"""
    head = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>渗透测试授权书 / Authorization Letter</title>
<style>
  body{font-family:-apple-system,'Segoe UI',Roboto,'Microsoft YaHei',sans-serif;margin:0;background:#fff;color:#1a1a1a;padding:40px;line-height:1.7;}
  h1{font-size:26px;text-align:center;margin:0 0 4px;}
  .sub-en{text-align:center;color:#666;font-size:13px;margin-bottom:24px;}
  h2{font-size:16px;margin:22px 0 8px;border-left:4px solid #2563eb;padding-left:10px;}
  p,li{font-size:14px;color:#222;}
  code{background:#f1f5f9;padding:2px 6px;border-radius:4px;font-size:13px;}
  table.meta{width:100%;border-collapse:collapse;margin:8px 0 4px;}
  table.meta th{text-align:left;width:220px;background:#f8fafc;border:1px solid #e2e8f0;padding:8px 10px;font-size:13px;vertical-align:top;}
  table.meta td{border:1px solid #e2e8f0;padding:8px 10px;font-size:13px;}
  table.sign{width:100%;border-collapse:collapse;margin-top:10px;}
  table.sign th{border:1px solid #e2e8f0;background:#f8fafc;padding:8px 10px;font-size:13px;}
  table.sign td{border:1px solid #e2e8f0;padding:10px;font-size:13px;vertical-align:top;width:50%;}
  .line{margin:10px 0;}
  .note{margin-top:24px;padding:12px;background:#f8fafc;border-left:3px solid #2563eb;border-radius:6px;font-size:13px;color:#555;}
  @media print{body{padding:18mm;} h1,h2{break-after:avoid;}}
</style></head><body>
"""
    return head + body + "</body></html>"


def save_machine_report(scan, fmt, out_path=None):
    """将 SARIF / JSON 报告写入磁盘并返回路径；fmt ∈ {'sarif','json'}。"""
    if fmt not in ("sarif", "json"):
        raise ValueError("fmt must be 'sarif' or 'json'")
    content = build_sarif(scan) if fmt == "sarif" else build_json(scan)
    if out_path is None:
        ext = "sarif.json" if fmt == "sarif" else "json"
        out_path = os.path.join(BASE_DIR, "autopentest_report_%s_%s" % (scan["id"], ext))
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return out_path
