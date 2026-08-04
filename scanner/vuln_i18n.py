"""PenScope —— 漏洞描述中英双语映射（U-07）

按 CWE 编号集中维护漏洞「类名」与「修复建议」的中英双语文本，供前端按当前
语言本地化发现展示（类名 / 修复建议）。未命中时回退到后端原始文本，避免任何
字段缺失导致显示空白。

后端报告生成（reports.py）也可通过 localize() 取用同一份映射，保持单一事实源。
"""
# 每条：cwe -> {"name": {zh, en}, "remediation": {zh, en}}
VULN_I18N = {
    "CWE-79": {
        "name": {"zh": "跨站脚本（XSS）", "en": "Cross-site Scripting (XSS)"},
        "remediation": {
            "zh": "对一切用户可控输出做上下文相关编码（HTML / 属性 / JS / URL）；设置内容安全策略（CSP），并对会话 Cookie 启用 HttpOnly。",
            "en": "Contextually encode all user-controlled output (HTML/attribute/JS/URL); set a Content-Security-Policy and mark session cookies HttpOnly.",
        },
    },
    "CWE-89": {
        "name": {"zh": "SQL 注入", "en": "SQL Injection"},
        "remediation": {
            "zh": "一律使用参数化查询 / 预编译语句，禁止字符串拼接 SQL；对必要动态标识做白名单校验，并遵循最小权限数据库账号。",
            "en": "Always use parameterized queries / prepared statements; never concatenate SQL from input. Whitelist any required dynamic identifiers and use least-privilege DB accounts.",
        },
    },
    "CWE-22": {
        "name": {"zh": "路径遍历（任意文件读取）", "en": "Path Traversal (Arbitrary File Read)"},
        "remediation": {
            "zh": "对文件路径做规范化解码后校验是否落在允许根目录内；用白名单限制可接受的文件名，禁止 ../ 与绝对路径。",
            "en": "Canonicalize and confine file paths within an allowed root; whitelist acceptable filenames and reject ../ sequences and absolute paths.",
        },
    },
    "CWE-918": {
        "name": {"zh": "服务端请求伪造（SSRF）", "en": "Server-Side Request Forgery (SSRF)"},
        "remediation": {
            "zh": "对出站请求目标做协议 / 主机白名单与私网/云元数据地址阻断；禁用不必要的 file:// 等非常规协议，启用出口流量监控。",
            "en": "Enforce allowlists and block private/cloud-metadata destinations for outbound requests; disable unnecessary schemes (e.g. file://) and monitor egress.",
        },
    },
    "CWE-601": {
        "name": {"zh": "开放重定向", "en": "Open Redirect"},
        "remediation": {
            "zh": "重定向目标改用内部相对路径或白名单主机；对外跳转型参数做严格校验，禁止将用户可控 URL 直接用于 3xx Location。",
            "en": "Use internal relative paths or an allowlisted host for redirects; strictly validate redirect parameters and never put user-controlled URLs directly into 3xx Location.",
        },
    },
    "CWE-862": {
        "name": {"zh": "缺失授权（越权访问）", "en": "Missing Authorization"},
        "remediation": {
            "zh": "对所有敏感资源与操作实施服务端鉴权与基于角色的访问控制（RBAC）；默认拒绝，并复核隐藏参数（role/admin/uid）带来的越权面。",
            "en": "Enforce server-side authentication and role-based access control on all sensitive resources; deny by default and review privilege-escalation parameters (role/admin/uid).",
        },
    },
    "CWE-287": {
        "name": {"zh": "认证缺陷", "en": "Improper Authentication"},
        "remediation": {
            "zh": "全程使用 HTTPS 传输凭据，启用多因素认证；避免在 URL 查询串中传递令牌/密钥，并对登录端点实施防爆破限速。",
            "en": "Transmit credentials over HTTPS only, enable MFA, avoid passing tokens/secrets in URL query strings, and rate-limit login endpoints against brute force.",
        },
    },
    "CWE-352": {
        "name": {"zh": "跨站请求伪造（CSRF）", "en": "Cross-Site Request Forgery (CSRF)"},
        "remediation": {
            "zh": "为所有状态变更请求引入同源 CSRF Token 并校验；对敏感操作要求重新认证或二次确认，并通过 SameSite=Strict/Lax Cookie 属性与自定义请求头（X-Requested-With）加固。",
            "en": "Issue and verify a same-site CSRF token on all state-changing requests; require re-auth or step-up confirmation for sensitive actions, and harden with SameSite=Strict/Lax cookies and a custom header (X-Requested-With).",
        },
    },
    "CWE-200": {
        "name": {"zh": "敏感信息暴露", "en": "Exposure of Sensitive Information"},
        "remediation": {
            "zh": "收敛详细错误与调试堆栈的对外输出；对含密钥/令牌/个人信息的响应做脱敏，并最小化接口返回字段。",
            "en": "Suppress verbose errors and debug stacks from responses; redact secrets/tokens/PII and minimize returned fields on APIs.",
        },
    },
    "CWE-668": {
        "name": {"zh": "资产暴露", "en": "Exposure of Resource to Wrong Sphere"},
        "remediation": {
            "zh": "此为资产/服务暴露类发现（非直接漏洞）：收敛对外暴露的服务面，仅对必要端口开放并叠加防火墙/访问控制；公网明文邮件端口建议启用隐式 TLS 或强制 STARTTLS。",
            "en": "This is an asset/service-exposure finding (not a directly exploitable vulnerability): reduce the externally reachable attack surface, open only necessary ports with firewall/access control, and enable implicit TLS or enforce STARTTLS on plaintext mail ports.",
        },
    },
    "CWE-693": {
        "name": {"zh": "防护机制失效", "en": "Protection Mechanism Failure"},
        "remediation": {
            "zh": "补全缺失的安全响应头（HSTS、X-Content-Type-Options、X-Frame-Options 等），并定期复核安全基线配置。",
            "en": "Add missing security headers (HSTS, X-Content-Type-Options, X-Frame-Options, etc.) and periodically review the security configuration baseline.",
        },
    },
    "CWE-1035": {
        "name": {"zh": "使用含已知漏洞的组件", "en": "Using Components with Known Vulnerabilities"},
        "remediation": {
            "zh": "将相关组件升级到已修复版本，并接入依赖/组件漏洞扫描与补丁生命周期管理。",
            "en": "Upgrade the affected component to a patched version and adopt dependency/component vulnerability scanning with a patch lifecycle.",
        },
    },
    "CWE-434": {
        "name": {"zh": "危险文件上传", "en": "Unrestricted Upload of Dangerous File"},
        "remediation": {
            "zh": "校验文件类型（白名单 + 魔数）、重命名并存储到非执行目录；对图片等做二次渲染，禁止直接执行上传文件。",
            "en": "Validate file type (allowlist + magic bytes), rename and store outside executable paths, re-render images, and never execute uploaded files.",
        },
    },
    "CWE-319": {
        "name": {"zh": "明文传输敏感信息", "en": "Cleartext Transmission of Sensitive Information"},
        "remediation": {
            "zh": "对承载凭据或敏感数据的通道强制启用 TLS，并配置 HSTS 防止降级到明文。",
            "en": "Enforce TLS on any channel carrying credentials or sensitive data and configure HSTS to prevent cleartext downgrade.",
        },
    },
    "CWE-942": {
        "name": {"zh": "过度许可的跨域资源共享（CORS）", "en": "Permissive Cross-domain Policy (CORS)"},
        "remediation": {
            "zh": "将 Access-Control-Allow-Origin 收敛为明确可信来源，避免配合 Allow-Credentials 使用通配符。",
            "en": "Restrict Access-Control-Allow-Origin to explicit trusted origins and never combine a wildcard with Allow-Credentials.",
        },
    },
    "CWE-209": {
        "name": {"zh": "敏感信息经错误信息泄露", "en": "Generation of Error Message with Sensitive Information"},
        "remediation": {
            "zh": "对外返回通用错误码，将详细堆栈/数据库错误仅记录于服务端日志，不向前端暴露。",
            "en": "Return generic error codes to clients and log detailed stack/database errors server-side only.",
        },
    },
    "CWE-538": {
        "name": {"zh": "文件/目录信息暴露", "en": "Insertion of Sensitive Information into Externally-Accessible File"},
        "remediation": {
            "zh": "移除或禁止公开访问含敏感信息的文件（如备份、配置文件、目录列表），并收紧 Web 根目录权限。",
            "en": "Remove or block public access to sensitive files (backups, configs, listings) and tighten web-root permissions.",
        },
    },
    "CWE-548": {
        "name": {"zh": "目录列表暴露", "en": "Information Exposure Through Directory Listing"},
        "remediation": {
            "zh": "在 Web 服务器关闭目录浏览；对必要下载目录使用索引白名单或鉴权。",
            "en": "Disable directory browsing on the web server; use index allowlists or authentication for required download directories.",
        },
    },
    "CWE-306": {
        "name": {"zh": "缺失身份校验", "en": "Missing Authentication for Critical Function"},
        "remediation": {
            "zh": "对关键功能（数据访问、状态变更）强制身份认证；默认拒绝未认证请求。",
            "en": "Require authentication for critical functions (data access, state changes); deny unauthenticated requests by default.",
        },
    },
    "CWE-650": {
        "name": {"zh": "HTTP 方法滥用", "en": "Trusting HTTP Permission Methods on the Server"},
        "remediation": {
            "zh": "仅开放业务所需 HTTP 方法，禁用不必要的 PUT/DELETE 等状态变更方法，并对方法做服务端校验。",
            "en": "Expose only required HTTP methods, disable unnecessary state-changing methods (PUT/DELETE), and validate methods server-side.",
        },
    },
    "CWE-598": {
        "name": {"zh": "凭据出现在 URL 查询串", "en": "Use of GET Request Method with Sensitive Query Strings"},
        "remediation": {
            "zh": "改用 POST/请求体或标准 Authorization 头传递凭据；避免 Token/Key 经 URL 暴露给历史、日志与 Referer。",
            "en": "Pass credentials via POST bodies or standard Authorization headers instead of URLs to avoid leaking tokens in history, logs, and Referer.",
        },
    },
    "CWE-16": {
        "name": {"zh": "配置缺陷", "en": "Configuration Weakness"},
        "remediation": {
            "zh": "按安全基线复核并加固服务配置（超时、加密套件、默认账号、错误信息等）。",
            "en": "Review and harden service configuration against a security baseline (timeouts, ciphers, default accounts, error verbosity).",
        },
    },
}

_LANGS = ("zh", "en")


def localize(cwe, field, lang, default=""):
    """返回 cwe 在 field(name/remediation) 下 lang 语言文本；缺失回退 default。"""
    if lang not in _LANGS:
        lang = "zh"
    entry = VULN_I18N.get(cwe)
    if not entry:
        return default
    return entry.get(field, {}).get(lang, default)


def map_for_lang(lang):
    """返回 {cwe: {name, remediation}}，仅含该语言有定义的字段（便于前端按语言取用）。"""
    if lang not in _LANGS:
        lang = "zh"
    out = {}
    for cwe, entry in VULN_I18N.items():
        item = {}
        for field in ("name", "remediation"):
            text = entry.get(field, {}).get(lang)
            if text:
                item[field] = text
        if item:
            out[cwe] = item
    return out
