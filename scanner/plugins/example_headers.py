"""F-08 内置示例插件：被动安全响应头检测。

演示第三方扫描器如何借助 BaseScanner 接入流水线：
- 仅做被动 GET 并检查响应头；
- 缺失 HSTS / X-Content-Type-Options 时产出 Info 级发现；
- 零写入、零误报风险，用于验证插件框架端到端可用。
二次开发者可复制本文件结构编写自己的插件，放入 ~/.autopentest/plugins/ 即可启用。
"""
from scanner.plugin_base import BaseScanner

# 期望存在的安全响应头 -> 缺失时的修复建议
_REQUIRED_HEADERS = {
    "Strict-Transport-Security": "启用 HSTS（Strict-Transport-Security）以防止降级攻击与 Cookie 劫持。",
    "X-Content-Type-Options": "设置 X-Content-Type-Options: nosniff 以防止 MIME 嗅探攻击。",
    "X-Frame-Options": "设置 X-Frame-Options 以防止点击劫持（Clickjacking）。",
}


class ExampleSecurityHeadersScanner(BaseScanner):
    name = "example-security-headers"
    description = "被动检测缺失的安全响应头（HSTS / X-Content-Type-Options / X-Frame-Options）"

    def scan(self, ctx):
        url = ctx.target.get("url") or ("http://" + ctx.target.get("host", ""))
        if not url:
            return
        try:
            r = ctx.session.get(url, timeout=8, verify=ctx.verify_ssl, allow_redirects=False)
        except Exception as e:
            ctx.audit("plugin_err", url, f"示例插件请求失败: {e}")
            return
        missing = {h: advice for h, advice in _REQUIRED_HEADERS.items() if h not in r.headers}
        if not missing:
            return
        lines = "\n".join(f"- {h}：{advice}" for h, advice in missing.items())
        ctx.add_finding(
            "安全响应头缺失", f"响应缺少 {len(missing)} 个安全头（{', '.join(missing)}）",
            "Info",
            f"目标响应未包含以下安全响应头：\n{lines}",
            "", lines, url,
            cwe="CWE-693", endpoint=url, http_method="GET",
            verification_status="info", evidence_level="L1",
        )
