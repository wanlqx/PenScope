"""F-08：扫描器插件化框架 —— 抽象基类与受限运行时上下文。

设计目标：让第三方/二次开发者无需改动 run_scans 阶段机即可接入扫描流水线。
插件只需继承 BaseScanner 并实现 scan(ctx)，框架会自动发现并运行它。

ctx（ScanContext）是插件能接触到的**受限**运行时上下文：
- ctx.target：当前 Web 目标信息（含 url / server / title 等）。
- ctx.session：复用主扫描的 requests.Session（共享超时/TLS 配置）。
- ctx.verify_ssl：是否校验 TLS。
- ctx.add_finding(...)：与 db.add_finding 同签名，自动绑定 scan_id。
- ctx.audit(action, target, note)：向审计日志写入一条记录。
插件**不应**直接 import db / run_scans，以保持与主程序解耦、可被独立测试。
"""
from abc import ABC, abstractmethod


class BaseScanner(ABC):
    """所有插件扫描器的抽象基类。

    子类必须实现：
      - name：短标识（英文，唯一，用于日志与去重）。
      - description：一句话说明扫描器用途。
      - scan(self, ctx)：执行扫描，结果通过 ctx.add_finding 上报。
    """

    #: 短标识（英文，唯一）
    name = "unnamed"
    #: 一句话用途说明
    description = ""

    @abstractmethod
    def scan(self, ctx):
        """执行扫描。通过 ctx.add_finding(...) 上报发现，通过 ctx.audit(...) 记录日志。"""
        raise NotImplementedError


class ScanContext:
    """传递给插件扫描器的受限运行时上下文。"""

    def __init__(self, scan_id, target, session, verify_ssl, add_finding, audit, created_by=None):
        self.scan_id = scan_id
        self.target = target            # dict，至少含 "url"，常含 "server"/"title"
        self.session = session
        self.verify_ssl = verify_ssl
        self._add_finding = add_finding
        self._audit = audit
        self._created_by = created_by

    def add_finding(self, category, title, risk, detail, poc, remediation, target_ref,
                    cwe="", endpoint=None, http_method=None,
                    verification_status="unverified", evidence_level="L1", **kwargs):
        """与 db.add_finding 同签名，自动绑定 scan_id。

        输入校验（防御第三方插件传入非法值导致 db 写入异常或前端渲染错乱）：
          - risk 不在 config.RISK_LEVELS 白名单时降级为 "Info"；
          - category / title 为空时静默丢弃（返回 None）并记一条审计告警，
            避免空发现污染列表与报告。run_scans.py 调用插件已有 try/except，本处为内层保险。
        """
        from config import RISK_LEVELS
        if risk not in RISK_LEVELS:
            risk = "Info"
        if not category or not title:
            self.audit(
                "invalid_finding", self.target.get("url", ""),
                f"插件上报了非法发现（category/title 为空）：category={category!r} title={title!r}"
            )
            return None
        return self._add_finding(
            self.scan_id, category, title, risk, detail, poc, remediation, target_ref,
            cwe=cwe, endpoint=endpoint, http_method=http_method,
            verification_status=verification_status, evidence_level=evidence_level, **kwargs)

    def audit(self, action, target, note):
        """向审计日志写入一条记录（自动带上 scan 的 created_by）。"""
        return self._audit(self._created_by, action, target, note)
