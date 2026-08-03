"""PenScope —— 前端 JS 桥接口层（无后端模式）

本模块取代原 Flask 后端：以 pywebview 的 js_api 形式暴露给静态前端
（frontend/index.html），前端通过 window.pywebview.api.<方法> 调用本地 Python。
所有方法均为同步函数，返回 JSON 可序列化对象（dict / list）；pywebview 会自动
包装为 Promise。无任何登录 / 会话 / CSRF —— 这是一款纯本地桌面工具，使用者即操作者。

安全设计保留：
- 新增目标必须显式确认"已获授权"（authorized=True）才会被批准可扫描；
- 利用验证 / 上传测试 两个高危阶段仍会暂停，等待使用者在界面点击"批准"才继续
  （复核闸门逻辑见 decide_review）。
"""
import datetime
import json
import logging
import os
import platform
import sys

import config

log = logging.getLogger(__name__)
from db import (
    active_scan_count,
    add_target,
    approve_target,
    archive_scans_before,
    audit,
    audit_heatmap,
    audit_tail,
    clear_audit,
    compare_scans,
    create_scan,
    create_schedule,
    db_stats,
    decide_review,
    delete_audit,
    findings_matrix,
    findings_of,
    findings_page,
    get_baseline,
    get_finding,
    get_scan,
    get_setting,
    get_target,
    list_scans,
    list_schedules,
    list_target_tags,
    list_targets,
    pending_reviews,
    reject_target,
    rescan_diff,
    restore_trash,
    review_of,
    set_finding_cvss,
    set_finding_fix_status,
    set_scan_archived,
    set_setting,
    set_target_tags,
    stage_events,
    trash_scan,
    trash_schedule,
    trash_target,
    update_scan,
    update_schedule,
    update_target,
)
from reports import build_authorization_letter, build_json, build_pdf_report, build_report, build_sarif
from scanner.redact import redact_dict, redact_sensitive
from scanner.vuln_i18n import map_for_lang

_OPERATOR = "analyst"  # 单机使用者标识（无多用户）


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# U-04 统一错误码体系：所有 API 失败响应遵循 {ok, code, error, hint} 信封。
# code 为稳定的机器可读标识，error 为面向用户的错误描述，hint 为可操作建议（可选）。
_ERR_CODES = {
    "E_INVALID": "参数非法或格式错误",
    "E_NOT_FOUND": "请求的资源不存在",
    "E_SCOPE": "操作超出授权范围（作用域围栏）",
    "E_FORBID": "操作被禁止（如目标未授权）",
    "E_BUSY": "资源正忙，无法执行该操作",
    "E_INTERNAL": "服务器内部错误",
}


def _ok(payload=None):
    """成功信封：保留既有返回字段，并补 ok 标记。"""
    if payload is None:
        return {"ok": True}
    if isinstance(payload, dict) and "ok" not in payload:
        payload = dict(payload)
        payload["ok"] = True
    return payload


def _err(code, error, hint=None):
    """失败信封：{ok:False, code, error, hint?}。"""
    return {"ok": False, "code": code, "error": error, "hint": hint}


class Api:
    # ---------------- 应用信息 ----------------
    def app_info(self):
        return _ok({
            "version": getattr(config, "VERSION", "1.0.0"),
            "data_dir": config.BASE_DIR,
            "db_path": config.DB_PATH,
            "python": platform.python_version(),
            "os": platform.system(),
            "gated_stages": list(config.GATED_STAGES.keys()),
        })

    # ---------------- 目标 / 授权 ----------------
    def list_targets(self):
        return list_targets()

    def topology_data(self):
        """F-07：返回全量资产拓扑图数据（目标→子域→端口 + 漏洞链叠加）。
        前端据此用原生 SVG 力导向布局渲染，无需外部 d3 依赖。"""
        from topology import build_topology
        try:
            data = build_topology()
        except Exception as e:  # 拓扑聚合失败不应拖垮页面其它功能
            return _err("E_INTERNAL", "拓扑生成失败", str(e))
        return {"ok": True, "topology": data}

    def add_target(self, host, port_range="common", note="", authorization="", authorized=False, verify_tls=1):
        """新增目标。必须显式确认已获授权（authorized=True），否则拒绝。
        确认后目标直接置为 approved（单机工具，使用者即授权人）。
        verify_tls：是否校验目标 TLS 证书（默认 1 校验；自签证书目标传 0 跳过校验）。"""
        host = (host or "").strip()
        if not host:
            return _err("E_INVALID", "请填写目标主机 / IP", "host 不能为空")
        if not authorized:
            return _err("E_SCOPE", "未确认已获授权：请勾选『我已获得该目标的书面授权』", "发起扫描前需确认已获书面授权")
        authorization = (authorization or "").strip() or "（使用者本地确认已获授权）"
        tid = add_target(host, port_range, note, authorization, _OPERATOR, verify_tls=int(verify_tls))
        # 单机模式：使用者本人即为授权人，确认后直接批准
        approve_target(tid, _OPERATOR)
        audit(_OPERATOR, "target_add", host,
              f"提交并授权目标 {host}（{port_range}），进入可扫描状态", "")
        return {"ok": True, "tid": tid}

    def update_target(self, tid, host, port_range="common", note="", authorization="", verify_tls=None):
        """编辑目标元数据（增删改查之「改」）。verify_tls 为可选（自签证书跳过校验时传 0）。"""
        tid = int(tid)
        host = (host or "").strip()
        if not host:
            return _err("E_INVALID", "请填写目标主机 / IP", "host 不能为空")
        t = get_target(tid)
        if not t:
            return _err("E_NOT_FOUND", "目标不存在")
        vt = int(verify_tls) if verify_tls is not None else None
        update_target(tid, host, port_range, note, authorization, verify_tls=vt)
        audit(_OPERATOR, "target_edit", host, f"编辑目标 #{tid}（{port_range}）", "")
        return {"ok": True}

    def delete_target(self, tid):
        """删除目标（增删改查之「删」）。若有进行中的扫描则拒绝，避免数据悬空。
        U-03：删除前入回收站，返回 undo_token 供 5 秒窗口内撤销。"""
        tid = int(tid)
        t = get_target(tid)
        if not t:
            return _err("E_NOT_FOUND", "目标不存在")
        if active_scan_count(tid) > 0:
            return _err("E_BUSY", "该目标仍有进行中的扫描，请先等待扫描结束或删除相关扫描任务", "请等待进行中的扫描完成，或在『扫描任务』中删除相关任务")
        token = trash_target(tid)
        audit(_OPERATOR, "target_delete", t["host"], f"删除目标 #{tid}（可撤销）", "")
        return _ok({"undo_token": token})

    # ---------------- 目标标签（F-06 资产分组） ----------------
    def list_target_tags(self):
        """返回全部标签及其关联目标数 [{tag, count}]，供目标列表的标签筛选条使用。"""
        return list_target_tags()

    # ---------------- 资产基线（F-05 资产变更告警） ----------------
    def get_target_baseline(self, tid):
        """F-05：返回某目标的资产基线快照（含最近一次变更记录与发生时间）。无基线返回空对象。"""
        tid = int(tid)
        b = get_baseline(tid)
        if not b:
            return {"ok": True, "baseline": None}
        return {"ok": True, "baseline": b}

    # ---------------- 漏洞描述双语映射（U-07） ----------------
    def vuln_i18n_map(self, lang=None):
        """U-07：返回当前语言下的 CWE → {name, remediation} 双语映射，供前端本地化发现展示。
        lang 缺省时取存储的语言设置（get_setting('language')）。"""
        if not lang:
            lang = get_setting("language") or "zh"
        return {"ok": True, "lang": lang, "map": map_for_lang(lang)}

    def set_target_tags(self, tid, tags=None):
        """F-06：覆盖式设置目标标签（资产分组）。tags 为字符串列表（逗号分隔亦可）。
        用于按业务维度（如 生产/测试、Web/API、客户A）对资产分组与筛选。"""
        tid = int(tid)
        t = get_target(tid)
        if not t:
            return _err("E_NOT_FOUND", "目标不存在")
        # 兼容逗号分隔字符串传入
        if isinstance(tags, str):
            tags = [x for x in tags.split(",")]
        clean = set_target_tags(tid, tags)
        audit(_OPERATOR, "target_tags", t["host"], f"更新目标 #{tid} 标签：{clean}", "")
        return _ok({"tags": clean})

    # ---------------- 认证配置 / 会话续期（C-06） ----------------
    # 凭据在本机以 Fernet 加密存储（scanner.vault）；以下接口对前端「永不回传明文密码」，
    # 仅返回 masked 资料（has_password + 用户名 + 登录端点等）。开启会话续期前，使用者须已获得
    # 该目标的书面授权，并理解凭据将以加密形式留存于本机（详见 scanner.vault 安全说明）。
    def set_auth_profile(self, tid, profile):
        """保存某目标的认证配置（会话续期凭据）。密码以加密形式落盘；返回 masked 视图。

        密码留空且已有配置含密码时，保留原密码（便于仅修改其它字段而不重置凭据）。"""
        tid = int(tid)
        t = get_target(tid)
        if not t:
            return _err("E_NOT_FOUND", "目标不存在")
        if not isinstance(profile, dict):
            return _err("E_INVALID", "profile 必须为对象")
        login_url = (profile.get("login_url") or "").strip()
        if not login_url:
            return _err("E_INVALID", "请填写登录端点 URL", "login_url 不能为空")
        try:
            from scanner.vault import VaultError, get_vault, mask_profile
            vault = get_vault()
            method = str(profile.get("method") or "post").lower()
            if method not in ("post", "get"):
                method = "post"
            password = profile.get("password") or ""
            if not isinstance(password, str):
                password = str(password)
            existing = vault.get(tid)
            if (not password) and existing and existing.get("password"):
                password = existing["password"]   # 留空 = 保留原密码
            if not password:
                return _err("E_INVALID", "请填写登录密码（首次保存必须提供）", "password 不能为空")
            extra = profile.get("extra_fields") or []
            extra_clean = []
            if isinstance(extra, list):
                for it in extra[:20]:
                    if isinstance(it, (list, tuple)) and len(it) == 2:
                        extra_clean.append([str(it[0]), str(it[1])])
            try:
                mr = int(profile.get("max_renewals") or 5)
            except (TypeError, ValueError):
                mr = 5
            mr = max(1, min(50, mr))
            clean = {
                "login_url": login_url,
                "method": method,
                "user_field": (profile.get("user_field") or "").strip(),
                "pass_field": (profile.get("pass_field") or "").strip(),
                "username": (profile.get("username") or "").strip(),
                "password": password,
                "extra_fields": extra_clean,
                "csrf_autodetect": bool(profile.get("csrf_autodetect", True)),
                "max_renewals": mr,
            }
            vault.store(tid, clean)
            audit(_OPERATOR, "auth_profile_set", t["host"],
                  "已保存目标认证配置（会话续期凭据，加密存储）", "")
            return {"ok": True, "profile": mask_profile(clean)}
        except Exception as e:
            from scanner.vault import VaultError
            if isinstance(e, VaultError):
                return _err("E_INTERNAL", "保险库不可用", str(e))
            log.warning("保存认证配置失败（非保险库错误）: %s", e)
            return _err("E_INTERNAL", "保存认证配置失败", str(e))

    def get_auth_profile(self, tid):
        """返回某目标的认证配置 masked 视图（不含明文密码）。无配置返回 configured:False。"""
        tid = int(tid)
        t = get_target(tid)
        if not t:
            return _err("E_NOT_FOUND", "目标不存在")
        try:
            from scanner.vault import VaultError, get_vault, mask_profile
            p = get_vault().get(tid)
            return {"ok": True, "profile": mask_profile(p)}
        except VaultError as e:
            return _err("E_INTERNAL", "保险库不可用", str(e))

    def delete_auth_profile(self, tid):
        """删除某目标的认证配置（凭据从保险库移除）。"""
        tid = int(tid)
        t = get_target(tid)
        if not t:
            return _err("E_NOT_FOUND", "目标不存在")
        try:
            from scanner.vault import VaultError, get_vault
            get_vault().delete(tid)
            audit(_OPERATOR, "auth_profile_del", t["host"], "已删除目标认证配置", "")
            return {"ok": True}
        except VaultError as e:
            return _err("E_INTERNAL", "保险库不可用", str(e))

    def list_auth_profiles(self):
        """返回全部已配置认证目标（masked 视图 + 目标 host），供设置/概览展示。"""
        try:
            from scanner.vault import VaultError, get_vault, mask_profile
            out = []
            for tid in get_vault().list():
                tt = get_target(tid)
                p = get_vault().get(tid)
                m = mask_profile(p)
                m["tid"] = tid
                m["host"] = tt["host"] if tt else "?"
                out.append(m)
            return {"ok": True, "profiles": out}
        except VaultError as e:
            return _err("E_INTERNAL", "保险库不可用", str(e))

    def test_auth_profile(self, profile):
        """用给定配置做一次登录尝试，验证凭据是否有效（仅单次尝试，不爆破、不写库）。"""
        if not isinstance(profile, dict):
            return _err("E_INVALID", "profile 必须为对象")
        login_url = (profile.get("login_url") or "").strip()
        if not login_url:
            return _err("E_INVALID", "请填写登录端点 URL", "login_url 不能为空")
        try:
            from scanner.session_renew import SessionRenewal
            ctrl = SessionRenewal(profile, verify_ssl=bool(profile.get("verify_ssl", True)))
            ok = ctrl.login()
            return {"ok": True, "success": ok,
                    "message": ("登录成功，凭据有效" if ok else "登录失败：请检查登录端点 / 字段名 / 凭据")}
        except Exception as e:
            return _err("E_INTERNAL", "登录测试失败", str(e))

    # ---------------- 扫描任务 ----------------
    def list_scans(self, limit=50, include_archived=False):
        return list_scans(limit, include_archived=include_archived)

    def get_scan(self, sid):
        s = get_scan(int(sid))
        return dict(s) if s else None

    def archive_scan(self, sid, archived=1):
        """P-04：单条扫描归档 / 取消归档。"""
        if not get_scan(int(sid)):
            return _err("E_NOT_FOUND", "扫描不存在")
        ok = set_scan_archived(int(sid), int(archived))
        return _ok({"archived": int(archived)}) if ok else _err("E_INTERNAL", "归档失败")

    def archive_scans_before(self, iso_date, target_id=None):
        """P-04：批量归档指定日期之前完成且未归档的扫描，返回归档数量。"""
        if not iso_date:
            return _err("E_INVALID", "必须提供截止日期")
        n = archive_scans_before(str(iso_date), int(target_id) if target_id else None)
        return _ok({"archived_count": n})

    def findings_of(self, sid):
        return findings_of(int(sid))

    def findings_page(self, sid, limit=50, offset=0):
        """P-03：分页返回某扫描的发现，便于大批量发现分批加载。"""
        s = get_scan(int(sid))
        if not s:
            return _err("E_NOT_FOUND", "扫描不存在")
        items, total = findings_page(int(sid), int(limit), int(offset))
        return _ok({"items": items, "total": total, "limit": int(limit), "offset": int(offset)})

    def get_scan_stages(self, sid):
        """I-02：返回该扫描的阶段时间线（甘特图数据源），按标准阶段顺序排列。
        每个阶段给出 start / end（已完成阶段）与 duration_ms；仍在运行的阶段 end 为 null。"""
        _ORDER = ["scope_check", "recon", "subdomain_enum", "web_detect",
                  "exploit_verify", "upload_test", "report"]
        evs = stage_events(int(sid))
        by_stage = {}
        for e in evs:
            by_stage.setdefault(e["stage"], []).append(e)
        stages = []
        for st in _ORDER:
            ev_list = by_stage.get(st)
            if not ev_list:
                continue
            start = ev_list[0]["ts"]
            last = ev_list[-1]
            end = last["ts"] if last["status"] in ("done", "paused", "failed") else None
            dur = None
            if end:
                try:
                    delta = (datetime.datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
                             - datetime.datetime.strptime(start, "%Y-%m-%d %H:%M:%S"))
                    dur = int(delta.total_seconds() * 1000)
                except Exception:
                    dur = None
            stages.append({
                "stage": st, "status": last["status"],
                "start": start, "end": end, "duration_ms": dur,
            })
        return _ok({"stages": stages})

    def create_scan(self, tid, name="手动扫描"):
        t = get_target(int(tid))
        if not t:
            return _err("E_NOT_FOUND", "目标不存在")
        if t["status"] != "approved":
            return _err("E_FORBID", "目标未授权，禁止扫描（授权围栏）", "请先对该目标完成授权审批")
        sid = create_scan(int(tid), name or f"手动扫描 {t['host']}", _OPERATOR)
        audit(_OPERATOR, "scan_create", t["host"], f"创建扫描任务 #{sid}", "")
        return {"ok": True, "sid": sid}

    def delete_scan(self, sid):
        """删除扫描任务及其发现（清理历史）。U-03：返回 undo_token 供撤销。"""
        sid = int(sid)
        s = get_scan(sid)
        if not s:
            return _err("E_NOT_FOUND", "扫描不存在")
        token = trash_scan(sid)
        audit(_OPERATOR, "scan_delete", f"scan#{sid}", "删除扫描任务及其发现（可撤销）", "")
        return _ok({"undo_token": token})

    # ---------------- 人工复核闸门 ----------------
    def list_reviews(self):
        return pending_reviews()

    def decide_review(self, rid, decision):
        """批准 / 拒绝一条复核。
        - add_target 类：批准则批准目标，拒绝则拒绝目标；
        - 扫描类（exploit_verify / upload_test）：批准则放行扫描继续（status->approved），
          拒绝则终止扫描（status->failed）。"""
        r = review_of(int(rid))
        if not r or r["status"] != "pending":
            return _err("E_NOT_FOUND", "该复核已处理或不存在")
        decide_review(int(rid), decision, _OPERATOR)
        if r["kind"] == "add_target":
            if decision == "approve":
                approve_target(r["target_id"], _OPERATOR)
            else:
                reject_target(r["target_id"], _OPERATOR)
            t = get_target(r["target_id"])
            audit(_OPERATOR, "review_add_target", t["host"] if t else "",
                  f"复核决定：{decision}", "")
        else:
            sid = r["scan_id"]
            if decision == "approve":
                update_scan(sid, status="approved")
                audit(_OPERATOR, "gate_approve", f"scan#{sid}",
                      f"批准闸门 [{r['kind']}]，扫描继续", "")
            else:
                s = get_scan(sid)
                note = "使用者拒绝执行该阶段"
                try:
                    import json
                    summ = json.loads(s["summary"] or "{}") if s else {}
                    summ["gate_reject_note"] = note
                    update_scan(sid, status="failed", summary=json.dumps(summ))
                except Exception:
                    update_scan(sid, status="failed")
                audit(_OPERATOR, "gate_reject", f"scan#{sid}",
                      f"拒绝闸门 [{r['kind']}]，扫描终止", "")
        return {"ok": True}

    # ---------------- 定时 / 批量调度 ----------------
    def list_schedules(self):
        return list_schedules()

    def create_schedule(self, name, target_ids, interval_minutes=1440):
        try:
            tids = [int(x) for x in (target_ids or []) if str(x).strip()]
        except Exception:
            return _err("E_INVALID", "目标 ID 格式错误", "target_ids 应为逗号分隔的整数")
        if not name or not tids:
            return _err("E_INVALID", "请填写名称并选择至少一个已授权目标", "name 必填且 target_ids 至少包含一个已授权目标")
        sid = create_schedule(name, tids, int(interval_minutes), _OPERATOR)
        audit(_OPERATOR, "schedule_create", name,
              f"创建定时任务 #{sid}，目标 {tids}，间隔 {interval_minutes} 分钟", "")
        return {"ok": True, "sid": sid}

    def toggle_schedule(self, sid, enabled):
        update_schedule(int(sid), enabled=1 if enabled else 0)
        audit(_OPERATOR, "schedule_toggle", str(sid), f"启用={enabled}", "")
        return {"ok": True}

    def save_schedule(self, sid, name, target_ids, interval_minutes=1440, enabled=1):
        """编辑定时任务（增删改查之「改」）：名称、目标、间隔、启用状态。"""
        try:
            tids = [int(x) for x in (target_ids or []) if str(x).strip()]
        except Exception:
            return _err("E_INVALID", "目标 ID 格式错误", "target_ids 应为逗号分隔的整数")
        if not name or not tids:
            return _err("E_INVALID", "请填写名称并选择至少一个已授权目标", "name 必填且 target_ids 至少包含一个已授权目标")
        try:
            iv = max(1, int(interval_minutes))
        except Exception:
            iv = 1440
        update_schedule(int(sid), name=name, target_ids=",".join(str(t) for t in tids),
                        interval_minutes=iv, enabled=1 if enabled else 0)
        audit(_OPERATOR, "schedule_edit", str(sid), f"编辑定时任务，目标 {tids}，间隔 {iv} 分钟", "")
        return {"ok": True}

    def delete_schedule(self, sid):
        """删除定时任务（增删改查之「删」）。U-03：返回 undo_token 供撤销。"""
        token = trash_schedule(int(sid))
        if token is None:
            return _err("E_NOT_FOUND", "定时任务不存在")
        audit(_OPERATOR, "schedule_delete", str(sid), "删除定时任务（可撤销）", "")
        return _ok({"undo_token": token})

    # ---------------- 审计日志 ----------------
    def audit_tail(self, limit=200):
        return audit_tail(int(limit))

    def clear_audit(self):
        """清空审计日志（增删改查之「清空」）。"""
        n = clear_audit()
        audit(_OPERATOR, "audit_clear", "", f"清空审计日志，共 {n} 条", "")
        return {"ok": True, "count": n}

    def delete_audit(self, aid):
        """删除单条审计日志。"""
        delete_audit(int(aid))
        return {"ok": True}

    # ---------------- 报告 ----------------
    def build_report(self, sid, template=None):
        """返回报告的 HTML 字符串（F-01 多模板：summary/tech/compliance），前端以 iframe(srcdoc) 展示 / 用户另存。"""
        s = get_scan(int(sid))
        if not s:
            return _err("E_NOT_FOUND", "扫描不存在")
        if template not in ("summary", "tech", "compliance"):
            template = get_setting("report_template") or "tech"
        return {"ok": True, "html": build_report(s, template), "template": template}

    def build_pdf_report(self, sid, template=None):
        """尝试生成 PDF 报告；若系统未安装 weasyprint/pdfkit，则返回 html 供前端自行保存。
        F-01：支持 summary/tech/compliance 模板。"""
        s = get_scan(int(sid))
        if not s:
            return _err("E_NOT_FOUND", "扫描不存在")
        if template not in ("summary", "tech", "compliance"):
            template = get_setting("report_template") or "tech"
        pdf_path = build_pdf_report(s, template=template)
        if pdf_path and os.path.exists(pdf_path):
            return {"ok": True, "pdf_path": pdf_path, "template": template}
        return {"ok": True, "html": build_report(s, template), "fallback": True, "template": template,
                "message": "未检测到 PDF 生成库，已返回 HTML 报告，请使用「保存 HTML」或浏览器打印为 PDF。"}

    def build_sarif_report(self, sid):
        """F-04：返回 SARIF 2.1.0 JSON 字符串（兼容 VS Code / GitHub Code Scanning）。"""
        s = get_scan(int(sid))
        if not s:
            return _err("E_NOT_FOUND", "扫描不存在")
        return {"ok": True, "sarif": build_sarif(s)}

    def build_json_report(self, sid):
        """F-04：返回机器可读的标准化 JSON 报告。"""
        s = get_scan(int(sid))
        if not s:
            return _err("E_NOT_FOUND", "扫描不存在")
        return {"ok": True, "json": build_json(s)}

    def authorization_letter(self, target_id):
        """U-10：生成某目标的渗透测试授权书 HTML（自带浅色主题 + 打印优化）。
        前端以 iframe 展示，并提供「保存 HTML」与「打印 / 另存为 PDF」。"""
        t = get_target(int(target_id))
        if not t:
            return _err("E_NOT_FOUND", "目标不存在")
        html = build_authorization_letter(t, _OPERATOR)
        return {"ok": True, "html": html}

    def get_chains(self, sid):
        """C-01：返回该扫描关联出的漏洞利用链（不发起新请求，基于已有发现推理）。"""
        s = get_scan(int(sid))
        if not s:
            return _err("E_NOT_FOUND", "扫描不存在")
        from chain import analyze_chains
        chains = analyze_chains(findings_of(s["id"]))
        return {"ok": True, "chains": chains}

    def set_finding_fix_status(self, fid, status):
        """F-02：更新单条发现的修复状态（open/verifying/fixed/wont_fix）。"""
        ok = set_finding_fix_status(int(fid), status)
        if not ok:
            return _err("E_INVALID", "发现不存在或状态非法（应为 open/verifying/fixed/wont_fix）", "status 取值限于 open / verifying / fixed / wont_fix")
        return {"ok": True}

    def get_finding(self, fid):
        """I-04/I-06：返回单条发现的完整记录（含 evidence_meta / cvss_vector / poc_script），用于详情弹窗。"""
        f = get_finding(int(fid))
        if not f:
            return _err("E_NOT_FOUND", "发现不存在")
        return dict(f)

    def set_finding_cvss(self, fid, score, vector):
        """I-06：保存人工校准后的 CVSS 3.1 评分（0–10）与向量。向量须为合法 CVSS:3.1 基础向量。"""
        try:
            score = float(score)
        except (TypeError, ValueError):
            return _err("E_INVALID", "CVSS 评分必须是 0–10 的数值", "score 应为浮点数，范围 0.0–10.0")
        ok = set_finding_cvss(int(fid), score, str(vector or ""))
        if not ok:
            return _err("E_INVALID", "发现不存在或 CVSS 向量格式非法",
                        "向量须形如 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H（8 个标准度量）")
        return {"ok": True}

    def rescan_diff(self, target_id):
        """F-02：返回同一目标最近两次已完成扫描的修复对比（新增/已解决/持续存在）。"""
        d = rescan_diff(int(target_id))
        if d is None:
            return {"ok": True, "available": False, "diff": None}
        return {"ok": True, "available": True, "diff": d}

    def findings_matrix(self, sid):
        """I-03：返回单扫描的发现矩阵（端点 × 漏洞类型），单元格含最高风险 / 数量 / 代表发现 id。"""
        s = get_scan(int(sid))
        if not s:
            return _err("E_NOT_FOUND", "扫描不存在")
        return _ok(findings_matrix(int(sid)))

    def compare_scans(self, scan_a_id, scan_b_id):
        """F-03：对比任意两次（同目标）扫描，给出新增 / 已解决 / 持续存在（scan_a 作基线）。"""
        d = compare_scans(int(scan_a_id), int(scan_b_id))
        if d is None:
            return {"ok": True, "available": False, "diff": None}
        return {"ok": True, "available": True, "diff": d}

    def undo_delete(self, token):
        """U-03：在 5 秒撤销窗口内还原被删除的目标 / 扫描 / 定时任务。"""
        if restore_trash(token):
            return {"ok": True}
        return _err("E_NOT_FOUND", "撤销已过期或无效（操作无法恢复）", "撤销窗口仅 5 秒，过期后数据已被永久删除")

    # ---------------- 设置 ----------------
    def get_settings(self):
        """返回全部用户设置；缺失项使用默认值。"""
        defaults = {"language": "zh", "theme": "dark", "font_size": "14", "layout": "comfortable",
                    "wizard_done": "0", "report_template": "tech",
                    "enable_auth_probe": "0", "auth_probe_dict": "",
                    "asset_change_alert": "0", "asset_change_notify": "1", "asset_autoscan": "0",
                    "enable_session_renew": "0",
                    "close_behavior": "minimize",
                    "fx_enabled": "1",
                    "bg_particles_enabled": "1", "bg_particle_density": "1.0",
                    "panel_opacity": "0.9"}
        result = dict(defaults)
        for k in defaults:
            v = get_setting(k)
            if v is not None:
                result[k] = v
        return _ok(result)

    def exit_app(self):
        """应用内「退出」按钮：干净地终止整个进程（停托盘 + 销毁窗口 + os._exit）。

        实现委托给 main_gui.exit_app，避免与窗口/托盘生命周期耦合；若导入失败则直接强退。
        """
        try:
            import main_gui
            main_gui.exit_app()
        except Exception:
            import os
            os._exit(0)
        return {"ok": True}

    def set_settings(self, settings):
        """保存用户设置；settings 为 dict。键白名单 + 值校验（font_size 必须为 12-20 整数）。
        wizard_done / report_template 为向导与报告模板偏好，仅作字符串持久化。
        enable_auth_probe 为默认凭据探测开关（"0"/"1"，高危，需书面授权，前端开启时弹闸门确认）；
        auth_probe_dict 为自定义弱口令字典绝对路径（留空用内置，仅启用探测时生效）。
        asset_change_alert / asset_change_notify / asset_autoscan 为 F-05 资产变更告警设置
        （"0"/"1"；asset_change_notify 默认开、其余默认关）。"""
        allowed = {"language", "theme", "font_size", "layout", "wizard_done", "report_template",
                   "enable_auth_probe", "auth_probe_dict",
                   "asset_change_alert", "asset_change_notify", "asset_autoscan",
                   "enable_session_renew",
                   "close_behavior", "fx_enabled",
                   "bg_particles_enabled", "bg_particle_density",
                   "panel_opacity"}
        clean = {}
        for k, v in settings.items():
            if k not in allowed:
                continue
            if k == "font_size":
                # 校验为 12-20 的整数，防止非法值流入前端 CSS（style.setProperty 不执行，
                # 但越界/非数值值会导致样式错乱，属输入卫生加固）
                try:
                    n = int(v)
                except (TypeError, ValueError):
                    return _err("E_INVALID", "font_size 必须为 12-20 的整数", "font_size 取整范围 12-20")
                if not (12 <= n <= 20):
                    return _err("E_INVALID", "font_size 必须在 12-20 之间", "font_size 取整范围 12-20")
                clean[k] = str(n)
            elif k == "report_template":
                clean[k] = str(v) if str(v) in ("summary", "tech", "compliance") else "tech"
            elif k == "wizard_done":
                clean[k] = "1" if str(v) in ("1", "true", "True") else "0"
            elif k == "enable_auth_probe":
                clean[k] = "1" if str(v) in ("1", "true", "True") else "0"
            elif k == "auth_probe_dict":
                s = str(v or "").strip()
                if s:
                    # L-06：弱口令字典路径校验，避免越界读取系统目录或非文件
                    p = os.path.normpath(os.path.abspath(s))
                    if not os.path.isfile(p):
                        return _err("E_INVALID", "弱口令字典路径不存在或不是常规文件", p)
                    _sys_dirs = (r"\windows\system32", r"\windows\syswow64",
                                 r"\windows\systemapps", r"\windows\winxs")
                    if any(seg in p.lower() for seg in _sys_dirs):
                        return _err("E_INVALID", "弱口令字典路径位于受限系统目录", p)
                clean[k] = s
            elif k == "enable_session_renew":
                # C-06：会话续期开关（开启即允许在本机加密存储目标登录凭据并自动重登）
                clean[k] = "1" if str(v) in ("1", "true", "True") else "0"
            elif k in ("asset_change_alert", "asset_change_notify", "asset_autoscan", "fx_enabled"):
                clean[k] = "1" if str(v) in ("1", "true", "True") else "0"
            else:
                clean[k] = str(v)
        for k, v in clean.items():
            set_setting(k, v)
        audit(_OPERATOR, "settings_update", "", json.dumps({k: clean[k] for k in clean}))
        return {"ok": True}

    # ---------------- 运维 / UX（U-05 / U-11 / U-12） ----------------
    def redact_text(self, text):
        """U-12：对一段文本做敏感数据脱敏（供前端在展示证据/响应前先过一遍，或导出前调用）。"""
        if not isinstance(text, str):
            return {"ok": True, "text": text}
        return {"ok": True, "text": redact_sensitive(text)}

    def audit_heatmap(self, days=90):
        """U-11：返回最近 days 天审计操作计数热力数据。"""
        try:
            days = int(days)
        except (TypeError, ValueError):
            days = 90
        if days <= 0 or days > 365:
            days = 90
        return {"ok": True, "heatmap": audit_heatmap(days)}

    def export_diagnostic(self):
        """U-05：一键导出诊断包（JSON）。

        包含版本、运行平台、脱敏后的设置、库统计、近期审计（脱敏），用于报障/排错。
        所有明文凭据字段均已经 redact_dict 处理，不会泄露真实密钥。
        """
        import platform

        settings_keys = ["language", "theme", "font_size", "layout",
                         "wizard_done", "report_template"]
        raw_settings = {k: get_setting(k) for k in settings_keys}
        recent = audit_tail(200)
        redacted_audit = []
        for r in recent:
            redacted_audit.append({
                "id": r.get("id"),
                "ts": r.get("ts"),
                "username": r.get("username"),
                "action": r.get("action"),
                "target": r.get("target"),
                "detail": redact_sensitive(r.get("detail") or ""),
                "ip": r.get("ip"),
            })
        bundle = {
            "product": "PenScope",
            "version": config.VERSION,
            "generated_at": _now(),
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "db_stats": db_stats(),
            "settings": redact_dict({k: (v if v is not None else "") for k, v in raw_settings.items()}),
            "recent_audit": redacted_audit,
            "note": "敏感字段（口令/令牌/私钥/密钥）已脱敏处理。",
        }
        return {"ok": True, "diagnostic": bundle}

    def selftest_report(self, json_str):
        """自检测试桥：接收前端 runSelfTest 产出的 JSON 报告并落盘（仅 --selftest 模式调用，常态无副作用）。"""
        import json as _json
        import os
        try:
            data = _json.loads(json_str)
        except Exception as e:
            return {"ok": False, "error": "invalid json: %s" % e}
        out = os.path.join(os.getcwd(), "selftest_report.json")
        try:
            with open(out, "w", encoding="utf-8") as f:
                _json.dump(data, f, ensure_ascii=False, indent=2)
            return {"ok": True, "path": out}
        except Exception as e:
            return {"ok": False, "error": str(e)}
