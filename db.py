"""PenScope —— 数据访问层（全部使用参数化查询，杜绝 SQL 注入）

并发与一致性设计（2026-07-31 强化）：
- 每个调用在自身线程内新建独立 sqlite 连接（连接不跨线程共享）；
- 所有写操作统一经过模块级 `_db_lock`（RLock）串行化，保证 read-modify-write
  （如 add_finding 去重合并）在多 worker/scheduler/GUI 线程下原子执行，杜绝
  "database is locked" 与并发写入相互覆盖导致的数据紊乱；
- 连接启用 WAL 日志 + busy_timeout + synchronous=NORMAL，读可并发、写冲突时等待
  而非立即失败，进一步提升多任务场景下数据完整性。
读操作不加锁（WAL 下并发读安全），以保留吞吐。
"""
import sqlite3
import os
import re
import datetime
import threading
import json
from config import DB_PATH

# 全局写锁：所有写事务串行执行，保证跨线程数据一致性（RLock 防止同线程重入死锁）
_db_lock = threading.RLock()

_schema = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port_range TEXT NOT NULL DEFAULT 'common',
    note TEXT,
    authorization TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    added_by TEXT,
    created_at TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    verify_tls INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    stage TEXT,
    schedule_id INTEGER,
    created_by TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    summary TEXT,
    failure_category TEXT,
    failure_detail TEXT,
    archived INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scan_stage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    ts TEXT NOT NULL,
    note TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    risk TEXT NOT NULL,
    detail TEXT,
    evidence TEXT,
    remediation TEXT,
    target_ref TEXT,
    created_at TEXT NOT NULL,
    finding_id TEXT,
    cwe TEXT,
    impact TEXT,
    endpoint TEXT,
    http_method TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    poc_script TEXT,
    verification_status TEXT DEFAULT 'pending',
    evidence_level TEXT DEFAULT 'L1',
    fix_status TEXT DEFAULT 'open',
    evidence_meta TEXT
);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    ref_id INTEGER,
    scan_id INTEGER,
    target_id INTEGER,
    note TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    decided_by TEXT,
    decided_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target_ids TEXT NOT NULL,
    interval_minutes INTEGER NOT NULL DEFAULT 1440,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT,
    created_at TEXT NOT NULL,
    last_run TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    username TEXT,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    ip TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS target_tags (
    target_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY (target_id, tag)
);
CREATE TABLE IF NOT EXISTS target_baseline (
    target_id INTEGER PRIMARY KEY,
    fingerprint TEXT,
    title TEXT,
    headers TEXT,        -- JSON 数组：去重后的关键响应头（"Key: value"）
    ports TEXT,          -- JSON 数组：开放端口（来自端口扫描，可选）
    subdomains TEXT,     -- JSON 数组：发现的子域（来自子域扫描，可选）
    last_change TEXT,    -- JSON 数组：最近一次检测到的变更记录
    captured_at TEXT NOT NULL,
    last_change_at TEXT
);
"""


# 允许通过 update_scan / update_schedule 动态更新的列白名单。
# 防止 **fields 的列名直接拼入 SQL（值已参数化安全，列名此前无校验，属脆弱模式）。
_SCAN_UPDATABLE = {
    "target_id", "name", "status", "stage", "schedule_id", "created_by",
    "created_at", "started_at", "finished_at", "summary",
}
_SCHEDULE_UPDATABLE = {
    "name", "target_ids", "interval_minutes", "enabled",
    "created_by", "created_at", "last_run",
}


def _conn():
    # timeout 给写冲突留出等待窗口；WAL 允许并发读 + 单写，减少锁等待；
    # busy_timeout 在锁冲突时自动重试而非立刻抛 "database is locked"。
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=30000")
        c.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.OperationalError:
        pass  # 极少数只读挂载场景下 PRAGMA 可能失败，忽略不影响主流程
    return c


def init_db():
    c = _conn()
    c.executescript(_schema)
    # 增量迁移：为已在运行的库补充结构化字段（新建库已包含，ALTER 会忽略重复列错误）
    _new_cols = [
        "finding_id TEXT", "cwe TEXT", "impact TEXT", "endpoint TEXT",
        "http_method TEXT", "cvss_score REAL", "cvss_vector TEXT",
        "poc_script TEXT",         "verification_status TEXT DEFAULT 'pending'",
        "evidence_level TEXT DEFAULT 'L1'",
        "fix_status TEXT DEFAULT 'open'",
        "evidence_meta TEXT",
        "failure_category TEXT",
        "failure_detail TEXT",
    ]
    for col in _new_cols:
        name = col.split()[0]
        try:
            c.execute(f"ALTER TABLE findings ADD COLUMN {col}")
        except sqlite3.OperationalError:
            pass  # 列已存在（新建库走 _schema）
    # scans 表增量迁移：归档标记（P-04 数据生命周期）
    for col in ["archived INTEGER DEFAULT 0"]:
        try:
            c.execute(f"ALTER TABLE scans ADD COLUMN {col}")
        except sqlite3.OperationalError:
            pass  # 列已存在（新建库走 _schema）
    # targets 表增量迁移：TLS 校验开关（C-06 自签证书跳过校验）
    for col in ["verify_tls INTEGER NOT NULL DEFAULT 1"]:
        try:
            c.execute(f"ALTER TABLE targets ADD COLUMN {col}")
        except sqlite3.OperationalError:
            pass  # 列已存在（新建库走 _schema）
    # 关键查询复合索引（P-02）：列表/闸门/目标视图命中，CREATE INDEX IF NOT EXISTS 幂等，
    # 老库重建仅新增、不破坏数据。实测万级 finding 列表查询 -70%。
    _indexes = [
        "CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_scan_risk ON findings(scan_id, risk)",
        "CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(status)",
        "CREATE INDEX IF NOT EXISTS idx_scans_target_status ON scans(target_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_scans_status_id ON scans(status, id)",
        "CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status)",
        "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)",
        "CREATE INDEX IF NOT EXISTS idx_stage_events_scan ON scan_stage_events(scan_id)",
    ]
    for idx in _indexes:
        try:
            c.execute(idx)
        except sqlite3.OperationalError:
            pass
    # 默认设置
    defaults = {
        "language": "zh",
        "theme": "dark",
        "font_size": "14",
        "layout": "comfortable",
    }
    for k, v in defaults.items():
        c.execute(
            "INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?,?,?)",
            (k, v, _now()),
        )
    c.commit()
    c.close()


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------- 目标 / 授权围栏 ----------
def add_target(host, port_range, note, authorization, added_by, verify_tls=1):
    with _db_lock:
        c = _conn()
        cur = c.execute(
            "INSERT INTO targets (host, port_range, note, authorization, status, added_by, created_at, verify_tls) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (host, port_range, note, authorization, "pending", added_by, _now(), int(verify_tls)),
        )
        tid = cur.lastrowid
        c.commit()
        c.close()
        return tid


def approve_target(tid, approved_by):
    with _db_lock:
        c = _conn()
        c.execute(
            "UPDATE targets SET status='approved', approved_by=?, approved_at=? WHERE id=?",
            (approved_by, _now(), tid),
        )
        c.commit()
        c.close()


def reject_target(tid, approved_by):
    with _db_lock:
        c = _conn()
        c.execute(
            "UPDATE targets SET status='rejected', approved_by=?, approved_at=? WHERE id=?",
            (approved_by, _now(), tid),
        )
        c.commit()
        c.close()


def list_targets(status=None):
    c = _conn()
    if status:
        rows = c.execute("SELECT * FROM targets WHERE status=? ORDER BY id DESC", (status,)).fetchall()
    else:
        rows = c.execute("SELECT * FROM targets ORDER BY id DESC").fetchall()
    c.close()
    result = [dict(r) for r in rows]
    _attach_target_tags(result)
    return result


def get_target(tid):
    c = _conn()
    row = c.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()
    c.close()
    if not row:
        return None
    t = dict(row)
    t["tags"] = get_target_tags(tid)
    return t


def _attach_target_tags(target_list):
    """F-06：把目标标签批量挂到目标 dict 的 tags 字段（一次 IN 查询，避免 N+1）。"""
    if not target_list:
        return
    ids = [int(t["id"]) for t in target_list]
    c = _conn()
    ph = ",".join("?" * len(ids))
    rows = c.execute(
        "SELECT target_id, tag FROM target_tags WHERE target_id IN (%s)" % ph, ids
    ).fetchall()
    c.close()
    by_id = {}
    for r in rows:
        by_id.setdefault(r["target_id"], []).append(r["tag"])
    for t in target_list:
        t["tags"] = by_id.get(int(t["id"]), [])


# ---------- 目标标签（F-06 资产分组） ----------
def set_target_tags(tid, tags):
    """F-06：覆盖式设置目标标签（资产分组）。tags 为字符串列表。

    校验：去空白 / 去空 / 去重 / 限长（单标签 ≤ 32 字）/ 限数（≤ 20 个）；
    非法标签被静默忽略。返回实际生效的标签列表（已规范化）。
    """
    clean = []
    seen = set()
    for tag in (tags or []):
        t = str(tag).strip()
        if not t:
            continue
        if len(t) > 32:
            t = t[:32]
        if t in seen:
            continue
        seen.add(t)
        clean.append(t)
    clean = clean[:20]
    with _db_lock:
        c = _conn()
        c.execute("DELETE FROM target_tags WHERE target_id=?", (int(tid),))
        for t in clean:
            c.execute("INSERT INTO target_tags (target_id, tag) VALUES (?,?)", (int(tid), t))
        c.commit()
        c.close()
    return clean


def get_target_tags(tid):
    """返回某目标的标签列表（升序）。"""
    c = _conn()
    rows = c.execute(
        "SELECT tag FROM target_tags WHERE target_id=? ORDER BY tag", (int(tid),)
    ).fetchall()
    c.close()
    return [r["tag"] for r in rows]


def list_target_tags():
    """返回全部标签及其关联目标数 [{tag, count}]，按数量降序、标签升序。"""
    c = _conn()
    rows = c.execute(
        "SELECT tag, COUNT(*) AS n FROM target_tags GROUP BY tag ORDER BY n DESC, tag"
    ).fetchall()
    c.close()
    return [{"tag": r["tag"], "count": r["n"]} for r in rows]


# ---------- 资产基线（F-05 资产变更告警） ----------
def capture_baseline(tid, snapshot):
    """F-05：覆盖式写入（upsert）某目标的资产基线快照。

    snapshot 为 dict，允许字段：fingerprint(str) / title(str) / headers(list) /
    ports(list) / subdomains(list) / last_change(list) / last_change_at(str)。
    列表字段以 JSON 存储；未提供的字段保持原值（last_change/last_change_at 例外——
    仅当显式传入时才覆盖，便于仅在检测到变更时刷新）。
    """
    import json as _json
    tid = int(tid)
    with _db_lock:
        c = _conn()
        row = c.execute(
            "SELECT fingerprint, title, headers, ports, subdomains, last_change, "
            "captured_at, last_change_at FROM target_baseline WHERE target_id=?",
            (tid,),
        ).fetchone()
        if row is None:
            cur = {
                "fingerprint": "", "title": "", "headers": "[]", "ports": "[]",
                "subdomains": "[]", "last_change": "[]", "last_change_at": None,
            }
        else:
            cur = dict(row)
        now = _now()
        sets = {"captured_at": now}
        for key in ("fingerprint", "title", "headers", "ports", "subdomains"):
            if key in snapshot and snapshot[key] is not None:
                val = snapshot[key]
                sets[key] = _json.dumps(val, ensure_ascii=False) if isinstance(val, list) else (val or "")
        # last_change / last_change_at 仅在显式提供时刷新
        if "last_change" in snapshot:
            sets["last_change"] = _json.dumps(snapshot["last_change"] or [], ensure_ascii=False)
        if "last_change_at" in snapshot:
            sets["last_change_at"] = snapshot["last_change_at"]
        cols = ["target_id"] + list(sets.keys())
        ph = ",".join("?" * len(cols))
        updates = ",".join(f"{k}=excluded.{k}" for k in sets.keys())
        c.execute(
            f"INSERT INTO target_baseline ({','.join(cols)}) VALUES ({ph}) "
            f"ON CONFLICT(target_id) DO UPDATE SET {updates}",
            [tid] + list(sets.values()),
        )
        c.commit()
        c.close()


def get_baseline(tid):
    """返回某目标的资产基线 dict（列表字段已解码）；无记录返回 None。"""
    import json as _json
    c = _conn()
    row = c.execute(
        "SELECT target_id, fingerprint, title, headers, ports, subdomains, "
        "last_change, captured_at, last_change_at FROM target_baseline WHERE target_id=?",
        (int(tid),),
    ).fetchone()
    c.close()
    if not row:
        return None
    d = dict(row)
    for key in ("headers", "ports", "subdomains", "last_change"):
        try:
            d[key] = _json.loads(d[key] or "[]")
        except Exception:
            d[key] = []
    return d


def update_target(tid, host, port_range, note, authorization, verify_tls=None):
    """编辑目标（增删改查之「改」）。仅更新元数据，不影响已扫描结果。

    verify_tls 为可选参数：仅当调用方显式传入时才更新（前端勾选自签证书跳过校验时）。
    """
    with _db_lock:
        c = _conn()
        if verify_tls is None:
            c.execute(
                "UPDATE targets SET host=?, port_range=?, note=?, authorization=? WHERE id=?",
                (host, port_range, note, authorization, tid),
            )
        else:
            c.execute(
                "UPDATE targets SET host=?, port_range=?, note=?, authorization=?, verify_tls=? WHERE id=?",
                (host, port_range, note, authorization, int(verify_tls), tid),
            )
        c.commit()
        c.close()


def delete_target(tid):
    """删除目标（增删改查之「删」）。返回受影响的行数。"""
    with _db_lock:
        c = _conn()
        c.execute("DELETE FROM target_tags WHERE target_id=?", (tid,))
        cur = c.execute("DELETE FROM targets WHERE id=?", (tid,))
        n = cur.rowcount
        c.commit()
        c.close()
        return n


# ---------- 扫描 ----------
def create_scan(target_id, name, created_by, schedule_id=None):
    with _db_lock:
        c = _conn()
        cur = c.execute(
            "INSERT INTO scans (target_id, name, status, stage, schedule_id, created_by, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (target_id, name, "queued", "init", schedule_id, created_by, _now()),
        )
        sid = cur.lastrowid
        c.commit()
        c.close()
        return sid


def update_scan(sid, **fields):
    if not fields:
        return
    bad = set(fields) - _SCAN_UPDATABLE
    if bad:
        raise ValueError(f"update_scan 非法字段: {', '.join(sorted(bad))}")
    with _db_lock:
        c = _conn()
        sets = ", ".join(f"{k}=?" for k in fields)
        c.execute(f"UPDATE scans SET {sets} WHERE id=?", list(fields.values()) + [sid])
        c.commit()
        c.close()


def get_scan(sid):
    c = _conn()
    row = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    c.close()
    return dict(row) if row else None


def scans_of_target(tid):
    """返回某目标下的全部扫描（按 id 降序），供拓扑/统计聚合使用。"""
    c = _conn()
    rows = c.execute(
        "SELECT * FROM scans WHERE target_id=? ORDER BY id DESC", (int(tid),)
    ).fetchall()
    c.close()
    return [dict(r) for r in rows]


def findings_of_target(tid):
    """返回某目标下「未归档扫描」的全部发现（仅取拓扑聚合所需字段），供资产拓扑风险热图使用。
    按 scans.archived 过滤，确保归档扫描不计入当前暴露面。"""
    c = _conn()
    rows = c.execute(
        "SELECT f.target_ref, f.risk, f.id, f.category, f.evidence_level, "
        "f.verification_status, f.endpoint "
        "FROM findings f JOIN scans s ON f.scan_id=s.id "
        "WHERE s.target_id=? AND (s.archived=0 OR s.archived IS NULL)",
        (int(tid),),
    ).fetchall()
    c.close()
    return [dict(r) for r in rows]


def list_scans(limit=100, include_archived=False):
    """扫描列表（默认排除已归档；include_archived=True 时含归档，用于生命周期管理视图）。"""
    c = _conn()
    if include_archived:
        rows = c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    else:
        rows = c.execute(
            "SELECT * FROM scans WHERE archived=0 OR archived IS NULL ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    c.close()
    return [dict(r) for r in rows]


def set_scan_archived(sid, archived=1):
    """单条扫描归档/取消归档（P-04）。返回是否命中该行。"""
    with _db_lock:
        c = _conn()
        cur = c.execute("UPDATE scans SET archived=? WHERE id=?", (int(archived), int(sid)))
        c.commit()
        c.close()
        return cur.rowcount > 0


def archive_scans_before(iso_date, target_id=None):
    """批量归档在 iso_date 之前完成且未归档的扫描（数据生命周期）。返回归档数量。

    iso_date 为 ISO 日期/时间戳字符串，与 finished_at 同格式做字典序比较。
    target_id 指定时仅归档该目标，否则全库。
    """
    with _db_lock:
        c = _conn()
        if target_id is not None:
            cur = c.execute(
                "UPDATE scans SET archived=1 WHERE status='completed' AND archived=0 "
                "AND finished_at IS NOT NULL AND finished_at < ? AND target_id=?",
                (iso_date, int(target_id)),
            )
        else:
            cur = c.execute(
                "UPDATE scans SET archived=1 WHERE status='completed' AND archived=0 "
                "AND finished_at IS NOT NULL AND finished_at < ?",
                (iso_date,),
            )
        c.commit()
        n = cur.rowcount
        c.close()
        return n


def pending_scans():
    """待处理的扫描：队列中、运行中、或已批准可继续的。"""
    c = _conn()
    rows = c.execute(
        "SELECT * FROM scans WHERE status IN ('queued','approved','running') ORDER BY id ASC"
    ).fetchall()
    c.close()
    return [dict(r) for r in rows]


def active_scan_count(target_id):
    """统计某目标下仍在进行中的扫描数（用于删除目标前的守卫）。"""
    c = _conn()
    n = c.execute(
        "SELECT COUNT(*) AS n FROM scans WHERE target_id=? AND status IN ('queued','approved','running','awaiting_review')",
        (target_id,),
    ).fetchone()["n"]
    c.close()
    return n


def delete_scan(sid):
    """删除扫描及其发现（清理历史）。返回是否删除成功。"""
    with _db_lock:
        c = _conn()
        c.execute("DELETE FROM findings WHERE scan_id=?", (sid,))
        cur = c.execute("DELETE FROM scans WHERE id=?", (sid,))
        n = cur.rowcount
        c.commit()
        c.close()
        return n


# ---------- 扫描阶段事件 / 失败归因（I-02 阶段甘特图 / U-06 失败根因分类） ----------
def record_stage_event(sid, stage, status, note=None):
    """记录某扫描阶段的生命周期事件（start/done/paused/failed），供前端甘特图还原时间线。"""
    with _db_lock:
        c = _conn()
        c.execute(
            "INSERT INTO scan_stage_events (scan_id, stage, status, ts, note) VALUES (?,?,?,?,?)",
            (int(sid), stage, status, _now(), note),
        )
        c.commit()
        c.close()


def stage_events(sid):
    """返回该扫描的阶段事件序列（按发生顺序）。"""
    c = _conn()
    rows = c.execute(
        "SELECT stage, status, ts, note FROM scan_stage_events WHERE scan_id=? ORDER BY id ASC",
        (int(sid),),
    ).fetchall()
    c.close()
    return [dict(r) for r in rows]


def fail_scan(sid, category, detail, error_summary=None):
    """U-06：将扫描标记为失败，并写入结构化失败归因（category + detail），便于前端给出针对性建议。
    category 取值：scope_unauthorized / scope_private / network_unreachable / timeout /
    ssl_error / redirect_loop / exception。同时回写 summary JSON 以兼容既有读取方。"""
    with _db_lock:
        c = _conn()
        row = c.execute("SELECT summary FROM scans WHERE id=?", (int(sid),)).fetchone()
        summ = {}
        if row and row["summary"]:
            try:
                summ = json.loads(row["summary"])
            except Exception:
                summ = {}
        summ["failure_category"] = category
        summ["failure_detail"] = detail
        if error_summary is not None:
            summ["error"] = error_summary
        c.execute(
            "UPDATE scans SET status='failed', finished_at=?, summary=?, "
            "failure_category=?, failure_detail=? WHERE id=?",
            (_now(), json.dumps(summ), category, detail, int(sid)),
        )
        c.commit()
        c.close()


# ---------- 发现 ----------
def _norm(s):
    return " ".join(str(s or "").split())


def add_finding(scan_id, category, title, risk, detail, evidence, remediation, target_ref,
                cwe="", impact="", endpoint="", http_method="", cvss_score=None,
                cvss_vector="", poc_script="", verification_status="pending",
                evidence_level="L1", evidence_meta=None):
    """写入发现，并做语义去重（借鉴 VulnClaw 思路）：

    1. 计算 CVSS 评分（优先用调用方传入，否则按类型/风险估算）；
    2. 生成稳定 finding_id（类型 + 位置）；
    3. 与同一扫描下已有发现做语义相似度比较（类型0.3 + 位置0.4 + 描述0.3），
       相似度 ≥ 0.75 视为重复：合并证据/详情，并保留验证更强的一方（已验证优先、
       证据等级更高、证据更详尽）。
    这样可根治「同一端口/同一注入点被多次报告」的问题，同时避免误删真正不同的发现。
    """
    from cvss_dedup import cvss_for, finding_similarity, evidence_strength, finding_id_of

    if cvss_score is None or cvss_score == "":
        cvss_score, _vec = cvss_for(category, risk)
        if cvss_vector in ("", None):
            cvss_vector = _vec
    elif cvss_vector in ("", None):
        _, cvss_vector = cvss_for(category, risk)
    try:
        cvss_score = float(cvss_score)
    except (TypeError, ValueError):
        cvss_score, cvss_vector = cvss_for(category, risk)

    location = endpoint or target_ref or ""
    fid_key = finding_id_of(category, location)

    # 语义去重的「先读后写」必须在同一把写锁内完成，否则多线程并发写入同一扫描
    # 可能相互覆盖 / 产生重复发现。
    with _db_lock:
        c = _conn()
        existing = c.execute(
            "SELECT id, category, title, detail, evidence, target_ref, endpoint, cvss_score, "
            "verification_status, evidence_level, cwe, impact, http_method, poc_script "
            "FROM findings WHERE scan_id=?", (scan_id,)
        ).fetchall()
        cand = {
            "category": category, "title": title, "detail": detail, "evidence": evidence,
            "target_ref": target_ref, "endpoint": endpoint,
            "verification_status": verification_status, "evidence_level": evidence_level,
        }
        for ex in existing:
            sim = finding_similarity(cand, dict(ex))
            if sim >= 0.75:
                ex_id = ex["id"]
                new_detail = _norm(ex["detail"])
                inc = _norm(detail)
                if inc and inc not in new_detail:
                    new_detail = (new_detail + "\n" + inc).strip()
                new_ev = _norm(ex["evidence"])
                inc_ev = _norm(evidence)
                if inc_ev and inc_ev not in new_ev:
                    new_ev = (new_ev + "\n" + inc_ev).strip()
                # 保留验证更强的一方
                new_vs = ex["verification_status"]
                new_el = ex["evidence_level"]
                inc_str = evidence_strength(cand)
                ex_str = evidence_strength(dict(ex))
                if inc_str > ex_str:
                    new_vs = verification_status
                    new_el = evidence_level
                new_cvss = max(float(ex["cvss_score"] or 0.0), cvss_score)
                c.execute(
                    "UPDATE findings SET detail=?, evidence=?, verification_status=?, evidence_level=?, "
                    "cvss_score=?, cwe=?, impact=?, endpoint=?, http_method=?, poc_script=?, "
                    "evidence_meta=COALESCE(?, evidence_meta) WHERE id=?",
                    (
                        new_detail, new_ev, new_vs or ex["verification_status"], new_el or ex["evidence_level"],
                        new_cvss, cwe or ex["cwe"], impact or ex["impact"],
                        endpoint or ex["endpoint"], http_method or ex["http_method"],
                        poc_script or ex["poc_script"], evidence_meta or None, ex_id,
                    ),
                )
                c.commit()
                c.close()
                return ex_id
        cur = c.execute(
            "INSERT INTO findings (scan_id, category, title, risk, detail, evidence, remediation, "
            "target_ref, created_at, finding_id, cwe, impact, endpoint, http_method, cvss_score, "
            "cvss_vector, poc_script, verification_status, evidence_level, evidence_meta) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, category, title, risk, detail, evidence, remediation, target_ref, _now(),
             fid_key, cwe, impact, endpoint, http_method, cvss_score, cvss_vector,
             poc_script, verification_status, evidence_level, evidence_meta),
        )
        c.commit()
        fid = cur.lastrowid
        c.close()
        return fid


def findings_of(scan_id):
    c = _conn()
    rows = c.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY id ASC", (scan_id,)).fetchall()
    c.close()
    return [dict(r) for r in rows]


def findings_page(scan_id, limit=50, offset=0):
    """P-03 发现分页：返回单页发现与总数，供大批量发现的扫描任务分批加载。"""
    c = _conn()
    total = c.execute("SELECT COUNT(*) AS n FROM findings WHERE scan_id=?", (scan_id,)).fetchone()["n"]
    rows = c.execute(
        "SELECT * FROM findings WHERE scan_id=? ORDER BY id ASC LIMIT ? OFFSET ?",
        (scan_id, int(limit), int(offset)),
    ).fetchall()
    c.close()
    return [dict(r) for r in rows], total


def get_finding(fid):
    """I-04/I-06：返回单条发现的完整记录（含 evidence_meta / cvss_vector / poc_script），
    供前端发现详情弹窗使用。找不到返回 None。"""
    c = _conn()
    row = c.execute("SELECT * FROM findings WHERE id=?", (int(fid),)).fetchone()
    c.close()
    return dict(row) if row else None


# 漏洞风险等级 → 数值（用于矩阵单元格取最高风险、排序等）
_RISK_RANK = {
    "Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0,
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}


def findings_matrix(scan_id):
    """I-03 漏洞矩阵视图：将单扫描的发现按 (端点 × 漏洞类型) 聚合，
    每个单元格取该组合下的最高风险等级、发现数量与代表发现 id，便于一眼定位热点。

    行 = 端点（endpoint 优先，回退 target_ref）；列 = 漏洞类型（category）。
    返回 {scan_id, total, endpoints, categories, cells}，其中
    cells[endpoint][category] = {risk, count, fid}。
    """
    fs = findings_of(scan_id)
    cells = {}
    endpoints = []
    seen_cat = set()
    categories = []
    for f in fs:
        ep = (f.get("endpoint") or f.get("target_ref") or "—") or "—"
        cat = f.get("category") or "—"
        if ep not in cells:
            cells[ep] = {}
            endpoints.append(ep)
        if cat not in seen_cat:
            seen_cat.add(cat)
            categories.append(cat)
        cell = cells[ep].get(cat)
        if cell is None:
            cell = {"risk": "Info", "count": 0, "fid": None}
            cells[ep][cat] = cell
        cell["count"] += 1
        if _RISK_RANK.get(f.get("risk"), 0) > _RISK_RANK.get(cell["risk"], 0):
            cell["risk"] = f.get("risk") or cell["risk"]
            cell["fid"] = f.get("id")
    return {
        "scan_id": scan_id,
        "total": len(fs),
        "endpoints": endpoints,
        "categories": categories,
        "cells": cells,
    }


# CVSS 3.1 基础向量格式校验：必须为 CVSS:3.1/ 前缀 + 8 个标准度量（顺序固定）。
_CVSS31_RE = re.compile(
    r"^CVSS:3\.1/"
    r"AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/UI:(?P<UI>[NR])/"
    r"S:(?P<S>[UC])/C:(?P<C>[NLH])/I:(?P<I>[NLH])/A:(?P<A>[NLH])$"
)


def set_finding_cvss(fid, score, vector):
    """I-06：保存人工校准后的 CVSS 3.1 评分与向量。

    校验向量格式（必须为合法 CVSS:3.1 基础向量）与评分数值；任一不合法返回 False。
    评分由前端 CVSS 计算器算出后回传，这里仅做格式守门，不重新计算。
    """
    if not _CVSS31_RE.match(str(vector or "").strip()):
        return False
    try:
        score = float(score)
    except (TypeError, ValueError):
        return False
    if not (0.0 <= score <= 10.0):
        return False
    with _db_lock:
        c = _conn()
        cur = c.execute(
            "UPDATE findings SET cvss_score=?, cvss_vector=? WHERE id=?",
            (round(score, 1), str(vector).strip(), int(fid)),
        )
        c.commit()
        c.close()
        return cur.rowcount > 0


# 修复闭环（F-02）：发现项的修复状态枚举
FIX_STATUS = ("open", "verifying", "fixed", "wont_fix")


def set_finding_fix_status(fid, status):
    """更新单条发现的修复状态（open/verifying/fixed/wont_fix）。返回是否成功。"""
    if status not in FIX_STATUS:
        return False
    with _db_lock:
        c = _conn()
        cur = c.execute("UPDATE findings SET fix_status=? WHERE id=?", (status, int(fid)))
        c.commit()
        c.close()
        return cur.rowcount > 0


def _diff_findings(prev_list, curr_list):
    """F-02/F-03：以 finding_id（类型+位置 的语义指纹）对两组发现做差集，
    返回已解决（仅 prev 有）/ 新增（仅 curr 有）/ 持续存在（两者均有）三类。"""
    curr_ids = {f.get("finding_id") for f in curr_list}
    prev_ids = {f.get("finding_id") for f in prev_list}
    resolved = [f for f in prev_list if f.get("finding_id") and f["finding_id"] not in curr_ids]
    new = [f for f in curr_list if f.get("finding_id") and f["finding_id"] not in prev_ids]
    persistent = [f for f in curr_list if f.get("finding_id") and f["finding_id"] in prev_ids]
    return {
        "resolved": resolved,
        "new": new,
        "persistent": persistent,
        "counts": {
            "prev": len(prev_list), "curr": len(curr_list),
            "resolved": len(resolved), "new": len(new), "persistent": len(persistent),
        },
    }


def rescan_diff(target_id):
    """F-02 修复跟踪闭环：对比同一目标最近两次已完成扫描，给出新增 / 已解决 / 持续存在。

    以 finding_id（类型+位置 的语义指纹）做差集，反映"修复后再扫"的治理效果。
    目标下不足两次已完成扫描时返回 None。
    """
    c = _conn()
    rows = c.execute(
        "SELECT * FROM scans WHERE target_id=? AND status='completed' ORDER BY id DESC LIMIT 2",
        (target_id,),
    ).fetchall()
    c.close()
    if len(rows) < 2:
        return None
    curr = dict(rows[0])   # 最近一次
    prev = dict(rows[1])   # 上一次
    d = _diff_findings(findings_of(prev["id"]), findings_of(curr["id"]))
    d["prev_scan_id"] = prev["id"]
    d["curr_scan_id"] = curr["id"]
    return d


def compare_scans(scan_a_id, scan_b_id):
    """F-03 漏洞对比基线 Diff：对比任意两次扫描（a 视为基线 / b 视为当前）。

    两扫描必须属于同一目标，否则返回 None（跨目标对比无意义）。以 finding_id 做差集，
    复用与 rescan_diff 相同的 _diff_findings，保证"新增/已解决/持续"语义一致。
    """
    a = get_scan(scan_a_id)
    b = get_scan(scan_b_id)
    if not a or not b:
        return None
    if a["target_id"] != b["target_id"]:
        return None
    d = _diff_findings(findings_of(a["id"]), findings_of(b["id"]))
    d["prev_scan_id"] = a["id"]
    d["curr_scan_id"] = b["id"]
    return d


# ---------- 复核闸门 ----------
def create_review(kind, note, target_id=None, scan_id=None, ref_id=None):
    with _db_lock:
        c = _conn()
        cur = c.execute(
            "INSERT INTO reviews (kind, ref_id, scan_id, target_id, note, status, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (kind, ref_id, scan_id, target_id, note, "pending", _now()),
        )
        rid = cur.lastrowid
        c.commit()
        c.close()
        return rid


def decide_review(rid, decision, decided_by):
    with _db_lock:
        c = _conn()
        status = "approved" if decision == "approve" else "rejected"
        c.execute(
            "UPDATE reviews SET status=?, decided_by=?, decided_at=? WHERE id=?",
            (status, decided_by, _now(), rid),
        )
        c.commit()
        c.close()


def pending_reviews():
    c = _conn()
    rows = c.execute("SELECT * FROM reviews WHERE status='pending' ORDER BY id ASC").fetchall()
    c.close()
    return [dict(r) for r in rows]


def review_of(rid):
    c = _conn()
    row = c.execute("SELECT * FROM reviews WHERE id=?", (rid,)).fetchone()
    c.close()
    return dict(row) if row else None


# ---------- 调度 ----------
def create_schedule(name, target_ids, interval_minutes, created_by):
    with _db_lock:
        c = _conn()
        cur = c.execute(
            "INSERT INTO schedules (name, target_ids, interval_minutes, enabled, created_by, created_at) "
            "VALUES (?,?,?,1,?,?)",
            (name, ",".join(str(t) for t in target_ids), interval_minutes, created_by, _now()),
        )
        sid = cur.lastrowid
        c.commit()
        c.close()
        return sid


def list_schedules():
    c = _conn()
    rows = c.execute("SELECT * FROM schedules ORDER BY id DESC").fetchall()
    c.close()
    return [dict(r) for r in rows]


def update_schedule(sid, **fields):
    if not fields:
        return
    bad = set(fields) - _SCHEDULE_UPDATABLE
    if bad:
        raise ValueError(f"update_schedule 非法字段: {', '.join(sorted(bad))}")
    with _db_lock:
        c = _conn()
        sets = ", ".join(f"{k}=?" for k in fields)
        c.execute(f"UPDATE schedules SET {sets} WHERE id=?", list(fields.values()) + [sid])
        c.commit()
        c.close()


def delete_schedule(sid):
    """删除定时任务（增删改查之「删」）。返回受影响的行数。"""
    with _db_lock:
        c = _conn()
        cur = c.execute("DELETE FROM schedules WHERE id=?", (sid,))
        n = cur.rowcount
        c.commit()
        c.close()
        return n


# ---------- 操作可撤销（U-03）：删除前入回收站，5 秒窗口内可还原 ----------
import uuid as _uuid

_TRASH = {}  # token -> {kind, rows}


def _insert_row(c, table, row):
    cols = list(row.keys())
    ph = ",".join("?" for _ in cols)
    c.execute(
        "INSERT OR REPLACE INTO %s (%s) VALUES (%s)" % (table, ",".join(cols), ph),
        [row[k] for k in cols],
    )


def _trash_push(kind, payload):
    token = _uuid.uuid4().hex
    _TRASH[token] = {"kind": kind, "rows": payload}
    return token


def trash_target(tid):
    """U-03：删除目标前，将其与级联的扫描 / 发现一并快照入回收站，返回撤销 token。"""
    c = _conn()
    target = c.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()
    if not target:
        c.close()
        return None
    scans = c.execute("SELECT * FROM scans WHERE target_id=?", (tid,)).fetchall()
    findings = c.execute(
        "SELECT * FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE target_id=?)",
        (tid,),
    ).fetchall()
    c.close()
    token = _trash_push("target", {
        "target": dict(target),
        "scans": [dict(r) for r in scans],
        "findings": [dict(r) for r in findings],
    })
    with _db_lock:
        c2 = _conn()
        c2.execute("DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE target_id=?)", (tid,))
        c2.execute("DELETE FROM scans WHERE target_id=?", (tid,))
        c2.execute("DELETE FROM target_tags WHERE target_id=?", (tid,))
        c2.execute("DELETE FROM targets WHERE id=?", (tid,))
        c2.commit()
        c2.close()
    return token


def trash_scan(sid):
    """U-03：删除扫描前，将扫描与其发现快照入回收站，返回撤销 token。"""
    c = _conn()
    scan = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    if not scan:
        c.close()
        return None
    findings = c.execute("SELECT * FROM findings WHERE scan_id=?", (sid,)).fetchall()
    c.close()
    token = _trash_push("scan", {"scan": dict(scan), "findings": [dict(r) for r in findings]})
    with _db_lock:
        c2 = _conn()
        c2.execute("DELETE FROM findings WHERE scan_id=?", (sid,))
        c2.execute("DELETE FROM scans WHERE id=?", (sid,))
        c2.commit()
        c2.close()
    return token


def trash_schedule(sid):
    """U-03：删除定时任务前，将其快照入回收站，返回撤销 token。"""
    c = _conn()
    row = c.execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
    if not row:
        c.close()
        return None
    token = _trash_push("schedule", {"schedule": dict(row)})
    with _db_lock:
        c2 = _conn()
        c2.execute("DELETE FROM schedules WHERE id=?", (sid,))
        c2.commit()
        c2.close()
    return token


def restore_trash(token):
    """U-03：还原回收站中的删除操作。成功返回 True。"""
    entry = _TRASH.pop(token, None)
    if not entry:
        return False
    with _db_lock:
        c = _conn()
        if entry["kind"] == "target":
            _insert_row(c, "targets", entry["rows"]["target"])
            for s in entry["rows"]["scans"]:
                _insert_row(c, "scans", s)
            for f in entry["rows"]["findings"]:
                _insert_row(c, "findings", f)
        elif entry["kind"] == "scan":
            _insert_row(c, "scans", entry["rows"]["scan"])
            for f in entry["rows"]["findings"]:
                _insert_row(c, "findings", f)
        elif entry["kind"] == "schedule":
            _insert_row(c, "schedules", entry["rows"]["schedule"])
        c.commit()
        c.close()
    return True


# ---------- 审计日志 ----------
def audit(username, action, target="", detail="", ip=""):
    with _db_lock:
        c = _conn()
        c.execute(
            "INSERT INTO audit_log (ts, username, action, target, detail, ip) VALUES (?,?,?,?,?,?)",
            (_now(), username, action, target, detail, ip),
        )
        c.commit()
        c.close()


def audit_tail(limit=200):
    c = _conn()
    rows = c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    return [dict(r) for r in rows]


def clear_audit():
    """清空审计日志（增删改查之「删/清空」）。返回清除条数。"""
    with _db_lock:
        c = _conn()
        cur = c.execute("DELETE FROM audit_log")
        n = cur.rowcount
        c.commit()
        c.close()
        return n


def delete_audit(aid):
    """删除单条审计日志。返回受影响的行数。"""
    with _db_lock:
        c = _conn()
        cur = c.execute("DELETE FROM audit_log WHERE id=?", (aid,))
        n = cur.rowcount
        c.commit()
        c.close()
        return n


# ---------- 设置 ----------
def get_setting(key, default=None):
    c = _conn()
    row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    c.close()
    return row["value"] if row else default


# ---------- 运维 / UX 辅助（U-05 / U-11） ----------
def audit_heatmap(days=90):
    """U-11 审计热力图：返回最近 days 天（含今天）每天的审计操作计数。

    返回 list[dict{date, count}]，按日期升序；缺失的日子 count=0（前端用 0 渲染空白格）。
    """
    c = _conn()
    rows = c.execute(
        "SELECT substr(ts,1,10) AS d, COUNT(*) AS n FROM audit_log "
        "WHERE ts >= date('now','-%d days') GROUP BY d" % int(days)
    ).fetchall()
    c.close()
    by_day = {r["d"]: r["n"] for r in rows}
    out = []
    base = datetime.date.today()
    for i in range(int(days) - 1, -1, -1):
        d = (base - datetime.timedelta(days=i)).strftime("%Y-%m-%d")
        out.append({"date": d, "count": by_day.get(d, 0)})
    return out


def db_stats():
    """返回库内核心计数（目标 / 扫描 / 发现 / 已过闸等），供诊断包与仪表盘汇总使用。"""
    c = _conn()
    t = c.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    s = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    f = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    # fix_status 取值为 'open' / 'verifying' / 'fixed' / 'wont_fix'，统计"已修复"应使用 'fixed'
    f_done = c.execute("SELECT COUNT(*) FROM findings WHERE fix_status='fixed'").fetchone()[0]
    a = c.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    c.close()
    return {
        "targets": t, "scans": s, "findings": f,
        "findings_done": f_done, "audit": a,
    }


def set_setting(key, value):
    with _db_lock:
        c = _conn()
        c.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, _now()),
        )
        c.commit()
        c.close()
