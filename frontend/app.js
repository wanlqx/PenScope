/* PenScope —— 静态前端（无后端）
 * 通过 window.pywebview.api 调用本地 Python 接口层（app_api.Api）。
 * 支持多语言（中/英）、主题切换、字体大小与布局自定义。
 */
(function () {
  "use strict";

  var api = null;
  var current = { view: "dashboard", param: null };
  var settings = { language: "zh", theme: "dark", font_size: "14", layout: "comfortable",
    fx_enabled: "1",
    bg_particles_enabled: "1", bg_particle_density: "1.0", panel_opacity: "0.9" };
  // 扫描详情自动刷新状态（用户可控）。仅在用户停留在扫描详情且扫描活跃时刷新；
  // 一旦切换视图即被 router() 中的 clearScanTimer() 取消，确保不会被强制拉回扫描界面。
  // P-06：优先由 Python 侧阶段事件（window.__autopentestOnScanEvent）主动推送刷新；
  // _scanTimer 降级为「仅推送丢失时的兜底」（间隔加长 + 近期有推送则跳过），CPU 占用显著下降。
  var autoRefresh = true;
  var _scanTimer = null;
  var _lastScanPush = 0;          // 最近一次收到推送事件的时间戳（ms）
  var _vulnI18n = {};             // U-07：CWE → {name, remediation} 双语映射（按当前语言）
  // 方案B 事件流：环形缓冲最近 8 条扫描阶段事件，供仪表盘实时活动卡片展示
  var _evtFeed = [];
  function pushEvt(evt) {
    if (!evt) return;
    _evtFeed.unshift({
      scan_id: evt.scan_id, stage: evt.stage || "", status: evt.status || "",
      msg: evt.message || evt.msg || "", ts: Date.now()
    });
    if (_evtFeed.length > 8) _evtFeed.length = 8;
    if (current.view === "dashboard") renderEvtFeed();
  }
  function clearScanTimer() {
    if (_scanTimer) { clearInterval(_scanTimer); _scanTimer = null; }
  }

  // P-06：pywebview 事件推送入口。Python 在每次阶段事件后通过 evaluate_js 调用本函数，
  // 仅当当前正停留在「对应扫描详情」或「目标中心」时才刷新，绝不强制跳转。
  window.__autopentestOnScanEvent = function (evt) {
    if (!evt || evt.type !== "scan_event") return;
    _lastScanPush = Date.now();
    pushEvt(evt);   // 方案B 事件流：缓冲并实时刷新仪表盘活动卡片
    if (current.view === "scan" && String(current.param) === String(evt.scan_id)) {
      router();   // 重新渲染当前扫描详情（甘特图 / 发现 / 状态即时更新）
    } else if (current.view === "target") {
      router();   // 目标中心扫描历史状态同步更新
    }
  };

  // 方案B 事件流渲染：局部更新 #evt-feed，不重渲整个仪表盘
  function renderEvtFeed() {
    var box = document.getElementById("evt-feed");
    if (!box) return;
    if (!_evtFeed.length) {
      box.innerHTML = '<li class="evt-empty">' + esc(t("evtEmpty")) + "</li>";
      return;
    }
    box.innerHTML = _evtFeed.map(function (e) {
      var d = new Date(e.ts);
      function p(n) { return (n < 10 ? "0" : "") + n; }
      var tm = p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
      var stCls = e.status === "completed" ? "ok" : (e.status === "failed" ? "err" : "run");
      var stTxt = e.status || t("evtRunning");
      return '<li class="evt-item"><span class="evt-ts mono">' + tm + '</span>' +
        '<span class="evt-scan">#' + esc(String(e.scan_id)) + '</span>' +
        '<span class="evt-stage">' + esc(e.stage || t("evtStage")) + '</span>' +
        '<span class="evt-st ' + stCls + '">' + esc(stTxt) + '</span></li>';
    }).join("");
  }

  // 多语言资源来自 i18n.js（window.I18N），便于扩展更多语言，无需改动此处逻辑。
  var I18N = window.I18N || {
    zh: { appName: "PenScope" }, en: { appName: "PenScope" }
  };

  function t(key) {
    return (I18N[settings.language] || I18N.zh)[key] || key;
  }

  // U-07：按当前语言本地化发现的「类名 / 修复建议」（取自后端 vuln_i18n_map）。
  // 未命中映射时原样返回后端字段，绝不产生空白。
  function locVuln(f) {
    if (!f || !f.cwe) return f;
    var entry = _vulnI18n[f.cwe];
    if (!entry) return f;
    var out = Object.assign({}, f);
    // CWE-200 是「信息暴露」父类，涵盖环境指纹 / 子域资产 / 敏感信息泄露 / API 安全等
    // 多种具体发现；若统一覆盖为「敏感信息暴露」，会让 Info 级的信息/资产类发现看起来像
    // 高危漏洞。故 CWE-200 不覆盖后端 category，保留各自具体名称以示区分。
    // （端口暴露已独立映射为 CWE-668「资产暴露」，仍走覆盖分支，显示一致。）
    if (entry.name && f.cwe !== "CWE-200") out.category = entry.name;
    if (entry.remediation) out.remediation = entry.remediation;
    return out;
  }

  // 加载/刷新漏洞双语映射（语言变化时调用）
  function loadVulnI18n() {
    if (!api) return;
    call("vuln_i18n_map", settings.language).then(function (r) {
      if (r && r.ok) _vulnI18n = r.map || {};
    }).catch(function () {});
  }

  // 验证状态 → 徽标配色（verified/unverified/info 走 i18n；其余复用 unverified 文案）
  function verifyBadge(vs) {
    var color = {
      verified: "var(--low)", unverified: "var(--warn)", heuristic: "var(--warn)",
      pending: "#8b949e", rejected: "var(--danger)", info: "var(--info)"
    }[vs] || "#8b949e";
    var key = ({ verified: "verified", unverified: "unverified", info: "info" })[vs] || "unverified";
    return '<span class="vbadge" style="background:' + color + '">' + t(key) + '</span>';
  }

  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  // U-12 敏感数据脱敏（展示层安全网，与后端 scanner/redact.py 同策略）。
  // 仅对显示在界面上的证据/响应文本做掩码，数据库原文保持不变。
  function redact(text) {
    if (typeof text !== "string") return text;
    var s = text;
    s = s.replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, "***REDACTED_PRIVATE_KEY***");
    s = s.replace(/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "***REDACTED_JWT***");
    s = s.replace(/(AKIA|ASIA)[0-9A-Z]{16}/g, function (m) { return m.slice(0, 4) + "********"; });
    s = s.replace(/(password|passwd|pwd|secret|api[_-]?key|apikey|token|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|auth[_-]?token)(["']?\s*[:=]\s*["']?)[^\s"'`,}{\]]+/gi, function (m, p1, p2) { return p1 + p2 + "***REDACTED***"; });
    s = s.replace(/([Bb]earer\s+)[A-Za-z0-9\-._~+/]+=*/g, "$1***REDACTED***");
    s = s.replace(/(session|sid|token|auth|jwt|csrf|access_token|refresh_token)=[A-Za-z0-9_\-]{8,}/g, function (m) { return m.slice(0, m.indexOf("=") + 1) + "********"; });
    return s;
  }
  function call(method) {
    var args = Array.prototype.slice.call(arguments, 1);
    return api[method].apply(api, args);
  }
  function riskBadge(risk) {
    var colors = { Critical: "var(--crit)", High: "var(--high)", Medium: "var(--med)", Low: "var(--low)", Info: "var(--info)" };
    var names = { Critical: t("riskLevel"), High: t("riskLevel"), Medium: t("riskLevel"), Low: t("riskLevel"), Info: t("riskLevel") };
    var cn = { Critical: "严重", High: "高危", Medium: "中危", Low: "低危", Info: "信息" };
    var en = { Critical: "Critical", High: "High", Medium: "Medium", Low: "Low", Info: "Info" };
    var label = settings.language === "en" ? (en[risk] || risk) : (cn[risk] || risk);
    return '<span class="badge" style="background:' + (colors[risk] || "#888") + '">' + esc(label) + "</span>";
  }
  function stageTag(status) {
    var cls = "run";
    if (status === "awaiting_review") cls = "wait";
    else if (status === "completed") cls = "done";
    else if (status === "failed") cls = "fail";
    return '<span class="stage ' + cls + '">' + esc(status) + "</span>";
  }
  function toast(msg, type) {
    var d = document.createElement("div");
    d.className = "flash";
    d.setAttribute("role", "status");
    d.setAttribute("aria-live", "polite");
    d.style.position = "fixed";
    d.style.top = "16px"; d.style.right = "16px"; d.style.zIndex = 99;
    d.style.maxWidth = "360px";
    if (type === "ok") d.style.color = "var(--low)";
    if (type === "err") d.style.color = "var(--danger)";
    d.textContent = msg;
    document.body.appendChild(d);
    setTimeout(function () { d.remove(); }, 3200);
  }
  // U-03 操作可撤销：删除成功后弹出带「撤销」的提示，5 秒窗口内可还原。
  function toastUndo(r, doneMsg, onDone) {
    if (!r.ok) { toast(r.error || (settings.language === "en" ? "Failed" : "操作失败"), "err"); return; }
    var undos = r.undos || (r.undo_token ? [r.undo_token] : null);
    if (!undos || !undos.length) { toast(doneMsg, "ok"); if (onDone) onDone(); return; }
    var d = document.createElement("div");
    d.className = "flash";
    d.style.position = "fixed";
    d.style.top = "16px"; d.style.right = "16px"; d.style.zIndex = 99;
    d.style.maxWidth = "360px";
    d.style.display = "flex"; d.style.alignItems = "center"; d.style.gap = "12px";
    d.innerHTML = '<span>' + esc(doneMsg) + '</span>' +
      '<button class="btn sm" id="undo-btn">' + t("undo") + '</button>';
    document.body.appendChild(d);
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      d.remove(); if (onDone) onDone();
    }, 5000);
    d.querySelector("#undo-btn").addEventListener("click", function () {
      if (done) return; done = true; clearTimeout(timer);
      call("undo_deletes", undos).then(function (ur) {
        d.remove();
        if (ur.ok) toast(settings.language === "en" ? "Undone" : "已撤销", "ok");
        else toast(ur.error || (settings.language === "en" ? "Undo failed" : "撤销失败"), "err");
        if (onDone) onDone();
      });
    });
  }
  function view() { return document.getElementById("view"); }
  // 自动刷新后恢复滚动位置（修复"资产拓扑概览"等页面停留时跳动/回到顶部）
  function paintView(html) {
    var v = view();
    if (!v) return;
    var sv = v.scrollTop;          // 替换前记录当前滚动位置
    v.innerHTML = html;
    v.scrollTop = sv;              // 渲染后保持位置，避免页面跳回顶部
  }

  // ---------------- P-05 虚拟滚动（长列表 O(visible) 渲染） ----------------
  // 在固定高度滚动容器内只渲染「可视区 + overscan」行，避免万级数据全量 DOM 卡顿。
  // scroller：滚动容器（会被设置 overflow + relative）；rows：数据数组；
  // renderRow(row, index) → 单行内层 HTML（单元格由 .vrow 的 grid 模板对齐）；
  // opts：{rowHeight, overscan, rowClass}。返回 paint() 供外部（数据变化/resize）重绘。
  function mountVirtualList(scroller, rows, renderRow, opts) {
    opts = opts || {};
    var rowHeight = opts.rowHeight || 34;
    var overscan = opts.overscan || 8;
    scroller.innerHTML = "";
    scroller.classList.add("vlist");
    scroller.style.position = "relative";
    scroller.style.overflowY = "auto";
    var sizer = document.createElement("div");
    sizer.className = "vlist-sizer";
    sizer.style.position = "relative";
    sizer.style.width = "100%";
    sizer.style.height = (rows.length * rowHeight) + "px";
    scroller.appendChild(sizer);
    var live = {};  // index -> 已挂载的行元素

    function paint() {
      var scrollTop = scroller.scrollTop;
      var viewH = scroller.clientHeight || 400;
      var start = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
      var end = Math.min(rows.length, Math.ceil((scrollTop + viewH) / rowHeight) + overscan);
      Object.keys(live).forEach(function (k) {
        var idx = +k;
        if (idx < start || idx >= end) {
          var el = live[idx];
          if (el && el.parentNode) el.parentNode.removeChild(el);
          delete live[idx];
        }
      });
      for (var i = start; i < end; i++) {
        if (live[i]) continue;
        var row = document.createElement("div");
        row.className = "vrow" + (opts.rowClass ? " " + opts.rowClass : "");
        row.style.position = "absolute";
        row.style.top = (i * rowHeight) + "px";
        row.style.left = "0";
        row.style.right = "0";
        row.style.height = rowHeight + "px";
        row.innerHTML = renderRow(rows[i], i);
        sizer.appendChild(row);
        live[i] = row;
      }
    }
    var raf = null;
    scroller.addEventListener("scroll", function () {
      if (raf) return;
      raf = requestAnimationFrame(function () { raf = null; paint(); });
    });
    // 初始渲染延后一帧，确保容器已完成布局（clientHeight 可用）
    requestAnimationFrame(paint);
    scroller._vpaint = paint;
    return paint;
  }

  // ---------------- 通用弹窗 / 确认 ----------------
  // 编辑类表单弹窗：title 标题，bodyHtml 表单内容，onSave(root) 在点击「保存」时回调。
  function openModal(title, bodyHtml, onSave, okText) {
    var root = document.getElementById("modal-root");
    root.innerHTML = '<div class="overlay"><div class="modal" role="dialog" aria-modal="true" aria-label="' + esc(title) + '" style="height:auto;max-height:86%;width:560px">' +
      '<div class="modal-head"><b>' + esc(title) + '</b><div>' +
      '<button class="btn sm" id="ov-ok">' + (okText || t("save")) + '</button> ' +
      '<button class="btn sm ghost" id="ov-cancel">' + t("cancel") + '</button></div></div>' +
      '<div class="modal-body" id="ov-body">' + bodyHtml + '</div></div></div>';
    document.getElementById("ov-cancel").addEventListener("click", function () { root.innerHTML = ""; });
    document.getElementById("ov-ok").addEventListener("click", function () { onSave(root); });
    _focusModal(root);
    return root;
  }
  // 危险操作确认弹窗：onYes 在点击「确定」后执行。
  function confirmDialog(title, msg, onYes) {
    var root = document.getElementById("modal-root");
    root.innerHTML = '<div class="overlay"><div class="modal" role="dialog" aria-modal="true" aria-label="' + esc(title) + '" style="height:auto;max-height:86%;width:460px">' +
      '<div class="modal-head"><b>' + esc(title) + '</b><div>' +
      '<button class="btn sm danger" id="cf-yes">' + t("confirm") + '</button> ' +
      '<button class="btn sm ghost" id="cf-no">' + t("cancel") + '</button></div></div>' +
      '<div class="modal-body"><p style="margin:0">' + esc(msg) + '</p></div></div></div>';
    document.getElementById("cf-no").addEventListener("click", function () { root.innerHTML = ""; });
    document.getElementById("cf-yes").addEventListener("click", function () { root.innerHTML = ""; onYes(); });
    _focusModal(root);
  }
  // U-09：弹窗打开时将焦点移入对话框（便于键盘 / 读屏用户），并在失焦返回时仍可 Esc 关闭。
  function _focusModal(root) {
    var m = root.querySelector(".modal");
    if (m) { m.setAttribute("tabindex", "-1"); try { m.focus(); } catch (e) {} }
  }

  /* ==================================================================
     UI 融合重构（A 骨架 + B 仪表盘密度 + C 引导与详情组织）
     全部为新增纯增量函数；renderFindingModal 保留作 fallback。
     改动的现有函数见：applySettings / router / renderDashboard /
     openFinding / setupShortcuts / __autopentestOnScanEvent / boot。
     ================================================================== */

  // 三组分层导航数据（数据驱动 nav，顺带修旧 map 漏 topology 的隐性 bug）
  var NAV_DATA = [
    { group: "grpWorkspace", items: [
      { view: "dashboard", key: "dashboard", ico: "▦" },
      { view: "targets",   key: "targets",   ico: "◉" },
      { view: "scans",     key: "scans",     ico: "⟳" },
      { view: "topology",  key: "topology",  ico: "⌬" },
    ]},
    { group: "grpGovernance", items: [
      { view: "reviews",   key: "reviews",   ico: "⚠" },
      { view: "scheduler", key: "scheduler", ico: "⏱" },
      { view: "audit",     key: "audit",     ico: "☰" },
    ]},
    { group: "grpSystem", items: [
      { view: "settings", key: "about", ico: "⚙" },
    ]},
  ];
  // 视图 → 顶栏标题 i18n 键
  var _VIEW_TITLE = {
    dashboard: "dashboard", targets: "targets", scans: "scans", scan: "scanDetail",
    target: "targetCenter", reviews: "reviews", scheduler: "scheduleTask",
    audit: "auditLog", topology: "topology", settings: "about"
  };

  function renderNav() {
    var nav = document.getElementById("nav");
    if (!nav) return;
    var html = "";
    NAV_DATA.forEach(function (sec) {
      // 方案B rail：不渲染分组标题文字，仅用细分隔线区分（见 CSS .nav-section + .nav-section::before）
      html += '<div class="nav-section">';
      sec.items.forEach(function (it) {
        var label = esc(t(it.key));
        var badge = it.view === "reviews"
          ? '<span class="ni-badge" id="ni-reviews" style="display:none">0</span>' : "";
        html += '<a class="nav-item" href="#' + it.view + '" data-view="' + it.view +
          '" title="' + label + '" aria-label="' + label + '">' +
          '<span class="ni-ico" aria-hidden="true">' + it.ico + '</span>' +
          '<span class="tip">' + label + '</span>' + badge + '</a>';
      });
      html += '</div>';
    });
    nav.innerHTML = html;
  }

  function renderTopbar() {
    var si = document.getElementById("tb-search-input");
    if (si) si.setAttribute("placeholder", t("topbarSearch"));
    // SOC 顶栏元素 i18n：环境徽标文本 + 告警铃 title
    var env = document.querySelector(".tb-env");
    if (env) env.innerHTML = '<span class="dot" aria-hidden="true"></span>' + esc(t("tbEnvLocal"));
    var bell = document.getElementById("tb-bell");
    if (bell) bell.title = t("topbarBell");
    startClock();
  }

  // —— 顶栏时钟（每秒更新，SOC 风格 HH:MM:SS）——
  var _clockTimer = null;
  function startClock() {
    if (_clockTimer) return;
    var tick = function () {
      var el = document.getElementById("tb-clock");
      if (!el) return;
      var d = new Date();
      function p(n) { return (n < 10 ? "0" : "") + n; }
      el.textContent = p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
    };
    tick();
    _clockTimer = setInterval(tick, 1000);
  }

  // 统一刷新外围 chrome：nav 高亮、顶栏标题、关闭命令面板
  function refreshChrome() {
    var nav = document.getElementById("nav");
    if (nav) nav.querySelectorAll(".nav-item").forEach(function (a) {
      var on = a.getAttribute("data-view") === current.view;
      a.classList.toggle("active", on);
      if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
    var tt = document.getElementById("tb-title");
    if (tt) tt.textContent = t(_VIEW_TITLE[current.view] || "dashboard");
    closeCmdPalette();
  }

  // —— 引导条：规则化下一步（吸收 C 的始终可见引导） ——
  function renderGuideBar(ctx) {
    if (sessionStorage.getItem("guideDismissed")) return "";
    var reviews = (ctx.reviews || []).length;
    var targets = ctx.targets || [];
    var scans = ctx.scans || [];
    var running = scans.filter(function (s) { return s.status === "running" || s.status === "queued" || s.status === "paused"; }).length;
    var completed = scans.filter(function (s) { return s.status === "completed"; }).length;
    var txt = "", go = null, act = "";
    if (reviews > 0) { txt = t("guideReview").replace("{n}", reviews); go = "#reviews"; act = t("reviews"); }
    else if (!targets.length) { txt = t("guideNoTarget"); go = "#targets"; act = t("addTarget"); }
    else if (!scans.length) { txt = t("guideNoScan"); go = "#scans"; act = t("startScan"); }
    else if (running > 0) { txt = t("guideRunning").replace("{n}", running); go = "#scan/" + scans[0].id; act = t("scans"); }
    else if (completed > 0) { txt = t("guideDone"); go = "#scans"; act = t("report"); }
    else return "";
    return '<div class="guide-bar" id="guide-bar">' +
      '<span class="gb-ico" aria-hidden="true">💡</span>' +
      '<span class="gb-text"><b>' + esc(t("guideNext")) + '：</b>' + esc(txt) + '</span>' +
      (go ? '<button class="gb-act" data-go="' + go + '">' + esc(act) + '</button>' : '') +
      '<button class="gb-dismiss" id="gb-dismiss">' + esc(t("guideDismiss")) + '</button></div>';
  }
  function bindGuideBar() {
    var gb = document.getElementById("guide-bar");
    if (!gb) return;
    var act = gb.querySelector(".gb-act");
    if (act) act.addEventListener("click", function () { navigate(act.getAttribute("data-go")); });
    var dis = document.getElementById("gb-dismiss");
    if (dis) dis.addEventListener("click", function () {
      sessionStorage.setItem("guideDismissed", "1"); gb.classList.add("hidden");
    });
  }

  // —— 状态栏 + 8s 定时刷新（吸收 B 的底部状态条） ——
  var _statusTimer = null;
  function renderStatusBar() {
    var sb = document.getElementById("statusbar");
    if (!sb) return;
    sb.innerHTML =
      '<span class="sb-item"><span class="sb-dot" id="sb-dot"></span><span id="sb-running">' + esc(t("statusBarRunning")) + ' 0</span></span>' +
      '<span class="sb-item">' + esc(t("statusBarTargets")) + ': <b id="sb-targets">—</b></span>' +
      '<span class="sb-item">' + esc(t("statusBarScans")) + ': <b id="sb-scans">—</b></span>' +
      '<span class="sb-item">' + esc(t("statusBarReviews")) + ': <b id="sb-reviews">—</b></span>' +
      '<span class="sb-spacer"></span>' +
      '<span class="sb-item">PenScope</span>';
  }
  function refreshStatusBar() {
    if (!api) return;
    Promise.all([call("list_targets"), call("list_scans", 50), call("list_reviews")]).then(function (res) {
      var targets = res[0] || [], scans = res[1] || [], reviews = res[2] || [];
      var running = scans.filter(function (s) {
        return s.status === "running" || s.status === "queued" || s.status === "paused";
      }).length;
      var el = document.getElementById("sb-targets"); if (el) el.textContent = targets.length;
      el = document.getElementById("sb-scans"); if (el) el.textContent = scans.length;
      el = document.getElementById("sb-reviews"); if (el) el.textContent = reviews.length;
      el = document.getElementById("sb-running"); if (el) el.textContent = t("statusBarRunning") + " " + running;
      el = document.getElementById("sb-dot"); if (el) el.classList.toggle("run", running > 0);
      var badge = document.getElementById("ni-reviews");
      if (badge) { badge.style.display = reviews.length ? "" : "none"; badge.textContent = reviews.length; }
      // 告警铃：有待复核闸门时高亮 + ping 动画
      var bell = document.getElementById("tb-bell");
      if (bell) {
        bell.classList.toggle("has-alert", reviews.length > 0);
        if (reviews.length > 0) bell.setAttribute("title", t("reviews") + ": " + reviews.length);
      }
    }).catch(function () {});
  }
  function startStatusTimer() {
    if (_statusTimer) return;
    refreshStatusBar();
    _statusTimer = setInterval(refreshStatusBar, 8000);
  }

  // —— 纯 SVG sparkline / donut（零外部依赖） ——
  function sparkSVG(values, color) {
    if (!values || !values.length) return "";
    var w = 120, h = 26, pad = 2;
    var max = Math.max.apply(null, values), min = Math.min.apply(null, values);
    var range = (max - min) || 1;
    var step = (w - pad * 2) / Math.max(1, values.length - 1);
    var pts = values.map(function (v, i) {
      var x = pad + i * step;
      var y = pad + (h - pad * 2) * (1 - (v - min) / range);
      return x.toFixed(1) + "," + y.toFixed(1);
    }).join(" ");
    return '<svg class="kpi-spark" viewBox="0 0 ' + w + " " + h + '" preserveAspectRatio="none">' +
      '<polyline points="' + pts + '" fill="none" stroke="' + (color || "var(--accent)") +
      '" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/></svg>';
  }
  function donutSVG(segs) {
    var total = segs.reduce(function (s, x) { return s + (x.value || 0); }, 0);
    var r = 36, cx = 48, cy = 48, sw = 12, C = 2 * Math.PI * r, off = 0, circles = "";
    if (!total) {
      circles = '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="var(--panel2)" stroke-width="' + sw + '"/>';
    } else {
      segs.forEach(function (s) {
        if (!s.value) return;
        var len = (s.value / total) * C;
        circles += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + s.color +
          '" stroke-width="' + sw + '" stroke-dasharray="' + len.toFixed(2) + " " + (C - len).toFixed(2) +
          '" stroke-dashoffset="' + (-off).toFixed(2) + '" transform="rotate(-90 ' + cx + " " + cy + ')"/>';
        off += len;
      });
    }
    return '<svg class="donut" viewBox="0 0 96 96">' + circles + '</svg>';
  }
  function _scansByDay(scans, days) {
    var out = [], now = new Date();
    for (var i = days - 1; i >= 0; i--) {
      var d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i);
      out.push({ key: d.toISOString().slice(0, 10), count: 0 });
    }
    var idx = {};
    out.forEach(function (d, i) { idx[d.key] = i; });
    (scans || []).forEach(function (s) {
      var k = (s.created_at || "").slice(0, 10);
      if (idx[k] != null) out[idx[k]].count++;
    });
    return out.map(function (d) { return d.count; });
  }

  // —— UI 阶段 5：仪表盘拓扑缩略（静态径向布局，无力学模拟 / 无交互，点击跳转完整拓扑） ——
  // 复用 _topoNodeRadius / _topoNodeColor / _topoRiskColor（函数声明提升，可前置引用）
  // 缓存移到模块级：paintView 整体重渲染会销毁 #topo-mini DOM 节点，导致原挂在节点上的
  // _topoSig 缓存一并丢失，每次仪表盘 4s 刷新都重建 SVG 产生闪动。模块级缓存跨重渲染存活，
  // 且缓存上次渲染的 HTML 以便节点被重建后瞬时回填，消除 spinner→svg 的闪动。
  var _topoSig = null;     // 拓扑数据签名（含语言）：节点 id 集合 + 边数 + 语言
  var _topoHtml = "";      // 上次渲染的 SVG+图例 HTML，用于瞬时回填消除 spinner 闪动
  function renderTopoMini() {
    var el = document.getElementById("topo-mini");
    if (!el) return;
    // 瞬时恢复：若已有缓存 HTML，先立即回填，盖掉 paintView 留下的 spinner，杜绝闪动
    if (_topoHtml) el.innerHTML = _topoHtml;
    call("topology_data").then(function (r) {
      el = document.getElementById("topo-mini");
      if (!el) return;
      var topo = (r && r.ok && r.topology) || { nodes: [], edges: [] };
      var lang = settings.language || "zh";
      // 数据签名：语言 + 节点 id 集合 + 边数。未变化时跳过重建，彻底消除 4s 自动刷新导致的闪动
      var sig = lang + "|" + (topo.nodes || []).map(function (n) { return n.id; }).sort().join(",") + "|" + (topo.edges || []).length;
      if (sig === _topoSig && _topoHtml) return;   // 数据未变：保持已恢复的缓存，无需重绘
      _topoSig = sig;
      if (!topo.nodes.length) {
        _topoHtml = '<div class="topo-mini-empty">' + esc(t("topoMiniEmpty")) + '</div>';
        el.innerHTML = _topoHtml;
        return;
      }
      var W = 320, H = 190, cx = W / 2, cy = H / 2;
      var n = topo.nodes.length;
      var R = Math.min(W, H) / 2 - 26;
      // 静态径向布局：target 居中，其余环形分布（无力学模拟，轻量预览）
      var nodes = topo.nodes.map(function (nd, i) {
        if (nd.type === "target") return Object.assign({}, nd, { x: cx, y: cy });
        var ang = (i / Math.max(1, n - 1)) * Math.PI * 2;
        return Object.assign({}, nd, { x: cx + Math.cos(ang) * R, y: cy + Math.sin(ang) * R });
      });
      var byId = {}; nodes.forEach(function (x) { byId[x.id] = x; });
      var eHtml = "", nHtml = "";
      topo.edges.forEach(function (e) {
        var a = byId[e.source], b = byId[e.target];
        if (!a || !b) return;
        if (e.kind === "chain") {
          eHtml += '<line stroke="#ff5a5a" stroke-width="1.1" stroke-dasharray="3 3" opacity=".7" x1="' + a.x +
            '" y1="' + a.y + '" x2="' + b.x + '" y2="' + b.y + '"/>';
        } else {
          eHtml += '<line stroke="rgba(140,150,170,.3)" stroke-width="1" x1="' + a.x +
            '" y1="' + a.y + '" x2="' + b.x + '" y2="' + b.y + '"/>';
        }
      });
      nodes.forEach(function (nd) {
        var r = Math.max(3, _topoNodeRadius(nd) * 0.5);  // 缩小半径适配缩略尺寸
        var fill = _topoNodeColor(nd);
        var ring = (nd.maxRisk && nd.type !== "port")
          ? ' stroke="' + _topoRiskColor(nd.maxRisk) + '" stroke-width="2"'
          : ' stroke="rgba(255,255,255,.2)" stroke-width="1"';
        nHtml += '<circle cx="' + nd.x + '" cy="' + nd.y + '" r="' + r + '" fill="' + fill + '"' + ring + '/>';
      });
      _topoHtml = '<svg class="topo-mini-svg" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="' +
        esc(t("topology")) + '">' + eHtml + nHtml + '</svg>' +
        '<div class="topo-mini-legend">' +
          '<span><i class="dot" style="background:var(--accent)"></i>' + esc(t("topoTarget")) + '</span>' +
          '<span><i class="dot" style="background:#2bb3a3"></i>' + esc(t("topoHost")) + '</span>' +
          '<span><i class="dot" style="background:#8a93a6"></i>' + esc(t("topoPort")) + '</span>' +
          '<span><i class="dot" style="background:#ff5a5a"></i>' + esc(t("topoFinding")) + '</span>' +
          '<span><i class="line"></i>' + esc(t("topoChain")) + '</span>' +
        '</div>';
      el.innerHTML = _topoHtml;
    }).catch(function () {
      el = document.getElementById("topo-mini");
      // 仅在尚无任何成功缓存（首次加载即失败）时回填空态；已有缓存则保留，不回退到错误态
      if (el && !_topoHtml) el.innerHTML = '<div class="topo-mini-empty">' + esc(t("topoMiniEmpty")) + '</div>';
    });
  }

  // —— UI 阶段 5：目标行内展开（懒加载扫描，DOM 局部插入，不重渲染整个视图以保留表单状态） ——
  var _tgtScansCache = null;     // list_scans 结果缓存，首次展开任一目标时加载
  function _ensureTgtScans() {
    if (_tgtScansCache) return Promise.resolve(_tgtScansCache);
    return call("list_scans", 100).then(function (scans) { _tgtScansCache = scans || []; return _tgtScansCache; });
  }
  function toggleTgt(tid) {
    var row = document.querySelector('tr[data-tid="' + tid + '"]');
    if (!row) return;
    var toggle = row.querySelector(".tgt-toggle");
    var next = row.nextElementSibling;
    var existing = (next && next.classList && next.classList.contains("tgt-detail-row")) ? next : null;
    if (existing) {  // 收起
      existing.remove();
      if (toggle) toggle.classList.remove("open");
      return;
    }
    if (toggle) toggle.classList.add("open");
    var detail = document.createElement("tr");
    detail.className = "tgt-detail-row";
    detail.innerHTML = '<td colspan="9"><div class="tgt-detail"><span class="spinner"></span>' +
      (settings.language === "en" ? "Loading…" : "加载中…") + '</div></td>';
    row.parentNode.insertBefore(detail, row.nextSibling);
    _ensureTgtScans().then(function (scans) {
      var mine = scans.filter(function (s) { return s.target_id === tid; });
      detail.innerHTML = '<td colspan="9">' + renderTgtDetail(tid, mine) + '</td>';
    }).catch(function () {
      detail.innerHTML = '<td colspan="9"><div class="tgt-detail"><span class="err">' +
        (settings.language === "en" ? "Load failed" : "加载失败") + '</span></div></td>';
    });
  }
  function renderTgtDetail(tid, scans) {
    var en = settings.language === "en";
    var recent = scans.slice(0, 5);
    var completed = scans.filter(function (s) { return s.status === "completed"; }).length;
    var html = '<div class="tgt-detail">' +
      '<div class="td-col">' +
        '<div class="td-mini">' +
          '<div class="m"><b>' + scans.length + '</b><span>' + esc(t("tgtScansCount").replace("{n}", scans.length)) + '</span></div>' +
          '<div class="m"><b>' + completed + '</b><span>' + (en ? "Completed" : "已完成") + '</span></div>' +
        '</div>' +
        '<h4>' + esc(t("tgtRecentScans")) + '</h4>';
    if (recent.length) {
      html += '<table><thead><tr><th>#</th><th>' + esc(t("name")) + '</th><th>' + esc(t("status")) +
        '</th><th>' + esc(t("stage")) + '</th><th></th></tr></thead><tbody>';
      recent.forEach(function (s, i) {
        html += '<tr><td>' + (i + 1) + '</td><td>' + esc(s.name) + '</td><td>' + stageTag(s.status) +
          '</td><td>' + esc(s.stage || "") + '</td><td><a class="btn sm" href="#scan/' + s.id + '">' +
          (en ? "Detail" : "详情") + '</a></td></tr>';
      });
      html += '</tbody></table>';
    } else {
      html += '<div class="td-empty">' + esc(t("tgtNoScans")) + '</div>';
    }
    html += '</div>' +
      '<div class="td-col" style="max-width:200px;flex:none">' +
        '<a class="btn sm" href="#target/' + tid + '">' + esc(t("tgtViewCenter")) + '</a>' +
      '</div></div>';
    return html;
  }

  // —— 命令面板（吸收 A 的 ⌘K，模糊搜索 + 键盘导航） ——
  var _cmdItems = null, _cmdMatches = [], _cmdIdx = 0;
  function cmdItems() {
    if (_cmdItems) return _cmdItems;
    _cmdItems = [];
    NAV_DATA.forEach(function (sec) {
      sec.items.forEach(function (it) {
        _cmdItems.push({ cat: t(sec.group), label: t(it.key), view: it.view, ico: it.ico });
      });
    });
    _cmdItems.push({ cat: t("grpSystem"), label: t("exportDiag"), action: "diag", ico: "📦" });
    return _cmdItems;
  }
  function openCmdPalette() {
    var ov = document.getElementById("cmd-overlay");
    if (!ov) return;
    _cmdItems = null;                 // 重建以拾取语言变化
    var items = cmdItems();
    _cmdMatches = items.slice(); _cmdIdx = 0;
    ov.innerHTML = '<div class="cmd-panel"><div class="cmd-in"><span class="ico" style="color:var(--muted)">⌘</span>' +
      '<input id="cmd-input" placeholder="' + esc(t("cmdPlaceholder")) + '"></div>' +
      '<div class="cmd-list" id="cmd-list"></div></div>';
    ov.classList.remove("hidden");
    renderCmdList();
    var inp = document.getElementById("cmd-input");
    if (!inp) return;
    inp.focus();
    inp.addEventListener("input", function () {
      var q = inp.value.trim().toLowerCase();
      _cmdMatches = !q ? items.slice() : items.filter(function (it) {
        return (it.label || "").toLowerCase().indexOf(q) >= 0 ||
               (it.cat || "").toLowerCase().indexOf(q) >= 0 ||
               (it.view || "").indexOf(q) >= 0;
      });
      _cmdIdx = 0; renderCmdList();
    });
    inp.addEventListener("keydown", function (e) {
      // 面板打开（焦点在输入框）时 Ctrl/⌘+K 仍可切换关闭；全局快捷键在 INPUT 焦点下会 return，故在此单独处理
      if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) { e.preventDefault(); closeCmdPalette(); return; }
      if (e.key === "ArrowDown") { e.preventDefault(); _cmdIdx = Math.min(_cmdIdx + 1, _cmdMatches.length - 1); renderCmdList(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); _cmdIdx = Math.max(_cmdIdx - 1, 0); renderCmdList(); }
      else if (e.key === "Enter") { e.preventDefault(); runCmd(_cmdMatches[_cmdIdx]); }
      else if (e.key === "Escape") { e.preventDefault(); closeCmdPalette(); }
    });
  }
  function renderCmdList() {
    var box = document.getElementById("cmd-list");
    if (!box) return;
    if (!_cmdMatches.length) { box.innerHTML = '<div class="cmd-empty">' + esc(t("cmdEmpty")) + '</div>'; return; }
    box.innerHTML = _cmdMatches.map(function (it, i) {
      return '<div class="cmd-item' + (i === _cmdIdx ? " active" : "") + '" data-i="' + i + '">' +
        '<span class="ci-ico" aria-hidden="true">' + (it.ico || "•") + '</span>' +
        '<span>' + esc(it.label) + '</span>' +
        '<span class="ci-cat">' + esc(it.cat) + '</span>' +
        '<span class="ci-kbd">' + esc(t("cmdGoTo")) + '</span></div>';
    }).join("");
    box.querySelectorAll(".cmd-item").forEach(function (el) {
      el.addEventListener("mouseenter", function () {
        _cmdIdx = parseInt(el.getAttribute("data-i"), 10);
        // 仅切换高亮，不重建整个列表：避免鼠标点击在 DOM 重建瞬间丢失（mousedown/mouseup 落在不同节点 → 不触发 click）
        box.querySelectorAll(".cmd-item").forEach(function (x) { x.classList.toggle("active", x === el); });
      });
      el.addEventListener("click", function () { runCmd(_cmdMatches[parseInt(el.getAttribute("data-i"), 10)]); });
    });
  }
  function runCmd(it) {
    if (!it) return;
    closeCmdPalette();
    if (it.view) navigate("#" + it.view);
    else if (it.action === "diag") {
      call("export_diagnostic").then(function () { toast(settings.language === "en" ? "Exported" : "已导出", "ok"); }).catch(function () {});
    }
  }
  function closeCmdPalette() {
    var ov = document.getElementById("cmd-overlay");
    if (ov && !ov.classList.contains("hidden")) { ov.classList.add("hidden"); ov.innerHTML = ""; }
  }

  // —— 漏洞详情抽屉（吸收 C 的 4 Tab，替代发现弹窗；renderFindingModal 保留作 fallback） ——
  function openCtxPanel() {
    var p = document.getElementById("ctx-panel"), b = document.getElementById("ctx-backdrop");
    if (p) { p.classList.add("open"); p.setAttribute("aria-hidden", "false"); }
    if (b) { b.classList.add("open"); b.setAttribute("aria-hidden", "false"); }
    document.body.classList.add("ctx-open");
  }
  function closeCtxPanel() {
    var p = document.getElementById("ctx-panel"), b = document.getElementById("ctx-backdrop");
    if (p) { p.classList.remove("open"); p.setAttribute("aria-hidden", "true"); p.innerHTML = ""; }
    if (b) { b.classList.remove("open"); b.setAttribute("aria-hidden", "true"); }
    document.body.classList.remove("ctx-open");
  }
  function renderFindingDrawer(f) {
    var p = document.getElementById("ctx-panel");
    if (!p) { renderFindingModal(f); return; }   // 骨架缺失时降级到弹窗
    f = locVuln(f);
    var lvl = f.evidence_level || "L1";
    var meta = null;
    try { meta = f.evidence_meta ? JSON.parse(f.evidence_meta) : null; } catch (e) { meta = null; }
    var tabs = [
      { id: "overview", label: t("ctxTabOverview") },
      { id: "evidence", label: t("ctxTabEvidence") },
      { id: "reqresp", label: t("ctxTabReqResp") },
      { id: "cvss", label: t("ctxTabCvss") },
    ];
    p.innerHTML =
      '<div class="ctx-head">' +
        '<span class="evbadge ev-' + esc(lvl) + '" title="' + esc(t("ev" + lvl + "d")) + '">' + esc(t("ev" + lvl)) + '</span>' +
        '<span class="ctx-title" title="' + esc(f.category) + ' #' + f.id + '">' + esc(t("findingDetail")) + ' #' + f.id + '</span>' +
        '<button class="ctx-close" id="ctx-close" title="' + esc(t("drawerClose")) + '" aria-label="' + esc(t("close")) + '">×</button>' +
      '</div>' +
      '<div class="ctx-tabs">' + tabs.map(function (tb, i) {
        return '<button class="ctx-tab' + (i === 0 ? " active" : "") + '" data-tab="' + tb.id + '">' + esc(tb.label) + '</button>';
      }).join("") + '</div>' +
      '<div class="ctx-body findbody">' +
        '<div class="ctx-pane active" data-pane="overview">' + drawerOverview(f) + '</div>' +
        '<div class="ctx-pane" data-pane="evidence">' + drawerEvidence(f) + '</div>' +
        '<div class="ctx-pane" data-pane="reqresp">' + (meta ? renderDiff(meta) : '<p class="note-inline">' + esc(t("noReqResp")) + '</p>') + '</div>' +
        '<div class="ctx-pane" data-pane="cvss">' + renderCvssCalc(f) + '</div>' +
      '</div>';
    openCtxPanel();
    var cl = document.getElementById("ctx-close");
    if (cl) cl.addEventListener("click", closeCtxPanel);
    p.querySelectorAll(".ctx-tab").forEach(function (tab) {
      tab.addEventListener("click", function () {
        var id = tab.getAttribute("data-tab");
        p.querySelectorAll(".ctx-tab").forEach(function (x) { x.classList.toggle("active", x === tab); });
        p.querySelectorAll(".ctx-pane").forEach(function (pane) { pane.classList.toggle("active", pane.getAttribute("data-pane") === id); });
        if (id === "cvss") bindCvssEvents(f);
      });
    });
    bindCopyPoc(f);
  }
  function drawerOverview(f) {
    return '<div class="frow">' + riskBadge(f.risk) + verifyBadge(f.verification_status) +
      (f.cwe ? '<span class="kv"><b>CWE</b>' + esc(f.cwe) + '</span>' : '') +
      (f.endpoint ? '<span class="kv"><b>' + (settings.language === "en" ? "Endpoint" : "端点") + '</b>' + esc(f.endpoint) + '</span>' : '') +
      (f.http_method ? '<span class="kv"><b>' + (settings.language === "en" ? "Method" : "方法") + '</b>' + esc(f.http_method) + '</span>' : '') +
      '</div>' +
      '<h3 style="margin:6px 0">' + esc(f.category) + ' — ' + esc(f.title) + '</h3>' +
      (f.remediation ? '<div class="fsection">' + esc(t("remediation")) + '</div><p style="margin:4px 0 10px">' + esc(f.remediation) + '</p>' : '') +
      (f.detail ? '<p style="margin:6px 0">' + esc(f.detail) + '</p>' : '');
  }
  function drawerEvidence(f) {
    var h = '<div class="fsection">' + esc(t("evidenceText")) + '</div>' +
      '<pre>' + esc(redact(f.evidence || (settings.language === "en" ? "(empty)" : "（空）"))) + '</pre>';
    if (f.poc_script) {
      h += '<div class="fsection">' + esc(t("poc")) + '</div><pre>' + esc(f.poc_script) + '</pre>' +
        '<button class="btn sm" id="fd-copy">' + esc(t("copyPoc")) + '</button>';
    }
    return h;
  }
  function bindCopyPoc(f) {
    var btn = document.getElementById("fd-copy");
    if (!btn) return;
    btn.addEventListener("click", function () {
      try {
        if (navigator.clipboard) navigator.clipboard.writeText(f.poc_script);
        else { var ta = document.createElement("textarea"); ta.value = f.poc_script; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); }
        toast(settings.language === "en" ? "Copied" : "已复制", "ok");
      } catch (e) { toast(settings.language === "en" ? "Copy failed" : "复制失败", "err"); }
    });
  }
  function bindCvssEvents(f) {
    var metrics = document.getElementById("cvss-metrics");
    if (metrics && !metrics._bound) {
      metrics._bound = true;
      metrics.querySelectorAll("select[data-cvss]").forEach(function (sel) { sel.addEventListener("change", recomputeCvss); });
    }
    var save = document.getElementById("cvss-save");
    if (save && !save._bound) {
      save._bound = true;
      save.addEventListener("click", function () {
        var vec = save.getAttribute("data-vec") || (f.cvss_vector || "");
        var score = cvss31Score(vec);
        if (score == null) { toast(settings.language === "en" ? "Invalid vector" : "向量非法", "err"); return; }
        call("set_finding_cvss", f.id, score, vec).then(function (r) {
          if (!r.ok) { toast(r.error || (settings.language === "en" ? "Save failed" : "保存失败"), "err"); return; }
          toast(settings.language === "en" ? "Rating updated" : "评级已更新", "ok");
        });
      });
    }
    recomputeCvss();   // 进入 CVSS Tab 时刷新分数显示
  }

  // 一次性绑定顶栏 / 抽屉遮罩点击
  var _chromeBound = false;
  function bindChromeEvents() {
    if (_chromeBound) return; _chromeBound = true;
    var search = document.getElementById("tb-search");
    if (search) search.addEventListener("click", function () { openCmdPalette(); });
    var si = document.getElementById("tb-search-input");
    if (si) si.addEventListener("focus", function () { openCmdPalette(); });
    var reload = document.getElementById("tb-reload");
    if (reload) reload.addEventListener("click", function () { router(); toast(settings.language === "en" ? "Reloaded" : "已刷新", "ok"); });
    var bell = document.getElementById("tb-bell");
    if (bell) bell.addEventListener("click", function () { navigate("#reviews"); });
    var bd = document.getElementById("ctx-backdrop");
    if (bd) bd.addEventListener("click", closeCtxPanel);
    // 点击命令面板遮罩（面板外区域）关闭，修复"点了没反应、没法退出"
    var cmdOv = document.getElementById("cmd-overlay");
    if (cmdOv) cmdOv.addEventListener("click", function (e) { if (e.target === cmdOv) closeCmdPalette(); });
    // 初始化粒子网络动态背景 + 鼠标跟随按钮效果 + 鼠标拖尾（方案B 动态特效）
    // 主开关 fx_enabled：关闭后统一禁用所有动态/静态视觉效果（鼠标跟随、自定义光标、
    // 背景粒子、扫描线、暗角、噪点、按钮光晕），恢复系统原生外观。
    applyFxClass();
    if (settings.fx_enabled !== "0") {
      initBgFx();
      initBtnGlow();
    }
    // 应用内「退出」按钮：二次确认后请求后端干净退出（避免误关丢失进行中的扫描）
    var exitBtn = document.getElementById("tb-exit");
    if (exitBtn) exitBtn.addEventListener("click", function () {
      confirmDialog(
        settings.language === "en" ? "Exit PenScope?" : "退出 PenScope？",
        settings.language === "en" ? "This will close the application completely; any running scans will be stopped."
          : "将完全关闭应用程序，正在进行的扫描会被终止。",
        function () { call("exit_app"); }
      );
    });
  }

  // 视觉效果主开关：根据 settings.fx_enabled 切换 body.fx-off，
  // 由 CSS 隐藏扫描线 / 暗角 / 噪点 / 自定义光标，并停用按钮光晕。
  function applyFxClass() {
    if (settings.fx_enabled === "0") document.body.classList.add("fx-off");
    else document.body.classList.remove("fx-off");
  }

  // —— 粒子网络动态背景（增强版：更多粒子 + 特色运动 + 自适应）——
  // 性能保障：reduced-motion 禁用 / 页面隐藏暂停 / 粒子数自适应屏幕尺寸 / DPR 上限 2
  function initBgFx() {
    var canvas = document.getElementById("bg-fx");
    if (!canvas) return;
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (settings.bg_particles_enabled === "0") return;  // 用户可在设置中关闭背景粒子
    var ctx = canvas.getContext("2d");
    if (!ctx) return;
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var w = 0, h = 0, particles = [], rafId = null, running = false, tick = 0;
    // 粒子颜色池：混合 SOC 青紫 + 赛博红橙（参考 vulnclaw.com）
    var COLORS = [
      { dot: "rgba(34,211,238,", line: "rgba(34,211,238," },  // 青
      { dot: "rgba(139,92,246,", line: "rgba(139,92,246," },  // 紫
      { dot: "rgba(255,59,92,",  line: "rgba(255,59,92,"  },  // 红
      { dot: "rgba(255,107,53,", line: "rgba(255,107,53," },  // 橙
      { dot: "rgba(99,102,241,", line: "rgba(99,102,241," },  // 靛蓝
    ];

    function initParticles(n) {
      particles = [];
      for (var i = 0; i < n; i++) {
        var ci = i % COLORS.length;
        particles.push({
          x: Math.random() * w, y: Math.random() * h,
          vx: (Math.random() - 0.5) * 0.4, vy: (Math.random() - 0.5) * 0.4,
          r: Math.random() * 2.8 + 0.8,
          baseR: 0,      // 基准半径，用于脉动
          phase: Math.random() * Math.PI * 2,  // 脉动相位
          pulseSpeed: 0.02 + Math.random() * 0.03,
          twPhase: Math.random() * Math.PI * 2,  // 闪烁相位
          twSpeed: 0.015 + Math.random() * 0.02,  // 闪烁速度
          ci: ci, glow: Math.random() * 0.5 + 0.3,  // 发光强度
          orbitAngle: Math.random() * Math.PI * 2,
          orbitSpeed: (Math.random() - 0.5) * 0.008,
          orbitRadius: Math.random() * 20 + 5,
          orbitCx: Math.random() * w, orbitCy: Math.random() * h
        });
        particles[i].baseR = particles[i].r;
      }
    }
    function resize() {
      w = window.innerWidth; h = window.innerHeight;
      canvas.width = w * dpr; canvas.height = h * dpr;
      canvas.style.width = w + "px"; canvas.style.height = h + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      // 粒子密度增强：随屏幕尺寸 + 用户密度设置自适应（上限 240，下限 64）
      var dens = parseFloat(settings.bg_particle_density || "1");
      var target = Math.min(240, Math.max(64, Math.floor(w * h / 13000 * dens)));
      // 保留部分旧粒子的位置特征，避免每次 resize 重新分布导致视觉跳跃
      if (particles.length > 0) {
        var old = particles;
        initParticles(target);
        for (var i = 0; i < Math.min(old.length, particles.length); i++) {
          particles[i].x = old[i].x;
          particles[i].y = old[i].y;
        }
      } else {
        initParticles(target);
      }
    }
    function step() {
      if (!running) return;
      tick++;
      ctx.clearRect(0, 0, w, h);
      var maxDist = 160, maxDist2 = maxDist * maxDist;
      // 连线
      for (var i = 0; i < particles.length; i++) {
        var p = particles[i];
        // 特色运动：轨道偏移 + 脉动
        p.orbitAngle += p.orbitSpeed;
        var ox = Math.cos(p.orbitAngle) * p.orbitRadius * 0.1;
        var oy = Math.sin(p.orbitAngle) * p.orbitRadius * 0.1;
        // 全局流场：随相位缓慢摆动的"飘动"运动，使粒子场更有生命力（特色运动）
        var drift = Math.sin(tick * 0.004 + p.phase) * 0.06;
        p.x += p.vx + ox * 0.02 + drift;
        p.y += p.vy + oy * 0.02 + Math.cos(tick * 0.004 + p.phase) * 0.04;
        // 脉动半径
        p.r = p.baseR + Math.sin(tick * p.pulseSpeed + p.phase) * 0.6;
        // 边界反弹
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
        // 粒子间连线
        for (var j = i + 1; j < particles.length; j++) {
          var q = particles[j];
          var dx = p.x - q.x, dy = p.y - q.y, d2 = dx * dx + dy * dy;
          if (d2 < maxDist2) {
            var a = (1 - Math.sqrt(d2) / maxDist) * 0.25;
            var c = p.ci < 2 ? COLORS[p.ci] : COLORS[q.ci % COLORS.length];
            ctx.strokeStyle = c.line + a + ")";
            ctx.lineWidth = 0.5;
            ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y); ctx.stroke();
          }
        }
      }
      // 粒子（带光晕 + 脉动）
      for (var k = 0; k < particles.length; k++) {
        var pt = particles[k];
        var c = COLORS[pt.ci];
        var tw = 0.6 + 0.4 * Math.sin(tick * pt.twSpeed + pt.twPhase);  // 闪烁
        ctx.shadowColor = c.dot.slice(0, -1) + "1)";
        ctx.shadowBlur = pt.glow * 10 * tw;
        ctx.fillStyle = c.dot + (pt.glow * tw) + ")";
        ctx.beginPath(); ctx.arc(pt.x, pt.y, Math.max(0.5, pt.r), 0, Math.PI * 2); ctx.fill();
        ctx.shadowBlur = 0;
      }
      rafId = requestAnimationFrame(step);
    }
    function start() { if (!running) { running = true; step(); } }
    function stop() { running = false; if (rafId) { cancelAnimationFrame(rafId); rafId = null; } }

    resize();
    window.addEventListener("resize", resize);
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) stop(); else start();
    });
    start();
  }

  // —— 鼠标跟随按钮光晕（.btn-glow，事件委托，零逐元素绑定）——
  // —— 自定义光标跟随（参考 vulnclaw.com 红点 + 轮廓）——
  function initBtnGlow() {
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    // 按钮光晕委托（事件委托，零逐元素绑定）
    document.addEventListener("mousemove", function (e) {
      var el = e.target;
      if (!el || !el.closest) return;
      var btn = el.closest(".btn-glow");
      if (!btn) return;
      var r = btn.getBoundingClientRect();
      btn.style.setProperty("--mx", (e.clientX - r.left) + "px");
      btn.style.setProperty("--my", (e.clientY - r.top) + "px");
    }, { passive: true });
  }

  // —— 面板透明度应用 ——
  function applyPanelOpacity() {
    var op = parseFloat(settings.panel_opacity || "0.95");
    document.documentElement.style.setProperty("--panel-opacity", op);
    document.documentElement.style.setProperty("--panel2-opacity", Math.min(1, op + 0.03));
  }
  // —— 面板透明度预览（设置面板拖动滑块时实时预览）——
  function applyPanelOpacityPreview(val) {
    var op = parseFloat(val || "0.95");
    document.documentElement.style.setProperty("--panel-opacity", op);
    document.documentElement.style.setProperty("--panel2-opacity", Math.min(1, op + 0.03));
  }

  // ---------------- 设置应用 ----------------
  function applySettings() {
    document.documentElement.setAttribute("data-theme", settings.theme);
    document.documentElement.setAttribute("data-layout", settings.layout);
    document.documentElement.style.setProperty("--font-base", settings.font_size + "px");
    applyPanelOpacity();
    applyFxClass();
    // 数据驱动渲染外围 chrome（顺带修复旧 map 数组漏 topology 的隐性 bug）
    renderNav();
    renderTopbar();
    renderStatusBar();
    var sf = document.querySelector(".side-foot");
    if (sf) {
      sf.textContent = "AI"; // rail 模式下仅显示品牌缩写，长文本移至 title tooltip
      sf.title = settings.language === "en"
        ? "Local desktop tool · no login required"
        : "本地桌面工具 · 无需登录";
    }
  }
  function loadSettings() {
    return call("get_settings").then(function (s) {
      settings = Object.assign(settings, s || {});
      applySettings();
    }).catch(function () {});
  }

  // ---------------- 路由 ----------------
  function parseHash() {
    var h = (location.hash || "#dashboard").replace(/^#/, "");
    var parts = h.split("/");
    current.view = parts[0] || "dashboard";
    current.param = parts[1] || null;
  }
  function navigate(hash) { location.hash = hash; }

  function router() {
    clearScanTimer();   // 切换视图时取消对扫描界面的自动跟随，杜绝"退出后又被强制进入"
    if (topoSim && topoSim.raf) { cancelAnimationFrame(topoSim.raf); topoSim.raf = null; }  // 停止拓扑模拟动画
    parseHash();
    refreshChrome();    // nav 高亮 + 顶栏标题 + 关闭命令面板
    closeCtxPanel();    // 进入新视图时关闭漏洞详情抽屉
    var map = {
      dashboard: renderDashboard, targets: renderTargets, scans: renderScans,
      scan: renderScanDetail, target: renderTargetCenter, reviews: renderReviews, scheduler: renderScheduler,
      audit: renderAudit, settings: renderSettings, topology: renderTopology
    };
    (map[current.view] || renderDashboard)();
  }

  // ---------------- 仪表盘 ----------------
  function renderDashboard() {
    Promise.all([call("list_targets"), call("list_scans", 20), call("list_reviews")])
      .then(function (res) {
        var targets = res[0], scans = res[1], reviews = res[2];
        var running = scans.filter(function (s) {
          return s.status === "running" || s.status === "queued" || s.status === "paused";
        }).length;
        var st = { done: 0, run: 0, fail: 0, other: 0 };
        scans.forEach(function (s) {
          if (s.status === "completed") st.done++;
          else if (s.status === "running" || s.status === "queued" || s.status === "paused") st.run++;
          else if (s.status === "failed") st.fail++;
          else st.other++;
        });
        var spark = _scansByDay(scans, 14);
        var en = settings.language === "en";
        var html = '<h1>' + t("dashboard") + '</h1>' +
          '<p class="muted">' + (en
            ? "AI-driven automated penetration testing (local desktop tool) · high-risk actions require manual confirmation"
            : "AI 驱动的自动化渗透测试（本地桌面工具）· 高危动作需人工确认") + '</p>' +
          renderGuideBar({ targets: targets, scans: scans, reviews: reviews }) +
          '<div class="grid12">' +
            '<div class="kpi"><div class="kpi-lbl">' + t("targets") + '</div><div class="kpi-num">' + targets.length + '</div></div>' +
            '<div class="kpi"><div class="kpi-lbl">' + t("scans") + '</div><div class="kpi-num">' + scans.length + '</div>' +
              sparkSVG(spark, "var(--accent2)") + '</div>' +
            '<div class="kpi warn"><div class="kpi-lbl">' + t("reviews") + '</div><div class="kpi-num">' + reviews.length + '</div></div>' +
            '<div class="kpi"><div class="kpi-lbl">' + t("statusBarRunning") + '</div><div class="kpi-num">' + running + '</div></div>' +
          '</div>' +
          '<div class="card evt-card"><div class="evt-head"><h2 style="margin:0;font-size:15px">' + t("evtFeedTitle") + '</h2>' +
            '<span class="evt-live"><span class="evt-dot" aria-hidden="true"></span>' + t("evtLive") + '</span></div>' +
            '<ul class="evt-feed" id="evt-feed"></ul></div>' +
          '<div class="ring-card">' + donutSVG([
            { value: st.done, color: "var(--low)" },
            { value: st.run, color: "var(--warn)" },
            { value: st.fail, color: "var(--danger)" },
            { value: st.other, color: "var(--muted)" }
          ]) + '<div class="ring-legend">' +
            '<div class="li"><span class="dot" style="background:var(--low)"></span><span class="lbl">' + (en ? "Completed" : "完成") + '</span><b>' + st.done + '</b></div>' +
            '<div class="li"><span class="dot" style="background:var(--warn)"></span><span class="lbl">' + (en ? "Running/Queued" : "进行/排队") + '</span><b>' + st.run + '</b></div>' +
            '<div class="li"><span class="dot" style="background:var(--danger)"></span><span class="lbl">' + (en ? "Failed" : "失败") + '</span><b>' + st.fail + '</b></div>' +
            '<div class="li"><span class="dot" style="background:var(--muted)"></span><span class="lbl">' + (en ? "Other" : "其它") + '</span><b>' + st.other + '</b></div>' +
          '</div></div>' +
        '<div class="topo-mini-card" id="topo-mini-card" title="' + esc(t("topoMiniHint")) + '">' +
          '<div class="topo-mini-head"><h2 style="margin:0;font-size:15px">' + esc(t("topoMiniTitle")) + '</h2>' +
          '<span class="tm-hint">↗ ' + esc(t("topoMiniHint")) + '</span></div>' +
          '<div id="topo-mini"><span class="spinner"></span>' + (en ? "Loading…" : "加载中…") + '</div>' +
        '</div>';
        html += '<div class="card"><h2 style="margin:0 0 10px">' + t("recentScans") + '</h2>';
        if (scans.length) {
          html += '<table><thead><tr><th>#</th><th>' + t("name") + '</th><th>' + t("targetId") + '</th><th>' + t("status") + '</th><th>' + t("stage") + '</th><th></th></tr></thead><tbody>';
          scans.forEach(function (s, i) {
            html += '<tr><td>' + (i + 1) + '</td><td>' + esc(s.name) + '</td><td>' + s.target_id +
              '</td><td>' + stageTag(s.status) + '</td><td>' + esc(s.stage || "") +
              '</td><td><a class="btn sm" href="#scan/' + s.id + '">' + (settings.language === "en" ? "Detail" : "详情") + '</a></td></tr>';
          });
          html += "</tbody></table>";
        } else html += '<p class="muted">' + t("noData") + '</p>';
        html += "</div>";
        if (reviews.length) {
          html += '<div class="card" style="border-color:var(--warn)"><h2 style="margin:0 0 8px">⚠ ' + t("pendingReviews") + '（' + reviews.length + '）</h2>' +
            '<p class="muted">' + (settings.language === "en" ? "Approve/reject gated actions in " : "请在 ") +
            '<a href="#reviews">' + t("reviews") + '</a>' + (settings.language === "en" ? "." : " 中批准/拒绝。") + '</p>' +
            '<ul>' + reviews.map(function (r) { return '<li><span class="tag">' + esc(r.kind) + "</span> " + esc(r.note) + "</li>"; }).join("") + "</ul></div>";
        }
        paintView(html);
        bindGuideBar();
        renderTopoMini();
        renderEvtFeed();   // 方案B 事件流：填充实时活动卡片
        var tmCard = document.getElementById("topo-mini-card");
        if (tmCard) tmCard.addEventListener("click", function () { navigate("#topology"); });
      })
      .catch(function (e) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Load failed: " : "加载失败：") + esc(e) + "</div>"; });
  }

  // ---------------- 授权目标 ----------------
  function renderTargets() {
    _tgtScansCache = null;  // 每次进入目标视图失效缓存，保证展开数据新鲜
    Promise.all([call("list_targets"), call("list_target_tags")]).then(function (res) {
      var targets = res[0], allTags = res[1];
      // F-06：当前标签筛选（客户端过滤，避免每次打后端）
      var shown = (tagFilter == null) ? targets : targets.filter(function (x) {
        return (x.tags || []).indexOf(tagFilter) >= 0;
      });
      function tagChips(tags) {
        if (!tags || !tags.length) return '<span class="muted">—</span>';
        return tags.map(function (tg) {
          return '<button class="tag chip" data-tag="' + esc(tg) + '">' + esc(tg) + '</button>';
        }).join(" ");
      }
      var html = '<h1>' + t("targets") + '</h1>' +
        '<div class="warnbox">' + (settings.language === "en"
          ? "New targets must be authorized before scanning. Do not scan assets without permission."
          : "新增目标需勾选「我已获得该目标的书面授权」才会被批准可扫描。请勿对未授权资产发起扫描。") + '</div>' +
        '<div class="card"><h2 style="margin:0 0 10px">' + t("addTarget") + '</h2>' +
        '<form id="f-add"><div class="row">' +
          '<div><label>' + t("targetHost") + '</label><input name="host" placeholder="192.168.1.10 / example.com" required></div>' +
          '<div><label>' + t("portRange") + '</label><select name="port_range">' +
            '<option value="common">' + t("commonPorts") + '</option>' +
            '<option value="top1000">' + t("top1000") + '</option>' +
            '<option value="80,443,8080-8090">' + t("customPorts") + '</option>' +
          '</select></div></div>' +
        '<label>' + t("authNote") + '</label>' +
        '<textarea name="authorization" placeholder="PT-2026-0730"></textarea>' +
        '<label>' + t("note") + '</label><input name="note" placeholder="">' +
        '<div class="checkrow"><input type="checkbox" id="authorized" name="authorized"><label for="authorized">' + t("authorize") + '</label></div>' +
        '<div class="checkrow"><input type="checkbox" id="skip_tls" name="skip_tls"><label for="skip_tls">' + t("skipTlsVerify") + '</label></div>' +
        '<button class="btn btn-glow" style="margin-top:14px" type="submit">' + t("submitAuth") + '</button>' +
        '</form></div>' +
        '<div class="card"><h2 style="margin:0 0 10px">' + t("tagFilter") + '</h2>' +
        '<div class="tagbar" id="tagbar">' +
          '<button class="tag chip' + (tagFilter == null ? " on" : "") + '" data-tag="">' + t("allTags") + '</button>' +
          allTags.map(function (x) {
            return '<button class="tag chip' + (tagFilter === x.tag ? " on" : "") + '" data-tag="' + esc(x.tag) + '">' + esc(x.tag) + ' <span class="cnt">' + x.count + '</span></button>';
          }).join(" ") +
        '</div></div>' +
        '<div class="card"><h2 style="margin:0 0 10px">' + t("targetList") + '（' + shown.length + '）</h2><table>' +
        '<thead><tr><th></th><th>#</th><th>' + t("host") + '</th><th>' + t("ports") + '</th><th>' + t("tags") + '</th><th>' + t("authStatus") + '</th><th>' + t("authInfo") + '</th><th>' + t("tls") + '</th><th>' + t("actions") + '</th></tr></thead><tbody>';
      if (targets.length) {
        targets.forEach(function (row) {
          var st = row.status === "approved" ? '<span class="badge" style="background:var(--low)">' + (settings.language === "en" ? "Approved" : "已授权") + '</span>'
            : row.status === "pending" ? '<span class="badge" style="background:var(--warn)">' + (settings.language === "en" ? "Pending" : "待审批") + '</span>'
            : '<span class="badge" style="background:var(--danger)">' + (settings.language === "en" ? "Rejected" : "已拒绝") + '</span>';
          var act = '';
          if (row.status === "approved")
            act += '<button class="btn sm" data-scan="' + row.id + '">' + t("startScan") + '</button> ';
          act += '<button class="btn sm ghost" data-edit-target="' + row.id + '">' + t("edit") + '</button> ';
          act += '<button class="btn sm danger" data-del-target="' + row.id + '">' + t("delete") + '</button>';
          var tls = row.verify_tls == 0
            ? '<span class="badge" style="background:var(--warn)">' + (settings.language === "en" ? "Skip" : "跳过") + '</span>'
            : '<span class="badge" style="background:var(--low)">' + (settings.language === "en" ? "Verify" : "校验") + '</span>';
          html += '<tr data-tid="' + row.id + '"><td class="tgt-toggle" data-tid="' + row.id + '" title="' + t("tgtExpand") + '" role="button" tabindex="0">▸</td><td>' + row.id + '</td><td><a href="#target/' + row.id + '" style="color:var(--info);text-decoration:none">' + esc(row.host) + '</a></td><td>' + esc(row.port_range) +
            '</td><td>' + tagChips(row.tags) + '</td><td>' + st + '</td><td class="muted">' + esc(row.authorization) + '</td><td>' + tls + '</td><td>' + act + '</td></tr>';
        });
      } else html += '<tr><td colspan="9" class="muted" style="text-align:center">' + t("noData") + '</td></tr>';
      html += "</tbody></table></div>";
      view().innerHTML = html;

      // UI 阶段 5：目标行内展开（点击 chevron / 键盘 Enter 切换）
      view().querySelectorAll(".tgt-toggle").forEach(function (b) {
        function _go() { toggleTgt(parseInt(b.getAttribute("data-tid"), 10)); }
        b.addEventListener("click", _go);
        b.addEventListener("keydown", function (e) {
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); _go(); }
        });
      });

      // F-06 标签筛选：点击标签切换过滤，点击「全部」清除
      var bar = document.getElementById("tagbar");
      if (bar) bar.addEventListener("click", function (e) {
        var b = e.target.closest("[data-tag]");
        if (!b) return;
        var tg = b.getAttribute("data-tag");
        tagFilter = (tg === "") ? null : tg;
        renderTargets();
      });

      document.getElementById("f-add").addEventListener("submit", function (e) {
        e.preventDefault();
        var f = e.target;
        var authorized = f.authorized.checked;
        call("add_target", f.host.value, f.port_range.value, f.note.value, f.authorization.value, authorized, f.skip_tls.checked ? 0 : 1)
          .then(function (r) {
            if (r.ok) { toast(settings.language === "en" ? "Target added" : "目标已添加并授权", "ok"); f.reset(); renderTargets(); }
            else toast(r.error || (settings.language === "en" ? "Failed" : "添加失败"), "err");
          });
      });
      view().querySelectorAll("[data-scan]").forEach(function (b) {
        b.addEventListener("click", function () {
          var tid = b.getAttribute("data-scan");
          call("create_scan", tid, (settings.language === "en" ? "Manual scan #" : "手动扫描 #") + tid).then(function (r) {
            if (r.ok) navigate("#scan/" + r.sid);
            else toast(r.error || (settings.language === "en" ? "Failed" : "创建失败"), "err");
          });
        });
      });
      view().querySelectorAll("[data-edit-target]").forEach(function (b) {
        b.addEventListener("click", function () {
          var row = targets.find(function (x) { return x.id === parseInt(b.getAttribute("data-edit-target"), 10); });
          if (!row) return;
          call("get_auth_profile", row.id).then(function (ap) {
            var prof = (ap && ap.ok && ap.profile) || null;
            var configured = !!(prof && prof.configured);
            var extraText = (prof && prof.extra_fields && prof.extra_fields.length)
              ? prof.extra_fields.map(function (e) { return e[0] + "=" + e[1]; }).join("\n") : "";
            var body = '<div class="form-row"><label>' + t("targetHost") + '</label><input id="et-host" value="' + esc(row.host) + '"></div>' +
              '<div class="form-row"><label>' + t("portRange") + '</label><input id="et-port" value="' + esc(row.port_range) + '"></div>' +
              '<div class="form-row"><label>' + t("authNote") + '</label><textarea id="et-auth">' + esc(row.authorization || "") + '</textarea></div>' +
              '<div class="form-row"><label>' + t("note") + '</label><input id="et-note" value="' + esc(row.note || "") + '"></div>' +
              '<div class="form-row"><label>' + t("tags") + '</label><input id="et-tags" placeholder="' + t("tagPlaceholder") + '" value="' + esc((row.tags || []).join(", ")) + '"></div>' +
              '<div class="checkrow"><input type="checkbox" id="et-skip-tls"' + (row.verify_tls == 0 ? " checked" : "") + '><label for="et-skip-tls">' + t("skipTlsVerify") + '</label></div>' +
              // ---- C-06 认证配置（会话续期）折叠段 ----
              '<details class="authcfg"' + (configured ? " open" : "") + '>' +
                '<summary>' + esc(t("authConfig")) + ' · <span class="' + (configured ? "ok" : "muted") + '">' + (configured ? t("authConfigured") : t("authNotConfigured")) + '</span></summary>' +
                '<p class="muted" style="margin:6px 0">' + esc(t("authConfigDesc")) + '</p>' +
                '<div class="form-row"><label>' + t("authLoginUrl") + '</label><input id="et-auth-login" value="' + esc((prof && prof.login_url) || "") + '"></div>' +
                '<div class="form-row"><label>' + t("authMethod") + '</label><select id="et-auth-method"><option value="post"' + ((prof && prof.method === "get") ? "" : " selected") + '>POST</option><option value="get"' + ((prof && prof.method === "get") ? " selected" : "") + '>GET</option></select></div>' +
                '<div class="form-row"><label>' + t("authUserField") + '</label><input id="et-auth-ufield" placeholder="user / username / email" value="' + esc((prof && prof.user_field) || "") + '"></div>' +
                '<div class="form-row"><label>' + t("authPassField") + '</label><input id="et-auth-pfield" placeholder="pass / password / pwd" value="' + esc((prof && prof.pass_field) || "") + '"></div>' +
                '<div class="form-row"><label>' + t("authUsername") + '</label><input id="et-auth-user" value="' + esc((prof && prof.username) || "") + '"></div>' +
                '<div class="form-row"><label>' + t("authPassword") + '</label><input id="et-auth-pass" type="password" placeholder="' + esc(t("authKeepPass")) + '"></div>' +
                '<div class="form-row"><label>' + t("authExtraFields") + '</label><textarea id="et-auth-extra" placeholder="csrf_token=abc">' + esc(extraText) + '</textarea></div>' +
                '<div class="checkrow"><input type="checkbox" id="et-auth-csrf"' + ((prof && prof.csrf_autodetect === false) ? "" : " checked") + '><label for="et-auth-csrf">' + t("authCsrf") + '</label></div>' +
                '<div class="form-row"><label>' + t("authMaxRenew") + '</label><input id="et-auth-max" type="number" min="1" max="50" value="' + ((prof && prof.max_renewals) || 5) + '"></div>' +
                '<div class="form-row" style="flex-direction:row;gap:8px;align-items:center;flex-wrap:wrap">' +
                  '<button class="btn" id="et-auth-test" type="button">' + t("authTest") + '</button>' +
                  '<button class="btn" id="et-auth-save" type="button">' + t("authSaveConfig") + '</button>' +
                  (configured ? '<button class="btn danger" id="et-auth-del" type="button">' + t("authDelConfig") + '</button>' : '') +
                  '<span id="et-auth-msg" class="muted"></span>' +
                '</div>' +
              '</details>';
            openModal(t("editTarget"), body, function (root) {
              var tagsVal = root.querySelector("#et-tags").value;
              // ---- C-06 认证配置按钮 ----
              var msg = root.querySelector("#et-auth-msg");
              function _authSummary() { return root.querySelector("details.authcfg summary span"); }
              function collectAuth() {
                var extra = root.querySelector("#et-auth-extra").value.split("\n").map(function (l) { return l.trim(); })
                  .filter(Boolean).map(function (l) {
                    var i = l.indexOf("="); if (i < 0) return null; return [l.slice(0, i), l.slice(i + 1)];
                  }).filter(Boolean);
                return {
                  login_url: root.querySelector("#et-auth-login").value.trim(),
                  method: root.querySelector("#et-auth-method").value,
                  user_field: root.querySelector("#et-auth-ufield").value.trim(),
                  pass_field: root.querySelector("#et-auth-pfield").value.trim(),
                  username: root.querySelector("#et-auth-user").value.trim(),
                  password: root.querySelector("#et-auth-pass").value,
                  extra_fields: extra,
                  csrf_autodetect: root.querySelector("#et-auth-csrf").checked,
                  max_renewals: parseInt(root.querySelector("#et-auth-max").value, 10) || 5
                };
              }
              var testBtn = root.querySelector("#et-auth-test");
              if (testBtn) testBtn.addEventListener("click", function () {
                msg.textContent = t("authTesting"); msg.className = "muted";
                call("test_auth_profile", collectAuth()).then(function (r) {
                  if (r.ok && r.success) { msg.textContent = t("authTestPass"); msg.className = "ok"; }
                  else { msg.textContent = (r && r.message) || t("authTestFail"); msg.className = "err"; }
                });
              });
              var saveBtn = root.querySelector("#et-auth-save");
              if (saveBtn) saveBtn.addEventListener("click", function () {
                call("set_auth_profile", row.id, collectAuth()).then(function (r) {
                  if (r.ok) {
                    msg.textContent = t("authConfigured"); msg.className = "ok";
                    var s = _authSummary(); if (s) { s.textContent = t("authConfigured"); s.className = "ok"; }
                  } else { msg.textContent = (r && r.error) || "fail"; msg.className = "err"; }
                });
              });
              var delBtn = root.querySelector("#et-auth-del");
              if (delBtn) delBtn.addEventListener("click", function () {
                confirmDialog(t("authDelConfig"), t("authConfigDesc"), function () {
                  call("delete_auth_profile", row.id).then(function (r) {
                    if (r.ok) {
                      msg.textContent = t("authNotConfigured"); msg.className = "muted";
                      var s = _authSummary(); if (s) { s.textContent = t("authNotConfigured"); s.className = "muted"; }
                    }
                  });
                });
              });
              // ---- 目标元数据保存（原有逻辑） ----
              call("update_target", row.id,
                root.querySelector("#et-host").value,
                root.querySelector("#et-port").value,
                root.querySelector("#et-note").value,
                root.querySelector("#et-auth").value,
                root.querySelector("#et-skip-tls").checked ? 0 : 1).then(function (r) {
                if (r.ok) {
                  call("set_target_tags", row.id, tagsVal).then(function () {
                    toast(t("saved"), "ok"); root.innerHTML = ""; renderTargets();
                  });
                } else toast(r.error || (settings.language === "en" ? "Failed" : "保存失败"), "err");
              });
            });
          });
        });
      });
      view().querySelectorAll("[data-del-target]").forEach(function (b) {
        b.addEventListener("click", function () {
          var tid = b.getAttribute("data-del-target");
          confirmDialog(t("delete"), t("confirmDeleteTarget"), function () {
            call("delete_target", parseInt(tid, 10)).then(function (r) {
              toastUndo(r, t("deleted"), renderTargets);
            });
          });
        });
      });
    }).catch(function (e) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Load failed: " : "加载失败：") + esc(e) + "</div>"; });
  }

  // ---------------- 目标中心化视图（I-01） ----------------
  var tcIncludeArchived = false;  // P-04：是否在本视图展示已归档扫描
  var tagFilter = null;           // F-06：目标列表的标签筛选（null = 不过滤）
  function renderTargetCenter() {
    var tid = parseInt(current.param, 10);
    Promise.all([call("list_targets"), call("get_target_baseline", tid)]).then(function (res) {
      var targets = res[0], baseline = res[1] && res[1].baseline;
      var target = targets.find(function (x) { return x.id === tid; });
      if (!target) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Target not found" : "目标不存在") + '</div>'; return; }
      Promise.all([call("list_scans", 200, tcIncludeArchived), call("list_reviews")]).then(function (res) {
        var scans = res[0].filter(function (s) { return s.target_id === tid; });
        var fpromises = scans.filter(function (s) { return s.status === "completed"; })
          .map(function (s) { return call("findings_of", s.id).then(function (fs) {
            return fs.map(function (f) { f._sid = s.id; return f; }); }); });
        var cpromises = scans.filter(function (s) { return s.status === "completed"; })
          .map(function (s) { return call("get_chains", s.id).then(function (r) {
            return (r.ok && r.chains) ? r.chains : []; }); });
        Promise.all(fpromises.concat(cpromises)).then(function (lists) {
          var all = [].concat.apply([], lists.slice(0, fpromises.length));
          var allChains = [].concat.apply([], lists.slice(fpromises.length));
          var riskCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
          all.forEach(function (f) { if (riskCounts[f.risk] != null) riskCounts[f.risk]++; });
          var st = target.status === "approved" ? '<span class="badge" style="background:var(--low)">' + (settings.language === "en" ? "Approved" : "已授权") + '</span>'
            : target.status === "pending" ? '<span class="badge" style="background:var(--warn)">' + (settings.language === "en" ? "Pending" : "待审批") + '</span>'
            : '<span class="badge" style="background:var(--danger)">' + (settings.language === "en" ? "Rejected" : "已拒绝") + '</span>';
          var tls = target.verify_tls == 0 ? (settings.language === "en" ? "Skip" : "跳过") : (settings.language === "en" ? "Verify" : "校验");
          var dtl = settings.language === "en" ? "Detail" : "详情";
          var html = '<a class="back" href="#targets">' + t("back") + '</a>' +
            '<h1>' + t("targetCenter") + ' · ' + esc(target.host) + '</h1>' +
            '<div class="card"><div class="kv">' +
            t("host") + '：<code>' + esc(target.host) + '</code> ｜ ' + t("ports") + '：<code>' + esc(target.port_range) + '</code> ｜ ' +
            t("status") + '：' + st + ' ｜ ' + t("tls") + '：' + tls + '<br>' +
            t("authInfo") + '：<span class="muted">' + esc(target.authorization) + '</span>' +
            (target.tags && target.tags.length ? '<br>' + t("tags") + '：' + target.tags.map(function (tg) { return '<span class="tag">' + esc(tg) + '</span>'; }).join(" ") : '') +
            '</div>' +
            (target.status === "approved" ? '<button class="btn" style="margin-top:12px" id="tc-scan">' + t("startScan") + '</button>' : '') +
            '<button class="btn ghost" style="margin-top:12px;margin-left:8px" id="tc-compare">' + t("compareScans") + '</button>' +
            '<button class="btn ghost" style="margin-top:12px;margin-left:8px" id="tc-tags">' + t("editTags") + '</button>' +
            '<button class="btn ghost" style="margin-top:12px;margin-left:8px" id="tc-letter">' + t("authLetter") + '</button>' +
            '</div>';
          // F-05：资产基线卡片（指纹/标题/采集时间 + 最近变更）
          var cnMap = { fingerprint: t("fingerprint"), title: t("title"), headers: t("headers") || "响应头", ports: t("ports"), subdomains: t("subdomains") || "子域" };
          var baseHtml = '<div class="card"><h2 style="margin:0 0 10px">' + t("baseline") + '</h2>';
          if (!baseline) {
            baseHtml += '<p class="muted">' + esc(t("baselineNone")) + '</p>';
          } else {
            baseHtml += '<div class="kv">' + t("fingerprint") + '：<code>' + esc(baseline.fingerprint || "(空)") + '</code><br>' +
              t("title") + '：<span class="muted">' + esc(baseline.title || "(空)") + '</span><br>' +
              t("baselineCaptured") + '：<span class="muted">' + esc(baseline.captured_at || "-") + '</span></div>';
            if (baseline.last_change && baseline.last_change.length) {
              baseHtml += '<h3 style="margin:12px 0 6px">' + t("baselineChanges") + '（' + esc(baseline.last_change_at || "") + '）</h3>';
              baseHtml += baseline.last_change.map(function (c) {
                var cn = cnMap[c.field] || c.field;
                var badge = c.type === "scalar_changed" ? (settings.language === "en" ? "changed" : "变化")
                  : c.type === "added" ? (settings.language === "en" ? "added" : "新增")
                  : (settings.language === "en" ? "removed" : "消失");
                var detail = c.type === "scalar_changed"
                  ? ('<code>' + esc(c.old || "(空)") + '</code> → <code>' + esc(c.new || "(空)") + '</code>')
                  : ('<code>' + esc(c.value) + '</code>');
                return '<div class="li"><span class="tag chip on">' + badge + '</span> <b>' + esc(cn) + '</b> ' + detail + '</div>';
              }).join("");
            } else {
              baseHtml += '<p class="muted" style="margin-top:8px">' + esc(t("noChanges")) + '</p>';
            }
          }
          baseHtml += '</div>';
          html += baseHtml;
          var rcolors = { Critical: "var(--crit)", High: "var(--high)", Medium: "var(--med)", Low: "var(--low)", Info: "var(--info)" };
          html += '<div class="stats" style="margin-top:16px">' +
            Object.keys(riskCounts).map(function (r) {
              return '<div class="stat"><span class="num" style="color:' + (rcolors[r] || "#888") + '">' + riskCounts[r] + '</span><span class="lbl">' + t("riskLevel") + '</span></div>';
            }).join("") + '</div>';
          html += '<div class="card"><h2 style="margin:0 0 10px">' + t("scanHistory") + '（' + scans.length + '）</h2>';
          html += '<label class="chk"><input type="checkbox" id="tc-arch-toggle"' + (tcIncludeArchived ? " checked" : "") + '> ' + t("includeArchived") + '</label> ';
          html += '<button class="btn ghost sm" id="tc-arch90" title="' + t("archive90Hint") + '">' + t("archive90") + '</button>';
          if (scans.length) {
            html += '<table><thead><tr><th>#</th><th>' + t("name") + '</th><th>' + t("status") + '</th><th>' + t("stage") + '</th><th>' + t("finishedAt") + '</th><th></th></tr></thead><tbody>';
            scans.slice(0, 15).forEach(function (s, i) {
              var archived = (s.archived == 1);
              var archBtn = archived
                ? '<button class="btn sm ghost" data-arch="' + s.id + '" data-val="0">' + t("unarchive") + '</button>'
                : '<button class="btn sm ghost" data-arch="' + s.id + '" data-val="1">' + t("archive") + '</button>';
              html += '<tr' + (archived ? ' class="arch-row"' : '') + '><td>' + (i + 1) + (archived ? ' <span class="badge arch">' + t("archived") + '</span>' : '') + '</td><td>' + esc(s.name) + '</td><td>' + stageTag(s.status) + '</td><td>' + esc(s.stage || "") + '</td><td class="muted">' + esc(s.finished_at || "-") + '</td>' +
                '<td><a class="btn sm" href="#scan/' + s.id + '">' + dtl + '</a> ' + archBtn + '</td></tr>';
            });
            html += '</tbody></table>';
          } else html += '<p class="muted">' + t("noData") + '</p>';
          html += '</div>';
          if (allChains.length) {
            html += '<div class="card"><h2 style="margin:0 0 10px">' + t("attackChains") + '（' + allChains.length + '）</h2><table><thead><tr><th>' + t("riskLevel") + '</th><th>' + t("chainName") + '</th><th>' + t("chainPath") + '</th></tr></thead><tbody>';
            allChains.forEach(function (c) {
              var path = c.steps.map(function (s) { return esc(s.category); }).join(" → ");
              html += '<tr><td>' + riskBadge(c.risk) + '</td><td><b>' + esc(c.name) + '</b><br><span class="muted">' + esc(c.narrative) + '</span></td><td class="mono">' + path + '</td></tr>';
            });
            html += '</tbody></table></div>';
          }
          html += '<div class="card"><h2 style="margin:0 0 10px">' + t("vulnTimeline") + '（' + t("totalFindings") + '：' + all.length + '）</h2>';
          if (all.length) {
            var sorted = all.slice().sort(function (a, b) { return (b._sid || 0) - (a._sid || 0); });
            html += '<table><thead><tr><th>' + t("riskLevel") + '</th><th>' + t("vulnType") + '</th><th>' + t("affectedScope") + '</th><th>#' + t("scanDetail") + '</th></tr></thead><tbody>';
            sorted.slice(0, 20).forEach(function (f) {
              html += '<tr><td>' + riskBadge(f.risk) + '</td><td><b>' + esc(f.category) + '</b><br>' + esc(f.title) + '</td><td class="mono">' + esc(f.target_ref) + '</td><td><a href="#scan/' + f._sid + '">#' + f._sid + '</a></td></tr>';
            });
            html += '</tbody></table>';
          } else html += '<p class="muted">' + t("noData") + '</p>';
          html += '</div>';
          html += '<div id="tc-extra"></div>';
          view().innerHTML = html;
          var bs = document.getElementById("tc-scan");
          if (bs) bs.addEventListener("click", function () {
            call("create_scan", tid, (settings.language === "en" ? "Manual scan #" : "手动扫描 #") + tid).then(function (r) {
              if (r.ok) navigate("#scan/" + r.sid); else toast(r.error || (settings.language === "en" ? "Failed" : "创建失败"), "err");
            });
          });
          var bc = document.getElementById("tc-compare");
          if (bc) bc.addEventListener("click", function () { openCompare(tid); });
          // F-06 标签编辑：弹出逗号分隔输入框，保存后回写并刷新
          var bt = document.getElementById("tc-tags");
          if (bt) bt.addEventListener("click", function () {
            var cur = (target.tags || []).join(", ");
            var body = '<div class="form-row"><label>' + t("tags") + '</label>' +
              '<input id="tc-tags-input" placeholder="' + t("tagPlaceholder") + '" value="' + esc(cur) + '"></div>' +
              '<p class="muted" style="margin:6px 0 0">' + t("tagHint") + '</p>';
            openModal(t("editTags"), body, function (root) {
              call("set_target_tags", tid, root.querySelector("#tc-tags-input").value).then(function (r) {
                if (r.ok) { toast(t("saved"), "ok"); root.innerHTML = ""; renderTargetCenter(); }
                else toast(r.error || (settings.language === "en" ? "Failed" : "保存失败"), "err");
              });
            });
          });
          // U-10 授权书：生成可打印/导出的授权书
          var bl = document.getElementById("tc-letter");
          if (bl) bl.addEventListener("click", function () { openLetter(tid); });
          // P-04 数据归档：切换"显示已归档" + 单条归档/取消 + 批量归档 90 天前
          var at = document.getElementById("tc-arch-toggle");
          if (at) at.addEventListener("change", function () {
            tcIncludeArchived = at.checked;
            renderTargetCenter();
          });
          var a90 = document.getElementById("tc-arch90");
          if (a90) a90.addEventListener("click", function () {
            var cutoff = new Date(Date.now() - 90 * 86400000).toISOString().slice(0, 10);
            call("archive_scans_before", cutoff, tid).then(function (r) {
              if (!r.ok) { toast(r.error || "failed", "err"); return; }
              toast((settings.language === "en" ? "Archived " : "已归档 ") + r.archived_count + (settings.language === "en" ? " scans" : " 条扫描"), "ok");
              renderTargetCenter();
            });
          });
          Array.prototype.forEach.call(document.querySelectorAll("[data-arch]"), function (btn) {
            btn.addEventListener("click", function () {
              var sid = parseInt(btn.getAttribute("data-arch"), 10);
              var val = parseInt(btn.getAttribute("data-val"), 10);
              call("archive_scan", sid, val).then(function (r) {
                if (!r.ok) { toast(r.error || "failed", "err"); return; }
                renderTargetCenter();
              });
            });
          });
          // F-02 修复对比：对比最近两次已完成扫描
          call("rescan_diff", tid).then(function (rd) {
            var ph = document.getElementById("tc-extra");
            if (!ph || !rd.ok || !rd.available || !rd.diff) return;
            var d = rd.diff, card = "";
            card += '<div class="card"><h2 style="margin:0 0 10px">' + t("rescanDiff") + '</h2>';
            card += '<p class="muted">' + t("rescanDiffDesc").replace("{prev}", "#" + d.prev_scan_id).replace("{curr}", "#" + d.curr_scan_id) + '</p>';
            card += '<div class="stats">' +
              '<div class="stat"><span class="num" style="color:var(--high)">' + d.counts.new + '</span><span class="lbl">' + t("newFindings") + '</span></div>' +
              '<div class="stat"><span class="num" style="color:var(--low)">' + d.counts.resolved + '</span><span class="lbl">' + t("resolved") + '</span></div>' +
              '<div class="stat"><span class="num" style="color:var(--med)">' + d.counts.persistent + '</span><span class="lbl">' + t("persistent") + '</span></div>' +
              '<div class="stat"><span class="num">' + d.counts.prev + '→' + d.counts.curr + '</span><span class="lbl">' + t("findingCount") + '</span></div></div>';
            if (d.resolved.length) {
              card += '<h3 style="margin:14px 0 6px">' + t("resolved") + '（' + d.resolved.length + '）</h3><div class="chain-list">';
              d.resolved.slice(0, 15).forEach(function (orig) { var f = locVuln(orig); card += '<div class="li">' + riskBadge(f.risk) + ' <b>' + esc(f.category) + '</b>：' + esc(f.title) + '</div>'; });
              card += '</div>';
            }
            if (d.new.length) {
              card += '<h3 style="margin:14px 0 6px">' + t("newFindings") + '（' + d.new.length + '）</h3><div class="chain-list">';
              d.new.slice(0, 15).forEach(function (orig) { var f = locVuln(orig); card += '<div class="li">' + riskBadge(f.risk) + ' <b>' + esc(f.category) + '</b>：' + esc(f.title) + '</div>'; });
              card += '</div>';
            }
            card += '</div>';
            ph.outerHTML = card;
          });
        });
      });
    }).catch(function (e) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Load failed: " : "加载失败：") + esc(e) + "</div>"; });
  }

  // ---------------- 扫描任务 ----------------
  function renderScans() {
    call("list_scans", 50).then(function (scans) {
      var html = '<h1>' + t("scans") + '</h1>' +
        '<div class="toolbar scan-bar"><label class="chk"><input type="checkbox" id="scan-selall"> ' + t("selectAll") + '</label>' +
        '<button class="btn danger" id="scan-batchdel" disabled>' + t("batchDelete") + ' (<span id="scan-selcnt">0</span>)</button></div>' +
        '<div class="card"><table>' +
        '<thead><tr><th class="col-chk"></th><th>#</th><th>' + t("name") + '</th><th>' + t("targetId") + '</th><th>' + t("status") + '</th><th>' + t("stage") + '</th><th>' + t("createdBy") + '</th><th></th></tr></thead><tbody>';
      if (scans.length) {
        scans.forEach(function (s, i) {
          html += '<tr><td class="col-chk"><input type="checkbox" class="scan-chk" value="' + s.id + '"></td>' +
            '<td>' + (i + 1) + '</td><td>' + esc(s.name) + '</td><td>' + s.target_id + '</td><td>' +
            stageTag(s.status) + '</td><td>' + esc(s.stage || "") + '</td><td>' + esc(s.created_by) +
            '</td><td><a class="btn sm" href="#scan/' + s.id + '">' + (settings.language === "en" ? "Detail" : "详情") + '</a>' +
            (s.status === "completed" ? ' <a class="btn sm ghost" href="#scan/' + s.id + '" data-report="' + s.id + '">' + t("report") + '</a>' : "") +
            ' <button class="btn sm danger" data-del-scan="' + s.id + '">' + t("delete") + '</button>' +
            '</td></tr>';
        });
      } else html += '<tr><td colspan="8" class="muted" style="text-align:center">' + t("noData") + '</td></tr>';
      html += "</tbody></table></div>";
      paintView(html);
      view().querySelectorAll("[data-report]").forEach(function (a) {
        a.addEventListener("click", function (e) { e.preventDefault(); openReport(a.getAttribute("data-report")); });
      });
      view().querySelectorAll("[data-del-scan]").forEach(function (b) {
        b.addEventListener("click", function () {
          var sid = b.getAttribute("data-del-scan");
          confirmDialog(t("delete"), t("confirmDeleteScan"), function () {
            call("delete_scan", parseInt(sid, 10)).then(function (r) {
              toastUndo(r, t("deleted"), renderScans);
            });
          });
        });
      });
      // —— 批量删除：多选 + 全选 + 批量删除按钮 ——
      var chks = view().querySelectorAll(".scan-chk");
      var selall = document.getElementById("scan-selall");
      var batchBtn = document.getElementById("scan-batchdel");
      var cntEl = document.getElementById("scan-selcnt");
      function syncSel() {
        var n = view().querySelectorAll(".scan-chk:checked").length;
        if (cntEl) cntEl.textContent = n;
        if (batchBtn) batchBtn.disabled = n === 0;
        if (selall) selall.checked = n > 0 && n === chks.length;
      }
      chks.forEach(function (c) { c.addEventListener("change", syncSel); });
      if (selall) selall.addEventListener("change", function () {
        chks.forEach(function (c) { c.checked = selall.checked; }); syncSel();
      });
      if (batchBtn) batchBtn.addEventListener("click", function () {
        var ids = [];
        view().querySelectorAll(".scan-chk:checked").forEach(function (c) { ids.push(parseInt(c.value, 10)); });
        if (!ids.length) return;
        confirmDialog(t("batchDelete"), t("confirmDeleteScans").replace("{n}", ids.length), function () {
          call("delete_scans", ids).then(function (r) {
            if (!r.ok) { toast(r.error || (settings.language === "en" ? "Failed" : "操作失败"), "err"); return; }
            toastUndo(r, t("deleted") + (r.removed ? " · " + r.removed : ""), renderScans);
          });
        });
      });
    }).catch(function (e) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Load failed: " : "加载失败：") + esc(e) + "</div>"; });
  }

  // ---------------- 扫描详情 ----------------
  var _scanPage = { limit: 50, offset: 0 };
  function renderScanDetail() {
    var sid = current.param;
    _scanPage = { limit: 50, offset: 0 };
    Promise.all([call("get_scan", sid)]).then(function (res) {
      var s = res[0];
      if (!s) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Scan not found" : "扫描不存在") + '</div>'; return; }
      var active = (s.status === "running" || s.status === "awaiting_review" || s.status === "queued");
      var html = '<a class="back" href="#scans">' + t("back") + '</a>' +
        (active ? ' <label class="autoref"><input type="checkbox" id="autoref"' + (autoRefresh ? " checked" : "") + '> ' + t("autoRefresh") + '</label>' : "") +
        '<h1>' + t("scanDetail") + ' #' + s.id + '</h1>' +
        '<p class="muted">' + t("name") + '：' + esc(s.name) + ' ｜ ' + t("createdBy") + '：' + esc(s.created_by) + ' ｜ ' + t("createdAt") + '：' + esc(s.created_at) + '</p>' +
        '<p>' + t("status") + '：' + stageTag(s.status) + ' ' + t("stage") + '：<span class="stage">' + esc(s.stage || "") + '</span>' +
        (active ? ' <span class="spinner"></span>' : '') + '</p>';
      if (s.status === "awaiting_review")
        html += '<div class="card" style="border-color:var(--warn)"><b>⚠ ' + (settings.language === "en" ? "This scan is paused. Approve in " : "该扫描已在关键节点暂停，请在 ") + '<a href="#reviews">' + t("reviews") + '</a>' + (settings.language === "en" ? "." : " 中批准以继续。") + '</b></div>';
      if (s.status === "failed") {
        var _fc = s.failure_category || "exception";
        var _fl = t("fail_" + _fc) || t("fail_exception");
        var _fh = t("fail_" + _fc + "_h") || t("fail_exception_h");
        html += '<div class="card" style="border-color:var(--danger)"><b>✖ ' + (settings.language === "en" ? "Scan failed" : "扫描失败") + '：' + esc(_fl) + '</b>' +
          '<p class="muted" style="margin:6px 0 0">' + esc(_fh) + '</p>' +
          (s.target_id ? ' <a class="btn sm" style="margin-top:8px" href="#target/' + s.target_id + '">' + (settings.language === "en" ? "Go to target" : "前往目标") + '</a>' : '') +
          '</div>';
      }
      html += '<div class="card" id="findings-card"><h2 style="margin:0 0 10px">' + t("findings") + '</h2>' +
        '<div id="findings-body"><p class="muted">' + (settings.language === "en" ? "Loading…" : "加载中…") + '</p></div></div>';
      html += '<div class="toolbar" style="margin:12px 0;display:flex;gap:8px;flex-wrap:wrap">' +
        (s.status === "completed" ? '<button class="btn" id="btn-report" data-sid="' + s.id + '">' + t("viewReport") + '</button>' : '') +
        '<button class="btn ghost" id="btn-matrix" data-sid="' + s.id + '">' + t("vulnMatrix") + '</button>' +
        '</div>';
      html += '<div id="gantt-slot"></div>';
      view().innerHTML = html;
      call("get_scan_stages", sid).then(function (gr) {
        var slot = document.getElementById("gantt-slot");
        if (slot && gr && gr.ok) slot.outerHTML = renderGantt(gr.stages);
      });
      var rb = document.getElementById("btn-report");
      if (rb) rb.addEventListener("click", function () { openReport(s.id); });
      var mb = document.getElementById("btn-matrix");
      if (mb) mb.addEventListener("click", function () { openMatrix(s.id); });
      function loadFindings() {
        call("findings_page", sid, _scanPage.limit, _scanPage.offset).then(function (r) {
          if (!r.ok) { document.getElementById("findings-body").innerHTML = '<p class="muted">' + esc(r.error || "") + '</p>'; return; }
          var items = r.items, total = r.total;
          var body = document.getElementById("findings-body");
          if (!items.length) { body.innerHTML = '<p class="muted">' + (settings.language === "en" ? "No findings yet..." : "尚未产生发现，扫描进行中…") + '</p>'; return; }
          var fixOpts = ["open", "verifying", "fixed", "wont_fix"];
          var tbl = '<table><thead><tr><th>' + t("riskLevel") + '</th><th>' + t("vulnType") + '</th><th>' + t("affectedScope") + '</th><th>' + t("verification") + '</th><th>' + t("cwe") + '</th><th>' + t("evidenceLevel") + '</th><th>' + t("fixStatus") + '</th><th>' + t("remediation") + '</th></tr></thead><tbody>';
          items.forEach(function (orig) {
            var f = locVuln(orig);
            var cur = f.fix_status || "open";
            var opts = fixOpts.map(function (o) {
              return '<option value="' + o + '"' + (o === cur ? " selected" : "") + '>' + t("fix_" + o) + '</option>';
            }).join("");
            var lvl = f.evidence_level || "L1";
            tbl += '<tr class="finding-row" data-fid="' + f.id + '"><td>' + riskBadge(f.risk) + '</td><td><b>' + esc(f.category) + '</b><br>' + esc(f.title) +
              '</td><td class="mono">' + esc(f.target_ref) + '</td><td>' + verifyBadge(f.verification_status) +
              '</td><td class="mono">' + esc(f.cwe || "") + '</td>' +
              '<td><span class="evbadge ev-' + esc(lvl) + '" title="' + esc(t("ev" + lvl + "d")) + '">' + esc(t("ev" + lvl)) + '</span></td>' +
              '<td><select class="fix-sel" data-fid="' + f.id + '">' + opts + '</select></td>' +
              '<td>' + esc(f.remediation) + '</td></tr>';
          });
          tbl += "</tbody></table>";
          var pages = Math.max(1, Math.ceil(total / _scanPage.limit));
          var curPage = Math.floor(_scanPage.offset / _scanPage.limit) + 1;
          tbl += '<div class="pager"><button class="btn sm" id="pg-prev"' + (curPage <= 1 ? " disabled" : "") + '>‹ ' + t("prev") + '</button>' +
            '<span class="muted">' + curPage + ' / ' + pages + '（' + total + ' ' + (settings.language === "en" ? "items" : "项") + '）</span>' +
            '<button class="btn sm" id="pg-next"' + (curPage >= pages ? " disabled" : "") + '>' + t("next") + ' ›</button></div>';
          body.innerHTML = tbl;
          body.querySelectorAll(".finding-row").forEach(function (row) {
            row.addEventListener("click", function (e) {
              if (e.target.closest(".fix-sel")) return;  // 点击修复下拉不触发详情
              openFinding(row.getAttribute("data-fid"));
            });
          });
          body.querySelectorAll(".fix-sel").forEach(function (sel) {
            sel.addEventListener("change", function () {
              call("set_finding_fix_status", sel.getAttribute("data-fid"), sel.value).then(function (rr) {
                if (!rr.ok) { toast(rr.error || (settings.language === "en" ? "Failed" : "操作失败"), "err"); return; }
                toast(settings.language === "en" ? "Fix status updated" : "修复状态已更新", "ok");
              });
            });
          });
          var pv = document.getElementById("pg-prev");
          if (pv) pv.addEventListener("click", function () { if (_scanPage.offset >= _scanPage.limit) { _scanPage.offset -= _scanPage.limit; loadFindings(); } });
          var nx = document.getElementById("pg-next");
          if (nx) nx.addEventListener("click", function () { if (_scanPage.offset + _scanPage.limit < total) { _scanPage.offset += _scanPage.limit; loadFindings(); } });
        });
      }
      loadFindings();
      // 仅在用户停留本扫描详情且扫描活跃时，才启用兜底轮询；
      // 间隔拉长为 8 秒，且若近期（<7s）已收到 P-06 推送事件则跳过 —— 绝大多数刷新由推送驱动。
      function startScanTimer() {
        clearScanTimer();
        _scanTimer = setInterval(function () {
          if (current.view === "scan" && current.param === sid) {
            if (Date.now() - _lastScanPush < 7000) return;  // 推送近期已刷新，避免重复
            router();
          } else {
            clearScanTimer();
          }
        }, 8000);
      }
      if (active && autoRefresh) startScanTimer();
      var ar = document.getElementById("autoref");
      if (ar) ar.addEventListener("change", function () {
        autoRefresh = ar.checked;
        if (autoRefresh && active) startScanTimer(); else clearScanTimer();
      });
    }).catch(function (e) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Load failed: " : "加载失败：") + esc(e) + "</div>"; });
  }

  // ---------------- 阶段甘特图（I-02） ----------------
  function renderGantt(stages) {
    if (!stages || !stages.length) return "";
    var parse = function (ts) {
      if (!ts) return null;
      var d = new Date(String(ts).replace(/-/g, "/"));
      return isNaN(d.getTime()) ? null : d;
    };
    var starts = [], ends = [];
    stages.forEach(function (s) { var st = parse(s.start); if (st) starts.push(st); var en = parse(s.end); if (en) ends.push(en); });
    if (!starts.length) return "";
    var now = new Date();
    var min = new Date(Math.min.apply(null, starts.map(function (d) { return d.getTime(); })));
    var maxEnd = ends.length ? new Date(Math.max.apply(null, ends.map(function (d) { return d.getTime(); }))) : now;
    stages.forEach(function (s) { if (!s.end) { var st = parse(s.start); if (st && st > maxEnd) maxEnd = st; } });
    var span = Math.max(1, maxEnd.getTime() - min.getTime());
    var colors = { done: "var(--low)", paused: "var(--warn)", failed: "var(--danger)", start: "var(--info)", running: "var(--info)" };
    var html = '<div class="card"><h2 style="margin:0 0 10px">' + t("ganttTitle") + '</h2>';
    stages.forEach(function (s) {
      var st = parse(s.start); if (!st) return;
      var end = parse(s.end) || now;
      var left = (st.getTime() - min.getTime()) / span * 100;
      var width = Math.max(2, (end.getTime() - st.getTime()) / span * 100);
      var status = s.status === "start" ? "running" : s.status;
      var color = colors[status] || "var(--info)";
      var label = t("st_" + s.stage) || s.stage;
      var durTxt = s.duration_ms != null
        ? (s.duration_ms >= 1000 ? (s.duration_ms / 1000).toFixed(1) + "s" : s.duration_ms + "ms")
        : (status === "running" ? "…" : "");
      html += '<div style="display:flex;align-items:center;gap:8px;margin:7px 0">' +
        '<div style="width:118px;font-size:12px;color:#9aa4b2;flex:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(label) + '">' + esc(label) + '</div>' +
        '<div style="flex:1;background:rgba(255,255,255,0.07);height:14px;border-radius:7px;position:relative;overflow:hidden">' +
        '<div style="position:absolute;left:' + left.toFixed(1) + '%;top:0;bottom:0;width:' + width.toFixed(1) + '%;background:' + color + ';border-radius:7px"></div>' +
        '</div>' +
        '<div style="width:96px;font-size:11px;text-align:right;color:#9aa4b2;flex:none">' + durTxt + '</div>' +
        '</div>';
    });
    html += '</div>';
    return html;
  }

  // ---------------- 发现详情弹窗（I-04 证据分级 / I-05 请求响应 Diff / I-06 CVSS 计算器） ----------------
  function openFinding(fid) {
    call("get_finding", fid).then(function (f) {
      if (!f || f.ok === false) { toast((f && f.error) || (settings.language === "en" ? "Finding not found" : "发现不存在"), "err"); return; }
      renderFindingModal(f);
    }).catch(function (e) { toast(settings.language === "en" ? "Load failed" : "加载失败", "err"); });
  }

  // CVSS 3.1 基础评分（与 FIRST 规范一致）：输入标准向量，输出 0–10 评分。
  function cvss31Score(vec) {
    var m = /^CVSS:3\.1\/AV:([NALP])\/AC:([LH])\/PR:([NLH])\/UI:([NR])\/S:([UC])\/C:([NLH])\/I:([NLH])\/A:([NLH])$/.exec(vec || "");
    if (!m) return null;
    var AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 }[m[1]];
    var AC = { L: 0.77, H: 0.44 }[m[2]];
    var PRu = { N: 0.85, L: 0.62, H: 0.27 }, PRc = { N: 0.85, L: 0.68, H: 0.50 };
    var PR = (m[5] === "U") ? PRu[m[3]] : PRc[m[3]];
    var UI = { N: 0.85, R: 0.62 }[m[4]];
    var S = m[5];
    var C = { H: 0.56, L: 0.22, N: 0.0 }[m[6]];
    var I = { H: 0.56, L: 0.22, N: 0.0 }[m[7]];
    var A = { H: 0.56, L: 0.22, N: 0.0 }[m[8]];
    var iss = 1 - ((1 - C) * (1 - I) * (1 - A));
    var impact = (S === "U") ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    var expl = 8.22 * AV * AC * PR * UI;
    if (impact <= 0) return 0.0;
    var raw = (S === "U") ? Math.min(impact + expl, 10) : Math.min(1.08 * (impact + expl), 10);
    return Math.ceil(raw * 10) / 10;  // roundup1
  }

  function cvssColor(score) {
    if (score == null) return "var(--muted)";
    if (score >= 9.0) return "var(--crit)";
    if (score >= 7.0) return "var(--high)";
    if (score >= 4.0) return "var(--med)";
    if (score > 0.0) return "var(--low)";
    return "var(--info)";
  }
  function cvssSeverity(score) {
    if (score == null) return "—";
    if (score >= 9.0) return (settings.language === "en" ? "Critical" : "严重");
    if (score >= 7.0) return (settings.language === "en" ? "High" : "高危");
    if (score >= 4.0) return (settings.language === "en" ? "Medium" : "中危");
    if (score > 0.0) return (settings.language === "en" ? "Low" : "低危");
    return (settings.language === "en" ? "Info" : "信息");
  }

  // 将 payload 在文本中高亮（转义后包裹 <mark>）
  function highlightPayload(text, payload) {
    if (!payload || !text) return esc(text);
    var safe = esc(text);
    var sp = esc(payload);
    // 逐处替换（payload 可能多次出现）
    return safe.split(sp).join("<mark>" + sp + "</mark>");
  }

  // I-05：请求 / 响应 Diff 视图
  function renderDiff(meta) {
    if (!meta || (!meta.request && !meta.baseline_request && !meta.response)) {
      return '<p class="note-inline">' + esc(t("noDiff")) + '</p>';
    }
    var html = "";
    var base = redact(meta.baseline_request || "");
    var req = redact(meta.request || "");
    var resp = redact(meta.response || "");
    var pay = redact(meta.payload || "");
    if (meta.baseline_request && meta.request) {
      html += '<div class="diff-cap">' + esc(t("baselineReq")) + '</div><div class="diff-box">' + highlightPayload(base, pay) + '</div>';
      html += '<div class="diff-cap">' + esc(t("injectedReq")) + '</div><div class="diff-box">' + highlightPayload(req, pay) + '</div>';
    } else if (meta.request) {
      html += '<div class="diff-cap">' + esc(t("injectedReq")) + (pay ? '（' + esc(t("payloadLabel")) + ': <code>' + esc(pay) + '</code>）' : '') + '</div>';
      html += '<div class="diff-box">' + highlightPayload(req, pay) + '</div>';
    }
    if (meta.response) {
      html += '<div class="diff-cap">' + (settings.language === "en" ? "Response" : "响应") + '</div><div class="diff-box">' + esc(resp) + '</div>';
    }
    return html;
  }

  // I-06：CVSS 3.1 交互式计算器（返回 HTML 片段，事件在 renderFindingModal 中绑定）
  var _CVSS_METRICS = [
    ["AV", [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]]],
    ["AC", [["L", "Low"], ["H", "High"]]],
    ["PR", [["N", "None"], ["L", "Low"], ["H", "High"]]],
    ["UI", [["N", "None"], ["R", "Required"]]],
    ["S", [["U", "Unchanged"], ["C", "Changed"]]],
    ["C", [["H", "High"], ["L", "Low"], ["N", "None"]]],
    ["I", [["H", "High"], ["L", "Low"], ["N", "None"]]],
    ["A", [["H", "High"], ["L", "Low"], ["N", "None"]]],
  ];
  function renderCvssCalc(f) {
    var vec = (f.cvss_vector || "").trim();
    if (!/^CVSS:3\.1\//.test(vec)) {
      vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N";
    }
    var cur = {};
    vec.replace(/([A-Z]+):([A-Z]+)/g, function (_, k, v) { cur[k] = v; return ""; });
    var cells = _CVSS_METRICS.map(function (mt) {
      var key = mt[0];
      var opts = mt[1].map(function (o) {
        var lbl = (settings.language === "en") ? o[1] : o[1];
        return '<option value="' + o[0] + '"' + (cur[key] === o[0] ? " selected" : "") + '>' + key + ':' + o[0] + ' (' + lbl + ')</option>';
      }).join("");
      return '<div class="cvss-metric"><label>' + key + '</label><select data-cvss="' + key + '">' + opts + '</select></div>';
    }).join("");
    var score = cvss31Score(vec);
    var col = cvssColor(score);
    return '<div class="cvss-metrics" id="cvss-metrics">' + cells + '</div>' +
      '<div class="cvss-score"><span class="num" id="cvss-num" style="color:' + col + '">' + (score == null ? "—" : score.toFixed(1)) + '</span>' +
      '<span class="muted" id="cvss-sev">' + cvssSeverity(score) + '</span>' +
      '<div class="bar"><i id="cvss-bar" style="width:' + (score == null ? 0 : score * 10) + '%;background:' + col + '"></i></div></div>' +
      '<p class="note-inline">' + esc(t("cvssHint")) + '</p>' +
      '<button class="btn sm" id="cvss-save" data-fid="' + f.id + '">' + esc(t("cvssSave")) + '</button>';
  }
  function recomputeCvss() {
    var root = document.getElementById("cvss-metrics");
    if (!root) return;
    var parts = ["CVSS:3.1"];
    _CVSS_METRICS.forEach(function (mt) {
      var sel = root.querySelector('select[data-cvss="' + mt[0] + '"]');
      if (sel) parts.push(mt[0] + ":" + sel.value);
    });
    var vec = parts.join("/");
    var score = cvss31Score(vec);
    var col = cvssColor(score);
    var num = document.getElementById("cvss-num");
    var sev = document.getElementById("cvss-sev");
    var bar = document.getElementById("cvss-bar");
    if (num) num.textContent = (score == null ? "—" : score.toFixed(1));
    if (num) num.style.color = col;
    if (sev) sev.textContent = cvssSeverity(score);
    if (bar) { bar.style.width = (score == null ? 0 : score * 10) + "%"; bar.style.background = col; }
    var save = document.getElementById("cvss-save");
    if (save) save.setAttribute("data-vec", vec);
  }

  function renderFindingModal(f) {
    f = locVuln(f);
    var lvl = f.evidence_level || "L1";
    var meta = null;
    try { meta = f.evidence_meta ? JSON.parse(f.evidence_meta) : null; } catch (e) { meta = null; }
    var root = document.getElementById("modal-root");
    var html = '<div class="overlay"><div class="modal" style="height:auto;max-height:90%;width:720px">' +
      '<div class="modal-head"><b>' + esc(t("findingDetail")) + ' #' + f.id + '</b>' +
      '<button class="btn sm ghost" id="fd-close">' + t("close") + '</button></div>' +
      '<div class="modal-body findbody">' +
      '<div class="frow">' +
      riskBadge(f.risk) +
      '<span class="evbadge ev-' + esc(lvl) + '" title="' + esc(t("ev" + lvl + "d")) + '">' + esc(t("ev" + lvl)) + '</span>' +
      verifyBadge(f.verification_status) +
      (f.cwe ? '<span class="kv"><b>CWE</b>' + esc(f.cwe) + '</span>' : '') +
      (f.endpoint ? '<span class="kv"><b>' + (settings.language === "en" ? "Endpoint" : "端点") + '</b>' + esc(f.endpoint) + '</span>' : '') +
      (f.http_method ? '<span class="kv"><b>' + (settings.language === "en" ? "Method" : "方法") + '</b>' + esc(f.http_method) + '</span>' : '') +
      '</div>' +
      '<h3 style="margin:6px 0">' + esc(f.category) + ' — ' + esc(f.title) + '</h3>' +
      (f.remediation ? '<div class="fsection">' + esc(t("remediation")) + '</div><p style="margin:4px 0 10px">' + esc(f.remediation) + '</p>' : '') +
      (f.detail ? '<p style="margin:6px 0">' + esc(f.detail) + '</p>' : '') +
      '<div class="fsection">' + esc(t("evidenceText")) + '</div>' +
      '<pre>' + esc(redact(f.evidence || (settings.language === "en" ? "(empty)" : "（空）"))) + '</pre>' +
      (meta ? ('<div class="fsection">' + esc(t("reqResp")) + '</div>' + renderDiff(meta)) : '') +
      (f.poc_script ? ('<div class="fsection">' + esc(t("poc")) + '</div><pre>' + esc(f.poc_script) + '</pre>' +
        '<button class="btn sm" id="fd-copy">' + esc(t("copyPoc")) + '</button>') : '') +
      '<div class="fsection">' + esc(t("cvssCalc")) + '</div>' +
      renderCvssCalc(f) +
      '</div></div></div>';
    root.innerHTML = html;
    document.getElementById("fd-close").addEventListener("click", function () { root.innerHTML = ""; });
    var copyBtn = document.getElementById("fd-copy");
    if (copyBtn) copyBtn.addEventListener("click", function () {
      try {
        if (navigator.clipboard) navigator.clipboard.writeText(f.poc_script);
        else { var ta = document.createElement("textarea"); ta.value = f.poc_script; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); }
        toast(settings.language === "en" ? "Copied" : "已复制", "ok");
      } catch (e) { toast(settings.language === "en" ? "Copy failed" : "复制失败", "err"); }
    });
    var metrics = document.getElementById("cvss-metrics");
    if (metrics) metrics.querySelectorAll("select[data-cvss]").forEach(function (sel) {
      sel.addEventListener("change", recomputeCvss);
    });
    var save = document.getElementById("cvss-save");
    if (save) {
      recomputeCvss();
      save.addEventListener("click", function () {
        var vec = save.getAttribute("data-vec") || (f.cvss_vector || "");
        var score = cvss31Score(vec);
        if (score == null) { toast(settings.language === "en" ? "Invalid vector" : "向量非法", "err"); return; }
        call("set_finding_cvss", f.id, score, vec).then(function (r) {
          if (!r.ok) { toast(r.error || (settings.language === "en" ? "Save failed" : "保存失败"), "err"); return; }
          toast(settings.language === "en" ? "Rating updated" : "评级已更新", "ok");
        });
      });
    }
  }

  // ---------------- 漏洞矩阵视图（I-03） ----------------
  function openMatrix(sid) {
    call("findings_matrix", sid).then(function (r) {
      var root = document.getElementById("modal-root");
      if (!r || r.ok === false) { toast((r && r.error) || (settings.language === "en" ? "Load failed" : "加载失败"), "err"); return; }
      var m = r;
      if (!m.total) {
        root.innerHTML = '<div class="overlay"><div class="modal" style="max-width:560px"><div class="modal-head"><b>' + esc(t("matrixTitle")) + '</b><button class="btn sm ghost" id="mx-close">' + t("close") + '</button></div><div class="modal-body"><p class="muted">' + esc(t("matrixNoData")) + '</p></div></div></div>';
        document.getElementById("mx-close").addEventListener("click", function () { root.innerHTML = ""; });
        return;
      }
      var rc = { Critical: "var(--crit)", High: "var(--high)", Medium: "var(--med)", Low: "var(--low)", Info: "var(--info)" };
      var head = '<th>' + esc(t("matrixEndpoint")) + '</th>' + m.categories.map(function (c) {
        return '<th title="' + esc(c) + '">' + esc(c.length > 16 ? c.slice(0, 15) + "…" : c) + '</th>';
      }).join("");
      var rows = m.endpoints.map(function (ep) {
        var cells = m.categories.map(function (c) {
          var cell = m.cells[ep][c];
          if (!cell || !cell.count) return '<td class="mx-empty"></td>';
          var col = rc[cell.risk] || "var(--info)";
          return '<td class="mx-cell" data-fid="' + (cell.fid || "") + '" title="' + esc(t("matrixCellTip")) + '" style="background:' + col + '">' + cell.count + '</td>';
        }).join("");
        return '<tr><td class="mx-ep" title="' + esc(ep) + '">' + esc(ep.length > 40 ? ep.slice(0, 39) + "…" : ep) + '</td>' + cells + '</tr>';
      }).join("");
      var html = '<div class="overlay"><div class="modal" style="height:auto;max-height:90%;width:min(96vw,1080px)"><div class="modal-head"><b>' + esc(t("matrixTitle")) + ' #' + m.scan_id + '</b><button class="btn sm ghost" id="mx-close">' + t("close") + '</button></div>' +
        '<div class="modal-body"><p class="muted">' + esc(t("matrixTotal")) + '：' + m.total + ' ｜ ' + esc(t("matrixCellTip")) + '</p>' +
        '<div style="overflow:auto"><table class="mx-table"><thead><tr>' + head + '</tr></thead><tbody>' + rows + '</tbody></table></div></div></div></div>';
      root.innerHTML = html;
      document.getElementById("mx-close").addEventListener("click", function () { root.innerHTML = ""; });
      root.querySelectorAll(".mx-cell").forEach(function (td) {
        var fid = td.getAttribute("data-fid");
        if (!fid) return;
        td.style.cursor = "pointer";
        td.addEventListener("click", function () { root.innerHTML = ""; openFinding(fid); });
      });
    }).catch(function () { toast(settings.language === "en" ? "Load failed" : "加载失败", "err"); });
  }

  // ---------------- 扫描对比（基线 Diff，F-03） ----------------
  function openCompare(tid) {
    call("list_scans", 50).then(function (scans) {
      scans = scans.filter(function (s) { return s.target_id === tid && s.status === "completed"; })
        .sort(function (a, b) { return a.id - b.id; });
      var root = document.getElementById("modal-root");
      if (scans.length < 2) {
        root.innerHTML = '<div class="overlay"><div class="modal" style="max-width:560px"><div class="modal-head"><b>' + esc(t("compareTitle")) + '</b><button class="btn sm ghost" id="cp-close">' + t("close") + '</button></div><div class="modal-body"><p class="muted">' + esc(t("compareNoScans")) + '</p></div></div></div>';
        document.getElementById("cp-close").addEventListener("click", function () { root.innerHTML = ""; });
        return;
      }
      var opts = scans.map(function (s) {
        return '<option value="' + s.id + '">#' + s.id + ' · ' + esc(s.name) + (s.finished_at ? ' · ' + esc(s.finished_at) : '') + '</option>';
      }).join("");
      var html = '<div class="overlay"><div class="modal" style="max-width:660px"><div class="modal-head"><b>' + esc(t("compareTitle")) + '</b><button class="btn sm ghost" id="cp-close">' + t("close") + '</button></div>' +
        '<div class="modal-body"><p class="muted">' + esc(t("compareHint")) + '</p>' +
        '<div class="form-row"><label>' + t("compareBase") + '</label><select id="cp-base">' + opts + '</select></div>' +
        '<div class="form-row"><label>' + t("compareCurr") + '</label><select id="cp-curr">' + opts + '</select></div>' +
        '<button class="btn" id="cp-run" style="margin-top:12px">' + t("compareBtn") + '</button>' +
        '<div id="cp-result" style="margin-top:14px"></div></div></div></div>';
      root.innerHTML = html;
      document.getElementById("cp-close").addEventListener("click", function () { root.innerHTML = ""; });
      var baseSel = document.getElementById("cp-base"), currSel = document.getElementById("cp-curr");
      if (scans.length >= 2) { baseSel.value = scans[scans.length - 2].id; currSel.value = scans[scans.length - 1].id; }
      document.getElementById("cp-run").addEventListener("click", function () {
        var a = baseSel.value, b = currSel.value;
        if (a === b) { toast(t("compareInvalid"), "err"); return; }
        call("compare_scans", a, b).then(function (r) {
          var ph = document.getElementById("cp-result");
          if (!ph) return;
          if (!r || r.ok === false || !r.available || !r.diff) {
            ph.innerHTML = '<p class="muted">' + esc((r && r.error) || t("compareNoScans")) + '</p>';
            return;
          }
          ph.innerHTML = renderCompareResult(r.diff);
        }).catch(function () { toast(settings.language === "en" ? "Load failed" : "加载失败", "err"); });
      });
    }).catch(function () { toast(settings.language === "en" ? "Load failed" : "加载失败", "err"); });
  }

  function renderCompareResult(d) {
    function listHtml(items) {
      if (!items.length) return '<p class="muted">' + (settings.language === "en" ? "None" : "无") + '</p>';
      return '<div class="chain-list">' + items.map(function (orig) {
        var f = locVuln(orig);
        return '<div class="li">' + riskBadge(f.risk) + ' <b>' + esc(f.category) + '</b>：' + esc(f.title) +
          ' <span class="muted">(' + esc(f.target_ref) + ')</span></div>';
      }).join("") + '</div>';
    }
    var html = '<p class="muted">' + t("compareDesc").replace("{base}", "#" + d.prev_scan_id).replace("{curr}", "#" + d.curr_scan_id) + '</p>';
    html += '<div class="stats">' +
      '<div class="stat"><span class="num" style="color:var(--high)">' + d.counts.new + '</span><span class="lbl">' + t("newFindings") + '</span></div>' +
      '<div class="stat"><span class="num" style="color:var(--low)">' + d.counts.resolved + '</span><span class="lbl">' + t("resolved") + '</span></div>' +
      '<div class="stat"><span class="num" style="color:var(--med)">' + d.counts.persistent + '</span><span class="lbl">' + t("persistent") + '</span></div>' +
      '<div class="stat"><span class="num">' + d.counts.prev + '→' + d.counts.curr + '</span><span class="lbl">' + t("findingCount") + '</span></div></div>';
    html += '<h3 style="margin:14px 0 6px">' + t("newFindings") + '（' + d.new.length + '）</h3>' + listHtml(d.new);
    html += '<h3 style="margin:14px 0 6px">' + t("resolved") + '（' + d.resolved.length + '）</h3>' + listHtml(d.resolved);
    html += '<h3 style="margin:14px 0 6px">' + t("persistent") + '（' + d.persistent.length + '）</h3>' + listHtml(d.persistent);
    return html;
  }

  // ---------------- 复核闸门 ----------------
  function renderReviews() {
    call("list_reviews").then(function (reviews) {
      var html = '<h1>' + t("reviews") + '</h1>' +
        '<p class="muted">' + (settings.language === "en" ? "Exploit verification / upload testing pauses here for your approval." : "利用验证 / 上传测试 等高危动作会在此暂停，需你确认后才继续。") + '</p><div class="card">';
      if (reviews.length) {
        html += '<table><thead><tr><th>' + t("vulnType") + '</th><th>' + t("note") + '</th><th>' + t("targetId") + '</th><th></th></tr></thead><tbody>';
        reviews.forEach(function (r) {
          html += '<tr><td><span class="tag">' + esc(r.kind) + '</span></td><td>' + esc(r.note) + '</td><td class="muted">' +
            (r.scan_id ? 'scan#' + r.scan_id : (r.target_id ? 'target#' + r.target_id : "")) + '</td>' +
            '<td><button class="btn sm" data-approve="' + r.id + '">' + t("approve") + '</button> ' +
            '<button class="btn sm danger" data-reject="' + r.id + '">' + t("reject") + '</button></td></tr>';
        });
        html += "</tbody></table>";
      } else html += '<p class="muted">' + t("noData") + '</p>';
      html += "</div>";
      paintView(html);
      view().querySelectorAll("[data-approve]").forEach(function (b) {
        b.addEventListener("click", function () { decide(b.getAttribute("data-approve"), "approve"); });
      });
      view().querySelectorAll("[data-reject]").forEach(function (b) {
        b.addEventListener("click", function () { decide(b.getAttribute("data-reject"), "reject"); });
      });
    }).catch(function (e) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Load failed: " : "加载失败：") + esc(e) + "</div>"; });
  }
  function decide(rid, decision) {
    call("decide_review", rid, decision).then(function (r) {
      if (r.ok) { toast(decision === "approve" ? (settings.language === "en" ? "Approved" : "已批准，扫描继续") : (settings.language === "en" ? "Rejected" : "已拒绝"), decision === "approve" ? "ok" : "err"); renderReviews(); }
      else toast(r.error || (settings.language === "en" ? "Failed" : "操作失败"), "err");
    });
  }

  // ---------------- 定时 / 批量 ----------------
  function renderScheduler() {
    Promise.all([call("list_schedules"), call("list_targets")]).then(function (res) {
      var scheds = res[0], targets = res[1].filter(function (t) { return t.status === "approved"; });
      var html = '<h1>' + t("scheduler") + '</h1><div class="card"><h2 style="margin:0 0 10px">' + t("newSchedule") + '</h2>' +
        '<form id="f-sched"><div class="row">' +
          '<div><label>' + t("taskName") + '</label><input name="name" placeholder="Daily scan" required></div>' +
          '<div><label>' + t("intervalMin") + '</label><input name="interval" type="number" value="1440" min="1"></div></div>' +
        '<label>' + t("selectTargets") + '</label><select name="target_ids" multiple size="4">';
      targets.forEach(function (tg) { html += '<option value="' + tg.id + '">' + esc(tg.host) + '</option>'; });
      html += '</select><button class="btn" style="margin-top:14px" type="submit">' + t("createSchedule") + '</button></form></div>';
      html += '<div class="card"><h2 style="margin:0 0 10px">' + t("scheduleList") + '</h2><table>' +
        '<thead><tr><th>#</th><th>' + t("name") + '</th><th>' + t("targetId") + '</th><th>' + t("intervalMin") + '</th><th>' + t("status") + '</th><th></th></tr></thead><tbody>';
      if (scheds.length) {
        scheds.forEach(function (sc) {
          var on = sc.enabled;
          html += '<tr><td>' + sc.id + '</td><td>' + esc(sc.name) + '</td><td class="muted">' + esc(sc.target_ids) +
            '</td><td>' + sc.interval_minutes + ' min</td><td>' + (on ? t("enabled") : t("disabled")) + '</td>' +
            '<td><button class="btn sm ghost" data-toggle="' + sc.id + '" data-on="' + (on ? 0 : 1) + '">' +
            (on ? t("disabled") : t("enabled")) + '</button> ' +
            '<button class="btn sm ghost" data-edit-sched="' + sc.id + '">' + t("edit") + '</button> ' +
            '<button class="btn sm danger" data-del-sched="' + sc.id + '">' + t("delete") + '</button></td></tr>';
        });
      } else html += '<tr><td colspan="6" class="muted" style="text-align:center">' + t("noData") + '</td></tr>';
      html += "</tbody></table></div>";
      view().innerHTML = html;

      document.getElementById("f-sched").addEventListener("submit", function (e) {
        e.preventDefault();
        var f = e.target;
        var tids = Array.prototype.slice.call(f.target_ids.selectedOptions).map(function (o) { return o.value; });
        call("create_schedule", f.name.value, tids, parseInt(f.interval.value, 10) || 1440).then(function (r) {
          if (r.ok) { toast(settings.language === "en" ? "Schedule created" : "定时任务已创建", "ok"); renderScheduler(); }
          else toast(r.error || (settings.language === "en" ? "Failed" : "创建失败"), "err");
        });
      });
      view().querySelectorAll("[data-toggle]").forEach(function (b) {
        b.addEventListener("click", function () {
          call("toggle_schedule", b.getAttribute("data-toggle"), b.getAttribute("data-on") === "1").then(function () {
            renderScheduler();
          });
        });
      });
      view().querySelectorAll("[data-edit-sched]").forEach(function (b) {
        b.addEventListener("click", function () {
          var sc = scheds.find(function (x) { return x.id === parseInt(b.getAttribute("data-edit-sched"), 10); });
          if (!sc) return;
          var cur = (sc.target_ids || "").split(",").filter(Boolean);
          var opts = targets.map(function (tg) {
            var sel = cur.indexOf(String(tg.id)) >= 0 ? " selected" : "";
            return '<option value="' + tg.id + '"' + sel + '>' + esc(tg.host) + '</option>';
          }).join("");
          var body = '<div class="form-row"><label>' + t("taskName") + '</label><input id="es-name" value="' + esc(sc.name) + '"></div>' +
            '<div class="form-row"><label>' + t("intervalMin") + '</label><input id="es-int" type="number" min="1" value="' + sc.interval_minutes + '"></div>' +
            '<div class="form-row"><label>' + t("selectTargets") + '</label><select id="es-tids" multiple size="4">' + opts + '</select></div>' +
            '<div class="checkrow"><input type="checkbox" id="es-en" ' + (sc.enabled ? "checked" : "") + '><label for="es-en">' + t("enabled") + '</label></div>';
          openModal(t("editSchedule"), body, function (root) {
            var name = root.querySelector("#es-name").value;
            var iv = parseInt(root.querySelector("#es-int").value, 10) || 1440;
            var tids = Array.prototype.slice.call(root.querySelector("#es-tids").selectedOptions).map(function (o) { return o.value; });
            var en = root.querySelector("#es-en").checked ? 1 : 0;
            call("save_schedule", sc.id, name, tids, iv, en).then(function (r) {
              if (r.ok) { toast(t("saved"), "ok"); root.innerHTML = ""; renderScheduler(); }
              else toast(r.error || (settings.language === "en" ? "Failed" : "保存失败"), "err");
            });
          });
        });
      });
      view().querySelectorAll("[data-del-sched]").forEach(function (b) {
        b.addEventListener("click", function () {
          var sid = b.getAttribute("data-del-sched");
          confirmDialog(t("delete"), t("confirmDeleteSchedule"), function () {
            call("delete_schedule", parseInt(sid, 10)).then(function (r) {
              toastUndo(r, t("deleted"), renderScheduler);
            });
          });
        });
      });
    }).catch(function (e) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Load failed: " : "加载失败：") + esc(e) + "</div>"; });
  }

  // ---------------- 审计日志 ----------------
  function renderAudit() {
    Promise.all([call("audit_tail", 2000), call("audit_heatmap", 90)]).then(function (res) {
      var logs = res[0];
      var heat = (res[1].ok && res[1].heatmap) || [];
      var maxc = heat.reduce(function (m, d) { return Math.max(m, d.count); }, 0) || 1;
      var cells = heat.map(function (d) {
        var lvl = d.count === 0 ? 0 : Math.ceil((d.count / maxc) * 4);
        return '<div class="hm-cell hm-' + lvl + '" title="' + esc(d.date) + ': ' + d.count + '"></div>';
      }).join("");
      var html = '<h1>' + t("audit") + '</h1>' +
        '<div class="card"><h3>' + (settings.language === "en" ? "Activity Heatmap (last 90 days)" : "活动热力图（近 90 天）") + '</h3>' +
        '<div class="hm-grid">' + cells + '</div>' +
        '<div class="hm-legend"><span class="hm-cell hm-0"></span><span class="hm-cell hm-1"></span><span class="hm-cell hm-2"></span><span class="hm-cell hm-3"></span><span class="hm-cell hm-4"></span> ' +
        (settings.language === "en" ? "less → more" : "少 → 多") + '</div></div>' +
        '<div class="toolbar"><button class="btn sm danger" id="btn-clear-log">' + t("clearLog") + '</button>' +
        '<span class="muted" style="margin-left:10px">' + t("virtualNote") + '</span></div>' +
        // P-05：审计日志（随时间无界增长）改用虚拟滚动，仅渲染可视区行
        '<div class="card"><div class="vhead"><span>' + t("createdAt") + '</span><span>' + t("createdBy") + '</span><span>' + t("actions") + '</span><span>' + t("targetId") + '</span><span>' + t("note") + '</span></div>' +
        '<div id="audit-vlist"></div></div>';
      view().innerHTML = html;
      var scroller = document.getElementById("audit-vlist");
      if (logs.length) {
        mountVirtualList(scroller, logs, function (l) {
          return '<span class="muted">' + esc(l.ts) + '</span>' +
            '<span>' + esc(l.username) + '</span>' +
            '<span class="tag">' + esc(l.action) + '</span>' +
            '<span>' + esc(l.target) + '</span>' +
            '<span class="muted vnote">' + esc(l.detail) + '</span>';
        }, { rowHeight: 36, overscan: 10 });
      } else {
        scroller.innerHTML = '<div class="muted" style="padding:16px;text-align:center">' + t("noData") + '</div>';
      }
      var cl = document.getElementById("btn-clear-log");
      if (cl) cl.addEventListener("click", function () {
        confirmDialog(t("clearLog"), t("confirmClearLog"), function () {
          call("clear_audit").then(function (r) {
            if (r.ok) { toast(t("cleared"), "ok"); renderAudit(); }
            else toast(r.error || (settings.language === "en" ? "Failed" : "清空失败"), "err");
          });
        });
      });
    }).catch(function (e) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Load failed: " : "加载失败：") + esc(e) + "</div>"; });
  }

  // ---------------- 设置 ----------------
  function renderSettings() {
    call("app_info").then(function (info) {
      var html = '<h1>' + t("settings") + '</h1>' +
        '<div class="card settings-group"><h3>' + (settings.language === "en" ? "Appearance" : "外观设置") + '</h3>' +
        '<div class="setting-row"><label>' + t("language") + '</label>' +
          '<select id="set-lang"><option value="zh" ' + (settings.language === "zh" ? "selected" : "") + '>中文</option>' +
          '<option value="en" ' + (settings.language === "en" ? "selected" : "") + '>English</option></select></div>' +
        '<div class="setting-row"><label>' + t("theme") + '</label>' +
          '<select id="set-theme"><option value="dark" ' + (settings.theme === "dark" ? "selected" : "") + '>' + t("dark") + '</option>' +
          '<option value="light" ' + (settings.theme === "light" ? "selected" : "") + '>' + t("light") + '</option></select></div>' +
        '<div class="setting-row"><label>' + t("fontSize") + '</label>' +
          '<input type="range" id="set-font" min="12" max="20" value="' + settings.font_size + '">' +
          '<span id="font-val" style="margin-left:8px;min-width:24px">' + settings.font_size + 'px</span></div>' +
        '<div class="setting-row"><label>' + t("layout") + '</label>' +
          '<select id="set-layout"><option value="comfortable" ' + (settings.layout === "comfortable" ? "selected" : "") + '>' + t("comfortable") + '</option>' +
          '<option value="card" ' + (settings.layout === "card" ? "selected" : "") + '>' + t("card") + '</option></select></div>' +
        '<div class="setting-row"><label>' + t("reportTemplate") + '</label>' +
          '<select id="set-tpl"><option value="summary" ' + (settings.report_template === "summary" ? "selected" : "") + '>' + t("tplSummary") + '</option>' +
          '<option value="tech" ' + (settings.report_template === "tech" ? "selected" : "") + '>' + t("tplTech") + '</option>' +
          '<option value="compliance" ' + (settings.report_template === "compliance" ? "selected" : "") + '>' + t("tplCompliance") + '</option></select></div>' +
        '<button class="btn" style="margin-top:14px" id="btn-save-set">' + (settings.language === "en" ? "Save Settings" : "保存设置") + '</button></div>' +
        '<div class="card settings-group"><h3>' + (settings.language === "en" ? "Window Behavior" : "窗口行为") + '</h3>' +
        '<div class="setting-row"><label>' + (settings.language === "en" ? "Close button action" : "关闭按钮行为") + '</label>' +
          '<select id="set-closebehavior"><option value="minimize" ' + (settings.close_behavior === "minimize" ? "selected" : "") + '>' + (settings.language === "en" ? "Minimize to tray" : "最小化到托盘") + '</option>' +
          '<option value="exit" ' + (settings.close_behavior === "exit" ? "selected" : "") + '>' + (settings.language === "en" ? "Exit application" : "完全退出") + '</option></select></div>' +
        '<p class="muted" style="margin:0">' + (settings.language === "en" ? "Minimize to tray keeps the app running in the background; Exit closes it completely." : "最小化到托盘保持应用后台运行；完全退出则关闭应用。") + '</p></div>' +
        '<div class="card settings-group"><h3>' + (settings.language === "en" ? "Visual Effects" : "视觉效果") + '</h3>' +
        '<div class="setting-row"><label>' + (settings.language === "en" ? "Enable visual effects" : "启用视觉效果") + '</label>' +
          '<input type="checkbox" id="set-fx" ' + (settings.fx_enabled === "1" ? "checked" : "") + '></div>' +
        '<p class="muted" style="margin:0">' + (settings.language === "en" ? "Master switch for all dynamic/static visual effects (background particles, scanlines, vignette, noise, button glow). Turn off for a plain native look." : "统一控制所有动态/静态视觉效果（背景粒子、扫描线、暗角、噪点、按钮光晕）的总开关。关闭后恢复系统原生简洁外观。") + '</p></div>' +
        '<div class="card settings-group"><h3>' + (settings.language === "en" ? "Panel Transparency" : "面板透明度") + '</h3>' +
        '<div class="setting-row"><label>' + (settings.language === "en" ? "Panel opacity" : "面板不透明度") + '</label>' +
          '<input type="range" id="set-panelopacity" min="0.35" max="1" step="0.05" value="' + settings.panel_opacity + '">' +
          '<span id="panelopacity-val" style="margin-left:8px;min-width:36px">' + Math.round(parseFloat(settings.panel_opacity) * 100) + '%</span></div>' +
        '<p class="muted" style="margin:0">' + (settings.language === "en" ? "Lower values make panels more transparent, revealing the background particle effect. Text remains fully opaque." : "降低该值使面板更透明，露出背景粒子特效。文字保持完全不透明。") + '</p></div>' +
        '<div class="card settings-group"><h3>' + (settings.language === "en" ? "Background Particles" : "背景粒子") + '</h3>' +
        '<div class="setting-row"><label>' + (settings.language === "en" ? "Enable particles" : "启用粒子") + '</label>' +
          '<input type="checkbox" id="set-bgparticles" ' + (settings.bg_particles_enabled === "1" ? "checked" : "") + '></div>' +
        '<div class="setting-row"><label>' + (settings.language === "en" ? "Density" : "密度") + '</label>' +
          '<input type="range" id="set-bgdensity" min="0.5" max="2.5" step="0.1" value="' + settings.bg_particle_density + '">' +
          '<span id="bgdensity-val" style="margin-left:8px;min-width:28px">' + settings.bg_particle_density + '</span></div>' +
        '<p class="muted" style="margin:0">' + (settings.language === "en" ? "Dynamic particle field behind panels. Lower panel opacity reveals more of it." : "面板之后的动态粒子场；降低面板不透明度可显露更多。") + '</p></div>' +
        '<div class="card settings-group"><h3>' + (settings.language === "en" ? "Security Probe" : "安全探测") + '</h3>' +
        '<div class="setting-row"><label>' + t("authProbe") + '</label>' +
          '<input type="checkbox" id="set-authprobe" ' + (settings.enable_auth_probe === "1" ? "checked" : "") + '></div>' +
        '<p class="muted" style="margin:0 0 12px">' + esc(t("authProbeDesc")) + '</p>' +
        '<div class="setting-row"><label>' + t("customDict") + '</label>' +
          '<input type="text" id="set-authdict" style="flex:1;min-width:160px" placeholder="' + esc(t("customDictPlaceholder")) + '" value="' + esc(settings.auth_probe_dict || "") + '"></div>' +
        '<p class="muted" style="margin:0">' + esc(t("customDictNote")) + '</p></div>' +
        '<div class="card settings-group"><h3>' + t("sessionRenew") + '</h3>' +
        '<div class="setting-row"><label>' + t("sessionRenew") + '</label>' +
          '<input type="checkbox" id="set-renew" ' + (settings.enable_session_renew === "1" ? "checked" : "") + '></div>' +
        '<p class="muted" style="margin:0 0 12px">' + esc(t("sessionRenewDesc")) + '</p>' +
        '<p class="note" style="margin:0">' + esc(t("sessionRenewInfo")) + '</p></div>' +
        '<div class="card settings-group"><h3>' + t("monitorGroup") + '</h3>' +
        '<div class="setting-row"><label>' + t("assetAlert") + '</label>' +
          '<input type="checkbox" id="set-assetalert" ' + (settings.asset_change_alert === "1" ? "checked" : "") + '></div>' +
        '<p class="muted" style="margin:0 0 12px">' + esc(t("assetAlertDesc")) + '</p>' +
        '<div class="setting-row"><label>' + t("assetNotify") + '</label>' +
          '<input type="checkbox" id="set-assetnotify" ' + (settings.asset_change_notify !== "0" ? "checked" : "") + '></div>' +
        '<p class="muted" style="margin:0 0 12px">' + esc(t("assetNotifyDesc")) + '</p>' +
        '<div class="setting-row"><label>' + t("assetAutoscan") + '</label>' +
          '<input type="checkbox" id="set-assetautoscan" ' + (settings.asset_autoscan === "1" ? "checked" : "") + '></div>' +
        '<p class="muted" style="margin:0">' + esc(t("assetAutoscanDesc")) + '</p></div>' +
        '<div class="card"><h3>' + t("about") + '</h3><div class="kv">' +
        t("version") + '：<code>' + esc(info.version) + '</code><br>' +
        t("os") + '：<code>' + esc(info.os) + ' / Python ' + esc(info.python) + '</code><br>' +
        t("dataDir") + '：<code>' + esc(info.data_dir) + '</code><br>' +
        t("dbPath") + '：<code>' + esc(info.db_path) + '</code><br>' +
        t("gatedStages") + '：<code>' + esc(info.gated_stages.join(", ")) + '</code>' +
        '</div></div>' +
        '<div class="card"><h3>' + (settings.language === "en" ? "Operations Tools" : "运维工具") + '</h3>' +
        '<p class="muted" style="margin:0 0 10px">' + (settings.language === "en" ? "One-click package of version / settings (redacted) / DB stats / recent audit (redacted) for troubleshooting." : "一键打包版本 / 设置（已脱敏）/ 库统计 / 近期审计（已脱敏），用于报障排错。") + '</p>' +
        '<button class="btn" id="btn-export-diag">' + esc(t("exportDiag")) + '</button>' +
        '</div>' +
        '<div class="card"><h3>' + (settings.language === "en" ? "Keyboard Shortcuts" : "键盘快捷键") + '</h3>' +
        '<div class="kv">' + esc(t("kbdHelp")) + '</div></div>' +
        '<div class="note"><b>' + t("legalNotice") + '：</b>' + t("legalText") + '</div>';
      view().innerHTML = html;

      document.getElementById("set-font").addEventListener("input", function (e) {
        document.getElementById("font-val").textContent = e.target.value + "px";
      });
      // —— 鼠标特效 / 背景粒子：实时绑定（拖动即更新 settings，预览随之变化）——
      function liveRange(id, key, spanId, fmt) {
        var el = document.getElementById(id), sp = document.getElementById(spanId);
        if (!el) return;
        el.addEventListener("input", function () {
          settings[key] = el.value;
          if (sp) sp.textContent = fmt ? fmt(el.value) : el.value;
        });
      }
      function liveSelect(id, key) {
        var el = document.getElementById(id);
        if (el) el.addEventListener("change", function () { settings[key] = el.value; });
      }
      liveRange("set-bgdensity", "bg_particle_density", "bgdensity-val", null);
      var bgChk = document.getElementById("set-bgparticles");
      if (bgChk) bgChk.addEventListener("change", function () { settings.bg_particles_enabled = bgChk.checked ? "1" : "0"; });
      var fxChk = document.getElementById("set-fx");
      if (fxChk) fxChk.addEventListener("change", function () {
        settings.fx_enabled = fxChk.checked ? "1" : "0";
        applyFxClass();  // 立即反馈：静态层（扫描线/暗角/噪点/自定义光标）实时开关；动态层（粒子/拖尾）保存刷新后生效
      });
      // 实时预览（canvas 脱离 DOM 时自动停止，避免泄漏）
      var panelOp = document.getElementById("set-panelopacity");
      if (panelOp) panelOp.addEventListener("input", function (e) {
        document.getElementById("panelopacity-val").textContent = Math.round(parseFloat(e.target.value) * 100) + "%";
        applyPanelOpacityPreview(e.target.value);
      });
      // C-05：开启默认凭据探测前，强制闸门确认（书面授权 / 账号锁定风险）。
      var authChk = document.getElementById("set-authprobe");
      if (authChk) authChk.addEventListener("change", function () {
        if (authChk.checked) {
          confirmDialog(t("authProbeConfirm"), t("authProbeConfirmBody"), function () {
            authChk.checked = true;
          });
          // 先取消勾选，待用户确认（onYes 内重新勾上）；取消则保持未勾选。
          authChk.checked = false;
        }
      });
      document.getElementById("btn-save-set").addEventListener("click", function () {
        settings.language = document.getElementById("set-lang").value;
        settings.theme = document.getElementById("set-theme").value;
        settings.font_size = document.getElementById("set-font").value;
        settings.layout = document.getElementById("set-layout").value;
        settings.report_template = document.getElementById("set-tpl").value;
        settings.close_behavior = document.getElementById("set-closebehavior").value;
        settings.bg_particles_enabled = document.getElementById("set-bgparticles").checked ? "1" : "0";
        settings.bg_particle_density = document.getElementById("set-bgdensity").value;
        settings.panel_opacity = document.getElementById("set-panelopacity").value;
        settings.fx_enabled = document.getElementById("set-fx").checked ? "1" : "0";
        settings.enable_auth_probe = document.getElementById("set-authprobe").checked ? "1" : "0";
        settings.auth_probe_dict = (document.getElementById("set-authdict").value || "").trim();
        settings.asset_change_alert = document.getElementById("set-assetalert").checked ? "1" : "0";
        settings.asset_change_notify = document.getElementById("set-assetnotify").checked ? "1" : "0";
        settings.asset_autoscan = document.getElementById("set-assetautoscan").checked ? "1" : "0";
        settings.enable_session_renew = document.getElementById("set-renew").checked ? "1" : "0";
        call("set_settings", settings).then(function () {
          applySettings();
          loadVulnI18n();   // U-07：语言切换后刷新漏洞双语映射
          toast(settings.language === "en" ? "Settings saved" : "设置已保存", "ok");
          renderSettings();
        });
      });
      var diag = document.getElementById("btn-export-diag");
      if (diag) diag.addEventListener("click", function () {
        call("export_diagnostic").then(function (r) {
          if (!r.ok) { toast(r.error || "导出失败", "err"); return; }
          var blob = new Blob([JSON.stringify(r.diagnostic, null, 2)], { type: "application/json" });
          var url = URL.createObjectURL(blob);
          var a = document.createElement("a");
          a.href = url;
          a.download = "autopentest_diagnostic_" + (r.diagnostic.version || "v") + ".json";
          document.body.appendChild(a); a.click(); a.remove();
          URL.revokeObjectURL(url);
          toast(settings.language === "en" ? "Diagnostic package downloaded" : "诊断包已下载", "ok");
        });
      });
    }).catch(function (e) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Load failed: " : "加载失败：") + esc(e) + "</div>"; });
  }

  // ---------------- 资产拓扑可视化（F-07） ----------------
  // 完全离线、无外部 d3 依赖：原生 SVG 力导向布局 + 平移/缩放/拖拽/点击详情。
  var topoSim = null;  // 当前拓扑模拟状态（render 时重建；切换视图/卸载时停止 rAF）

  function _topoRiskColor(risk) {
    switch ((risk || "").toLowerCase()) {
      case "critical": case "high": return "#ff5a5a";
      case "medium": return "#ffb020";
      case "low": return "#ffe066";
      case "info": return "#4f8cff";
      default: return "#8a93a6";
    }
  }
  function _topoNodeRadius(n) {
    if (n.type === "target") return 24;
    if (n.type === "host") return 16;
    if (n.type === "port") return 9;
    return 11; // finding
  }
  function _topoNodeColor(n) {
    if (n.type === "target") return "var(--accent)";
    if (n.type === "host") return "#2bb3a3";
    if (n.type === "port") return "#8a93a6";
    return _topoRiskColor(n.risk);
  }

  function renderTopology() {
    if (topoSim && topoSim.raf) cancelAnimationFrame(topoSim.raf);
    topoSim = null;
    // 立即显示加载状态，防止空白闪动
    view().innerHTML = '<div class="empty"><span class="spinner"></span>' + (settings.language === "en" ? "Loading topology..." : "正在加载拓扑…") + '</div>';
    // 保存当前滚动位置，修复 view().innerHTML 重置 scrollTop 的问题
    var mainEl = document.getElementById("view");
    var savedScroll = mainEl ? mainEl.scrollTop : 0;
    call("topology_data").then(function (r) {
      if (!r.ok) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Topology failed: " : "拓扑生成失败：") + esc(r.error || "") + "</div>"; return; }
      var topo = r.topology || { nodes: [], edges: [] };
      if (!topo.nodes.length) {
        view().innerHTML = '<h1>' + t("topology") + '</h1><p class="muted">' + esc(t("topologyDesc")) + '</p>' +
          '<div class="empty" style="margin-top:24px">' + esc(t("topoEmpty")) + '</div>';
        return;
      }
      var html = '<h1>' + t("topology") + '</h1>' +
        '<p class="muted">' + esc(t("topologyDesc")) + '</p>' +
        '<div class="topo-toolbar">' +
          '<label class="topo-toggle"><input type="checkbox" id="topo-chain" checked> ' + esc(t("topoShowChain")) + '</label>' +
          '<button class="btn sm ghost" id="topo-reset">' + esc(t("topoReset")) + '</button>' +
          '<span class="muted" style="margin-left:auto">' + esc(t("topoToggleZoom")) + '</span>' +
        '</div>' +
        '<div class="topo-wrap">' +
          '<svg id="topo-svg" role="img" aria-label="' + esc(t("topology")) + '" width="100%" height="100%"></svg>' +
          '<div class="topo-legend">' + esc(t("topoLegend")) +
            '<span><i class="dot" style="background:var(--accent)"></i>' + esc(t("topoTarget")) + '</span>' +
            '<span><i class="dot" style="background:#2bb3a3"></i>' + esc(t("topoHost")) + '</span>' +
            '<span><i class="dot" style="background:#8a93a6"></i>' + esc(t("topoPort")) + '</span>' +
            '<span><i class="dot" style="background:#ff5a5a"></i>' + esc(t("topoFinding")) + '</span>' +
            '<span><i class="line chain"></i>' + esc(t("topoChain")) + '</span>' +
          '</div>' +
          '<div class="topo-detail" id="topo-detail"><span class="muted">' + esc(t("topoNoNode")) + '</span></div>' +
        '</div>';
      view().innerHTML = html;
      // 恢复滚动位置（新视图初始为 0，但后续 DOM 变更不应重置）
      if (mainEl) mainEl.scrollTop = 0;
      // 延迟一帧初始化力导向，确保 SVG DOM 渲染完毕后再启动动画，消除闪动
      requestAnimationFrame(function () {
        _topoInit(topo);
        var chainChk = document.getElementById("topo-chain");
        if (chainChk) chainChk.addEventListener("change", function () { topoSim.showChain = chainChk.checked; _topoDraw(); });
        var resetBtn = document.getElementById("topo-reset");
        if (resetBtn) resetBtn.addEventListener("click", function () { _topoReset(); });
      });
    }).catch(function (e) { view().innerHTML = '<div class="empty">' + (settings.language === "en" ? "Load failed: " : "加载失败：") + esc(e) + "</div>"; });
  }

  function _topoInit(topo) {
    var svg = document.getElementById("topo-svg");
    var W = svg.clientWidth || 900, H = svg.clientHeight || 520;
    var nodes = topo.nodes.map(function (n, i) {
      var ang = (i / topo.nodes.length) * Math.PI * 2;
      return Object.assign({}, n, {
        x: W / 2 + Math.cos(ang) * 190 + (i % 3) * 14,
        y: H / 2 + Math.sin(ang) * 130 + (i % 2) * 14,
        vx: 0, vy: 0
      });
    });
    var byId = {}; nodes.forEach(function (n) { byId[n.id] = n; });
    var edges = topo.edges.filter(function (e) { return byId[e.source] && byId[e.target]; });
    // 创建 SVG DOM 结构（一次性，后续只更新属性）
    svg.innerHTML = '<g id="topo-vp" will-change="transform"><g id="topo-edges"></g><g id="topo-nodes"></g></g>';
    // 预创建边和节点元素，后续只更新属性（避免 innerHTML 替换导致回流）
    var eG = document.getElementById("topo-edges"), nG = document.getElementById("topo-nodes");
    eG.textContent = ""; nG.textContent = "";
    edges.forEach(function (e) {
      var line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("data-kind", e.kind || "asset");
      if (e.kind === "chain") {
        line.setAttribute("class", "topo-e-chain");
      } else {
        line.setAttribute("class", "topo-e-asset");
      }
      eG.appendChild(line);
    });
    nodes.forEach(function (n) {
      var g = document.createElementNS("http://www.w3.org/2000/svg", "g");
      g.setAttribute("class", "topo-node" + (n.type === "target" ? " is-target" : ""));
      g.setAttribute("data-id", n.id);
      var circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      var r = _topoNodeRadius(n), fill = _topoNodeColor(n);
      circle.setAttribute("r", r);
      circle.setAttribute("fill", fill);
      if (n.maxRisk && n.type !== "port") {
        circle.setAttribute("stroke", _topoRiskColor(n.maxRisk));
        circle.setAttribute("stroke-width", "3");
      } else {
        circle.setAttribute("stroke", "rgba(255,255,255,.25)");
        circle.setAttribute("stroke-width", "1.5");
      }
      g.appendChild(circle);
      if (n.type !== "port") {
        var txt = document.createElementNS("http://www.w3.org/2000/svg", "text");
        txt.setAttribute("class", "topo-label");
        txt.setAttribute("x", "0");
        txt.setAttribute("y", r + 12);
        txt.setAttribute("text-anchor", "middle");
        txt.textContent = (n.label || "").length > 22 ? (n.label.slice(0, 21) + "…") : n.label;
        g.appendChild(txt);
      }
      n._el = g; n._circle = circle;  // 缓存引用，后续更新属性
      nG.appendChild(g);
    });
    topoSim = { svg: svg, nodes: nodes, byId: byId, edges: edges, W: W, H: H,
                tx: 0, ty: 0, k: 1, showChain: true, raf: null, alpha: 0.6, drag: null, pan: null,
                eG: eG, nG: nG };
    _topoBind();
    _topoDraw();
    _topoRun();
  }

  function _topoDraw() {
    if (!topoSim) return;
    var vp = document.getElementById("topo-vp");
    vp.setAttribute("transform", "translate(" + topoSim.tx.toFixed(1) + "," + topoSim.ty.toFixed(1) + ") scale(" + topoSim.k.toFixed(3) + ")");
    // 更新边的可见性（innerHTML 替换 → 属性更新）
    var eLines = topoSim.eG.querySelectorAll("line");
    topoSim.edges.forEach(function (e, i) {
      var line = eLines[i];
      if (!line) return;
      if (e.kind === "chain" && !topoSim.showChain) {
        line.style.display = "none"; return;
      }
      line.style.display = "";
      var a = topoSim.byId[e.source], b = topoSim.byId[e.target];
      if (!a || !b) return;
      line.setAttribute("x1", a.x.toFixed(1));
      line.setAttribute("y1", a.y.toFixed(1));
      line.setAttribute("x2", b.x.toFixed(1));
      line.setAttribute("y2", b.y.toFixed(1));
    });
    // 更新节点位置（属性更新，不替换 DOM）
    topoSim.nodes.forEach(function (n) {
      if (!n._el) return;
      n._el.setAttribute("transform", "translate(" + n.x.toFixed(1) + "," + n.y.toFixed(1) + ")");
    });
  }

  function _topoBind() {
    var svg = topoSim.svg;
    function toGraph(ev) {
      var rect = svg.getBoundingClientRect();
      return {
        x: (ev.clientX - rect.left - topoSim.tx) / topoSim.k,
        y: (ev.clientY - rect.top - topoSim.ty) / topoSim.k
      };
    }
    svg.addEventListener("pointerdown", function (ev) {
      var g = ev.target.closest ? ev.target.closest(".topo-node") : null;
      var p = toGraph(ev);
      if (g) {
        var id = g.getAttribute("data-id");
        topoSim.drag = { id: id, dx: topoSim.byId[id].x - p.x, dy: topoSim.byId[id].y - p.y };
        topoSim.alpha = Math.max(topoSim.alpha, 0.3);  // 拖拽时唤醒模拟
      } else {
        topoSim.pan = { x: ev.clientX, y: ev.clientY, tx: topoSim.tx, ty: topoSim.ty };
      }
      svg.setPointerCapture(ev.pointerId);
    });
    svg.addEventListener("pointermove", function (ev) {
      if (topoSim.drag) {
        var p = toGraph(ev), n = topoSim.byId[topoSim.drag.id];
        n.x = p.x + topoSim.drag.dx; n.y = p.y + topoSim.drag.dy; n.vx = 0; n.vy = 0;
        _topoDraw();
      } else if (topoSim.pan) {
        topoSim.tx = topoSim.pan.tx + (ev.clientX - topoSim.pan.x);
        topoSim.ty = topoSim.pan.ty + (ev.clientY - topoSim.pan.y);
        _topoDraw();
      }
    });
    function endDrag(ev) {
      if (topoSim.drag) { _topoDetail(topoSim.byId[topoSim.drag.id]); topoSim.drag = null; }
      topoSim.pan = null;
      try { svg.releasePointerCapture(ev.pointerId); } catch (e) {}
    }
    svg.addEventListener("pointerup", endDrag);
    svg.addEventListener("pointercancel", endDrag);
    svg.addEventListener("wheel", function (ev) {
      ev.preventDefault();
      var rect = svg.getBoundingClientRect();
      var mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
      var f = ev.deltaY < 0 ? 1.1 : 0.9;
      var nk = Math.min(3, Math.max(0.3, topoSim.k * f));
      // 以光标为锚点缩放
      topoSim.tx = mx - (mx - topoSim.tx) * (nk / topoSim.k);
      topoSim.ty = my - (my - topoSim.ty) * (nk / topoSim.k);
      topoSim.k = nk;
      _topoDraw();
    }, { passive: false });
  }

  function _topoRun() {
    function tick() {
      if (!topoSim) return;
      if (!document.body.contains(topoSim.svg)) { topoSim.raf = null; return; }  // 视图已切换
      // 页面不可见时停止动画，避免后台回流
      if (document.hidden) { topoSim.raf = requestAnimationFrame(tick); return; }
      var ns = topoSim.nodes, n = ns.length, cx = topoSim.W / 2, cy = topoSim.H / 2;
      // 两两斥力
      for (var i = 0; i < n; i++) {
        var a = ns[i], ax = 0, ay = 0;
        for (var j = 0; j < n; j++) {
          if (i === j) continue;
          var b = ns[j], dx = a.x - b.x, dy = a.y - b.y;
          var d2 = dx * dx + dy * dy; if (d2 < 1) d2 = 1;
          var f = 2600 / d2; var d = Math.sqrt(d2);
          ax += (dx / d) * f; ay += (dy / d) * f;
        }
        // 向中心轻微引力
        ax += (cx - a.x) * 0.012; ay += (cy - a.y) * 0.012;
        a._fx = ax; a._fy = ay;
      }
      // 弹簧（边）
      topoSim.edges.forEach(function (e) {
        if (e.kind === "chain" && !topoSim.showChain) return;
        var a = topoSim.byId[e.source], b = topoSim.byId[e.target];
        if (!a || !b) return;
        var ideal = e.kind === "chain" ? 150 : 95;
        var dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
        var f = (d - ideal) * 0.045;
        var fx = (dx / d) * f, fy = (dy / d) * f;
        a._fx += fx; a._fy += fy; b._fx -= fx; b._fy -= fy;
      });
      // 积分
      var al = topoSim.alpha;
      ns.forEach(function (p) {
        if (topoSim.drag && topoSim.drag.id === p.id) { p.vx = 0; p.vy = 0; return; }
        p.vx = (p.vx + (p._fx || 0) * al) * 0.82;
        p.vy = (p.vy + (p._fy || 0) * al) * 0.82;
        p.x += p.vx; p.y += p.vy;
        var pad = 40;
        if (p.x < pad) { p.x = pad; p.vx *= -0.5; }
        if (p.x > topoSim.W - pad) { p.x = topoSim.W - pad; p.vx *= -0.5; }
        if (p.y < pad) { p.y = pad; p.vy *= -0.5; }
        if (p.y > topoSim.H - pad) { p.y = topoSim.H - pad; p.vy *= -0.5; }
      });
      topoSim.alpha *= 0.985;
      _topoDraw();
      if (topoSim.alpha > 0.02) topoSim.raf = requestAnimationFrame(tick);
      else topoSim.raf = null;
    }
    topoSim.raf = requestAnimationFrame(tick);
  }

  function _topoReset() {
    if (!topoSim) return;
    var W = topoSim.W, H = topoSim.H;
    topoSim.nodes.forEach(function (n, i) {
      var ang = (i / topoSim.nodes.length) * Math.PI * 2;
      n.x = W / 2 + Math.cos(ang) * 190 + (i % 3) * 14;
      n.y = H / 2 + Math.sin(ang) * 130 + (i % 2) * 14;
      n.vx = 0; n.vy = 0;
    });
    topoSim.tx = 0; topoSim.ty = 0; topoSim.k = 1; topoSim.alpha = 1;
    _topoDraw(); _topoRun();
  }

  function _topoDetail(n) {
    var el = document.getElementById("topo-detail");
    if (!n) { el.innerHTML = '<span class="muted">' + esc(t("topoNoNode")) + '</span>'; return; }
    var h = '<div class="topo-d-h"><b>' + esc(n.label || n.id) + '</b> <span class="muted">' + esc(t("topo" + n.type.charAt(0).toUpperCase() + n.type.slice(1)) || n.type) + '</span></div>';
    if (n.type === "target") {
      h += '<div>' + esc(t("topoFindings")) + '：<b>' + (n.findingCount || 0) + '</b></div>';
      if (n.maxRisk) h += '<div>' + esc(t("topoRisk")) + '：<span style="color:' + _topoRiskColor(n.maxRisk) + ';font-weight:700">' + esc(n.maxRisk) + '</span></div>';
      if (n.tags && n.tags.length) h += '<div>' + esc(t("tags")) + '：' + n.tags.map(function (x) { return '<span class="tag chip">' + esc(x) + '</span>'; }).join(" ") + '</div>';
      if (n.status) h += '<div>' + esc(t("status")) + '：' + esc(n.status) + '</div>';
    } else if (n.type === "host") {
      h += '<div>' + esc(t("topoFindings")) + '：<b>' + (n.findingCount || 0) + '</b></div>';
      if (n.maxRisk) h += '<div>' + esc(t("topoRisk")) + '：<span style="color:' + _topoRiskColor(n.maxRisk) + ';font-weight:700">' + esc(n.maxRisk) + '</span></div>';
    } else if (n.type === "port") {
      h += '<div>' + esc(t("topoPorts")) + '：<b>' + esc(n.label) + '</b></div>';
    } else if (n.type === "finding") {
      h += '<div>' + esc(t("risk")) + '：<span style="color:' + _topoRiskColor(n.risk) + ';font-weight:700">' + esc(n.risk || t("topoUnknown")) + '</span></div>';
      if (n.findingId) h += '<div class="muted mono">#' + esc(n.findingId) + '</div>';
    }
    el.innerHTML = h;
  }

  // ---------------- 报告弹窗（F-01 多模板） ----------------
  function openReport(sid) {
    var curTpl = settings.report_template || "tech";
    function gen(tpl) {
      call("build_report", sid, tpl).then(function (r) {
        if (!r.ok) { toast(r.error || (settings.language === "en" ? "Report failed" : "生成报告失败"), "err"); return; }
        curTpl = r.template || tpl;
        var root = document.getElementById("modal-root");
        var tplOpts = [["summary", t("tplSummary")], ["tech", t("tplTech")], ["compliance", t("tplCompliance")]]
          .map(function (o) { return '<option value="' + o[0] + '"' + (o[0] === curTpl ? " selected" : "") + '>' + o[1] + '</option>'; })
          .join("");
        var buttons = '<label style="font-size:12px">' + t("reportTemplate") +
          ' <select id="rep-tpl">' + tplOpts + '</select></label> ' +
          '<button class="btn sm ghost" id="btn-save">' + t("saveHtml") + '</button> ' +
          '<button class="btn sm ghost" id="btn-pdf">' + t("savePdf") + '</button> ' +
          '<button class="btn sm ghost" id="btn-sarif">' + t("exportSarif") + '</button> ' +
          '<button class="btn sm ghost" id="btn-json">' + t("exportJson") + '</button> ' +
          '<button class="btn sm" id="btn-close">' + t("close") + '</button>';
        root.innerHTML = '<div class="overlay"><div class="modal" role="dialog" aria-modal="true" aria-label="' + t("report") + ' #' + esc(sid) + '">' +
          '<div class="modal-head"><b>' + t("report") + ' #' + esc(sid) + '</b>' +
          '<div>' + buttons + '</div></div>' +
          '<iframe class="report-frame" id="rep-frame" srcdoc="' + esc(r.html) + '"></iframe>' +
          '</div></div>';
        document.getElementById("btn-close").addEventListener("click", function () { root.innerHTML = ""; });
        document.getElementById("rep-tpl").addEventListener("change", function () { gen(this.value); });
        document.getElementById("btn-save").addEventListener("click", function () {
          var blob = new Blob([r.html], { type: "text/html" });
          var a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = "autopentest_report_" + sid + "_" + curTpl + ".html";
          a.click();
          URL.revokeObjectURL(a.href);
        });
        document.getElementById("btn-pdf").addEventListener("click", function () {
          call("build_pdf_report", sid, curTpl).then(function (pr) {
            if (pr.pdf_path) {
              var a = document.createElement("a");
              a.href = "file://" + pr.pdf_path;
              a.download = "autopentest_report_" + sid + "_" + curTpl + ".pdf";
              a.click();
            } else {
              toast(settings.language === "en" ? "PDF engine unavailable, saved HTML instead" : "未检测到 PDF 库，已保存 HTML", "ok");
              var blob = new Blob([pr.html || r.html], { type: "text/html" });
              var b = document.createElement("a");
              b.href = URL.createObjectURL(blob);
              b.download = "autopentest_report_" + sid + "_" + curTpl + ".html";
              b.click();
              URL.revokeObjectURL(b.href);
            }
          });
        });
        document.getElementById("btn-sarif").addEventListener("click", function () {
          call("build_sarif_report", sid).then(function (sr) {
            if (!sr.ok) { toast(sr.error || "SARIF export failed", "err"); return; }
            var blob = new Blob([sr.sarif], { type: "application/json" });
            var a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = "autopentest_report_" + sid + ".sarif.json";
            a.click();
            URL.revokeObjectURL(a.href);
          });
        });
        document.getElementById("btn-json").addEventListener("click", function () {
          call("build_json_report", sid).then(function (jr) {
            if (!jr.ok) { toast(jr.error || "JSON export failed", "err"); return; }
            var blob = new Blob([jr.json], { type: "application/json" });
            var a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = "autopentest_report_" + sid + ".json";
            a.click();
            URL.revokeObjectURL(a.href);
          });
        });
      });
    }
    gen(curTpl);
  }

  // ---------------- 授权书（U-10） ----------------
  function openLetter(tid) {
    call("authorization_letter", tid).then(function (r) {
      if (!r.ok) { toast(r.error || (settings.language === "en" ? "Generate failed" : "生成失败"), "err"); return; }
      var root = document.getElementById("modal-root");
      var buttons = '<button class="btn sm ghost" id="lt-save">' + t("saveHtml") + '</button> ' +
        '<button class="btn sm ghost" id="lt-print">' + t("printPdf") + '</button> ' +
        '<button class="btn sm" id="lt-close">' + t("close") + '</button>';
      root.innerHTML = '<div class="overlay"><div class="modal" role="dialog" aria-modal="true" aria-label="' + t("authLetter") + ' #' + esc(tid) + '" style="width:760px;max-width:94%">' +
        '<div class="modal-head"><b>' + t("authLetter") + ' · #' + esc(tid) + '</b><div>' + buttons + '</div></div>' +
        '<iframe class="report-frame" id="lt-frame" srcdoc="' + esc(r.html) + '"></iframe>' +
        '</div></div>';
      document.getElementById("lt-close").addEventListener("click", function () { root.innerHTML = ""; });
      document.getElementById("lt-save").addEventListener("click", function () {
        var blob = new Blob([r.html], { type: "text/html" });
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "autopentest_authorization_" + tid + ".html";
        a.click();
        URL.revokeObjectURL(a.href);
      });
      document.getElementById("lt-print").addEventListener("click", function () {
        var f = document.getElementById("lt-frame");
        try {
          if (f && f.contentWindow) { f.contentWindow.print(); return; }
        } catch (e) { /* 部分 webview 不支持 window.print，退回到保存 HTML */ }
        toast(settings.language === "en" ? "Print unsupported here; saved HTML instead" : "当前环境不支持打印，已保存 HTML（可用浏览器打印为 PDF）", "ok");
        var blob = new Blob([r.html], { type: "text/html" });
        var b = document.createElement("a");
        b.href = URL.createObjectURL(blob);
        b.download = "autopentest_authorization_" + tid + ".html";
        b.click();
        URL.revokeObjectURL(b.href);
      });
    });
  }

  // ---------------- 自动刷新（只读视图） ----------------
  // 注意：刻意排除 "scan" —— 扫描详情的轮询由上面专门的、可取消的 _scanTimer 负责，
  // 全局轮询只刷新仪表盘 / 扫描列表 / 复核队列的数据，绝不主动"进入"扫描界面。
  // 自动刷新（只读视图）：仅当数据真正变化时才重渲染当前视图。
  // 直接每 5s 整体重绘会导致仪表盘（尤其资产拓扑预览）周期性闪动，故先比对数据签名，
  // 未变化则跳过整页重渲染；活跃扫描期间数据变化仍会刷新（属预期更新）。
  var _lastRefreshSig = undefined;  // undefined = 尚未建立基线（导航已渲染，首拍仅建基线不重绘）
  function _autoRefresh() {
    if (["dashboard", "scans", "reviews"].indexOf(current.view) < 0) return;
    var p;
    if (current.view === "dashboard") p = Promise.all([call("list_targets"), call("list_scans", 20), call("list_reviews")]);
    else if (current.view === "scans") p = call("list_scans", 100);
    else p = call("list_reviews");
    p.then(function (res) {
      var sig;
      if (current.view === "dashboard")
        sig = res[0].map(function (x) { return x.id + ":" + (x.status || ""); }).join(",") + "|" +
              res[1].map(function (x) { return x.id + ":" + (x.status || "") + ":" + (x.stage || ""); }).join(",") + "|" +
              res[2].map(function (x) { return x.id + ":" + (x.kind || ""); }).join(",");
      else if (current.view === "scans")
        sig = res.map(function (x) { return x.id + ":" + (x.status || "") + ":" + (x.stage || ""); }).join(",");
      else
        sig = res.map(function (x) { return x.id + ":" + (x.kind || ""); }).join(",");
      if (_lastRefreshSig === undefined) { _lastRefreshSig = sig; return; }  // 首拍仅建基线
      if (sig === _lastRefreshSig) return;  // 未变化：跳过整页重渲染，杜绝拓扑预览闪动
      _lastRefreshSig = sig;
      router();
    }).catch(function () {});
  }
  setInterval(_autoRefresh, 5000);

  // ---------------- 首次使用向导（U-01） ----------------
  function renderWizard() {
    var root = document.getElementById("modal-root");
    var step = 1;
    function paint() {
      var html = '<div class="overlay"><div class="modal" style="max-width:600px">' +
        '<div class="modal-head"><b>🧭 ' + t("wizardTitle") + '</b>' +
        '<button class="btn sm ghost" id="wz-skip">' + t("wizardSkip") + '</button></div>' +
        '<div class="modal-body">';
      html += '<p class="muted">' + t("wizardIntro") + '</p>' +
        '<div class="wzstep">' + t("wizardStep").replace("{n}", step) + '</div>';
      if (step === 1) {
        html += '<h3 style="margin:6px 0 10px">' + t("wizardStep1Title") + '</h3>' +
          '<div class="form-row"><label>' + t("targetHost") + '</label><input id="wz-host" placeholder="192.168.1.10 / example.com"></div>' +
          '<div class="form-row"><label>' + t("portRange") + '</label><select id="wz-port">' +
          '<option value="common">' + t("commonPorts") + '</option><option value="top1000">' + t("top1000") + '</option>' +
          '<option value="80,443,8080-8090">' + t("customPorts") + '</option></select></div>' +
          '<div class="form-row"><label>' + t("authNote") + '</label><textarea id="wz-auth" placeholder="PT-2026-0730"></textarea></div>' +
          '<div class="checkrow"><input type="checkbox" id="wz-authc"><label for="wz-authc">' + t("authorize") + '</label></div>';
      } else if (step === 2) {
        html += '<h3 style="margin:6px 0 10px">' + t("wizardStep2Title") + '</h3>' +
          '<div class="form-row"><label>' + t("reportTemplate") + '</label>' +
          '<select id="wz-tpl"><option value="summary">' + t("tplSummary") + '</option>' +
          '<option value="tech" selected>' + t("tplTech") + '</option>' +
          '<option value="compliance">' + t("tplCompliance") + '</option></select></div>' +
          '<p class="muted">' + t("wizardTplTech") + '</p>';
      } else {
        html += '<h3 style="margin:6px 0 10px">' + t("wizardStep3Title") + '</h3>' +
          '<p>' + t("wizardDone2") + '</p>';
      }
      html += '</div><div class="modal-foot" style="padding:12px 16px;display:flex;gap:8px;justify-content:flex-end">';
      if (step > 1) html += '<button class="btn sm ghost" id="wz-back">' + t("wizardBack") + '</button>';
      if (step < 3) html += '<button class="btn sm" id="wz-next">' + t("wizardNext") + '</button>';
      else html += '<button class="btn sm" id="wz-finish">' + t("wizardFinish") + '</button>';
      html += '</div></div></div>';
      root.innerHTML = html;
      var skip = document.getElementById("wz-skip");
      if (skip) skip.addEventListener("click", finishWizard);
      var back = document.getElementById("wz-back");
      if (back) back.addEventListener("click", function () { step--; paint(); });
      var next = document.getElementById("wz-next");
      if (next) next.addEventListener("click", function () {
        if (step === 1) {
          var host = document.getElementById("wz-host").value.trim();
          if (!host) { toast(t("targetHost") + " " + (settings.language === "en" ? "required" : "必填"), "err"); return; }
          if (!document.getElementById("wz-authc").checked) { toast(t("noPermission"), "err"); return; }
          call("add_target", host, document.getElementById("wz-port").value, "",
               document.getElementById("wz-auth").value, true, 1).then(function (r) {
            if (!r.ok) { toast(r.error || (settings.language === "en" ? "Failed" : "添加失败"), "err"); return; }
            toast(t("addTarget") + " OK", "ok");
            step++; paint();
          });
        } else if (step === 2) {
          var tpl = document.getElementById("wz-tpl").value;
          call("set_settings", { report_template: tpl }).then(function () {
            settings.report_template = tpl;
            step++; paint();
          });
        }
      });
      var finish = document.getElementById("wz-finish");
      if (finish) finish.addEventListener("click", finishWizard);
    }
    function finishWizard() {
      call("set_settings", { wizard_done: "1" }).then(function () {
        settings.wizard_done = "1";
        root.innerHTML = "";
        router();
      });
    }
    paint();
  }

  // ---------------- 启动 ----------------
  window.addEventListener("hashchange", router);
  // ---------------- U-08 键盘快捷键 ----------------
  var _gotoMap = { d: "dashboard", t: "targets", s: "scans", a: "audit", r: "reviews", c: "scheduler", "?": "settings" };
  var _gotoPending = false;
  function toggleShortcutHelp() {
    var ex = document.getElementById("kbd-help");
    if (ex) { ex.remove(); return; }
    var rows = [
      ["g then d", settings.language === "en" ? "Dashboard" : "仪表盘"],
      ["g then t", settings.language === "en" ? "Targets" : "目标"],
      ["g then s", settings.language === "en" ? "Scans" : "扫描"],
      ["g then a", settings.language === "en" ? "Audit" : "审计"],
      ["g then r", settings.language === "en" ? "Reviews" : "复核"],
      ["g then c", settings.language === "en" ? "Scheduler" : "定时"],
      ["g then ?", settings.language === "en" ? "Settings" : "设置"],
      ["? / Ctrl+K", settings.language === "en" ? "Toggle this help" : "切换本帮助"],
    ];
    var html = '<div class="overlay" id="kbd-help"><div class="modal" role="dialog" aria-modal="true" aria-label="' +
      (settings.language === "en" ? "Keyboard Shortcuts" : "键盘快捷键") + '" style="width:440px"><div class="modal-head"><b>' +
      (settings.language === "en" ? "Keyboard Shortcuts" : "键盘快捷键") + '</b>' +
      '<button class="btn sm ghost" id="kbd-help-close">' + t("close") + '</button></div>' +
      '<div class="modal-body"><table class="kbd-table">' +
      rows.map(function (r) { return '<tr><td><code>' + esc(r[0]) + '</code></td><td>' + esc(r[1]) + '</td></tr>'; }).join("") +
      '</table></div></div></div>';
    document.body.insertAdjacentHTML("beforeend", html);
    var hc = document.getElementById("kbd-help-close");
    if (hc) hc.addEventListener("click", function () { var e = document.getElementById("kbd-help"); if (e) e.remove(); });
    // 点击遮罩（面板外区域）关闭快捷键帮助
    var kbdOv = document.getElementById("kbd-help");
    if (kbdOv) kbdOv.addEventListener("click", function (e) { if (e.target === kbdOv) kbdOv.remove(); });
  }
  function setupShortcuts() {
    document.addEventListener("keydown", function (e) {
      var tag = (e.target && e.target.tagName) || "";
      if (/^(INPUT|SELECT|TEXTAREA)$/.test(tag) || (e.target && e.target.isContentEditable)) return;
      if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        var _ov = document.getElementById("cmd-overlay");
        if (_ov && !_ov.classList.contains("hidden")) closeCmdPalette();
        else openCmdPalette();
        return;
      }
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (_gotoPending) {
        var v = _gotoMap[e.key.toLowerCase()];
        _gotoPending = false;
        if (v) { navigate("#" + v); toast((settings.language === "en" ? "Go: " : "跳转：") + v, "ok"); }
        return;
      }
      if (e.key === "g" || e.key === "G") { _gotoPending = true; return; }
      if (e.key === "?") { toggleShortcutHelp(); return; }
      if (e.key === "Escape") {
        // U-09：Esc 关闭任意打开的弹窗（对话框 / 报告 / 授权书）或快捷键帮助
        var ov = document.querySelector("#modal-root .overlay");
        if (ov) { ov.parentElement.innerHTML = ""; return; }
        var h = document.getElementById("kbd-help"); if (h) h.remove();
      }
    });
  }

  function boot() {
    setupShortcuts();
    bindChromeEvents();  // 绑定顶栏事件、粒子背景、按钮光晕（v1.20.0 方案B）
    if (!api) { view().innerHTML = '<div class="empty"><span class="spinner"></span>' + (settings.language === "en" ? "Initializing local engine..." : "正在初始化本地引擎…") + '</div>'; return; }
    loadSettings().then(function () {
      loadVulnI18n();   // U-07：加载当前语言的漏洞双语映射
      // 首次向导：无目标且尚未跑过向导时弹出（U-01）
      if (settings.wizard_done === "1") { router(); return; }
      call("list_targets").then(function (targets) {
        if (!targets || !targets.length) renderWizard();
        else { settings.wizard_done = "1"; router(); }
      }).catch(function () { router(); });
    });
  }
  // ============ 自检测试桥（仅 --selftest 模式由宿主触发，常态零副作用） ============
  function installErrorHooks() {
    window.__errors = window.__errors || [];
    if (window.__stHooks) return;
    window.__stHooks = true;
    window.addEventListener("error", function (e) {
      window.__errors.push({ type: "js", msg: e.message, stack: (e.error && e.error.stack) || "", ts: Date.now() });
    });
    window.addEventListener("unhandledrejection", function (e) {
      var r = e.reason || {};
      window.__errors.push({ type: "promise", msg: (r && r.message) || String(r), stack: (r && r.stack) || "", ts: Date.now() });
    });
    var oe = console.error, ow = console.warn;
    console.error = function () {
      try { window.__errors.push({ type: "console.error", msg: Array.prototype.map.call(arguments, String).join(" "), stack: "", ts: Date.now() }); } catch (_) {}
      return oe.apply(console, arguments);
    };
    console.warn = function () {
      try { window.__errors.push({ type: "console.warn", msg: Array.prototype.map.call(arguments, String).join(" "), stack: "", ts: Date.now() }); } catch (_) {}
      return ow.apply(console, arguments);
    };
  }
  // 由宿主（main_gui --selftest）调用：逐视图导航 + 探测 API + 采集异常 + 落盘报告
  function runSelfTest(plan) {
    plan = plan || {};
    var views = plan.views || ["dashboard", "targets", "scans", "reviews", "topology", "settings", "audit", "scheduler"];
    var probes = plan.api || [
      { method: "list_targets" }, { method: "list_scans", args: [20] },
      { method: "list_reviews" }, { method: "topology_data" }, { method: "get_settings" }
    ];
    var actions = plan.actions || [];
    installErrorHooks();
    window.__errors = [];
    var report = { ts: new Date().toISOString(), views: [], api: [], actions: [], backendErrors: [], errors: [], summary: {} };
    function wait(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
    function snap() {
      var v = view();
      return { hasView: !!v, scrollHeight: v ? v.scrollHeight : 0, bodyLen: document.body ? document.body.innerHTML.length : 0 };
    }
    function gotoView(v) {
      return Promise.resolve().then(function () { navigate("#" + v); router(); })
        .then(function () { return wait(700); })
        .then(function () { report.views.push({ view: v, errors: window.__errors.slice(), snap: snap() }); });
    }
    function probe(p) {
      return Promise.resolve().then(function () {
        var a = p.args || [];
        return call.apply(null, [p.method].concat(a));
      }).then(function () { report.api.push({ method: p.method, ok: true }); })
        .catch(function (e) {
          report.backendErrors.push({ method: p.method, msg: (e && e.message) || String(e), stack: (e && e.stack) || "" });
          report.api.push({ method: p.method, ok: false });
        });
    }
    function act(sel) {
      return Promise.resolve().then(function () {
        var el = document.querySelector(sel);
        if (el) { el.click(); return wait(400).then(function () { report.actions.push({ sel: sel, clicked: true }); }); }
        report.actions.push({ sel: sel, clicked: false, note: "not found" });
      });
    }
    return Promise.resolve().then(function () { return loadSettings(); }).then(function () {
      var chain = Promise.resolve();
      views.forEach(function (v) { chain = chain.then(function () { return gotoView(v); }); });
      probes.forEach(function (p) { chain = chain.then(function () { return probe(p); }); });
      actions.forEach(function (s) { chain = chain.then(function () { return act(s); }); });
      return chain;
    }).then(function () {
      report.errors = window.__errors.slice();
      var errs = window.__errors;
      report.summary = {
        totalErrors: errs.length,
        jsErrors: errs.filter(function (e) { return e.type === "js" || e.type === "promise"; }).length,
        consoleErrors: errs.filter(function (e) { return e.type.indexOf("console") === 0; }).length,
        backendErrors: report.backendErrors.length
      };
      try {
        if (api && api.selftest_report) return api.selftest_report(JSON.stringify(report)).then(function () { return report; });
      } catch (_) {}
      return report;
    });
  }
  window.__app = {
    runSelfTest: runSelfTest,
    errors: function () { return window.__errors || []; },
    goto: function (v) { navigate("#" + v); router(); },
    routes: function () { return ["dashboard", "targets", "scans", "reviews", "topology", "settings", "audit", "scheduler"]; }
  };

  if (window.pywebview) {
    api = window.pywebview.api;
    boot();
  } else {
    window.addEventListener("pywebviewready", function () {
      api = window.pywebview.api;
      boot();
    });
  }
})();
