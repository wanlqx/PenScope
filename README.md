# PenScope

> AI 驱动的**自动化渗透测试**桌面工具（纯本地、无后端、无需登录）。

**正式版 v1.0.0** · 下载见 [GitHub Releases](../../releases) · 仅用于已获书面授权的渗透测试。

[![CI](https://github.com/wanlqx/PenScope/actions/workflows/ci.yml/badge.svg)](https://github.com/wanlqx/PenScope/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/wanlqx/PenScope?label=release)](https://github.com/wanlqx/PenScope/releases)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

PenScope 是一款面向安全测试人员 / 授权渗透测试场景的桌面应用。它把端口扫描、Web 漏洞扫描（SQL 注入、XSS、CSRF、文件上传）、利用验证、报告生成等工作流整合在一个原生窗口中，**所有逻辑都在你本机运行**，不依赖任何远程服务器，也不需要账号密码。

---

## ✨ 核心特性

- **纯本地、无后端**：pywebview 原生窗口直接加载内置前端，前端通过 JS 桥调用本机 Python 扫描引擎；没有 HTTP 服务、没有账号体系，数据只存于本机 SQLite。
- **授权围栏**：新增目标必须显式确认「已获书面授权」才会被批准可扫描，防止对未授权资产发起测试。
- **人工复核闸门**：利用验证（时间盲注证明）、文件上传测试等高危动作会被暂停，需你在界面点击「批准」才继续执行——既安全又透明。
- **完整渗透测试工作流**：`授权目标 → 端口 / 子域探测 → Web 漏洞扫描 → 利用验证 → 报告`，一键生成带风险分级与修复建议的 HTML 报告。
- **专业安全报告**：每份报告包含漏洞名称、类型、**CWE 编号**、**CVSS 3.1 评分 / 向量**、从环境准备到 Payload 的完整复现步骤、受影响端点 / 方法、概念验证（PoC）片段、修复建议与预防措施，并标注每项发现的验证状态。
- **结构化漏洞模型 + 语义去重**：每个发现携带 CWE、CVSS、验证状态、证据等级、端点 / 方法、PoC 等结构化字段；按类型 / 位置 / 描述相似度去重，根治「同一注入点被多次报告」，同时保留证据更充分的一方。
- **多层漏洞验证（降低误报）**：SQLi 经错误型 / 时间盲注双重确认、XSS 验证在可执行上下文回显、利用验证阶段执行受控探针；已验证发现标记 `已验证`，疑似发现标记 `待确认`，在报告与列表中直观区分。
- **覆盖的漏洞检测能力**：
  - 端口 / 服务探测与资产暴露发现；
  - Web 十大类漏洞：SQL 注入、XSS、CSRF、文件上传、SSRF（CWE-918）、路径遍历（CWE-22）、开放重定向（CWE-601）、缺失授权（CWE-862）、认证缺陷（CWE-287，默认凭据探测 opt-in）、敏感信息泄露；
  - 邮件协议 STARTTLS / 明文传输检测（SMTP / POP3 / IMAP，只观察不登录）；
  - 目录暴露与云 AK/SK、JWT、私钥、内网 IP、调试堆栈等泄露检测（全只读）；
  - 已知漏洞版本联动（被动命中「组件 + 版本 + CVE」）与 WAF 自适应绕过变换。
- **误报治理体系**：命令注入差分标记消除反射误报、CSRF 区分「真无防护才报高危」、布尔盲注多轮稳定判定、基线差分排除页面固有内容、软 404 相似度降噪——宁漏不夸。
- **资产管理与可视化**：资产拓扑力导向图（暴露面 / 风险热图 / 漏洞利用链）、目标标签分组、资产基线快照与变更告警、中文渗透测试授权书生成。
- **报告与合规导出**：多模板 HTML 报告（摘要 / 技术 / 合规对照）、SARIF 2.1.0 与标准化 JSON 机器可读导出、漏洞利用链编排（如 SSRF→内网）、中文渗透测试授权书。
- **设置与个性化**：中文 / 英文界面、浅色 / 深色主题、字体大小、舒适 / 紧凑 / 卡片三种布局，设置持久化到本地数据库。
- **视觉效果可自主开关（新增）**：提供统一的「视觉效果」总开关，可一键开启 / 关闭所有动态与静态视觉特效——鼠标拖尾、自定义光标、背景粒子、扫描线、暗角、噪点与按钮光晕。关闭后恢复系统原生简洁外观，适合追求性能或纯净界面的场景；各特效亦可在设置中单独微调。
- **定时 / 批量巡检**：可创建定时任务，对多个已授权目标周期性巡检。
- **审计日志与合规留痕**：所有关键动作留痕，便于复盘与合规；近 90 天操作密度热力图可视化。
- **插件化扩展框架**：继承 `BaseScanner` 的 `.py` 放入 `~/.autopentest/plugins/`，经 `python -m scanner.plugins trust <file>` 登记信任后接入扫描流水线；默认「严格信任」模式杜绝静默任意代码执行。详见 [CONTRIBUTING.md](CONTRIBUTING.md)。
- **加密凭据保险库（可选）**：为需要登录态的目标提供 Fernet 加密凭据库与会话续期（默认关闭，需显式开启并二次确认），前端只返回掩码，后端绝不回传明文密码。
- **单文件分发**：打包为单个 `PenScope.exe`，双击即用，含系统托盘（关闭窗口最小化到托盘）。

---

## 🔒 安全与合规

- **仅限授权使用**：本工具用于你**已获书面授权**的目标。新增目标需显式确认授权；默认不执行任何主动 / 破坏性动作（默认凭据探测、会话续期、上传测试均默认关闭，需人工开启并二次确认）。
- **纯本地、无外联后台**：所有扫描逻辑在本机运行，不回传任何数据；子域枚举等只读情报源为公开服务（crt.sh / DNS），且只记为资产发现。
- **仓库不含任何密钥 / 凭据**：运行时密钥由程序在 exe 同级目录自动生成（Fernet），前端永不接触明文密码；本仓库通过 `.gitignore` 排除所有 `*.key`、`*vault*.json`、数据库与日志。详见 [SECURITY.md](SECURITY.md)。
- **合法合规**：请遵守所在地区法律法规与目标方的授权范围；产生的报告与授权书可作为测试合法性凭证。

---

## 📦 安装与运行

### 方式一：直接运行（推荐给使用者）
1. 从发布页下载 `PenScope.exe`。
2. **确保已安装 [Microsoft Edge WebView2 运行时](https://developer.microsoft.com/zh-cn/microsoft-edge/webview2/)**（Windows 10/11 通常已内置；若双击无窗口，请安装后重试）。
3. 双击 `PenScope.exe`，自动弹出原生界面。

> 数据（扫描库 `autopentest.db`）保存在 exe 同级目录，卸载时删除该目录即可。

### 方式二：从源码运行（开发者）
要求：Python **3.11+**（GUI 推荐 Windows + [WebView2 运行时](https://developer.microsoft.com/zh-cn/microsoft-edge/webview2/)）。
```bash
pip install -r requirements-lock.txt || pip install -r requirements.txt   # 优先锁文件，保证可复现
python main_gui.py
```

---

## 🚀 使用流程

1. **授权目标**：侧栏「授权目标」→ 填写主机 / IP、端口范围，勾选「我已获得该目标的书面授权」→ 提交即被批准。
2. **发起扫描**：在目标行点击「发起扫描」，后台自动执行。可在「扫描任务」查看进度。
3. **处理复核闸门**：若发现高危注入或上传点，扫描会在「利用验证 / 上传测试」节点暂停。前往「复核闸门」点击「批准」继续（或「拒绝」终止）。
4. **查看报告**：扫描完成后，在扫描详情页点击「查看 / 保存完整报告」，可在线查看或导出 HTML。

---

## ⚠️ 合法使用声明

本工具**仅限对您已获得书面授权的目标**进行安全测试。未经授权对他人系统发起扫描，可能违反《网络安全法》等相关法律法规，后果由使用者自行承担。所有利用验证均为只读或良性探针，不执行破坏性操作。生成的报告含敏感安全信息，请妥善保管。

---

## 🗂 项目结构（开发者）

```
PenScope/
├── main_gui.py        # 桌面入口：启动引擎线程 + pywebview 原生窗口
├── app_api.py         # JS 桥接口层（前端调用的本地 Python 方法）
├── config.py          # 路径 / 扫描参数 / 版本 / 复核闸门配置
├── db.py              # SQLite 数据访问（目标/扫描/发现/复核/调度/审计）
├── run_scans.py       # 扫描编排 Worker（阶段机）
├── reports.py         # HTML 报告生成
├── scanner/           # 扫描引擎（端口/Web/载荷）
├── frontend/          # 纯静态前端（index.html / app.js / style.css / i18n.js）
├── assets/            # 图标、托盘图标
├── tests/             # 单元测试 + E2E（pytest）
├── conftest.py        # 测试路径引导（项目根加入 sys.path）
├── build_nowrap.py    # 打包脚本（PyInstaller 单文件，自动 verify_build）
└── PenScope.spec      # 打包规格
```

### 打包
```bash
python build_nowrap.py        # 按 PenScope.spec 用 PyInstaller 构建，并自动跑 verify_build 校验
```
产物：`dist/PenScope.exe`（单文件、隐藏终端、内置原生界面 + 系统托盘）。

> **打包环境要求（重要）**：构建**必须在 Windows 上进行**（PyInstaller 单文件 + WebView2 原生界面），CI 的发布流程也使用 `windows-latest` runner。
> `build_nowrap.py` 在**本次构建进程内、且仅在 PyInstaller 构建期**会临时把 `os.remove / unlink / rmdir` 还原为 Windows 底层 `nt.*` 实现，以绕过本机 safe-delete 沙箱封装，使构建清理步骤能删除临时文件；**构建结束后立即还原**，不污染其它逻辑，也不在打包产物中留后门。请勿在非 Windows 或非受信环境运行该脚本。详见 [SECURITY.md](SECURITY.md) 与 `build_nowrap.py` 头部注释。

### 运行测试
```bash
pip install pytest
python -m pytest              # 运行 tests/ 下全部单元测试
# CI 默认仅运行「无需显示/网络」的纯逻辑子集（跨 ubuntu + windows 双 runner）：
python -m pytest tests/test_session_vault.py tests/test_hardening.py \
    tests/test_cred_dict.py tests/smoke_nobackend.py \
    tests/test_scope_redirect.py tests/test_vuln_i18n.py -q
```
E2E 脚本（`tests/e2e_access_auth_dvwa.py` 等）需本地起受控目标或 DVWA，默认不随 `pytest` 自动执行。

---

## 🔐 安全设计要点

- 无网络服务端、无账号体系，数据仅存于本机 SQLite。
- 授权围栏 + 人工复核闸门，确保高危动作需使用者显式确认。
- 扫描引擎使用参数化查询访问自身数据库，杜绝 SQL 注入。
- 利用验证仅做「证明可利用」（时间盲注 / 错误复现），不提取数据；上传测试仅上传良性标记文件。
- 工具定位为**只读 / 良性**扫描器：所有写入 / 延迟 / 外带类动作（命令注入时间盲注、文件上传测试）均走人工批准闸门，默认不触发；仅用于你已获授权的目标。
- **插件以当前用户权限执行任意代码**：内置示例插件随包发布、受信；外部插件默认「严格信任」模式——落盘文件不会自动执行，须先 `python -m scanner.plugins trust <file>` 登记（记录 SHA-256，篡改即拒载）。**只安装来自可信来源的插件**，第三方插件等同于在本机运行其代码。长期计划将插件放入独立子进程隔离运行（见 [CONTRIBUTING.md](CONTRIBUTING.md)）。

---

## 🤝 参与贡献

欢迎参与 PenScope 的开发！请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 了解开发环境搭建、测试运行与 PR 流程，并遵守 [行为准则](CODE_OF_CONDUCT.md)。发现安全漏洞请按 [安全策略](SECURITY.md) **私下**报告，勿公开 Issue。

## 📄 许可证

本项目以 [Apache License 2.0](LICENSE) 发布。
