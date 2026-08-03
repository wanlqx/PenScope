# PenScope

> AI 驱动的**自动化渗透测试**桌面工具（纯本地、无后端、无需登录）。

**正式版 v1.0.0** · 下载见 [GitHub Releases](../../releases) · 仅用于已获书面授权的渗透测试。

PenScope 是一款面向安全测试人员 / 授权渗透测试场景的桌面应用。它把端口扫描、Web 漏洞扫描（SQL 注入、XSS、CSRF、文件上传）、利用验证、报告生成等工作流整合在一个原生窗口中，**所有逻辑都在你本机运行**，不依赖任何远程服务器，也不需要账号密码。

---

## ✨ 特性

- **纯本地、无后端**：pywebview 原生窗口直接加载内置前端，前端通过 JS 桥调用本机 Python 扫描引擎；没有 HTTP 服务、没有账号体系。
- **授权围栏**：新增目标必须显式确认「已获书面授权」才会被批准可扫描，防止对未授权资产发起测试。
- **人工复核闸门**：利用验证（时间盲注证明）、上传测试等高危动作会被暂停，需你在界面点击「批准」才继续执行——既安全又透明。
- **完整工作流**：`授权目标 → 扫描（端口/Web 漏洞）→ 利用验证 → 报告`，一键生成带风险分级与修复建议的 HTML 报告。
- **专业测试报告（v1.2.0 / v1.3.0 增强）**：每份报告包含漏洞名称、类型、**CWE 编号**、**CVSS 3.1 评分/向量**、从环境准备到 Payload 的完整复现步骤、**受影响端点/方法**、**概念验证（PoC）片段**、修复建议与预防措施，并标注每项发现的**验证状态**。
- **结构化漏洞模型 + 语义去重（v1.3.0）**：每个发现携带 CWE、CVSS、验证状态、证据等级、端点/方法、PoC 等结构化字段；采用借鉴 VulnClaw 的语义相似度（类型 0.3 + 位置 0.4 + 描述 0.3，阈值 0.75）做去重，根治「同一端口/注入点被多次报告」问题，同时保留证据更充分的一方。
- **漏洞验证机制（v1.3.0）**：SQLi 经错误型 / 时间盲注双重确认、XSS 验证在可执行上下文回显、利用验证阶段执行受控探针——已验证的发现标记为 `已验证`，启发式/疑似发现标记为 `待确认`，在报告与列表中直观区分，**显著降低误报**。
- **命令注入 + API 安全（v1.3.2）**：命令注入检测采用**差分标记法**（注入 `APCMD_$((a+b))` 这类含命令替换的载荷，仅当"执行态结果出现且字面串不出现"才判定），从根上消除反射型误报；API 安全被动检测 CORS 误配置、明文令牌/密钥泄露、方法滥用与详细错误。
- **子域枚举 + 目录/敏感信息扫描（v1.3.4）**：被动子域枚举（crt.sh 证书透明度 + 只读 DNS 解析，仅记为资产发现、绝不自动建扫描）；目录暴露与云 AK/SK、JWT、私钥、内网 IP、调试堆栈等敏感信息泄露检测（全只读 GET/HEAD）。
- **误报率持续降低（v1.3.5 / v1.3.6）**：命令注入差分标记消除反射误报；CSRF 仅对"无 Token 字段 + 无自定义 Header/同源校验信号 + 服务端接受良性 POST"的表单报高危，其余（受 SameSite/自定义 Header/服务端校验保护）降级 Info；SQLi 布尔盲注改为多轮采样 + 基线归一化，仅"多轮稳定差异"才判定，消除动态内容造成的误报。
- **覆盖缺口分析（v1.3.7 起）**：基于公开漏洞态势（NVD / CNVD）做能力覆盖 gap 分析，让扫描能力边界持续跟随真实威胁，而非封闭在自有规则库里。
- **扫描健壮性增强（v1.3.7）**：
  - **私有地址护栏**：`scope_check` 阶段自动识别 RFC1918 私有段 / 链路本地 / 保留 / 未指定网段并阻断扫描，防止误扫内网（回环地址特意放行，保留本机评估场景）。
  - **邮件 / 协议感知**：对 SMTP(25/587)/POP3(110)/IMAP(143) 等按服务类型选端口模板，做只渎的 STARTTLS / 明文传输检测（不改密、不登录、不爆破），把"明文传输无 STARTTLS"作为中危配置缺陷发现。
  - **同 IP 多 vhost 端口复用**：对共享公网 IP 的多个子域，复用一次端口探测结果，仅分别做 vhost 级 Web 检测，避免重复端口扫描噪音。
- **覆盖缺口补齐（v1.3.8）：SSRF + 路径遍历**：基于覆盖缺口分析，补齐 Top 高频缺口中的两项——
  - **SSRF / CWE-918**：两层检测。① 强证据（保守，仅在明确证据时）：注入 `file:///etc/passwd` 或云元数据地址（`169.254.169.254/latest/meta-data`）后，若响应出现本地文件内容 / 元数据 JSON 特征，报高危（仍标记待确认 / L3）；② 对 `url/file/path/redirect/avatar` 等 URL 类参数给出**低危"潜在 SSRF 注入点"观察项**（与既有上传点 / API 被动检测风格一致），不夸大为已利用。
  - **路径遍历 / CWE-22**：只读响应检测，向 URL 参数与表单字段注入 `../` 序列（含 URL 编码 / 双重编码 / 点斜杠 / Windows 反斜杠变体），观测是否泄露 `/etc/passwd` 或 `win.ini` 内容；**以"无载荷基线"排除页面固有内容误报**，判定均为中危 / 待确认 / L2。
- **访问控制与认证（v1.3.9）：缺失授权 + 认证缺陷**：基于覆盖缺口分析，补齐后续两项高频缺口——
  - **缺失授权 / CWE-862**：强制浏览（对敏感路径发"无会话" GET，与 404 基线差分，L2/unverified）+ 权限指示参数（role=/admin=/uid= 等）被动观察（L1）；四重降噪（基线差异 + 静态资源排除 + 敏感路径白名单 + 软 404 相似度），宁漏不夸。
  - **认证缺陷 / CWE-287**：被动 L1 观察（登录端点识别 / 凭证出现在 URL query / 明文 HTTP 表单 / Basic 非 HTTPS）；**主动默认凭据探测默认关（opt-in，config.ENABLE_AUTH_PROBE）**，避免触发账号锁定 / 被判定爆破，延续"只读不写"原则。
- **开放重定向（v1.4.0）：CWE-601**：基于覆盖缺口分析补齐后续高频缺口——向 URL 参数 / 表单字段注入重定向 sink 载荷，仅当响应 `3xx` 且 `Location` 指向**站外主机**才报"潜在开放重定向"（中危 / 待确认 / L2）。保守降噪：① 只认站外跳转、同源跳转一律排除；② `allow_redirects=False` 只读 Location 头、零外联；③ 重定向 sink 参数名额外给一条低危 L1 被动观察（与 SSRF / 缺失授权同风格）。
  - **认证探针 CSRF 感知（v1.4.0 增强）**：`CWE-287` 默认凭据探测在 opt-in 开启后，会先抓取登录页、提取并回填 `user_token` 等真实隐藏字段，使探针可在 DVWA 之类带 CSRF 校验的登录端点用 `admin/password` 正常命中（不再被 "CSRF token is incorrect" 拦下），同时不影响无 token 端点的原有行为。
- **设置模块（v1.2.0 / v1.3.0 多语言）**：支持中文/英文切换（语言资源抽离到 `frontend/i18n.js`，可扩展更多语言）、浅色/深色主题、字体大小调节、舒适/紧凑/卡片三种布局；设置持久化到本地数据库。
- **定时 / 批量**：可创建定时任务，对多个已授权目标周期性巡检。
- **审计日志**：所有关键动作留痕，便于复盘与合规。
- **体验与闭环增强（v1.5.0）**：首次使用向导、目标中心化视图、多模板报告（摘要/技术/合规对照）、漏洞利用链编排（SSRF→内网、缺失授权→敏感接口等）、修复跟踪闭环（发现修复状态 + 同目标重扫差异对比）、SARIF 2.1.0 / 标准化 JSON 机器可读导出、发现分页、删除操作 5 秒可撤销、统一错误码体系（`{ok, code, error, hint}`）；扫描引擎 asyncio 协程化提速，DB 复合索引优化大列表查询。
- **扫描可观测性增强（v1.6.0）**：扫描详情新增**阶段甘特图**（作用域校验 → 端口探测 → 子域枚举 → Web 检测 → 利用验证 → 上传测试 → 报告，按真实耗时着色、暂停/失败态高亮）；扫描失败按根因**结构化归类**（未授权 / 私有网段 / 目标不可达 / 响应超时 / TLS 校验失败 / 重定向环路 / 未预期错误），详情页给出针对性处置建议（TLS 校验失败可直接跳转目标编辑「跳过 TLS 校验」）；`process_scan` 全阶段埋点并捕获异常，杜绝扫描卡在 running。
- **发现证据增强（v1.7.0）**：发现表格新增**证据等级**列（L1 观察 / L2 请求响应 / L3 已验证 / L4 强验证），点击行打开详情弹窗分级展示证据、**请求/响应 Diff**（高亮注入载荷）、PoC/curl 一键复制，以及**CVSS 3.1 交互计算器**（8 度量实时评分、人工校准回写报告）。
- **漏洞分析视图（v1.8.0）**：扫描详情新增**漏洞矩阵**弹窗（端点 × 漏洞类型热力表，按风险着色、点击单元格下钻到代表发现）；目标中心新增**扫描对比**弹窗，手动选同目标的两次扫描做基线 Diff，三色渲染新增 / 已解决 / 持续发现（与自动重扫差异互补）。
- **检测深度增强（v1.9.0）**：时间盲注改用**5 次良性响应统计基线 + 3σ 抖动吸收**（C-02，误报显著下降）；payload 按**检测到的 WAF 类型**自动切换绕过变换（C-03，覆盖 Cloudflare/AWS/ModSecurity/360/Akamai 等）；Web 检测阶段对 `Server`/框架头做**CVE 版本联动**（C-04，被动命中「组件+版本+CVE」）。
- **数据生命周期（v1.10.0）**：扫描支持**归档**（默认视图隐藏历史，可一键恢复）；目标中心提供「显示已归档」勾选、单条归档/取消、以及「归档 90 天前扫描」批量动作，长期使用的扫描库不再被陈旧数据淹没。
- **实时进度推送（v1.11.0）**：用 pywebview 事件推送**替代前端 4 秒轮询**——扫描阶段事件由 Python 主动推给前端即时刷新（甘特图/发现/状态），轮询降级为 8 秒兜底且仅在推送丢失时生效，CPU 占用下降、实时性提升。
- **插件化框架（v1.12.0）**：打破硬编码，提供 `BaseScanner` 抽象基类 + `ScanContext` 受限上下文；`~/.autopentest/plugins/` 放入继承 `BaseScanner` 的 `.py` 即可被自动发现并接入流水线（内置示例：被动安全响应头检测）。二次开发门槛显著下降。
- **运维/UX 增强（v1.13.0）**：**敏感数据脱敏**（U-12，证据与请求/响应中的密钥/Token/私钥展示即掩码，导出亦脱敏）；**一键诊断包导出**（U-05，设置页打包版本/统计/审计为 JSON 报障）；**键盘快捷键**（U-08，`g` 前缀导航 + `?`/`Ctrl+K` 帮助）；**审计热力图**（U-11，近 90 天操作密度可视化）。
- **资产分组与无障碍（v1.14.0）**：**目标标签分组（F-06）**——目标可打彩色标签（如 `dmz`/`prod`/`critical`，单标签 ≤32 字、≤20 个），目标列表顶部按标签一键筛选（含计数），目标中心可编辑标签；**渗透测试授权书（U-10）**——一键生成中文授权书 HTML（含文档编号/签署栏/授权范围/允许与禁止动作/30 天有效期），内联预览并可打印/另存为 PDF，作为测试合法性书面凭证；**前端无障碍（U-09）**——skip-link 跳转到主内容、`role=navigation/main/dialog`、焦点可见轮廓、`aria-live` 状态播报、Esc 关闭弹窗，契合 WCAG 方向。
- **漏洞描述双语映射（v1.15.0 / U-07）**：新增 `scanner/vuln_i18n.py` 按 CWE 集中维护漏洞「类名」与「修复建议」的中英双语文本（覆盖 XSS/SQLi/路径遍历/SSRF/开放重定向/缺失授权/认证缺陷/信息泄露/防护失效/CWE-1035 等 20 类高频 CWE）；`app_api.vuln_i18n_map(lang)` 暴露当前语言的 `{CWE: {name, remediation}}` 映射；前端按当前语言本地化发现列表、发现详情弹窗（新增修复建议段）、重扫差异与对比卡片的漏洞类名与修复建议，**未命中映射时回退后端原文**，绝不产生空白；语言切换即时刷新映射。
- **弱口令字典外置（v1.16.0 / C-05）**：把 `scanner/auth.py` 硬编码的 `_DEFAULT_CREDS` 外置为 `config/dicts/default_creds.txt`（随 exe 打包分发），新增 `scanner/cred_dict.py` 加载器（`load_default_creds`：支持自定义字典路径、注释/空白/重复/超长字段丢弃与限条数、缺失文件逐级回退内置→内嵌兜底）；`config.AUTH_PROBE_DICT_PATH` / 环境变量 `AUTOPENTEST_AUTH_DICT` / 设置项 `auth_probe_dict` 均可指定自定义字典（用户导入）。设置页新增「安全探测」分组：默认凭据探测开关（开启时强制授权确认闸门，提示账号锁定风险）+ 自定义字典路径输入框；`run_scans` 经设置项 `enable_auth_probe`/`auth_probe_dict` 决定探测与字典，`config.ENABLE_AUTH_PROBE` 仍作为代码级主闸门（默认关）。新增 `tests/test_cred_dict.py`（9 例）。
- **资产变更告警（v1.17.0 / F-05）**：新增资产基线机制——每次 Web 扫描后采集目标 Web 指纹（Server/X-Powered-By/标题等）/ 关键响应头快照并落库（`target_baseline` 表，`db.capture_baseline`/`get_baseline`）；`asset_watch.diff_asset_snapshot` 纯函数比对相邻两次快照，输出「指纹/标题变化、端口/子域增删」结构化变更（首次建立基线不告警）；`run_scans` 扫描结束后按设置项 `asset_change_alert`（总开关）/`asset_change_notify`（桌面气泡，默认开）/`asset_autoscan`（自动增量扫描，默认关）触发记录 + 托盘通知 + 可选自动复核；`notify.py` 封装系统托盘气泡，GUI 不可用时安全降级。目标中心新增「资产基线」卡片（指纹/标题/采集时间/最近变更），设置页新增「持续监控」分组三个开关。新增 `tests/test_asset_watch.py`（7 例）。
- **资产拓扑可视化（v1.18.0 / F-07）**：新增「资产拓扑」视图（导航新增入口），用**原生 SVG 力导向布局**渲染全量资产暴露面——目标根节点 → 子域/主机节点 → 开放端口节点，每个 host 节点按范围内发现的最高风险着色（红/橙/黄/蓝风险热图），并叠加**漏洞利用链**（C-01）虚线边与链上发现节点（可开关）；支持滚轮缩放、拖拽空白平移、拖拽节点、点击查看详情（类型/风险/发现数/端口/标签），含图例与「重置视图」。完全离线、无外部 d3 依赖。后端 `topology.build_topology` 聚合 `targets`/`target_baseline`(端口·子域)/`findings`(按 host 聚合风险)/`chain`(链路边)；`db` 新增 `scans_of_target`/`findings_of_target`（仅未归档扫描计入当前暴露面）；`app_api.topology_data` 暴露数据。新增 `tests/test_topology.py`（3 例）。
- **加密凭据保险库与会话续期（v1.19.0 / C-06）**：为需要登录态的目标提供**Fernet 加密凭据保险库**（`scanner/vault.py`，密钥取自环境变量 `AUTOPENTEST_VAULT_KEY` 或程序目录同级 `autopentest.key`，缺失自动生成），凭据以密文落盘、前端 `get_auth_profile` 只返回掩码（绝不回传明文密码）。配套**可续期会话**（`scanner/session_renew.py`）：登录一次后，对请求做会话失效检测（重定向到登录页 / 响应含登录表单 / 401），自动重登并重试（受 `config.SESSION_RENEW_MAX=5` 与设置项上限约束，防止账号锁定风险放大），并审计 + 产出一条 Info 类「会话续期」发现（含续期次数）。接入 `run_scans`：目标配置保险库且设置项 `enable_session_renew=1` 时，把续期会话注入外层 banner/插件/爬取/API/目录扫描与逐页扫描器；总闸门 `config.ENABLE_SESSION_RENEW=False`（默认关），且仅对显式配置并存储凭据的目标生效。目标编辑弹窗新增「认证配置（会话续期）」折叠段（登录 URL/方法/用户名字段/密码字段/用户名/密码 + 测试登录/保存），设置页新增 `enable_session_renew` 开关；`app_api` 暴露 `set_auth_profile`/`get_auth_profile`/`delete_auth_profile`/`list_auth_profiles`/`test_auth_profile`（后端绝不回传明文密码）。`verify_build` 登记 `scanner.vault`/`scanner.session_renew`。新增 `tests/test_session_vault.py`（5 例）+ `tests/test_session_renew.py`（7 例）。
- **前端长列表虚拟滚动（v1.20.0 / P-05）**：为随时间无界增长的**审计日志**引入可复用虚拟滚动（`mountVirtualList`：固定高度滚动容器内只渲染「可视区 + overscan」行，渲染开销由 O(n) 降为 O(可视行数)）。审计日志视图改为表头 + 虚拟滚动容器（grid 列模板对齐），一次性拉取上限由 300 提至 2000 条并由虚拟列表按需渲染，长日志（数千条）也不会因全量 DOM 而卡顿。漏洞发现列表此前已由 P-03 服务端分页（每页仅 `limit` 行进入 DOM），二者共同满足计划「长列表 O(n)→O(1)」目标——在已分页列表之上叠加虚拟滚动属冗余，故仅对无界增长的审计日志落地。新增无独立后端改动，前端 `node --check` 通过；i18n 增 `virtualNote`（zh/en），`style.css` 增 `.vlist/.vhead/.vrow` 样式。
- **单文件分发**：打包为单个 `PenScope.exe`，双击即用，含系统托盘（关闭窗口最小化到托盘）。

---

## 🔒 安全与合规

- **仅限授权使用**：本工具用于你**已获书面授权**的目标。新增目标需显式确认授权；默认不执行任何主动/破坏性动作（默认凭据探测、会话续期、上传测试均默认关闭，需人工开启并二次确认）。
- **纯本地、无外联后台**：所有扫描逻辑在本机运行，不回传任何数据；子域枚举等只读情报源为公开服务（crt.sh / DNS），且只记为资产发现。
- **仓库不含任何密钥/凭据**：运行时密钥由程序在 exe 同级目录自动生成（Fernet），前端永不接触明文密码；本仓库通过 `.gitignore` 排除所有 `*.key`、`*vault*.json`、数据库与日志。详见 [SECURITY.md](SECURITY.md)。
- **合法合规**：请遵守所在地区法律法规与目标方的授权范围；产生的报告与授权书可作为测试合法性凭证。

---

## 📦 安装与运行

### 方式一：直接运行（推荐给使用者）
1. 从发布页下载 `PenScope.exe`。
2. **确保已安装 [Microsoft Edge WebView2 运行时](https://developer.microsoft.com/zh-cn/microsoft-edge/webview2/)**（Windows 10/11 通常已内置；若双击无窗口，请安装后重试）。
3. 双击 `PenScope.exe`，自动弹出原生界面。

> 数据（扫描库 `autopentest.db`）保存在 exe 同级目录，卸载时删除该目录即可。

### 方式二：从源码运行（开发者）
```bash
pip install -r requirements.txt
python main_gui.py
```

---

## 🚀 使用流程

1. **授权目标**：侧栏「授权目标」→ 填写主机/IP、端口范围，勾选「我已获得该目标的书面授权」→ 提交即被批准。
2. **发起扫描**：在目标行点击「发起扫描」，后台自动执行。可在「扫描任务」查看进度，运行中每 5 秒自动刷新。
3. **处理复核闸门**：若发现高危注入或上传点，扫描会在「利用验证 / 上传测试」节点暂停。前往「复核闸门」点击「批准」继续（或「拒绝」终止）。
4. **查看报告**：扫描完成后，在扫描详情页点击「查看 / 保存完整报告」，可在线查看或导出 HTML。

---

## ⚠️ 合法使用声明

本工具**仅限对您已获得书面授权的目标**进行安全测试。未经授权对他人系统发起扫描，可能违反《网络安全法》等相关法律法规，后果由使用者自行承担。所有利用验证均为只读或良性探针，不执行破坏性操作。生成的报告含敏感安全信息，请妥善保管。

---

## 🗂 项目结构（开发者）

```
autopentest-ai/
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
└── PenScope.spec # 打包规格
```

### 打包
```bash
python build_nowrap.py        # 按 PenScope.spec 用 PyInstaller 构建，并自动跑 verify_build 校验
```
产物：`dist/PenScope.exe`（单文件、隐藏终端、内置原生界面 + 系统托盘）。

### 运行测试
```bash
pip install pytest
python -m pytest              # 运行 tests/ 下全部单元测试
```
E2E 脚本（`tests/e2e_access_auth_dvwa.py` 等）需本地起受控目标或 DVWA，默认不随 `pytest` 自动执行。

---

## 🔐 安全设计要点

- 无网络服务端、无账号体系，数据仅存于本机 SQLite。
- 授权围栏 + 人工复核闸门，确保高危动作需使用者显式确认。
- 扫描引擎使用参数化查询访问自身数据库，杜绝 SQL 注入。
- 利用验证仅做「证明可利用」（时间盲注 / 错误复现），不提取数据；上传测试仅上传良性标记文件。

---

## 📌 近期版本与误报治理

| 版本 | 要点 |
| --- | --- |
| v1.3.2 | 新增命令注入（差分标记法雏形）+ API 安全（被动）检测模块，接入阶段机与人工闸门。 |
| v1.3.3 | 修复扫描界面循环强制进入；数据层增删改查 + WAL/锁并发加固。 |
| v1.3.4 | 补齐 P1：被动子域枚举 + 目录/敏感信息扫描（全只读）。 |
| v1.3.5 | **误报率降低**：命令注入改为差分标记法，根治反射型误报（mail.jxnu.edu.cn / Exchange OWA 同款）。 |
| v1.3.6 | **误报率降低**：CSRF 区分"真无防护才报高危"、SQLi 布尔盲注多轮稳定判定，消除动态内容误报。 |
| v1.3.7 | **覆盖缺口分析**：基于 NVD/CNVD 公开漏洞态势做能力覆盖 gap 分析；私有地址护栏、邮件/协议感知（STARTTLS/明文）、同 IP 多 vhost 端口复用。 |
| v1.3.8 | **覆盖缺口补齐**：新增 SSRF（CWE-918，file:// + 云元数据强证据 / URL 参数注入点观察）与路径遍历（CWE-22，多编码 `../` 注入 + 基线防误报）只读检测模块，接入阶段机 Web 检测；全部回归测试通过，重建 exe。 |
| v1.3.9 | **访问控制与认证**：新增缺失授权（CWE-862，强制浏览 + 越权参数观察）与认证缺陷（CWE-287，被动观察 + opt-in 默认凭据探测）只读检测模块，接入阶段机 Web 检测；全部回归测试通过，重建 exe 并由 `verify_build` 自动校验（新模块登记进 EXPECTED_MODULES）。 |
| v1.4.0 | **开放重定向**：新增开放重定向（CWE-601，重定向 sink 注入 + Location 站外判定，零外联只读）只读检测模块，接入阶段机 Web 检测；认证缺陷（CWE-287）默认凭据探测新增 CSRF 感知回填，使其可在 DVWA 等带 CSRF 校验的登录端点命中 `admin/password`；全部单元测试（14 例）+ 受控/DVWA E2E（8 项）通过，重建 exe 并由 `verify_build` 自动校验（`scanner.open_redirect` 登记进 EXPECTED_MODULES）。 |
| v1.4.1 | **安全审计整改**：依据《安全漏洞扫描报告》闭环全部 2 个 MEDIUM + 5 个卫生项。AP-001 重定向作用域围栏：新增 `scanner/scope`，`collect_pages`/`fingerprint_web` 改为手动逐跳跟随重定向并对每跳复检私网/回环/云元数据（CWE-918）；AP-002 TLS 按目标可配置：`targets` 增 `verify_tls`（默认开启校验），scanner 默认 `verify_ssl=True`，新增前端「跳过 TLS 校验」勾选，crt.sh 固定校验；H-4 `font_size` 范围校验、H-5 DB 列名白名单、H-1 清理遗留 `secret.key` 与 bottle 依赖。pytest **34/34** 通过，重建 exe + `verify_build` PASS。 |
| v1.4.2 | **AP-001 修正补丁**：回归扫描（真实 DVWA 靶场）发现 v1.4.1 的 `host_blocked` 对「一切重定向目的（含回环）」误杀 localhost 靶场同源重定向，导致 `collect_pages` 返回 0 页。重构为 `redirect_target_blocked(redirect_netloc, base_host)`：以起始目标为基准——同源/相对重定向跟随；跨主机指向受保护内网时仅当起始目标亦在内网（扫自己靶场）才跟随，否则判 SSRF 丢弃。`fingerprint_web` 相对重定向误丢一并修正。新增 `tests/e2e_regression_dvwa.py` 全链路回归；pytest **35/35** 通过，重建 exe + `verify_build` PASS。 |
| v1.5.0 | **改进方案批量落地（8 项 P0/P1）**：新增 `chain.py` 漏洞链编排（C-01）；`reports.py` 新增摘要/技术/合规三模板（F-01）、SARIF 2.1.0 + 标准化 JSON 导出（F-04）；`db.py` 复合索引（P-02）、发现分页 `findings_page`（P-03）、修复状态 `fix_status` + 重扫差异 `rescan_diff`（F-02）、删除回收站 `trash_*`/`restore_trash` 与 5 秒撤销（U-03）；`run_scans.py` asyncio 协程化提速（P-01）；`app_api.py` 统一错误码信封 `{ok, code, error, hint}`（U-04）；前端首次向导（U-01）、目标中心化视图（I-01）、报告导出按钮、漏洞链/修复对比面板、发现分页与撤销提示。pytest **35/35** 通过 + DVWA E2E 回归通过，重建 exe（含 `chain` 模块）+ `verify_build` PASS。 |
| v1.6.0 | **扫描可观测性（2 项 P1）**：阶段甘特图（I-02）+ 失败根因分类（U-06）。`run_scans.process_scan` 全阶段埋点 `scan_stage_events`（start/done/paused/failed）并重写 `scope_check` 走 `db.fail_scan`；异常经 `_classify_error` 归类为结构化 `failure_category`/`failure_detail`（scope_unauthorized / scope_private / network_unreachable / timeout / ssl_error / redirect_loop / exception），写入 scans 表与 summary，并捕获异常避免扫描卡在 running。`db.record_stage_event`/`stage_events`/`fail_scan` + `app_api.get_scan_stages` 暴露数据；前端扫描详情渲染横向甘特条（进行中/暂停/失败/完成着色）+ 失败横幅（按 category 给针对性 hint，ssl_error 提供「前往目标」跳过重验）。新增 `tests/test_scan_observability.py`（5 例）。pytest **40/40** 通过 + DVWA E2E 回归通过，重建 exe + `verify_build` PASS。 |
| v1.7.0 | **发现证据增强（3 项 P1）**：证据分级渲染（I-04）+ 请求/响应 Diff（I-05）+ CVSS 交互计算器（I-06）。`findings` 表新增 `evidence_meta` 列；`scanner/evidence.py` 从已验证发现的 HTTP 交换重建请求/响应文本并写入 `evidence_meta`（SQLi 错误型、XSS 反射型已接入）；`db.add_finding` 支持持久化并在去重合并时 `COALESCE` 保留；`app_api.get_finding`/`set_finding_cvss` 暴露单条发现与人工校准的 CVSS 3.1 评分（向量格式守门）。前端发现表格新增证据等级列（L1–L4 着色徽章），点击行打开详情弹窗：分级展示证据、Diff 视图高亮注入载荷、PoC/curl 一键复制、CVSS 3.1 计算器（8 度量交互、前端实时评分、保存回写报告）。新增 `tests/test_finding_evidence.py`（6 例）。pytest **46/46** 通过 + DVWA E2E 回归通过，重建 exe（含 `scanner.evidence`）+ `verify_build` PASS。 |
| v1.8.0 | **漏洞分析视图（2 项 P1）**：漏洞矩阵视图（I-03）+ 扫描对比基线 Diff（F-03）。`db.findings_matrix(scan_id)` 将单扫描发现按 (端点 × 漏洞类型) 聚合成热力矩阵，单元格取该组合最高风险等级 + 数量 + 代表发现 id，前端扫描详情「漏洞矩阵」弹窗按风险着色、点击单元格下钻到代表发现详情；`db.compare_scans(scan_a, scan_b)`（复用 `rescan_diff` 的 `_diff_findings` 差集逻辑）对比任意两次**同目标**扫描，输出新增/已解决/持续三类，前端目标中心「对比扫描」弹窗可手动选基线/当前两次扫描并三色渲染对比结果（与 F-02 自动重扫差异互补）。新增 `tests/test_finding_matrix.py`（5 例）。pytest **51/51** 通过，重建 exe + `verify_build` PASS。 |
| v1.9.0 | **检测深度三件套（3 项 P1）**：响应差异基线建模（C-02）+ WAF 自适应（C-03）+ CVE 联动（C-04）。C-02 新建 `scanner/baseline.py`，将 `_verify_sqli_time` 的单点基线升级为「5 次良性响应统计分布 + 3σ 抖动吸收」（`is_significant_delay`：仅当延迟显著高于基线分布且接近注入延迟量级才判定），时间盲注误报显著下降，证据写入基线摘要；C-03 `payloads.py` 按 WAF 类型分派专属绕过变换（`WAF_EVASION`：Cloudflare/AWS/ModSecurity/Wordfence/Sucuri/360/Akamai/Barracuda/F5 各自的内联注释/大小写/制表/编码组合，未知 WAF 退化为通用集），并扩充 WAF 指纹库；C-04 在 `run_scans` web_detect 阶段对 `Server` 头 / 框架头 / 标题做 `match_vulns` 版本关联，输出「组件+版本+CVE」被动命中（标记 info、注明需结合补丁状态，按 (组件,版本) 去重）。新增 `tests/test_detection_depth.py`（16 例，覆盖 3σ 判定、WAF 分派、版本命中）。pytest **67/67** 通过 + DVWA E2E 回归通过（CWE-1035 命中验证 C-04 生效），重建 exe（含 `scanner.baseline`，PYZ 854）+ `verify_build` PASS。 |
| v1.10.0 | **数据归档（P-04）**：`scans` 表新增 `archived` 列（schema + 增量迁移）；`db.set_scan_archived` 单条归档/取消、`archive_scans_before(iso_date, target_id?)` 按日期批量归档已完成且未归档扫描（数据生命周期）、`list_scans(limit, include_archived=False)` 默认隐藏归档；`app_api.archive_scan`/`archive_scans_before` 暴露（含 E_NOT_FOUND 守门）；目标中心扫描历史新增「显示已归档」勾选 + 每条「归档/取消归档」按钮 + 「归档 90 天前扫描」批量动作（默认视图不再被历史数据淹没，归档项可一键恢复）。新增 `tests/test_scan_archival.py`（4 例：单条隐藏/恢复、按日期批量仅归档旧 completed、按目标范围、未知扫描返回 False）。pytest **71/71** 通过 + DVWA E2E 回归通过，重建 exe + `verify_build` PASS（PYZ 854，VERSION 1.10.0）。 |
| v1.11.0 | **WebSocket 事件推送（P-06）**：用 pywebview 事件推送**替代前端 4 秒轮询**。Python 侧在 `process_scan` 每次阶段事件（`record_stage_event`）后通过已注册窗口 `window.evaluate_js` 主动推送 `scan_event`（含 scan_id/stage/status/note/ts）；`main_gui` 在窗口创建后调用 `run_scans.set_push_window(window)` 解耦注入；前端 `window.__autopentestOnScanEvent` 收到即刷新当前扫描详情（及目标中心扫描历史），**绝不强制跳转**。`_scanTimer` 轮询间隔由 4s 拉长至 8s 并加「近 7s 内有推送则跳过」守卫，降级为纯兜底——扫描活跃时绝大多数刷新由推送驱动，CPU 占用下降、实时性提升。新增 `tests/test_scan_push.py`（4 例：无窗口 no-op、JS 负载格式、窗口异常吞掉、复位）。pytest **75/75** 通过 + DVWA E2E 回归通过，重建 exe + `verify_build` PASS（PYZ 854，VERSION 1.11.0）。 |
| v1.12.0 | **扫描器插件化框架（F-08）**：打破 14 模块硬编码。新增 `scanner/plugin_base.py`（`BaseScanner` 抽象基类 + `ScanContext` 受限运行时上下文：插件仅暴露 `add_finding`/`audit`/`session`/`target`，不直连 db/run_scans，可独立单元测试）；`scanner/plugins/` 加载器 `load_plugins()` 内置示例显式 import（确保被打包）+ 外部 `~/.autopentest/plugins/` 目录自动发现（带缓存与异常隔离，首次运行自动建目录并写 `_README.txt`）；内置示例 `example_headers.py` 被动检测缺失安全响应头（整合为单条 Info 发现，规避语义去重合并）。`run_scans.run_plugin_scanners` 在 web_detect 阶段接入，受 `config.ENABLE_PLUGINS` 总开关控制（无插件零开销、单插件异常仅审计不中断）。新增 `tests/test_plugin_framework.py`（5 例）。pytest **80/80** 通过 + DVWA E2E 回归通过（CWE-693 验证示例插件生效），重建 exe（含 `scanner.plugin_base`/`plugins`/`example_headers`，PYZ 857）+ `verify_build` PASS。 |
| v1.13.0 | **运维/UX 增强（4 项 P2）**：敏感数据脱敏（U-12）+ 诊断包导出（U-05）+ 键盘快捷键（U-08）+ 审计热力图（U-11）。U-12 新增 `scanner/redact.py`（保守正则脱敏：AWS/Bearer/JWT/PEM 私钥块/密码键值/会话 Cookie），前端 `redact()` 展示层安全网对发现证据与请求/响应文本实时掩码（库原文不变）；U-05 `app_api.export_diagnostic` 一键打包版本/平台/脱敏设置/库统计/近期审计（脱敏）为 JSON，前端设置页「导出诊断包」按钮直接下载；U-08 全局快捷键（`g` 前缀导航 d/t/s/a/r/c/? + `?`/`Ctrl+K` 帮助浮层，输入态自动禁用）；U-11 `db.audit_heatmap(days)` 按天聚合审计计数，审计页渲染近 90 天热力图。新增 `tests/test_ops_ux.py`（10 例）。pytest **90/90** 通过 + DVWA E2E 回归通过，重建 exe（含 `scanner.redact`，PYZ 858）+ `verify_build` PASS。 |
| v1.14.0 | **资产分组与无障碍（3 项 P2）**：目标标签分组（F-06）+ 授权书模板（U-10）+ 前端无障碍（U-09）。F-06 新增 `target_tags` 表与 `db.set_target_tags`/`get_target_tags`/`list_target_tags`（覆盖式写入、去空白/去重/限长 32/限数 20、批量挂标签避免 N+1），`delete_target`/`trash_target` 级联清除标签；目标列表顶部按标签一键筛选（含计数），目标中心可编辑标签；`app_api` 暴露 `list_target_tags`/`set_target_tags`/`authorization_letter`。U-10 `reports.build_authorization_letter` 生成中文授权书 HTML（含文档编号/签署栏/授权范围/允许与禁止动作/30 天有效期/目标备注，自带浅色主题 + 打印 CSS），前端 iframe 内联预览 + 打印/另存 PDF。U-09 增加 skip-link、`role=navigation/main/dialog`、`aria-modal`、`aria-live` 状态播报、`:focus-visible` 焦点轮廓、Esc 关闭弹窗。新增 `tests/test_asset_tags.py`（9 例）+ `tests/test_authorization_letter.py`（5 例）。pytest **104/104** 通过 + DVWA E2E 回归通过，重建 exe（PYZ 858，无新增模块）+ `verify_build` PASS。 |
| v1.15.0 | **漏洞描述双语映射（U-07）**：新增 `scanner/vuln_i18n.py`，按 CWE 集中维护漏洞「类名」与「修复建议」中英双语文本（覆盖 XSS/SQLi/路径遍历/SSRF/开放重定向/缺失授权/认证缺陷/信息泄露/防护失效/使用含已知漏洞组件 等 20 类高频 CWE），提供 `localize(cwe, field, lang, default)` 与 `map_for_lang(lang)`（单一事实源，后端报告亦可复用）；`app_api.vuln_i18n_map(lang)` 暴露当前语言映射（缺省取存储语言）。前端 `locVuln(f)` 按当前语言本地化发现列表、发现详情弹窗（新增修复建议段）、重扫差异与对比卡片的类名与修复建议，未命中回退后端原文；语言切换即时刷新。新增 `tests/test_vuln_i18n.py`（5 例）。pytest **109/109** 通过 + DVWA E2E 回归通过（5 findings，无异常），重建 exe（含 `scanner.vuln_i18n`，PYZ 859）+ `verify_build` PASS。 |
| v1.16.0 | **弱口令字典外置（C-05）**：把 `scanner/auth.py` 硬编码的 `_DEFAULT_CREDS` 外置为 `config/dicts/default_creds.txt`（随 exe 打包分发），新增 `scanner/cred_dict.py` 加载器（`load_default_creds`：支持自定义字典路径、`#` 注释/空白/重复/无冒号/超长字段丢弃与限条数、缺失文件逐级回退「内置→内嵌兜底」，保证探测功能不崩）；`config.AUTH_PROBE_DICT_PATH` / 环境变量 `AUTOPENTEST_AUTH_DICT` / 设置项 `auth_probe_dict` 均可指定自定义字典（用户导入）。设置页新增「安全探测」分组：默认凭据探测开关（开启时强制授权确认闸门，提示账号锁定/被判定爆破风险）+ 自定义字典路径输入框；`run_scans` 经设置项 `enable_auth_probe`/`auth_probe_dict` 决定探测与字典，`config.ENABLE_AUTH_PROBE` 仍作为代码级主闸门（默认关）。新增 `tests/test_cred_dict.py`（9 例）。pytest **118/118** 通过 + DVWA E2E 回归通过（5 findings，无异常），重建 exe（含 `scanner.cred_dict`，PYZ 860，字典已打入 `config/dicts`）+ `verify_build` PASS。 |
| v1.17.0 | **资产变更告警（F-05）**：新增资产基线机制——每次 Web 扫描后采集目标 Web 指纹（Server/X-Powered-By/标题等）与关键响应头快照并落库（`target_baseline` 表，`db.capture_baseline`/`get_baseline`）；`asset_watch.diff_asset_snapshot` 纯函数比对相邻两次快照，输出「指纹/标题变化、端口/子域增删」结构化变更（首次建立基线不告警）；`run_scans._apply_asset_baseline` 扫描结束后按设置项 `asset_change_alert`（总开关，默认关）/`asset_change_notify`（桌面气泡，默认开）/`asset_autoscan`（自动增量扫描，默认关）触发审计记录 + 系统托盘通知 + 可选自动复核；新增 `notify.py` 封装托盘气泡（GUI 不可用时安全降级），`main_gui` 启动时注册托盘引用。目标中心新增「资产基线」卡片（指纹/标题/采集时间/最近变更），设置页新增「持续监控」分组三开关。`verify_build` 登记 `asset_watch`/`notify`。新增 `tests/test_asset_watch.py`（7 例）。pytest **125/125** 通过 + DVWA E2E 回归通过（5 findings，无异常），重建 exe（含 `asset_watch`/`notify`，PYZ 862）+ `verify_build` PASS。 |
| v1.18.0 | **资产拓扑可视化（F-07）**：新增「资产拓扑」视图，原生 SVG 力导向布局渲染目标→子域→端口暴露面，host 节点按发现最高风险着色（风险热图），叠加漏洞利用链（C-01）虚线边与链上发现节点（可开关）；支持缩放/平移/拖拽/点击详情、图例、重置视图，完全离线无 d3 依赖。`topology.build_topology` 聚合 targets/target_baseline(端口·子域)/findings(按 host 风险)/chain(链路边)；`db` 新增 `scans_of_target`/`findings_of_target`（仅未归档扫描计入）；`app_api.topology_data` 暴露数据。`verify_build` 登记 `topology`。新增 `tests/test_topology.py`（3 例）。pytest **128/128** 通过 + DVWA E2E 回归通过（5 findings，无异常），重建 exe（含 `topology`，PYZ 863）+ `verify_build` PASS。 |
| v1.19.0 | **加密凭据保险库与会话续期（C-06）**：新增 `scanner/vault.py`（Fernet 加密本地凭据库，密钥来自 env `AUTOPENTEST_VAULT_KEY` 或程序目录 `autopentest.key`，缺失自动生成；`get_vault` 惰性单例；`get_auth_profile` 只返回掩码），与 `scanner/session_renew.py`（`SessionRenewal` + `RenewableSession`：登录一次后检测会话失效自动重登重试，受 `SESSION_RENEW_MAX=5`/设置上限约束，续期>0 时审计并产出 Info 发现）。接入 `run_scans` 续期会话注入逐页扫描器与外层检测；总闸门 `ENABLE_SESSION_RENEW=False`（默认关），仅对显式配置凭据的目标生效。`app_api` 暴露 5 个保险库接口（不回传明文）；目标编辑弹窗新增认证配置折叠段、设置页新增 `enable_session_renew` 开关。`verify_build` 登记 `vault`/`session_renew`。新增 `tests/test_session_vault.py`+`tests/test_session_renew.py`（12 例）。pytest **140/140** 通过 + DVWA E2E 回归通过（5 findings，无异常），重建 exe（含 `scanner.vault`/`scanner.session_renew`，PYZ 866）+ `verify_build` PASS。 |
| v1.20.0 | **前端长列表虚拟滚动（P-05）**：新增可复用 `mountVirtualList`（固定高度滚动容器内只渲染可视区 + overscan 行，渲染 O(n)→O(可见)）；审计日志视图改为表头 + 虚拟滚动容器（grid 列对齐），拉取上限 300→2000 条由虚拟列表按需渲染，长日志不卡顿。漏洞发现列表由 P-03 服务端分页已覆盖，故未叠加冗余虚拟滚动。无后端改动，前端 `node --check` 通过；i18n 增 `virtualNote`，CSS 增 `.vlist/.vhead/.vrow`。纯前端改动，无新增测试与模块，pytest 沿用 **140/140**，DVWA E2E 维持通过；重建 exe（VERSION 1.20.0）+ `verify_build` PASS（PYZ 868）。 |
| v1.12.0 | **扫描器插件化框架（F-08）**：打破 14 模块硬编码，提供可扩展的二次开发接口。`scanner/plugin_base.py` 定义 `BaseScanner` 抽象基类 + `ScanContext` 受限运行时上下文（仅暴露 `add_finding`/`audit`/`session`/`target`/`verify_ssl`，插件不直连 db/run_scans）；`scanner/plugins/` 包提供 `load_plugins()` 加载器（内置示例显式 import 确保被打包 + 外部 `~/.autopentest/plugins/` 目录自动发现，带缓存与异常隔离，首次运行自动创建该目录并写入 `_README.txt`）；内置示例 `example_headers.py`（被动检测缺失的 HSTS/X-Content-Type-Options/X-Frame-Options，整合为单条 Info 发现）。`run_scans.run_plugin_scanners` 在 web_detect 阶段对每个 Web 目标运行已注册插件（异常隔离、开关 `config.ENABLE_PLUGINS` 可整体关闭，无插件时零开销）。`verify_build` 登记 plugin_base/plugins/example_headers。新增 `tests/test_plugin_framework.py`（5 例：抽象约束、上下文转发、加载+缓存、端到端产出、开关 no-op）。pytest **80/80** 通过 + DVWA E2E 回归通过（新增 CWE-693 命中，证明示例插件在真实扫描中生效），重建 exe + `verify_build` PASS（PYZ 857，VERSION 1.12.0）。 |

> 工具定位为**只读/良性**扫描器：所有"写入/延迟/外带"类动作（命令注入时间盲注、文件上传测试）均走人工批准闸门，默认不触发；仅用于你已获授权的目标。
