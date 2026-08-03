# 🤝 参与贡献 PenScope

感谢你对 PenScope 的兴趣！本文件说明如何搭建开发环境、运行测试、遵循代码风格并提交改动。

> **合规前提**：PenScope 仅用于**已获书面授权**的渗透测试 / 红队演练。任何贡献都不得用于帮助未授权攻击。提交即表示你同意遵守本仓库的 [行为准则](CODE_OF_CONDUCT.md) 与 [安全策略](SECURITY.md)。

## 1. 开发环境

要求：Python **3.11**（CI 固定用 3.11；本地 3.11+ 均可）。GUI 依赖 pywebview + WebView2，**Windows 推荐**用于运行/打包；纯逻辑测试在 Windows / Ubuntu 均可运行（见 CI 矩阵）。
打包工具：**PyInstaller 6.x**（当前锁定 `6.21.0`，见 `requirements-lock.txt`）。

```bash
# 克隆
git clone https://github.com/wanlqx/PenScope.git
cd PenScope

# 创建并激活虚拟环境（推荐）
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS / Linux

# 安装依赖（优先用锁文件保证可复现；锁文件滞后时回退到 requirements.txt）
pip install -r requirements-lock.txt || pip install -r requirements.txt
pip install pytest ruff bandit pip-audit pre-commit   # 开发期额外工具

# 可选：安装 pre-commit 钩子，提交前自动跑 ruff / bandit（见「本地开发工具」）
pre-commit install
```

# 本地打包（产出 dist/PenScope.exe）
python make_icon.py          # 再生图标资源
python build_nowrap.py       # PyInstaller 单文件构建
```

> ⚠️ **构建平台限制**：`build_nowrap.py` 直接使用 Windows 原生模块 `nt`（用于绕过本机
> safe-delete 沙箱对 `os.remove` 的拦截），因此**只能在 Windows 上运行**。在 Linux / macOS
> 上会直接报错退出。CI 的发布任务已固定使用 `windows-latest` runner；本地构建也必须在
> Windows 下进行。如需在其它平台打包，请改用标准 `pyinstaller PenScope.spec` 并自行处理
> 沙箱拦截（不推荐，nt 还原逻辑正是为 Windows 沙箱环境设计的）。

## 2. 运行测试

测试套件分为三类：

- **纯逻辑单测**（无需显示 / 网络，CI 默认运行）：
  ```bash
  python -m pytest tests/test_session_vault.py tests/test_hardening.py \
      tests/test_cred_dict.py tests/smoke_nobackend.py \
      tests/test_scope_redirect.py tests/test_vuln_i18n.py -q
  ```
- **功能 / 集成测试**：部分 `tests/test_*.py` 需要本地数据库（自动建临时库），可直接运行。
- **端到端 / GUI 测试**（`tests/e2e_*.py`、`test_ops_ux.py` 等）：需要显示环境或靶机（如 DVWA），请在本机手动运行，不要提交需要外部服务的测试到 CI 默认集。

运行全量（本机、有显示时）：`python -m pytest -q`

> CI 在 **ubuntu-latest + windows-latest** 双 runner 上运行上述纯逻辑测试，保证跨平台一致性。

## 3. 代码风格

- 格式化 / Lint：`ruff check .`（可选 `ruff format .`）。
- **`ruff` 已是 CI 硬门禁（测试同等级别必须通过）**：提交前务必本地跑一遍，避免 PR 被 CI 拦截。
- 安全静态分析：`bandit -r scanner app_api.py`。
- 依赖漏洞：`pip-audit -r requirements-lock.txt`。
- 保持中文 / 英文界面字符串通过 `config` 与前端 i18n 资源维护，勿硬编码到逻辑中。

### 3.1 本地开发工具（pre-commit）

仓库根含 `.pre-commit-config.yaml`（ruff 检查 + 格式化、bandit 安全扫描）。安装后每次 `git commit` 自动执行：

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files   # 手动对全部文件执行
```

### 3.2 依赖锁文件（可复现构建）

运行时依赖版本由 `requirements-lock.txt`（pip-compile 生成，含完整传递依赖与锁定版本）固定。更新依赖后请重新生成锁文件并提交：

```bash
pip install pip-tools
pip-compile requirements.txt -o requirements-lock.txt   # Python 3.11 环境下执行
```

CI / 发布构建优先使用 `requirements-lock.txt`，失败时回退到 `requirements.txt`。

## 4. 提交 PR 流程

1. Fork 并基于 `master` 创建特性分支：`git checkout -b feat/your-feature`。
2. 确保上述纯逻辑测试通过、ruff 无明显错误。
3. 提交信息建议遵循 Conventional Commits：`feat:` / `fix:` / `docs:` / `security:` / `ci:` / `chore:`。
4. 推送并发起 Pull Request，填写 PR 模板（变更说明、测试、安全影响）。
5. 维护者审阅后会合并；版本号与发布说明由 `tools/release.py` 与 `CHANGELOG.md` 统一管理，请勿在 PR 中手动改写 `config.VERSION`。

## 5. 安全相关改动

涉及凭据、授权围栏、扫描逻辑的改动需额外谨慎，并在 PR 中说明安全影响。发现漏洞请按 [SECURITY.md](SECURITY.md) 流程**私下**报告，勿公开 Issue。

## 6. 插件开发与安全

PenScope 支持通过 `scanner.plugins.load_plugins()` 加载扩展扫描器（继承 `scanner.plugin_base.BaseScanner`）：

- **内置示例**：`scanner/plugins/example_headers.py`，随包发布、受信，始终自动加载。
- **外部插件**：把 `.py` 放入 `~/.autopentest/plugins/`，但**默认处于「严格信任」模式**，
  落盘的文件不会自动执行，必须先显式登记信任才会加载：

  ```bash
  python -m scanner.plugins trust ~/.autopentest/plugins/你的插件.py   # 登记/更新信任（记录 SHA-256）
  python -m scanner.plugins list                                       # 列出已信任插件
  python -m scanner.plugins verify                                     # 校验哈希是否仍匹配（篡改检测）
  ```

  登记会将插件文件的 SHA-256 写入 `~/.autopentest/plugins/manifest.json`；之后该文件被改动（篡改）将**拒绝加载**。
  信任模式由 `config.PLUGIN_TRUST_MODE` 控制：`strict`（默认）/ `warn`（加载未登记插件但高亮告警）/ `off`（不加载外部插件），
  环境变量 `PENSCOPE_PLUGIN_TRUST` 可临时覆盖。

> ⚠️ **信任边界（重要）**：外部插件在被加载时由 `importlib` **直接执行任意 Python 代码**，拥有与 PenScope 相同的当前用户权限。
> 因此：
> 1. 只从**可信来源**获取并安装插件；不要运行来源不明或未经审查的插件文件。
> 2. 插件可访问本机文件系统、网络与凭据保险库所在进程，请将其视为一等代码执行点对待。
> 3. 严格信任白名单 + 完整性哈希已是**中期隔离**手段（杜绝静默任意代码执行与篡改）；
>    长期计划：将插件放入**独立子进程**中隔离运行（沙箱 / 最小权限 / JSON-RPC 通信），进一步降低对主进程的信任暴露面。当前版本尚未实现该子进程隔离。
