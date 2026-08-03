# 🤝 参与贡献 PenScope

感谢你对 PenScope 的兴趣！本文件说明如何搭建开发环境、运行测试、遵循代码风格并提交改动。

> **合规前提**：PenScope 仅用于**已获书面授权**的渗透测试 / 红队演练。任何贡献都不得用于帮助未授权攻击。提交即表示你同意遵守本仓库的 [行为准则](CODE_OF_CONDUCT.md) 与 [安全策略](SECURITY.md)。

## 1. 开发环境

要求：Python 3.11+（CI 使用 3.11），Windows 推荐（GUI 使用 pywebview + WebView2）。

```bash
# 克隆
git clone https://github.com/wanlqx/PenScope.git
cd PenScope

# 创建并激活虚拟环境（推荐）
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS / Linux

# 安装依赖
pip install -r requirements.txt
pip install pytest ruff bandit pip-audit   # 开发期额外工具

# 本地打包（产出 dist/PenScope.exe）
python make_icon.py          # 再生图标资源
python build_nowrap.py       # PyInstaller 单文件构建
```

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

## 3. 代码风格

- 格式化 / Lint：`ruff check .`（可选 `ruff format .`）。
- 安全静态分析：`bandit -r scanner app_api.py`。
- 依赖漏洞：`pip-audit -r requirements.txt`。
- 保持中文 / 英文界面字符串通过 `config` 与前端 i18n 资源维护，勿硬编码到逻辑中。

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

- **内置示例**：`scanner/plugins/example_headers.py`，随包发布以证明框架可用。
- **外部插件**：把 `.py` 放入 `~/.autopentest/plugins/` 即被自动发现并接入扫描流水线。

> ⚠️ **信任边界（重要）**：外部插件在应用启动时由 `importlib` **直接执行任意 Python 代码**，拥有与 PenScope 相同的当前用户权限。
> 因此：
> 1. 只从**可信来源**获取并安装插件；不要运行来源不明或未经审查的插件文件。
> 2. 插件可访问本机文件系统、网络与凭据保险库所在进程，请将其视为一等代码执行点对待。
> 3. 长期计划：将插件放入**独立子进程**中隔离运行（沙箱 / 最小权限），降低对主进程的信任暴露面。当前版本尚未实现该隔离。
