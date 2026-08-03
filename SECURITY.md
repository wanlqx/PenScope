# 安全政策（Security Policy）

## 1. 仅限授权使用

PenScope 是一款**授权式**自动化渗透测试工具，仅供你对**已获书面授权**的目标使用。
- 新增目标必须显式确认授权；
- 默认不执行任何主动/破坏性动作（默认凭据探测、会话续期、文件上传测试均默认关闭，需人工开启并二次确认）；
- 请遵守所在地法律法规与目标方的授权范围。产生的报告与授权书可作为测试合法性凭证。

## 2. 本仓库不包含任何凭据

发布产物（源码与 `PenScope.exe`）**严禁包含私人信息、密钥、令牌或敏感凭据**。通过以下机制保证：

- `.gitignore` 忽略：`*.key`、`autopentest.key`、`*vault*.json`、`*.db*`、`*.log`、`.env*`、训练/调试产物（如 `knowledge_feed/`、`bug_report.*`）与 `.workbuddy/`。
- 运行时凭据保险库（`scanner/vault.py`）的密钥：
  - 优先取自环境变量 `AUTOPENTEST_VAULT_KEY`（仅本地注入，绝不入库）；
  - 缺失时由程序在 exe 同级目录**自动随机生成** `autopentest.key`，并对凭据做 Fernet 加密落盘；
  - 前端 `get_auth_profile` 只返回掩码，**后端绝不回传明文密码**。
- 扫描目标、发现、日志等用户数据保存在 exe 同级数据库（`autopentest.db`），均属于本地运行时数据，不随仓库分发。

> 贡献者在提交前请确认：`git status` 中不应出现任何 `*.key`、`*vault*.json`、`*.db`、`*.log` 或个人目标信息。

## 3. 漏洞上报

如发现 PenScope **自身**的安全问题（而非你用 PenScope 扫出的目标漏洞），请通过以下方式私下报告，勿在公开 Issue 披露细节：
- 在仓库创建 **Security Advisory**（推荐），或
- 通过 Issue 联系维护者并注明「安全相关，请私信」。

我们会尽快评估并修复，并在修复后公开致谢（经你同意）。

## 4. 供应链与构建

- 构建依赖见 `requirements.txt`（仅 `requests / pywebview / pystray / Pillow / pyinstaller`，无远端服务依赖）。
- 图标/托盘资源由 `make_icon.py` 在构建时再生，不提交二进制资源。
- CI 构建在 GitHub 官方 `windows-latest`  runner 上进行，产物经 `verify_build` 校验模块完整性。
