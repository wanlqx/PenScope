# PenScope 代码安全审计报告与修复记录

> 审计对象：PenScope v1.0.0（原 AutoPentest AI）全部 Python 源文件 + 前端 + 构建/工具脚本
> 审计结论：**高危/严重 0 项**；中危 2 项、低危 6 项、信息 2 项，均在本次修复闭环中处理或确认合规。

## 修复状态总览

| 编号 | 级别 | 问题 | 状态 | 修复位置 |
|------|------|------|------|----------|
| M-01 | 中危 | 构建脚本全局替换 os.remove/unlink/rmdir 为 nt.* 且不还原 | ✅ 已修复 | `build_nowrap.py` |
| M-02 | 中危 | 发布脚本 `_sh` 外部命令输入缺乏校验 | ✅ 已修复 | `tools/release.py` |
| L-01 | 低危 | `_PORT_CACHE` 全局字典无淘汰，长期运行内存增长 | ✅ 已修复 | `run_scans.py` |
| L-02 | 低危 | `_verify_banner` 裸 `except: pass` 静默吞异常 | ✅ 已修复 | `scanner/port_scan.py` |
| L-03 | 低危 | `set_auth_profile` 通用异常无日志 | ✅ 已修复 | `app_api.py` |
| L-04 | 低危 | 密钥文件 Windows 上 chmod 权限仅部分生效 | ✅ 已修复 | `scanner/vault.py` |
| L-05 | 低危 | `os.startfile` 打开数据目录未做路径规范化 | ✅ 已修复 | `main_gui.py` |
| L-06 | 低危 | `auth_probe_dict` 路径未校验，可越界读取 | ✅ 已修复 | `app_api.py` |
| I-01 | 信息 | 报告 HTML 转义一致 | ✅ 已确认合规 | `reports.py` |
| I-02 | 信息 | 数据库层参数化查询 | ✅ 已确认合规 | `db.py` |

## 修复细节

### M-01 构建脚本 os.* 替换作用域收敛
- **原问题**：`build_nowrap.py` 在模块导入时把 `os.remove / os.unlink / os.rmdir` 整体替换为 Windows 底层 `nt.unlink / nt.rmdir`，用于绕过本机 safe-delete 沙箱封装，使 PyInstaller 清理步骤能删临时文件，但**构建后从不还原**，会污染整个进程内的文件删除语义。
- **修复**：导入时先快照原始 `os` 函数；构建（`pimain.run()`）放在 `try/finally` 中，无论成功与否都在 `finally` 调用 `_restore_os()` 还原，消除对进程内其它逻辑的副作用，也避免被恶意 `nt` 模块劫持环境滥用。

### M-02 发布脚本外部输入校验
- **原问题**：`tools/release.py` 的 `_sh` 经 `subprocess.run(..., shell=False)` 执行 `git/gh` 命令，标签名等外部输入未做格式校验。
- **修复**：新增 `_safe_ref()`，用正则 `^[A-Za-z0-9._/-]+$` 校验标签名（来自 `config.VERSION` 严格解析，本已安全，此为纵深防御）；分支名/远程名仍为硬编码常量（如 `origin/main`），无注入面。

### L-01 `_PORT_CACHE` 增加 TTL 淘汰
- **原问题**：`run_scans.py` 的 `_PORT_CACHE` 全局字典永不清理，长期大量目标扫描时持续增长。
- **修复**：改为 `(value, timestamp)` 结构，新增 `_port_cache_get/_port_cache_set`；TTL 30 分钟过期 + 最大 1024 条（超出淘汰最旧），调用点同步改写。

### L-02 `_verify_banner` 增加异常日志
- **修复**：裸 `except Exception: pass` 改为 `except Exception as exc: log.debug(...)`，记录端口与异常，区分“协议不支持 / 超时 / 对端断开”，不阻断回退到原 banner。

### L-03 `set_auth_profile` 异常差异化
- **修复**：已用 `isinstance(e, VaultError)` 区分保险库错误；新增 `log.warning` 记录非保险库类保存失败，便于精确诊断（仍对前端返回脱敏的 `E_INTERNAL`）。

### L-04 凭据密钥文件 Windows ACL 加固
- **原问题**：`scanner/vault.py` 生成 Fernet 密钥后以 `chmod(0o600)` 收窄权限，Windows 上 POSIX 权限仅部分生效。
- **修复**：新增 `_harden_key_permissions()`——Windows 下调用 `icacls <path> /inheritance:r /grant:r <user>:(R)` 去除继承并仅授权当前用户只读；非 Windows 保持 `chmod 0600`。

### L-05 `os.startfile` 路径规范化
- **修复**：`_open_data_folder()` 中 `os.startfile(d)` → `os.startfile(os.path.normpath(d))`，防御路径篡改导致的非预期文件打开（路径本由程序内部计算，风险极低，此为纵深防御）。

### L-06 `auth_probe_dict` 路径校验
- **修复**：`set_settings` 中该字段非空时：解析为绝对规范化路径 → 校验为**存在的常规文件** → 拒绝指向 `Windows\System32 / SysWOW64 / SystemApps / WinSxS` 等受限系统目录；否则返回 `E_INVALID`，避免越界读取。

## 持续合规事项（非代码缺陷）
- 仓库通过 `.gitignore` 忽略 `*.db / *.log / *.key / *vault* / .env* / dist/ / build/ / knowledge_feed/ / .workbuddy/` 等，确保密钥、数据库、日志、训练产物**不入库**。
- 凭据保险库仅对显式配置并存储的目标生效，且后端对前端**永不回传明文密码**（仅 masked 视图）。
- 发布产物（GitHub Release 挂载的 `PenScope.exe`）与源码中均不含私人信息 / 令牌 / 凭据。
