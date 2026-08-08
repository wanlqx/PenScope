# 桌面端 Agent 状态栏 —— 设计与落地清单

> 状态：**已完成（后端脚手架 + GUI 落地均已合并；2026-08-08 用户授权「可以进行2」后由自动循环落地）**。
> 安全围栏：纯观测性 UI，不触发任何扫描/写动作；推送 seam 无窗口时静默 no-op。

## 1. 目标

PenScope 是 pywebview 纯本地桌面工具。扫描执行期间用户看不到后台进度，容易产生"卡住"观感。
需要一个常驻的 **Agent 状态栏**，实时展示 AI 副驾当前所处阶段，让扫描过程透明、可观测。

## 2. 状态机（已落地，纯后端）

`scanner/agent_status.py` 定义线程安全的 `AgentStatusBar` 与推送 seam `push_agent_status`，
覆盖以下生命周期状态：

| 状态 | 含义 |
|------|------|
| `idle` | 空闲 |
| `thinking` | AI 推理 / 路由调度（router.py 决策时） |
| `recon` | 侦查 / 指纹识别（product_fp / known_vuln 探针） |
| `scanning` | 只读主动探针（web_scan / port_scan 等） |
| `verifying` | 证据收敛 / 三路裁决（reflexion / evidence_store） |
| `awaiting_human` | 人工复核闸门待决（高危动作被拦截，如时间盲注 / 上传测试） |
| `reporting` | 报告生成 |
| `error` | 出错（含未知状态被拒绝） |

- 状态切换经 `set_state(state, note=None, **meta)`，校验非法态并自动转 `error`。
- `meta` 可携带 `scan_id` / `target_id` / `progress`（0~1 进度条）。
- 支持 `subscribe(cb)` 订阅回调，状态变更同步广播（测试 / 日志桥接复用）。
- 进程级单例 `default_bar` 供 run_scans / 插件直接 import 使用。

## 3. 推送 seam（已落地，与 push_scan_event 同构）

`push_agent_status(state, note=None, window=None, **meta)`：

- 通过 `window.evaluate_js("window.__autopentestOnAgentStatus({...})")` 推前端；
- 未注册窗口（`set_agent_status_window` 未调用）时**静默 no-op**；
- 窗口异常（未就绪 / 已销毁 / 线程调度异常）**静默吞掉**，绝不中断扫描 worker；
- 自动合并 `scanner.logctx` 当前 scan 上下文（scan_id / target_id），调用点无需手动传。

## 4. GUI 落地清单（已落地，2026-08-08）

1. **DOM**：复用既有 `frontend/index.html` 的 `#statusbar` 容器，在 `renderStatusBar()` 中追加 `#sb-agent` 节点（状态圆点 + 文本），不破坏既有 running/targets/scans/reviews 项。
2. **渲染**：前端实现 `window.__autopentestOnAgentStatus(payload)`，按 `payload.state` 切换 `.sb-dot` 颜色类（think/recon/scan/verify/human/report/err）+ 双语文案（中/英，跟随 `settings.language`）。状态留存模块级 `_agentState`，`renderStatusBar` 每 8s 重渲时回显，避免被刷新冲掉。
3. **注册**：`main_gui.py` 窗口创建后调用 `set_agent_status_window(window)`（紧邻 `run_scans.set_push_window`）。
4. **埋点**：`run_scans.process_scan._evt` 在每次阶段事件（start/done/failed/paused）同步调用 `push_agent_status(...)`，经 `_agent_state_for_stage()` 把扫描阶段名映射为 AI 副驾状态（关键字匹配，对阶段命名不敏感）。
5. **视觉闸**：`body.fx-off` 时仅停用 `.sb-dot` 脉冲动画（`animation:none`），**功能性状态文本仍可见**——状态栏属核心可观测性而非装饰特效层，故保留文本（UX 更优，且与「fx 关闭即隐藏装饰层」的本意一致）。
6. **构建登记**：`scanner.agent_status` 已加入 `verify_build.py` 的 `EXPECTED_MODULES`，PYZ 校验覆盖。

## 5. 验证

- 后端：`tests/test_agent_status.py` 9 项（状态机 6 + 推送 seam 3），纯逻辑无 GUI 依赖，全绿。
- 门禁命令已扩展 `or agent_status`，纳入自动循环验证。
- `build_nowrap.py` 重建无回归（新模块已在 EXPECTED_MODULES，PYZ 校验覆盖）。
