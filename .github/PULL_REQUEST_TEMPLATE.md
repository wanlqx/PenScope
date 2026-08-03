# Pull Request

## 变更说明
<!-- 简要描述本次改动的目的与内容 -->

## 关联 Issue
<!-- 例：Closes #123 -->

## 改动类型
- [ ] 新功能（feat）
- [ ] 缺陷修复（fix）
- [ ] 文档（docs）
- [ ] 安全加固（security）
- [ ] CI / 构建（ci）
- [ ] 其他（chore）

## 测试
- [ ] 已运行本地纯逻辑测试：
  `python -m pytest tests/test_session_vault.py tests/test_hardening.py tests/test_cred_dict.py tests/smoke_nobackend.py tests/test_scope_redirect.py tests/test_vuln_i18n.py -q`
- [ ] ruff / bandit 无新增阻断问题
- [ ] 涉及 GUI 的改动已在本地窗口验证

## 安全影响
<!-- 若涉及授权围栏、人工复核、凭据保险库、扫描逻辑，请说明安全影响 -->
- 是否改变授权 / 复核闸门：是 / 否
- 是否引入新的外部请求或依赖：是 / 否
- 是否涉及凭据 / 密钥处理：是 / 否

## 检查清单
- [ ] 未提交任何真实目标 IP、账号、密码、Cookie、令牌或敏感数据
- [ ] 未改动 `config.VERSION`（版本号由发布流程统一维护）
- [ ] 新增依赖已写入 `requirements.txt`
