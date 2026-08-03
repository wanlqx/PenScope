"""PenScope —— 全局配置
纯本地桌面工具：无后端、无账号、无密钥。所有状态存于本地 SQLite。
兼容 PyInstaller 打包：资源在只读的 BUNDLE_DIR，运行时数据在可写的 BASE_DIR。
"""
import os
import sys

# 路径处理：兼容 PyInstaller 打包（--onefile 会把资源解压到临时目录 sys._MEIPASS）
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)      # 可执行文件所在目录（可写，存数据库）
    BUNDLE_DIR = sys._MEIPASS                        # 打包进 exe 的只读资源目录
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = BASE_DIR

# 应用名称（展示给使用者，唯一对外品牌名；改名只需改此处 + 重新构建）
APP_NAME = "PenScope"

# 语义化版本号（MAJOR.MINOR.PATCH），展示给使用者；发布标签为 v<VERSION>
# 规范：MAJOR=不兼容/重大架构变更；MINOR=向后兼容的功能新增；PATCH=向后兼容的问题修复。
VERSION = "1.0.0"

# F-08：插件化框架总开关。关闭后不加载/运行任何插件扫描器（含内置示例）。
ENABLE_PLUGINS = True

# 插件信任模式（外部插件 ~/.autopentest/plugins/*.py 的加载策略）：
#   strict（默认）：仅加载「已显式信任且其 SHA-256 与登记值一致」的外部插件；
#                   任意未登记/被篡改的文件不会自动执行（杜绝静默任意代码执行）。
#   warn：加载全部外部插件但高亮告警（兼容旧行为 / 本地开发用）。
#   off：完全不加载外部插件。
# 环境变量 PENSCOPE_PLUGIN_TRUST 可临时覆盖。通过 `python -m scanner.plugins trust <file>` 登记信任。
PLUGIN_TRUST_MODE = os.environ.get("PENSCOPE_PLUGIN_TRUST", "strict").lower()

# 数据库文件（存放在可执行文件目录下，保证可写）
DB_PATH = os.environ.get("AUTOPENTEST_DB", os.path.join(BASE_DIR, "autopentest.db"))

# 扫描默认参数
DEFAULT_TIMEOUT = 3.0
MAX_PORTS_PER_HOST = 1000
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443,
    9000, 9200, 11211, 27017, 50070
]

# 风险等级（由高到低）
RISK_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]
RISK_CN = {
    "Critical": "严重",
    "High": "高危",
    "Medium": "中危",
    "Low": "低危",
    "Info": "信息",
}

# 需要人工复核的"闸门"阶段（关键决策节点）
# 这些阶段在扫描流程中会被暂停，等待使用者批准后才继续
GATED_STAGES = {
    "add_target": "将新目标加入授权范围（防止对未授权资产发起扫描）",
    "exploit_verify": "对疑似漏洞进行利用验证（可能触发真实利用，需授权确认）",
    "upload_test": "对文件上传点进行上传测试（可能写入测试文件，需授权确认）",
}

# 主动默认凭据探测开关（CWE-287）。默认关闭：登录尝试属半攻击行为，易触发账号锁定 /
# 被判定爆破，遵循"默认只读、不爆破、不写"原则，把主动动作交给用户显式开启。
# 注意：ENABLE_AUTH_PROBE 是代码级主闸门（默认 False）；C-05 后还可在"设置"中经授权确认
# 开启（设置项 enable_auth_probe），二者任一为真即启用探测，探测字典见 AUTH_PROBE_DICT_PATH。
ENABLE_AUTH_PROBE = False

# C-06：会话续期（已授权目标的登录态维持/自动重登）总开关。
# 默认关闭：会话续期需在本机加密存储目标登录凭据（scanner.vault），属敏感能力，
# 遵循"默认只读、不爆破、不写"原则，由使用者显式开启（设置项 enable_session_renew），
# 且仅对「显式配置并存储了凭据」的目标生效。凭据以 Fernet 加密落盘，前端永不拿到明文密码。
ENABLE_SESSION_RENEW = False

# C-06：会话续期单次扫描的默认最大自动重登次数（超出后停止续期，避免账号锁定风险放大）。
SESSION_RENEW_MAX = 5

# 默认凭据探测字典（C-05 外置）。留空则使用打包内置字典 config/dicts/default_creds.txt；
# 填入绝对路径可整体替换为自定义字典（用户导入）。亦可用环境变量 AUTOPENTEST_AUTH_DICT
# 或设置项 auth_probe_dict 覆盖（优先级：env/设置 > 本配置 > 内置 > 内嵌兜底）。
AUTH_PROBE_DICT_PATH = None
