"""PenScope —— 默认凭据字典加载器（C-05 外置）。

把原本硬编码在 scanner/auth.py 的 `_DEFAULT_CREDS` 外置为可维护、可用户导入的字典文件：

  - 打包内置字典：`<BUNDLE_DIR>/config/dicts/default_creds.txt`（随 exe 分发）。
  - 自定义字典：通过 config.AUTH_PROBE_DICT_PATH 或环境变量 AUTOPENTEST_AUTH_DICT
    指定；也可由调用方（run_scans）从设置项 `auth_probe_dict` 显式传入路径。
  - 内嵌兜底：极端情况下（字典文件缺失 / 打包遗漏）仍可用，内容与 default_creds.txt 一致。

统一经 `_normalize` 处理：跳过空白与 `#` 注释、丢弃无冒号/超长字段、去重、限条数。
所有来源解析失败时回退到下一优先级来源，保证探测功能不崩。
"""
import os

from config import BUNDLE_DIR

# 打包内置字典路径（位于只读 BUNDLE_DIR；开发态 BUNDLE_DIR == BASE_DIR）。
BUNDLED_DICT_PATH = os.path.join(BUNDLE_DIR, "config", "dicts", "default_creds.txt")

# 安全上限：防止超大自定义字典拖慢探测或耗尽内存。
MAX_ENTRIES = 5000
MAX_FIELD_LEN = 256

# 内嵌兜底字典（与 config/dicts/default_creds.txt 内容保持一致）。
_EMBEDDED_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"), ("admin", "123456"),
    ("root", "root"), ("root", "password"), ("administrator", "administrator"), ("guest", "guest"),
    ("test", "test"), ("admin", "admin@123"), ("user", "user"), ("sa", "sa"),
    ("postgres", "postgres"), ("admin", "letmein"),
]


def _normalize(path):
    """读取并规范化一个字典文件。返回 [(user, pass), ...]；文件缺失/无法解码返回 None（调用方回退）。"""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            rows, seen = [], set()
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    continue
                user, _, pwd = line.partition(":")
                user, pwd = user.strip(), pwd.strip()
                if not user or not pwd:
                    continue
                if len(user) > MAX_FIELD_LEN or len(pwd) > MAX_FIELD_LEN:
                    continue
                key = (user, pwd)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(key)
                if len(rows) >= MAX_ENTRIES:
                    break
            return rows
    except (OSError, UnicodeDecodeError):
        return None


def load_default_creds(path=None):
    """返回 [(user, pass), ...]。来源优先级：

    1. 显式参数 path（调用方/测试用，最高优先）；
    2. 环境变量 AUTOPENTEST_AUTH_DICT 或 config.AUTH_PROBE_DICT_PATH；
    3. 打包内置字典 default_creds.txt；
    4. 内嵌兜底 _EMBEDDED_DEFAULT_CREDS。

    所有文件来源均经 _normalize（去注释/空白/重复/超长 + 限条数）；
    一旦某个来源返回非空列表即采用，否则回退到下一来源。
    """
    candidates = []
    if path:
        candidates.append(path)
    env_path = os.environ.get("AUTOPENTEST_AUTH_DICT")
    if env_path:
        candidates.append(env_path)
    cfg_path = getattr(__import__("config"), "AUTH_PROBE_DICT_PATH", None)
    if cfg_path:
        candidates.append(cfg_path)
    candidates.append(BUNDLED_DICT_PATH)
    for c in candidates:
        if not c:
            continue
        res = _normalize(c)
        if res:  # 非空列表（含解析成功但为空也跳过，继续回退）
            return res
    return list(_EMBEDDED_DEFAULT_CREDS)
