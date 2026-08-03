"""F-08 插件加载器。

加载策略（带模块级缓存，避免每次扫描重复 import）：
  1. 内置示例插件：本包显式 import（确保被 PyInstaller 收集），随包发布以证明框架可用。
  2. 外部插件：用户把 .py 放入 ~/.autopentest/plugins/ 即被自动发现（二次开发扩展点）。

load_plugins() 返回 BaseScanner 实例列表；单个插件加载/实例化失败只告警，不影响其他插件。
"""
import importlib.util
import logging
import os

from scanner.plugin_base import BaseScanner

_LOG = logging.getLogger("PenScope.plugins")

# 用户二次开发插件放置目录（首次加载时若不存在则创建，便于发现）。
EXTERNAL_DIR = os.path.join(os.path.expanduser("~"), ".autopentest", "plugins")

# 内置示例插件：显式 import 以确保被打包工具收集，并纳入内置列表。
from scanner.plugins.example_headers import ExampleSecurityHeadersScanner

_CACHE = None


def _load_module_from_file(path):
    name = "autopentest_external_plugin_" + os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _instances_from_module(mod):
    out = []
    for attr in vars(mod).values():
        if (isinstance(attr, type) and issubclass(attr, BaseScanner)
                and attr is not BaseScanner):
            try:
                out.append(attr())
            except Exception as e:  # 实例化失败
                _LOG.warning("插件实例化失败 %s: %s", attr, e)
    return out


def _builtin_instances():
    # 内置示例：随包发布，证明框架可用。
    return [ExampleSecurityHeadersScanner()]


def _external_instances():
    out = []
    created = False
    if not os.path.isdir(EXTERNAL_DIR):
        try:
            os.makedirs(EXTERNAL_DIR, exist_ok=True)
            created = True
        except Exception as e:
            _LOG.warning("创建外部插件目录失败 %s: %s", EXTERNAL_DIR, e)
            return out
    if created:
        try:
            readme = os.path.join(EXTERNAL_DIR, "_README.txt")
            if not os.path.exists(readme):
                with open(readme, "w", encoding="utf-8") as f:
                    f.write(
                        "PenScope 插件目录\n"
                        "========================\n"
                        "把继承 scanner.plugin_base.BaseScanner 的 .py 文件放到此目录，\n"
                        "重启应用即可被自动发现并接入扫描流水线。\n"
                        "参考内置示例：scanner/plugins/example_headers.py\n")
        except Exception:
            pass
    for fn in sorted(os.listdir(EXTERNAL_DIR)):
        if fn.endswith(".py") and not fn.startswith("_"):
            try:
                mod = _load_module_from_file(os.path.join(EXTERNAL_DIR, fn))
                out += _instances_from_module(mod)
            except Exception as e:
                _LOG.warning("外部插件加载失败 %s: %s", fn, e)
    return out


def load_plugins(force=False):
    """返回已注册的 BaseScanner 实例列表（带缓存）。force=True 强制重新扫描。"""
    global _CACHE
    if _CACHE is not None and not force:
        return _CACHE
    found = _builtin_instances() + _external_instances()
    _CACHE = found
    return found
