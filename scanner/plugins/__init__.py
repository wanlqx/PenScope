"""F-08 插件加载器（含信任白名单 + 完整性校验）。

信任模型（中期隔离，详见 CONTRIBUTING.md「插件开发与安全」）：
  - 内置示例插件：随包发布、受信，始终自动加载。
  - 外部插件（~/.autopentest/plugins/*.py）：默认「严格信任」模式——
    只有被显式加入白名单、且其 SHA-256 与登记值一致的插件才会被加载。
    任意落盘但未登记的 .py 不会自动执行（杜绝静默任意代码执行）。
    通过 `python -m scanner.plugins trust <file>` 登记/更新信任。

加载失败/校验失败均只告警，不影响其他插件与内置插件。
"""
import hashlib
import importlib.util
import json
import logging
import os

try:  # config 不依赖本模块，导入安全；失败则退回环境变量/默认值
    from config import ENABLE_PLUGINS as _CFG_ENABLED
    from config import PLUGIN_TRUST_MODE as _CFG_TRUST
except Exception:  # pragma: no cover - 极端导入顺序异常
    _CFG_TRUST = None
    _CFG_ENABLED = True

from scanner.plugin_base import BaseScanner
from scanner.plugins.example_headers import ExampleSecurityHeadersScanner

PLUGIN_TRUST_MODE = (
    _CFG_TRUST or os.environ.get("PENSCOPE_PLUGIN_TRUST", "strict") or "strict"
).lower()

_LOG = logging.getLogger("PenScope.plugins")

# 用户二次开发插件放置目录（首次加载时若不存在则创建，便于发现）。
EXTERNAL_DIR = os.path.join(os.path.expanduser("~"), ".autopentest", "plugins")
# 信任白名单清单：记录每个被信任插件的 SHA-256（篡改检测）。
MANIFEST_PATH = os.path.join(EXTERNAL_DIR, "manifest.json")

_CACHE = None


def _iso_now():
    try:
        from datetime import datetime
        return datetime.now().isoformat(timespec="seconds")
    except Exception:  # pragma: no cover
        return ""


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_manifest(manifest_path=None):
    path = manifest_path or MANIFEST_PATH
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        _LOG.warning("读取插件信任清单失败 %s: %s", path, e)
        return {}


def _save_manifest(data, manifest_path=None):
    path = manifest_path or MANIFEST_PATH
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)  # 原子写，避免半截清单导致信任失效


def trust_plugin(path, manifest_path=None, external_dir=None):
    """登记/更新对某个外部插件的信任：记录其当前 SHA-256。返回 (ok, msg)。"""
    manifest_path = manifest_path or MANIFEST_PATH
    external_dir = external_dir or EXTERNAL_DIR
    path = os.path.abspath(path)
    if not os.path.isfile(path) or not path.endswith(".py"):
        return False, "不是常规 .py 插件文件"
    if os.path.dirname(path).rstrip("/\\") != os.path.abspath(external_dir).rstrip("/\\"):
        return False, "插件必须位于 %s 下" % external_dir
    name = os.path.splitext(os.path.basename(path))[0]
    data = _load_manifest(manifest_path)
    data[name] = {"sha256": _sha256(path), "added": _iso_now(), "note": ""}
    _save_manifest(data, manifest_path)
    return True, "已信任插件 %s（已记录完整性哈希）" % name


def list_trusted(manifest_path=None):
    return _load_manifest(manifest_path)


def verify_trusted(manifest_path=None, external_dir=None):
    """校验已信任插件的哈希是否仍匹配。返回 (ok_names, tampered_names)。"""
    manifest_path = manifest_path or MANIFEST_PATH
    external_dir = external_dir or EXTERNAL_DIR
    data = _load_manifest(manifest_path)
    ok, bad = [], []
    for name, info in data.items():
        full = os.path.join(external_dir, name + ".py")
        if not os.path.isfile(full):
            bad.append(name)
            continue
        if info.get("sha256") and _sha256(full) != info["sha256"]:
            bad.append(name)
        else:
            ok.append(name)
    return ok, bad


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
    # 内置示例：随包发布、受信，始终自动加载（证明框架可用）。
    return [ExampleSecurityHeadersScanner()]


def _write_readme():
    try:
        readme = os.path.join(EXTERNAL_DIR, "_README.txt")
        if not os.path.exists(readme):
            with open(readme, "w", encoding="utf-8") as f:
                f.write(
                    "PenScope 插件目录\n"
                    "========================\n"
                    "把继承 scanner.plugin_base.BaseScanner 的 .py 文件放到此目录。\n"
                    "\n"
                    "安全：默认「严格信任」模式下，落盘的文件不会自动执行。\n"
                    "必须先登记信任才能加载：\n"
                    "    python -m scanner.plugins trust <本目录下的插件文件.py>\n"
                    "登记会记录该文件的 SHA-256；之后文件被改动（篡改）将拒绝加载。\n"
                    "参考内置示例：scanner/plugins/example_headers.py\n")
    except Exception:
        pass


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
        _write_readme()

    if PLUGIN_TRUST_MODE == "off":
        _LOG.info("外部插件已禁用（PLUGIN_TRUST_MODE=off）")
        return out

    manifest = _load_manifest()
    strict = PLUGIN_TRUST_MODE == "strict"
    loaded, skipped = [], []

    for fn in sorted(os.listdir(EXTERNAL_DIR)):
        if not fn.endswith(".py") or fn.startswith("_"):
            continue
        full = os.path.join(EXTERNAL_DIR, fn)
        base = os.path.splitext(fn)[0]
        if base in manifest:
            expected = manifest[base].get("sha256")
            if expected:
                actual = _sha256(full)
                if actual != expected:
                    _LOG.warning("插件 %s 完整性校验失败（哈希不匹配，可能已被篡改），拒绝加载", fn)
                    skipped.append(fn)
                    continue
            try:
                mod = _load_module_from_file(full)
                out += _instances_from_module(mod)
                loaded.append(fn)
            except Exception as e:
                _LOG.warning("外部插件加载失败 %s: %s", fn, e)
                skipped.append(fn)
        else:
            if strict:
                _LOG.warning(
                    "外部插件 %s 未列入信任白名单，已跳过（用 "
                    "`python -m scanner.plugins trust %s` 登记）", fn, full)
                skipped.append(fn)
            else:  # warn 模式：兼容旧行为，加载但高亮告警
                _LOG.warning("以非严格模式加载未登记插件 %s（任意代码执行风险），建议改为严格信任", fn)
                try:
                    mod = _load_module_from_file(full)
                    out += _instances_from_module(mod)
                    loaded.append(fn)
                except Exception as e:
                    _LOG.warning("外部插件加载失败 %s: %s", fn, e)
                    skipped.append(fn)

    if skipped:
        _LOG.warning("共跳过 %d 个外部插件（严格模式下需显式 trust 才加载）", len(skipped))
    return out


def load_plugins(force=False):
    """返回已注册的 BaseScanner 实例列表（带缓存）。force=True 强制重新扫描。"""
    global _CACHE
    if _CACHE is not None and not force:
        return _CACHE
    if not _CFG_ENABLED:
        _LOG.info("插件总开关已关闭（config.ENABLE_PLUGINS=False），不加载任何插件")
        _CACHE = []
        return _CACHE
    found = _builtin_instances() + _external_instances()
    _CACHE = found
    return found
