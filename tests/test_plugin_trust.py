"""插件信任白名单 + 完整性校验测试（纯逻辑，无需 pywebview / 靶机）。

通过把 EXTERNAL_DIR / MANIFEST_PATH / PLUGIN_TRUST_MODE 指向临时目录来隔离测试，
不触碰真实用户插件目录。每个测试都 force 重新扫描以绕过模块级缓存。
"""
import textwrap

import pytest

import scanner.plugins as plugins

PLUGIN_SRC = textwrap.dedent(
    """
    from scanner.plugin_base import BaseScanner

    class MyScan(BaseScanner):
        name = "my-scan"
        description = "test plugin"

        def scan(self, ctx):
            return None
    """
)


@pytest.fixture
def ext_env(tmp_path, monkeypatch):
    ext = tmp_path / "plugins"
    ext.mkdir()
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(plugins, "EXTERNAL_DIR", str(ext))
    monkeypatch.setattr(plugins, "MANIFEST_PATH", str(manifest))
    monkeypatch.setattr(plugins, "_CACHE", None)
    plugin_file = ext / "my_scan.py"
    plugin_file.write_text(PLUGIN_SRC, encoding="utf-8")
    return {"ext": str(ext), "manifest": str(manifest), "plugin": str(plugin_file)}


def _names():
    return [type(i).__name__ for i in plugins.load_plugins(force=True)]


def _write_plugin(path, content=PLUGIN_SRC):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def test_strict_blocks_untrusted(ext_env, monkeypatch):
    monkeypatch.setattr(plugins, "PLUGIN_TRUST_MODE", "strict")
    names = _names()
    assert "MyScan" not in names
    # 内置示例插件仍应加载
    assert "ExampleSecurityHeadersScanner" in names


def test_trusted_plugin_loads(ext_env, monkeypatch):
    monkeypatch.setattr(plugins, "PLUGIN_TRUST_MODE", "strict")
    ok, msg = plugins.trust_plugin(
        ext_env["plugin"], manifest_path=ext_env["manifest"], external_dir=ext_env["ext"])
    assert ok, msg
    names = _names()
    assert "MyScan" in names
    assert "ExampleSecurityHeadersScanner" in names


def test_tampered_plugin_rejected(ext_env, monkeypatch):
    monkeypatch.setattr(plugins, "PLUGIN_TRUST_MODE", "strict")
    ok, msg = plugins.trust_plugin(
        ext_env["plugin"], manifest_path=ext_env["manifest"], external_dir=ext_env["ext"])
    assert ok, msg
    # 篡改插件内容（哈希改变）
    _write_plugin(ext_env["plugin"], PLUGIN_SRC + "\n# tampered\n")
    names = _names()
    assert "MyScan" not in names  # 篡改后应拒载
    assert "ExampleSecurityHeadersScanner" in names  # 内置不受影响


def test_warn_mode_loads_untrusted(ext_env, monkeypatch):
    monkeypatch.setattr(plugins, "PLUGIN_TRUST_MODE", "warn")
    names = _names()
    assert "MyScan" in names  # warn 模式加载未登记插件


def test_off_mode_loads_nothing_external(ext_env, monkeypatch):
    monkeypatch.setattr(plugins, "PLUGIN_TRUST_MODE", "off")
    names = _names()
    assert "MyScan" not in names
    assert "ExampleSecurityHeadersScanner" in names


def test_verify_detects_tamper(ext_env, monkeypatch):
    monkeypatch.setattr(plugins, "PLUGIN_TRUST_MODE", "strict")
    plugins.trust_plugin(
        ext_env["plugin"], manifest_path=ext_env["manifest"], external_dir=ext_env["ext"])
    ok, bad = plugins.verify_trusted(
        manifest_path=ext_env["manifest"], external_dir=ext_env["ext"])
    assert ok and not bad
    _write_plugin(ext_env["plugin"], PLUGIN_SRC + "\n# tampered\n")
    ok, bad = plugins.verify_trusted(
        manifest_path=ext_env["manifest"], external_dir=ext_env["ext"])
    assert bad and "my_scan" in bad
