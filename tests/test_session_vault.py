"""C-06 加密凭据保险库单元测试（tempfile 隔离，注入 Fernet key，不触碰真实库/密钥）。"""
import os
import tempfile

import pytest
from cryptography.fernet import Fernet

from scanner.vault import Vault, VaultError, mask_profile


def _rm(p):
    for _ in range(20):
        try:
            if os.path.exists(p):
                os.remove(p)
            return
        except OSError:
            import time
            time.sleep(0.05)
    try:
        if os.path.exists(p):
            os.remove(p)
    except OSError:
        pass


@pytest.fixture
def vault():
    d = tempfile.mkdtemp(prefix="vault_test_")
    key = Fernet.generate_key()
    v = Vault(path=os.path.join(d, "v.bin"), key_path=os.path.join(d, "k.key"),
              master_key=key)
    yield v
    _rm(os.path.join(d, "v.bin"))
    _rm(os.path.join(d, "v.bin.tmp"))
    _rm(os.path.join(d, "k.key"))


def _profile(tid=1):
    return {
        "login_url": "https://example.com/login",
        "method": "post",
        "user_field": "user",
        "pass_field": "pass",
        "username": "admin",
        "password": "s3cr3t",
        "extra_fields": [["csrf", "abc"]],
        "csrf_autodetect": True,
        "max_renewals": 5,
    }


def test_store_get_roundtrip(vault):
    vault.store(1, _profile(1))
    got = vault.get(1)
    assert got["username"] == "admin"
    assert got["password"] == "s3cr3t"          # 后端内部可取明文密码
    assert got["extra_fields"] == [["csrf", "abc"]]


def test_delete_and_list(vault):
    vault.store(1, _profile(1))
    vault.store(2, _profile(2))
    assert set(vault.list()) == {1, 2}
    assert vault.delete(1) is True
    assert vault.list() == [2]
    assert vault.exists(1) is False
    assert vault.delete(99) is False


def test_encrypted_at_rest(vault):
    """密文文件不应包含明文密码（加密落盘）。"""
    vault.store(1, _profile(1))
    with open(vault.path, "rb") as f:
        blob = f.read()
    assert b"s3cr3t" not in blob
    assert len(blob) > 0


def test_tamper_detected(vault):
    """文件被篡改（非合法密文）时加载应抛 VaultError。"""
    vault.store(1, _profile(1))
    with open(vault.path, "wb") as f:
        f.write(b"not-a-valid-ciphertext!!!!")
    with pytest.raises(VaultError):
        vault.get(1)


def test_mask_profile_hides_password():
    m = mask_profile(_profile(1))
    assert m["configured"] is True
    assert m["has_password"] is True
    assert "password" not in m
    assert m["username"] == "admin"
    assert m["login_url"] == "https://example.com/login"
    # 无配置返回安全视图
    assert mask_profile(None) == {"configured": False}


def test_env_key_resolution(tmp_path, monkeypatch):
    """无 master_key 时，优先使用环境变量 AUTOPENTEST_VAULT_KEY。"""
    key = Fernet.generate_key()
    monkeypatch.setenv("AUTOPENTEST_VAULT_KEY", key.decode("ascii"))
    v = Vault(path=str(tmp_path / "v.bin"), key_path=str(tmp_path / "k.key"))
    v.store(7, _profile(7))
    got = v.get(7)
    assert got["password"] == "s3cr3t"
    # 环境变量优先于（不存在的）密钥文件
    assert not os.path.exists(v._key_path)
