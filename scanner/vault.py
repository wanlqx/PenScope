"""PenScope —— C-06 加密凭据保险库（本地会话续期凭证存储）。

设计目标（安全优先）：
  - 仅在「使用者已获书面授权」的目标上，存储用于维持/续期认证会话的登录凭据。
  - 凭据以 Fernet（AES-128-CBC + HMAC-SHA256）整体加密后落盘，明文绝不写入数据库或日志。
  - 密钥来源优先级：环境变量 AUTOPENTEST_VAULT_KEY（base64url Fernet key）
    > 同目录密钥文件 autopentest.key（首次使用随机生成，权限收窄 0600）
    > 兜底：随机生成并持久化到密钥文件。
  - 库内全量数据为一整段密文；无密钥文件 + 无环境变量则无法解密（防随数据库被随手拷贝泄露）。
  - 后端 API（app_api）对前端「永不回传明文密码」，仅返回 masked 资料（has_password + 用户名 + 登录端点等）。

局限（务必知悉）：单用户桌面工具，密钥与密文同机存放。这能防止「数据库文件被分享/备份泄露」导致的凭据明文外泄，
但无法防御「已登录同机账户」的攻击者（其可同时取到密钥与密文）。请勿在共享/多用户主机上存储高权限凭据；
如确需更高保护，可经环境变量 AUTOPENTEST_VAULT_KEY 注入由外部密钥管理（如系统凭据管理器）下发的临时密钥。
"""
import os
import json
import base64

try:
    from cryptography.fernet import Fernet, InvalidToken
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover - 极罕见：构建环境缺 cryptography
    Fernet = None
    InvalidToken = Exception
    _HAS_CRYPTO = False

from config import DB_PATH, BASE_DIR


def _vault_paths():
    """保险库文件与密钥文件均放在数据库同级目录（随 AUTOPENTEST_DB 迁移）。"""
    db_dir = os.path.dirname(os.path.abspath(DB_PATH))
    return (
        os.path.join(db_dir, "autopentest_vault.bin"),
        os.path.join(db_dir, "autopentest.key"),
    )


def _harden_key_permissions(path):
    """收窄密钥文件权限（L-04）：
    - Windows：用 icacls 去除继承并仅授权当前用户只读，阻止同机其他用户读取密钥；
    - 非 Windows：沿用 POSIX chmod 0600。
    失败仅告警，不阻断（密钥已生成，后续读取仍由本用户完成）。"""
    try:
        if os.name == "nt":
            import subprocess
            user = os.environ.get("USERNAME") or os.environ.get("USER")
            if user:
                # /inheritance:r 去掉继承；/grant:r 仅授予当前用户读取(R)，覆盖原有 ACE
                subprocess.run(
                    ["icacls", path, "/inheritance:r", "/grant:r", "%s:(R)" % user],
                    check=False, capture_output=True,
                )
        else:
            os.chmod(path, 0o600)
    except OSError:
        pass


class VaultError(Exception):
    """保险库不可用（如缺少加密依赖且无可降级路径）。"""


class Vault:
    """本地加密凭据保险库：以 tid 为键存储认证配置（含密码，整体加密）。

    可在测试中以 master_key（bytes，Fernet key）注入，避免触碰文件系统/生成密钥。
    """

    def __init__(self, path=None, key_path=None, master_key=None):
        self.path, self._key_path = (path, key_path) if path else _vault_paths()
        self._master_key = master_key  # bytes（Fernet key）或 None
        self._fernet = None

    # ---------------- 密钥 ----------------
    def _resolve_key(self):
        if self._master_key is not None:
            return self._master_key
        env_key = os.environ.get("AUTOPENTEST_VAULT_KEY")
        if env_key:
            self._master_key = env_key.encode("utf-8") if isinstance(env_key, str) else env_key
            return self._master_key
        # 密钥文件：缺失则随机生成并落盘（收窄权限）
        if os.path.exists(self._key_path):
            with open(self._key_path, "rb") as f:
                self._master_key = f.read().strip()
            if self._master_key:
                return self._master_key
        self._master_key = Fernet.generate_key()
        try:
            with open(self._key_path, "wb") as f:
                f.write(self._master_key)
            _harden_key_permissions(self._key_path)
        except OSError as e:  # pragma: no cover
            raise VaultError(f"无法写入密钥文件 {self._key_path}: {e}")
        return self._master_key

    def _f(self):
        if self._fernet is None:
            if not _HAS_CRYPTO:  # pragma: no cover
                raise VaultError("缺少 cryptography 依赖，无法加解密保险库")
            self._fernet = Fernet(self._resolve_key())
        return self._fernet

    # ---------------- 读写 ----------------
    def _load_all(self):
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "rb") as f:
            blob = f.read()
        if not blob:
            return {}
        try:
            plain = self._f().decrypt(blob)
        except InvalidToken:
            raise VaultError("保险库校验失败（密钥不匹配或文件被篡改）")
        try:
            return json.loads(plain.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise VaultError("保险库内容损坏")

    def _save_all(self, data):
        plain = json.dumps(data, ensure_ascii=False).encode("utf-8")
        blob = self._f().encrypt(plain)
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
        os.replace(tmp, self.path)

    # ---------------- 公共 API ----------------
    def store(self, tid, profile):
        """写入（覆盖）某目标的认证配置。profile 为 dict，password 以明文传入、整体加密落盘。"""
        tid = int(tid)
        data = self._load_all()
        data[str(tid)] = profile
        self._save_all(data)
        return True

    def get(self, tid):
        """返回某目标的完整 profile（含密码，明文）。仅后端内部使用，绝不对外暴露。"""
        tid = int(tid)
        data = self._load_all()
        return data.get(str(tid))

    def delete(self, tid):
        tid = int(tid)
        data = self._load_all()
        if str(tid) in data:
            del data[str(tid)]
            self._save_all(data)
            return True
        return False

    def list(self):
        """返回所有已配置 tid 列表。"""
        return [int(k) for k in self._load_all().keys()]

    def exists(self, tid):
        return self.get(tid) is not None


def mask_profile(profile):
    """把完整 profile 转为前端安全视图：剔除密码，保留结构信息 + has_password 标记。

    即使 profile 为 None 也安全返回 {configured:False}。"""
    if not profile:
        return {"configured": False}
    out = {
        "configured": True,
        "has_password": bool(profile.get("password")),
        "login_url": profile.get("login_url", ""),
        "method": profile.get("method", "post"),
        "user_field": profile.get("user_field", ""),
        "pass_field": profile.get("pass_field", ""),
        "username": profile.get("username", ""),
        "extra_fields": profile.get("extra_fields", []),
        "csrf_autodetect": bool(profile.get("csrf_autodetect", True)),
        "max_renewals": int(profile.get("max_renewals", 5) or 5),
    }
    return out


_vault_singleton = None


def get_vault():
    """惰性单例：测试可经环境变量 AUTOPENTEST_VAULT_KEY 注入密钥。"""
    global _vault_singleton
    if _vault_singleton is None:
        _vault_singleton = Vault()
    return _vault_singleton
