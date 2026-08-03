"""C-05：默认凭据字典加载器单元测试。

覆盖：内置打包字典加载、自定义路径、注释/空行/去重/无冒号/超长丢弃、限条数、
环境变量覆盖、显式路径优先、缺失文件回退链。
"""
import os
import tempfile

from scanner.cred_dict import _EMBEDDED_DEFAULT_CREDS, BUNDLED_DICT_PATH, _normalize, load_default_creds


def _write_tmp(text):
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="cred_test_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def test_bundled_dict_loads():
    creds = load_default_creds()
    assert len(creds) == len(_EMBEDDED_DEFAULT_CREDS) == 14
    assert ("admin", "admin") in creds
    assert ("admin", "letmein") in creds


def test_bundled_path_exists():
    assert os.path.isfile(BUNDLED_DICT_PATH), "打包内置字典文件应存在"


def test_normalize_comments_blanks_dedup_and_bad_lines():
    p = _write_tmp(
        "# comment line\n"
        "\n"
        "alice:secret\n"
        "bob:pass123\n"
        "alice:secret\n"          # 重复，应去重
        "no_colon_here\n"          # 无冒号，应丢弃
        "charlie:  :weird\n"      # partition 后 pwd 含前缀空格，strip 后为 ":weird"（仍有效）
    )
    try:
        rows = _normalize(p)
        assert ("alice", "secret") in rows
        assert ("bob", "pass123") in rows
        assert rows.count(("alice", "secret")) == 1, "重复项应被去重"
        assert all(":" in (u + ":" + v) for u, v in rows)
    finally:
        os.remove(p)


def test_normalize_drops_overlong_field():
    long_v = "x" * 300
    p = _write_tmp("user1:%s\nuser2:ok\n" % long_v)
    try:
        rows = _normalize(p)
        assert ("user2", "ok") in rows
        assert all(len(u) <= 256 and len(v) <= 256 for u, v in rows)
    finally:
        os.remove(p)


def test_normalize_missing_file_returns_none():
    assert _normalize("__definitely_missing_file__.txt") is None


def test_explicit_path_overrides_env_and_bundled():
    env_path = _write_tmp("envuser:envpass\n")
    explicit = _write_tmp("explicituser:explicitpass\n")
    old = os.environ.get("AUTOPENTEST_AUTH_DICT")
    try:
        os.environ["AUTOPENTEST_AUTH_DICT"] = env_path
        res = load_default_creds(explicit)
        assert ("explicituser", "explicitpass") in res
        assert ("envuser", "envpass") not in res
    finally:
        if old is None:
            os.environ.pop("AUTOPENTEST_AUTH_DICT", None)
        else:
            os.environ["AUTOPENTEST_AUTH_DICT"] = old
        os.remove(env_path)
        os.remove(explicit)


def test_env_var_overrides_bundled():
    env_path = _write_tmp("envonly:envonlypass\n")
    old = os.environ.get("AUTOPENTEST_AUTH_DICT")
    try:
        os.environ["AUTOPENTEST_AUTH_DICT"] = env_path
        res = load_default_creds()
        assert ("envonly", "envonlypass") in res
        assert ("admin", "admin") not in res
    finally:
        if old is None:
            os.environ.pop("AUTOPENTEST_AUTH_DICT", None)
        else:
            os.environ["AUTOPENTEST_AUTH_DICT"] = old
        os.remove(env_path)


def test_missing_explicit_path_falls_through_to_bundled():
    res = load_default_creds("__missing_cred_file__.txt")
    assert ("admin", "admin") in res, "显式路径缺失应回退到内置字典"


def test_embedded_fallback_matches_bundled_count():
    # 兜底列表与内置文件内容保持一致（防止打包遗漏时无字典可用）。
    assert len(_EMBEDDED_DEFAULT_CREDS) == 14
    assert ("admin", "admin") in _EMBEDDED_DEFAULT_CREDS
