"""插件信任白名单管理 CLI。

用法:
  python -m scanner.plugins trust <插件文件.py>   登记/更新对某插件的信任（记录 SHA-256）
  python -m scanner.plugins list                  列出已信任的外部插件
  python -m scanner.plugins verify                校验已信任插件的哈希是否仍匹配（篡改检测）
"""
import sys

from scanner.plugins import (
    EXTERNAL_DIR,
    list_trusted,
    trust_plugin,
    verify_trusted,
)


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd = argv[0]
    if cmd == "trust":
        if len(argv) < 2:
            print("用法: python -m scanner.plugins trust <插件文件.py>")
            return 2
        ok, msg = trust_plugin(argv[1])
        print(msg)
        return 0 if ok else 1
    if cmd == "list":
        m = list_trusted()
        if not m:
            print("（无已信任的外部插件）")
        else:
            print("已信任插件（目录 %s）：" % EXTERNAL_DIR)
            for name, info in m.items():
                print("  - %s  sha256=%s…  added=%s" % (
                    name, (info.get("sha256") or "")[:16], info.get("added", "")))
        return 0
    if cmd == "verify":
        ok, bad = verify_trusted()
        for n in ok:
            print("  OK   %s" % n)
        for n in bad:
            print("  FAIL %s（缺失或哈希不匹配，可能被篡改）" % n)
        if bad:
            print("存在 %d 个异常插件，请检查。" % len(bad))
            return 1
        print("全部 %d 个已信任插件完整性校验通过。" % len(ok))
        return 0
    print("未知命令: %s\n" % cmd)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
