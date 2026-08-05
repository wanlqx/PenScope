# -*- coding: utf-8 -*-
"""独立校验: 启动靶机 -> 对每题跑 exploit -> 比对 FLAGS 真值。"""
import os, sys, threading, time
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lab"))

import vuln_lab
from core.client import LabClient
from core.exploits import exploit
from core.config import load_challenges

PORT = 8097
def start():
    t = threading.Thread(target=vuln_lab.run_lab, args=(PORT,), daemon=True)
    t.start(); time.sleep(1.0)

if __name__ == "__main__":
    start()
    base = f"http://127.0.0.1:{PORT}"
    chs = load_challenges()
    fails = []
    for c in chs:
        cid = c["id"]
        client = LabClient(base)
        got = exploit(cid, client, base)
        truth = vuln_lab.FLAGS.get(cid)
        ok = got == truth
        if not ok:
            fails.append((cid, got, truth))
        print(f"  {cid:<7} {'OK ' if ok else 'FAIL'} expect={truth} got={got}")
    print(f"\n总题数={len(chs)}  失败={len(fails)}")
    if fails:
        print("失败明细:")
        for cid, got, truth in fails:
            print(f"  {cid}: got={got} truth={truth}")
        sys.exit(1)
    print("✅ 全部 37 题利用序列与靶机真值一致")
