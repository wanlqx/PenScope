"""pytest 路径引导：将项目根目录加入 sys.path，使 tests/ 下的用例能直接
import scanner / config / db / run_scans / reports 等顶层模块。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
