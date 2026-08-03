"""PenScope —— OS 命令注入检测模块

检测目标表单参数 / URL 查询参数是否可被拼接执行系统命令。采用**差分标记法**，
从根本上消除旧版"回显型"检测的反射型误报：

  * 注入含**命令替换**的差分载荷，例如 `; echo APCMD_$((123+456))`。
  * 若目标**真正执行**了命令（存在注入），shell 会先计算 `$((123+456))` 再 echo，
    响应中出现**计算结果**标记 `APCMD_579`。
  * 若输入只是**被原样回显**（无注入，旧版误报的根源），响应中出现的是**字面串**
    `APCMD_$((123+456))`（含 `$((` 元字符），与计算结果截然不同。
  * 判定规则：仅当"计算结果标记出现 且 字面串不出现"时，才记命令注入
    （High / unverified / L2），交由人工结合时间盲注进一步确认。这一步让
    反射型误报几乎归零——回显型页面必然带字面 `$((`，会被直接排除。

时间盲注型（金标准）仍走 `exploit_verify` 人工闸门（见 run_scans._verify_cmd），
默认不在此阶段执行，避免对目标造成延迟 / 资源消耗。

所有载荷均不含破坏性指令；不读取、不外传任何业务数据。
"""
import re
import random
import requests
from scanner.web_scan import _send_form, discover, _mk
from scanner.payloads import PayloadGenerator, detect_waf
from cvss_dedup import cwe_for

_MARKER_PREFIX = "APCMD"

# 命令分隔符候选（覆盖 Unix shell 与 cmd.exe 常见写法）
_SEPARATORS = (";", "|", "||", "&&", "&", "$( ", "` ")


def _cmd_poc(target, method, field, payload):
    """生成命令注入复现 curl 命令（示意）。"""
    if method == "post":
        return f"curl -X POST '{target}' --data '{field}={payload}&submit=1'"
    return f"curl '{target}?{field}={payload}'"


def _build_payload(sep):
    """生成差分式回显型探测载荷。

    返回 (payload, marker_exec, marker_literal)：
      - payload        : 注入字符串，例如 `; echo APCMD_$((123+456))`
      - marker_exec    : 命令"被执行"时应当出现的标记，例如 `APCMD_579`
      - marker_literal : 注入载荷中的字面算术串，例如 `APCMD_$((123+456))`
    通过"执行态"与"字面态"的差异即可一次性区分真实注入与输入回显。
    """
    a, b = random.randint(1, 999), random.randint(1, 999)
    literal = f"APCMD_$(({a}+{b}))"   # 字面态：未执行时原样回显
    executed = f"APCMD_{a + b}"        # 执行态：shell 计算后回显
    if sep.startswith("$( "):
        return f"$(echo {literal})", executed, literal
    if sep.startswith("` "):
        return f"`echo {literal}`", executed, literal
    return f"{sep.strip()} echo {literal}", executed, literal


def scan_cmd(url, session, pg, timeout=6.0, verify_ssl=True):
    """命令注入检测：对每个表单/URL 参数注入命令分隔符并观察输出回显（差分标记）。"""
    findings = []
    forms = discover(url, session, timeout, verify_ssl)
    test_points = []
    for f in forms:
        for field in [n for n in f["fields"] if n not in f["file_fields"]]:
            test_points.append((f["action"], f["method"], field, f["fields"]))
    from urllib.parse import urlparse, urlunparse, parse_qs
    q = urlparse(url)
    base = urlunparse(q._replace(query="", fragment=""))
    for k in parse_qs(q.query).keys():
        test_points.append((base, "get", k, [k]))
    if not test_points:
        return findings

    seen = set()
    for target, method, p, fields in test_points:
        if (target, method, p) in seen:
            continue
        seen.add((target, method, p))
        for sep in _SEPARATORS:
            payload, marker_exec, marker_literal = _build_payload(sep)
            try:
                r = _send_form(session, target, method, fields, p, payload, timeout, verify_ssl)
            except requests.RequestException:
                continue
            text = r.text or ""
            # 差分判定（核心：消除反射型误报）：
            #   - 字面算术串出现 => 输入被原样回显（无注入，旧版误报源）=> 跳过
            #   - 计算结果标记出现且字面串不出现 => 命令被执行 => 疑似注入
            if marker_literal in text:
                continue
            if marker_exec in text:
                findings.append(_mk(
                    "命令注入", f"参数 '{p}' 疑似命令注入（命令输出回显）", "High",
                    f"向参数 {p}（端点 {target}，方法 {method.upper()}）注入命令分隔符后，"
                    f"自定义差分标记被命令执行并输出结果 '{marker_exec}'"
                    f"（而非字面串 '{marker_literal}'），疑似存在命令注入"
                    f"（仍需时间盲注进一步确认）。",
                    f"differential marker executed: {marker_exec} "
                    f"(literal {marker_literal} not reflected)",
                    "禁止将用户输入拼接到系统命令；使用子进程的列表参数（不启用 shell）；"
                    "对输入做严格白名单与长度限制；服务进程以最小权限运行。",
                    target,
                    cwe=cwe_for("命令注入"), endpoint=target, http_method=method.upper(),
                    verification_status="unverified", evidence_level="L2",
                    poc=_cmd_poc(target, method, p, "$(echo APCMD_EXECUTED)"),
                ))
                break  # 该参数已确认疑似，跳过其余分隔符
    return findings
