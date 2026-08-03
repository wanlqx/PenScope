"""PenScope —— 响应差异基线建模（C-02）

为时间盲注 / 长延迟类检测建立"正常响应"基线，用**统计分布**替代单点采样，
显著降低时间盲注与长延迟类误报：网络抖动、瞬时延迟尖峰不再被误判为注入成功。

设计原则（与项目"降低误报、保守判定"一致）：
  * 对同一个"良性"请求重复采样多次，得到耗时分布（均值 + 标准差）。
  * 仅当注入后延迟**显著**高于基线分布（>3σ 且接近注入延迟量级）才判定，
    把偶发抖动吸收进阈值，避免把"网络慢了一拍"当成"Sleep 命中"。
  * 样本不足时退化为保守的单点比较，绝不放松判定标准。
"""
import hashlib
import statistics


def response_hash(resp):
    """对响应做归一化哈希，用于内容稳定性判定（识别动态内容抖动）。

    仅取状态码 + 响应文本前 512 字节做 SHA1，足以区分"同一页面不同动态片段"。
    """
    if resp is None:
        return ""
    norm = "{}|{}".format(resp.status_code, (resp.text or "")[:512])
    return hashlib.sha1(norm.encode("utf-8", "ignore")).hexdigest()


def sample_times(send_fn, n=5):
    """对同一个"良性"请求重复发送 n 次，收集每次耗时（秒）并返回耗时列表。

    send_fn 应返回一个浮动秒数，或 (dt, resp) 二元组；异常 / 非法返回值会被跳过，
    因此基线采样本身失败也不会导致后续判定崩溃（退化为样本不足分支）。
    """
    times = []
    for _ in range(n):
        try:
            r = send_fn()
        except Exception:
            continue
        if isinstance(r, (int, float)):
            times.append(float(r))
        elif isinstance(r, (tuple, list)) and len(r) >= 1:
            try:
                times.append(float(r[0]))
            except (TypeError, ValueError):
                continue
    return times


def is_significant_delay(dt, baseline_times, delay=2.0):
    """判断一次延迟 dt 是否显著超过基线（时间盲注判定核心）。

    同时满足：
      1) dt >= delay * 0.6                         —— 至少接近注入延迟量级
      2) dt >= mean + max(delay*0.75, 3*std, 1.0)  —— 显著高于基线分布并高于抖动阈值
    用 3σ 吸收网络抖动，避免瞬时尖峰误报。
    基线样本不足（<3）时退化为保守单点比较（dt >= mean + max(delay*0.75, 1.5)）。
    """
    if dt is None:
        return False
    dt = float(dt)
    if not baseline_times:
        return False
    mean = statistics.mean(baseline_times)
    std = statistics.pstdev(baseline_times) if len(baseline_times) >= 2 else 0.0
    if dt < delay * 0.6:
        return False
    if len(baseline_times) < 3:
        return dt >= mean + max(delay * 0.75, 1.5)
    return dt >= mean + max(delay * 0.75, 3.0 * std, 1.0)


def baseline_digest(times):
    """基线统计摘要，供证据文本 / 报告记录（样本数、均值、标准差）。"""
    if not times:
        return {"n": 0, "mean": 0.0, "std": 0.0}
    return {
        "n": len(times),
        "mean": round(statistics.mean(times), 3),
        "std": round(statistics.pstdev(times) if len(times) >= 2 else 0.0, 3),
    }
