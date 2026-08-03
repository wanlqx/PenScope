#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_icon.py —— 为 PenScope 生成方案B SOC 主题图标
输出：
  assets/icon.ico  （多尺寸 16/32/48/64/128/256，用于窗口与 exe）
  assets/tray.png  （32x32 透明背景，用于系统托盘）

设计：青→紫对角渐变圆角块 + 白色盾牌 + 青色勾选（与前端 .brand SVG 一致）。
仅依赖 Pillow，无外部素材。
"""
import os

from PIL import Image, ImageDraw

SIZE = 256
HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "assets")


def lerp(c1, c2, t):
    return tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))


def make_gradient(size, c1, c2):
    """对角渐变（左上 c1 → 右下 c2）。"""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    px = img.load()
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * max(1, size - 1))
            px[x, y] = lerp(c1, c2, t) + (255,)
    return img


def rounded_mask(size, radius):
    mask = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(mask)
    try:
        d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    except AttributeError:
        # 旧版 Pillow 无 rounded_rectangle，退化为圆形掩膜
        d.ellipse([0, 0, size - 1, size - 1], fill=255)
    return mask


def draw_shield(draw, size, color):
    s = size
    pts = [
        (0.50 * s, 0.12 * s),
        (0.85 * s, 0.24 * s),
        (0.85 * s, 0.55 * s),
        (0.50 * s, 0.92 * s),
        (0.15 * s, 0.55 * s),
        (0.15 * s, 0.24 * s),
    ]
    draw.polygon(pts, fill=color)


def draw_check(draw, size, color):
    s = size
    p1 = (0.34 * s, 0.50 * s)
    p2 = (0.45 * s, 0.62 * s)
    p3 = (0.68 * s, 0.36 * s)
    w = max(2, int(0.07 * s))
    draw.line([p1, p2], fill=color, width=w)
    draw.line([p2, p3], fill=color, width=w)
    r = w // 2
    for p in (p1, p2, p3):
        draw.ellipse([p[0] - r, p[1] - r, p[0] + r, p[1] + r], fill=color)


def build_base():
    c1 = (34, 211, 238)    # accent-cyan
    c2 = (139, 92, 246)    # accent-violet
    bg = make_gradient(SIZE, c1, c2)
    mask = rounded_mask(SIZE, int(SIZE * 0.22))
    base = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    base.paste(bg, (0, 0), mask)
    d = ImageDraw.Draw(base)
    draw_shield(d, SIZE, (255, 255, 255, 255))
    draw_check(d, SIZE, (34, 211, 238, 255))
    return base


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    base = build_base()
    ico_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    ico_path = os.path.join(OUT_DIR, "icon.ico")
    base.save(ico_path, format="ICO", sizes=ico_sizes)
    tray = base.resize((32, 32), Image.LANCZOS)
    tray_path = os.path.join(OUT_DIR, "tray.png")
    tray.save(tray_path, format="PNG")
    print("OK icon.ico ->", ico_path, os.path.getsize(ico_path), "bytes")
    print("OK tray.png ->", tray_path, os.path.getsize(tray_path), "bytes")


if __name__ == "__main__":
    main()
