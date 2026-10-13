"""生成 tg-video-dl 应用图标（纯标准库，无 PIL 依赖）。

设计：深空蓝渐变底 + Telegram 纸飞机轮廓 + 向下的下载箭头（点题"下载"）。
2x 超采样抗锯齿，输出 256/64 两档。

产出：
  deploy/fpk/ICON.PNG                   64x64   包图标
  deploy/fpk/ICON_256.PNG               256x256 包图标
  deploy/fpk/app/ui/images/icon_64.png  64x64   入口图标
  deploy/fpk/app/ui/images/icon_256.png 256x256 入口图标
"""
from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "deploy" / "fpk"
S = 1024  # 渲染画布（512 设计坐标 x2 超采样）


def new_canvas() -> list[list[tuple[float, float, float, float]]]:
    return [[(0.0, 0.0, 0.0, 0.0)] * S for _ in range(S)]


def over(dst, src):
    """src over dst（alpha 合成）。"""
    sa = src[3]
    if sa <= 0:
        return dst
    if sa >= 1:
        return src
    da = dst[3]
    oa = sa + da * (1 - sa)
    if oa <= 0:
        return (0.0, 0.0, 0.0, 0.0)
    return tuple((src[i] * sa + dst[i] * da * (1 - sa)) / oa for i in range(3)) + (oa,)


def fill_rounded_rect(canvas, x0, y0, x1, y1, r, color):
    for y in range(max(0, int(y0)), min(S, int(math.ceil(y1)))):
        for x in range(max(0, int(x0)), min(S, int(math.ceil(x1)))):
            cx = min(max(x + 0.5, x0 + r), x1 - r)
            cy = min(max(y + 0.5, y0 + r), y1 - r)
            if (x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2 <= r * r:
                canvas[y][x] = over(canvas[y][x], color)


def gradient_bg(canvas):
    """对角渐变：深蓝 → 亮蓝（Telegram 配色倾向）。"""
    c0 = (0.11, 0.36, 0.72)
    c1 = (0.16, 0.62, 0.92)
    for y in range(S):
        for x in range(S):
            t = (x + y) / (2 * S - 2)
            col = tuple(c0[i] + (c1[i] - c0[i]) * t for i in range(3)) + (1.0,)
            canvas[y][x] = col


def draw_triangle(canvas, pts, color):
    """扫描线填充三角形集合（凸包近似即可）。"""
    ys = [p[1] for p in pts]
    for y in range(max(0, int(min(ys))), min(S, int(math.ceil(max(ys))))):
        yc = y + 0.5
        nodes = []
        n = len(pts)
        for i in range(n):
            x0, y0 = pts[i]
            x1, y1 = pts[(i + 1) % n]
            if (y0 <= yc < y1) or (y1 <= yc < y0):
                t = (yc - y0) / (y1 - y0)
                nodes.append(x0 + t * (x1 - x0))
        nodes.sort()
        for i in range(0, len(nodes) - 1, 2):
            for x in range(max(0, int(nodes[i])), min(S, int(math.ceil(nodes[i + 1])))):
                canvas[y][x] = over(canvas[y][x], color)


def bezier(p0, p1, p2, p3, t):
    mt = 1 - t
    return (
        mt**3 * p0[0] + 3 * mt**2 * t * p1[0] + 3 * mt * t**2 * p2[0] + t**3 * p3[0],
        mt**3 * p0[1] + 3 * mt**2 * t * p1[1] + 3 * mt * t**2 * p2[1] + t**3 * p3[1],
    )


def draw_plane(canvas, scale, ox, oy, color):
    """Telegram 风格纸飞机（简化为两个三角面）。"""
    def P(px, py):
        return (ox + px * scale, oy + py * scale)

    # 机身主体
    body = [P(-0.62, 0.06), P(0.62, -0.30), P(-0.10, 0.30)]
    draw_triangle(canvas, body, color)
    # 折翼（稍暗，制造立体感）
    wing = [P(-0.10, 0.30), P(0.62, -0.30), P(-0.02, 0.02)]
    draw_triangle(canvas, wing, (color[0] * 0.78, color[1] * 0.80, color[2] * 0.86, color[3]))


def draw_arrow(canvas, scale, ox, oy, color):
    """下载箭头：竖杆 + 三角头 + 底部托盘。"""
    def R(x0, y0, x1, y1):
        fill_rounded_rect(canvas, ox + x0 * scale, oy + y0 * scale,
                          ox + x1 * scale, oy + y1 * scale, 0.02 * scale, color)

    R(-0.055, -0.62, 0.055, 0.16)                       # 竖杆
    draw_triangle(canvas, [                            # 箭头
        (ox - 0.24 * scale, oy + 0.06 * scale),
        (ox + 0.24 * scale, oy + 0.06 * scale),
        (ox, oy + 0.44 * scale),
    ], color)
    R(-0.30, 0.56, 0.30, 0.68)                          # 托盘


def downsample(canvas, size):
    """盒式降采样到 size×size（抗锯齿），带预乘 alpha。"""
    factor = S // size
    out = []
    for by in range(size):
        row = []
        for bx in range(size):
            r = g = b = a = 0.0
            for y in range(by * factor, (by + 1) * factor):
                for x in range(bx * factor, (bx + 1) * factor):
                    px = canvas[y][x]
                    r += px[0] * px[3]
                    g += px[1] * px[3]
                    b += px[2] * px[3]
                    a += px[3]
            n = factor * factor
            if a > 0:
                row.append((int(round(r / a * 255)), int(round(g / a * 255)),
                            int(round(b / a * 255)), int(round(a / n * 255))))
            else:
                row.append((0, 0, 0, 0))
        out.append(row)
    return out


def write_png(path: Path, rows):
    h = len(rows)
    w = len(rows[0])
    raw = b"".join(b"\x00" + b"".join(struct.pack("BBBB", *px) for px in row) for row in rows)

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 9))
           + chunk(b"IEND", b""))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)


def main():
    canvas = new_canvas()
    fill_rounded_rect(canvas, 0, 0, S, S, 0.22 * S, (0, 0, 0, 1))  # 圆角遮罩底
    gradient_bg(canvas)
    # 圆角外裁掉
    mask = new_canvas()
    fill_rounded_rect(mask, 0, 0, S, S, 0.22 * S, (0, 0, 0, 1))
    for y in range(S):
        for x in range(S):
            canvas[y][x] = canvas[y][x] if mask[y][x][3] > 0.5 else (0, 0, 0, 0)

    draw_plane(canvas, S * 0.36, S * 0.50, S * 0.40, (1.0, 1.0, 1.0, 0.97))
    draw_arrow(canvas, S * 0.30, S * 0.52, S * 0.66, (1.0, 1.0, 1.0, 1.0))

    targets = [
        (ROOT / "ICON.PNG", 64),
        (ROOT / "ICON_256.PNG", 256),
        (ROOT / "app" / "ui" / "images" / "icon_64.png", 64),
        (ROOT / "app" / "ui" / "images" / "icon_256.png", 256),
    ]
    for path, size in targets:
        write_png(path, downsample(canvas, size))
        print(f"[icons] 已生成 {path} ({size}x{size})")


if __name__ == "__main__":
    main()
