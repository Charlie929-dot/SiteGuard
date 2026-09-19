#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SiteGuard 图标生成器
用纯 Python 标准库（zlib + struct）手写 PNG，生成盾牌形图标
状态颜色：gray / green / yellow / red，每个状态 16/32/48/128 四种尺寸
"""
import zlib
import struct
import os

# 颜色定义 (R, G, B)
COLORS = {
    'gray':   (156, 163, 175),   # #9ca3af
    'green':  (22, 163, 74),     # #16a34a
    'yellow': (202, 138, 4),     # #ca8a04
    'red':    (220, 38, 38),     # #dc2626
}

def shield_mask(x, y, size):
    """盾牌形状：判断坐标是否在盾牌内部（归一化坐标 0-1）"""
    nx = x / size
    ny = y / size
    # 盾牌：上半部矩形 + 下半部尖角
    # 顶部圆角矩形区域
    if ny <= 0.55:
        # 顶部主体，两侧留边
        margin = 0.18
        if margin <= nx <= (1 - margin):
            return True
        return False
    else:
        # 下半部逐渐收窄成尖角
        # 从 y=0.55 到 y=0.95 收窄到中心点
        t = (ny - 0.55) / (0.95 - 0.55)  # 0 -> 1
        if t >= 1:
            return False
        # 宽度随 t 线性收窄
        top_margin = 0.18
        bottom_margin = 0.50  # 底部中心
        margin = top_margin + (bottom_margin - top_margin) * t
        if margin <= nx <= (1 - margin):
            return True
        return False

def write_png(path, size, color):
    """写一个纯色 PNG 图标"""
    rows = []
    for y in range(size):
        row = bytearray()
        # 每行开头加 filter type 0
        row.append(0)
        for x in range(size):
            if shield_mask(x, y, size):
                r, g, b = color
                row.extend([r, g, b, 255])
            else:
                row.extend([0, 0, 0, 0])  # 透明
        rows.append(bytes(row))

    raw = b''.join(rows)

    def chunk(ctype, data):
        c = ctype + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

    # PNG 签名
    sig = b'\x89PNG\r\n\x1a\n'
    # IHDR
    ihdr = struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0)  # 8bit RGBA
    # IDAT
    idat = zlib.compress(raw, 9)
    # IEND
    png = sig + chunk(b'IHDR', ihdr) + chunk(b'IDAT', idat) + chunk(b'IEND', b'')

    with open(path, 'wb') as f:
        f.write(png)

def main():
    base = os.path.dirname(os.path.abspath(__file__))
    icons_dir = os.path.join(base, 'icons')
    os.makedirs(icons_dir, exist_ok=True)

    sizes = [16, 32, 48, 128]
    for state, color in COLORS.items():
        for size in sizes:
            path = os.path.join(icons_dir, f'{state}-{size}.png')
            write_png(path, size, color)
            print(f'生成: {path}')

    print('全部图标生成完成')

if __name__ == '__main__':
    main()
