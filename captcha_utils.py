# -*- coding: utf-8 -*-
"""
验证码生成工具 - 大字体跨平台清晰版
"""
import random
import io
import os
from PIL import Image, ImageDraw, ImageFont, ImageFilter

CHARACTERS = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'

FONT_CANDIDATES = [
    r'C:\Windows\Fonts\arialbd.ttf',
    r'C:\Windows\Fonts\Arial.ttf',
    r'C:\Windows\Fonts\segoeuib.ttf',
    r'C:\Windows\Fonts\msyhbd.ttc',
    r'C:\Windows\Fonts\msyh.ttc',
    '/System/Library/Fonts/Supplemental/Arial Bold.ttf',
    '/System/Library/Fonts/Supplemental/Arial.ttf',
    '/System/Library/Fonts/Helvetica.ttc',
    '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
    '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf',
]

def generate_captcha(length=4):
    """生成随机验证码"""
    return ''.join(random.choice(CHARACTERS) for _ in range(length))

def _load_font(size):
    for font_path in FONT_CANDIDATES:
        if os.path.exists(font_path):
            try:
                return ImageFont.truetype(font_path, size)
            except OSError:
                continue
    try:
        return ImageFont.truetype('arial.ttf', size)
    except OSError:
        return ImageFont.load_default()

def generate_captcha_image(captcha_text):
    """生成大字体、高对比度、跨浏览器友好的 PNG 验证码。"""
    width = 160
    height = 60
    scale = 2
    canvas_size = (width * scale, height * scale)

    image = Image.new('RGB', canvas_size, (245, 251, 255))
    draw = ImageDraw.Draw(image)

    for y in range(canvas_size[1]):
        ratio = y / max(canvas_size[1] - 1, 1)
        r = int(248 - 12 * ratio)
        g = int(252 - 8 * ratio)
        b = 255
        draw.line([(0, y), (canvas_size[0], y)], fill=(r, g, b))

    for _ in range(24):
        x = random.randint(0, canvas_size[0] - 1)
        y = random.randint(0, canvas_size[1] - 1)
        draw.ellipse((x, y, x + 2, y + 2), fill=(random.randint(175, 215), random.randint(215, 238), 255))

    for _ in range(2):
        x1 = random.randint(0, canvas_size[0] // 4)
        y1 = random.randint(canvas_size[1] // 4, canvas_size[1] * 3 // 4)
        x2 = random.randint(canvas_size[0] * 3 // 4, canvas_size[0])
        y2 = random.randint(canvas_size[1] // 4, canvas_size[1] * 3 // 4)
        draw.line([(x1, y1), (x2, y2)], fill=(125, 188, 238), width=2)

    font = _load_font(34 * scale)
    slot_width = canvas_size[0] / len(captcha_text)

    for i, char in enumerate(captcha_text):
        bbox = draw.textbbox((0, 0), char, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        x = int(i * slot_width + (slot_width - text_width) / 2 + random.randint(-2, 2) * scale)
        y = int((canvas_size[1] - text_height) / 2 - 2 * scale + random.randint(-1, 1) * scale)
        x = max(8 * scale, min(x, canvas_size[0] - text_width - 8 * scale))
        y = max(4 * scale, min(y, canvas_size[1] - text_height - 4 * scale))
        draw.text((x + 2, y + 2), char, fill=(170, 216, 250), font=font)
        draw.text((x, y), char, fill=(18, 84, 145), font=font)

    image = image.filter(ImageFilter.SMOOTH)
    image = image.resize((width, height), Image.Resampling.LANCZOS)

    buf = io.BytesIO()
    image.save(buf, format='PNG', optimize=True)
    buf.seek(0)
    return buf
